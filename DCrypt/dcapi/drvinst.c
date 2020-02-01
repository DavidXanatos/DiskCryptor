/*
    *
    * DiskCryptor - open source partition encryption tool
	* Copyright (c) 2007-2014
	* ntldr <ntldr@diskcryptor.net> PGP key ID - 0xC48251EB4F8E4E6E
    *

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 3 as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <strsafe.h>
#include "drvinst.h"
#include "dcres.h"
#include "misc.h"
#include "drv_ioctl.h"
#include "dcapi.h"

static const TCHAR g_dcrypt_service_name[] = _T("dcrypt");
static const TCHAR g_maindriver_filename[] = _T("dcrypt.sys");
static const TCHAR g_service_description[] = _T("DiskCryptor driver");

static const TCHAR g_dcrypt_config_key[] = _T("SYSTEM\\CurrentControlSet\\Services\\dcrypt\\config");
static const TCHAR g_volume_filter_key[] = _T("SYSTEM\\CurrentControlSet\\Control\\Class\\{71A27CDD-812A-11D0-BEC7-08002BE2092F}");
static const TCHAR g_cdrom_filter_key[] = _T("SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E965-E325-11CE-BFC1-08002BE10318}");
static const TCHAR g_crash_filter_key[] = _T("SYSTEM\\CurrentControlSet\\Control\\CrashControl"); 

DWORD dc_load_config(dc_conf_data* conf)
{
	DC_FLAGS flags;
	HKEY     h_key;
	DWORD    status, cb;

	if ( (status = RegOpenKey(HKEY_LOCAL_MACHINE, g_dcrypt_config_key, &h_key)) == NO_ERROR )
	{
		cb = sizeof(conf->conf_flags);

		if (RegQueryValueEx(h_key, _T("Flags"), NULL, NULL, (BYTE *)&conf->conf_flags, &cb) != NO_ERROR) {
			conf->conf_flags = 0;
		}

		cb = sizeof(conf->build);

		if (RegQueryValueEx(h_key, _T("sysBuild"), NULL, NULL, (BYTE *)&conf->build, &cb) != NO_ERROR) {
			conf->build = 0;
		}

		cb = sizeof(conf->hotkeys);

		if (RegQueryValueEx(h_key, _T("Hotkeys"), NULL, NULL, (BYTE *)&conf->hotkeys, &cb) != NO_ERROR) {
			memset(&conf->hotkeys, 0, sizeof(conf->hotkeys));
		}

		if (dc_device_control(DC_CTL_GET_FLAGS, NULL, 0, &flags, sizeof(flags)) == NO_ERROR) {
			conf->load_flags = flags.load_flags;
		} else {
			conf->load_flags = 0;
		}

		RegCloseKey(h_key);
	}
	return status;
}

DWORD dc_save_config(const dc_conf_data* conf)
{
	DC_FLAGS flags = { conf->conf_flags, conf->load_flags, };
	DWORD    status, build = DC_DRIVER_VER;
	HKEY     h_key;

	if ( (status = RegCreateKey(HKEY_LOCAL_MACHINE, g_dcrypt_config_key, &h_key)) == NO_ERROR )
	{
		if ( (status = RegSetValueEx(h_key, _T("Flags"), 0, REG_DWORD, (const BYTE *)&conf->conf_flags, sizeof(conf->conf_flags))) != NO_ERROR ) goto cleanup;
		if ( (status = RegSetValueEx(h_key, _T("Hotkeys"), 0, REG_BINARY, (const BYTE *)&conf->hotkeys, sizeof(conf->hotkeys))) != NO_ERROR ) goto cleanup;
		if ( (status = RegSetValueEx(h_key, _T("sysBuild"), 0, REG_DWORD, (const BYTE *)&build, sizeof(build))) != NO_ERROR ) goto cleanup;
		if ( (status = RegFlushKey(h_key)) != NO_ERROR ) goto cleanup;

		if ( (status = dc_device_control(DC_CTL_SET_FLAGS, &flags, sizeof(flags), NULL, 0)) == ERROR_DC_NOT_FOUND ) status = NO_ERROR;
cleanup:
		RegCloseKey(h_key);
	}
	return status;
}

static DWORD remove_from_reg_multi_sz(PCTSTR key_name, PCTSTR value_name, PCTSTR content)
{
	HKEY  h_key;
	TCHAR buff[1024], *p = buff;
	DWORD cb = sizeof(buff), len, status;
	DWORD type;

	if ( (status = RegOpenKey(HKEY_LOCAL_MACHINE, key_name, &h_key)) != NO_ERROR ) return status;
	if ( (status = RegQueryValueEx(h_key, value_name, NULL, &type, (BYTE *)&buff, &cb)) != NO_ERROR ) goto cleanup;
	
	if (type != REG_MULTI_SZ || cb < sizeof(TCHAR)) {
		status = ERROR_DATATYPE_MISMATCH;
		goto cleanup;
	}

	while ( (len = (DWORD)(_tcslen(p) * sizeof(TCHAR))) != 0 )
	{
		if (_tcscmp(p, content) == 0)
		{
			cb -= len + sizeof(TCHAR);
			memmove(p, (const BYTE*)p + len + sizeof(TCHAR), cb - ((const BYTE*)p - (const BYTE*)buff));

			if (cb == 0 || buff[0] == 0) {
				cb = 0; break;
			}
		} else {
			p += (len / sizeof(TCHAR)) + 1;
		}
	}
	if (cb != 0) {
		if ( (status = RegSetValueEx(h_key, value_name, 0, REG_MULTI_SZ, (const BYTE *)&buff, cb)) != NO_ERROR ) goto cleanup;
	} else {
		if ( (status = RegDeleteValue(h_key, value_name)) != NO_ERROR ) goto cleanup;
	}
	status = RegFlushKey(h_key);
cleanup:
	RegCloseKey(h_key);
	return status;
}

static DWORD add_to_reg_multi_sz(PCTSTR key_name, PCTSTR value_name, PCTSTR content)
{
	HKEY  h_key;
	TCHAR buff[1024], *p;
	DWORD cb, len, status;
	DWORD type;
	
	if ( (status = RegOpenKey(HKEY_LOCAL_MACHINE, key_name, &h_key)) != NO_ERROR ) return status;

	len = (DWORD)((_tcslen(content) + 1) * sizeof(TCHAR));
	cb  = sizeof(buff); p = buff;

	if ( (status = RegQueryValueEx(h_key, value_name, NULL, &type, (BYTE *)&buff, &cb)) != NO_ERROR )
	{
		if (status != ERROR_FILE_NOT_FOUND) goto cleanup;
		buff[0] = 0; cb = sizeof(TCHAR);
	} else
	{
		if (type != REG_MULTI_SZ || cb + len > sizeof(buff)) {
			status = ERROR_DATATYPE_MISMATCH;
			goto cleanup;
		}
	}
	
	for (; *p != 0; p += _tcslen(p) + 1) {
		if (_tcscmp(p, content) == 0) goto cleanup;
	}

	memmove((BYTE *)buff + len, buff, cb);
	memcpy(buff, content, len);
	cb += len;

	if ( (status = RegSetValueEx(h_key, value_name, 0, REG_MULTI_SZ, (const BYTE *)&buff, cb)) == NO_ERROR )
	{
		status = RegFlushKey(h_key);
	}
cleanup:
	RegCloseKey(h_key);
	return status;
}

static DWORD make_driver_path(PTSTR pszPath, size_t cchPath, PCTSTR driver_name)
{
	TCHAR sys_path[MAX_PATH];
	DWORD length;

	if ( (length = GetSystemDirectory(sys_path, _countof(sys_path))) == 0 || length >= _countof(sys_path) )
	{
		return ERROR_INVALID_NAME;
	}
	if ( FAILED(StringCchPrintf(pszPath, cchPath, _T("%s\\drivers\\%s"), sys_path, driver_name)) )
	{
		return ERROR_INSUFFICIENT_BUFFER;
	}
	return NO_ERROR;
}

static DWORD save_dcrypt_driver_file()
{
	TCHAR source_path[MAX_PATH], dest_path[MAX_PATH], *p;
	DWORD length, status;

	if (g_inst_dll == NULL || (length = GetModuleFileName(g_inst_dll, source_path, _countof(source_path))) == 0) return ERROR_INVALID_NAME;
	if (length >= _countof(source_path) - 1 || (p = _tcsrchr(source_path, '\\')) == NULL) return ERROR_INVALID_NAME;
	if ( FAILED(StringCchCopy(p + 1, _countof(source_path) - (p - source_path) - 1, g_maindriver_filename)) ) return ERROR_INSUFFICIENT_BUFFER;
	
	if ( (status = make_driver_path(dest_path, _countof(dest_path), g_maindriver_filename)) != NO_ERROR ) return status;
	if ( CopyFile(source_path, dest_path, FALSE) == FALSE ) return GetLastError();
	return NO_ERROR;
}

static DWORD install_dcrypt_driver_service()
{
	TCHAR     driver_path[MAX_PATH];
	SC_HANDLE h_scm = NULL;
	SC_HANDLE h_svc = NULL;
	DWORD     status;

	if ( (status = make_driver_path(driver_path, _countof(driver_path), g_maindriver_filename)) != NO_ERROR ) {
		goto cleanup;
	}
	if ( (h_scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS)) == NULL ) {
		status = GetLastError();
		goto cleanup;
	}

	if (h_svc = CreateService(h_scm,                  // hSCManager
		                      g_dcrypt_service_name,  // lpServiceName,
							  g_service_description,  // lpDisplayName
		                      SERVICE_ALL_ACCESS,     // dwDesiredAccess
							  SERVICE_KERNEL_DRIVER,  // dwServiceType
							  SERVICE_BOOT_START,     // dwStartType
							  SERVICE_ERROR_CRITICAL, // dwErrorControl
							  driver_path,            // lpBinaryPathName
							  _T("Filter"),           // lpLoadOrderGroup
							  NULL,                   // lpdwTagId
							  _T("FltMgr"),           // lpDependencies
							  NULL, NULL))            // lpServiceStartName, lpPassword
	{
		status = NO_ERROR;
	} else {
		status = GetLastError();
	}
cleanup:
	if (h_svc != NULL) CloseServiceHandle(h_svc);
	if (h_scm != NULL) CloseServiceHandle(h_scm);
	return status;
}

static DWORD remove_service(PCTSTR service_name)
{
	SC_HANDLE h_scm = NULL;
	SC_HANDLE h_svc = NULL;
	DWORD     status;
	
	if ( (h_scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS)) != NULL &&
		 (h_svc = OpenService(h_scm, service_name, SERVICE_ALL_ACCESS)) != NULL &&
		 (DeleteService(h_svc) != FALSE) )
	{
		status = NO_ERROR;
	} else {
		status = GetLastError();
	}
	if (h_svc != NULL) CloseServiceHandle(h_svc);
	if (h_scm != NULL) CloseServiceHandle(h_scm);
	return status;
}

static DWORD add_altitude_info()
{
	HKEY  hkey_1 = NULL;
	HKEY  hkey_2 = NULL;
	DWORD status, flags = 0;

	if ( (status = RegCreateKey(HKEY_LOCAL_MACHINE, _T("SYSTEM\\CurrentControlSet\\Services\\dcrypt\\Instances"), &hkey_1)) != NO_ERROR ) goto cleanup;
	if ( (status = RegSetValueEx(hkey_1, _T("DefaultInstance"), 0, REG_SZ, (const BYTE*)_T("dcrypt"), sizeof(_T("dcrypt")))) != NO_ERROR ) goto cleanup;
	
	if ( (status = RegCreateKey(hkey_1, _T("dcrypt"), &hkey_2)) != NO_ERROR ) goto cleanup;
	if ( (status = RegSetValueEx(hkey_2, _T("Altitude"), 0, REG_SZ, (const BYTE*)_T("87150"), sizeof(_T("87150")))) != NO_ERROR ) goto cleanup;
	if ( (status = RegSetValueEx(hkey_2, _T("Flags"), 0, REG_DWORD, (const BYTE*)&flags, sizeof(flags))) != NO_ERROR ) goto cleanup;

	if ( (status = RegFlushKey(hkey_2)) != NO_ERROR ) goto cleanup;
	if ( (status = RegFlushKey(hkey_1)) != NO_ERROR ) goto cleanup;

cleanup:
	if (hkey_2 != NULL) RegCloseKey(hkey_2);
	if (hkey_1 != NULL) RegCloseKey(hkey_1);
	return status;
}

DWORD dc_install_driver()
{
	dc_conf_data config = { DC_DRIVER_VER, (CONF_HW_CRYPTO | CONF_AUTOMOUNT_BOOT | CONF_ENABLE_SSD_OPT), };
	DWORD        status;

	// copy driver to system directory and install driver service
	if ( (status = save_dcrypt_driver_file()) != NO_ERROR ) goto cleanup;
	if ( (status = install_dcrypt_driver_service()) != NO_ERROR ) goto cleanup;
	
	// add Altitude
	if ( (status = add_altitude_info()) != NO_ERROR ) goto cleanup;

	// add Volume and CDROM filters
	if ( (status = add_to_reg_multi_sz(g_volume_filter_key, _T("LowerFilters"), g_dcrypt_service_name)) != NO_ERROR ) goto cleanup;
	if ( (status = add_to_reg_multi_sz(g_cdrom_filter_key, _T("UpperFilters"), g_dcrypt_service_name)) != NO_ERROR ) goto cleanup;

#pragma warning( disable : 4996 )
	if (LOBYTE(LOWORD(GetVersion())) >= 6) {
#pragma warning( default : 4996 )
		// add crashdump filter (Vista+)
		if ( (status = add_to_reg_multi_sz(g_crash_filter_key, _T("DumpFilters"), g_maindriver_filename)) != NO_ERROR ) goto cleanup;
	}

	// setup default config
	if ( (status = dc_save_config(&config)) != NO_ERROR ) goto cleanup;

cleanup:
	if (status != NO_ERROR) dc_remove_driver();
	return status;
}

DWORD dc_remove_driver()
{
	TCHAR path[MAX_PATH];
	DWORD status = NO_ERROR, ret;

	// remove Volume AND CDROM filters
	if ( (ret = remove_from_reg_multi_sz(g_cdrom_filter_key, _T("UpperFilters"), g_dcrypt_service_name)) != NO_ERROR ) status = ret;
	if ( (ret = remove_from_reg_multi_sz(g_volume_filter_key, _T("LowerFilters"), g_dcrypt_service_name)) != NO_ERROR ) status = ret;

#pragma warning( disable : 4996 )
	if (LOBYTE(LOWORD(GetVersion())) >= 6) {
#pragma warning( default : 4996 )
		// remove crashdump filtes (Vista+)
		if ( (ret = remove_from_reg_multi_sz(g_crash_filter_key, _T("DumpFilters"), g_maindriver_filename)) != NO_ERROR ) status = ret;
	}

	// remove service
	if ( (ret = remove_service(g_dcrypt_service_name)) != NO_ERROR ) status = ret;

	// delete driver file
	if ( (ret = make_driver_path(path, _countof(path), g_maindriver_filename)) == NO_ERROR )
	{
		if (MoveFileEx(path, NULL, MOVEFILE_DELAY_UNTIL_REBOOT) == FALSE) status = GetLastError();
	} else {
		status = ret;
	}
	return status;
}

BOOL dc_is_driver_installed()
{
	TCHAR path[MAX_PATH];

	if (make_driver_path(path, _countof(path), g_maindriver_filename) != NO_ERROR) return FALSE;
	if (GetFileAttributes(path) == INVALID_FILE_ATTRIBUTES) return FALSE;
	return TRUE;
}

BOOL dc_is_driver_works()
{
	HANDLE h_device;

	if ( (dc_is_driver_installed() != FALSE) &&
		 (h_device = CreateFile(DC_WIN32_NAME, 0, 0, NULL, OPEN_EXISTING, 0, NULL)) != INVALID_HANDLE_VALUE )
	{
		CloseHandle(h_device);
		return TRUE;
	}
	return FALSE;
}

DWORD dc_update_driver()
{
	TCHAR        buff[MAX_PATH];
	dc_conf_data config;
	DWORD        status;
	
	if ( (status = save_dcrypt_driver_file()) != NO_ERROR ) goto cleanup;
	if ( (status = dc_load_config(&config)) != NO_ERROR ) goto cleanup;

	if (config.build < 692)
	{
		// remove dc_fsf.sys
		if ( (status = make_driver_path(buff, _countof(buff), _T("dc_fsf.sys"))) != NO_ERROR ) goto cleanup;
		DeleteFile(buff);
		// add Altitude
		if ( (status = add_altitude_info()) != NO_ERROR ) goto cleanup;
	}
	if (config.build < 366)
	{
		// add CDROM filter
		if ( (status = add_to_reg_multi_sz(g_cdrom_filter_key, _T("UpperFilters"), g_dcrypt_service_name)) != NO_ERROR ) goto cleanup;
		// set new default flags
		config.conf_flags |= CONF_HW_CRYPTO | CONF_AUTOMOUNT_BOOT;
	}
	if (config.build < 642) {
		config.conf_flags |= CONF_ENABLE_SSD_OPT;
	}
	
#pragma warning( disable : 4996 )
	if (config.build < 818 && LOBYTE(LOWORD(GetVersion())) >= 6) {
#pragma warning( default : 4996 )
		// add crashdump filter (Vista+)
		if ( (status = add_to_reg_multi_sz(g_crash_filter_key, _T("DumpFilters"), g_maindriver_filename)) != NO_ERROR ) goto cleanup;
	}
	
	if ( (status = dc_save_config(&config)) == NO_ERROR )
	{
		StringCchPrintf(buff, _countof(buff), _T("DC_UPD_%d"), dc_get_version());
		GlobalAddAtom(buff);
	}
cleanup:
	return status;
}
