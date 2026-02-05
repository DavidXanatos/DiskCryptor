/*
	*
	* DiskCryptor - open source partition encryption tool
	* Copyright (c) 2019-2026
	* DavidXanatos <info@diskcryptor.org>
	* partial copyright 2013-2017 IDRIX from the VeraCrypt project

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
#include <shlobj.h>
#include <shtypes.h>
#include <KnownFolders.h>
#include <stdio.h>
#include <tchar.h>
#include <strsafe.h>
#include "w10.h"
#include "misc.h"
#include "dcconst.h"
#include "version.h"

#pragma comment( lib, "Ole32.lib" )

// File list for offline installation
typedef struct _DC_OFFLINE_FILE {
	const wchar_t* source;  // Source filename (in installation directory)
	const wchar_t* target;  // Target path relative to Windows directory
} DC_OFFLINE_FILE;

static const DC_OFFLINE_FILE g_offline_files[] = {
	{ L"dcrypt.sys",	L"Windows\\System32\\Drivers\\dcrypt.sys" }, // must be first
	{ L"dcrypt.sys",	L"Program Files\\dcrypt\\dcrypt.sys" },
	{ L"dcrypt.exe",	L"Program Files\\dcrypt\\dcrypt.exe" },
	{ L"dccon.exe",		L"Program Files\\dcrypt\\dccon.exe" },
	{ L"dcapi.dll",		L"Program Files\\dcrypt\\dcapi.dll" },
#ifdef _M_IX86
	{ L"DcsPkg_IA32.zip",L"Program Files\\dcrypt\\DcsPkg_IA32.zip" },
	{ L"Shim_IA32.zip",  L"Program Files\\dcrypt\\Shim_IA32.zip" },
#elifdef _M_ARM64
	{ L"DcsPkg_AA64.zip",L"Program Files\\dcrypt\\DcsPkg_AA64.zip" },
	{ L"Shim_AA64.zip",  L"Program Files\\dcrypt\\Shim_AA64.zip" },
#else
	{ L"DcsPkg_X64.zip",L"Program Files\\dcrypt\\DcsPkg_X64.zip" },
	{ L"Shim_X64.zip",  L"Program Files\\dcrypt\\Shim_X64.zip" },
#endif
	{ L"dcinst.exe",	L"Program Files\\dcrypt\\dcinst.exe" },
	{ L"license.txt",	L"Program Files\\dcrypt\\license.txt" }
};


typedef HRESULT(WINAPI *SHGETKNOWNFOLDERPATH) (
	_In_     const GUID*      rfid,
	_In_     DWORD            dwFlags,
	_In_opt_ HANDLE           hToken,
	_Out_    PWSTR            *ppszPath
	);

/*
 * Use RtlGetVersion to get Windows version because GetVersionEx is affected by application manifestation.
 */
typedef NTSTATUS(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);

static BOOL GetWindowsVersion(LPOSVERSIONINFOW lpVersionInformation)
{
	BOOL bRet = FALSE;
	RtlGetVersionPtr RtlGetVersionFn = (RtlGetVersionPtr)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlGetVersion");
	if (RtlGetVersionFn != NULL)
	{
		if (ERROR_SUCCESS == RtlGetVersionFn(lpVersionInformation))
			bRet = TRUE;
	}

	if (!bRet)
#pragma warning( disable : 4996 )
		bRet = GetVersionExW(lpVersionInformation);
#pragma warning( default : 4996 )

	return bRet;
}

int is_w10_reflect_supported()
{
	OSVERSIONINFOEXW os;
	os.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);
	if (GetWindowsVersion((LPOSVERSIONINFOW)&os) == FALSE)
		return 0;
	// starting from Windows 10 1607 (Build 14393), ReflectDrivers in Setupconfig.ini is supported
	return os.dwMajorVersion >= 10 && os.dwBuildNumber >= 14393;
}

BOOL GetSetupconfigLocation(wchar_t* path, DWORD cchSize)
{
	wchar_t szShell32Path[MAX_PATH] = { 0 };
	HMODULE hShell32 = NULL;
	BOOL bResult = FALSE;

	path[0] = 0;

	if (GetSystemDirectory(szShell32Path, MAX_PATH))
		StringCchCatW(szShell32Path, MAX_PATH, L"\\Shell32.dll");
	else
		StringCchCopyW(szShell32Path, MAX_PATH, L"C:\\Windows\\System32\\Shell32.dll");

	hShell32 = LoadLibrary(szShell32Path);
	if (hShell32)
	{
		SHGETKNOWNFOLDERPATH SHGetKnownFolderPathFn = (SHGETKNOWNFOLDERPATH)GetProcAddress(hShell32, "SHGetKnownFolderPath");
		if (SHGetKnownFolderPathFn)
		{
			wchar_t* pszUsersPath = NULL;
			if (S_OK == SHGetKnownFolderPathFn(&FOLDERID_UserProfiles, 0, NULL, &pszUsersPath))
			{
				StringCchPrintfW(path, cchSize, L"%s\\Default\\AppData\\Local\\Microsoft\\Windows\\WSUS\\", pszUsersPath);
				CoTaskMemFree(pszUsersPath);
				bResult = TRUE;
			}
		}
		FreeLibrary(hShell32);
	}

	if (!bResult && is_w10_reflect_supported())
	{
		StringCchPrintfW(path, cchSize, L"%c:\\Users\\Default\\AppData\\Local\\Microsoft\\Windows\\WSUS\\", szShell32Path[0]);
		bResult = TRUE;
	}

	return bResult;
}

int update_w10_reflect_driver()
{
	wchar_t szSetupconfigLocation[MAX_PATH + 20];
	DWORD	uInstallPathLen;
	TCHAR	szInstallPath[MAX_PATH], *p;
	wchar_t wszBuffer[2 * MAX_PATH];

	if (!GetSetupconfigLocation(szSetupconfigLocation, ARRAYSIZE(szSetupconfigLocation)))
		return ST_NF_FILE;
	CreateDirectoryW(szSetupconfigLocation, NULL);
	StringCchCatW(szSetupconfigLocation, ARRAYSIZE(szSetupconfigLocation), L"SetupConfig.ini");

	if (g_inst_dll == NULL || (uInstallPathLen = GetModuleFileName(g_inst_dll, szInstallPath, _countof(szInstallPath))) == 0) return ST_NF_FILE;
	if (uInstallPathLen >= _countof(szInstallPath) - 1 || (p = wcsrchr(szInstallPath, '\\')) == NULL) return ST_NF_FILE;
	*p = L'\0';

	if ( !((0 < GetPrivateProfileStringW(L"SetupConfig", L"ReflectDrivers", L"", wszBuffer, ARRAYSIZE(wszBuffer), szSetupconfigLocation)) && (_wcsicmp(wszBuffer, szInstallPath) == 0)) )
	{
		wsprintf(wszBuffer, L"\"%s\"", szInstallPath);
		WritePrivateProfileStringW(L"SetupConfig", L"ReflectDrivers", wszBuffer, szSetupconfigLocation);

		wsprintf(wszBuffer, L"\"%s\\PostOOBE.cmd\"", szInstallPath);
		WritePrivateProfileStringW(L"SetupConfig", L"PostOOBE", wszBuffer, szSetupconfigLocation);
	}

	return ST_OK;
}

int remove_w10_reflect_driver()
{
	wchar_t szSetupconfigLocation[MAX_PATH + 20];

	if (!GetSetupconfigLocation(szSetupconfigLocation, ARRAYSIZE(szSetupconfigLocation)))
		return ST_NF_FILE;
	StringCchCatW(szSetupconfigLocation, ARRAYSIZE(szSetupconfigLocation), L"SetupConfig.ini");

	if ( _waccess(szSetupconfigLocation,0) != 0 )
	{
		WritePrivateProfileStringW(L"SetupConfig", L"ReflectDrivers", NULL, szSetupconfigLocation);
		WritePrivateProfileStringW(L"SetupConfig", L"PostOOBE", NULL, szSetupconfigLocation);
	}

	return ST_OK;
}

// Helper function to enable a privilege
static BOOL EnablePrivilege(LPCWSTR privilegeName)
{
	HANDLE hToken;
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		return FALSE;

	if (!LookupPrivilegeValueW(NULL, privilegeName, &luid))
	{
		CloseHandle(hToken);
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
	{
		CloseHandle(hToken);
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		CloseHandle(hToken);
		return FALSE;
	}

	CloseHandle(hToken);
	return TRUE;
}

// Helper function to enable required privileges for registry hive operations
static BOOL EnableRegistryPrivileges()
{
	BOOL result = TRUE;
	result = EnablePrivilege(SE_BACKUP_NAME) && result;
	result = EnablePrivilege(SE_RESTORE_NAME) && result;
	return result;
}

// Helper function to remove a string from a REG_MULTI_SZ list
static BOOL RemoveFromMultiSz(wchar_t* buffer, DWORD bufferSize, const wchar_t* value)
{
	wchar_t* src = buffer;
	wchar_t* dst = buffer;
	BOOL found = FALSE;

	while (*src)
	{
		if (_wcsicmp(src, value) == 0)
		{
			found = TRUE;
			src += wcslen(src) + 1;
			continue;
		}

		if (src != dst)
		{
			size_t len = wcslen(src) + 1;
			wmemmove(dst, src, len);
			dst += len;
			src += len;
		}
		else
		{
			size_t len = wcslen(src) + 1;
			dst += len;
			src += len;
		}
	}

	if (found)
	{
		*dst = L'\0'; // Double null terminator
		if (dst > buffer)
			dst[1] = L'\0';
	}

	return found;
}

// Helper function to add a string to a REG_MULTI_SZ list
static BOOL AddToMultiSz(wchar_t* buffer, DWORD bufferSize, const wchar_t* value)
{
	wchar_t* p = buffer;
	DWORD len = (DWORD)wcslen(value);

	// Check if value already exists
	while (*p)
	{
		if (_wcsicmp(p, value) == 0)
			return TRUE; // Already present
		p += wcslen(p) + 1;
	}

	// Calculate current size
	DWORD currentSize = (DWORD)((p - buffer) * sizeof(wchar_t));
	DWORD neededSize = currentSize + (len + 1) * sizeof(wchar_t) + sizeof(wchar_t);

	if (neededSize > bufferSize)
		return FALSE; // Not enough space

	// Add new value at the end
	wcscpy_s(p, bufferSize / sizeof(wchar_t) - (p - buffer), value);
	p[len + 1] = L'\0'; // Double null terminator

	return TRUE;
}

// Helper function to prepend a string to a REG_MULTI_SZ list (adds at the beginning)
static BOOL PrependToMultiSz(wchar_t* buffer, DWORD bufferSize, const wchar_t* value)
{
	wchar_t* p = buffer;
	DWORD len = (DWORD)wcslen(value);
	DWORD currentSize = 0;
	wchar_t* end;

	// Check if value already exists at the beginning
	if (*p && _wcsicmp(p, value) == 0)
		return TRUE; // Already at the beginning

	// Find end of multi-sz and check if value exists elsewhere
	while (*p)
	{
		if (_wcsicmp(p, value) == 0)
		{
			// Value exists but not at the beginning - remove it first
			RemoveFromMultiSz(buffer, bufferSize, value);
			break;
		}
		p += wcslen(p) + 1;
	}

	// Calculate current size (excluding value if it was removed)
	p = buffer;
	while (*p)
		p += wcslen(p) + 1;
	currentSize = (DWORD)((p - buffer) * sizeof(wchar_t));

	// Calculate needed size: new value + existing content + double null
	DWORD neededSize = (len + 1) * sizeof(wchar_t) + currentSize + sizeof(wchar_t);
	if (neededSize > bufferSize)
		return FALSE; // Not enough space

	// Shift existing content to make room at the beginning
	if (currentSize > 0)
		wmemmove(buffer + len + 1, buffer, currentSize / sizeof(wchar_t));

	// Insert new value at the beginning
	wcscpy(buffer, value);

	// Ensure proper double null termination
	end = buffer + len + 1;
	while (*end)
		end += wcslen(end) + 1;
	end[1] = L'\0';

	return TRUE;
}

// Helper function to add a filter value to a registry key (prepends to REG_MULTI_SZ)
static LSTATUS AddFilterToRegistry(const wchar_t* keyPath, const wchar_t* valueName, const wchar_t* filterValue)
{
	LSTATUS lResult;
	HKEY hKey;
	DWORD dwType, dwSize;
	wchar_t multiSzBuffer[4096];

	lResult = RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_READ | KEY_WRITE, &hKey);
	if (lResult != ERROR_SUCCESS)
		return lResult;

	dwSize = sizeof(multiSzBuffer);
	ZeroMemory(multiSzBuffer, sizeof(multiSzBuffer));

	lResult = RegQueryValueExW(hKey, valueName, NULL, &dwType, (BYTE*)multiSzBuffer, &dwSize);
	if (lResult != ERROR_SUCCESS || dwType != REG_MULTI_SZ)
	{
		// Value doesn't exist, create it with just the filter
		wcscpy_s(multiSzBuffer, ARRAYSIZE(multiSzBuffer), filterValue);
		multiSzBuffer[wcslen(filterValue) + 1] = L'\0'; // Double null terminator
		dwSize = (DWORD)((wcslen(filterValue) + 2) * sizeof(wchar_t));
	}
	else
	{
		// Prepend filter to existing value (must be first)
		PrependToMultiSz(multiSzBuffer, sizeof(multiSzBuffer), filterValue);

		// Calculate size of multi-sz
		wchar_t* p = multiSzBuffer;
		while (*p)
			p += wcslen(p) + 1;
		dwSize = (DWORD)((p - multiSzBuffer + 1) * sizeof(wchar_t));
	}

	lResult = RegSetValueExW(hKey, valueName, 0, REG_MULTI_SZ, (BYTE*)multiSzBuffer, dwSize);
	RegCloseKey(hKey);

	return lResult;
}

// Helper function to remove a filter value from a registry key (removes from REG_MULTI_SZ)
static LSTATUS RemoveFilterFromRegistry(const wchar_t* keyPath, const wchar_t* valueName, const wchar_t* filterValue)
{
	LSTATUS lResult;
	HKEY hKey;
	DWORD dwType, dwSize;
	wchar_t multiSzBuffer[4096];

	lResult = RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_READ | KEY_WRITE, &hKey);
	if (lResult != ERROR_SUCCESS)
		return lResult;

	dwSize = sizeof(multiSzBuffer);
	ZeroMemory(multiSzBuffer, sizeof(multiSzBuffer));

	lResult = RegQueryValueExW(hKey, valueName, NULL, &dwType, (BYTE*)multiSzBuffer, &dwSize);
	if (lResult == ERROR_SUCCESS && dwType == REG_MULTI_SZ)
	{
		if (RemoveFromMultiSz(multiSzBuffer, sizeof(multiSzBuffer), filterValue))
		{
			// Calculate size of multi-sz
			wchar_t* p = multiSzBuffer;
			while (*p)
				p += wcslen(p) + 1;
			dwSize = (DWORD)((p - multiSzBuffer + 1) * sizeof(wchar_t));

			// If empty, delete the value
			if (multiSzBuffer[0] == L'\0')
				lResult = RegDeleteValueW(hKey, valueName);
			else
				lResult = RegSetValueExW(hKey, valueName, 0, REG_MULTI_SZ, (BYTE*)multiSzBuffer, dwSize);
		}
	}

	RegCloseKey(hKey);
	return lResult;
}

int install_dc_offline(const wchar_t* windows_path)
{
	wchar_t hivePath[MAX_PATH];
	wchar_t sourcePath[MAX_PATH];
	wchar_t sourceFile[MAX_PATH];
	wchar_t targetFile[MAX_PATH];
	wchar_t* p;
	DWORD uInstallPathLen;
	LSTATUS lResult;
	HKEY hKey;
	DWORD dwValue;

	if (windows_path == NULL)
		return ST_INVALID_PARAM;

	// Enable required privileges for registry operations
	if (!EnableRegistryPrivileges())
		return ST_ACCESS_DENIED;

	// Build path to SYSTEM hive
	StringCchPrintfW(hivePath, ARRAYSIZE(hivePath), L"%s\\Windows\\System32\\Config\\SYSTEM", windows_path);

	// Check if hive exists
	if (_waccess(hivePath, 0) != 0)
		return ST_NF_FILE;

	// Get source path (where dcrypt binaries are located)
	if (g_inst_dll == NULL || (uInstallPathLen = GetModuleFileName(g_inst_dll, sourcePath, _countof(sourcePath))) == 0)
		return ST_NF_FILE;
	if (uInstallPathLen >= _countof(sourcePath) - 1 || (p = wcsrchr(sourcePath, L'\\')) == NULL)
		return ST_NF_FILE;
	*p = L'\0';

	// Check if OFFLINE_SYSTEM hive is already loaded
	lResult = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"OFFLINE_SYSTEM", 0, KEY_READ, &hKey);
	if (lResult == ERROR_SUCCESS)
	{
		RegCloseKey(hKey);
		// Try to unload it first
		RegUnLoadKeyW(HKEY_LOCAL_MACHINE, L"OFFLINE_SYSTEM");
	}

	// Load the offline SYSTEM hive
	lResult = RegLoadKeyW(HKEY_LOCAL_MACHINE, L"OFFLINE_SYSTEM", hivePath);
	if (lResult != ERROR_SUCCESS)
		return ST_REG_ERROR;

	// Create dcrypt service key
	lResult = RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"OFFLINE_SYSTEM\\ControlSet001\\Services\\dcrypt",
		0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
	if (lResult != ERROR_SUCCESS)
	{
		RegUnLoadKeyW(HKEY_LOCAL_MACHINE, L"OFFLINE_SYSTEM");
		return ST_REG_ERROR;
	}

	// Set Type = 1 (SERVICE_KERNEL_DRIVER)
	dwValue = 1;
	RegSetValueExW(hKey, L"Type", 0, REG_DWORD, (BYTE*)&dwValue, sizeof(dwValue));

	// Set Start = 0 (SERVICE_BOOT_START)
	dwValue = 0;
	RegSetValueExW(hKey, L"Start", 0, REG_DWORD, (BYTE*)&dwValue, sizeof(dwValue));

	// Set ErrorControl = 3 (SERVICE_ERROR_CRITICAL)
	dwValue = 3;
	RegSetValueExW(hKey, L"ErrorControl", 0, REG_DWORD, (BYTE*)&dwValue, sizeof(dwValue));

	// Set ImagePath
	const wchar_t* imagePath = L"\\SystemRoot\\System32\\drivers\\dcrypt.sys";
	RegSetValueExW(hKey, L"ImagePath", 0, REG_EXPAND_SZ, (BYTE*)imagePath,
		(DWORD)((wcslen(imagePath) + 1) * sizeof(wchar_t)));

	// Set DisplayName
	const wchar_t* displayName = L"DiskCryptor driver";
	RegSetValueExW(hKey, L"DisplayName", 0, REG_SZ, (BYTE*)displayName,
		(DWORD)((wcslen(displayName) + 1) * sizeof(wchar_t)));

	// Set Description
	RegSetValueExW(hKey, L"Description", 0, REG_SZ, (BYTE*)displayName,
		(DWORD)((wcslen(displayName) + 1) * sizeof(wchar_t)));

	// Set Group
	const wchar_t* group = L"Filter";
	RegSetValueExW(hKey, L"Group", 0, REG_SZ, (BYTE*)group,
		(DWORD)((wcslen(group) + 1) * sizeof(wchar_t)));

	// Set DependOnService
	wchar_t depend[] = L"FltMgr\0";
	RegSetValueExW(hKey, L"DependOnService", 0, REG_MULTI_SZ, (BYTE*)depend, sizeof(depend));

	RegCloseKey(hKey);

	// Create Instances subkey
	lResult = RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"OFFLINE_SYSTEM\\ControlSet001\\Services\\dcrypt\\Instances",
		0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
	if (lResult == ERROR_SUCCESS)
	{
		const wchar_t* defaultInstance = L"dcrypt";
		RegSetValueExW(hKey, L"DefaultInstance", 0, REG_SZ, (BYTE*)defaultInstance,
			(DWORD)((wcslen(defaultInstance) + 1) * sizeof(wchar_t)));
		RegCloseKey(hKey);
	}

	// Create Instances\dcrypt subkey
	lResult = RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"OFFLINE_SYSTEM\\ControlSet001\\Services\\dcrypt\\Instances\\dcrypt",
		0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
	if (lResult == ERROR_SUCCESS)
	{
		const wchar_t* altitude = L"87150";
		RegSetValueExW(hKey, L"Altitude", 0, REG_SZ, (BYTE*)altitude,
			(DWORD)((wcslen(altitude) + 1) * sizeof(wchar_t)));

		dwValue = 0;
		RegSetValueExW(hKey, L"Flags", 0, REG_DWORD, (BYTE*)&dwValue, sizeof(dwValue));

		RegCloseKey(hKey);
	}

	// Create config subkey
	lResult = RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"OFFLINE_SYSTEM\\ControlSet001\\Services\\dcrypt\\config",
		0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
	if (lResult == ERROR_SUCCESS)
	{
		dwValue = (CONF_HW_CRYPTO | CONF_AUTOMOUNT_BOOT | CONF_ENABLE_SSD_OPT);
		RegSetValueExW(hKey, L"Flags", 0, REG_DWORD, (BYTE*)&dwValue, sizeof(dwValue));

		BYTE hotkeys[16] = {0};
		RegSetValueExW(hKey, L"Hotkeys", 0, REG_BINARY, hotkeys, sizeof(hotkeys));

		dwValue = DC_DRIVER_VER;
		RegSetValueExW(hKey, L"sysBuild", 0, REG_DWORD, (BYTE*)&dwValue, sizeof(dwValue));

		RegCloseKey(hKey);
	}

	// Add dcrypt to LowerFilters for Volume class
	AddFilterToRegistry(L"OFFLINE_SYSTEM\\ControlSet001\\Control\\Class\\{71A27CDD-812A-11D0-BEC7-08002BE2092F}",
		L"LowerFilters", L"dcrypt");

	// Add dcrypt to UpperFilters for DiskDrive class
	AddFilterToRegistry(L"OFFLINE_SYSTEM\\ControlSet001\\Control\\Class\\{4D36E967-E325-11CE-BFC1-08002BE10318}",
		L"UpperFilters", L"dcrypt");

	// Add dcrypt.sys to DumpFilters for CrashControl
	AddFilterToRegistry(L"OFFLINE_SYSTEM\\ControlSet001\\Control\\CrashControl",
		L"DumpFilters", L"dcrypt.sys");

	// Unload the hive
	RegUnLoadKeyW(HKEY_LOCAL_MACHINE, L"OFFLINE_SYSTEM");

	// create program directory
	StringCchPrintfW(targetFile, ARRAYSIZE(targetFile), L"%s\\Program Files\\dcrypt", windows_path);
	CreateDirectoryW(targetFile, NULL);

	// Copy files
	for (int i = 0; i < ARRAYSIZE(g_offline_files); i++)
	{
		StringCchPrintfW(sourceFile, ARRAYSIZE(sourceFile), L"%s\\%s", sourcePath, g_offline_files[i].source);
		StringCchPrintfW(targetFile, ARRAYSIZE(targetFile), L"%s\\%s", windows_path, g_offline_files[i].target);
		CopyFileW(sourceFile, targetFile, FALSE);
	}

	// add redirector
	StringCchPrintfW(targetFile, ARRAYSIZE(targetFile), L"%s\\Windows\\dccon.cmd", windows_path);
	const char dccon_cmd[] = 
	"rem @echo off\n"
	"if %1 == -gui goto gui\n"
	"\"\\Program Files\\dcrypt\\dccon.exe\" %*\n"
	"goto end\n"
	":gui\n"
	"start \"\" \"\\Program Files\\dcrypt\\dcrypt.exe\"\n"
	":end\n";
	save_file(targetFile, (void*)dccon_cmd, (int)strlen(dccon_cmd));

	return ST_OK;
}

int remove_dc_offline(const wchar_t* windows_path)
{
	wchar_t hivePath[MAX_PATH];
	wchar_t targetFile[MAX_PATH];
	LSTATUS lResult;
	HKEY hKey;

	if (windows_path == NULL)
		return ST_INVALID_PARAM;

	// Enable required privileges for registry operations
	if (!EnableRegistryPrivileges())
		return ST_ACCESS_DENIED;

	// Build path to SYSTEM hive
	StringCchPrintfW(hivePath, ARRAYSIZE(hivePath), L"%s\\Windows\\System32\\Config\\SYSTEM", windows_path);

	// Check if hive exists
	if (_waccess(hivePath, 0) != 0)
		return ST_NF_FILE;

	// Check if OFFLINE_SYSTEM hive is already loaded
	lResult = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"OFFLINE_SYSTEM", 0, KEY_READ, &hKey);
	if (lResult == ERROR_SUCCESS)
	{
		RegCloseKey(hKey);
		// Try to unload it first
		RegUnLoadKeyW(HKEY_LOCAL_MACHINE, L"OFFLINE_SYSTEM");
	}

	// Load the offline SYSTEM hive
	lResult = RegLoadKeyW(HKEY_LOCAL_MACHINE, L"OFFLINE_SYSTEM", hivePath);
	if (lResult != ERROR_SUCCESS)
		return ST_REG_ERROR;

	// Remove dcrypt from LowerFilters for Volume class
	RemoveFilterFromRegistry(L"OFFLINE_SYSTEM\\ControlSet001\\Control\\Class\\{71A27CDD-812A-11D0-BEC7-08002BE2092F}",
		L"LowerFilters", L"dcrypt");

	// Remove dcrypt from UpperFilters for DiskDrive class
	RemoveFilterFromRegistry(L"OFFLINE_SYSTEM\\ControlSet001\\Control\\Class\\{4D36E967-E325-11CE-BFC1-08002BE10318}",
		L"UpperFilters", L"dcrypt");

	// Remove dcrypt.sys from DumpFilters for CrashControl
	RemoveFilterFromRegistry(L"OFFLINE_SYSTEM\\ControlSet001\\Control\\CrashControl",
		L"DumpFilters", L"dcrypt.sys");

	// Delete dcrypt service key
	RegDeleteTreeW(HKEY_LOCAL_MACHINE, L"OFFLINE_SYSTEM\\ControlSet001\\Services\\dcrypt");

	// Unload the hive
	RegUnLoadKeyW(HKEY_LOCAL_MACHINE, L"OFFLINE_SYSTEM");

	// Delete files driver
	StringCchPrintfW(targetFile, ARRAYSIZE(targetFile), L"%s\\%s", windows_path, g_offline_files[0].target);
	DeleteFileW(targetFile);

	// remove redirectors
	StringCchPrintfW(targetFile, ARRAYSIZE(targetFile), L"%s\\Windows\\dccon.cmd", windows_path);
	DeleteFileW(targetFile);

	return ST_OK;
}