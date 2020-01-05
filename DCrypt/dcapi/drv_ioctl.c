/*
    *
    * DiskCryptor - open source partition encryption tool
	* Copyright (c) 2008-2013
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
#include "defines.h"
#include "drv_ioctl.h"
#include "misc.h"
#include "dcapi.h"

int dc_open_device()
{
	HANDLE h_device;

	h_device = CreateFile(DC_WIN32_NAME, 0, 0, NULL, OPEN_EXISTING, 0, NULL);

	if (h_device != INVALID_HANDLE_VALUE) {
		TlsSetValue(g_tls_index, h_device);
		return ST_OK;
	}
    return ST_ERROR;
}

int dc_is_old_runned()
{
	HANDLE h_device;

	h_device = CreateFile(DC_OLD_WIN32_NAME, 0, 0, NULL, OPEN_EXISTING, 0, NULL);

	if (h_device != INVALID_HANDLE_VALUE) {
		CloseHandle(h_device);
		return 1;
	}
	return 0;
}

DWORD dc_device_control(DWORD dwIoControlCode, LPCVOID lpInBuffer, DWORD nInBufferSize, LPVOID lpOutBuffer, DWORD nOutBufferSize)
{
	HANDLE h_device;
	DWORD  bytes;

	if ( (h_device = TlsGetValue(g_tls_index)) == NULL )
	{
		if ( (h_device = CreateFile(DC_WIN32_NAME, 0, 0, NULL, OPEN_EXISTING, 0, NULL)) == INVALID_HANDLE_VALUE )
		{
			return ERROR_DC_NOT_FOUND;
		}
		TlsSetValue(g_tls_index, h_device);
	}

	if (DeviceIoControl(h_device, dwIoControlCode, (PVOID)lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, &bytes, NULL) == FALSE)
	{
		return GetLastError();
	} else {
		return NO_ERROR;
	}
}

static int dc_get_vol_info(wchar_t *name, vol_inf *info)
{
	HANDLE   h_device = TlsGetValue(g_tls_index);
	dc_ioctl dctl;
	int      succs;
	u32      bytes;
	int      resl;
	
	do
	{
		wcschr(name, L'}')[1] = 0;
		wcscpy(info->w32_device, name);

		_snwprintf(
			dctl.device, countof(dctl.device), L"\\??\\Volume%s", wcschr(name, '{'));

		succs = DeviceIoControl(
			h_device, DC_CTL_RESOLVE,
			&dctl, sizeof(dctl), &dctl, sizeof(dctl), &bytes, NULL);

		if ( (succs == 0) || (dctl.status != ST_OK) ) {
			resl = ST_ERROR; break;
		}

		wcscpy(info->device, dctl.device);

		succs = DeviceIoControl(
			h_device, DC_CTL_STATUS,
			&dctl, sizeof(dc_ioctl), &info->status, sizeof(dc_status), &bytes, NULL);

		if (succs == 0) {
			resl = ST_ERROR; break;
		} else 
		{
			if (info->status.mnt_point[0] == 0) {
				wcscpy(info->status.mnt_point, info->w32_device);
			}
			resl = ST_OK;
		}
	} while (0);
	
	return resl;
}

int dc_get_boot_device(wchar_t *device)
{
	dc_ioctl dctl;
	u32      bytes;
	int      succs;

	wcscpy(dctl.device, L"\\ArcName\\multi(0)disk(0)rdisk(0)partition(1)");

	succs = DeviceIoControl(
		TlsGetValue(g_tls_index), DC_CTL_RESOLVE, 
		&dctl, sizeof(dctl), &dctl, sizeof(dctl), &bytes, NULL);

	if (succs != 0) 
	{
		if (dctl.status == ST_OK) {
			wcscpy(device, dctl.device);			
		}
		return dctl.status;
	} else {		
		return ST_ERROR;
	}
}

int dc_first_volume(vol_inf *info)
{
	wchar_t name[MAX_PATH];
	
	info->find = FindFirstVolume(name, countof(name));

	if (info->find != INVALID_HANDLE_VALUE) 
	{
		if (dc_get_vol_info(name, info) != ST_OK) {
			return dc_next_volume(info);
		} else {
			return ST_OK;
		}
	} 

	return ST_ERROR;
}

int dc_next_volume(vol_inf *info)
{
	wchar_t name[MAX_PATH];

	FindNextVolume(
		info->find, name, countof(name));

	if (GetLastError() != ERROR_NO_MORE_FILES) 
	{
		if (dc_get_vol_info(name, info) != ST_OK) {
			return dc_next_volume(info);
		} else {
			return ST_OK;
		}
	} else {
		FindVolumeClose(info->find);		
	}

	return ST_ERROR;
}

int dc_get_version()
{
	int version;

	if (dc_device_control(DC_GET_VERSION, NULL, 0, &version, sizeof(version)) != NO_ERROR)
	{
		version = 0;
	}
	return version;
}

int dc_mount_volume(wchar_t *device, dc_pass *password, int flags)
{
	dc_ioctl *dctl;
	u32       bytes;
	int       resl;
	int       succs;

	do
	{
		if ( (dctl = secure_alloc(sizeof(dc_ioctl))) == NULL ) {
			resl = ST_NOMEM; break;
		}

		wcscpy(dctl->device, device); dctl->flags = flags;

		if (password != NULL) {
			memcpy(&dctl->passw1, password, sizeof(dc_pass));
		}

		succs = DeviceIoControl(
			TlsGetValue(g_tls_index), DC_CTL_MOUNT,
			dctl, sizeof(dc_ioctl), dctl, sizeof(dc_ioctl), &bytes, NULL);

		if (succs == 0) {
			resl = ST_ERROR; break;
		}

		resl = dctl->status;
	} while (0);

	if (dctl != NULL) {
		secure_free(dctl);
	}

	return resl;
}

int dc_mount_all(dc_pass *password, int *mounted, int flags)
{
	dc_ioctl *dctl;
	u32       bytes;
	int       resl;
	int       succs;

	do
	{
		if ( (dctl = secure_alloc(sizeof(dc_ioctl))) == NULL ) {
			resl = ST_NOMEM; break;
		}

		if (password != NULL) {
			memcpy(&dctl->passw1, password, sizeof(dc_pass));			
		}

		dctl->flags = flags;

		succs = DeviceIoControl(
			TlsGetValue(g_tls_index), DC_CTL_MOUNT_ALL,
			dctl, sizeof(dc_ioctl), dctl, sizeof(dc_ioctl), &bytes, NULL);

		if (succs == 0) {
			resl = ST_ERROR; break;
		}

		resl = dctl->status; 
		mounted[0] = dctl->n_mount;
	} while (0);

	if (dctl != NULL) {
		secure_free(dctl);
	}

	return resl;
}

int dc_unmount_volume(wchar_t *device, int flags)
{
	HANDLE    h_device = TlsGetValue(g_tls_index);
	dc_ioctl  dctl;
	dc_status status;
	u32       bytes;
	int       succs;
	int       resl;
	wchar_t   mnt_p[MAX_PATH];

	wcscpy(dctl.device, device);

	do
	{
		succs = DeviceIoControl(
			h_device, DC_CTL_STATUS, 
			&dctl, sizeof(dc_ioctl), &status, sizeof(dc_status), &bytes, NULL
			);

		if ( (succs == 0) || (IS_UNMOUNTABLE(&status) == 0) ) {
			resl = ST_UNMOUNTABLE; break;
		}

		dctl.flags = flags;

		succs = DeviceIoControl(
			h_device, DC_CTL_UNMOUNT,
			&dctl, sizeof(dc_ioctl), &dctl, sizeof(dc_ioctl), &bytes, NULL
			);

		if (succs == 0) {
			resl = ST_ERROR; break;
		}

		if ( (resl = dctl.status) != ST_OK ) {
			break;
		}

		if ( (flags & MF_DELMP) || (status.mnt_flags & MF_DELMP) ) 
		{
			_snwprintf(
				mnt_p, countof(mnt_p), L"%s\\", status.mnt_point);

			DeleteVolumeMountPoint(mnt_p);
		}
	} while (0);

	return resl;
}

int dc_unmount_all()
{
	vol_inf info;
	
	if (dc_first_volume(&info) == ST_OK)
	{
		do
		{
			if (info.status.flags & F_ENABLED) {
				dc_unmount_volume(info.device, MF_FORCE);
			}
		} while (dc_next_volume(&info) == ST_OK);
	}
	
	return ST_OK;
}

int dc_add_password(dc_pass *password)
{
	dc_ioctl *dctl;
	u32       bytes;
	int       resl;
	int       succs;

	do
	{
		if ( (dctl = secure_alloc(sizeof(dc_ioctl))) == NULL ) {
			resl = ST_NOMEM; break;
		}

		memcpy(&dctl->passw1, password, sizeof(dc_pass));

		succs = DeviceIoControl(
			TlsGetValue(g_tls_index), DC_CTL_ADD_PASS,
			dctl, sizeof(dc_ioctl), dctl, sizeof(dc_ioctl), &bytes, NULL
			);

		if (succs == 0) {
			resl = ST_ERROR;
		} else {
			resl = dctl->status;
		}
	} while (0);

	if (dctl != NULL) {
		secure_free(dctl);
	}
	return resl;
}

int dc_start_encrypt(wchar_t *device, dc_pass *password, crypt_info *crypt)
{
	dc_ioctl *dctl;
	u32       bytes;
	int       resl;
	int       succs;

	do
	{
		if ( (dctl = secure_alloc(sizeof(dc_ioctl))) == NULL ) {
			resl = ST_NOMEM; break;
		}

		wcscpy(dctl->device, device);
		memcpy(&dctl->passw1, password, sizeof(dc_pass));
		
		dctl->crypt = crypt[0];

		succs = DeviceIoControl(
			TlsGetValue(g_tls_index), DC_CTL_ENCRYPT_START,
			dctl, sizeof(dc_ioctl), dctl, sizeof(dc_ioctl), &bytes, NULL);

		if (succs == 0) {
			resl = ST_ERROR; break;
		}

		resl = dctl->status;
	} while (0);

	if (dctl != NULL) {
		secure_free(dctl);
	}

	return resl;
}

int dc_start_re_encrypt(wchar_t *device, dc_pass *password, crypt_info *crypt)
{
	dc_ioctl *dctl;
	u32       bytes;
	int       resl;
	int       succs;

	do
	{
		if ( (dctl = secure_alloc(sizeof(dc_ioctl))) == NULL ) {
			resl = ST_NOMEM; break;
		}

		wcscpy(dctl->device, device);
		memcpy(&dctl->passw1, password, sizeof(dc_pass));

		dctl->crypt = crypt[0];

		succs = DeviceIoControl(
			TlsGetValue(g_tls_index), DC_CTL_RE_ENC_START,
			dctl, sizeof(dc_ioctl), dctl, sizeof(dc_ioctl), &bytes, NULL);

		if (succs == 0) {
			resl = ST_ERROR; break;
		}

		resl = dctl->status;
	} while (0);

	if (dctl != NULL) {
		secure_free(dctl);
	}

	return resl;
}

int dc_start_decrypt(wchar_t *device, dc_pass *password)
{
	dc_ioctl *dctl;
	u32       bytes;
	int       resl;
	int       succs;

	do
	{
		if ( (dctl = secure_alloc(sizeof(dc_ioctl))) == NULL ) {
			resl = ST_NOMEM; break;
		}

		wcscpy(dctl->device, device);
		memcpy(&dctl->passw1, password, sizeof(dc_pass));

		succs = DeviceIoControl(
			TlsGetValue(g_tls_index), DC_CTL_DECRYPT_START,
			dctl, sizeof(dc_ioctl), dctl, sizeof(dc_ioctl), &bytes, NULL);

		if (succs == 0) {
			resl = ST_ERROR; break;
		}

		resl = dctl->status;
	} while (0);

	if (dctl != NULL) {
		secure_free(dctl);
	}

	return resl;
}

int dc_change_password(
	  wchar_t *device, dc_pass *old_pass, dc_pass *new_pass
	  )
{
	dc_ioctl *dctl;
	u32       bytes;
	int       resl;
	int       succs;

	do
	{
		if ( (dctl = secure_alloc(sizeof(dc_ioctl))) == NULL ) {
			resl = ST_NOMEM; break;
		}

		wcscpy(dctl->device, device);
		memcpy(&dctl->passw1, old_pass, sizeof(dc_pass));
		memcpy(&dctl->passw2, new_pass, sizeof(dc_pass));

		succs = DeviceIoControl(
			TlsGetValue(g_tls_index), DC_CTL_CHANGE_PASS,
			dctl, sizeof(dc_ioctl), dctl, sizeof(dc_ioctl), &bytes, NULL);

		if (succs == 0) {
			resl = ST_ERROR; break;
		}

		resl = dctl->status;
	} while (0);

	if (dctl != NULL) {
		secure_free(dctl);
	}

	return resl;
}

int dc_enc_step(wchar_t *device, int wp_mode)
{
	dc_ioctl dctl;
	u32      bytes;
	int      succs;

	wcscpy(dctl.device, device);

	dctl.crypt.wp_mode = wp_mode;

	succs = DeviceIoControl(
		TlsGetValue(g_tls_index), DC_CTL_ENCRYPT_STEP,
		&dctl, sizeof(dc_ioctl), &dctl, sizeof(dc_ioctl), &bytes, NULL);

	if (succs == 0) {
		return ST_ERROR;
	} else {
		return dctl.status;
	}
}

int dc_dec_step(wchar_t *device)
{
	dc_ioctl dctl;
	u32      bytes;
	int      succs;

	wcscpy(dctl.device, device);

	succs = DeviceIoControl(
		TlsGetValue(g_tls_index), DC_CTL_DECRYPT_STEP,
		&dctl, sizeof(dc_ioctl), &dctl, sizeof(dc_ioctl), &bytes, NULL);

	if (succs == 0) {
		return ST_ERROR;
	} else {
		return dctl.status;
	}
}

int dc_format_step(wchar_t *device, int wp_mode)
{
	dc_ioctl dctl;
	u32      bytes;
	int      succs;

	wcscpy(dctl.device, device);

	dctl.crypt.wp_mode = wp_mode;

	succs = DeviceIoControl(
		TlsGetValue(g_tls_index), DC_FORMAT_STEP,
		&dctl, sizeof(dc_ioctl), &dctl, sizeof(dc_ioctl), &bytes, NULL);

	if (succs == 0) {
		return ST_ERROR;
	} else {
		return dctl.status;
	}
}

int dc_sync_enc_state(wchar_t *device)
{
	dc_ioctl dctl;
	u32      bytes;
	int      succs;

	wcscpy(dctl.device, device);

	succs = DeviceIoControl(
		TlsGetValue(g_tls_index), DC_CTL_SYNC_STATE,
		&dctl, sizeof(dc_ioctl), &dctl, sizeof(dc_ioctl), &bytes, NULL);

	if (succs == 0) {
		return ST_ERROR;
	} else {
		return dctl.status;
	}
}

int dc_get_device_status(wchar_t *device, dc_status *status)
{
	dc_ioctl dctl;
	u32      bytes;
	int      succs;

	wcscpy(dctl.device, device);

	succs = DeviceIoControl(
		TlsGetValue(g_tls_index), DC_CTL_STATUS,
		&dctl, sizeof(dc_ioctl), status, sizeof(dc_status), &bytes, NULL);

	if (succs == 0) {
		return ST_ERROR;
	} else
	{
		if (status->mnt_point[0] == 0) {
			wcscpy(status->mnt_point, device); /* -- */
		}
		return dctl.status;
	}
}

int dc_benchmark(int cipher, dc_bench_info *info)
{
	u32 bytes;
	int succs;

	succs = DeviceIoControl(TlsGetValue(g_tls_index), DC_CTL_BENCHMARK, 
		&cipher, sizeof(cipher), info, sizeof(dc_bench_info), &bytes, NULL);

	return succs != 0 ? ST_OK : ST_ERROR;
}

int dc_start_format(wchar_t *device, dc_pass *password, crypt_info *crypt)
{
	dc_ioctl *dctl;
	u32       bytes;
	int       resl;
	int       succs;

	do
	{
		if ( (dctl = secure_alloc(sizeof(dc_ioctl))) == NULL ) {
			resl = ST_NOMEM; break;
		}

		wcscpy(dctl->device, device);
		memcpy(&dctl->passw1, password, sizeof(dc_pass));

		dctl->crypt = crypt[0];

		succs = DeviceIoControl(
			TlsGetValue(g_tls_index), DC_FORMAT_START,
			dctl, sizeof(dc_ioctl), dctl, sizeof(dc_ioctl), &bytes, NULL);

		if (succs == 0) {
			resl = ST_ERROR; break;
		}

		resl = dctl->status;
	} while (0);

	if (dctl != NULL) {
		secure_free(dctl);
	}

	return resl;
}

int dc_done_format(wchar_t *device)
{
	dc_ioctl dctl;
	u32      bytes;
	int      succs;

	wcscpy(dctl.device, device);

	succs = DeviceIoControl(
		TlsGetValue(g_tls_index), DC_FORMAT_DONE,
		&dctl, sizeof(dc_ioctl), &dctl, sizeof(dc_ioctl), &bytes, NULL);

	if (succs != 0) {
		return dctl.status;
	} else {
		return ST_ERROR;
	}
}

void dc_get_bsod()
{
	u32 bytes;

	DeviceIoControl(
		TlsGetValue(g_tls_index), DC_CTL_BSOD, NULL, 0, NULL, 0, &bytes, NULL);
}

int dc_backup_header(wchar_t *device, dc_pass *password, void *out)
{
	dc_backup_ctl *back;
	u32            bytes;
	int            succs;
	int            resl;

	do
	{
		if ( (back = secure_alloc(sizeof(dc_backup_ctl))) == NULL ) {
			resl = ST_NOMEM; break;
		}

		wcscpy(back->device, device);
		memcpy(&back->pass, password, sizeof(dc_pass));

		succs = DeviceIoControl(
			TlsGetValue(g_tls_index), DC_BACKUP_HEADER,
			back, sizeof(dc_backup_ctl), back, sizeof(dc_backup_ctl), &bytes, NULL);

		if (succs == 0) {
			resl = ST_ERROR; break;
		}

		memcpy(out, back->backup, DC_AREA_SIZE);
		resl = back->status;
	} while (0);

	if (back != NULL) {
		secure_free(back);
	}

	return resl;
}

int dc_restore_header(wchar_t *device, dc_pass *password, void *in)
{
	dc_backup_ctl *back;
	u32            bytes;
	int            succs;
	int            resl;

	do
	{
		if ( (back = secure_alloc(sizeof(dc_backup_ctl))) == NULL ) {
			resl = ST_NOMEM; break;
		}

		wcscpy(back->device, device);
		memcpy(&back->pass, password, sizeof(dc_pass));
		memcpy(back->backup, in, DC_AREA_SIZE);

		succs = DeviceIoControl(
			TlsGetValue(g_tls_index), DC_RESTORE_HEADER,
			back, sizeof(dc_backup_ctl), back, sizeof(dc_backup_ctl), &bytes, NULL);

		if (succs == 0) {
			resl = ST_ERROR; break;
		}
		
		resl = back->status;
	} while (0);

	if (back != NULL) {
		secure_free(back);
	}

	return resl;
}
