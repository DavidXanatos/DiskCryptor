/*
    *
    * DiskCryptor - open source partition encryption tool
	* Copyright (c) 2008-2011
	* ntldr <ntldr@diskcryptor.net> PGP key ID - 0xC48251EB4F8E4E6E
    * partial copyright Juergen Schmied and Jon Griffiths

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
#include <aclapi.h>
#include <ntddscsi.h>
#include <stdio.h>
#include <math.h>

#include "misc.h"
#include "drv_ioctl.h"

typedef int (WINAPI fmt_callback) (int unk1, int unk2, int unk3);

typedef void (WINAPI *PFORMAT) (
	 wchar_t *root_path, u32 unk1, wchar_t *fs_type, wchar_t *label, u32 unk2, fmt_callback callback
	 );

#define KB ((u64)1024)
#define MB (KB*KB)
#define GB (KB*KB*KB)
#define TB (KB*KB*KB*KB)
#define PB (KB*KB*KB*KB*KB)

static struct {
  u64     limit;
  double  divisor; 
  double  normaliser;
  int     decimals;
  wchar_t prefix;
} b_formats[] = {
	{ 10*KB,   10.24,        100.0,  2, 'K' }, /* 10 KB */
    { 100*KB,  102.4,        10.0,   1, 'K' }, /* 100 KB */
    { 1000*KB, 1024.0,       1.0,    0, 'M' }, /* 1000 KB */
    { 10*MB,   10485.76,     100.0,  2, 'M' }, /* 10 MB */
    { 100*MB,  104857.6,     10.0,   1, 'M' }, /* 100 MB */
    { 1000*MB, 1048576.0,    1.0,    0, 'M' }, /* 1000 MB */
    { 10*GB,   10737418.24,  100.0,  2, 'G' }, /* 10 GB */
    { 100*GB,  107374182.4,  10.0,   1, 'G' }, /* 100 GB */
    { 1000*GB, 1073741824.0, 1.0,    0, 'G' }, /* 1000 GB */
    { 10*TB,   10485.76,     100.0,  2, 'T' }, /* 10 TB */
    { 100*TB,  104857.6,     10.0,   1, 'T' }, /* 100 TB */
    { 1000*TB, 1048576.0,    1.0,    0, 'T' }, /* 1000 TB */
    { 10*PB,   10737418.24,  100.00, 2, 'P' }, /* 10 PB */
    { 100*PB,  107374182.4,  10.00,  1, 'P' }, /* 100 PB */
    { 1000*PB, 1073741824.0, 1.00,   0, 'P' }  /* 1000 PB */
};

typedef BOOL (WINAPI *ISWOW64PROCESS)(HANDLE, PBOOL);

int enable_privilege(wchar_t *name)
{
	HANDLE           h_token = NULL;
	TOKEN_PRIVILEGES tp;
	LUID             luid;
	int              resl;

	do
	{
		OpenProcessToken(
			GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &h_token);

		if (h_token == NULL) {
			resl = ST_ACCESS_DENIED; break;
		}

		if (LookupPrivilegeValue(NULL, name, &luid) == FALSE) {
			resl = ST_ACCESS_DENIED; break;
		}

		tp.PrivilegeCount           = 1;
		tp.Privileges[0].Luid       = luid;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (AdjustTokenPrivileges(
			h_token, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL) == FALSE)
		{
			resl = ST_ACCESS_DENIED;			
		} else {
			resl = ST_OK;
		}
	} while (0);

	if (h_token != NULL) {
		CloseHandle(h_token);
	}

	return resl;
}

int is_admin()
{
	SID_IDENTIFIER_AUTHORITY autort  = SECURITY_NT_AUTHORITY;
	PSID                     adm_sid = NULL;
	BOOL                     member  = FALSE;
	int                      resl;

	do
	{
		AllocateAndInitializeSid(
			&autort, 2, SECURITY_BUILTIN_DOMAIN_RID, 
			DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adm_sid);

		if (adm_sid == NULL) {
			resl = ST_NOMEM; break;
		}

		if (CheckTokenMembership(NULL, adm_sid, &member) == FALSE) {
			resl = ST_ERROR; break;
		}

		if (member != FALSE) {
			resl = ST_OK;
		} else {
			resl = ST_NO_ADMIN;
		}
	} while (0);

	if (adm_sid != NULL) {
		FreeSid(adm_sid);
	}

	return resl;
}

int save_file(wchar_t *name, void *data, int size)
{
	HANDLE hfile;
	u32    bytes;
	int    resl;

	hfile = CreateFile(
		name, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);

	if (hfile != INVALID_HANDLE_VALUE) 
	{
		WriteFile(hfile, data, size, &bytes, NULL);
		CloseHandle(hfile);
		resl = ST_OK;
	} else {
		resl = ST_ACCESS_DENIED;
	}

	return resl;
}

int load_file(wchar_t *name, void **data, int *size)
{
	HANDLE hfile;
	u32    bytes;
	int    resl;

	do
	{
		hfile = CreateFile(
			name, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

		if (hfile == INVALID_HANDLE_VALUE) {
			hfile = NULL; resl = ST_ACCESS_DENIED; break;
		}

		*size = GetFileSize(hfile, NULL);
		*data = malloc(*size);

		if (*data == NULL) {
			resl = ST_NOMEM; break;
		}
		if (ReadFile(hfile, *data, *size, &bytes, NULL) == 0) {
			free(*data); resl = ST_IO_ERROR;
		} else {
			resl = ST_OK;
		}
	} while (0);

	if (hfile != NULL) {
		CloseHandle(hfile);
	}

	return resl;
}

PVOID secure_alloc(ULONG length)
{
	DC_LOCK_MEMORY mem;

	// on 32 bit system xts_key must be located in executable memory
	// x64 does not require this
#ifdef _M_IX86
	if ( (mem.ptr = VirtualAlloc(NULL, (mem.length = length), MEM_COMMIT+MEM_RESERVE, PAGE_EXECUTE_READWRITE)) == NULL ) return NULL;
#else
	if ( (mem.ptr = VirtualAlloc(NULL, (mem.length = length), MEM_COMMIT+MEM_RESERVE, PAGE_READWRITE)) == NULL ) return NULL;
#endif
	if (dc_device_control(DC_CTL_LOCK_MEM, &mem, sizeof(mem), NULL, 0) != NO_ERROR) VirtualLock(mem.ptr, length);
	return mem.ptr;
}

void secure_free(PVOID ptr)
{
	MEMORY_BASIC_INFORMATION mbi;
	
	if ( (dc_device_control(DC_CTL_UNLOCK_MEM, &ptr, sizeof(ptr), NULL, 0) != NO_ERROR) &&
		 (VirtualQuery(ptr, &mbi, sizeof(mbi)) == sizeof(mbi) && mbi.BaseAddress == ptr && mbi.AllocationBase == ptr) )
	{
		RtlSecureZeroMemory(ptr, mbi.RegionSize);
		VirtualUnlock(ptr, mbi.RegionSize);
	}
	VirtualFree(ptr, 0, MEM_RELEASE);
}

int is_wow64()
{
	ISWOW64PROCESS IsWow64Process;
	BOOL           is_wow = FALSE;

	IsWow64Process = pv(GetProcAddress(
		GetModuleHandleA("kernel32"), "IsWow64Process"));

	if (IsWow64Process == NULL) {
		return 0;
	}

	IsWow64Process(
		GetCurrentProcess(), &is_wow);

	return (is_wow != FALSE);		
}

int dc_fs_type(u8 *buff)
{
	if (memcmp(buff + 3, "NTFS    ", 8) == 0) {
		return FS_NTFS;
	}
	if (memcmp(buff + 54, "FAT12   ", 8) == 0) {
		return FS_FAT12;
	}
	if (memcmp(buff + 54, "FAT16   ", 8) == 0) {
		return FS_FAT16;
	}
	if (memcmp(buff + 82, "FAT32   ", 8) == 0) {
		return FS_FAT32;
	}
	if (memcmp(buff + 3, "EXFAT   ", 8) == 0) {
		return FS_EXFAT;
	}
	return FS_UNK;
}

dc_disk_p *dc_disk_open(int dsk_num, int is_cd)
{
	DISK_GEOMETRY dg;
	wchar_t       device[MAX_PATH];
	int           succs;	
	dc_disk_p    *dp;
	u32           bytes;

	if (is_cd == 0)
	{
		_snwprintf(
			device, countof(device), L"\\\\.\\PhysicalDrive%d", dsk_num);
	} else {
		_snwprintf(
			device, countof(device), L"\\\\.\\CdRom%d", dsk_num);
	}

	succs = 0;
	do
	{
		if ( (dp = malloc(sizeof(dc_disk_p))) == NULL ) {
			break;
		}

		dp->hdisk = CreateFile(
			device, GENERIC_READ | GENERIC_WRITE, 
			FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

		if (dp->hdisk == INVALID_HANDLE_VALUE) {
			dp->hdisk = NULL; break;
		}

		if (is_cd == 0)
		{
			succs = DeviceIoControl(
				dp->hdisk, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &dg, sizeof(dg), &bytes, NULL);

			if (succs != 0) {
				dp->media = dg.MediaType;
				dp->bps   = dg.BytesPerSector;
				dp->spc   = dg.TracksPerCylinder * dg.SectorsPerTrack;
				dp->size  = dg.Cylinders.QuadPart * d64(dp->spc) * d64(dp->bps);			
			}
		} else {
			dp->media = Unknown;
			dp->bps   = CD_SECTOR_SIZE;
			dp->spc   = 0;
			dp->size  = 0; succs = 1;
		}
	} while (0);

	if ( (succs == 0) && (dp != NULL) ) 
	{
		if (dp->hdisk != NULL) {
			CloseHandle(dp->hdisk);
		}
		free(dp); dp = NULL;
	}

	return dp;
}

void dc_disk_close(dc_disk_p *dp)
{
	CloseHandle(dp->hdisk);
	free(dp);
}

int dc_disk_read(dc_disk_p *dp, void *buff, int size, u64 offset)
{
	u64 n_offs;
	u32 n_size, bytes;
	u32 b_offs;
	u8 *p_buff;
	int resl;

	if ( (offset % dp->bps) || (size % dp->bps) ) 
	{
		b_offs = offset % dp->bps;
		n_offs = offset - b_offs;
		n_size = b_offs + size;
		n_size = n_size + (dp->bps - (n_size % dp->bps));
		p_buff = malloc(n_size);		
	} else {
		n_offs = offset, n_size = size, p_buff = buff;
	}
	
	do
	{
		if (p_buff == NULL) {
			resl = ST_NOMEM; break;
		}

		bytes = SetFilePointer(
			dp->hdisk, d32(n_offs), &p32(&n_offs)[1], FILE_BEGIN);

		if (bytes == INVALID_SET_FILE_POINTER) {
			resl = ST_IO_ERROR; break;
		}

		if (ReadFile(dp->hdisk, p_buff, n_size, &bytes, NULL) == 0) {
			resl = ST_IO_ERROR;
		} else {
			resl = ST_OK;
		}
	} while (0);

	if (p_buff != buff)
	{
		if (resl == ST_OK) {
			memcpy(buff, p_buff + b_offs, size);
		}
		free(p_buff);
	}
	
	return resl;
}

int dc_disk_write(dc_disk_p *dp, void *buff, int size, u64 offset)
{
	u64 n_offs;
	u32 n_size, bytes;
	u32 b_offs;
	u8 *p_buff;
	int resl;

	if ( (offset % dp->bps) || (size % dp->bps) ) 
	{
		b_offs = offset % dp->bps;
		n_offs = offset - b_offs;
		n_size = b_offs + size;
		n_size = n_size + (dp->bps - (n_size % dp->bps));
		p_buff = malloc(n_size);		
	} else {
		n_offs = offset, n_size = size, p_buff = buff;
	}
	
	do
	{
		if (p_buff == NULL) {
			resl = ST_NOMEM; break;
		}

		bytes = SetFilePointer(
			dp->hdisk, d32(n_offs), &p32(&n_offs)[1], FILE_BEGIN);

		if (bytes == INVALID_SET_FILE_POINTER) {
			resl = ST_IO_ERROR; break;
		}

		if (p_buff != buff)
		{
			if (ReadFile(dp->hdisk, p_buff, n_size, &bytes, NULL) == 0) {
				resl = ST_IO_ERROR; break;
			}

			memcpy(p_buff + b_offs, buff, size);

			SetFilePointer(
				dp->hdisk, d32(n_offs), &p32(&n_offs)[1], FILE_BEGIN);

			if (WriteFile(dp->hdisk, p_buff, n_size, &bytes, NULL) == 0) {
				resl = ST_IO_ERROR;
			} else { resl = ST_OK; }
		} else 
		{
			if (WriteFile(dp->hdisk, p_buff, n_size, &bytes, NULL) == 0) {
				resl = ST_IO_ERROR;
			} else { resl = ST_OK; }
		}
	} while (0);

	if (p_buff != buff) {		
		free(p_buff);
	}
	
	return resl;	
}


int is_win_vista()
{
	OSVERSIONINFO osv;

	osv.dwOSVersionInfoSize = sizeof(osv);
	GetVersionEx(&osv);
	return (osv.dwMajorVersion >= 6);
}


/* this function grabbed from ReactOS sources */
void dc_format_byte_size(
	   wchar_t *wc_buf, int wc_size, u64 num_bytes
	   )
{
	double  d_bytes;
	wchar_t format[20];
	int     i;

	if (num_bytes < 1024) 
	{
		_snwprintf(
			wc_buf, wc_size, L"%d bytes", (u32)(num_bytes));
	} else 
	{
		for (i = 0; i < countof(b_formats); i++) 
		{
			if (num_bytes < b_formats[i].limit) {
				break;
			}
		}

		if (i > 8) {
			d_bytes = (double)(num_bytes >> 20) + 0.001; /* Scale down by I MB */
		} else {
			d_bytes = (double)(num_bytes) + 0.00001;
		}

		d_bytes = floor(d_bytes / b_formats[i].divisor) / b_formats[i].normaliser;

		_snwprintf(
			format, countof(format), L"%%-.%df %%cB", b_formats[i].decimals);
		
		_snwprintf(
			wc_buf, wc_size, format, d_bytes, b_formats[i].prefix);		
	}
}

wchar_t *dc_get_cipher_name(int cipher_id)
{
	static wchar_t *cp_names[] = {
		L"AES",
		L"Twofish",
		L"Serpent",
		L"AES-Twofish",
		L"Twofish-Serpent",
		L"Serpent-AES",
		L"AES-Twofish-Serpent"
	};

	return cp_names[cipher_id];
}


static int WINAPI dc_format_callback(int unk1, int unk2, int unk3) {
	return 1;
}

int dc_format_fs(wchar_t *root, wchar_t *fs)
{
	HMODULE fmifs;
	PFORMAT Format;
	int     resl;

	do
	{
		if ( (fmifs = LoadLibrary(L"fmifs")) == NULL ) {
			resl = ST_ERROR; break;
		}

		if ( (Format = pv(GetProcAddress(fmifs, "Format"))) == NULL ) {
			resl = ST_ERROR; break;
		}

		Format(root, 0, fs, L"", 1, dc_format_callback);
		resl = ST_OK;
	} while (0);

	if (fmifs != NULL) {
		FreeLibrary(fmifs);
	}

	return resl;
}

#ifdef _M_IX86
long _stdcall save_fpu_state(unsigned char state[32]) {
	return 0;
}
void _stdcall load_fpu_state(unsigned char state[32]) {
}
#endif