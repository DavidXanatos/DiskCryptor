/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2010-2013
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

#include <ntifs.h>
#include <ntdddisk.h>
#include <ntstrsafe.h>
#include "defines.h"
#include "debug.h"
#include "devhook.h"
#include "ssd_trim.h"
#include "misc.h"
#include "device_io.h"

// function types declaration
KSTART_ROUTINE dc_trim_thread;

#define MAX_TRIM_FILES 128
#define TRIM_MIN_LEN   4096

static BOOLEAN dc_is_trim_supported(dev_hook *hook)
{
	STORAGE_PROPERTY_QUERY pquery = { StorageDeviceTrimProperty,  PropertyStandardQuery, };
	DEVICE_TRIM_DESCRIPTOR trimds  = { 0 };
	NTSTATUS               status;
	
	if ( !NT_SUCCESS(status = io_device_control(hook->orig_dev,
		                                        IOCTL_STORAGE_QUERY_PROPERTY,
												&pquery, sizeof(pquery), &trimds, sizeof(trimds))) )
	{
		DbgMsg("IOCTL_STORAGE_QUERY_PROPERTY fails, dev=%ws, status=%08x\n", hook->dev_name, status);
		return FALSE;
	}
	if (trimds.Version < sizeof(DEVICE_TRIM_DESCRIPTOR) || trimds.Size < sizeof(DEVICE_TRIM_DESCRIPTOR)) {
		DbgMsg("Invalid DEVICE_TRIM_DESCRIPTOR returned, dev=%ws\n", hook->dev_name);
		return FALSE;
	}
	DbgMsg("device %ws TrimEnabled = %d\n", hook->dev_name, trimds.TrimEnabled);
	return trimds.TrimEnabled;
}

static HANDLE dc_create_trim_file(dev_hook *hook, ULONGLONG length)
{
	FILE_VALID_DATA_LENGTH_INFORMATION vdli;
	FILE_END_OF_FILE_INFORMATION       eofi;
	OBJECT_ATTRIBUTES                  obj_a;
	UNICODE_STRING                     u_name;	
	IO_STATUS_BLOCK                    iosb;
	wchar_t                            buff[MAX_PATH];
	HANDLE                             h_file;
	NTSTATUS                           status;

	if ( !NT_SUCCESS(status = RtlStringCchPrintfW(buff, MAX_PATH, L"%s\\$DC_TRIM_%x$", hook->dev_name, __rdtsc())) ) return NULL;
	RtlInitUnicodeString(&u_name, buff);
	InitializeObjectAttributes(&obj_a, &u_name, OBJ_KERNEL_HANDLE, NULL, NULL);

	if ( !NT_SUCCESS(status = ZwCreateFile(&h_file, GENERIC_WRITE, &obj_a, &iosb, NULL, 0, 0, FILE_CREATE, 0, NULL, 0)) )
	{
		DbgMsg("Can not create trim file, status=%08x, path=%ws\n", status, buff);
		return NULL;
	}
	vdli.ValidDataLength.QuadPart = length;
	eofi.EndOfFile.QuadPart = length;

	if ( !NT_SUCCESS(status = ZwSetInformationFile(h_file, &iosb, &eofi, sizeof(eofi), FileEndOfFileInformation)) ||
		 !NT_SUCCESS(status = ZwSetInformationFile(h_file, &iosb, &vdli, sizeof(vdli), FileValidDataLengthInformation)) )
	{
		DbgMsg("Can not allocate space for trim, status=%08x, path=%ws\n", status, buff);
	}
	return h_file;
}

static void dc_do_trim(dev_hook *hook)
{
	FILE_FS_SIZE_INFORMATION     sinf;
	FILE_DISPOSITION_INFORMATION dinf = { TRUE };
	HANDLE                       h_files[MAX_TRIM_FILES];
	int                          n_files = 0, i;
	HANDLE                       h_file;
	IO_STATUS_BLOCK              iosb;	
	NTSTATUS                     status;
	ULONGLONG                    length;

	// create first trim file
	if ( (h_file = dc_create_trim_file(hook, TRIM_MIN_LEN)) == NULL ) {
		return;
	} else {
		h_files[n_files++] = h_file;
	}
	for (i = 0; i < MAX_TRIM_FILES - 1; i++)
	{
		status = ZwQueryVolumeInformationFile(h_file, &iosb, &sinf, sizeof(sinf), FileFsSizeInformation);

		if ( (NT_SUCCESS(status) == FALSE) || (sinf.AvailableAllocationUnits.QuadPart == 0) ) {
			break;
		} else {
			length = max(sinf.AvailableAllocationUnits.QuadPart / 2, 1) * d64(sinf.BytesPerSector * sinf.SectorsPerAllocationUnit);
		}
		if (h_file = dc_create_trim_file(hook, length)) {
			h_files[n_files++] = h_file;
		}
	}
	// delete trim files
	for (i = 0; i < n_files; i++) {
		ZwSetInformationFile(h_files[i], &iosb, &dinf, sizeof(dinf), FileDispositionInformation);
		ZwClose(h_files[i]);
	}
}

static void dc_trim_thread(dev_hook *hook)
{
	if (dc_is_trim_supported(hook) != FALSE) {
		dc_do_trim(hook);
	}
	dc_deref_hook(hook);
	PsTerminateSystemThread(STATUS_SUCCESS);
}

void dc_trim_free_space(dev_hook *hook)
{
	dc_reference_hook(hook);

	if (start_system_thread(dc_trim_thread, hook, NULL) != ST_OK) {
		dc_deref_hook(hook);
	}
}