/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2014
    * ntldr <ntldr@diskcryptor.net> PGP key ID - 0x1B6A24550F33E44A
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
#include "dump_helpers.h"
#include "devhook.h"
#include "mount.h"
#include "misc_mem.h"

static dev_hook* current_dump_device = NULL;

static NTSTATUS dc_dump_start(__in BOOLEAN is_hibernation)
{
	dev_hook* hook;
	ULONG     number_of_mounts = 0;
	BOOLEAN   dump_device_encrypted = FALSE;
	ULONG     found_dump_devices = 0;

	for (hook = dc_first_hook(); hook != NULL; hook = dc_next_hook(hook))
	{
		if (hook->flags & (is_hibernation ? F_HIBERNATE : F_CRASHDUMP))
		{
			// dump device must be mounted,
			// dump device must not contain unencrypted part
			// and encryption keys must not have been erased by dc_clean_keys / mm_clean_secure_memory
			dump_device_encrypted = (hook->flags & F_ENABLED) != 0 &&
				                    ( (hook->flags & F_SYNC) == 0 || (hook->flags & F_REENCRYPT) != 0 ) &&
									(hook->dsk_key != NULL && hook->dsk_key->encrypt != NULL) &&
									(hook->tmp_key == NULL || hook->tmp_key->encrypt != NULL);
			found_dump_devices++;
			current_dump_device = hook;
		}
		if (hook->flags & F_ENABLED) number_of_mounts++;
	}

	// if no active mounts, dump encryption not needed
	if (number_of_mounts == 0)
	{
		dc_clean_pass_cache(); // prevent saving unencrypted passwords to disk
		return STATUS_FVE_NOT_ENCRYPTED;
	}

	// operation allowed if dump device is correctly encrypted
	if (found_dump_devices == 1 && dump_device_encrypted) return STATUS_SUCCESS;

	// operation not allowed because encryption keys may leak to dump
	return STATUS_ACCESS_DENIED;
}

static void dc_dump_finish()
{
	mm_clean_secure_memory();
	dc_clean_keys();
	current_dump_device = NULL;
}

static
NTSTATUS dc_dump_encrypt(
	__inout PLARGE_INTEGER DiskByteOffset,
	__in    PMDL           Mdl,
	__out   PUCHAR         EncryptedData
	)
{
	ULONGLONG offset = DiskByteOffset->QuadPart;
	ULONG     length = Mdl->ByteCount;
	PUCHAR    p_data;
#ifdef _M_IX86
	KIRQL     old_irql;
#endif

	// dump device hook must be known at this point
	if (current_dump_device == NULL) return STATUS_INVALID_DEVICE_STATE;

	// data length and disk byte offset must be multiples of XTS_SECTOR_SIZE
	if ( (length % XTS_SECTOR_SIZE) != 0 || (offset % XTS_SECTOR_SIZE) != 0 ) return STATUS_DATATYPE_MISALIGNMENT_ERROR;

	// Callers of MmGetSystemAddressForMdlSafe must be running at IRQL <= DISPATCH_LEVEL
	// Mdl must be already mapped to system VA
	if ((Mdl->MdlFlags & (MDL_MAPPED_TO_SYSTEM_VA | MDL_SOURCE_IS_NONPAGED_POOL)) == 0) return STATUS_NOT_MAPPED_DATA;
	p_data = (PUCHAR)Mdl->MappedSystemVa;

	if (current_dump_device->flags & F_NO_REDIRECT) {
		// redirection is not used, the data are moved forward by the header length
		DiskByteOffset->QuadPart += current_dump_device->head_len;
	} else {
		// writing to redirected area is not supported
		if (offset < current_dump_device->head_len) return STATUS_NOT_SUPPORTED;
	}

#ifdef _M_IX86
	// raise IRQL to HIGH_LEVEL for disable KeSaveFloatingPointState on x86
	KeRaiseIrql(HIGH_LEVEL, &old_irql);
#endif

	if ((current_dump_device->flags & F_SYNC) && (offset + length > current_dump_device->tmp_size))
	{
		ULONG     part1_length = offset < current_dump_device->tmp_size ? (ULONG)(current_dump_device->tmp_size - offset) : 0;
		ULONGLONG part2_offset = offset < current_dump_device->tmp_size ? current_dump_device->tmp_size : offset;
		ULONG     part2_length = length - part1_length;

		if (part1_length != 0) { // write to part encrypted with master key
			xts_encrypt(p_data, EncryptedData, part1_length, offset, current_dump_device->dsk_key);
		}
		if (part2_length != 0) { // write to part encrypted with temporary key
			xts_encrypt(p_data + part1_length, EncryptedData + part1_length, part2_length, part2_offset, current_dump_device->tmp_key);
		}
	} else { // write only to encrypted part
		xts_encrypt(p_data, EncryptedData, length, offset, current_dump_device->dsk_key);
	}

#ifdef _M_IX86
	KeLowerIrql(old_irql);
#endif

	return STATUS_SUCCESS;
}

static BOOLEAN dc_dump_is_hibernation_allowed()
{
	dev_hook* hook;
	ULONG     number_of_mounts = 0;
	ULONG     hibernation_devices = 0;
	BOOLEAN   hibernation_device_encrypted = FALSE;

	// find all devices with F_HIBERNATE flag
	for (hook = dc_first_hook(); hook != NULL; hook = dc_next_hook(hook))
	{
		if (hook->flags & F_HIBERNATE)
		{
			// dump device must be mounted,
			// dump device must not contain unencrypted part
			// and encryption keys must not have been erased by dc_clean_keys / mm_clean_secure_memory
			hibernation_device_encrypted = (hook->flags & F_ENABLED) != 0 &&
				                           ( (hook->flags & F_SYNC) == 0 || (hook->flags & F_REENCRYPT) != 0 ) &&
									       (hook->dsk_key != NULL && hook->dsk_key->encrypt != NULL) &&
										   (hook->tmp_key == NULL || hook->tmp_key->encrypt != NULL);
			hibernation_devices++;
		}
		if (hook->flags & F_ENABLED) number_of_mounts++;
	}

	// hibernation allowed if no active mounts or hibernation device is fully encrypted
	return number_of_mounts == 0 || (hibernation_devices == 1 && hibernation_device_encrypted);
}

// dump helpers structure passed to dump filters
DC_DUMP_HELPERS dc_dump_helpers = {
	dc_dump_start,
	dc_dump_finish,
	dc_dump_encrypt,
	dc_dump_is_hibernation_allowed,
};
