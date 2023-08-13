/*
    *
    * DiskCryptor - open source partition encryption tool
	* Copyright (c) 2019-2023
	* DavidXanatos <info@diskcryptor.org>
    * Copyright (c) 2008-2011 
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
#include <stddef.h>
#include "driver.h"
#include "defines.h"
#include "bootloader.h"
#include "boot_pass.h"
#include "mount.h"
#include "debug.h"


static void *find_8b(u8 *data, int size, u32 s1, u32 s2)
{
	int i;

	for (i = 0; i < size - 8; i++) {
		if (p32(data + i)[0] == s1 && p32(data + i)[1] == s2) return data + i;
	}
	return NULL;
}

static void dc_zero_boot(u32 bd_base, u32 bd_size)
{
	PHYSICAL_ADDRESS addr;
	void            *mem;
	
	/* map bootloader body */
	addr.HighPart = 0;
	addr.LowPart  = bd_base;

	if (mem = MmMapIoSpace(addr, bd_size, MmCached)) {
		/* zero bootloader body */
		burn(mem, bd_size);
		MmUnmapIoSpace(mem, bd_size);
	}
}

static void dc_restore_ints(bd_data *bdb)
{
	PHYSICAL_ADDRESS addr;
	void            *mem;

	DbgMsg("dc_restore_ints\n");

	/* map realmode interrupts table */
	addr.HighPart = 0;
	addr.LowPart  = 0;

	if (mem = MmMapIoSpace(addr, 0x1000, MmCached)) 
	{
		p32(mem)[0x13] = bdb->u.legacy.old_int13;
		p32(mem)[0x15] = bdb->u.legacy.old_int15;
		MmUnmapIoSpace(mem, 0x1000);
	}
}

static void dc_load_uefi_flags(bd_data *bdb)
{
	dc_boot_flags = bdb->u.uefi.flags;

	DbgMsg("dc_boot_flags=%08x\n", dc_boot_flags);
}

int dc_try_load_bdb(PHYSICAL_ADDRESS addr)
{
	int              ret = ST_ERROR;
	bd_data         *bdb;
	HANDLE			 h_mem;
	UNICODE_STRING   u_name;
	OBJECT_ATTRIBUTES obj_a;
	PVOID			 p_mem = NULL;
	SIZE_T			 u_size = PAGE_SIZE;

	RtlInitUnicodeString(&u_name, L"\\Device\\PhysicalMemory");
	InitializeObjectAttributes(&obj_a, &u_name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, (HANDLE)NULL, (PSECURITY_DESCRIPTOR)NULL);
	if (NT_SUCCESS(ZwOpenSection(&h_mem, SECTION_ALL_ACCESS, &obj_a)))
	{
		if (NT_SUCCESS(ZwMapViewOfSection(h_mem, NtCurrentProcess(), &p_mem, 0L, u_size, &addr, &u_size, ViewShare, 0, PAGE_READWRITE)))
		{
			__try 
			{
				if (bdb = find_8b((u8*)p_mem, PAGE_SIZE - offsetof(bd_data, u.extra), BDB_SIGN1, BDB_SIGN2))
				{
					//DbgMsg("boot data block found at %p\n", bdb);
					DbgMsg("boot data block found at 0x%x\n", addr.LowPart);
					DbgMsg("boot loader base 0x%x size %d\n", bdb->bd_base, bdb->bd_size);
					//DbgMsg("boot extra %08x %08x\n", bdb->u.legacy.old_int13, bdb->u.uefi.sign3);
					//DbgMsg("boot password %S\n", bdb->password.pass); // no no no
					/* restore realmode interrupts */
					if (bdb->u.legacy.old_int13 != 0)
						dc_restore_ints(bdb);
					else if (bdb->u.uefi.sign3 == BDB_SIGN3)
						dc_load_uefi_flags(bdb);
					/* add password to cache */
					dc_add_password(&bdb->password);
					/* save bootloader size */
					dc_boot_kbs = bdb->bd_size / 1024;
					/* set bootloader load flag */
					dc_load_flags |= DST_BOOTLOADER;
					/* zero bootloader body */
					dc_zero_boot(bdb->bd_base, bdb->bd_size);

					ret = ST_OK;
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				//status = GetExceptionCode();
			}

			ZwUnmapViewOfSection(NtCurrentProcess(), &p_mem);
		}

		ZwClose(h_mem);
	}

	return ret;
}

int dc_get_legacy_boot_pass()
{
	PHYSICAL_ADDRESS addr;
	/* scan memory in range 500-640k */
	for (addr.QuadPart = 500*1024; addr.LowPart < 640*1024; addr.LowPart += PAGE_SIZE) {
		if (dc_try_load_bdb(addr) == ST_OK) return ST_OK;
	}
	return ST_ERROR;
}

int dc_get_uefi_boot_pass() 
{
	PHYSICAL_ADDRESS addr;
	/* scan memory in range 1-16M in steps of 1M */
	for (addr.QuadPart = 0x00100000; addr.LowPart <= 0x01000000; addr.LowPart += (256 * PAGE_SIZE)) {
		if (dc_try_load_bdb(addr) == ST_OK) return ST_OK;
	}
	return ST_ERROR;
}

typedef NTSTATUS (NTAPI * P_NtQuerySystemEnvironmentValueEx)(
	__in PUNICODE_STRING VariableName,
	__in LPGUID VendorGuid,
	__out_bcount_opt(*ValueLength) PVOID Value,
	__inout PULONG ValueLength,
	__out_opt PULONG Attributes
);

BOOLEAN dc_efi_check()
{
	UNICODE_STRING uni;
	RtlInitUnicodeString(&uni, L"ZwQuerySystemEnvironmentValueEx");
	P_NtQuerySystemEnvironmentValueEx pNtQuerySystemEnvironmentValueEx = MmGetSystemRoutineAddress(&uni);
	if (!pNtQuerySystemEnvironmentValueEx) // only exported on windows 8 and later
		return FALSE;

	UNICODE_STRING NameString;
	RtlInitUnicodeString(&NameString, L" ");
	UNICODE_STRING GuidString;
	RtlInitUnicodeString(&GuidString, L"{00000000-0000-0000-0000-000000000000}");
	GUID Guid;
	RtlGUIDFromString(&GuidString, &Guid);

	UCHAR Buffer[4];
	ULONG Length = sizeof(Buffer);
	NTSTATUS status = pNtQuerySystemEnvironmentValueEx(&NameString, &Guid, Buffer, &Length, 0i64);

	//DbgMsg("NtQuerySystemEnvironmentValueEx, status=%08x\n", status);

	if(status == STATUS_VARIABLE_NOT_FOUND)
		dc_load_flags |= DST_UEFI_BOOT;
	return TRUE;
}

void dc_get_boot_pass()
{
	DbgMsg("dc_get_boot_pass\n");

	BOOLEAN efi_check_ok = dc_efi_check(); // on fail try booth

	if (!efi_check_ok || (dc_load_flags & DST_UEFI_BOOT)) 
	{
		if (dc_get_uefi_boot_pass() == ST_OK) {
			if(!efi_check_ok) 
				dc_load_flags |= DST_UEFI_BOOT;
			return;
		}
	}

	if (!efi_check_ok || !(dc_load_flags & DST_UEFI_BOOT)) 
	{
		if (dc_get_legacy_boot_pass() == ST_OK) {
			return;
		}
	}

	DbgMsg("boot data block NOT found\n");
}
