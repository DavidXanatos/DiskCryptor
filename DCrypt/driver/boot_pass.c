/*
    *
    * DiskCryptor - open source partition encryption tool
	* Copyright (c) 2019-2023
	* DavidXanatos <info@diskcryptor.org>
    * Copyright (c) 2008-2011 
    * ntldr <ntldr@diskcryptor.net> PGP key ID - 0xC48251EB4F8E4E6E
    *
    * Security updates (c) 2025
    * Improved memory handling for boot password transmission

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

/* Named constants for magic values */
#define REALMODE_IVT_SIZE       0x1000     /* Real-mode interrupt vector table size (4KB) */
#define LEGACY_MEM_START        (500*1024) /* Start of legacy memory scan range (500KB) */
#define LEGACY_MEM_END          (640*1024) /* End of legacy memory scan range (640KB) */
#define UEFI_MEM_START          0x00100000 /* Start of UEFI memory scan range (1MB) */
#define UEFI_MEM_END            0x01000000 /* End of UEFI memory scan range (16MB) */
#define UEFI_MEM_STEP           (256 * PAGE_SIZE) /* UEFI scan step size (1MB) */

/* Memory barrier to prevent compiler/CPU reordering of memory operations */
#define DC_MEMORY_BARRIER() KeMemoryBarrier()

/* Volatile pointer to prevent optimization of memory clearing */
typedef void* volatile DC_VOLATILE_PTR;

/*
 * Secure memory zeroing that cannot be optimized away
 * Uses volatile pointer and memory barrier
 */
static __forceinline void dc_secure_zero(void *ptr, size_t size)
{
	volatile unsigned char *p = (volatile unsigned char *)ptr;
	size_t i;
	
	for (i = 0; i < size; i++) {
		p[i] = 0;
	}
	
	DC_MEMORY_BARRIER();
}

/*
 * XOR-based password deobfuscation
 * The bootloader should XOR the password with a time-based key before storing
 * This provides defense-in-depth against memory scanning
 */
static void dc_deobfuscate_password(dc_pass *pass, u32 obfuscation_key)
{
	u8 *key_bytes = (u8*)&obfuscation_key;
	size_t i;
	
	if (obfuscation_key == 0) {
		return; /* Legacy bootloader without obfuscation */
	}
	
	for (i = 0; i < pass->size && i < MAX_PASSWORD; i++) {
		pass->pass[i] ^= key_bytes[i % 4];
	}
	
	DC_MEMORY_BARRIER();
}

static void *find_8b(u8 *data, int size, u32 s1, u32 s2)
{
	int i;

	for (i = 0; i < size - 8; i++) {
		if (p32(data + i)[0] == s1 && p32(data + i)[1] == s2) return data + i;
	}
	return NULL;
}

/*
 * Zero bootloader body in physical memory
 * SECURITY: This must be called IMMEDIATELY after extracting the password
 */
static void dc_zero_boot(u32 bd_base, u32 bd_size)
{
	PHYSICAL_ADDRESS addr;
	void            *mem;
	
	/* map bootloader body */
	addr.HighPart = 0;
	addr.LowPart  = bd_base;

	if (mem = MmMapIoSpace(addr, bd_size, MmCached)) {
		/* Securely zero bootloader body including password */
		dc_secure_zero(mem, bd_size);
		
		/* Force write-back of cached data */
		DC_MEMORY_BARRIER();
		
		MmUnmapIoSpace(mem, bd_size);
	}
}

/*
 * Zero the specific page containing boot data block
 * Called immediately after password extraction, before any other processing
 */
static void dc_zero_bdb_page(void *page_base, size_t page_size)
{
	dc_secure_zero(page_base, page_size);
	DC_MEMORY_BARRIER();
}

static void dc_restore_ints(bd_data *bdb)
{
	PHYSICAL_ADDRESS addr;
	void            *mem;

	DbgMsg("dc_restore_ints\n");

	/* map realmode interrupts table */
	addr.HighPart = 0;
	addr.LowPart  = 0;

	if (mem = MmMapIoSpace(addr, REALMODE_IVT_SIZE, MmCached)) 
	{
		p32(mem)[0x13] = bdb->u.legacy.old_int13;
		p32(mem)[0x15] = bdb->u.legacy.old_int15;
		MmUnmapIoSpace(mem, REALMODE_IVT_SIZE);
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
	dc_pass          local_pass;  /* Local copy to minimize exposure time */
	u32              bd_base_copy, bd_size_copy;
	int              is_legacy = 0;
	int              is_uefi = 0;
	u32              old_int13 = 0, old_int15 = 0;
	u32              uefi_flags = 0;

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
					DbgMsg("boot data block found at 0x%x\n", addr.LowPart);
					DbgMsg("boot loader base 0x%x size %d\n", bdb->bd_base, bdb->bd_size);
					
					/* 
					 * SECURITY: Copy all needed data to local variables FIRST
					 * Then immediately zero the source before any further processing
					 * This minimizes the window where plaintext password is in memory
					 */
					
					/* Copy password to local buffer */
					RtlCopyMemory(&local_pass, &bdb->password, sizeof(dc_pass));
					
					/* Copy other needed values */
					bd_base_copy = bdb->bd_base;
					bd_size_copy = bdb->bd_size;
					
					/* Check boot type before zeroing */
					if (bdb->u.legacy.old_int13 != 0) {
						is_legacy = 1;
						old_int13 = bdb->u.legacy.old_int13;
						old_int15 = bdb->u.legacy.old_int15;
					} else if (bdb->u.uefi.sign3 == BDB_SIGN3) {
						is_uefi = 1;
						uefi_flags = bdb->u.uefi.flags;
					}
					
					/* 
					 * SECURITY: Zero the password in physical memory IMMEDIATELY
					 * This is done BEFORE adding to cache to minimize exposure
					 */
					dc_secure_zero(&bdb->password, sizeof(dc_pass));
					DC_MEMORY_BARRIER();
					
					/* Zero the entire boot data block signatures to prevent re-discovery */
					bdb->sign1 = 0;
					bdb->sign2 = 0;
					DC_MEMORY_BARRIER();
					
					/* Now process the copied data */
					if (is_legacy) {
						/* Restore realmode interrupts using copied values */
						PHYSICAL_ADDRESS int_addr;
						void *int_mem;
						int_addr.HighPart = 0;
						int_addr.LowPart  = 0;
						if (int_mem = MmMapIoSpace(int_addr, 0x1000, MmCached)) {
							p32(int_mem)[0x13] = old_int13;
							p32(int_mem)[0x15] = old_int15;
							MmUnmapIoSpace(int_mem, 0x1000);
						}
					} else if (is_uefi) {
						dc_boot_flags = uefi_flags;
						DbgMsg("dc_boot_flags=%08x\n", dc_boot_flags);
					}
					
					/* Add password to cache from local copy */
					dc_add_password(&local_pass);
					
					/* SECURITY: Zero local password copy immediately after use */
					dc_secure_zero(&local_pass, sizeof(dc_pass));
					
					/* save bootloader size */
					dc_boot_kbs = bd_size_copy / 1024;
					
					/* set bootloader load flag */
					dc_load_flags |= DST_BOOTLOADER;
					
					/* zero entire bootloader body in physical memory */
					dc_zero_boot(bd_base_copy, bd_size_copy);

					ret = ST_OK;
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				/* On exception, still try to zero any exposed password data */
				dc_secure_zero(&local_pass, sizeof(dc_pass));
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
	for (addr.QuadPart = LEGACY_MEM_START; addr.LowPart < LEGACY_MEM_END; addr.LowPart += PAGE_SIZE) {
		if (dc_try_load_bdb(addr) == ST_OK) return ST_OK;
	}
	return ST_ERROR;
}

int dc_get_uefi_boot_pass() 
{
	PHYSICAL_ADDRESS addr;
	/* scan memory in range 1-16M in steps of 1M */
	for (addr.QuadPart = UEFI_MEM_START; addr.LowPart <= UEFI_MEM_END; addr.LowPart += UEFI_MEM_STEP) {
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
