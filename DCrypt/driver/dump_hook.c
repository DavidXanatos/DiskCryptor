/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2007-2014
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
#include "dump_hook.h"
#include "dump_helpers.h"
#include "debug.h"

typedef NTSTATUS (*PDUMPDRIVERENTRY)(IN PVOID unknown, IN PDUMP_STACK_CONTEXT dumpStack);
#define DUMP_MEM_SIZE (4096*16)

static PLIST_ENTRY    p_PsLoadedModuleListHead;
static volatile PVOID p_crash_DriverEntry[4];
static volatile LONG  crash_hooks_count;
static volatile PVOID p_hiber_DriverEntry[4];
static volatile LONG  hiber_hooks_count;
static PUCHAR         dump_hook_mem;
static PMDL           dump_hook_mdl;

// original dump driver handlers
static PDUMP_DRIVER_OPEN          old_OpenRoutine;
static PDUMP_DRIVER_WRITE         old_WriteRoutine;
static PDUMP_DRIVER_WRITE_PENDING old_WritePendingRoutine;
static PDUMP_DRIVER_FINISH        old_FinishRoutine;
static BOOLEAN                    hibernation_progress; // TRUE is hibernation, FALSE is crash dumping in progress
static NTSTATUS                   dump_status = STATUS_UNSUCCESSFUL;

static NTSTATUS dump_hook_new_WriteRoutine(IN PLARGE_INTEGER DiskByteOffset,
	                                       IN PMDL           Mdl)
{
	NTSTATUS status;

	// direct call old_WriteRoutine if encryption is not needed
	// or return error if encryption not initialized correctly
	if ( !NT_SUCCESS(dump_status) )
	{
		if (dump_status == STATUS_FVE_NOT_ENCRYPTED) return old_WriteRoutine(DiskByteOffset, Mdl);
		return dump_status;
	}

	// bugcheck if required parameter are not specified
	if (DiskByteOffset == NULL || Mdl == NULL)
	{
		KeBugCheckEx(STATUS_INVALID_PARAMETER, __LINE__, 0, (ULONG_PTR)DiskByteOffset, (ULONG_PTR)Mdl);
	}

	// bugcheck if encryption data too large
	if (Mdl->ByteCount > DUMP_MEM_SIZE)
	{
		KeBugCheckEx(STATUS_BUFFER_OVERFLOW, __LINE__, Mdl->ByteCount, 0, 0);
	}

	// encrypt the data (bugcheck if failed)
	if ( !NT_SUCCESS(status = dc_dump_helpers.dump_encrypt(DiskByteOffset, Mdl, dump_hook_mem)) )
	{
		KeBugCheckEx(STATUS_ENCRYPTION_FAILED, __LINE__, status, Mdl->ByteCount, 0);
	}

	// initialize new dump MDL with encrypted data
	MmInitializeMdl(dump_hook_mdl, dump_hook_mem, Mdl->ByteCount);
	dump_hook_mdl->MappedSystemVa = dump_hook_mem;
	dump_hook_mdl->MdlFlags       = MDL_SOURCE_IS_NONPAGED_POOL | MDL_MAPPED_TO_SYSTEM_VA;

	// call old_WriteRoutine with encrypted data
	return old_WriteRoutine(DiskByteOffset, dump_hook_mdl);
}

static NTSTATUS dump_hook_new_WritePendingRoutine(IN LONG           Action,
	                                              IN PLARGE_INTEGER DiskByteOffset,
												  IN PMDL           Mdl,
												  IN PVOID          LocalData)
{
	NTSTATUS status;

	// direct call old_WritePendingRoutine if encryption is not needed
	if (dump_status == STATUS_FVE_NOT_ENCRYPTED || Action != IO_DUMP_WRITE_START)
	{
		if (Action != IO_DUMP_WRITE_START) { // zero DiskByteOffset and Mdl for reinsurance
			DiskByteOffset = NULL;
			Mdl = NULL;
		}

		return old_WritePendingRoutine(Action, DiskByteOffset, Mdl, LocalData);
	}

	// if dump encryption not initialized, return error
	if ( !NT_SUCCESS(dump_status) ) return dump_status;

	// bugcheck if required parameter are not specified
	if (DiskByteOffset == NULL || Mdl == NULL)
	{
		KeBugCheckEx(STATUS_INVALID_PARAMETER, __LINE__, 0, (ULONG_PTR)DiskByteOffset, (ULONG_PTR)Mdl);
	}

	// bugcheck if encryption data too large
	if (Mdl->ByteCount > DUMP_MEM_SIZE)
	{
		KeBugCheckEx(STATUS_BUFFER_OVERFLOW, __LINE__, Mdl->ByteCount, 0, 0);
	}

	// encrypt the data (bugcheck if failed)
	if ( !NT_SUCCESS(status = dc_dump_helpers.dump_encrypt(DiskByteOffset, Mdl, dump_hook_mem)) )
	{
		KeBugCheckEx(STATUS_ENCRYPTION_FAILED, __LINE__, status, Mdl->ByteCount, 0);
	}

	// initialize new dump MDL with encrypted data
	MmInitializeMdl(dump_hook_mdl, dump_hook_mem, Mdl->ByteCount);
	dump_hook_mdl->MappedSystemVa = dump_hook_mem;
	dump_hook_mdl->MdlFlags       = MDL_SOURCE_IS_NONPAGED_POOL | MDL_MAPPED_TO_SYSTEM_VA;

	// call old_WritePendingRoutine with encrypted data
	return old_WritePendingRoutine(IO_DUMP_WRITE_START, DiskByteOffset, dump_hook_mdl, LocalData);
}

static void dump_hook_new_FinishRoutine(void)
{
	// call to original FinishRoutine
	if (old_FinishRoutine != NULL) old_FinishRoutine();

	// dump status should be re-defined in next call of OpenRoutine
	dump_status = STATUS_UNSUCCESSFUL;

	// zero all sensitive data
	RtlSecureZeroMemory(dump_hook_mem, DUMP_MEM_SIZE);
	dc_dump_helpers.dump_finish();
}

static BOOLEAN dump_hook_new_OpenRoutine(IN LARGE_INTEGER PartitionOffset)
{
	DbgMsg("dump_hook_new_OpenRoutine, PartitionOffset=%I64x\n", PartitionOffset);

	if ( !NT_SUCCESS(dump_status = dc_dump_helpers.dump_start(hibernation_progress)) )
	{
		if (dump_status != STATUS_FVE_NOT_ENCRYPTED)
		{
			DbgMsg("dumping operation are not allowed\n");
			return FALSE;
		}

		DbgMsg("dump encryption don't needed\n");
	}

	return ( old_OpenRoutine != NULL ? old_OpenRoutine(PartitionOffset) : FALSE );
}

static NTSTATUS dump_hook_new_DriverEntry(IN volatile PVOID*     p_old_DriverEntry,
	                                      IN PVOID               unknown, 
	                                      IN PDUMP_STACK_CONTEXT dumpStack)
{
#ifdef _M_IX86
	PDUMPDRIVERENTRY old_DriverEntry = (PDUMPDRIVERENTRY)_InterlockedExchange((volatile LONG*)p_old_DriverEntry, 0);
#else
	PDUMPDRIVERENTRY old_DriverEntry = (PDUMPDRIVERENTRY)_InterlockedExchangePointer(p_old_DriverEntry, NULL);
#endif
	NTSTATUS         status = ( old_DriverEntry ? old_DriverEntry(unknown, dumpStack) : STATUS_UNSUCCESSFUL );

	if (NT_SUCCESS(status) == FALSE) {
		DbgMsg("old_DriverEntry fails, status=%0.8x\n", status);
		return status;
	}

	if (unknown != NULL || dumpStack == NULL) {
		DbgMsg("invalid parameters in new_DriverEntry, unknown=%p, dumpStack=%p\n", unknown, dumpStack);
		return status;
	}

	// determine current operation
	hibernation_progress = (dumpStack->UsageType == DeviceUsageTypeHibernation) ||
		                   (dumpStack->UsageType != DeviceUsageTypeDumpFile && dumpStack->Init.CrashDump == FALSE);

	// save original dump driver functions and setup dump_hook handlers
	if (dumpStack->Init.OpenRoutine != dump_hook_new_OpenRoutine) {
		old_OpenRoutine = dumpStack->Init.OpenRoutine;
		dumpStack->Init.OpenRoutine = dump_hook_new_OpenRoutine;
	}
	if (dumpStack->Init.FinishRoutine != dump_hook_new_FinishRoutine) {
		old_FinishRoutine = dumpStack->Init.FinishRoutine;
		dumpStack->Init.FinishRoutine = dump_hook_new_FinishRoutine;
	}
	if (dumpStack->Init.WriteRoutine && dumpStack->Init.WriteRoutine != dump_hook_new_WriteRoutine) {
		old_WriteRoutine = dumpStack->Init.WriteRoutine;
		dumpStack->Init.WriteRoutine = dump_hook_new_WriteRoutine;
	}
	if (dumpStack->Init.WritePendingRoutine && dumpStack->Init.WritePendingRoutine != dump_hook_new_WritePendingRoutine) {
		old_WritePendingRoutine = dumpStack->Init.WritePendingRoutine;
		dumpStack->Init.WritePendingRoutine = dump_hook_new_WritePendingRoutine;
	}
	DbgMsg("dump driver functions hooked, hibernation_progress=%d\n", hibernation_progress);
	return status;
}

static NTSTATUS dump_hook_new_crash_DriverEntry_0(IN PVOID               unknown, 
	                                              IN PDUMP_STACK_CONTEXT dumpStack)
{
	return dump_hook_new_DriverEntry(&p_crash_DriverEntry[0], unknown, dumpStack);
}
static NTSTATUS dump_hook_new_crash_DriverEntry_1(IN PVOID               unknown, 
	                                              IN PDUMP_STACK_CONTEXT dumpStack)
{
	return dump_hook_new_DriverEntry(&p_crash_DriverEntry[1], unknown, dumpStack);
}
static NTSTATUS dump_hook_new_crash_DriverEntry_2(IN PVOID               unknown, 
	                                              IN PDUMP_STACK_CONTEXT dumpStack)
{
	return dump_hook_new_DriverEntry(&p_crash_DriverEntry[2], unknown, dumpStack);
}
static NTSTATUS dump_hook_new_crash_DriverEntry_3(IN PVOID               unknown, 
	                                              IN PDUMP_STACK_CONTEXT dumpStack)
{
	return dump_hook_new_DriverEntry(&p_crash_DriverEntry[3], unknown, dumpStack);
}
static NTSTATUS dump_hook_new_hiber_DriverEntry_0(IN PVOID               unknown, 
	                                              IN PDUMP_STACK_CONTEXT dumpStack)
{
	return dump_hook_new_DriverEntry(&p_hiber_DriverEntry[0], unknown, dumpStack);
}
static NTSTATUS dump_hook_new_hiber_DriverEntry_1(IN PVOID               unknown, 
	                                              IN PDUMP_STACK_CONTEXT dumpStack)
{
	return dump_hook_new_DriverEntry(&p_hiber_DriverEntry[1], unknown, dumpStack);
}
static NTSTATUS dump_hook_new_hiber_DriverEntry_2(IN PVOID               unknown, 
	                                              IN PDUMP_STACK_CONTEXT dumpStack)
{
	return dump_hook_new_DriverEntry(&p_hiber_DriverEntry[2], unknown, dumpStack);
}
static NTSTATUS dump_hook_new_hiber_DriverEntry_3(IN PVOID               unknown, 
	                                              IN PDUMP_STACK_CONTEXT dumpStack)
{
	return dump_hook_new_DriverEntry(&p_hiber_DriverEntry[3], unknown, dumpStack);
}

static PLDR_DATA_TABLE_ENTRY dump_hook_find_loader_entry(PVOID ImageBase)
{
	PLDR_DATA_TABLE_ENTRY ldr_entry = NULL;
	PLIST_ENTRY           entry;

	KeEnterCriticalRegion();

	for (entry = p_PsLoadedModuleListHead->Flink; entry != p_PsLoadedModuleListHead; entry = entry->Flink)
	{
		if ( ((PLDR_DATA_TABLE_ENTRY)entry)->DllBase == ImageBase ) {
			ldr_entry = (PLDR_DATA_TABLE_ENTRY)entry;
			break;
		}
	}
	KeLeaveCriticalRegion();
	return ldr_entry;
}

static void dump_hook_notify_image(IN PUNICODE_STRING FullImageName, 
	                               IN HANDLE          ProcessId,
								   IN PIMAGE_INFO     ImageInfo)
{
	PLDR_DATA_TABLE_ENTRY ldr_entry;
	ULONG                 i;
	
	if (ImageInfo->SystemModeImage == 0 || ImageInfo->ImageBase == NULL) return;
	if ((ldr_entry = dump_hook_find_loader_entry(ImageInfo->ImageBase)) == NULL) return;
	if (ldr_entry->BaseDllName.Buffer == NULL || ldr_entry->EntryPoint == NULL) return;

	if (ldr_entry->BaseDllName.Length <= 5*sizeof(wchar_t)) return;
	
	if (ldr_entry->BaseDllName.Length > 5*sizeof(wchar_t) && _wcsnicmp(ldr_entry->BaseDllName.Buffer, L"dump_", 5) == 0)
	{
		i = InterlockedIncrement(&crash_hooks_count) % (sizeof(p_crash_DriverEntry) / sizeof(p_crash_DriverEntry[0]));
		p_crash_DriverEntry[i] = ldr_entry->EntryPoint;

		switch (i) {
			case 0: ldr_entry->EntryPoint = dump_hook_new_crash_DriverEntry_0; break;
			case 1: ldr_entry->EntryPoint = dump_hook_new_crash_DriverEntry_1; break;
			case 2: ldr_entry->EntryPoint = dump_hook_new_crash_DriverEntry_2; break;
			case 3: ldr_entry->EntryPoint = dump_hook_new_crash_DriverEntry_3; break;
			default:
				KeBugCheck(STATUS_INTERNAL_ERROR);
		}
		DbgMsg("crashdump driver loaded, i=%d, BaseDllName=%wZ, FullDllName=%wZ\n", i, &ldr_entry->BaseDllName, &ldr_entry->FullDllName);
	}

	if (ldr_entry->BaseDllName.Length > 5*sizeof(wchar_t) && _wcsnicmp(ldr_entry->BaseDllName.Buffer, L"hiber_", 5) == 0)
	{
		i = InterlockedIncrement(&hiber_hooks_count) % (sizeof(p_hiber_DriverEntry) / sizeof(p_hiber_DriverEntry[0]));
		p_hiber_DriverEntry[i] = ldr_entry->EntryPoint;

		switch (i) {
			case 0: ldr_entry->EntryPoint = dump_hook_new_hiber_DriverEntry_0; break;
			case 1: ldr_entry->EntryPoint = dump_hook_new_hiber_DriverEntry_1; break;
			case 2: ldr_entry->EntryPoint = dump_hook_new_hiber_DriverEntry_2; break;
			case 3: ldr_entry->EntryPoint = dump_hook_new_hiber_DriverEntry_3; break;
			default:
				KeBugCheck(STATUS_INTERNAL_ERROR);
		}
		DbgMsg("hibernation driver loaded, i=%d, BaseDllName=%wZ, FullDllName=%wZ\n", i, &ldr_entry->BaseDllName, &ldr_entry->FullDllName);
	}
}

NTSTATUS dump_hook_init(PDRIVER_OBJECT DriverObject)
{
#if _M_IX86
	PHYSICAL_ADDRESS      allocation_high = { 0xFFFFFFFF, 0 };
#else
	PHYSICAL_ADDRESS      allocation_high = { 0xFFFFFFFF, 0x7FF };
#endif
	PLDR_DATA_TABLE_ENTRY ldr_entry;
	NTSTATUS              status;

	DbgMsg("dump_hook_init\n");

	// find PsLoadedModuleListHead in ntoskrnl
	if ( (DriverObject == NULL || DriverObject->DriverSection == NULL) ||
		 (ldr_entry = *((PLDR_DATA_TABLE_ENTRY*)DriverObject->DriverSection)) == NULL )
	{
		DbgMsg("first LDR_DATA_TABLE_ENTRY is not found\n");
		status = STATUS_PROCEDURE_NOT_FOUND;
		goto cleanup;
	}
	while ( ldr_entry != DriverObject->DriverSection )
	{
		if ( ldr_entry->BaseDllName.Length == 0x18 && *((PULONG)ldr_entry->BaseDllName.Buffer) == 0x0074006E )
		{
			p_PsLoadedModuleListHead = ldr_entry->InLoadOrderLinks.Blink;
			break;
		}
		ldr_entry = (PLDR_DATA_TABLE_ENTRY)ldr_entry->InLoadOrderLinks.Flink;
	}
	
	if (p_PsLoadedModuleListHead == NULL) {
		DbgMsg("PsLoadedModuleListHead is not found\n");
		status = STATUS_VARIABLE_NOT_FOUND;
		goto cleanup;
	}
	
	if ( (dump_hook_mem = (PUCHAR) MmAllocateContiguousMemory(DUMP_MEM_SIZE, allocation_high)) == NULL ||
		 (dump_hook_mdl = IoAllocateMdl(dump_hook_mem, DUMP_MEM_SIZE, FALSE, FALSE, NULL)) == NULL )
	{
		DbgMsg("insufficient resources for dump_hook, mem=%p, mdl=%p\n", dump_hook_mem, dump_hook_mdl);
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto cleanup;
	}
	MmBuildMdlForNonPagedPool(dump_hook_mdl);
	memset(dump_hook_mem, 0, DUMP_MEM_SIZE);

	if ( NT_SUCCESS(status = PsSetLoadImageNotifyRoutine(dump_hook_notify_image)) == FALSE ) {
		DbgMsg("PsSetLoadImageNotifyRoutine fails with status=%0.8x\n", status);
		goto cleanup;
	}
	DbgMsg("dump_hook initialized OK\n");
	status = STATUS_SUCCESS;

cleanup:
	if (NT_SUCCESS(status) == FALSE) {
		if (dump_hook_mdl != NULL) IoFreeMdl(dump_hook_mdl);
		if (dump_hook_mem != NULL) MmFreeContiguousMemory(dump_hook_mem);
		dump_hook_mdl = NULL, dump_hook_mem = NULL;
	}
	return status;
}
