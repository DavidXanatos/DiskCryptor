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
#include "dump_filter.h"
#include "dump_helpers.h"
#include "debug.h"
#include "driver.h"
#include "devhook.h"
#include "device_io.h"

static NTSTATUS dump_status = STATUS_UNSUCCESSFUL;
static PUCHAR   dump_mem_data = NULL;
static ULONG    dump_mem_size = 0;
static PMDL     dump_temp_mdl = NULL; // template MDL describes the dump_mem_data buffer

static NTSTATUS dump_filter_DumpStart(IN PFILTER_EXTENSION FilterExtension)
{
	DbgMsg("dump_filter_DumpStart, FilterExtension=%p, DumpType=%d\n", FilterExtension, FilterExtension->DumpType);
	
	if ( !NT_SUCCESS(dump_status = dc_dump_helpers.dump_start(FilterExtension->DumpType == DumpTypeHibernation)) )
	{
		// bugcheck if dump can not be written securely
		if (dump_status != STATUS_FVE_NOT_ENCRYPTED)
		{
			KeBugCheckEx(STATUS_ENCRYPTION_FAILED, __LINE__, dump_status, FilterExtension->DumpType, 0);
		}

		DbgMsg("dump encryption don't needed\n");
		return dump_status;
	}

	return STATUS_SUCCESS;
}

static NTSTATUS dump_filter_DumpWrite(IN PFILTER_EXTENSION FilterExtension,
	                                  IN PLARGE_INTEGER    DiskByteOffset,
									  IN PMDL              Mdl)
{
	NTSTATUS status;

	if ( !NT_SUCCESS(dump_status) )
	{
		if (dump_status == STATUS_FVE_NOT_ENCRYPTED) return STATUS_SUCCESS; // return STATUS_SUCCESS if encryption is not needed
		KeBugCheckEx(STATUS_ENCRYPTION_FAILED, __LINE__, dump_status, FilterExtension->DumpType, 0);
	}

	// bugcheck if required parameter are not specified
	if (DiskByteOffset == NULL || Mdl == NULL)
	{
		KeBugCheckEx(STATUS_INVALID_PARAMETER, __LINE__, (ULONG_PTR)FilterExtension, (ULONG_PTR)DiskByteOffset, (ULONG_PTR)Mdl);
	}

	// bugcheck if encryption data too large
	if (Mdl->ByteCount > dump_mem_size)
	{
		KeBugCheckEx(STATUS_BUFFER_OVERFLOW, __LINE__, Mdl->ByteCount, 0, 0);
	}

	// encrypt the data (bugcheck if failed)
	if ( !NT_SUCCESS(status = dc_dump_helpers.dump_encrypt(DiskByteOffset, Mdl, dump_mem_data)) )
	{
		KeBugCheckEx(STATUS_ENCRYPTION_FAILED, __LINE__, status, Mdl->ByteCount, 0);
	}

	// Callers of MmBuildMdlForNonPagedPool must be running at IRQL <= DISPATCH_LEVEL, we cannot use it
	// copy PFN's from dump_temp_mdl to Mdl and change system buffers pointers
	memcpy(
		MmGetMdlPfnArray(Mdl),
		MmGetMdlPfnArray(dump_temp_mdl),
		ADDRESS_AND_SIZE_TO_SPAN_PAGES(dump_mem_data, Mdl->ByteCount) * sizeof(PFN_NUMBER)
	);
	Mdl->MappedSystemVa = dump_temp_mdl->MappedSystemVa;
    Mdl->StartVa = dump_temp_mdl->StartVa;
    Mdl->ByteOffset = dump_temp_mdl->ByteOffset;

	return STATUS_SUCCESS;
}

static NTSTATUS dump_filter_DumpFinish(IN PFILTER_EXTENSION FilterExtension)
{
	RtlSecureZeroMemory(dump_mem_data, dump_mem_size);
	dc_dump_helpers.dump_finish();

	return STATUS_SUCCESS;
}

static NTSTATUS dump_filter_DumpUnload(IN PFILTER_EXTENSION FilterExtension)
{
	DbgMsg("dump_filter_DumpUnload, FilterExtension=%p, DumpType=%d\n", FilterExtension, FilterExtension->DumpType);

	RtlSecureZeroMemory(dump_mem_data, dump_mem_size);
	IoFreeMdl(dump_temp_mdl);
	MmFreeContiguousMemory(dump_mem_data);
	return STATUS_SUCCESS;
}

NTSTATUS dump_filter_DriverEntry(IN PFILTER_EXTENSION           FilterExtension,    // FILTER_EXTENSION structure, passed by OS in 1st parameter of DriverEntry
	                             IN PFILTER_INITIALIZATION_DATA InitializationData) // FILTER_INITIALIZATION_DATA structure, passed by OS in 2nd parameter of DriverEntry
{
#if _M_IX86
	PHYSICAL_ADDRESS allocation_high = { 0xFFFFFFFF, 0 };
#else
	PHYSICAL_ADDRESS allocation_high = { 0xFFFFFFFF, 0x7FF };
#endif
	NTSTATUS         status;
	ULONG            version = 0;

	DbgMsg("dump_filter_DriverEntry, FilterExtension=%p, DumpType=%d, IRQL=%d, MaxPagesPerWrite=%u\n", FilterExtension,
		                                                                                               FilterExtension->DumpType,
																									   KeGetCurrentIrql(),
																									   InitializationData->MaxPagesPerWrite);

	// this is critical filter, system should not write dumps if this filter is not initialized
	InitializationData->MajorVersion = DUMP_FILTER_MAJOR_VERSION;
	InitializationData->MinorVersion = DUMP_FILTER_MINOR_VERSION;
	InitializationData->Flags |= DUMP_FILTER_CRITICAL;

	// check input structures	
	if ( (dump_mem_size = InitializationData->MaxPagesPerWrite * PAGE_SIZE) == 0 ) {
		DbgMsg("FILTER_INITIALIZATION_DATA.MaxPagesPerWrite are invalid\n");
		return STATUS_INVALID_PARAMETER;
	}
	if (FilterExtension->DumpType != DumpTypeCrashdump && FilterExtension->DumpType != DumpTypeHibernation) {
		DbgMsg("FILTER_EXTENSION.DumpType are invalid\n");
		return STATUS_INVALID_PARAMETER;
	}

	// check version of main driver copy
	if ( !NT_SUCCESS(status = io_device_control(dc_device, DC_GET_VERSION, NULL, 0, &version, sizeof(version))) || version != DC_DRIVER_VER )
	{
		DbgMsg("invalid driver version, status=%08x, filter_v=%u, main_v=%u\n", status, DC_DRIVER_VER, version);
		return STATUS_INVALID_PARAMETER;
	}
	if ( !NT_SUCCESS(status = io_device_control(dc_device, DC_GET_DUMP_HELPERS, NULL, 0, &dc_dump_helpers, sizeof(DC_DUMP_HELPERS))) )
	{
		DbgMsg("DC_GET_DUMP_HELPERS failed, status=%08x\n", status);
		return status;
	}

	if ( (dump_mem_data = (PUCHAR)MmAllocateContiguousMemory(dump_mem_size, allocation_high)) == NULL ||
		 (dump_temp_mdl = IoAllocateMdl(dump_mem_data, dump_mem_size, FALSE, FALSE, NULL)) == NULL )
	{
		DbgMsg("insufficient resources for dump_filter\n");

		if (dump_mem_data != NULL) MmFreeContiguousMemory(dump_mem_data);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	MmBuildMdlForNonPagedPool(dump_temp_mdl);
	memset(dump_mem_data, 0, dump_mem_size);

	// setup dump filter routines
	InitializationData->DumpStart = dump_filter_DumpStart;
	InitializationData->DumpWrite = dump_filter_DumpWrite;
	InitializationData->DumpFinish = dump_filter_DumpFinish;
	InitializationData->DumpUnload = dump_filter_DumpUnload;

	return STATUS_SUCCESS;
}
