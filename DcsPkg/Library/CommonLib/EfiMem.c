/** @file
EFI memory helpers routines/wrappers

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov
Copyright (c) 2016. VeraCrypt, Mounir IDRASSI 

This program and the accompanying materials are licensed and made available
under the terms and conditions of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#include <Uefi.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/BaseMemoryLib.h>

#include "Library/CommonLib.h"


//////////////////////////////////////////////////////////////////////////
// Memory procedures wrappers
//////////////////////////////////////////////////////////////////////////

VOID*
MemAlloc(
   IN UINTN size
   ) {
   return AllocateZeroPool(size);
}

VOID*
MemRealloc(
	IN UINTN  OldSize,
	IN UINTN  NewSize,
	IN VOID   *OldBuffer  OPTIONAL
	) {
	return ReallocatePool(OldSize, NewSize, OldBuffer);
}

VOID
MemFree(
   IN VOID* ptr
   ) {
	if(ptr != NULL) FreePool(ptr);
}

//////////////////////////////////////////////////////////////////////////
// Memory mapped IO
//////////////////////////////////////////////////////////////////////////

EFI_STATUS
PrepareMemory(
   IN UINTN    address,
   IN UINTN    len,
   OUT VOID**  mem)
{
   EFI_STATUS              status;
   EFI_PHYSICAL_ADDRESS    ptr;
   VOID*                   buf;
   UINTN                   pages;
   pages = ((len & ~0x0FFF) + 0x1000) >> 12;
   ptr = address & ~0x0FFF;
//	OUT_PRINT(L"mem try %0x, %0x\n", pages, (UINTN)ptr);
   status = gBS->AllocatePages(AllocateAddress, EfiMemoryMappedIO, pages, &ptr);
   if (EFI_ERROR(status)) {
      return status;
   }
   buf = (void*)(UINTN)ptr;
   SetMem(buf, pages << 12, 0);
   *mem = buf;
   return status;
}

//////////////////////////////////////////////////////////////////////////
// Memory misc
//////////////////////////////////////////////////////////////////////////
EFI_STATUS MemoryHasPattern (
	CONST VOID* buffer,
	UINTN bufferLen,
	CONST VOID* pattern,
	UINTN patternLen)
{
	EFI_STATUS status = EFI_NOT_FOUND;
	if (patternLen <= bufferLen)
	{
		UINTN i;
		CONST UINT8* memPtr = (CONST UINT8*) buffer;
		for (i = 0; i <= (bufferLen - patternLen); ++i)
		{
			if (CompareMem (&memPtr[i], pattern, patternLen) == 0)
			{
				status = EFI_SUCCESS;
				break;
			}
		}
	}

	return status;
}
