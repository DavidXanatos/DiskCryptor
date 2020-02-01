/** @file
EFI DCS BML helpers routines/wrappers

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov
Copyright (c) 2016. VeraCrypt, Mounir IDRASSI 

This program and the accompanying materials are licensed and made available
under the terms and conditions of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#include <Library/CommonLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/DcsBmlProto.h>

//////////////////////////////////////////////////////////////////////////
// BML
//////////////////////////////////////////////////////////////////////////
EFI_HANDLE*                gBmlHandles = NULL;
UINTN                      gBmlCount = 0;
EFI_DCSBML_PROTOCOL*	   gBml = NULL;
EFI_GUID                   gBmlGuid = EFI_DCSBML_INTERFACE_PROTOCOL_GUID;

EFI_STATUS
BmlSelect(
    IN UINTN index) {
    if (index < gBmlCount) {
        return gBS->HandleProtocol(gBmlHandles[index], &gBmlGuid, (VOID**)&gBml);
    }
    return EFI_NOT_FOUND;
}

EFI_STATUS
InitBml() {
	EFI_STATUS	res;
	// BML control if supported
	res = EfiGetHandles(ByProtocol, &gBmlGuid, 0, &gBmlHandles, &gBmlCount);
	if (gBmlCount > 0) {
		return BmlSelect(gBmlCount - 1);
    }
    return EFI_NOT_FOUND;
}


EFI_STATUS
BmlLock(
	IN UINT32 lock
	)
{
	if (gBml != NULL) {
        return gBml->BootMenuLock(gBml, lock);
	}
	return EFI_UNSUPPORTED;
}

