/** @file
EFI touch/absolute pointer helpers

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov
Copyright (c) 2016. VeraCrypt, Mounir IDRASSI 

This program and the accompanying materials are licensed and made available
under the terms and conditions of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/
#include <Library/CommonLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DevicePathLib.h>
#include <Library/PrintLib.h>
#include <Protocol/AbsolutePointer.h>

EFI_HANDLE* gTouchHandles = NULL;
UINTN       gTouchCount = 0;
int         gTouchSimulate = 0;
UINT32      gTouchSimulateStep = 1;

EFI_ABSOLUTE_POINTER_PROTOCOL*	gTouchPointer = NULL;

EFI_STATUS
InitTouch() {
	EFI_STATUS res;
	res = EfiGetHandles(ByProtocol, &gEfiAbsolutePointerProtocolGuid, 0, &gTouchHandles, &gTouchCount);
	if (gTouchCount > 0) {
		TouchGetIO(gTouchHandles[gTouchCount - 1], &gTouchPointer);
	}
	return res;
}


EFI_STATUS
TouchGetIO(
	IN    EFI_HANDLE								Handle,
	OUT   EFI_ABSOLUTE_POINTER_PROTOCOL**	io
	) {
	if (!io) {
		return EFI_INVALID_PARAMETER;
	}
	return gBS->HandleProtocol(Handle, &gEfiAbsolutePointerProtocolGuid, (VOID**)io);
}

