/** @file
DCS configuration. Touch devices.

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov
Copyright (c) 2016. VeraCrypt, Mounir IDRASSI 

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#include <Library/CommonLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DevicePathLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>

#include "DcsCfg.h"

//////////////////////////////////////////////////////////////////////////
// Touch
//////////////////////////////////////////////////////////////////////////
UINTN       TouchIndex = 0;

void TouchPrintDevicePath(EFI_HANDLE handle) {
	EFI_ABSOLUTE_POINTER_PROTOCOL*		absio = NULL;
	EfiPrintDevicePath(handle);
	TouchGetIO(handle, &absio);
	if (absio != NULL) {
		EFI_STATUS              res;
		EFI_ABSOLUTE_POINTER_STATE		aps;
		SetMem(&aps, sizeof(aps), 0);
		res = absio->GetState(absio, &aps);
		OUT_PRINT(L" - X[%lld,%lld] Y[%lld,%lld] Z[%lld,%lld] A[0x%x] S[%r (%lld,%lld,%lld), 0x%x]",
			absio->Mode->AbsoluteMinX, absio->Mode->AbsoluteMaxX,
			absio->Mode->AbsoluteMinY, absio->Mode->AbsoluteMaxY,
			absio->Mode->AbsoluteMinZ, absio->Mode->AbsoluteMaxZ,
			absio->Mode->Attributes,
			res, aps.CurrentX, aps.CurrentY, aps.CurrentZ, aps.ActiveButtons
			);
	}
}

void TouchPrintDevicePathByIndex(UINTN touchIndex) {
	OUT_PRINT(L"%V%d%N ", touchIndex);
	TouchPrintDevicePath(gTouchHandles[touchIndex]);
}

void TouchPrintDevicePaths(CHAR16* msg) {
	UINTN i;
	OUT_PRINT(msg);
	for (i = 0; i < gTouchCount; ++i) {
		TouchPrintDevicePathByIndex(i);
		OUT_PRINT(L"\n");
	}
}

VOID
PrintTouchList() {
	InitTouch();
	TouchPrintDevicePaths(L"%HTouch handles%N\n");
}

VOID
TestTouch() {
	EFI_ABSOLUTE_POINTER_PROTOCOL*		absio = NULL;
	EFI_HANDLE					handle;
	EFI_STATUS              res;

	InitTouch();
	if (TouchIndex >= gTouchCount) return;
	handle = gTouchHandles[TouchIndex];
	EfiPrintDevicePath(handle);
	TouchGetIO(handle, &absio);
	if (absio != NULL) {
		EFI_ABSOLUTE_POINTER_STATE		aps;
		EFI_EVENT		events[2];
		UINTN EventIndex;

		events[0] = gST->ConIn->WaitForKey;
		events[1] = absio->WaitForInput;
		do {
			gBS->WaitForEvent(2, events, &EventIndex);
			SetMem(&aps, sizeof(aps), 0);
			res = absio->GetState(absio, &aps);
			OUT_PRINT(L" S[%r (%lld,%lld,%lld), 0x%x]",
				res, aps.CurrentX, aps.CurrentY, aps.CurrentZ, aps.ActiveButtons
				);
		} while (EventIndex == 1);
	}
}

