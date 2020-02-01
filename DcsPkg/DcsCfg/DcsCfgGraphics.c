/** @file
DCS configuration graphics devices

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov
Copyright (c) 2016. VeraCrypt, Mounir IDRASSI 

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#include <Library/CommonLib.h>
#include <Library/GraphLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/ShellLib.h>

#include <Library/DevicePathLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>

#include "DcsCfg.h"


//////////////////////////////////////////////////////////////////////////
// Graphics
//////////////////////////////////////////////////////////////////////////

void GraphPrintDevicePath(EFI_HANDLE handle) {
	EFI_GRAPHICS_OUTPUT_PROTOCOL*		grfio = NULL;
	EFI_STATUS              res;
	EfiPrintDevicePath(handle);
	res = GraphGetIO(handle, &grfio);
	if (!EFI_ERROR(res) && grfio != NULL) {
		UINT32	i;
		EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL*	cout;
		res = ConsoleGetOutput(handle, &cout);
		OUT_PRINT(L" - %d [%d (%d,%d) %d] %s",
			grfio->Mode->MaxMode, grfio->Mode->Mode,
			grfio->Mode->Info->HorizontalResolution, grfio->Mode->Info->VerticalResolution,
			grfio->Mode->Info->PixelFormat,
			EFI_ERROR(res) ? L"" : L"console"
			);

		for (i = 0; i < grfio->Mode->MaxMode; i++) {
			EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *info;
			UINTN szInfo;
			res = grfio->QueryMode(grfio, i, &szInfo, &info);
			if (!EFI_ERROR(res)) {
				OUT_PRINT(L"\n [%d (%d,%d) %d]",
					i,
					info->HorizontalResolution, info->VerticalResolution,
					grfio->Mode->Info->PixelFormat
					);
			}
		}
	}
}

void GraphPrintDevicePathByIndex(UINTN index) {
	OUT_PRINT(L"%V%d%N ", index);
	GraphPrintDevicePath(gGraphHandles[index]);
}

void GraphPrintDevicePaths(CHAR16* msg) {
	UINTN i;
	OUT_PRINT(msg);
	for (i = 0; i < gGraphCount; ++i) {
		GraphPrintDevicePathByIndex(i);
		OUT_PRINT(L"\n");
	}
}

VOID
PrintGraphList() {
	InitGraph();
	GraphPrintDevicePaths(L"%HGraphics handles%N\n");
}
