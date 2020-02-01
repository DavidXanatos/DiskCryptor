/** @file
DCS configuration block devices

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
#include <Library/BaseMemoryLib.h>
#include <Uefi/UefiGpt.h>
#include <Guid/Gpt.h>

#include "DcsCfg.h"

//////////////////////////////////////////////////////////////////////////
// Block I/O
//////////////////////////////////////////////////////////////////////////
UINTN       BioIndexStart = 0;
UINTN       BioIndexEnd = 0;
BOOLEAN     BioSkipPartitions = FALSE;

void BioPrintDevicePath(UINTN bioIndex) {
	OUT_PRINT(L"%V%d%N ", bioIndex);
	EfiPrintDevicePath(gBIOHandles[bioIndex]);
}

void BioPrintDevicePaths(CHAR16* msg) {
	UINTN i;
	OUT_PRINT(msg);
	if (BioIndexStart >= gBIOCount) return;
	for (i = BioIndexStart; i < gBIOCount; ++i) {
		if(BioSkipPartitions && EfiIsPartition(gBIOHandles[i])) continue;
		BioPrintDevicePath(i);
		OUT_PRINT(L"\n");
	}
}

VOID
PrintBioList() {
	InitBio();
	BioPrintDevicePaths(L"%HBlock IO handles%N\n");
}

