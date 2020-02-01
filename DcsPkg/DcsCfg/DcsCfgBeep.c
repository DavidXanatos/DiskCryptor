/** @file
This is DCS configuration, speaker beep

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

#include "DcsCfg.h"

//////////////////////////////////////////////////////////////////////////
// Speaker beep
//////////////////////////////////////////////////////////////////////////
void SpeakerPrintDevicePathByIndex(UINTN index) {
	OUT_PRINT(L"%V%d%N ", index);
	EfiPrintDevicePath(gSpeakerHandles[index]);
}

void SpeakerPrintDevicePaths(CHAR16* msg) {
	UINTN i;
	OUT_PRINT(msg);
	for (i = 0; i < gSpeakerCount; ++i) {
		SpeakerPrintDevicePathByIndex(i);
		OUT_PRINT(L"\n");
	}
}

VOID
PrintSpeakerList() {
	InitSpeaker();
	SpeakerPrintDevicePaths(L"%HSpeaker handles%N\n");
}

VOID
TestSpeaker() {
	SpeakerBeep((UINT16)gBeepToneDefault, gBeepNumberDefault, gBeepDurationDefault, gBeepIntervalDefault);
}