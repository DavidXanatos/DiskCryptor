/** @file
EFI speaker beep helpers routines/wrappers

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov
Copyright (c) 2016. VeraCrypt, Mounir IDRASSI 

This program and the accompanying materials are licensed and made available
under the terms and conditions of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#include <Library/CommonLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/Speaker.h>

//////////////////////////////////////////////////////////////////////////
// Beep
//////////////////////////////////////////////////////////////////////////
EFI_HANDLE*                gSpeakerHandles = NULL;
UINTN                      gSpeakerCount = 0;
EFI_SPEAKER_IF_PROTOCOL*	gSpeaker = NULL;
EFI_GUID                   gSpeakerGuid = EFI_SPEAKER_INTERFACE_PROTOCOL_GUID;

// Beep defaults
int gBeepEnabled = 1;
BOOLEAN	gBeepControlEnabled = 1;
int gBeepDevice = -1;
int gBeepNumberDefault = 1;
int gBeepDurationDefault = 100;
int gBeepIntervalDefault = 0;
int gBeepToneDefault = 0x500;

EFI_STATUS
InitSpeaker() {
	EFI_STATUS	res;
	// Init Console control if supported
	res = EfiGetHandles(ByProtocol, &gSpeakerGuid, 0, &gSpeakerHandles, &gSpeakerCount);
	if (gSpeakerCount > 0) {
		return SpeakerSelect(gSpeakerCount - 1);
	}
	return res;
}

EFI_STATUS
SpeakerSelect(
	IN UINTN index) {
	if (index < gSpeakerCount) {
		return gBS->HandleProtocol(gSpeakerHandles[index], &gSpeakerGuid, (VOID**)&gSpeaker);
	}
	return EFI_NOT_FOUND;
}

EFI_STATUS
SpeakerBeep(
	IN UINT16  Tone,
	IN UINTN   NumberOfBeeps,
	IN UINTN   Duration,
	IN UINTN   Interval
	)
{
	if (gSpeaker != NULL) {
		gSpeaker->SetSpeakerToneFrequency(gSpeaker, Tone);
		return gSpeaker->GenerateBeep(gSpeaker, NumberOfBeeps, Duration, Interval);
	}
	return EFI_UNSUPPORTED;
}

