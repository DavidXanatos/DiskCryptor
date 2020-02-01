/** @file
Ask password from console

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov
Copyright (c) 2016. VeraCrypt, Mounir IDRASSI
Copyright (c) 2019. DiskCryptor, David Xanatos

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#include <Uefi.h>
#include "Library/CommonLib.h"
#include "Library/PasswordLib.h"
#include <Library/UefiBootServicesTableLib.h>

VOID
AskConsolePwdInt(
	OUT UINT32   *length,
	OUT VOID     *asciiLine,
	OUT INT32    *retCode,
	IN  UINTN    length_max,
	IN  UINT8    show,
	IN  BOOLEAN  wide
	)
{
	EFI_INPUT_KEY key;
	UINT32 count = 0;
	UINTN i;
	UINTN line_max = length_max;
	if (wide)
		line_max /= 2;

	if ((asciiLine != NULL) && (line_max >= 1))
		SET_VAR_CHAR(asciiLine, wide, 0, '\0'); //asciiLine[0] = '\0';

	gST->ConOut->EnableCursor(gST->ConOut, TRUE);
	if (gPasswordTimeout) {
		EFI_EVENT      InputEvents[2];
		UINTN          EventIndex = 0;
		InputEvents[0] = gST->ConIn->WaitForKey;
		gBS->CreateEvent(EVT_TIMER, 0, (EFI_EVENT_NOTIFY)NULL, NULL, &InputEvents[1]);
		gBS->SetTimer(InputEvents[1], TimerRelative, 10000000 * gPasswordTimeout);
		gBS->WaitForEvent(2, InputEvents, &EventIndex);
		gBS->SetTimer(InputEvents[1], TimerCancel, 0);
		gBS->CloseEvent(InputEvents[1]);
		if (EventIndex == 1) {
			*retCode = AskPwdRetTimeout;
			return ;
		}
	}

	do {
		key = GetKey();
		// Remove dirty chars 0.1s
		FlushInputDelay(100000);
		
		if (key.ScanCode == SCAN_ESC) {
			*retCode = AskPwdRetCancel;
			break;
		}

		if (key.ScanCode == SCAN_F2) {
			*retCode = AskPwdRetChange;
			break;
		}

		if (key.ScanCode == SCAN_F3) {
			*retCode = AskPwdForcePass;
			break;
		}

		// SCAN_F4

		if (key.ScanCode == SCAN_F5) {
			show = show ? 0 : 1;
			if (count > 0) {
				if (show) {
					for (i = 0; i < count; i++) {
						OUT_PRINT(L"\b");
					}
					if (wide)
						OUT_PRINT(L"%s", asciiLine);
					else
						OUT_PRINT(L"%a", asciiLine);
				}
				else {
					for (i = 0; i < count; i++) {
						OUT_PRINT(L"\b");
					}
					if (gPasswordProgress) {
						for (i = 0; i < count; i++) {
							OUT_PRINT(L"*");
						}
					}
				}
			}
		}

		// SCAN_F6

		if (key.ScanCode == SCAN_F7) {
			gPlatformLocked = gPlatformLocked ? 0 : 1;
			ConsoleShowTip(gPlatformLocked ? L" Platform locked!" : L" Platform unlocked!", 10000000);
		}

		if (key.ScanCode == SCAN_F8) {
			gTPMLocked = gTPMLocked ? 0 : 1;
			ConsoleShowTip(gTPMLocked ? L" TPM locked!" : L" TPM unlocked!", 10000000);
		}

		if (key.ScanCode == SCAN_F9) {
			gSCLocked = gSCLocked ? 0 : 1;
			ConsoleShowTip(gSCLocked ? L" Smart card locked!" : L" Smart card unlocked!", 10000000);
		}

		// SCAN_F10
		// SCAN_F11
		// SCAN_F12

		if (key.UnicodeChar == CHAR_CARRIAGE_RETURN) {
			*retCode = AskPwdRetLogin;
			break;
		}

		if ((count >= (line_max - 1) &&
			key.UnicodeChar != CHAR_BACKSPACE) ||
			key.UnicodeChar == CHAR_NULL ||
			key.UnicodeChar == CHAR_TAB ||
			key.UnicodeChar == CHAR_LINEFEED ||
			key.UnicodeChar == CHAR_CARRIAGE_RETURN) {
			continue;
		}

		if (count == 0 && key.UnicodeChar == CHAR_BACKSPACE) {
			continue;
		}
		else if (key.UnicodeChar == CHAR_BACKSPACE) {
			if (gPasswordProgress || show) {
				OUT_PRINT(L"\b \b");
			}
			if (asciiLine != NULL) 
				SET_VAR_CHAR(asciiLine, wide, --count, '\0'); //asciiLine[--count] = '\0';
			continue;
		}

		// check size of line
		if (count < line_max - 1) {
			if (show) {
				OUT_PRINT(L"%c", key.UnicodeChar);
			}	else if (gPasswordProgress) {
				OUT_PRINT(L"*");
			}
			// save char
			if (asciiLine != NULL) {
				SET_VAR_CHAR(asciiLine, wide, count++, (CHAR8)key.UnicodeChar); //asciiLine[count++] = (CHAR8)key.UnicodeChar;
				SET_VAR_CHAR(asciiLine, wide, count, '\0'); //asciiLine[count] = 0;
			}
		}
	} while (key.UnicodeChar != CHAR_CARRIAGE_RETURN);

	if (length != NULL) {
		*length = count;
		if (wide)
			*length *= 2;
	}
	MEM_BURN (&key, sizeof (key));
	// Set end of line
	if (asciiLine != NULL) {
		SET_VAR_CHAR(asciiLine, wide, count, '\0'); //asciiLine[count] = '\0';
		if (gPasswordProgress || show) {
			for (i = 0; i < count; i++) {
				OUT_PRINT(L"\b \b");
			}
			OUT_PRINT(L"*");
		}
	}
	OUT_PRINT(L"\n");
}
