/** @file
Block R/W interceptor

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov
Copyright (c) 2016. VeraCrypt, Mounir IDRASSI
Copyright (c) 2019. DiskCryptor, David Xanatos

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#include "DcsInt.h"
#include <Library/DcsIntLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/DevicePathLib.h>
#include <Library/BaseMemoryLib.h>

#include <Library/CommonLib.h>
#include <Library/GraphLib.h>
#include "DcsConfig.h"
#include <Guid/EventGroup.h>


//////////////////////////////////////////////////////////////////////////
// Auxyliary hardware
//////////////////////////////////////////////////////////////////////////
EFI_STATUS 
InitAuxDrivers()
{
	int tmp;

	// touch
	tmp = ConfigReadInt("TouchDevice", -1);
	if (tmp == -1) InitTouch();
	if (tmp >= 0) {
		if (gTouchCount == 0) InitTouch();
		if (tmp < (int)gTouchCount) {
			TouchGetIO(gTouchHandles[tmp], &gTouchPointer);
		}
	}
	gTouchSimulate = ConfigReadInt("TouchSimulate", 0);

	// Graph
	tmp = ConfigReadInt("GraphDevice", -1);
	if (tmp == -1) InitGraph();
	if (tmp >= 0) {
		if (gGraphCount == 0) InitGraph();
		if (tmp < (int)gGraphCount) {
			GraphGetIO(gGraphHandles[tmp], &gGraphOut);
		}
	}
	if (gGraphOut != NULL) {
		tmp = ConfigReadInt("GraphMode", -1);
		if (tmp >= 0 && tmp <= (int)gGraphOut->Mode->MaxMode) {
			gGraphOut->SetMode(gGraphOut, tmp);
		}
	}

	// Beep
	gBeepEnabled = ConfigReadInt("Beep", 0);
	if (gBeepEnabled) {
		gBeepNumberDefault = ConfigReadInt("BeepNumber", 1);
		gBeepDurationDefault = ConfigReadInt("BeepDuration", 100);
		gBeepIntervalDefault = ConfigReadInt("BeepInterval", 0);
		gBeepToneDefault = ConfigReadInt("BeepTone", 0x500);
		gBeepControlEnabled = ConfigReadInt("BeepControl", 1) != 0;

		tmp = ConfigReadInt("BeepDevice", -1);
		if (tmp == -1) InitSpeaker();
		if (tmp >= 0) {
			if (gSpeakerCount == 0) InitSpeaker();
			if (tmp < (int)gSpeakerCount) {
				SpeakerSelect(tmp);
			}
		}
	}

	return EFI_SUCCESS;
}


//////////////////////////////////////////////////////////////////////////
// Exit action
//////////////////////////////////////////////////////////////////////////
enum OnExitTypes{
	OnExitAuthFailed = 1,
	OnExitAuthNotFound,
	OnExitAuthTimeout,
	OnExitAuthCancelled,
	OnExitSuccess
};

BOOLEAN 
AsciiCharNCmp(
	IN CHAR8 ch1,
	IN CHAR8 ch2
	)
{
	return (ch1 | 0x20) == (ch2 | 0x20);
}

VOID* 
VarStrNStr(
	IN VOID* str,
	IN VOID* pattern,
	IN UINTN size) 
{
	CHAR8* pos1 = str;
	CHAR8* pos2;
	CHAR8* posp;
	while (*pos1 != 0) {
		posp = pattern;
		pos2 = pos1;
		while (*posp != 0 && *pos2 != 0 && AsciiCharNCmp(*pos2,*posp)) {
			posp += size;
			pos2 += size;
		}
		if (*pos2 == 0 && *posp) return NULL;
		if (*posp == 0) return pos1;
		pos1 += size;
	}
	return NULL;
}

VOID* 
AsciiStrNStr(
	IN CHAR8* str,
	IN CHAR8* pattern)
{
	return VarStrNStr(str, pattern, sizeof(CHAR8));
}

VOID* 
UnicodeStrNStr(
	IN CHAR16* str,
	IN CHAR16* pattern)
{
	return VarStrNStr(str, pattern, sizeof(CHAR16));
}

BOOLEAN
OnExitGetParam(
	IN CHAR8 *action,
	IN CHAR8 *name,
	OUT CHAR8  **value,
	OUT CHAR16 **valueU
	) 
{
	CHAR8* pos;
	UINTN  len = 0;
	UINTN  i = 0;
	pos = AsciiStrNStr(action, name);
	if (pos == NULL) return FALSE;
	pos += AsciiStrLen(name);
	if(*pos != '(') return FALSE;
	pos++;
	while (pos[len] != 0 && pos[len] != ')') len++;
	if (pos[len] == 0) return FALSE;
	if (value != NULL) *value = MEM_ALLOC(len + 1);
	if (valueU != NULL) *valueU = MEM_ALLOC((len + 1) * 2);
	for (i = 0; i < len; ++i) {
		if (value != NULL) (*value)[i] = pos[i];
		if (valueU != NULL) (*valueU)[i] = pos[i];
	}
	return TRUE;
}

EFI_STATUS
OnExit(
	IN UINTN  type,
	IN EFI_STATUS retValue)
{
	CHAR8* guidStr = NULL;
	CHAR8* exitStatusStr = NULL;
	CHAR8* messageStr = NULL;
	CHAR8* delayStr = NULL;
	EFI_GUID *guid = NULL;
	CHAR16 *fileStr  = NULL;
	CHAR8  action[256] = { 0 };

	if (EFI_ERROR(retValue)) {
		CleanSensitiveData(FALSE);
	}
	
	switch (type) {
	case OnExitAuthFailed:		ConfigReadString("ActionFailed", "Exit", action, sizeof(action));		break;
	case OnExitAuthNotFound:	ConfigReadString("ActionNotFound", "Exit", action, sizeof(action));		break;
	case OnExitAuthTimeout:		ConfigReadString("ActionTimeout", "Shutdown", action, sizeof(action));	break;
	case OnExitAuthCancelled:	ConfigReadString("ActionSuccess", "Continue", action, sizeof(action));	break;
	case OnExitSuccess:			ConfigReadString("ActionCancelled", "Exit", action, sizeof(action));	break;
	}

	if (action[0] == 0) return retValue;

	if (OnExitGetParam(action, "guid", &guidStr, NULL)) {
		EFI_GUID tmp;
		if (DcsAsciiStrToGuid(&tmp, guidStr)) {
			guid = MEM_ALLOC(sizeof(EFI_GUID));
			CopyMem(guid, &tmp, sizeof(EFI_GUID));
		}
	}

	if (OnExitGetParam(action, "status", &exitStatusStr, NULL)) {
		retValue = AsciiStrDecimalToUintn(exitStatusStr);
	}

	if (!OnExitGetParam(action, "file", NULL, &fileStr)) {
		fileStr = NULL;
	}


	if (OnExitGetParam(action, "printinfo", NULL, NULL)) {
		OUT_PRINT(L"type %d\naction %a\n", type, action);
		if (guid != NULL) OUT_PRINT(L"guid %g\n", guid);
		if (fileStr != NULL) OUT_PRINT(L"file %s\n", fileStr);
		if (exitStatusStr != NULL) OUT_PRINT(L"status %d, %r\n", retValue, retValue);
	}

	if (OnExitGetParam(action, "message", &messageStr, NULL)) {
		OUT_PRINT(L"%a", messageStr);
	}

	if (OnExitGetParam(action, "delay", &delayStr, NULL)) {
		UINTN delay;
		EFI_INPUT_KEY key;
		delay = AsciiStrDecimalToUintn(delayStr);
		OUT_PRINT(L"\n");
		key = KeyWait(L"\r%d  ", delay, 0, 0);
		if (key.UnicodeChar != 0) GetKey();
	}

	if (AsciiStrNStr(action, "halt") == action) {
		retValue = EFI_DCS_HALT_REQUESTED;
	}

	else if (AsciiStrNStr(action, "shutdown") == action) {
		retValue = EFI_DCS_SHUTDOWN_REQUESTED;
	}
	
	else if (AsciiStrNStr(action, "reboot") == action) {
		retValue = EFI_DCS_REBOOT_REQUESTED;
	}

	else if (AsciiStrNStr(action, "cancel") == action) {
		retValue = EFI_DCS_USER_CANCELED;
	}

	else if (AsciiStrNStr(action, "exec") == action) {
		if (guid != NULL) {
			EFI_STATUS res;
			EFI_HANDLE h;
			res = EfiFindPartByGUID(guid, &h);
			if (EFI_ERROR(res)) {
				ERR_PRINT(L"\nCan't find start partition\n");
				CleanSensitiveData(FALSE);
				retValue = EFI_DCS_HALT_REQUESTED;
				goto exit;
			}
			// Try to exec
			if (fileStr != NULL) {				
				res = EfiExec(h, fileStr);
				if (EFI_ERROR(res)) {
					ERR_PRINT(L"\nStart %s - %r\n", fileStr, res);
					CleanSensitiveData(FALSE);
					retValue = EFI_DCS_HALT_REQUESTED;
					goto exit;
				}
			}
			else {
				ERR_PRINT(L"\nNo EFI execution path specified. Halting!\n");
				CleanSensitiveData(FALSE);
				retValue = EFI_DCS_HALT_REQUESTED;
				goto exit;
			}
		}		

		if (fileStr != NULL) {
			EfiSetVar(L"DcsExecCmd", NULL, fileStr, (StrLen(fileStr) + 1) * 2, EFI_VARIABLE_BOOTSERVICE_ACCESS);
		}
		goto exit;
	}

	else if (AsciiStrNStr(action, "postexec") == action) {
		if (guid != NULL) {
			EfiSetVar(L"DcsExecPartGuid", NULL, &guid, sizeof(EFI_GUID), EFI_VARIABLE_BOOTSERVICE_ACCESS);
		}
		if (fileStr != NULL) {
			EfiSetVar(L"DcsExecCmd", NULL, fileStr, (StrLen(fileStr) + 1) * 2, EFI_VARIABLE_BOOTSERVICE_ACCESS);
		}

		retValue = EFI_DCS_POSTEXEC_REQUESTED;
		goto exit;
	}

	else if (AsciiStrStr(action, "continue") == action) {
		retValue = EFI_SUCCESS;
		goto exit;
	}
	else if (AsciiStrStr(action, "exit") == action) {
		goto exit;
	}

exit:
	MEM_FREE(guidStr);
	MEM_FREE(exitStatusStr);
	MEM_FREE(messageStr);
	MEM_FREE(delayStr);
	MEM_FREE(guid);
	MEM_FREE(fileStr);
	return retValue;
}

//////////////////////////////////////////////////////////////////////////
// Exit boot loader event
//////////////////////////////////////////////////////////////////////////
EFI_EVENT             mVirtualAddrChangeEvent;
VOID
EFIAPI
VirtualNotifyEvent(
	IN EFI_EVENT        Event,
	IN VOID             *Context
	)
{
	// Clean all sensible info and keys before transfer to OS
	CleanSensitiveData(FALSE);
}

//////////////////////////////////////////////////////////////////////////
// Driver Entry Point
//////////////////////////////////////////////////////////////////////////
EFI_STATUS
UefiMain(
	EFI_HANDLE ImageHandle,
	EFI_SYSTEM_TABLE *SystemTable)
{
	EFI_STATUS res = EFI_SUCCESS;

#ifdef DEBUG_BUILD
	OUT_PRINT(L"DcsInt - DEBUG Build %s %s\n", _T(__DATE__), _T(__TIME__)); 
#endif

	InitBio();
	InitFS();
	InitConfig(CONFIG_FILE_PATH);
	InitParams();
	InitAuxDrivers();

#ifndef NO_BML
	// Remove BootNext to restore boot order
	BootMenuItemRemove(L"BootNext");
#endif

	//if (gExternMode) {
	//	ERR_PRINT(L"Extern Mode\n");
	//}

#ifdef DCS_SINGLE_MODULE

  #if DCS_SINGLE_MODULE == 0xDC
	res = DcsDiskCryptor(ImageHandle, SystemTable);
  #elif DCS_SINGLE_MODULE == 0x4C
	res = DcsVeraCrypt(ImageHandle, SystemTable);
  #else
	#error "Unknown DCS Module";
  #endif

#else
	PMENU_ITEM gMenu = NULL;
	PMENU_ITEM item = gMenu;
	CHAR16* presetImpl = NULL;

#pragma warning(disable:4054)
	gMenu = 
	item = DcsMenuAppend(item, L"DiskCryptor", 'd', NULL, (VOID*)DcsDiskCryptor);
	item = DcsMenuAppend(item, L"VeraCrypt", 'v', NULL, (VOID*)DcsVeraCrypt);
#pragma warning(default:4054)
	item = NULL;

	presetImpl = ConfigReadStringW("DcsModule", L"", NULL, 100);
	if (presetImpl[0] != L'\0') {
		item = gMenu;
		while (item != NULL) {
			if (UnicodeStrNStr(presetImpl, item->Text) == presetImpl) break;
			item = item->Next;
		}
	}

	if (item == NULL) {
		OUT_PRINT(L"Select Support Module:\n");
		DcsMenuPrint(gMenu);

		do {
			EFI_INPUT_KEY key = GetKey();

			if (key.ScanCode == SCAN_ESC) {
				return EFI_DCS_USER_CANCELED;
			}

			item = gMenu;
			while (item != NULL) {
				if (item->Select == key.UnicodeChar) break;
				item = item->Next;
			}
		} while (item == NULL);

		OUT_PRINT(L"\n");
	}
	else {
		if (gConfigDebug) {
			OUT_PRINT(L"Support Module: %H%s%N\n", item->Text);
		}
	}

#pragma warning(disable:4055)
	res = ((DCS_IMPL)item->Context)(ImageHandle, SystemTable);
#pragma warning(default:4055)

#endif

	if (gConfigDebug) {
		OUT_PRINT(L"DcsInt done\n");
	}

	if (EFI_ERROR(res)) {
		if (res == EFI_DCS_USER_TIMEOUT)
			return OnExit(OnExitAuthTimeout, res);
		else if (res == EFI_DCS_USER_CANCELED)
			return OnExit(OnExitAuthCancelled, res);
		else if (res == EFI_DCS_DATA_NOT_FOUND)
			return OnExit(OnExitAuthNotFound, res);
		else
			return OnExit(OnExitAuthFailed, res);
	}

	res = gBS->CreateEventEx(
		EVT_NOTIFY_SIGNAL,
		TPL_NOTIFY,
		VirtualNotifyEvent,
		NULL,
		&gEfiEventVirtualAddressChangeGuid,
		&mVirtualAddrChangeEvent
		);

	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Failed to setup VirtualAddrChangeEvent to Clean Sensitive Data from RAM after boot!");
	}

	return OnExit(OnExitSuccess, EFI_SUCCESS);
}
