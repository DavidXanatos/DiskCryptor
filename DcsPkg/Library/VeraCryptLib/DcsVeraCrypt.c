/** @file
Interface for DCS

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov
Copyright (c) 2016. VeraCrypt, Mounir IDRASSI

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the Apache License, Version 2.0.  

The full text of the license may be found at
https://opensource.org/licenses/Apache-2.0
**/

#include <DcsVeraCrypt.h>
#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/PrintLib.h>

#include <Library/CommonLib.h>
#include <Library/GraphLib.h>
#include <Library/PasswordLib.h>
#include <Library/DcsCfgLib.h>

#include <common/Password.h>
#include "common/Crypto.h"
#include "common/Crc.h"
#include "BootCommon.h"
#include "Library/DcsTpmLib.h"
#include <DcsConfig.h>

///////////////////////////////////////////////////////////////////////////
// Globals
//////////////////////////////////////////////////////////////////////////
#define MAX_MSG 256
int gAuthPasswordType = 0;
char* gAuthPasswordMsg = NULL;
Password gAuthPassword;

UINT8 gAutoLogin = 0;
char* gAutoPassword = NULL;

char* gAuthPimMsg = NULL;
int gAuthPimRqt = 1;
int gAuthPim = 0;

int gAuthTcRqt = 0;
int gAuthTc = 0;

char *gAuthHashMsg = NULL;
int gAuthHashRqt = 1;
int gAuthHash = 0;

int gAuthBootRqt = 0;
int gAuthBoot = 1;

int gAuthRetry = 10;
int gAuthPwdCode = 1;
int gRndDefault = 0;

char* gAuthErrorMsg = NULL;
char* gAuthStartMsg = NULL;

INT32 gRUD = 0;

int gAuthSecRegionSearch = 0;
int gSecRegionInfoDelay = 0;

CHAR8* gPlatformKeyFile = NULL;
UINTN gPlatformKeyFileSize = 0;

EFI_GUID *gPartitionGuidOS = NULL;

int gDcsBootForce = 1;
char* gForcePasswordMsg = NULL;
int gForcePasswordType = 0;
UINT8 gForcePasswordProgress = 1;

//////////////////////////////////////////////////////////////////////////
// Authorize
/////////////////////////////////////////////////////////////////////////

#define VCCONFIG_ALLOC(data, size)       \
        if(data != NULL) MEM_FREE(data); \
        data = MEM_ALLOC(size);

VOID
VCAuthLoadConfig() 
{
	int tmp;
	char* strTemp = NULL;

	if (gAuthPasswordMsg != NULL) return; // Already loaded

	SetMem(&gAuthPassword, sizeof(gAuthPassword), 0);

	VCCONFIG_ALLOC(gPasswordPictureFileName, MAX_MSG * 2);
	ConfigReadStringW("PasswordPicture", L"\\EFI\\" DCS_DIRECTORY L"\\login.bmp", gPasswordPictureFileName, MAX_MSG);

	VCCONFIG_ALLOC(gPasswordPictureChars, MAX_MSG);
	ConfigReadString("PictureChars", gPasswordPictureCharsDefault, gPasswordPictureChars, MAX_MSG);
	gPasswordPictureCharsLen = strlen(gPasswordPictureChars);

	gAuthPasswordType = ConfigReadInt("PasswordType", 0);

	gKeyboardLayout = ConfigReadInt("KeyboardLayout", 0);

	VCCONFIG_ALLOC(gAuthPasswordMsg, MAX_MSG);
	ConfigReadString("PasswordMsg", "Password:", gAuthPasswordMsg, MAX_MSG);

	gAutoLogin = (UINT8)ConfigReadInt("AutoLogin", 0);
	VCCONFIG_ALLOC(gAutoPassword, MAX_PASSWORD);
	ConfigReadString("AutoPassword", "", gAutoPassword, MAX_PASSWORD);

	VCCONFIG_ALLOC(gAuthPimMsg, MAX_MSG);
	gAuthPimRqt = ConfigReadInt("PimRqt", 1);
	gAuthPim = ConfigReadInt("Pim", 0);
	ConfigReadString("PimMsg", "Pim:", gAuthPimMsg, MAX_MSG);

	VCCONFIG_ALLOC(gAuthHashMsg, MAX_MSG);
	gAuthHashRqt = ConfigReadInt("HashRqt", 1);
	gAuthHash = ConfigReadInt("Hash", 0);

	strTemp = MEM_ALLOC(MAX_MSG);
	tmp = 1;
	AsciiSPrint(strTemp, MAX_MSG, "(0) TEST ALL");
	while (HashGetName(tmp) != NULL && *HashGetName(tmp) != 0)
	{
		AsciiSPrint(strTemp, MAX_MSG, "%a (%d) %s", strTemp, tmp, HashGetName(tmp));
		++tmp;
	};
	AsciiSPrint(strTemp, MAX_MSG, "%a \n\rHash:", strTemp);
	ConfigReadString("HashMsg", strTemp, gAuthHashMsg, MAX_MSG);
	MEM_FREE(strTemp);


	gAuthBootRqt = ConfigReadInt("BootRqt", 0);
	gAuthTcRqt = ConfigReadInt("TcRqt", 0);

	gPasswordProgress = (UINT8)ConfigReadInt("AuthorizeProgress", 1); // print "*"

	gPasswordVisible = (UINT8)ConfigReadInt("AuthorizeVisible", 0);   // show chars
	gPasswordHideLetters = ConfigReadInt("PasswordHideLetters", 1);   // always show letters in touch points
	gPasswordShowMark = ConfigReadInt("AuthorizeMarkTouch", 1);       // show touch points

	gPasswordTimeout = (UINT8)ConfigReadInt("PasswordTimeout", 180);   // If no password for <seconds> => <ESC>

	gDcsBootForce = ConfigReadInt("DcsBootForce", 1);                 // Ask password even if no USB marked found. 

	VCCONFIG_ALLOC(gForcePasswordMsg, MAX_MSG);
	ConfigReadString("ForcePasswordMsg", gAuthPasswordMsg, gForcePasswordMsg, MAX_MSG);
	gForcePasswordType = ConfigReadInt("ForcePasswordType", gAuthPasswordType);
	gForcePasswordProgress = (UINT8)ConfigReadInt("ForcePasswordProgress", gPasswordProgress);

	gAuthRetry = ConfigReadInt("AuthorizeRetry", 10);
	VCCONFIG_ALLOC(gAuthStartMsg, MAX_MSG);
	ConfigReadString("AuthStartMsg", "Authorizing...\n\r", gAuthStartMsg, MAX_MSG);
	VCCONFIG_ALLOC(gAuthErrorMsg, MAX_MSG);
	ConfigReadString("AuthErrorMsg", "Authorization failed. Wrong password, PIM or hash.\n\r", gAuthErrorMsg, MAX_MSG);

	gRUD = ConfigReadInt("RUD", 0);

	gRndDefault = ConfigReadInt("Random", 0);

	gAuthSecRegionSearch = ConfigReadInt("SecRegionSearch", 0);
	gSecRegionInfoDelay = ConfigReadInt("SecRegionInfoDelay", 0);

	gPlatformLocked = ConfigReadInt("PlatformLocked", 0);
	gTPMLocked = ConfigReadInt("TPMLocked", 0);
	gTPMLockedInfoDelay = ConfigReadInt("TPMLockedInfoDelay", 9);
	gSCLocked = ConfigReadInt("SCLocked", 0);

	strTemp = MEM_ALLOC(MAX_MSG);
	ConfigReadString("PartitionGuidOS", "", strTemp, MAX_MSG);
	if (strTemp[0] != 0) {
		EFI_GUID g;
		if (DcsAsciiStrToGuid(&g, strTemp)) {
			VCCONFIG_ALLOC(gPartitionGuidOS, sizeof(EFI_GUID));
			if (gPartitionGuidOS != NULL) {
				memcpy(gPartitionGuidOS, &g, sizeof(g));
			}
		}
	}
	MEM_FREE(strTemp);
}

//////////////////////////////////////////////////////////////////////////
// Configuration menu
//////////////////////////////////////////////////////////////////////////
PMENU_ITEM          gCfgMenu = NULL;
BOOLEAN             gCfgMenuContinue = TRUE;

EFI_STATUS
ActionCfgReboot(IN VOID *ctx) {
	gST->RuntimeServices->ResetSystem(EfiResetCold, EFI_SUCCESS, 0, NULL);
	return EFI_DEVICE_ERROR;
}

EFI_STATUS
ActionCfgTpm(IN VOID *ctx) {
	return gTpm->Configure(gTpm);
}

EFI_STATUS
ActionBoot(IN VOID *ctx) {
	gCfgMenuContinue = FALSE;
	gAuthPwdCode = AskPwdRetCancel;
	return EFI_SUCCESS;
}

EFI_STATUS
ActionNewPassword(IN VOID *ctx) {
	gCfgMenuContinue = FALSE;
	gAuthPwdCode = AskPwdRetLogin;
	return EFI_SUCCESS;
}

VOID 
CfgMenuCreate() {
	PMENU_ITEM          item = NULL;
	item = DcsMenuAppend(item, L"Boot", 'b', ActionBoot, NULL);
	gCfgMenu = item;
	item = DcsMenuAppend(item, L"Hard reset", 'r', ActionCfgReboot, NULL);
	item = DcsMenuAppend(item, L"New password", 'n', ActionNewPassword, NULL);
	if (gTpm != NULL) {
		item = DcsMenuAppend(item, L"Configure TPM", 't', ActionCfgTpm, NULL);
	}
}


VOID
VCAskPwd(
	IN	 UINTN	pwdType,
	OUT Password* vcPwd) {
	BOOL pwdReady;
	if (gAuthPasswordMsg == NULL) VCAuthLoadConfig();
	do {
		pwdReady = TRUE;
		if (pwdType == AskPwdNew) {
			EFI_INPUT_KEY key;
			key = KeyWait(L"Press 'c' to configure, others to skip %1d\r", 9, 0, 0);
			if (key.UnicodeChar == 'c') {
				PMENU_ITEM          item = NULL;
				EFI_STATUS          res;
				OUT_PRINT(L"\n%V%a %a configuration%N\n", TC_APP_NAME, VERSION_STRING);
				if (gCfgMenu == NULL) CfgMenuCreate();
				do {
					DcsMenuPrint(gCfgMenu);
					item = NULL;
					key.UnicodeChar = 0;
					while (item == NULL) {
						item = gCfgMenu;
						key = GetKey();
						while (item != NULL) {
							if (item->Select == key.UnicodeChar) break;
							item = item->Next;
						}
					}
					OUT_PRINT(L"%c\n", key.UnicodeChar);
					res = item->Action(item->Context);
					if (EFI_ERROR(res)) {
						ERR_PRINT(L"%r\n", res);
					}
				} while (gCfgMenuContinue);
				if ((gAuthPwdCode == AskPwdRetCancel) || (gAuthPwdCode == AskPwdRetTimeout)) {
					return;
				}
			}
		}

		if (gAutoLogin) {
			gAutoLogin = 0;
			gAuthPwdCode = AskPwdRetLogin;
			vcPwd->Length = (unsigned int)strlen(gAutoPassword);
			strcpy(vcPwd->Text, gAutoPassword);
		}
		else {
			if (gAuthPasswordType == 1 &&
				gGraphOut != NULL &&
				((gTouchPointer != NULL) || (gTouchSimulate != 0))) {
				AskPictPwdInt(pwdType, sizeof(vcPwd->Text), vcPwd->Text, &vcPwd->Length, &gAuthPwdCode, FALSE);
			}
			else {
				switch (pwdType) {
				case AskPwdNew:
					OUT_PRINT(L"New password:");
					break;
				case AskPwdConfirm:
					OUT_PRINT(L"Confirm password:");
					break;
				case AskPwdLogin:
				default:
					OUT_PRINT(L"%a", gAuthPasswordMsg);
					break;
				}
				AskConsolePwdInt(&vcPwd->Length, vcPwd->Text, &gAuthPwdCode, sizeof(vcPwd->Text), gPasswordVisible, FALSE);
			}

			if ((gAuthPwdCode == AskPwdRetCancel) || (gAuthPwdCode == AskPwdRetTimeout)) {
				return;
			}
		}
		if (gSCLocked) {
			ERR_PRINT(L"Smart card is not configured\n");
		}

		if (gPlatformLocked) {
			if (gPlatformKeyFile == NULL) {
				ERR_PRINT(L"Platform key file is absent\n");
			}
			else {
				ApplyKeyFile(vcPwd, gPlatformKeyFile, gPlatformKeyFileSize);
			}
		}

		if (gTPMLocked) {
			if (gTpm != NULL) {
				pwdReady = !EFI_ERROR(gTpm->Apply(gTpm, vcPwd));
				if (!pwdReady) {
					ERR_PRINT(L"TPM error: DCS configuration ");
					if (!gTpm->IsConfigured(gTpm)) {
						ERR_PRINT(L"absent\n");
					}
					else {
						ERR_PRINT(L"locked\n");
					}
				}
			}	else {
				ERR_PRINT(L"No TPM found\n");
			}
		}
	} while (!pwdReady);
}

VOID
VCAuthAsk() 
{
	MEM_BURN(&gAuthPassword, sizeof(gAuthPassword));
	VCAskPwd(AskPwdLogin, &gAuthPassword);

	if ((gAuthPwdCode == AskPwdRetCancel) || (gAuthPwdCode == AskPwdRetTimeout)) {
		MEM_BURN(&gAuthPassword, sizeof(gAuthPassword));
		return;
	}

	if (gAuthPimRqt) {
		gAuthPim = AskInt(gAuthPimMsg, gPasswordVisible);
	}
	if (gAuthTcRqt) {
		gAuthTc = AskConfirm("True crypt mode [N]?", gPasswordVisible);
	}

	if (gAuthBootRqt) {
		gAuthBoot = AskConfirm("Boot mount mode [N]?", gPasswordVisible);
	}

	if (gAuthHashRqt) {
		do {
			gAuthHash = AskInt(gAuthHashMsg, gPasswordVisible);
		} while (gAuthHash < 0 || gAuthHash > 5);
	}
}


//////////////////////////////////////////////////////////////////////////
// VeraCrypt helpers
//////////////////////////////////////////////////////////////////////////
void* VeraCryptMemAlloc(IN UINTN size) {
   return MEM_ALLOC(size);
}

void VeraCryptMemFree(IN VOID* ptr) {
   MEM_FREE(ptr);
}
void ThrowFatalException(int line) {
   ERR_PRINT(L"Fatal %d\n", line);
}

//////////////////////////////////////////////////////////////////////////
// Random data
//////////////////////////////////////////////////////////////////////////
BOOL
RandgetBytes(unsigned char *buf, int len, BOOL forceSlowPoll) {
	EFI_STATUS res;
	res = RndGetBytes(buf, len);
	return !EFI_ERROR(res);
}

//////////////////////////////////////////////////////////////////////////
// Key file
//////////////////////////////////////////////////////////////////////////

#define KEYFILE_POOL_SIZE	64
#define	KEYFILE_MAX_READ_LEN	(1024*1024)

VOID
ApplyKeyFile(
	IN OUT Password* password,
	IN     CHAR8*    keyfileData,
	IN     UINTN     keyfileDataSize
	) 
{
	unsigned __int32 crc = 0xffffffff;
	int writePos = 0;
	size_t totalRead = 0;
	size_t i;
	CHAR8 keyPool[KEYFILE_POOL_SIZE];
	
	ZeroMem(keyPool, sizeof(keyPool));

	for (i = 0; i < keyfileDataSize; i++)
	{
		crc = UPDC32(keyfileData[i], crc);

		keyPool[writePos++] += (unsigned __int8)(crc >> 24);
		keyPool[writePos++] += (unsigned __int8)(crc >> 16);
		keyPool[writePos++] += (unsigned __int8)(crc >> 8);
		keyPool[writePos++] += (unsigned __int8)crc;

		if (writePos >= KEYFILE_POOL_SIZE)
			writePos = 0;

		if (++totalRead >= KEYFILE_MAX_READ_LEN)
			break;
	}

	for (i = 0; i < sizeof(keyPool); i++)
	{
		if (i < password->Length)
			password->Text[i] += keyPool[i];
		else
			password->Text[i] = keyPool[i];
	}

	if (password->Length < (int)sizeof(keyPool))
		password->Length = sizeof(keyPool);

	burn (keyPool, sizeof(keyPool));
}