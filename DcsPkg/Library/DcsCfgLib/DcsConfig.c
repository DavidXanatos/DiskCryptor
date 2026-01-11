/** @file
Interface for DCS

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov
Copyright (c) 2016. VeraCrypt, Mounir IDRASSI
Copyright (c) 2019. DiskCryptor, David Xanatos

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the Apache License, Version 2.0.

The full text of the license may be found at
https://opensource.org/licenses/Apache-2.0
**/

#include <Uefi.h>
#include <DcsConfig.h>

#include <Library/CommonLib.h>
#include "common/Xml.h"


//////////////////////////////////////////////////////////////////////////
// Config
//////////////////////////////////////////////////////////////////////////
CHAR16* gConfigFileName = NULL;

char *gConfigBuffer = NULL;
UINTN gConfigBufferSize = 0;
char *gConfigBufferUpdated = NULL;
UINTN gConfigBufferUpdatedSize = 0;

BOOLEAN gConfigDebug = FALSE;
BOOLEAN  gExternMode = FALSE;

BOOLEAN 
InitConfig(CHAR16* configFileName)
{
	EFI_STATUS res;

	gConfigFileName = configFileName;

	if (gConfigBuffer) return TRUE;
	if (gConfigFileName == NULL) return FALSE;

	if (gPxeBoot) {
		res = PxeDownloadFile(gConfigFileName, &gConfigBuffer, &gConfigBufferSize);
	} else {
		res = FileLoad(NULL, gConfigFileName, &gConfigBuffer, &gConfigBufferSize);
	}
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Failed to load config file %r\n", res);
		return FALSE;
	}

#ifdef DEBUG_BUILD
	gConfigDebug = ConfigReadInt("VerboseDebug", 1) ? TRUE : FALSE;
#else
	gConfigDebug = ConfigReadInt("VerboseDebug", 0) ? TRUE : FALSE;
#endif

	return TRUE;
}

BOOLEAN
ConfigRead(char *configKey, char *configValue, int maxValueSize)
{
	char *xml;

	if (gConfigFileName == NULL) {
		ERR_PRINT(L"Config was not initialized!\n"); 
		//if (FileLoad(NULL, L"\\EFI\\VeraCrypt\\DcsProp", &gConfigBuffer, &gConfigBufferSize) != EFI_SUCCESS) {
		return FALSE;
		//}
	}

	xml = gConfigBufferUpdated != NULL? gConfigBufferUpdated : gConfigBuffer;
	if (xml != NULL)
	{
		xml = XmlFindElementByAttributeValue(xml, "config", "key", configKey);
		if (xml != NULL)
		{
			XmlGetNodeText(xml, configValue, maxValueSize);
			return TRUE;
		}
	}

	return FALSE;
}

int ConfigReadInt(char *configKey, int defaultValue)
{
	char s[32];
	if (ConfigRead(configKey, s, sizeof(s))) {
		if (*s == '-') {
			return (-1) * (int)AsciiStrDecimalToUintn(&s[1]);
		}
		return (int)AsciiStrDecimalToUintn(s);
	}
	else
		return defaultValue;
}

__int64 ConfigReadInt64(char *configKey, __int64 defaultValue)
{
	char s[32];
	if (ConfigRead(configKey, s, sizeof(s))) {
		if (*s == '-') {
			return -(__int64)AsciiStrDecimalToUint64(&s[1]); // __allmul is not available
		}
		return (__int64)AsciiStrDecimalToUint64(s);
	}
	else
		return defaultValue;
}

char *ConfigReadString(char *configKey, char *defaultValue, char *str, int maxLen)
{
	if (str == NULL) {
		str = MEM_ALLOC(maxLen);
	}

	if (!ConfigRead(configKey, str, maxLen)) {
		AsciiStrCpyS(str, maxLen, defaultValue);
	}
	return str;
}

CHAR16 *ConfigReadStringW(char *configKey, CHAR16 *defaultValue, CHAR16 *str, int maxLen)
{
	char* strTemp = NULL;

	if (str == NULL) {
		str = MEM_ALLOC(maxLen * sizeof(CHAR16));
	}

	strTemp = MEM_ALLOC(maxLen);
	if (!ConfigRead(configKey, strTemp, maxLen)) {
		StrCpyS(str, maxLen, defaultValue);
	}
	else {
		AsciiStrToUnicodeStrS(strTemp, str, maxLen);
	}
	MEM_FREE(strTemp);

	return str;
}

BOOLEAN 
InitParams()
{
	EFI_STATUS res;
	CHAR16*    cmd;
	UINTN      cmdSize;
	UINT32     cmdAttr;

	res = EfiGetVar(L"DcsExecMode", NULL, &cmd, &cmdSize, &cmdAttr);
	if (!EFI_ERROR(res)) {
		EfiSetVar(L"DcsExecMode", NULL, NULL, 0, cmdAttr); // clear variable
		if (StrStr(cmd, OPT_EXTERN_KEY) != NULL) {
			gExternMode = TRUE;
		}
	}

	return TRUE;
}


void(*gCleanSensitiveData)(BOOLEAN) = NULL;

VOID SetCleanSensitiveDataFunc(void(*cleanSensitiveData)(BOOLEAN))
{
	gCleanSensitiveData = cleanSensitiveData;
}

VOID CleanSensitiveData(BOOLEAN panic)
{
	if (!gCleanSensitiveData) {
		// we can't print from here as in some cases (VirtualNotifyEvent) this will crash the system!!!
		//ERR_PRINT(L"Can't Clean Sensitive Data from RAM!!!"); 
		return;
	}
	gCleanSensitiveData(panic);
}
