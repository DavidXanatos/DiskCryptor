/** @file
DCS configuration

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov
Copyright (c) 2016. VeraCrypt, Mounir IDRASSI
Copyright (c) 2019. DiskCryptor, David Xanatos

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the Apache License, Version 2.0.

The full text of the license may be found at
https://opensource.org/licenses/Apache-2.0
**/

#ifndef __DCSCONFIG_H__
#define __DCSCONFIG_H__

#include <Uefi.h>

#define _T2(x) L##x
#define _T(x) _T2(x)

//////////////////////////////////////////////////////////////////////////
// Build Config
//////////////////////////////////////////////////////////////////////////

//#define DEBUG_BUILD

#define DCS_DIRECTORY L"DCS"

#define DCS_CAPTION "Disk Cryptor" //Disk Cryptography Services
#define DCS_VERSION 204 // 2.04

#define NO_BML

#define DCS_SINGLE_MODULE 0xDC // disk cryptor
//#define DCS_SINGLE_MODULE 0x4C // vera crypt

#define OPT_EXTERN_KEY L"-extern"

//////////////////////////////////////////////////////////////////////////
// Dynamic Config
//////////////////////////////////////////////////////////////////////////
#define CONFIG_FILE_PATH L"\\EFI\\" DCS_DIRECTORY L"\\DcsProp"

extern char    *gConfigBuffer;
extern UINTN    gConfigBufferSize;
extern char    *gConfigBufferUpdated;
extern UINTN	gConfigBufferUpdatedSize;
extern BOOLEAN  gConfigDebug;
extern BOOLEAN  gExternMode;

BOOLEAN InitConfig(CHAR16* configFileName);
BOOLEAN ConfigRead(char *configKey, char *configValue, int maxValueSize);
int ConfigReadInt(char *configKey, int defaultValue);
__int64 ConfigReadInt64(char *configKey, __int64 defaultValue);
char *ConfigReadString(char *configKey, char *defaultValue, char *str, int maxLen); 
CHAR16 *ConfigReadStringW(char *configKey, CHAR16 *defaultValue, CHAR16 *str, int maxLen); 

BOOLEAN InitParams();

VOID SetCleanSensitiveDataFunc(void(*cleanSensitiveData)(BOOLEAN));
VOID CleanSensitiveData(BOOLEAN panic);

#endif
