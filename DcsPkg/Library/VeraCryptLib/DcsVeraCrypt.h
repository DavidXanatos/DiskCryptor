/** @file
Interface for DCS services

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov
Copyright (c) 2016. VeraCrypt, Mounir IDRASSI

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the Apache License, Version 2.0.  

The full text of the license may be found at
https://opensource.org/licenses/Apache-2.0
**/

#ifndef __DCSVERACRYPT_H__
#define __DCSVERACRYPT_H__

#include <Uefi.h>
#include <common/Tcdefs.h>
#include <common/Password.h>

//////////////////////////////////////////////////////////////////////////
// Auth
//////////////////////////////////////////////////////////////////////////
extern int gAuthPasswordType;
extern CHAR16*	gPasswordPictureFileName;
extern char* gAuthPasswordMsg;
extern Password gAuthPassword;

extern UINT8 gAutoLogin;
extern char* gAutoPassword;

extern char* gAuthPimMsg;
extern int gAuthPimRqt;
extern int gAuthPim;

extern int gAuthTcRqt;
extern int gAuthTc;

extern char *gAuthHashMsg;
extern int gAuthHashRqt;
extern int gAuthHash;

extern int gAuthBootRqt;
extern int gAuthBoot;

extern int gAuthRetry;
extern int gRndDefault;

extern char* gAuthStartMsg;
extern char* gAuthErrorMsg;

extern INT32 gRUD;

extern int gAuthSecRegionSearch;
extern int gSecRegionInfoDelay;

extern int gAuthPwdCode;

extern CHAR8* gPlatformKeyFile;
extern UINTN gPlatformKeyFileSize;

extern EFI_GUID *gPartitionGuidOS;
extern int gDcsBootForce;
extern char* gForcePasswordMsg;
extern int gForcePasswordType;
extern UINT8 gForcePasswordProgress;

void
VCAuthAsk();

VOID
VCAskPwd(
	IN	 UINTN	pwdType,
	OUT Password* vcPwd);

VOID
VCAuthLoadConfig();

VOID
ApplyKeyFile(
	IN OUT Password* password,
	IN     CHAR8*    keyfileData,
	IN     UINTN     keyfileDataSize
	);

#endif

