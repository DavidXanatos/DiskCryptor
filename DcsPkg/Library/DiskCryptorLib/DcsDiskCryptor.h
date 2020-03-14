/** @file
Interface for DCS

Copyright (c) 2019. DiskCryptor, David Xanatos

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the GNU General Public License, version 3.0 (GPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/GPL-3.0
**/

#ifndef _DCSDISKCRYPTOR_H_
#define _DCSDISKCRYPTOR_H_

#include <Uefi.h>
#include "include/boot/boot.h"

#define DC_APP_NAME "DiskCryptor"

#define MAX_MSG 256

extern char* gDCryptPasswordMsg;
extern int gDCryptAuthRetry;

extern char* gDCryptStartMsg;
extern char* gDCryptSuccessMsg;
extern char* gDCryptErrorMsg;

typedef struct _DCRYPT_DISKIO DCRYPT_DISKIO, *PDCRYPT_DISKIO;

PDCRYPT_DISKIO
GetDiskByNumber(int number);

VOID
DCAuthLoadConfig();

VOID
DCAskPwd(
	IN	 UINTN	pwdType,
	OUT dc_pass* vcPwd
);

EFI_STATUS
DCApplyKeyFile(
	IN OUT dc_pass* password,
	IN     CHAR16*   keyfilePath
);

EFI_STATUS
DCApplyKeyData(
	IN OUT dc_pass* password,
	UINT8*      fileData,
	UINTN       fileSize
);

#endif // _DCSDISKCRYPTOR_H_