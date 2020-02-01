/** @file
EFI TCG/TPM helpers

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov
Copyright (c) 2016. VeraCrypt, Mounir IDRASSI

This program and the accompanying materials are licensed and made available
under the terms and conditions of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#include <Library/CommonLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DevicePathLib.h>
#include <Library/PrintLib.h>
#include <Protocol/TcgService.h>
#include <Protocol/Tcg2Protocol.h>

EFI_HANDLE* gTcgHandles = NULL;
UINTN       gTcgCount = 0;

EFI_HANDLE* gTcg2Handles = NULL;
UINTN       gTcg2Count = 0;

EFI_STATUS
InitTcg() {
	EFI_STATUS res;
	res = EfiGetHandles(ByProtocol, &gEfiTcgProtocolGuid, 0, &gTcgHandles, &gTcgCount);
	res = EfiGetHandles(ByProtocol, &gEfiTcg2ProtocolGuid, 0, &gTcg2Handles, &gTcg2Count);
	return res;
}

