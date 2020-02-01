/** @file
This is DCS configuration, TPM

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov
Copyright (c) 2016. VeraCrypt, Mounir IDRASSI 

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#include <Library/CommonLib.h>
#include <Library/DcsTpmLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DcsCfgLib.h>
//#include "DcsVeraCrypt.h"

EFI_STATUS
Tpm12ListPcrs(
	UINT32 sPcr,
	UINT32 ePcr
	) {
	EFI_STATUS res;
	res = InitTpm12();
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"%r\n", res);
		return res;
	}
	return Tpm12DumpPcrs(sPcr, ePcr);
}

EFI_STATUS
Tpm12NvList(
	) {
	EFI_STATUS res;
	UINT32  count;
	UINT32  i;
	UINT32  nv[256];
	res = InitTpm12();
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"%r\n", res);
		return res;
	}
	count = sizeof(nv);
	res = Tpm12GetNvList(&count, nv);
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"%r\n", res);
		return res;
	}
	count = count >> 2;
	for (i = 0; i < count; ++i) {
		UINT32 index = SwapBytes32(nv[i]);
		UINT32 attr = 0;
		UINT32 dataSz = 0;
		UINT32 pcrR = 0;
		UINT32 pcrW = 0;
		OUT_PRINT(L"%H%08x%N ", index);
		res = Tpm12NvDetails(index, &attr, &dataSz, &pcrR, &pcrW);
		if (EFI_ERROR(res)) {
			ERR_PRINT(L"%r\n", res);
			continue;
		}

		OUT_PRINT(L"Attr[%08x] PcrR[%08x] PcrW[%08x] [%d] ", attr, pcrR, pcrW, dataSz);
		OUT_PRINT(L"\n");
	}
	return res;
}

EFI_STATUS
TpmDcsConfigure(
	) {
	EFI_STATUS res;
	DePassword pwd;
	MEM_BURN(&pwd, sizeof(pwd));
	CE(GetTpm());
	CE(RndInit(RndTypeTpm, NULL, 0, &gRnd));
	CE(gTpm->Configure(gTpm));
	CE(gTpm->Apply(gTpm, &pwd));
	// the key ends up in pwd and than what?!
	return res;

err:
	ERR_PRINT(L"%r, line %d", res, gCELine);
	return res;
}

//////////////////////////////////////////////////////////////////////////
// TPM 2.0
//////////////////////////////////////////////////////////////////////////
EFI_STATUS
Tpm2ListPcrs(
	UINT32 sPcr,
	UINT32 ePcr
	) {
	EFI_STATUS res;
	res = InitTpm20();
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"%r\n", res);
		return res;
	}
	return DcsTpm2DumpPcrs(sPcr, ePcr);
}

