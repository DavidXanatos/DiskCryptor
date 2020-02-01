/** @file
EFI TPM 2.0 DCS protocol

Copyright (c) 2016 Disk Cryptography Services for EFI (DCS), Alex Kolotnikov

This program and the accompanying materials are licensed and made available
under the terms and conditions of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#include <Library/CommonLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DevicePathLib.h>
#include <Library/PrintLib.h>
#include <Library/DcsTpmLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BaseCryptLib.h>

#include <IndustryStandard/Tpm20.h>
#include <IndustryStandard/TcpaAcpi.h>
#include <Library/Tpm2DeviceLib.h>
#include <Library/Tpm2CommandLib.h>
#include <Protocol/Tcg2Protocol.h>
#include "Library/DcsCfgLib.h"
#include <Library/BaseCryptLib.h>

#define DCS_TPM2_NV_INDEX         (0x1000000 | DCS_TPM_NV_INDEX)
#define DCS_TPM2_NV_INDEX_PCRS    (0x1100000 | DCS_TPM_NV_INDEX)

EFI_STATUS  Tcg2Ready = EFI_NOT_READY;
extern EFI_TCG2_PROTOCOL  *mTcg2Protocol;

EFI_STATUS
InitTpm20() {
	if (EFI_ERROR(Tcg2Ready)) {
		Tcg2Ready = Tpm2RequestUseTpm();
	}
	return Tcg2Ready;
}

EFI_STATUS
Sha256Hash(
	IN  VOID    *data,
	IN  UINTN   dataSize,
	OUT UINT8   *hash
	)
{
	UINTN ctxSize;
	VOID  *ctx;
	ctxSize = Sha256GetContextSize();
	ctx = MEM_ALLOC(ctxSize);
	if (ctx == NULL) return EFI_BUFFER_TOO_SMALL;
	Sha256Init(ctx);
	Sha256Update(ctx, data, dataSize);
	if (!Sha256Final(ctx, hash)) {
		MEM_FREE(ctx);
		return EFI_DEVICE_ERROR;
	}
	return EFI_SUCCESS;
}

//////////////////////////////////////////////////////////////////////////
// Tests
//////////////////////////////////////////////////////////////////////////
/*
EFI_STATUS
Tpm20AuthSesseion()
{
	EFI_STATUS                res = EFI_SUCCESS;
	TPMI_DH_OBJECT            TpmKey = TPM_RH_NULL;
	TPMI_DH_ENTITY            Bind = TPM_RH_NULL;
	TPM2B_NONCE               NonceCaller;
	TPM2B_ENCRYPTED_SECRET    Salt;
	TPM_SE                    SessionType = TPM_SE_POLICY;
	TPMT_SYM_DEF              Symmetric;
	TPMI_ALG_HASH             AuthHash = TPM_ALG_SHA256;
	TPMI_SH_AUTH_SESSION      SessionHandle;
	TPM2B_NONCE               NonceTPM;

	SetMem(&NonceCaller, sizeof(NonceCaller), 0);
	NonceCaller.size = 0x20;
	Salt.size = 0;
	Symmetric.algorithm = TPM_ALG_XOR;
	Symmetric.keyBits.xor = TPM_ALG_SHA256;

	res = Tpm2StartAuthSession(
		TpmKey,
		Bind,
		&NonceCaller,
		&Salt,
		SessionType,
		&Symmetric,
		AuthHash,
		OUT  &SessionHandle,
		OUT  &NonceTPM
		);

	res = Tpm2FlushContext(SessionHandle);

	return res;
}

EFI_STATUS
Tpm2NvDefine()
{
	EFI_STATUS                res = EFI_SUCCESS;
	TPMI_RH_PROVISION         AuthHandle = TPM_RH_OWNER;
	TPMI_RH_NV_INDEX          NvIndex = 0x1000001;
	TPMS_AUTH_COMMAND         AuthSession;
	TPM2B_AUTH                Auth;
	TPM2B_NV_PUBLIC           NvPublic;

	SetMem(&AuthSession, sizeof(AuthSession), 0);
	AuthSession.sessionHandle = TPM_RS_PW;
	AuthSession.nonce.size = 0;
	AuthSession.hmac.size = (UINT16)AsciiStrLen("tpmoPwd");
	AsciiStrCpy(AuthSession.hmac.buffer, "tpmoPwd");

	Auth.size = (UINT16)AsciiStrLen("tpmnPwd");
	AsciiStrCpy(Auth.buffer, "tpmnPwd");
	NvPublic.size = 4 + 2 + 4 + 2 + SHA256_DIGEST_SIZE + 2;
	NvPublic.nvPublic.nvIndex = NvIndex;
	NvPublic.nvPublic.nameAlg = TPM_ALG_SHA256;
	NvPublic.nvPublic.attributes.TPMA_NV_POLICYREAD = 1;
	NvPublic.nvPublic.attributes.TPMA_NV_POLICYWRITE = 1;
	NvPublic.nvPublic.attributes.TPMA_NV_OWNERREAD = 1;
	NvPublic.nvPublic.attributes.TPMA_NV_OWNERWRITE = 1;
	NvPublic.nvPublic.attributes.TPMA_NV_NO_DA = 1;
	NvPublic.nvPublic.authPolicy.size = SHA256_DIGEST_SIZE;
	CE(Tpm20MakePolicyPcr(0xf, &NvPublic.nvPublic.authPolicy.buffer[0]));
	NvPublic.nvPublic.dataSize = 64;

	CE(Tpm2NvDefineSpace(
		IN AuthHandle,
		IN &AuthSession, OPTIONAL
		IN &Auth,
		IN &NvPublic
		));

	CE(Tpm2NvUndefineSpace(
		IN AuthHandle,
		IN NvIndex,
		IN &AuthSession OPTIONAL
		));

	return res;
err:
	ERR_PRINT(L"NvDefineSpace(%d): %r\n", gCELine, res);
	return res;
}

EFI_STATUS
Tpm20NVRead()
{
	EFI_STATUS                res = EFI_SUCCESS;
	TPMI_RH_NV_AUTH           AuthHandle = TPM_RH_OWNER;
	TPMI_RH_NV_INDEX          NvIndex = 0x1000000;
	TPMS_AUTH_COMMAND         AuthSession;
	TPM2B_MAX_BUFFER          InData;
	UINT16                    Offset = 0;
	UINT16                    Size = 10;
	TPM2B_MAX_BUFFER          OutData;

	SetMem(&AuthSession, sizeof(AuthSession), 0);
	AuthSession.sessionHandle = TPM_RS_PW;
	AuthSession.nonce.size = 0;
	AuthSession.hmac.size = (UINT16)AsciiStrLen("tpmoPwd");
	AsciiStrCpy(AuthSession.hmac.buffer, "tpmoPwd");
	// AuthSession.sessionAttributes = 0;
	InData.size = 5;
	AsciiStrCpy(InData.buffer, "54321");

	res = Tpm2NvWrite(
		IN AuthHandle,
		IN NvIndex,
		IN &AuthSession, OPTIONAL
		IN &InData,
		IN Offset
		);

	res = Tpm2NvRead(
		IN AuthHandle,
		IN NvIndex,
		IN &AuthSession, OPTIONAL
		IN Size,
		IN Offset,
		&OutData
		);

	return res;
}
*/

//////////////////////////////////////////////////////////////////////////
// TPM 2.0 Helpers
//////////////////////////////////////////////////////////////////////////
EFI_STATUS
DcsTpm2PcrRead(
	IN UINT32   PcrIndex,
	OUT void    *PcrValue
	)
{
	EFI_STATUS res = EFI_SUCCESS;
	TPML_PCR_SELECTION        PcrSelectionIn = { 0 };
	UINT32                    PcrUpdateCounter;
	TPML_PCR_SELECTION        PcrSelectionOut;
	PcrSelectionIn.count = 1;
	PcrSelectionIn.pcrSelections[0].hash = TPM_ALG_SHA256;
	PcrSelectionIn.pcrSelections[0].sizeofSelect = 3;
	PcrSelectionIn.pcrSelections[0].pcrSelect[0] = (PcrIndex < 8) ? 1 << PcrIndex : 0;
	PcrSelectionIn.pcrSelections[0].pcrSelect[1] = (PcrIndex > 7) && (PcrIndex < 16) ? 1 << (PcrIndex - 8) : 0;
	PcrSelectionIn.pcrSelections[0].pcrSelect[2] = (PcrIndex > 15) ? 1 << (PcrIndex - 16) : 0;

	res = Tpm2PcrRead(&PcrSelectionIn, &PcrUpdateCounter, &PcrSelectionOut, PcrValue);
	return res;
}

#pragma pack(1)
typedef struct {
	UINT32         cmd;
	UINT32         count;
	TPM_ALG_ID     hashType;
	UINT8          pcrCount;
	UINT8          pcrSelection[3];
	UINT8          hash[SHA256_DIGEST_SIZE];
} TPM_CC_POLICYPCR;
#pragma pack()

EFI_STATUS
Tpm2MakePolicyPcr(
	IN  UINT32                    pcrMask,
	OUT UINT8                     *hash
	)
{
	EFI_STATUS                res = EFI_SUCCESS;
	TPML_DIGEST               PcrValue;
	UINTN                     ctxSize;
	VOID                      *ctx;
	UINT32                    tmp;
	UINTN                     i;
	TPM_CC_POLICYPCR          polycyPcr;
	
	polycyPcr.cmd = SwapBytes32(TPM_CC_PolicyPCR);
	polycyPcr.count = SwapBytes32(1);
	polycyPcr.hashType = SwapBytes16(TPM_ALG_SHA256);
	polycyPcr.pcrCount = 3;
	polycyPcr.pcrSelection[0] = pcrMask & 0xFF;
	polycyPcr.pcrSelection[1] = (pcrMask >> 8) & 0xFF;
	polycyPcr.pcrSelection[2] = (pcrMask >> 16) & 0xFF;

	ctxSize = Sha256GetContextSize();
	ctx = MEM_ALLOC(ctxSize);
	if (ctx == NULL) return EFI_BUFFER_TOO_SMALL;
	Sha256Init(ctx);
	tmp = pcrMask;
	for (i = 0; i < 32; ++i) {
		if ((tmp & 1) == 1) {
			CE(DcsTpm2PcrRead((UINT32)i, &PcrValue));
			Sha256Update(ctx, PcrValue.digests[0].buffer, SHA256_DIGEST_SIZE);
		}
		tmp >>= 1;
	}
	CE(Sha256Final(ctx, &polycyPcr.hash[0]) ? EFI_SUCCESS: EFI_DEVICE_ERROR);
	Sha256Init(ctx);
	SetMem(hash, SHA256_DIGEST_SIZE, 0);
	Sha256Update(ctx, hash, SHA256_DIGEST_SIZE);
	Sha256Update(ctx, &polycyPcr, sizeof(polycyPcr));
	CE(Sha256Final(ctx, &hash[0]) ? EFI_SUCCESS : EFI_DEVICE_ERROR);

err:
	MEM_FREE(ctx);
	return res;
}

#pragma pack(1)
typedef struct {
	TPM2_COMMAND_HEADER       Header;
	UINT16                    Size;
} TPM2_GET_RANDOM_COMMAND;

typedef struct {
	TPM2_RESPONSE_HEADER       Header;
	TPM2B_MAX_BUFFER           Data;
} TPM2_GET_RANDOM_RESPONSE;
#pragma pack()

EFI_STATUS
Tpm2GetRandom(
	IN  UINTN  size,
	OUT VOID*  data) 
{
	EFI_STATUS                        res = EFI_SUCCESS;
	UINTN                             remains = size;
	UINTN                             request;
	UINTN                             gotBytes;
	UINT8                             *rnd = data;
	TPM2_GET_RANDOM_COMMAND           SendBuffer;
	TPM2_GET_RANDOM_RESPONSE          RecvBuffer;
	UINT32                            SendBufferSize;
	UINT32                            RecvBufferSize;
	TPM_RC                            ResponseCode;

	SendBufferSize = (UINT32) sizeof(SendBuffer);
	SendBuffer.Header.tag = SwapBytes16(TPM_ST_NO_SESSIONS);
	SendBuffer.Header.commandCode = SwapBytes32(TPM_CC_GetRandom);
	SendBuffer.Header.paramSize = SwapBytes32(SendBufferSize);

	while (remains > 0) {
		request = (remains < sizeof(RecvBuffer.Data.buffer)) ? remains : sizeof(RecvBuffer.Data.buffer);
		SendBuffer.Size = SwapBytes16((UINT16)request);
		RecvBufferSize = (UINT32) sizeof(RecvBuffer);

		res = Tpm2SubmitCommand(SendBufferSize, (UINT8 *)&SendBuffer, &RecvBufferSize, (UINT8 *)&RecvBuffer);
		if (EFI_ERROR(res)) {
			return res;
		}

		if (RecvBufferSize < sizeof(TPM2_RESPONSE_HEADER)) {
			return EFI_DEVICE_ERROR;
		}
		ResponseCode = SwapBytes32(RecvBuffer.Header.responseCode);
		if (ResponseCode != TPM_RC_SUCCESS) {
			return EFI_DEVICE_ERROR;
		}
		gotBytes = SwapBytes16(RecvBuffer.Data.size);
		CopyMem(rnd, &RecvBuffer.Data.buffer[0], gotBytes);
		remains -= gotBytes;
		rnd += gotBytes;
	}
	return res;
}

EFI_STATUS
Tpm2Measure(
	IN UINT32    index,
	IN UINTN     size,
	IN VOID*     data) 
{
	EFI_STATUS                res = EFI_SUCCESS;
	TPMI_DH_PCR               PcrHandle = index;
	TPML_DIGEST_VALUES        Digests;

	Digests.count = 2;
	Digests.digests[0].hashAlg = TPM_ALG_SHA256;
	Digests.digests[1].hashAlg = TPM_ALG_SHA1;
	CE(Sha256Hash(data, size, &Digests.digests[0].digest.sha256[0]));
	CE(Sha1Hash(data, size, &Digests.digests[1].digest.sha1[0]));

	CE(Tpm2PcrExtend(PcrHandle,&Digests));

err:
	return res;
}

EFI_STATUS
DcsTpm2NVReadPcrMask(
	UINT32* mask
	)
{
	EFI_STATUS                res = EFI_SUCCESS;
	TPMI_RH_NV_AUTH           AuthHandle = DCS_TPM2_NV_INDEX_PCRS;
	TPMI_RH_NV_INDEX          NvIndex = DCS_TPM2_NV_INDEX_PCRS;
	TPMS_AUTH_COMMAND         AuthSession;
	UINT16                    Offset = 0;
	UINT16                    Size = 4;
	TPM2B_MAX_BUFFER          OutData;

	SetMem(&AuthSession, sizeof(AuthSession), 0);
	AuthSession.sessionHandle = TPM_RS_PW;
	AuthSession.nonce.size = 0;
	AuthSession.hmac.size = (UINT16)0;

	CE(Tpm2NvRead(
		IN AuthHandle,
		IN NvIndex,
		IN &AuthSession, OPTIONAL
		IN Size,
		IN Offset,
		&OutData
		));
	CopyMem(mask, &OutData.buffer[0], 4);
	*mask = SwapBytes32(*mask);

err:
	return res;
}

VOID
Tpm2AuthSessionOwnerPrepare(
	IN  UINT8                 *OwnerPwd,
	IN  UINT16                OwnerPwdSize,
	OUT TPMS_AUTH_COMMAND     *AuthSession
	) {
	SetMem(AuthSession, sizeof(*AuthSession), 0);
	AuthSession->sessionHandle = TPM_RS_PW;
	AuthSession->nonce.size = 0;
 	AuthSession->hmac.size = (UINT16)OwnerPwdSize;
 	CopyMem(&AuthSession->hmac.buffer[0], OwnerPwd, OwnerPwdSize);
//	AuthSession->hmac.size = (UINT16)AsciiStrLen("tpmoPwd");
//	AsciiStrCpy(AuthSession->hmac.buffer, "tpmoPwd");

}

EFI_STATUS
DcsTpm2Clean(
	UINT8    *OwnerPwd,
	UINT16    OwnerPwdSize
	)
{
	EFI_STATUS                res = EFI_SUCCESS;
	TPMS_AUTH_COMMAND         AuthSession;

	Tpm2AuthSessionOwnerPrepare(OwnerPwd, OwnerPwdSize, &AuthSession);

	res = Tpm2NvUndefineSpace(
		TPM_RH_OWNER,
		DCS_TPM2_NV_INDEX_PCRS,
		IN &AuthSession OPTIONAL
		);

	CE(Tpm2NvUndefineSpace(
		TPM_RH_OWNER,
		DCS_TPM2_NV_INDEX,
		IN &AuthSession OPTIONAL
		));

err:
	return res;
}

EFI_STATUS
DcsTpm2NvDefine(
	UINT8     *OwnerPwd,
	UINT16    OwnerPwdSize,
	UINT32    PcrMask,
	UINT8     *Secret
	)
{
	EFI_STATUS                res = EFI_SUCCESS;
	TPMS_AUTH_COMMAND         AuthSession;
	TPM2B_AUTH                Auth;
	TPM2B_NV_PUBLIC           NvPublic;
	TPM2B_MAX_BUFFER          InData;

	DcsTpm2Clean(OwnerPwd, OwnerPwdSize);
	Tpm2AuthSessionOwnerPrepare(OwnerPwd, OwnerPwdSize, &AuthSession);

	SetMem(&NvPublic, sizeof(NvPublic), 0);
	SetMem(&Auth, sizeof(Auth), 0);
	Auth.size = (UINT16)0;
	NvPublic.size = 4 + 2 + 4 + 2 + SHA256_DIGEST_SIZE + 2;
	NvPublic.nvPublic.nvIndex = DCS_TPM2_NV_INDEX;
	NvPublic.nvPublic.nameAlg = TPM_ALG_SHA256;
	NvPublic.nvPublic.attributes.TPMA_NV_POLICYREAD = 1;
	NvPublic.nvPublic.attributes.TPMA_NV_POLICYWRITE = 1;
	NvPublic.nvPublic.attributes.TPMA_NV_OWNERREAD = 1;
	NvPublic.nvPublic.attributes.TPMA_NV_OWNERWRITE = 1;
	NvPublic.nvPublic.attributes.TPMA_NV_NO_DA = 1;
	NvPublic.nvPublic.authPolicy.size = SHA256_DIGEST_SIZE;
	CE(Tpm2MakePolicyPcr(PcrMask, &NvPublic.nvPublic.authPolicy.buffer[0]));
	NvPublic.nvPublic.dataSize = DCS_TPM_NV_SIZE;

	CE(Tpm2NvDefineSpace(
		IN TPM_RH_OWNER,
		IN &AuthSession, OPTIONAL
		IN &Auth,
		IN &NvPublic
		));

	SetMem(&NvPublic, sizeof(NvPublic), 0);
	SetMem(&Auth, sizeof(Auth), 0);
	Auth.size = (UINT16)0;
	NvPublic.size = 4 + 2 + 4 + 2 + 2;
	NvPublic.nvPublic.nvIndex = DCS_TPM2_NV_INDEX_PCRS;
	NvPublic.nvPublic.nameAlg = TPM_ALG_SHA256;
	NvPublic.nvPublic.attributes.TPMA_NV_OWNERREAD = 1;
	NvPublic.nvPublic.attributes.TPMA_NV_OWNERWRITE = 1;
	NvPublic.nvPublic.attributes.TPMA_NV_AUTHREAD = 1;
	NvPublic.nvPublic.attributes.TPMA_NV_NO_DA = 1;
	NvPublic.nvPublic.authPolicy.size = 0;
	NvPublic.nvPublic.dataSize = 4;

	CE(Tpm2NvDefineSpace(
		IN TPM_RH_OWNER,
		IN &AuthSession, OPTIONAL
		IN &Auth,
		IN &NvPublic
		));

	InData.size = DCS_TPM_NV_SIZE;
	CopyMem(InData.buffer, Secret, DCS_TPM_NV_SIZE);

	CE(Tpm2NvWrite(
		IN TPM_RH_OWNER,
		IN DCS_TPM2_NV_INDEX,
		IN &AuthSession, OPTIONAL
		IN &InData,
		IN 0
		));

	InData.size = 4;
	PcrMask = SwapBytes32(PcrMask);
	CopyMem(InData.buffer, &PcrMask, 4);

	CE(Tpm2NvWrite(
		IN TPM_RH_OWNER,
		IN DCS_TPM2_NV_INDEX_PCRS,
		IN &AuthSession, OPTIONAL
		IN &InData,
		IN 0
		));

err:
	return res;
}

#pragma pack(1)
typedef struct {
	TPM2_COMMAND_HEADER       Header;
	UINT32                    Handle;
	UINT16                    auth;
	UINT32                    count;
	TPM_ALG_ID                hashType;
	UINT8                     pcrCount;
	UINT8                     pcrSelection[3];
} TPM2_POLICYPCR_COMMAND;

typedef struct {
	TPM2_RESPONSE_HEADER       Header;
} TPM2_POLICYPCR_RESPONSE;
#pragma pack()

EFI_STATUS
DcsTpm2NvRead(
	UINT8     *Secret
	)
{
	EFI_STATUS                res;
	TPMI_SH_AUTH_SESSION      SessionHandle = 0;
	UINT32                    PcrMask;

	CE(DcsTpm2NVReadPcrMask(&PcrMask));

	{
		TPMI_DH_OBJECT            TpmKey = TPM_RH_NULL;
		TPMI_DH_ENTITY            Bind = TPM_RH_NULL;
		TPM2B_NONCE               NonceCaller;
		TPM2B_ENCRYPTED_SECRET    Salt;
		TPM_SE                    SessionType = TPM_SE_POLICY;
		TPMT_SYM_DEF              Symmetric;
		TPMI_ALG_HASH             AuthHash = TPM_ALG_SHA256;
		TPM2B_NONCE               NonceTPM;

		SetMem(&NonceCaller, sizeof(NonceCaller), 0);
		NonceCaller.size = 0x20;
		Salt.size = 0;
		Symmetric.algorithm = TPM_ALG_XOR;
		Symmetric.keyBits.xor = TPM_ALG_SHA256;

		CE(Tpm2StartAuthSession(
			TpmKey,
			Bind,
			&NonceCaller,
			&Salt,
			SessionType,
			&Symmetric,
			AuthHash,
			OUT  &SessionHandle,
			OUT  &NonceTPM
			));

		{
			TPM2_POLICYPCR_COMMAND           SendBuffer;
			TPM2_POLICYPCR_RESPONSE          RecvBuffer;
			UINT32                           SendBufferSize;
			UINT32                           RecvBufferSize;
			TPM_RC                           ResponseCode;
			TPMS_AUTH_COMMAND                AuthSession;
			TPM2B_MAX_BUFFER          OutData;

			SetMem(&SendBuffer, sizeof(SendBuffer), 0);
			SetMem(&RecvBuffer, sizeof(RecvBuffer), 0);
			RecvBufferSize = (UINT32) sizeof(RecvBuffer);
			SendBufferSize = (UINT32) sizeof(SendBuffer);

			SendBuffer.Header.tag = SwapBytes16(TPM_ST_NO_SESSIONS);
			SendBuffer.Header.commandCode = SwapBytes32(TPM_CC_PolicyPCR);
			SendBuffer.Header.paramSize = SwapBytes32(SendBufferSize);
			SendBuffer.Handle = SwapBytes32(SessionHandle);
			SendBuffer.auth = 0;
			SendBuffer.hashType = SwapBytes16(TPM_ALG_SHA256);
			SendBuffer.count = SwapBytes32(1);
			SendBuffer.pcrCount = 3;
			SendBuffer.pcrSelection[0] = (PcrMask) & 0xFF;
			SendBuffer.pcrSelection[1] = ((PcrMask) >> 8) & 0xFF;
			SendBuffer.pcrSelection[2] = ((PcrMask) >> 16) & 0xFF;
			res = Tpm2SubmitCommand(SendBufferSize, (UINT8 *)&SendBuffer, &RecvBufferSize, (UINT8 *)&RecvBuffer);
			if (EFI_ERROR(res)) {
				return res;
			}

			if (RecvBufferSize < sizeof(TPM2_RESPONSE_HEADER)) {
				res = EFI_DEVICE_ERROR;
				goto err;
			}
			ResponseCode = SwapBytes32(RecvBuffer.Header.responseCode);
			if (ResponseCode != TPM_RC_SUCCESS) {
				res = EFI_DEVICE_ERROR;
				goto err;
			}

			SetMem(&AuthSession, sizeof(AuthSession), 0);
			AuthSession.sessionHandle = SessionHandle;
			AuthSession.nonce.size = SHA256_DIGEST_SIZE;
			AuthSession.hmac.size = 0;

			CE(Tpm2NvRead(
				DCS_TPM2_NV_INDEX,
				DCS_TPM2_NV_INDEX,
				&AuthSession,
				DCS_TPM_NV_SIZE,
				0,
				OUT &OutData
				));

			CopyMem(Secret, &OutData.buffer[0], DCS_TPM_NV_SIZE);
			SetMem(&OutData, sizeof(OutData), 0);
		}
	}
err:
	if (SessionHandle != 0) {
		Tpm2FlushContext(SessionHandle);
	}
	return res;
}

//////////////////////////////////////////////////////////////////////////
// PCRs
//////////////////////////////////////////////////////////////////////////
EFI_STATUS
DcsTpm2PrintPCR(
	IN UINT32 PcrIndex)
{
	TPML_DIGEST               PcrValue;
	EFI_STATUS                Status;
	OUT_PRINT(L"%HPCR%02d%N ", PcrIndex);
	Status = DcsTpm2PcrRead(PcrIndex, &PcrValue);
	if (EFI_ERROR(Status)) {
		ERR_PRINT(L"%r(%x)\n", Status); //  , Tpm12RespCode(gTpm12Io));
		return Status;
	}
	PrintBytes(PcrValue.digests[0].buffer, PcrValue.digests[0].size);
	OUT_PRINT(L"\n");
	return EFI_SUCCESS;
}

EFI_STATUS
DcsTpm2DumpPcrs(
	IN UINT32 sPcr,
	IN UINT32 ePcr)
{
	UINT32       i;
	EFI_STATUS   Status = EFI_SUCCESS;
	for (i = sPcr; i <= ePcr; ++i) {
		Status = DcsTpm2PrintPCR(i);
		if (EFI_ERROR(Status)) {
			return Status;
		}
	}
	return Status;
}

//////////////////////////////////////////////////////////////////////////
// DCS TPM 2.0 Protocol
//////////////////////////////////////////////////////////////////////////
BOOLEAN
DcsTpm2IsConfigured(
	DCS_TPM_PROTOCOL   *tpm
	)
{
	EFI_STATUS                res = EFI_SUCCESS;
	TPMI_RH_NV_INDEX          NvIndex = 0x1000000 | DCS_TPM_NV_INDEX;
	TPM2B_NV_PUBLIC           NvPublic;
	TPM2B_NAME                NvName;
	UINT32                    PcrMask;

	if (EFI_ERROR(res = DcsTpm2NVReadPcrMask(&PcrMask)) ||
		EFI_ERROR(res = Tpm2NvReadPublic(NvIndex, &NvPublic, &NvName)) ||
		(NvPublic.nvPublic.dataSize != DCS_TPM_NV_SIZE) ||
		(NvPublic.nvPublic.attributes.TPMA_NV_WRITTEN == 0)
		) {
		return FALSE;
	}

	return TRUE;
}

EFI_STATUS
DcsTpm2GetRandom(
	IN   DCS_TPM_PROTOCOL*  tpm,
	IN   UINT32             DataSize,
	OUT  UINT8              *Data
	)
{
	return Tpm2GetRandom(DataSize, Data);
}

EFI_STATUS
DcsTpm2Measure(
	DCS_TPM_PROTOCOL* tpm,
	IN UINTN          index,
	IN UINTN          dataSz,
	IN VOID*          data
	)
{
	if (index > 0x10000) {
		index = DCS_TPM_PCR_LOCK;
	}
	return Tpm2Measure((UINT32)index, dataSz, data);
}

EFI_STATUS
DcsTpm2Lock(
	DCS_TPM_PROTOCOL* tpm
	)
{
	UINT32  lock = 1;
	return Tpm2Measure(DCS_TPM_PCR_LOCK, sizeof(lock), &lock);
}

BOOLEAN
DcsTpm2IsOpen(
	DCS_TPM_PROTOCOL   *tpm
	)
{
	EFI_STATUS   res = EFI_SUCCESS;
	CHAR8        data[DCS_TPM_NV_SIZE];
	res = DcsTpm2NvRead(data);
	ZeroMem(data, DCS_TPM_NV_SIZE);
	return !EFI_ERROR(res);
}

typedef struct _Password Password;
extern VOID
ApplyKeyFile(
	IN OUT Password* password,
	IN     CHAR8*    keyfileData,
	IN     UINTN     keyfileDataSize
	);

EFI_STATUS
DcsTpm2Apply(
	DCS_TPM_PROTOCOL   *tpm,
	OUT VOID*          pwd
	)
{
	EFI_STATUS   res = EFI_SUCCESS;
	CHAR8        data[DCS_TPM_NV_SIZE];
	res = DcsTpm2NvRead(data);
	if (EFI_ERROR(res)) return res;
	ApplyKeyFile(pwd, data, DCS_TPM_NV_SIZE);
	ZeroMem(data, DCS_TPM_NV_SIZE);
	return EFI_SUCCESS;
}

EFI_STATUS
ActionTpm2PrintPcrs(
	IN  VOID *ctx
	)
{
	EFI_STATUS res = EFI_SUCCESS;
	UINTN     i;
	UINT32    pcrMask = 0x1FF;
	UINT32    tmp;

	DcsTpm2NVReadPcrMask(&pcrMask);
	pcrMask = AskPcrsMask(pcrMask);
	tmp = pcrMask;
	for (i = 0; i < 32; ++i) {
		if ((tmp & 1) == 1) {
			DcsTpm2PrintPCR((UINT32)i);
		}
		tmp >>= 1;
	}
	return res;
}

EFI_STATUS
ActionTpm2Clean(
	IN  VOID *ctx
	)
{
	EFI_STATUS res;
	CHAR16    ownerPass[TPM_OWNER_PWD_MAX];
	AskTpmOwnerPwd(ownerPass);
	CE(DcsTpm2Clean((UINT8*)ownerPass, (UINT16)StrLen(ownerPass) * 2));
err:
	return res;
}

EFI_STATUS
ActionTpm2Update(
	IN  VOID *ctx
	)
{
	EFI_STATUS res;
	CHAR16    ownerPass[TPM_OWNER_PWD_MAX];
	UINT32    pcrMask;
	UINT8     data[DCS_TPM_NV_SIZE];
	UINT8     v_data[DCS_TPM_NV_SIZE];

	CE(gRnd == NULL ? EFI_NOT_READY : EFI_SUCCESS);
	CE(gRnd->GetBytes(gRnd, data, sizeof(data)));

	AskTpmOwnerPwd(ownerPass);
	pcrMask = AskPcrsMask(0x137);

	res = DcsTpm2NvDefine((UINT8*)ownerPass, (UINT16)StrLen(ownerPass) * 2,pcrMask, data);

	res = DcsTpm2NvRead(v_data);
	if (CompareMem(v_data, data, DCS_TPM_NV_SIZE) != 0) {
		res = EFI_CRC_ERROR;
	}

	ZeroMem(v_data, DCS_TPM_NV_SIZE);
	ZeroMem(data, DCS_TPM_NV_SIZE);

err:
	return res;
}

PMENU_ITEM          mTpm2Menu = NULL;
BOOLEAN             mTpm2MenuContinue = TRUE;

EFI_STATUS
ActionTpm2Exit(
	IN  VOID *ctx
	)
{
	mTpm2MenuContinue = FALSE;
	return EFI_SUCCESS;
}


EFI_STATUS
DcsTpm2Configure(
	IN DCS_TPM_PROTOCOL* tpm
	) {
	PMENU_ITEM          item = NULL;
	EFI_STATUS          res;
	item = DcsMenuAppend(item, L"Update TPM secret", 'u', ActionTpm2Update, NULL);
	mTpm2Menu = item;
	item = DcsMenuAppend(item, L"Delete TPM secret", 'd', ActionTpm2Clean, NULL);
	item = DcsMenuAppend(item, L"Print PCRs", 'p', ActionTpm2PrintPcrs, NULL);
	item = DcsMenuAppend(item, L"Exit", 'e', ActionTpm2Exit, NULL);
	do {
		EFI_INPUT_KEY key;
		OUT_PRINT(L"TPM ");
		if (tpm->IsConfigured(tpm)) {
			OUT_PRINT(L"%Vconfigured%N, ");
			if (tpm->IsOpen(tpm)) {
				OUT_PRINT(L"%Vopen%N");
			}
			else {
				ERR_PRINT(L"locked");
			}
		}
		else {
			ERR_PRINT(L"not configured");
		}
		OUT_PRINT(L"\n");
		DcsMenuPrint(mTpm2Menu);
		item = NULL;
		key.UnicodeChar = 0;
		while (item == NULL) {
			item = mTpm2Menu;
			key = GetKey();
			while (item != NULL) {
				if (item->Select == key.UnicodeChar) break;
				item = item->Next;
			}
		}
		OUT_PRINT(L"%c\n", key.UnicodeChar);
		res = item->Action(item->Context);
		if (EFI_ERROR(res)) {
			ERR_PRINT(L"%r,line %d\n", res, gCELine);
		}
	} while (mTpm2MenuContinue);
	return EFI_SUCCESS;
}

VOID
DcsInitTpm20(
	IN OUT DCS_TPM_PROTOCOL* Tpm)
{
	Tpm->TpmVersion = 0x200;
	Tpm->IsConfigured = DcsTpm2IsConfigured;
	Tpm->IsOpen = DcsTpm2IsOpen;
	Tpm->Configure = DcsTpm2Configure;
	Tpm->Apply = DcsTpm2Apply;
	Tpm->Lock = DcsTpm2Lock;
	Tpm->Measure = DcsTpm2Measure;
	Tpm->GetRandom = DcsTpm2GetRandom;
}
