/** @file
EFI TPM12 helpers

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
#include <Library/DcsTpmLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BaseCryptLib.h>

#include <IndustryStandard/Tpm12.h>
#include <IndustryStandard/TcpaAcpi.h>
#include <Library/Tpm12DeviceLib.h>
#include <Protocol/TcgService.h>
#include "Library/DcsCfgLib.h"


#define TPM_PREPARE  Tpm12RequestUseTpm
#define TPM_TRANSMIT Tpm12SubmitCommand

//#pragma warning(disable: 4706)

extern EFI_TCG_PROTOCOL  *mTcgProtocol;

EFI_STATUS
InitTpm12() {
	EFI_STATUS res = EFI_SUCCESS;
	if (mTcgProtocol == NULL) {
		return TPM_PREPARE();
	}
	return res;
}

typedef struct  {
	UINT8      *Cmd;
	UINTN      CmdPos;
	UINTN      CmdSize;
	UINT8      *Resp;
	UINTN      RespPos;
	UINTN      RespSize;
	UINT8      *Hash;
} DCS_TPM12IO;

EFI_STATUS
Sha1Hash(
	IN  VOID    *data,
	IN  UINTN   dataSize,
	OUT UINT8   *hash
	)
{
	UINTN ctxSize;
	VOID  *ctx;
	ctxSize = Sha1GetContextSize();
	ctx = MEM_ALLOC(ctxSize);
	if (ctx == NULL) return EFI_BUFFER_TOO_SMALL;
	Sha1Init(ctx);
	Sha1Update(ctx, data, dataSize);
	if (!Sha1Final(ctx, hash)) {
		MEM_FREE(ctx);
		return EFI_DEVICE_ERROR;
	}
	return EFI_SUCCESS;
}

//////////////////////////////////////////////////////////////////////////
// TPM IO Create/ Free
//////////////////////////////////////////////////////////////////////////
EFI_STATUS
Tpm12IOCreate(
	DCS_TPM12IO **tpmio,
	UINTN cmdSize,
	UINTN respSize) 
{
	DCS_TPM12IO *io;
	if (tpmio == NULL) return EFI_INVALID_PARAMETER;
	io = *tpmio;
	if (io == NULL) {
		io = MEM_ALLOC(sizeof(*io));
		if (io == NULL) return EFI_BUFFER_TOO_SMALL;
	}
	if (io->CmdSize < cmdSize) {
		MEM_FREE(io->Cmd);
		io->Cmd = MEM_ALLOC(cmdSize);
		if (io->Cmd == NULL) goto err;
	}
	io->CmdPos = 0;
	io->CmdSize = cmdSize;
	if (io->RespSize < respSize) {
		MEM_FREE(io->Resp);
		io->Resp = MEM_ALLOC(respSize);
		if (io->Resp == NULL) goto err;
	}
	io->RespPos = 0;
	io->RespSize = respSize;
	if (io->Hash == NULL) {
		UINTN sha1ctxsize;
		sha1ctxsize = Sha1GetContextSize();
		io->Hash = MEM_ALLOC(sha1ctxsize);
		if (io->Hash == NULL) goto err;
	}
	if(!Sha1Init(io->Hash)) goto err;
	*tpmio = io;
	return EFI_SUCCESS;
err:
	MEM_FREE(io->Cmd);
	MEM_FREE(io->Resp);
	MEM_FREE(io->Hash);
	MEM_FREE(io);
	*tpmio = NULL;
	return EFI_BUFFER_TOO_SMALL;
}

VOID
Tpm12IOFree(
	DCS_TPM12IO **tpmio)
{
	DCS_TPM12IO *io;
	if (tpmio == NULL) return;
	io = *tpmio;
	if (io == NULL) return;
	MEM_FREE(io->Cmd);
	MEM_FREE(io->Resp);
	MEM_FREE(io->Hash);
	MEM_FREE(io);
	*tpmio = NULL;
}

//////////////////////////////////////////////////////////////////////////
// Cmd init and write
//////////////////////////////////////////////////////////////////////////
EFI_STATUS
Tpm12IOUpdateCmdSize(
	DCS_TPM12IO *tpmio) 
{
	UINT32      *data;
	if (tpmio == NULL) return EFI_INVALID_PARAMETER;
	data = (UINT32*)&tpmio->Cmd[2];
	*data = SwapBytes32((UINT32)tpmio->CmdPos);
	return EFI_SUCCESS;
}

EFI_STATUS
Tpm12IOWrite16(
	DCS_TPM12IO *tpmio,
	UINT16      prm,
	BOOLEAN     hashIt)
{
	UINT16      *data;
	if (tpmio == NULL) return EFI_INVALID_PARAMETER;
	if (tpmio->CmdPos + 2 >= tpmio->CmdSize) {
		tpmio->CmdPos = tpmio->CmdSize;
		return EFI_BUFFER_TOO_SMALL;
	}
	data = (UINT16*)&tpmio->Cmd[tpmio->CmdPos];
	*data = SwapBytes16(prm);
	if(hashIt) {
		Sha1Update(tpmio->Hash, data, 2);
	}
	tpmio->CmdPos += 2;
	return Tpm12IOUpdateCmdSize(tpmio);
}

EFI_STATUS
Tpm12IOWrite32(
	DCS_TPM12IO *tpmio,
	UINT32      prm,
	BOOLEAN     hashIt)
{
	UINT32      *data;
	if (tpmio == NULL) return EFI_INVALID_PARAMETER;
	if (tpmio->CmdPos + 4 >= tpmio->CmdSize){
		tpmio->CmdPos = tpmio->CmdSize;
		return EFI_BUFFER_TOO_SMALL;
	}
	data = (UINT32*)&tpmio->Cmd[tpmio->CmdPos];
	*data = SwapBytes32(prm);
	if (hashIt) {
		Sha1Update(tpmio->Hash, data, 4);
	}
	tpmio->CmdPos += 4;
	return Tpm12IOUpdateCmdSize(tpmio);
}

EFI_STATUS
Tpm12IOWriteBytes(
	DCS_TPM12IO *tpmio,
	VOID       *prm,
	UINTN       prmSize,
	BOOLEAN     hashIt)
{
	UINT8      *data;
	if (tpmio == NULL) return EFI_INVALID_PARAMETER;
	if (tpmio->CmdPos + prmSize >= tpmio->CmdSize) {
		tpmio->CmdPos = tpmio->CmdSize;
		return EFI_BUFFER_TOO_SMALL;
	}
	data = &tpmio->Cmd[tpmio->CmdPos];
	CopyMem(data, prm, prmSize);
	if (hashIt) {
		Sha1Update(tpmio->Hash, data, prmSize);
	}
	tpmio->CmdPos += prmSize;
	return Tpm12IOUpdateCmdSize(tpmio);
}

EFI_STATUS
Tpm12IOWrite8(
	DCS_TPM12IO *tpmio,
	UINT8       prm,
	BOOLEAN     hashIt) 
{
	return Tpm12IOWriteBytes(tpmio, &prm, 1, hashIt);
}

EFI_STATUS
Tpm12IOInit(
	DCS_TPM12IO *tpmio,
	UINT16       tag,
	UINT32       ord)
{
	if (tpmio == NULL) return EFI_INVALID_PARAMETER;
	tpmio->CmdPos = 0;
	ZeroMem(tpmio->Cmd, tpmio->CmdSize);
	tpmio->RespPos = 0;
	ZeroMem(tpmio->Resp, tpmio->RespSize);
	Sha1Init(tpmio->Hash);
	Tpm12IOWrite16(tpmio, tag, FALSE);
	Tpm12IOWrite32(tpmio, 0, FALSE);
	return Tpm12IOWrite32(tpmio, ord, TRUE);
}


//////////////////////////////////////////////////////////////////////////
// Read / Parse responces
//////////////////////////////////////////////////////////////////////////
UINT16
Tpm12RespTag(
	DCS_TPM12IO          *tpmio)
{
	UINT16 *tag;
	if (tpmio == NULL) return 0;
	tag = (UINT16*)tpmio->Resp;
	return SwapBytes16(*tag);
}

UINT32
Tpm12RespCode(
	IN  DCS_TPM12IO          *tpmio
	)
{
	UINT32 *code;
	if (tpmio == NULL) return 0;
	code = (UINT32*)&tpmio->Resp[6];
	return SwapBytes32(*code);
}

UINT32
Tpm12RespSize(
	IN  DCS_TPM12IO          *tpmio
	)
{
	UINT32 *size;
	if (tpmio == NULL) return 0;
	size = (UINT32*)&tpmio->Resp[2];
	return SwapBytes32(*size);
}

UINT8*
Tpm12RespData(
	IN  DCS_TPM12IO          *tpmio
	)
{
	if (tpmio == NULL) return NULL;
	return &tpmio->Resp[10];
}

EFI_STATUS
Tpm12RespRead16(
	IN  DCS_TPM12IO          *tpmio,
	OUT UINT16               *data,
	IN  BOOLEAN              hashIt
	)
{
	UINT16 *tmp;
	if (tpmio == NULL) return EFI_INVALID_PARAMETER;
	if(tpmio->RespPos + 2 > tpmio->RespSize) return EFI_BUFFER_TOO_SMALL;
	tmp = (UINT16 *)&tpmio->Resp[tpmio->RespPos];
	if (data != NULL) {
		*data = SwapBytes16(*tmp);
	}
	if (hashIt) {
		Sha1Update(tpmio->Hash, tmp, 2);
	}
	tpmio->RespPos += 2;
	return EFI_SUCCESS;
}

EFI_STATUS
Tpm12RespRead32(
	IN  DCS_TPM12IO          *tpmio,
	OUT UINT32               *data,
	IN  BOOLEAN              hashIt
	)
{
	UINT32 *tmp;
	if (tpmio == NULL) return EFI_INVALID_PARAMETER;
	if (tpmio->RespPos + 4 > tpmio->RespSize) return EFI_BUFFER_TOO_SMALL;
	tmp = (UINT32 *)&tpmio->Resp[tpmio->RespPos];
	if (data != NULL) {
		*data = SwapBytes32(*tmp);
	}
	if (hashIt) {
		Sha1Update(tpmio->Hash, tmp, 4);
	}
	tpmio->RespPos += 4;
	return EFI_SUCCESS;
}

EFI_STATUS
Tpm12RespReadBytes(
	IN  DCS_TPM12IO          *tpmio,
	OUT VOID                 *data,
	IN  UINT32               dataSize,
	IN  BOOLEAN              hashIt
	)
{
	UINT8 *tmp;
	if (tpmio == NULL) return EFI_INVALID_PARAMETER;
	if (tpmio->RespPos + dataSize > tpmio->RespSize) return EFI_BUFFER_TOO_SMALL;
	tmp = &tpmio->Resp[tpmio->RespPos];
	if (data != NULL) {
		CopyMem(data, tmp, dataSize);
	}
	if (hashIt) {
		Sha1Update(tpmio->Hash, tmp, dataSize);
	}
	tpmio->RespPos += dataSize;
	return EFI_SUCCESS;
}

VOID
Tpm12Parse16(UINT8** pos, UINT16 *data) {
	if (data == NULL) {
		data = (UINT16*)(*pos);
	}
	*data = SwapBytes16(*((UINT16*)(*pos)));
	(*pos) += 2;
}

VOID
Tpm12Parse32(UINT8** pos, UINT32 *data) {
	if (data == NULL) {
		data = (UINT32*)(*pos);
	}
	*data = SwapBytes32(*((UINT32*)(*pos)));
	(*pos) += 4;
}

VOID
Tpm12ParsePcrInfoShort(UINT8** pos, TPM_PCR_INFO_SHORT*data) {
	if (data == NULL) {
		data = (TPM_PCR_INFO_SHORT*)(*pos);
	}
	data->pcrSelection.sizeOfSelect = SwapBytes16(*((UINT16*)(*pos)));
	(*pos) += data->pcrSelection.sizeOfSelect + 2 + 1 + 20;
}

//////////////////////////////////////////////////////////////////////////
// Transmit command
//////////////////////////////////////////////////////////////////////////
EFI_STATUS
Tpm12Transmit(
	DCS_TPM12IO          *tpmio) 
{
	UINT32               TpmRecvSize;
	EFI_STATUS           res;
	if (tpmio == NULL) return EFI_INVALID_PARAMETER;
	if (tpmio->CmdPos >= tpmio->CmdSize) return EFI_BUFFER_TOO_SMALL;
	TpmRecvSize = (UINT32)tpmio->RespSize;
	res = TPM_TRANSMIT((UINT32)tpmio->CmdPos, tpmio->Cmd, &TpmRecvSize, tpmio->Resp);
	if (EFI_ERROR(res)) {
		return res;
	}
	if (Tpm12RespCode(tpmio) != TPM_SUCCESS) {
		return EFI_DEVICE_ERROR;
	}
	Sha1Init(tpmio->Hash); // Init hash
	tpmio->RespPos = 6;    // Skip tag and size
	Tpm12RespRead32(tpmio, NULL, TRUE);         // Hash return code
	Sha1Update(tpmio->Hash, tpmio->Cmd + 2, 4); // Hash ordinal
	return res;
}

//////////////////////////////////////////////////////////////////////////
// Global TPM12 I/O
//////////////////////////////////////////////////////////////////////////
DCS_TPM12IO *gTpm12Io = NULL;
EFI_STATUS
GetTpm12Io()
{
	EFI_STATUS res = EFI_SUCCESS;
	if (gTpm12Io == NULL) {
		res = Tpm12IOCreate(&gTpm12Io, 1024, 1024);
	}
	if (mTcgProtocol == NULL) {
		return EFI_NOT_READY;
	}
	return res;
}

//////////////////////////////////////////////////////////////////////////
// PCRs
//////////////////////////////////////////////////////////////////////////
EFI_STATUS
Tpm12Cmd_PcrRead(
	DCS_TPM12IO *tpmio,
	IN UINT32   PcrIndex
	)
{
	Tpm12IOInit(tpmio, TPM_TAG_RQU_COMMAND, TPM_ORD_PcrRead);
	return Tpm12IOWrite32(tpmio, PcrIndex, TRUE);
}

/**
Send PCR Read command to TPM1.2.

@param PcrIndex          The index of the PCR to read.
@param PcrValue          The PCR value.

@retval EFI_SUCCESS      Operation completed successfully.
@retval EFI_DEVICE_ERROR Unexpected device behavior.
**/
EFI_STATUS
Tpm12PcrRead(
	IN UINT32   PcrIndex,
	OUT void    *PcrValue
	)
{
	EFI_STATUS res;
	res = GetTpm12Io();
	if (EFI_ERROR(res)) return res;
	res = Tpm12Cmd_PcrRead(gTpm12Io, PcrIndex);
	if (EFI_ERROR(res)) return res;
	res = Tpm12Transmit(gTpm12Io);
	if (EFI_ERROR(res)) {
		return res;
	}
	Tpm12RespReadBytes(gTpm12Io, PcrValue, sizeof(TPM_PCRVALUE), TRUE);
	return res;
}

EFI_STATUS
Tpm12Cmd_PcrExtend(
	DCS_TPM12IO  *tpmio,
	IN  UINT32   PcrIndex,
	IN  UINTN    dataSz,
	IN  VOID     *data
	)
{
	TPM_DIGEST digest;
	Tpm12IOInit(tpmio, TPM_TAG_RQU_COMMAND, TPM_ORD_Extend);
	Sha1Hash(data, dataSz, (UINT8*)&digest);
	Tpm12IOWrite32(tpmio, PcrIndex, TRUE);
	return Tpm12IOWriteBytes(tpmio, &digest, sizeof(digest), TRUE);
}

/**
Send PCR Extend command to TPM1.2.

@param PcrIndex          The index of the PCR to read.
@param dataSz             size of data
@param data               data. Extend PCR with Sha1(data)

@retval EFI_SUCCESS      Operation completed successfully.
@retval EFI_DEVICE_ERROR Unexpected device behavior.
**/
EFI_STATUS
Tpm12PcrExtend(
	IN  UINT32   PcrIndex,
	IN  UINTN    dataSz,
	IN  VOID     *data
	)
{
	EFI_STATUS res;
	res = GetTpm12Io();
	if (EFI_ERROR(res)) return res;
	res = Tpm12Cmd_PcrExtend(gTpm12Io, PcrIndex, dataSz, data);
	if (EFI_ERROR(res)) return res;
	res = Tpm12Transmit(gTpm12Io);
	if (EFI_ERROR(res)) {
		return res;
	}
	return res;
}

EFI_STATUS
Tpm12PcrExtendAndLog(
	IN  UINT32   PcrIndex,
	IN  UINTN    dataSz,
	IN  VOID     *data
	)
{
	EFI_STATUS res = EFI_NOT_FOUND;

	/*TCG_PCR_EVENT_HDR                   TcgEvent;
	TcgEvent->PCRIndex = PcrIndex;
	TcgEvent->EventType = EventType;
	TcgEvent->EventSize = LogLen;
	CopyMem(&TcgEvent->Event[0], EventLog, LogLen);
	EventNumber = 1;
	Status = TcgProtocol->HashLogExtendEvent(
		TcgProtocol,
		(EFI_PHYSICAL_ADDRESS)(UINTN)HashData,
		HashDataLen,
		TPM_ALG_SHA,
		TcgEvent,
		&EventNumber,
		&EventLogLastEntry
		);
//	TcgEvent.PCRIndex = PcrIndex;
//	TcgEvent.EventType = EV_EFI_VARIABLE_DRIVER_CONFIG;
//	res = TpmMeasureAndLogData(PcrIndex, EV_EFI_VARIABLE_DRIVER_CONFIG, &TcgEvent, sizeof(TcgEvent), data, dataSz);
*/

	return res;
}

EFI_STATUS
Tpm12PcrsSave(
	IN UINTN sPcr,
	IN UINTN ePcr,
	TPM_DIGEST *Pcrs
	) {
	UINT32       i;
	EFI_STATUS   Status = EFI_SUCCESS;
	for (i = (UINT32)sPcr; i <= (UINT32)ePcr; ++i) {
		Status = Tpm12PcrRead(i, &Pcrs[i].digest);
		if (EFI_ERROR(Status)) {
			return Status;
		}
	}
	return Status;
}

EFI_STATUS
Tpm12PrintPCR(
	IN UINT32 PcrIndex)
{
	TPM_PCRVALUE PcrValue;
	EFI_STATUS   Status;
	OUT_PRINT(L"%HPCR%02d%N ", PcrIndex);
	Status = Tpm12PcrRead(PcrIndex, &PcrValue);
	if (EFI_ERROR(Status)) {
		ERR_PRINT(L"%r(%x)\n", Status, Tpm12RespCode(gTpm12Io));
		return Status;
	}
	PrintBytes(PcrValue.digest, sizeof(PcrValue));
	OUT_PRINT(L"\n");
	return EFI_SUCCESS;
}

EFI_STATUS
Tpm12DumpPcrs(
	IN UINT32 sPcr, 
	IN UINT32 ePcr)
{
	UINT32       i;
	EFI_STATUS   Status = EFI_SUCCESS;
	for (i = sPcr; i <= ePcr; ++i) {
		Status = Tpm12PrintPCR(i);
		if (EFI_ERROR(Status)) {
			return Status;
		}
	}
	return Status;
}

//////////////////////////////////////////////////////////////////////////
// Get Capability
//////////////////////////////////////////////////////////////////////////
EFI_STATUS
Tpm12Cmd_GetCapability(
	DCS_TPM12IO *tpmio,
	IN  UINT32    capArea,
	IN  UINT32    subCapSize,
	IN  UINT8     *subCap
	)
{
	EFI_STATUS res;
	Tpm12IOInit(tpmio, TPM_TAG_RQU_COMMAND, TPM_ORD_GetCapability);
	Tpm12IOWrite32(tpmio, capArea, TRUE);
	res = Tpm12IOWrite32(tpmio, subCapSize, TRUE);
	if (subCapSize > 0) {
		res = Tpm12IOWriteBytes(tpmio, subCap, subCapSize, TRUE);
	}
	return res;
}

/**
Send GetCapability command to TPM1.2.

@param capArea           The index of the Capability
@param subCapSize        The size of details.
@param subCap            Details

@retval EFI_SUCCESS      Operation completed successfully.
@retval EFI_DEVICE_ERROR Unexpected device behavior.
**/
EFI_STATUS
EFIAPI
Tpm12GetCapability(
	IN  UINT32    capArea,
	IN  UINT32    subCapSize,
	IN  UINT8     *subCap,
	OUT UINT32    *respSize,
	OUT UINT8     *resp
	)
{
	EFI_STATUS res;
	res = GetTpm12Io();
	if (EFI_ERROR(res)) return res;
	res = Tpm12Cmd_GetCapability(gTpm12Io, capArea, subCapSize, subCap);
	if (EFI_ERROR(res)) return res;
	res = Tpm12Transmit(gTpm12Io);
	if (EFI_ERROR(res)) {
		return res;
	}
	res = Tpm12RespRead32(gTpm12Io, respSize, TRUE);
	if (!EFI_ERROR(res)) {
		res = Tpm12RespReadBytes(gTpm12Io, resp, *respSize, TRUE);
	}
	return res;
}

//////////////////////////////////////////////////////////////////////////
// NV
//////////////////////////////////////////////////////////////////////////
EFI_STATUS
Tpm12GetNvList(
	OUT UINT32    *respSize,
	OUT UINT32    *resp
	) {
	return Tpm12GetCapability(TPM_CAP_NV_LIST, 0, NULL, respSize, (UINT8*)resp);
}

EFI_STATUS
Tpm12PcrsDigest(
	IN  UINT16     sizeOfSelect,
	IN  UINT8      *pcrSelect,
	IN  TPM_DIGEST *Pcrs,
	OUT TPM_DIGEST *digest
	)
{
	UINTN Sha1CtxSize;
	UINTN i;
	UINTN j;
	UINTN k;
	VOID* Sha1Ctx;
	UINT16 tmp16;
	UINT32 tmp32;

	k = 0;
	for (i = 0; i < sizeOfSelect; ++i) {
		UINT8 tmp = pcrSelect[i];
		for (j = 0; j < 8; ++j) {
			if ((tmp & 1) == 1) {
				k++;
			}
			tmp >>= 1;
		}
	}
	if (k == 0) return EFI_SUCCESS;
	Sha1CtxSize = Sha1GetContextSize();
	Sha1Ctx = MEM_ALLOC(Sha1CtxSize);
	if (Sha1Ctx == NULL) return EFI_BUFFER_TOO_SMALL;
	Sha1Init(Sha1Ctx);
	tmp16 = SwapBytes16(sizeOfSelect);
	Sha1Update(Sha1Ctx, &tmp16, sizeof(tmp16));
	Sha1Update(Sha1Ctx, pcrSelect, sizeOfSelect);

	tmp32 = SwapBytes32((UINT32)(k * sizeof(TPM_DIGEST)));
	Sha1Update(Sha1Ctx, &tmp32, sizeof(tmp32));
	k = 0;
	for (i = 0; i < sizeOfSelect; ++i) {
		UINT8 tmp = pcrSelect[i];
		for (j = 0; j < 8; ++j) {
			if ((tmp & 1) == 1) {
				Sha1Update(Sha1Ctx, &Pcrs[k], sizeof(TPM_DIGEST));
			}
			tmp >>= 1;
			k++;
		}
	}
	if (Sha1Final(Sha1Ctx, digest->digest)) return EFI_SUCCESS;
	return EFI_DEVICE_ERROR;
}

EFI_STATUS
Tpm12NvDetails(
	IN  UINT32    index,
	OUT UINT32    *attr,
	OUT UINT32    *dataSz,
	OUT UINT32    *pcrR,
	OUT UINT32    *pcrW
	) 
{
	EFI_STATUS res;
	TPM_PCR_INFO_SHORT* pcrRead;
	TPM_PCR_INFO_SHORT* pcrWrite;
	UINT8 nvdata[sizeof(TPM_NV_DATA_PUBLIC) + 256];
	UINT8* pos = nvdata;
	UINT32 sz = sizeof(nvdata);
	UINT32 swapindex = SwapBytes32(index);
	res = Tpm12GetCapability(TPM_CAP_NV_INDEX, 4, (UINT8*)&swapindex, &sz, nvdata);
	if(EFI_ERROR(res)) return res;
	Tpm12Parse16(&pos, NULL);
	Tpm12Parse32(&pos, &index);
	pcrRead = (TPM_PCR_INFO_SHORT*)pos;
	Tpm12ParsePcrInfoShort(&pos, NULL);
	pcrWrite = (TPM_PCR_INFO_SHORT*)pos;
	Tpm12ParsePcrInfoShort(&pos, NULL);
	Tpm12Parse16(&pos, NULL);
	Tpm12Parse32(&pos, attr);
	pos += 3;
	Tpm12Parse32(&pos, dataSz);
	if (pcrR != NULL) {
		*pcrR = pcrRead->pcrSelection.pcrSelect[0];
		*pcrR |= pcrRead->pcrSelection.sizeOfSelect > 1 ? pcrRead->pcrSelection.pcrSelect[1] << 8 : 0;
		*pcrR |= pcrRead->pcrSelection.sizeOfSelect > 2 ? pcrRead->pcrSelection.pcrSelect[2] << 16 : 0;
		*pcrR |= pcrRead->pcrSelection.sizeOfSelect > 3 ? pcrRead->pcrSelection.pcrSelect[3] << 24 : 0;
	}
	if (pcrW != NULL) {
		*pcrW =  pcrWrite->pcrSelection.pcrSelect[0];
		*pcrW |= pcrWrite->pcrSelection.sizeOfSelect > 1 ? pcrWrite->pcrSelection.pcrSelect[1] << 8 : 0;
		*pcrW |= pcrWrite->pcrSelection.sizeOfSelect > 2 ? pcrWrite->pcrSelection.pcrSelect[2] << 16 : 0;
		*pcrW |= pcrWrite->pcrSelection.sizeOfSelect > 3 ? pcrWrite->pcrSelection.pcrSelect[3] << 24 : 0;
	}
	return res;
}

//////////////////////////////////////////////////////////////////////////
// OSAP
//////////////////////////////////////////////////////////////////////////
#pragma pack(1)
typedef struct {
	TPM_NONCE nonceOdd;
	TPM_NONCE nonceOddOSAP;
	TPM_NONCE nonceEven;
	TPM_NONCE nonceEvenOSAP;
	TPM_DIGEST SharedSecret;
	TPM_AUTHHANDLE authHandle;
} TPM12_OSAP;
#pragma pack()

EFI_STATUS
Tpm12Cmd_OSAP(
	IN DCS_TPM12IO *tpmio,
	IN TPM12_OSAP *osap,
	IN UINT16  entityType,
	IN UINT32  entityValue
	)
{
	EFI_STATUS res;
	Tpm12IOInit(tpmio, TPM_TAG_RQU_COMMAND, TPM_ORD_OSAP);
	res = Tpm12IOWrite16(tpmio, entityType, TRUE);
	res = Tpm12IOWrite32(tpmio, entityValue, TRUE);
	res = Tpm12IOWriteBytes(tpmio, &osap->nonceOddOSAP, sizeof(osap->nonceOddOSAP), TRUE);
	return res;
}

TPM12_OSAP                        *gTpm12Osap;

EFI_STATUS
Tpm12OSAPStart(
	IN UINT16  entityType,
	IN UINT32  entityValue,
	IN CHAR16    *ownerPass
	)
{
	EFI_STATUS   res;
	TPM_DIGEST   ownerKey;
	UINTN        CtxSize;
	VOID*        HmacCtx;
	res = GetTpm12Io();
	if (EFI_ERROR(res)) return res;
	if (gTpm12Osap == NULL) {
		gTpm12Osap = MEM_ALLOC(sizeof(TPM12_OSAP));
	}
	res = Tpm12Cmd_OSAP(gTpm12Io, gTpm12Osap, entityType, entityValue);
	if (EFI_ERROR(res)) return res;
	res = Tpm12Transmit(gTpm12Io);
	if (EFI_ERROR(res)) {
		return res;
	}
	Tpm12RespRead32(gTpm12Io, &gTpm12Osap->authHandle, FALSE);
	Tpm12RespReadBytes(gTpm12Io, &gTpm12Osap->nonceEven, sizeof(TPM_NONCE), FALSE);
	res = Tpm12RespReadBytes(gTpm12Io, &gTpm12Osap->nonceEvenOSAP, sizeof(TPM_NONCE), FALSE);
	if (EFI_ERROR(res)) return res;
	Sha1Hash(ownerPass, StrLen(ownerPass) * 2, (UINT8*)&ownerKey);
	CtxSize = HmacSha1GetContextSize();
	HmacCtx = MEM_ALLOC(CtxSize);
	HmacSha1Init(HmacCtx, (UINT8*)&ownerKey, sizeof(ownerKey));
	HmacSha1Update(HmacCtx, &gTpm12Osap->nonceEvenOSAP, sizeof(gTpm12Osap->nonceEvenOSAP));
	HmacSha1Update(HmacCtx, &gTpm12Osap->nonceOddOSAP, sizeof(gTpm12Osap->nonceOddOSAP));
	HmacSha1Final(HmacCtx, (UINT8*)&gTpm12Osap->SharedSecret);
	MEM_FREE(HmacCtx);
	return res;
}

EFI_STATUS
Tpm12OSAPAppend(
	IN  UINT8 continueSession
	) 
{
	EFI_STATUS res;
	UINTN        CtxSize;
	VOID*        HmacCtx;
	TPM_DIGEST   hashCmd;
	TPM_DIGEST   auth;

	Tpm12IOWrite32(gTpm12Io, gTpm12Osap->authHandle, FALSE);
	Tpm12IOWriteBytes(gTpm12Io, &gTpm12Osap->nonceOdd, sizeof(gTpm12Osap->nonceOdd), FALSE);
	res = Tpm12IOWrite8(gTpm12Io, continueSession, FALSE);
	*((UINT16*)gTpm12Io->Cmd) = SwapBytes16(TPM_TAG_RQU_AUTH1_COMMAND); // Update Tag
	Sha1Final(gTpm12Io->Hash, (UINT8*)&hashCmd);
	CtxSize = HmacSha1GetContextSize();
	HmacCtx = MEM_ALLOC(CtxSize);
	if (HmacCtx == NULL) return EFI_BUFFER_TOO_SMALL;
	HmacSha1Init(HmacCtx, (UINT8*)&gTpm12Osap->SharedSecret, sizeof(gTpm12Osap->SharedSecret));
	HmacSha1Update(HmacCtx, &hashCmd, sizeof(hashCmd));
	HmacSha1Update(HmacCtx, &gTpm12Osap->nonceEven, sizeof(gTpm12Osap->nonceEven));
	HmacSha1Update(HmacCtx, &gTpm12Osap->nonceOdd, sizeof(gTpm12Osap->nonceOdd));
	HmacSha1Update(HmacCtx, &continueSession, sizeof(continueSession));
	HmacSha1Final(HmacCtx, (UINT8*)&auth);
	MEM_FREE(HmacCtx);
	res = Tpm12IOWriteBytes(gTpm12Io, &auth, sizeof(auth), FALSE);
	return res;
}

//////////////////////////////////////////////////////////////////////////
// NV
//////////////////////////////////////////////////////////////////////////
EFI_STATUS
Tpm12WritePcrInfo(
	IN DCS_TPM12IO  *tpmio,
	IN UINT16       sizeOfSelect,
	IN UINT8        *pcrSelect,
	IN UINT8        localityAtRelease,
	IN TPM_DIGEST*  pcrs) 
{
	TPM_DIGEST   digestAtRelease;
	ZeroMem(&digestAtRelease, sizeof(digestAtRelease));
	Tpm12IOWrite16   (tpmio, sizeOfSelect, TRUE);
	Tpm12IOWriteBytes(tpmio, pcrSelect, sizeOfSelect, TRUE);
	Tpm12IOWrite8(tpmio, localityAtRelease, TRUE);
	Tpm12PcrsDigest(sizeOfSelect, pcrSelect, pcrs, &digestAtRelease);
	return Tpm12IOWriteBytes(tpmio, &digestAtRelease, sizeof(TPM_DIGEST), TRUE);
}

TPM_DIGEST gTpm12Pcrs[24];
TPM_DIGEST gTpm12OwnerPass;

VOID
PcrUpdateMask(
	UINT32 mask,
	UINT8  *pcr) 
{
	pcr[0] = (UINT8)(mask & 0xFF);
	pcr[1] = (UINT8)((mask >> 8) & 0xFF);
	pcr[2] = (UINT8)((mask >> 16) & 0xFF);
}

EFI_STATUS
Tpm12NvSpace(
	IN UINT32    index,
	IN UINT32    size,
	IN CHAR16    *ownerPass,
	TPM_DIGEST   *pcrs,
	IN UINT32    pcrReadMask,
	IN UINT32    pcrWriteMask,
	IN UINT32    Attributes,
	IN UINT8     bReadSTClear,
	IN UINT8     bWriteSTClear,
	IN UINT8     bWriteDefine
	) {
	EFI_STATUS   res;
	TPM_DIGEST   encAuth;
	UINT8        pcrRead[3]; 
	UINT8        pcrWrite[3];

	PcrUpdateMask(pcrReadMask, pcrRead);
	PcrUpdateMask(pcrWriteMask, pcrWrite);
	SetMem(&encAuth, sizeof(encAuth), 0xEA); // No Auth

	res = Tpm12OSAPStart(TPM_ET_OWNER, TPM_KH_OWNER, ownerPass);
	if (EFI_ERROR(res)) {
		return res;
	}
	Tpm12IOInit(gTpm12Io, TPM_TAG_RQU_AUTH1_COMMAND, TPM_ORD_NV_DefineSpace);
	// NV_DATA_PUBLIC
	Tpm12IOWrite16(gTpm12Io, TPM_TAG_NV_DATA_PUBLIC, TRUE);
	Tpm12IOWrite32(gTpm12Io, index, TRUE);
	Tpm12WritePcrInfo(gTpm12Io, sizeof(pcrRead) , pcrRead,  0x1F, pcrs);
	Tpm12WritePcrInfo(gTpm12Io, sizeof(pcrWrite), pcrWrite, 0x1F, pcrs);
	Tpm12IOWrite16(gTpm12Io, TPM_TAG_NV_ATTRIBUTES, TRUE);
	Tpm12IOWrite32(gTpm12Io, Attributes, TRUE);
	Tpm12IOWrite8(gTpm12Io, bReadSTClear, TRUE);
	Tpm12IOWrite8(gTpm12Io, bWriteSTClear, TRUE);
	Tpm12IOWrite8(gTpm12Io, bWriteDefine, TRUE);
	Tpm12IOWrite32(gTpm12Io, size, TRUE);
	// 
	Tpm12IOWriteBytes(gTpm12Io, &encAuth, sizeof(encAuth), TRUE);
	// OSAP
	Tpm12OSAPAppend(0);

	res = Tpm12Transmit(gTpm12Io);
	if (EFI_ERROR(res)) {
		return res;
	}
	return res;
}

EFI_STATUS
Tpm12Cmd_NvRead(
	IN DCS_TPM12IO    *tpmio,
	IN TPM_NV_INDEX   NvIndex,
	IN UINT32         Offset,
	IN UINT32         DataSize
	)
{
	EFI_STATUS res;
	CE(Tpm12IOInit(tpmio, TPM_TAG_RQU_COMMAND, TPM_ORD_NV_ReadValue));
	CE(Tpm12IOWrite32(tpmio, NvIndex, TRUE));
	CE(Tpm12IOWrite32(tpmio, Offset, TRUE));
	CE(Tpm12IOWrite32(tpmio, DataSize, TRUE));
err:
	return res;
}

/**
Send NV ReadValue command to TPM1.2.

@param NvIndex           The index of the area to set.
@param Offset            The offset into the area.
@param DataSize          The size of the data area.
@param Data              The data to set the area to.

@retval EFI_SUCCESS      Operation completed successfully.
@retval EFI_DEVICE_ERROR Unexpected device behavior.
**/
EFI_STATUS
Tpm12NvRead(
	IN TPM_NV_INDEX   NvIndex,
	IN UINT32         Offset,
	IN OUT UINT32     *DataSize,
	OUT UINT8         *Data
	)
{
	EFI_STATUS res;
	res = GetTpm12Io();
	if (EFI_ERROR(res)) return res;
	res = Tpm12Cmd_NvRead(gTpm12Io, NvIndex,Offset,*DataSize);
	if (EFI_ERROR(res)) return res;
	res = Tpm12Transmit(gTpm12Io);
	if (EFI_ERROR(res)) {
		return res;
	}
	res = Tpm12RespRead32(gTpm12Io, DataSize, TRUE);
	if (!EFI_ERROR(res)) {
		res = Tpm12RespReadBytes(gTpm12Io, Data, *DataSize, TRUE);
	}
	return res;
}

EFI_STATUS
Tpm12Cmd_NvWrite(
	IN DCS_TPM12IO    *tpmio,
	IN TPM_NV_INDEX   NvIndex,
	IN UINT32         Offset,
	IN UINT32         DataSize,
	IN UINT8          *Data
	)
{
	EFI_STATUS res;
	CE(Tpm12IOInit(tpmio, TPM_TAG_RQU_COMMAND, TPM_ORD_NV_WriteValue));
	CE(Tpm12IOWrite32(tpmio, NvIndex, TRUE));
	CE(Tpm12IOWrite32(tpmio, Offset, TRUE));
	CE(Tpm12IOWrite32(tpmio, DataSize, TRUE));
	CE(Tpm12IOWriteBytes(tpmio, Data, DataSize, TRUE));
err:
	return res;
}

/**
Send NV WriteValue command to TPM1.2.

@param NvIndex           The index of the area to set.
@param Offset            The offset into the NV Area.
@param DataSize          The size of the data parameter.
@param Data              The data to set the area to.

@retval EFI_SUCCESS      Operation completed successfully.
@retval EFI_DEVICE_ERROR Unexpected device behavior.
**/
EFI_STATUS
EFIAPI
Tpm12NvWrite(
	IN TPM_NV_INDEX   NvIndex,
	IN UINT32         Offset,
	IN UINT32         DataSize,
	IN UINT8          *Data,
	CHAR16            *ownerPass
	)
{
	EFI_STATUS res;
	res = GetTpm12Io();
	if (EFI_ERROR(res)) return res;
	res = Tpm12OSAPStart(TPM_ET_OWNER, TPM_KH_OWNER, ownerPass);
	if (EFI_ERROR(res)) {
		return res;
	}
	res = Tpm12Cmd_NvWrite(gTpm12Io, NvIndex, Offset, DataSize, Data);
	if (EFI_ERROR(res)) return res;
	// OSAP
	Tpm12OSAPAppend(0);
	res = Tpm12Transmit(gTpm12Io);
	if (EFI_ERROR(res)) {
		return res;
	}
	return res;
}

/*
EFI_STATUS
Tpm12NvDefine(
	IN UINT32    index,
	IN UINT32    size,
	IN CHAR16    *ownerPass) {
	EFI_STATUS res;
// 	UINT32 sz = 20;
// 	UINT8  data[20];
// 	UINT8  dataR[20];
// 	SetMem(data, 20, 1);
// 
// 	CE(Tpm12PcrsSave(0, 23, gTpm12Pcrs));
// 	CE(Tpm12NvSpace(index, size, ownerPass, gTpm12Pcrs, 0x100, 0, 0x2, 0, 0, 0));
// 	CE(Tpm12NvWrite(index,0,size, data, ownerPass));
// 	CE(Tpm12NvRead(index, 0, &sz, dataR));
	CE(GetTpm());
	if (gRnd == NULL) {
		RndInit()
	}
	return res;
err:
	ERR_PRINT(L"%r(%x),line %d\n", res, Tpm12RespCode(gTpm12Io), gCELine);
	return res;
}*/

//////////////////////////////////////////////////////////////////////////
// Random
//////////////////////////////////////////////////////////////////////////
EFI_STATUS
Tpm12Cmd_GetRandom(
	IN DCS_TPM12IO    *tpmio,
	IN UINT32         DataSize
	)
{
	EFI_STATUS res;
	CE(Tpm12IOInit(tpmio, TPM_TAG_RQU_COMMAND, TPM_ORD_GetRandom));
	CE(Tpm12IOWrite32(tpmio, DataSize, TRUE));
err:
	return res;
}

EFI_STATUS
Tpm12GetRandom(
	IN OUT UINT32     *DataSize,
	OUT    UINT8      *Data
	)
{
	EFI_STATUS res;
	res = GetTpm12Io();
	if (EFI_ERROR(res)) return res;
	res = Tpm12Cmd_GetRandom(gTpm12Io, *DataSize);
	if (EFI_ERROR(res)) return res;
	res = Tpm12Transmit(gTpm12Io);
	if (EFI_ERROR(res)) {
		return res;
	}
	res = Tpm12RespRead32(gTpm12Io, DataSize, TRUE);
	if (!EFI_ERROR(res)) {
		res = Tpm12RespReadBytes(gTpm12Io, Data, *DataSize, TRUE);
	}
	return res;
}
//////////////////////////////////////////////////////////////////////////
// Protocol
//////////////////////////////////////////////////////////////////////////

typedef struct _Password Password;

extern VOID
ApplyKeyFile(
	IN OUT Password* password,
	IN     CHAR8*    keyfileData,
	IN     UINTN     keyfileDataSize
	);

EFI_STATUS
DcsTpm12Lock(
	DCS_TPM_PROTOCOL   *tpm
	)
{
	UINT32       lock = 1;
	return Tpm12PcrExtend(DCS_TPM_PCR_LOCK, sizeof(lock), &lock);
}

EFI_STATUS
DcsTpm12Apply(
	DCS_TPM_PROTOCOL   *tpm,
	OUT VOID*          pwd
	)
{
	EFI_STATUS   res;
	UINT32       sz = DCS_TPM_NV_SIZE;
	CHAR8        data[DCS_TPM_NV_SIZE];
	res = Tpm12NvRead(DCS_TPM_NV_INDEX, 0, &sz, data);
	if (EFI_ERROR(res)) return res;
	ApplyKeyFile(pwd, data, DCS_TPM_NV_SIZE);
	ZeroMem(data, DCS_TPM_NV_SIZE);
	return EFI_SUCCESS;
}

BOOLEAN
DcsTpm12IsOpen(
	DCS_TPM_PROTOCOL   *tpm
	)
{
	EFI_STATUS   res;
	UINT32       sz = DCS_TPM_NV_SIZE;
	UINT8        data[DCS_TPM_NV_SIZE];
	res = Tpm12NvRead(DCS_TPM_NV_INDEX, 0, &sz, data);
	if (EFI_ERROR(res)) return FALSE;
	ZeroMem(data, DCS_TPM_NV_SIZE);
	return TRUE;
}

BOOLEAN
DcsTpm12IsConfigured(
	DCS_TPM_PROTOCOL   *tpm
	)
{
	EFI_STATUS   res;
	UINT32       dataSz;
	UINT32       attr;
	UINT32       pcrR;
	UINT32       pcrW;
	res = Tpm12NvDetails(DCS_TPM_NV_INDEX, &attr, &dataSz, &pcrR, &pcrW);
	if (EFI_ERROR(res)) return FALSE;
	if (dataSz != DCS_TPM_NV_SIZE) return FALSE;
	return TRUE;
}

VOID
AskTpmOwnerPwd(
	OUT CHAR16*  ownerPass
	) {
	UINTN     ownerPassLen;
	OUT_PRINT(L"TPM owner password:");
	ZeroMem(ownerPass, TPM_OWNER_PWD_MAX * 2);
	GetLine(&ownerPassLen, ownerPass, NULL, TPM_OWNER_PWD_MAX - 1, FALSE);
}

UINT32 
AskPcrsMask(
	IN UINT32 def
	) 
{
	OUT_PRINT(L"PCR selection bits(hex):\n\
 1 BIOS           2 BIOS data         4 EFI drivers\n\
 8 EFI variables 10 EFI boot loader  20 EFI boot loader data\n\
40 Boot event    80 Manufacture     100 DcsProp\n");
	return (UINT32)AskHexUINT64("PCRs mask:", def);
}

EFI_STATUS
ActionTpm12Update(
	IN  VOID *ctx
	) 
{
	EFI_STATUS res;
	CHAR16    ownerPass[TPM_OWNER_PWD_MAX];
	UINT32    pcrMask;
	UINT8     data[DCS_TPM_NV_SIZE];
	ZeroMem(data, DCS_TPM_NV_SIZE);
	CE(Tpm12PcrsSave(0, 23, gTpm12Pcrs));
	AskTpmOwnerPwd(ownerPass);
	pcrMask = AskPcrsMask(0x137);
	CE(Tpm12NvSpace(DCS_TPM_NV_INDEX, DCS_TPM_NV_SIZE, ownerPass, gTpm12Pcrs, pcrMask, 0, 0x2, 0, 0, 0));
	CE(gRnd == NULL ? EFI_NOT_READY : EFI_SUCCESS);
	CE(gRnd->GetBytes(gRnd, data, sizeof(data)));
	CE(Tpm12NvWrite(DCS_TPM_NV_INDEX, 0, DCS_TPM_NV_SIZE, data, ownerPass));
err:
	return res;
}

EFI_STATUS
ActionTpm12Clean(
	IN  VOID *ctx
	) 
{
	EFI_STATUS res;
	CHAR16    ownerPass[TPM_OWNER_PWD_MAX];
	AskTpmOwnerPwd(ownerPass);
	CE(Tpm12NvSpace(DCS_TPM_NV_INDEX, 0, ownerPass, gTpm12Pcrs, 0, 0, 0x2, 0, 0, 0));
err:
	return res;
}

EFI_STATUS
ActionTpm12PrintPcrs(
	IN  VOID *ctx
	)
{
	EFI_STATUS res = EFI_SUCCESS;
	UINTN     i;
	UINT32    pcrMask = 0x1FF;
	UINT32    tmp;
	Tpm12NvDetails(DCS_TPM_NV_INDEX, NULL, NULL, &pcrMask, NULL);
	pcrMask = AskPcrsMask(pcrMask);
	tmp = pcrMask;
	for (i = 0; i < 32; ++i) {
		if ((tmp & 1) == 1) {
			Tpm12PrintPCR((UINT32)i);
		}
		tmp >>= 1;
	}
	return res;
}

PMENU_ITEM          mTpm12Menu = NULL;
BOOLEAN             mTpm12MenuContinue = TRUE;

EFI_STATUS
ActionTpm12Exit(
	IN  VOID *ctx
	)
{
	mTpm12MenuContinue = FALSE;
	return EFI_SUCCESS;
}


EFI_STATUS
DcsTpm12Configure(
	IN DCS_TPM_PROTOCOL* tpm
	) {
	PMENU_ITEM          item = NULL;
	EFI_STATUS          res;
	item = DcsMenuAppend(item, L"Update TPM secret", 'u', ActionTpm12Update, NULL);
	mTpm12Menu = item;
	item = DcsMenuAppend(item, L"Delete TPM secret", 'd', ActionTpm12Clean, NULL);
	item = DcsMenuAppend(item, L"Print PCRs", 'p', ActionTpm12PrintPcrs, NULL);
	item = DcsMenuAppend(item, L"Exit", 'e', ActionTpm12Exit, NULL);
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
		DcsMenuPrint(mTpm12Menu);
		item = NULL;
		key.UnicodeChar = 0;
		while (item == NULL) {
			item = mTpm12Menu;
			key = GetKey();
			while (item != NULL) {
				if (item->Select == key.UnicodeChar) break;
				item = item->Next;
			}
		}
		OUT_PRINT(L"%c\n", key.UnicodeChar);
		res = item->Action(item->Context);
		if (EFI_ERROR(res)) {
			ERR_PRINT(L"%r(%x),line %d\n", res, Tpm12RespCode(gTpm12Io), gCELine);
		}
	} while (mTpm12MenuContinue);
	return EFI_SUCCESS;
}

EFI_STATUS
DcsTpm12GetRandom(
	IN   DCS_TPM_PROTOCOL*  tpm,
	IN   UINT32             DataSize,
	OUT  UINT8              *Data
	)
{
	UINT32             remains = DataSize;
	UINT32             gotBytes = 0;
	UINT8              *rnd = Data;
	EFI_STATUS         res = EFI_SUCCESS;
	while (remains > 0)
	{
		gotBytes = remains;
		res = Tpm12GetRandom(&gotBytes, rnd);
		if (EFI_ERROR(res)) return res;
		rnd += gotBytes;
		remains -= gotBytes;
	}
	return res;
}

EFI_STATUS
DcsTpm12Measure(
	DCS_TPM_PROTOCOL* tpm,
	IN UINTN          index,
	IN UINTN          dataSz,
	IN VOID*          data
	) 
{
	EFI_STATUS res;
	TPM_DIGEST hash;
	if (index > 0x10000) {
		index = DCS_TPM_PCR_LOCK;
	}
	CE(Sha1Hash(data, dataSz, (UINT8*)&hash));
	CE(Tpm12PcrExtend((UINT32)index, sizeof(hash), &hash));

err:
	return res;
}

DCS_TPM_PROTOCOL* gTpm = (DCS_TPM_PROTOCOL*)NULL;

VOID
DcsInitTpm12(
	IN OUT DCS_TPM_PROTOCOL* Tpm)
{
	Tpm->TpmVersion = 0x102;
	Tpm->IsConfigured = DcsTpm12IsConfigured;
	Tpm->IsOpen = DcsTpm12IsOpen;
	Tpm->Configure = DcsTpm12Configure;
	Tpm->Apply = DcsTpm12Apply;
	Tpm->Lock = DcsTpm12Lock;
	Tpm->Measure = DcsTpm12Measure;
	Tpm->GetRandom = DcsTpm12GetRandom;
}

EFI_STATUS
GetTpm() {
	EFI_STATUS res;
	res = InitTpm12();
	if (!EFI_ERROR(res)) {
		gTpm = (DCS_TPM_PROTOCOL*)MEM_ALLOC(sizeof(DCS_TPM_PROTOCOL));
		if (gTpm == NULL) return EFI_BUFFER_TOO_SMALL;
		DcsInitTpm12(gTpm);
		return EFI_SUCCESS;
	}
	res = InitTpm20();
	if (!EFI_ERROR(res)) {
		gTpm = (DCS_TPM_PROTOCOL*)MEM_ALLOC(sizeof(DCS_TPM_PROTOCOL));
		if (gTpm == NULL) return EFI_BUFFER_TOO_SMALL;
		DcsInitTpm20(gTpm);
		return EFI_SUCCESS;
	}
	return res;
}

