/** @file
Block R/W interceptor

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov
Copyright (c) 2016. VeraCrypt, Mounir IDRASSI

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/


#include "DcsVeraCrypt.h"
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/DevicePathLib.h>
#include <Library/BaseMemoryLib.h>

#include <Library/CommonLib.h>
#include <Library/GraphLib.h>
#include <Library/PasswordLib.h>
#include <Library/BaseLib.h>
#include <Library/DcsCfgLib.h>
#include <Library/DcsIntLib.h>
#include <Library/DcsTpmLib.h>
#include <Library/PasswordLib.h>

#include "common/Tcdefs.h"
#include "common/Crypto.h"
#include "common/Volumes.h"
#include "common/Crc.h"
#include "crypto/cpu.h"
#include "BootCommon.h"
#include "DcsConfig.h"
#include <Guid/EventGroup.h>

static EFI_DEVICE_PATH*  gDcsBoot;
//static UINTN             gDcsBootSize;

#pragma pack(1)
typedef struct _BOOT_PARAMS {
	CHAR8                  Offset[TC_BOOT_LOADER_ARGS_OFFSET];
	BootArguments          BootArgs;
	BOOT_CRYPTO_HEADER     BootCryptoInfo;
	uint16                 pad1;
	SECREGION_BOOT_PARAMS  SecRegion;
} BOOT_PARAMS, *PBOOT_PARAMS;
#pragma pack()

static UINT32                  gHeaderSaltCrc32 = 0;
static PBOOT_PARAMS            bootParams = NULL;
// #define EFI_BOOTARGS_REGIONS_TEST ,0x9000000, 0xA000000
#define EFI_BOOTARGS_REGIONS_TEST
static UINTN BootArgsRegions[] = { EFI_BOOTARGS_REGIONS_HIGH, EFI_BOOTARGS_REGIONS_LOW EFI_BOOTARGS_REGIONS_TEST };

static CHAR8      Header[512];
static UINT32     BootDriveSignature = 0;
static EFI_GUID   BootDriveSignatureGpt;

static EFI_HANDLE              SecRegionHandle = NULL;
static UINT64                  SecRegionSector = 0;
static UINT8*                  SecRegionData = NULL;
static UINTN                   SecRegionSize = 0;
static UINTN                   SecRegionOffset = 0;
static PCRYPTO_INFO            SecRegionCryptInfo = NULL;

VOID
CleanSensitiveDataVC(BOOLEAN panic)
{
	if (SecRegionCryptInfo != NULL) {
		MEM_BURN(SecRegionCryptInfo, sizeof(*SecRegionCryptInfo));
	}

	if (gRnd != NULL) {
		MEM_BURN(gRnd, sizeof(*gRnd));
	}

	if (SecRegionData != NULL) {
		MEM_BURN(SecRegionData, SecRegionSize);
	}

	if (gAutoPassword != NULL) {
		MEM_BURN(gAutoPassword, MAX_PASSWORD);
	}

	if (panic && bootParams != NULL) {
		MEM_BURN(bootParams, sizeof(*bootParams));
	}
}

//////////////////////////////////////////////////////////////////////////
// Boot params memory
//////////////////////////////////////////////////////////////////////////

EFI_STATUS
GetBootParamsMemory() {
	EFI_STATUS              status = 0;
	UINTN                   index;
	if (bootParams != NULL) return EFI_SUCCESS;
	for (index = 0; index < sizeof(BootArgsRegions) / sizeof(BootArgsRegions[1]); ++index) {
		status = PrepareMemory(BootArgsRegions[index], sizeof(*bootParams), &bootParams);
		if (!EFI_ERROR(status)) {
			return status;
		}
	}
	return status;
}

EFI_STATUS
SetSecRegionParamsMemory() {
	EFI_STATUS              status = 0;
	UINTN                   index;
	UINT8*                  secRegion = NULL;
	UINT32                  crc;
	if (bootParams == NULL) return EFI_NOT_READY;

	bootParams->SecRegion.Ptr = 0;
	bootParams->SecRegion.Size = 0;

	if (DeList != NULL) {
		for (index = 0; index < sizeof(BootArgsRegions) / sizeof(BootArgsRegions[1]); ++index) {
			status = PrepareMemory(BootArgsRegions[index], DeList->DataSize, &secRegion);
			if (!EFI_ERROR(status)) {
//				OUT_PRINT(L"bootParams %08x SecRegion %08x\n", (UINTN)bootParams, (UINTN)secRegion);
				CopyMem(secRegion, SecRegionData + SecRegionOffset, DeList->DataSize);
				bootParams->SecRegion.Ptr = (UINT64)secRegion;
				bootParams->SecRegion.Size = DeList->DataSize;
				break;
			}
		}
	}

	status = gBS->CalculateCrc32(&bootParams->SecRegion, sizeof(SECREGION_BOOT_PARAMS) - 4, &crc);
	bootParams->SecRegion.Crc = crc;
	return status;
}

EFI_STATUS
PrepareBootParams(
	IN UINT32         bootDriveSignature,
	IN PCRYPTO_INFO   cryptoInfo)
{
	BootArguments           *bootArgs;
	EFI_STATUS              status;
	if (bootParams == NULL) status = EFI_UNSUPPORTED;
	else {
		bootArgs = &bootParams->BootArgs;
		TC_SET_BOOT_ARGUMENTS_SIGNATURE(bootArgs->Signature);
		bootArgs->BootLoaderVersion = VERSION_NUM;
		bootArgs->CryptoInfoOffset = (uint16)(FIELD_OFFSET(BOOT_PARAMS, BootCryptoInfo));
		bootArgs->CryptoInfoLength = (uint16)(sizeof(BOOT_CRYPTO_HEADER) + 2 + sizeof(SECREGION_BOOT_PARAMS));
		bootArgs->HeaderSaltCrc32 = gHeaderSaltCrc32;
		CopyMem(&bootArgs->BootPassword, &gAuthPassword, sizeof(gAuthPassword));
		bootArgs->HiddenSystemPartitionStart = 0;
		bootArgs->DecoySystemPartitionStart = 0;
		bootArgs->BootDriveSignature = bootDriveSignature;
		bootArgs->Flags = (uint32)(gAuthPim << 16);
		bootArgs->BootArgumentsCrc32 = GetCrc32((byte *)bootArgs, (int)((byte *)&bootArgs->BootArgumentsCrc32 - (byte *)bootArgs));
		if(cryptoInfo != NULL) bootParams->BootCryptoInfo.ea = (uint16)cryptoInfo->ea;
		if(cryptoInfo != NULL) bootParams->BootCryptoInfo.mode = (uint16)cryptoInfo->mode;
		if(cryptoInfo != NULL) bootParams->BootCryptoInfo.pkcs5 = (uint16)cryptoInfo->pkcs5;
		SetSecRegionParamsMemory();
		status = EFI_SUCCESS;
	}

	// Clean auth data
	MEM_BURN(&gAuthPassword, sizeof(gAuthPassword));
	MEM_BURN(&gAuthPim, sizeof(gAuthPim));

	return status;
}

void GetIntersection(IN uint64 start1, IN uint32 length1, IN uint64 start2, IN uint64 end2, OUT uint64 *intersectStart, OUT uint32 *intersectLength)
{
	uint64 end1 = start1 + length1 - 1;
	uint64 intersectEnd = (end1 <= end2) ? end1 : end2;

	*intersectStart = (start1 >= start2) ? start1 : start2;
	*intersectLength = (uint32)((*intersectStart > intersectEnd) ? 0 : intersectEnd + 1 - *intersectStart);

	if (*intersectLength == 0)
		*intersectStart = start1;
}

VOID UpdateDataBuffer(
	IN OUT UINT8* buf,
	IN UINT32    bufSize,
	IN UINT64    sector
	) {
	UINT64       intersectStart;
	UINT32       intersectLength;
	UINTN        i;
	if (DeList == NULL) return;
	for (i = 0; i < DeList->Count; ++i) {
		if (DeList->DE[i].Type == DE_Sectors) {
			GetIntersection(
				sector << 9, bufSize,
				DeList->DE[i].Sectors.Start, DeList->DE[i].Sectors.Start + DeList->DE[i].Sectors.Length - 1,
				&intersectStart, &intersectLength
				);
			if (intersectLength != 0) {
//				OUT_PRINT(L"S %d : %lld, %d\n", i, intersectStart, intersectLength);
//				OUT_PRINT(L"S");
				CopyMem(
					buf + (intersectStart - (sector << 9)),
					SecRegionData + SecRegionOffset + DeList->DE[i].Sectors.Offset + (intersectStart - (sector << 9)),
					intersectLength
					);
			}
		}
	}
}

//////////////////////////////////////////////////////////////////////////
// Read/Write
//////////////////////////////////////////////////////////////////////////
EFI_STATUS
VCBlockIO_Write(
	IN EFI_BLOCK_IO_PROTOCOL *This,
	IN UINT32                MediaId,
	IN EFI_LBA               Lba,
	IN UINTN                 BufferSize,
	IN VOID                  *Buffer
	)
{
	DCSINT_BLOCK_IO      *DcsIntBlockIo = NULL;
	CRYPTO_INFO          *CryptInfo = NULL;
	EFI_STATUS           Status = EFI_SUCCESS;
	EFI_LBA              startSector;
	DcsIntBlockIo = GetBlockIoByProtocol(This);
	if (DcsIntBlockIo) {	
		CryptInfo = ((CRYPTO_INFO*)DcsIntBlockIo->FilterParams);
		if (CryptInfo)
		{
			startSector = Lba;
			startSector += gAuthBoot ? 0 : CryptInfo->EncryptedAreaStart.Value >> 9;
			//Print(L"This[0x%x] mid %x Write: lba=%lld, size=%d %r\n", This, MediaId, Lba, BufferSize, Status);
			if ((startSector >= CryptInfo->EncryptedAreaStart.Value >> 9) &&
				(startSector < ((CryptInfo->EncryptedAreaStart.Value + CryptInfo->EncryptedAreaLength.Value) >> 9))) {
				VOID*	writeCrypted;
				writeCrypted = MEM_ALLOC(BufferSize);
				if (writeCrypted == NULL) {
					Status = EFI_BAD_BUFFER_SIZE;
					return Status;
				}
				CopyMem(writeCrypted, Buffer, BufferSize);
				//	Print(L"*");
				UpdateDataBuffer(writeCrypted, (UINT32)BufferSize, startSector);
				EncryptDataUnits(writeCrypted, (UINT64_STRUCT*)&startSector, (UINT32)(BufferSize >> 9), CryptInfo);
				Status = DcsIntBlockIo->LowWrite(This, MediaId, startSector, BufferSize, writeCrypted);
				MEM_FREE(writeCrypted);
			}
			else {
				Status = DcsIntBlockIo->LowWrite(This, MediaId, startSector, BufferSize, Buffer);
			}
		}
		else {
			Print(L"*");
			Status = DcsIntBlockIo->LowWrite(This, MediaId, Lba, BufferSize, Buffer);
		}
	}
	else {
		Status = EFI_BAD_BUFFER_SIZE;
	}
	return Status;
}

EFI_STATUS
VCBlockIO_Read(
	IN EFI_BLOCK_IO_PROTOCOL *This,
	IN UINT32                MediaId,
	IN EFI_LBA               Lba,
	IN UINTN                 BufferSize,
	OUT VOID                 *Buffer
	)
{
	DCSINT_BLOCK_IO      *DcsIntBlockIo = NULL;
	CRYPTO_INFO          *CryptInfo = NULL;
	EFI_STATUS           Status = EFI_SUCCESS;
	EFI_LBA              startSector;
	DcsIntBlockIo = GetBlockIoByProtocol(This);
	if (DcsIntBlockIo) {
		CryptInfo = ((CRYPTO_INFO*)DcsIntBlockIo->FilterParams);
		if (CryptInfo)
		{
			startSector = Lba;
			startSector += gAuthBoot ? 0 : CryptInfo->EncryptedAreaStart.Value >> 9;
			Status = DcsIntBlockIo->LowRead(This, MediaId, startSector, BufferSize, Buffer);
			//Print(L"This[0x%x] mid %x ReadBlock: lba=%lld, size=%d %r\n", This, MediaId, Lba, BufferSize, Status);
			if ((startSector >= CryptInfo->EncryptedAreaStart.Value >> 9) &&
				(startSector < ((CryptInfo->EncryptedAreaStart.Value + CryptInfo->EncryptedAreaLength.Value) >> 9))) {
				//	Print(L".");
				DecryptDataUnits(Buffer, (UINT64_STRUCT*)&startSector, (UINT32)(BufferSize >> 9), CryptInfo);
			}
			UpdateDataBuffer(Buffer, (UINT32)BufferSize, startSector);
		}
		else {
			Print(L".");
			Status = DcsIntBlockIo->LowRead(This, MediaId, Lba, BufferSize, Buffer);
		}
	}
	else {
		Status = EFI_BAD_BUFFER_SIZE;
	}
	return Status;
}

//////////////////////////////////////////////////////////////////////////
// Security regions
//////////////////////////////////////////////////////////////////////////
EFI_STATUS 
SecRegionLoadDefault(EFI_HANDLE partHandle)
{
	EFI_STATUS              res = EFI_SUCCESS;
	HARDDRIVE_DEVICE_PATH   dpVolme;
	EFI_BLOCK_IO_PROTOCOL   *bio = NULL;
	EFI_PARTITION_TABLE_HEADER* gptHdr;

	res = EfiGetPartDetails(partHandle, &dpVolme, &SecRegionHandle);
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Part details: %r\n,", res);
		return res;
	}

	// get BlockIo protocol
	bio = EfiGetBlockIO(SecRegionHandle);
	if (bio == NULL) {
		ERR_PRINT(L"Block I/O not supported\n");
		return EFI_NOT_FOUND;
	}

    if (bio->Media != NULL) {
        if (bio->Media->BlockSize != 512) {
            ERR_PRINT(L"Block size is %d. (not supported)\n", bio->Media->BlockSize);
            return EFI_INVALID_PARAMETER;
        }
    }

	SecRegionData = MEM_ALLOC(512);
	if (SecRegionData == NULL) {
		ERR_PRINT(L"No memory\n");
		return EFI_BUFFER_TOO_SMALL;
	}
	SecRegionSize = 512;

	res = bio->ReadBlocks(bio, bio->Media->MediaId, 0, 512, SecRegionData);
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Read: %r\n", res);
		goto error;
	}

	BootDriveSignature = *(uint32 *)(SecRegionData + 0x1b8);

	res = bio->ReadBlocks(bio, bio->Media->MediaId, 1, 512, SecRegionData);
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Read: %r\n", res);
		goto error;
	}

	gptHdr = (EFI_PARTITION_TABLE_HEADER*)SecRegionData;
	CopyMem(&BootDriveSignatureGpt, &gptHdr->DiskGUID, sizeof(BootDriveSignatureGpt));

	res = bio->ReadBlocks(bio, bio->Media->MediaId, TC_BOOT_VOLUME_HEADER_SECTOR, 512, SecRegionData);
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Read: %r\n", res);
		goto error;
	}

	return EFI_SUCCESS;
error:
	MEM_FREE(SecRegionData);
	SecRegionData = NULL;
	SecRegionSize = 0;
	return res;
}

EFI_STATUS 
SecRegionChangePwd() {
	EFI_STATUS              Status;
	EFI_BLOCK_IO_PROTOCOL*  bio = NULL;
	PCRYPTO_INFO            cryptoInfo, ci;
	Password                newPassword;
	Password                confirmPassword;
	INT32                   vcres;

	Status = RndPreapare();
	if (EFI_ERROR(Status)) {
		ERR_PRINT(L"Rnd: %r\n", Status);
		return Status;
	}

	do {
		ZeroMem(&newPassword, sizeof(newPassword));
		ZeroMem(&confirmPassword, sizeof(newPassword));
		VCAskPwd(AskPwdNew, &newPassword);
		if (gAuthPwdCode == AskPwdRetCancel) {
			return EFI_DCS_USER_CANCELED;
		}
		if (gAuthPwdCode == AskPwdRetTimeout) {
			return EFI_DCS_USER_TIMEOUT;
		}
		VCAskPwd(AskPwdConfirm, &confirmPassword);
		if (gAuthPwdCode == AskPwdRetCancel) {
			MEM_BURN(&newPassword, sizeof(newPassword));
			return EFI_DCS_USER_CANCELED;
		}
		if (gAuthPwdCode == AskPwdRetTimeout) {
			MEM_BURN(&newPassword, sizeof(newPassword));
			return EFI_DCS_USER_TIMEOUT;
		}
		if (newPassword.Length == confirmPassword.Length) {
			if (CompareMem(newPassword.Text, confirmPassword.Text, confirmPassword.Length) == 0) {
				break;
			}
		}
		ERR_PRINT(L"Password mismatch");
	} while (TRUE);

	OUT_PRINT(L"Generate...\n\r");
	cryptoInfo = SecRegionCryptInfo;
	vcres = CreateVolumeHeaderInMemory(
		gAuthBoot, Header,
		cryptoInfo->ea,
		cryptoInfo->mode,
		&newPassword,
		cryptoInfo->pkcs5,
		gAuthPim,
		cryptoInfo->master_keydata,
		&ci,
		cryptoInfo->VolumeSize.Value,
		0, //(volumeType == TC_VOLUME_TYPE_HIDDEN) ? cryptoInfo->hiddenVolumeSize : 0,
		cryptoInfo->EncryptedAreaStart.Value,
		cryptoInfo->EncryptedAreaLength.Value,
		gAuthTc ? 0 : cryptoInfo->RequiredProgramVersion,
		cryptoInfo->HeaderFlags,
		cryptoInfo->SectorSize,
		FALSE);

	if (vcres != 0) {
		ERR_PRINT(L"header create error(%x)\n", vcres);
		Status = EFI_INVALID_PARAMETER;
		goto ret;
	}

	// get BlockIo protocol
	bio = EfiGetBlockIO(SecRegionHandle);
	if (bio == NULL) {
		ERR_PRINT(L"Block io not supported\n,");
		Status = EFI_NOT_FOUND;
		goto ret;
	}

	Status = bio->WriteBlocks(bio, bio->Media->MediaId, SecRegionSector, 512, Header);
	if (EFI_ERROR(Status)) {
		ERR_PRINT(L"Write: %r\n", Status);
		goto ret;
	}
	CopyMem(&gAuthPassword, &newPassword, sizeof(gAuthPassword));
	CopyMem(SecRegionData + SecRegionOffset, Header, 512);

	ERR_PRINT(L"Update (%r)\n", Status);
	if (!EFI_ERROR(Status)) {
		EFI_INPUT_KEY key;
		key = KeyWait(L"Boot OS in %2d ('r' to reset)   \r", 5, 0, 0);
		if (key.UnicodeChar == 'r') {
			MEM_BURN(&newPassword, sizeof(newPassword));
			MEM_BURN(&confirmPassword, sizeof(confirmPassword));
			CleanSensitiveDataVC(FALSE);
			gST->RuntimeServices->ResetSystem(EfiResetCold, EFI_SUCCESS, 0, NULL);
		}
	}

ret:
	MEM_BURN(&newPassword, sizeof(newPassword));
	MEM_BURN(&confirmPassword, sizeof(confirmPassword));
	return Status;
}

EFI_STATUS
SelectDcsBootBySignature() 
{
	EFI_STATUS             res = EFI_NOT_FOUND;
	EFI_BLOCK_IO_PROTOCOL* bio = NULL;
	EFI_PARTITION_TABLE_HEADER* gptHdr;
	UINTN                  i;
	for (i = 0; i < gBIOCount; ++i) {
		if(EfiIsPartition(gBIOHandles[i])) continue;
		bio = EfiGetBlockIO(gBIOHandles[i]);
		if(bio == NULL) continue;
		res = bio->ReadBlocks(bio, bio->Media->MediaId, 0, 512, Header);
		if(EFI_ERROR(res)) continue;
		if((*(UINT32*)(Header+0x1b8)) != BootDriveSignature) continue;
		res = bio->ReadBlocks(bio, bio->Media->MediaId, 1, 512, Header);
		if (EFI_ERROR(res)) continue;
		gptHdr = (EFI_PARTITION_TABLE_HEADER*)Header;
		if (CompareMem(&BootDriveSignatureGpt, &gptHdr->DiskGUID, sizeof(BootDriveSignatureGpt)) != 0) continue;
		gDcsBoot = DevicePathFromHandle(gBIOHandles[i]);
		//gDcsBootSize = GetDevicePathSize(gDcsBoot);
		return EFI_SUCCESS;
	}
	return EFI_NOT_FOUND;
}

EFI_STATUS
SecRegionTryDecrypt() 
{
	int          vcres = 1;
	EFI_STATUS   res = EFI_SUCCESS;
	int          retry = gAuthRetry;
	PlatformGetID(SecRegionHandle, &gPlatformKeyFile, &gPlatformKeyFileSize);

	do {
		SecRegionOffset = 0;
		VCAuthAsk();
		if (gAuthPwdCode == AskPwdRetCancel) {
			return EFI_DCS_USER_CANCELED;
		}
		if (gAuthPwdCode == AskPwdRetTimeout) {
			return EFI_DCS_USER_TIMEOUT;
		}
		//if (gAuthPwdCode == AskPwdForcePass) {
		//	return 1;
		//}

		OUT_PRINT(L"%a", gAuthStartMsg);
		do {
			// EFI tables?
			if (TablesVerify(SecRegionSize - SecRegionOffset, SecRegionData + SecRegionOffset)) {
				EFI_TABLE_HEADER *mhdr = (EFI_TABLE_HEADER *)(SecRegionData + SecRegionOffset);
				UINTN tblZones = (mhdr->HeaderSize + 1024 * 128 - 1) / (1024 * 128);
				SecRegionOffset += tblZones * 1024 * 128;
				vcres = 1;
				continue;
			}
			// Try authorize zone
			CopyMem(Header, SecRegionData + SecRegionOffset, 512);
			vcres = ReadVolumeHeader(gAuthBoot, Header, &gAuthPassword, gAuthHash, gAuthPim, gAuthTc, &SecRegionCryptInfo, NULL);
		   SecRegionOffset += (vcres != 0) ? 1024 * 128 : 0;
		} while (SecRegionOffset < SecRegionSize && vcres != 0);

		if (vcres == 0) {
			OUT_PRINT(L"Success\n");
			OUT_PRINT(L"Start %d %lld len %lld\n", SecRegionOffset / (1024*128), SecRegionCryptInfo->EncryptedAreaStart.Value, SecRegionCryptInfo->EncryptedAreaLength.Value);
			break;
		}	else {
			ERR_PRINT(L"%a", gAuthErrorMsg);
			// clear previous failed authentication information
			MEM_BURN(&gAuthPassword, sizeof(gAuthPassword));
			if (gAuthPimRqt)
				MEM_BURN(&gAuthPim, sizeof(gAuthPim));
		}
		retry--;
	} while (vcres != 0 && retry > 0);

	if (vcres != 0) {
		return EFI_CRC_ERROR;
	}

	SecRegionSector = 62 + SecRegionOffset / 512;

	DeList = NULL;
	if (SecRegionSize > 512) {
		UINT64 startUnit = 0;
		DecryptDataUnits(SecRegionData + SecRegionOffset + 512, (UINT64_STRUCT*)&startUnit,(UINT32)255, SecRegionCryptInfo);
		if (CompareMem(SecRegionData + SecRegionOffset + 512, &gDcsDiskEntryListHeaderID, sizeof(gDcsDiskEntryListHeaderID)) != 0) {
			ERR_PRINT(L"Wrong DCS list header");
			return EFI_CRC_ERROR;
		}
		DeList = (DCS_DISK_ENTRY_LIST *)(SecRegionData + SecRegionOffset + 512);
		CopyMem(&BootDriveSignature, &DeList->DE[DE_IDX_DISKID].DiskId.MbrID, sizeof(BootDriveSignature));
		CopyMem(&BootDriveSignatureGpt, &DeList->DE[DE_IDX_DISKID].DiskId.GptID, sizeof(BootDriveSignatureGpt));

		if (DeList->DE[DE_IDX_EXEC].Type == DE_ExecParams) {
			DCS_DEP_EXEC *execParams = NULL;
			execParams = (DCS_DEP_EXEC *)(SecRegionData + SecRegionOffset + DeList->DE[DE_IDX_EXEC].Offset);
			EfiSetVar(L"DcsExecPartGuid", NULL, &execParams->ExecPartGuid, sizeof(EFI_GUID), EFI_VARIABLE_BOOTSERVICE_ACCESS);
			EfiSetVar(L"DcsExecCmd", NULL, &execParams->ExecCmd, (StrLen((CHAR16*)&execParams->ExecCmd) + 1) * 2, EFI_VARIABLE_BOOTSERVICE_ACCESS);
		}

		if (DeList->DE[DE_IDX_PWDCACHE].Type == DE_PwdCache) {
			DCS_DEP_PWD_CACHE *pwdCache = NULL;
			UINT64  sector = 0;
			pwdCache = (DCS_DEP_PWD_CACHE *)(SecRegionData + SecRegionOffset + DeList->DE[DE_IDX_PWDCACHE].Offset);
			EncryptDataUnits((UINT8*)pwdCache, (UINT64_STRUCT*)&sector, 1, SecRegionCryptInfo);
		}

		if (DeList->DE[DE_IDX_RND].Type == DE_Rnd) {
			UINT8 temp[4];
			UINT64  sector = 0;
			DCS_RND_SAVED* rndNewSaved;
			DCS_RND_SAVED* rndSaved = (DCS_RND_SAVED*)(SecRegionData + SecRegionOffset + DeList->DE[DE_IDX_RND].Offset);
			if (DeList->DE[DE_IDX_RND].Length == sizeof(DCS_RND_SAVED)) {
				if (!EFI_ERROR(res = RndLoad(rndSaved, &gRnd)) &&
					!EFI_ERROR(res = RndGetBytes(temp, sizeof(temp))) &&
					!EFI_ERROR(res = RndSave(gRnd, &rndNewSaved))
				) {
					EFI_BLOCK_IO_PROTOCOL   *bio = NULL;
					sector = (DeList->DE[DE_IDX_RND].Offset >> 9) - 1;
					OUT_PRINT(L"Last login %H%t%N\n", &rndSaved->SavedAt);

					EncryptDataUnits((UINT8*)rndNewSaved, (UINT64_STRUCT*)&sector, 1, SecRegionCryptInfo);
					sector = SecRegionSector + (DeList->DE[DE_IDX_RND].Offset >> 9);

					// get BlockIo protocol
					bio = EfiGetBlockIO(SecRegionHandle);
					if (bio == NULL) {
						ERR_PRINT(L"Block io not supported\n,");
					}
					
					res = bio->WriteBlocks(bio, bio->Media->MediaId, sector, 512, rndNewSaved);
					if (EFI_ERROR(res)) {
						ERR_PRINT(L"Write: %r\n", res);
					}
				}
			}
		}
	}

	// Select boot device
	res = SelectDcsBootBySignature();
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Decrypt device not found\n");
		return res;
	}

	// Change password if requested
	if (gAuthPwdCode == AskPwdRetChange) {
		if (gRnd != NULL)
		{
			res = RndPreapare();
			if (!EFI_ERROR(res)) {
				res = SecRegionChangePwd();
				if (EFI_ERROR(res)) {
					return res;
				}
			}
			else {
				ERR_PRINT(L"Random: %r\n", res);
			}
		}
		else {
			ERR_PRINT(L"Can't change password\n");
		}
	}

	gHeaderSaltCrc32 = GetCrc32(SecRegionData + SecRegionOffset, PKCS5_SALT_SIZE);	
	return EFI_SUCCESS;
}

//////////////////////////////////////////////////////////////////////////
// Open tables
//////////////////////////////////////////////////////////////////////////
UINT8* gOpenTables = NULL;

BOOLEAN
SecRegionTablesFind(UINT8* secRegion, UINTN secRegionSize, VOID** tables) {
	UINTN pos = 0;
	while (pos < SecRegionSize) {
		if (TablesVerify(secRegionSize - pos, secRegion + pos)) {
			*tables = secRegion + pos;
			return TRUE;
		}
		pos += 128 * 1024;
	}
	return FALSE;
}

#define DCSPROP_HEADER_SIGN SIGNATURE_64('D','C','S','P','R','O','P','_')
#define PICTPWD_HEADER_SIGN SIGNATURE_64('P','I','C','T','P','W','D','_')

VOID
VCAuthLoadConfigUpdated(UINT8* secRegion, UINTN secRegionSize) {
	if (SecRegionTablesFind(secRegion, secRegionSize, &gOpenTables)) {
		if (TablesGetData(gOpenTables, DCSPROP_HEADER_SIGN, &gConfigBufferUpdated, &gConfigBufferUpdatedSize)) {
			// Reload config parameters
			MEM_FREE(gAuthPasswordMsg);
			gAuthPasswordMsg = NULL;
			VCAuthLoadConfig();
		}
		TablesGetData(gOpenTables, PICTPWD_HEADER_SIGN, &gPictPwdBmp, &gPictPwdBmpSize);
	}
}

VOID
Pause(
	IN UINTN      seconds
	)
{
	if (seconds) {
		EFI_INPUT_KEY key;
		key = KeyWait(L"%2d   \r", seconds, 0, 0);
		if (key.UnicodeChar != 0) {
			GetKey();
		}
	}
}

VOID
PauseHandleInfo(
	IN EFI_HANDLE hndle,
	IN UINTN      seconds)
{
	if (seconds) {
		EfiPrintDevicePath(hndle);
		Pause(seconds);
		OUT_PRINT(L"\n");
	}
}

//////////////////////////////////////////////////////////////////////////
// VeraCrypt Entry Point
//////////////////////////////////////////////////////////////////////////
EFI_STATUS
DcsVeraCrypt(
	IN EFI_HANDLE ImageHandle,
	IN EFI_SYSTEM_TABLE *SystemTable)
{
	EFI_STATUS res;

	SetCleanSensitiveDataFunc(CleanSensitiveDataVC);

	// Load auth parameters
	VCAuthLoadConfig();

	if (gAuthSecRegionSearch) {
		res = PlatformGetAuthData(&SecRegionData, &SecRegionSize, &SecRegionHandle);
		if (!EFI_ERROR(res)) {
			VCAuthLoadConfigUpdated(SecRegionData, SecRegionSize);
			PauseHandleInfo(SecRegionHandle, gSecRegionInfoDelay);
		}
	} else if (gRUD != 0) {
		// RUD defined
		UINTN			i;
		BOOLEAN		devFound = FALSE;
		InitUsb();
		for (i = 0; i < gUSBCount; ++i) {
			CHAR8*		id = NULL;
			res = UsbGetId(gUSBHandles[i], &id);
			if (!EFI_ERROR(res) && id != NULL) {
				INT32		rud;
				rud = GetCrc32((unsigned char*)id, (int)AsciiStrLen(id));
				MEM_FREE(id);
				if (rud == gRUD) {
					devFound = TRUE;
					PauseHandleInfo(SecRegionHandle, gSecRegionInfoDelay);
					break;
				}
			}
		}
		if (!devFound) return EFI_DCS_DATA_NOT_FOUND;
	}

	// Force authorization
	if (SecRegionData == NULL && gDcsBootForce != 0) {
		res = EFI_NOT_FOUND;
		if (gPartitionGuidOS != NULL) {
			// Try to find by OS partition GUID
			UINTN i;
			for (i = 0; i < gBIOCount; ++i) {
				EFI_GUID guid;
				res = EfiGetPartGUID(gBIOHandles[i], &guid);
				if (EFI_ERROR(res)) continue;
				if (memcmp(gPartitionGuidOS, &guid, sizeof(guid)) == 0) {
					res = SecRegionLoadDefault(gBIOHandles[i]);
					break;
				}
			}
		}	else {
			res = SecRegionLoadDefault(gFileRootHandle);
		}
		if (EFI_ERROR(res)) {
			ERR_PRINT(L"Failed to find Crypto Header\n"); 
			return EFI_DCS_DATA_NOT_FOUND;
		}
		// force password type and message to simulate "press ESC to continue"
		MEM_FREE(gAuthPasswordMsg);
		gAuthPasswordType = gForcePasswordType;
		gAuthPasswordMsg = gForcePasswordMsg;
		gPasswordProgress = gForcePasswordProgress;
	}

	// ask any way? (by DcsBoot flag)
	if (SecRegionData == NULL) {
		if (gDcsBootForce != 0) {
			res = SecRegionLoadDefault(gFileRootHandle);
			if (EFI_ERROR(res)) {
				return EFI_DCS_DATA_NOT_FOUND;
			}
		}	else {
			return EFI_DCS_DATA_NOT_FOUND;
		}
	}

	res = GetBootParamsMemory();
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"No boot args memory: %r\n\r", res);
		KeyWait(L"%02d\r", 10, 0, 0);
		return res;
	}

	RndInit(gRndDefault, NULL, 0, &gRnd);

	res = GetTpm(); // Try to get TPM
	if (!EFI_ERROR(res)) {
		if (gConfigBuffer != NULL) {
			gTpm->Measure(gTpm, DCS_TPM_PCR_LOCK, gConfigBufferSize, gConfigBuffer); // Measure configuration
		}
		if (gTpm->IsConfigured(gTpm) && !gTpm->IsOpen(gTpm) && gTPMLockedInfoDelay) {
			ERR_PRINT(L"TPM is configured but locked. Probably boot chain is modified!\n");
			Pause(gTPMLockedInfoDelay);
		}
	}

	DetectX86Features();
	res = SecRegionTryDecrypt();
	if (gTpm != NULL) {
		gTpm->Lock(gTpm);
	}
	// Reset Console buffer
	gST->ConIn->Reset(gST->ConIn, FALSE);

	if (EFI_ERROR(res)) {
		// clear buffers with potential authentication data
		MEM_BURN(&gAuthPassword, sizeof(gAuthPassword));
		MEM_BURN(&gAuthPim, sizeof(gAuthPim));

		return res;
	}

	res = PrepareBootParams(BootDriveSignature, SecRegionCryptInfo);
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Can not set params for OS: %r", res);
		return res;
	}

	// Prepare decrypt
	res = AddCryptoMount(gDcsBoot, VCBlockIO_Read, VCBlockIO_Write, SecRegionCryptInfo);
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Mount %r\n", res);
		return res;
	}

	// Install decrypt
	res = DscInstallHook(ImageHandle, SystemTable);
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Bind %r\n", res);
		return res;
	}

	return EFI_SUCCESS;
}
