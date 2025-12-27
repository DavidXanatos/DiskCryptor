/** @file
GPT actions

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#include <Library/UefiBootServicesTableLib.h>
#include <Library/DevicePathLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PrintLib.h>
#include <Uefi/UefiGpt.h>
#include <Guid/Gpt.h>

#include <Library/CommonLib.h>
#include <Library/DcsCfgLib.h>
#include <DcsConfig.h>

EFI_GUID gEfiPartTypeMsReservedPartGuid = EFI_PART_TYPE_MS_RESERVED_PART_GUID;
EFI_GUID gEfiPartTypeBasicDataPartGuid = EFI_PART_TYPE_BASIC_DATA_PART_GUID;
EFI_GUID gEfiPartTypeMsRecoveryPartGuid = EFI_PART_TYPE_MS_RECOVERY_PART_GUID;

UINT64  gDcsDiskEntryListHeaderID = DCS_DISK_ENTRY_LIST_HEADER_SIGN;
UINT64  gDcsDiskEntryPwdCacheID = DCS_DEP_PWD_CACHE_SIGN;

DCS_DISK_ENTRY_LIST         *DeList = NULL;

UINT8                       *DeCryptoHeader = NULL;

EFI_PARTITION_TABLE_HEADER  *GptMainHdr = NULL;
EFI_PARTITION_ENTRY         *GptMainEntrys = NULL;
EFI_PARTITION_TABLE_HEADER  *GptAltHdr = NULL;
EFI_PARTITION_ENTRY         *GptAltEntrys = NULL;

UINT32                      DiskIdMbr = 0;
EFI_GUID                    DiskIdGpt = EFI_PART_TYPE_UNUSED_GUID;
DCS_DISK_ENTRY_DISKID       DeDiskId;

DCS_DEP_EXEC         *DeExecParams = NULL;

DCS_DEP_PWD_CACHE    *DePwdCache = NULL;

DCS_RND_SAVED        *DeRndSaved;

EFI_BLOCK_IO_PROTOCOL*      BlockIo = NULL;
CONST CHAR16*               DcsDiskEntrysFileName = L"DcsDiskEntrys";

EFI_PARTITION_ENTRY DcsHidePart;

UINTN   BootPartIdx;
UINTN   MirrorPartIdx;

//////////////////////////////////////////////////////////////////////////
// Partitions
//////////////////////////////////////////////////////////////////////////

VOID
GptPrint(
	IN  EFI_PARTITION_TABLE_HEADER  *PartHdr,
	IN  EFI_PARTITION_ENTRY         *Entrys
	)
{
	EFI_PARTITION_ENTRY         *Entry;
	UINTN                       index;
	if (PartHdr == NULL) {
		ERR_PRINT(L"No GPT is loaded\n");
		return;
	}
	Entry = Entrys;
	for (index = 0; index < PartHdr->NumberOfPartitionEntries; ++index, ++Entry) {
		if (CompareGuid(&Entry->PartitionTypeGUID, &gEfiPartTypeUnusedGuid)) {
			continue;
		}
		OUT_PRINT(L"%H%02d%N I:%g T:%g [%lld, %lld] %s\n",
			index,
			&Entry->UniquePartitionGUID,
			&Entry->PartitionTypeGUID,
			Entry->StartingLBA,
			Entry->EndingLBA,
			&Entry->PartitionName
			);
	}
}

EFI_STATUS
GptLoadFromDisk(
	IN UINTN  diskIdx
	) 
{
	EFI_STATUS                  res = EFI_SUCCESS;
	UINTN                       i;
	InitBio();

	BlockIo = EfiGetBlockIO(gBIOHandles[diskIdx]);
	if (BlockIo == NULL) {
		ERR_PRINT(L"Can't open device\n");
		return EFI_NOT_FOUND;
	}

	res = GptReadHeader(BlockIo, 1, &GptMainHdr);
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Can't read main GPT header: %r\n", res);
		goto error;
	}

	res = GptReadHeader(BlockIo, GptMainHdr->AlternateLBA, &GptAltHdr);
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Can't read alt GPT header: %r\n", res);
		goto error;
	}

	res = GptReadEntryArray(BlockIo, GptMainHdr, &GptMainEntrys);
	// Read GPT
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Main GPT error: %r\n", res);
		goto error;
	}

	res = GptReadEntryArray(BlockIo, GptAltHdr, &GptAltEntrys);
	// Read GPT
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Alt GPT error: %r\n", res);
		goto error;
	}

	DeCryptoHeader = MEM_ALLOC(512);
	if (DeCryptoHeader == NULL) {
		ERR_PRINT(L"Can't alloc CryptoHeader\n");
		res = EFI_BUFFER_TOO_SMALL;
		goto error;
	}

	// Load disk IDs
	res = BlockIo->ReadBlocks(BlockIo, BlockIo->Media->MediaId, 0, 512, DeCryptoHeader);
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Can't MBR \n");
		goto error;
	}

	SetMem(&DeDiskId, sizeof(DeDiskId), 0);
	DeDiskId.Type = DE_DISKID;
	CopyMem(&DeDiskId.MbrID, &DeCryptoHeader[0x1b8], sizeof(DiskIdMbr));
	CopyMem(&DeDiskId.GptID, &GptMainHdr->DiskGUID, sizeof(DiskIdGpt));

	// Load crypto header
	res = BlockIo->ReadBlocks(BlockIo, BlockIo->Media->MediaId, 62, 512, DeCryptoHeader);
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Can't read CryptoHeader\n");
		goto error;
	}

	for (i = 0; i < GptMainHdr->NumberOfPartitionEntries; ++i) {
		EFI_PARTITION_ENTRY *part;
		part = &GptMainEntrys[i];
		if (CompareMem(&gEfiPartTypeSystemPartGuid, &part->PartitionTypeGUID, sizeof(EFI_GUID)) == 0) {
			CHAR16*   defExec = L"\\EFI\\Microsoft\\Boot\\bootmgfw_ms.vc";
			DeExecParams = MEM_ALLOC(sizeof(*DeExecParams));
			ZeroMem(DeExecParams, sizeof(*DeExecParams));
			CopyMem(&DeExecParams->ExecPartGuid, &part->UniquePartitionGUID, sizeof(EFI_GUID));
			CopyMem(&DeExecParams->ExecCmd, defExec, (StrLen(defExec) + 1 ) * 2);
			break;
		}
	}
	return res;

error:
	MEM_FREE(GptMainHdr);
	MEM_FREE(GptMainEntrys);
	MEM_FREE(GptAltHdr);
	MEM_FREE(GptAltEntrys);
	MEM_FREE(DeCryptoHeader);
	return res;
}

VOID
DeListPrint() {
	OUT_PRINT(L"Diskid %08x, %g\n", DeDiskId.MbrID, &DeDiskId.GptID);
	if (DeExecParams != NULL) {
		OUT_PRINT(L"Exec %g, %s\n", &DeExecParams->ExecPartGuid, &DeExecParams->ExecCmd);
	}
	if (DePwdCache != NULL) {
		OUT_PRINT(L"PwdCache %d\n", DePwdCache->Count);
	}
	if (DeRndSaved != NULL) {
		OUT_PRINT(L"Rnd %d\n", DeRndSaved->Type);
	}
	GptPrint(GptMainHdr, GptMainEntrys);
}

#define DeList_UPDATE_BEGIN(Data, DEType, Index, Len)    \
   if (Data != NULL) {                                 \
       DeData[Index] = Data;                           \
       DeList->DE[Index].Type = DEType;                  \
       DeList->DE[Index].Offset = Offset;              \
       DeList->DE[Index].Length = Len;                 \
       Offset += ((Len + 511) >> 9) << 9;

#define DeList_UPDATE_END    \
   }

VOID
DeListSaveToFile() {
	EFI_STATUS                  res = EFI_SUCCESS;
	UINT32                      Offset;
	VOID*                       DeData[DE_IDX_TOTAL];
	UINT8*                      pad512buf = NULL;

	ZeroMem(DeData, sizeof(DeData));

	res = EFI_BUFFER_TOO_SMALL;
	DeList = MEM_ALLOC(sizeof(*DeList));
	if (DeList == NULL) {
		ERR_PRINT(L"Can't alloc DeList\n");
		goto error;
	}

	pad512buf = MEM_ALLOC(512);
	if (pad512buf == NULL) {
		ERR_PRINT(L"No memory\n");
		goto error;
	}

	DeList->Signature = DCS_DISK_ENTRY_LIST_HEADER_SIGN;
	DeList->HeaderSize = sizeof(*DeList);
	DeList->Count = DE_IDX_TOTAL;
	Offset = 0;

	DeList_UPDATE_BEGIN(DeCryptoHeader, DE_Sectors, DE_IDX_CRYPTOHEADER, 512)
		DeList->DE[DE_IDX_CRYPTOHEADER].Sectors.Start = 62 * 512;
	DeList_UPDATE_END

	DeList_UPDATE_BEGIN(DeList, DE_List, DE_IDX_LIST, 512)
	DeList_UPDATE_END

	CopyMem(&DeList->DE[DE_IDX_DISKID], &DeDiskId, sizeof(DeDiskId));

	DeList_UPDATE_BEGIN(GptMainHdr, DE_Sectors, DE_IDX_MAINGPTHDR, 512)
		DeList->DE[DE_IDX_MAINGPTHDR].Sectors.Start = GptMainHdr->MyLBA * 512;
	DeList_UPDATE_END

	DeList_UPDATE_BEGIN(GptMainEntrys, DE_Sectors, DE_IDX_MAINGPTENTRYS, GptMainHdr->NumberOfPartitionEntries * GptMainHdr->SizeOfPartitionEntry)
		DeList->DE[DE_IDX_MAINGPTENTRYS].Sectors.Start = GptMainHdr->PartitionEntryLBA * 512;
	DeList_UPDATE_END

	DeList_UPDATE_BEGIN(GptAltHdr, DE_Sectors, DE_IDX_ALTGPTHDR, 512)
		DeList->DE[DE_IDX_ALTGPTHDR].Sectors.Start = GptAltHdr->MyLBA * 512;
	DeList_UPDATE_END

	DeList_UPDATE_BEGIN(GptAltEntrys, DE_Sectors, DE_IDX_ALTGPTENTRYS, GptAltHdr->NumberOfPartitionEntries * GptAltHdr->SizeOfPartitionEntry)
		DeList->DE[DE_IDX_ALTGPTENTRYS].Sectors.Start = GptAltHdr->PartitionEntryLBA * 512;
	DeList_UPDATE_END

	DeList_UPDATE_BEGIN(DeExecParams, DE_ExecParams, DE_IDX_EXEC, sizeof(*DeExecParams))
	DeList_UPDATE_END

	DeList_UPDATE_BEGIN(DePwdCache, DE_PwdCache, DE_IDX_PWDCACHE, sizeof(*DePwdCache))
	DeList_UPDATE_END

	DeList_UPDATE_BEGIN(DeRndSaved, DE_Rnd, DE_IDX_RND, sizeof(*DeRndSaved))
	DeList_UPDATE_END

	DeList->DataSize = Offset;
	res = gBS->CalculateCrc32(DeList, 512, &DeList->CRC32);
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"CRC: %r\n", res);
		goto error;
	}
	{
		EFI_FILE*  file;
		UINTN     i;

		FileDelete(NULL, (CHAR16*)DcsDiskEntrysFileName);
		res = FileOpen(NULL, (CHAR16*)DcsDiskEntrysFileName, &file, EFI_FILE_MODE_READ | EFI_FILE_MODE_CREATE | EFI_FILE_MODE_WRITE, 0);
		if (EFI_ERROR(res)) {
			ERR_PRINT(L"File: %r\n", res);
			goto error;
		}
		for (i = 0; i < DeList->Count; ++i) {
			if (DeData[i] != 0 && DeList->DE[i].Type != DE_DISKID) {
				UINTN len;
				UINTN pad;
				len = (UINTN)DeList->DE[i].Length;
				pad = (((len + 511) >> 9) << 9) - len;
				res = FileWrite(file, DeData[i], len, NULL);
				if (EFI_ERROR(res)) {
					ERR_PRINT(L"Write: %r\n", res);
					goto error;
				}
				if (pad > 0) {
					res = FileWrite(file, pad512buf, pad, NULL);
					if (EFI_ERROR(res)) {
						ERR_PRINT(L"Write: %r\n", res);
						goto error;
					}
				}
			}
		}
		FileClose(file);
	}

error:
	MEM_FREE(DeList);
	MEM_FREE(pad512buf);
}

EFI_STATUS
DeListZero() {
	if (DePwdCache != NULL) {
		DePwdCache = AskConfirm("Remove passwords cache?", 1) ? NULL : DePwdCache;
	}
	if (DeExecParams != NULL) {
		DeExecParams = AskConfirm("Remove exec?", 1) ? NULL : DeExecParams;
	}
	if (DeRndSaved != NULL) {
		DeRndSaved = AskConfirm("Remove rnd?", 1) ? NULL : DeRndSaved;
	}
	if (GptMainHdr != NULL) {
		if (AskConfirm("Remove GPT?", 1)) {
			GptMainHdr = NULL;
			GptMainEntrys = NULL;
			GptAltHdr = NULL;
			GptAltEntrys = NULL;
		}
	}
	return EFI_SUCCESS;
}

EFI_STATUS
DeListParseSaved(
	IN UINT8 *DeBuffer
	)
{
	EFI_STATUS                  res = EFI_SUCCESS;
	DeCryptoHeader = DeBuffer;
	DeList = (DCS_DISK_ENTRY_LIST*)(DeBuffer + 512);
	CopyMem(&DeDiskId, &DeList->DE[DE_IDX_DISKID], sizeof(DeDiskId));

	if (DeList->DE[DE_IDX_EXEC].Type == DE_ExecParams) {
		DeExecParams = (DCS_DEP_EXEC *)(DeBuffer + DeList->DE[DE_IDX_EXEC].Offset);
	}

	if (DeList->DE[DE_IDX_RND].Type == DE_Rnd) {
		DeRndSaved = (DCS_RND_SAVED *)(DeBuffer + DeList->DE[DE_IDX_RND].Offset);
		if ((UINTN)DeList->DE[DE_IDX_RND].Length != sizeof(*DeRndSaved)) {
			return EFI_CRC_ERROR;
		}
	}

	if (DeList->DE[DE_IDX_PWDCACHE].Type == DE_PwdCache) {
		UINT32 crc = 0;
		UINT32 crcSaved = 0;
		DePwdCache = (DCS_DEP_PWD_CACHE*)(DeBuffer + DeList->DE[DE_IDX_PWDCACHE].Offset);
		if (DePwdCache->Sign != gDcsDiskEntryPwdCacheID) {
			return EFI_CRC_ERROR;
		}
		crcSaved = DePwdCache->CRC;
		DePwdCache->CRC = 0;
		res = gBS->CalculateCrc32(DePwdCache, sizeof(*DePwdCache), &crc);
		if (crc != crcSaved) {
			ERR_PRINT(L"Pwd cache crc\n");
			return EFI_CRC_ERROR;
		}
		DePwdCache->CRC = crcSaved;
	}

	if (DeList->DE[DE_IDX_MAINGPTHDR].Type == DE_Sectors) {
		GptMainHdr = (EFI_PARTITION_TABLE_HEADER*)(DeBuffer + DeList->DE[DE_IDX_MAINGPTHDR].Sectors.Offset);
		if ((GptMainHdr->Header.Signature != EFI_PTAB_HEADER_ID) ||
			!GptHeaderCheckCrc(512, &GptMainHdr->Header) ||
			(DeList->DE[DE_IDX_MAINGPTHDR].Sectors.Start >> 9) != GptMainHdr->MyLBA ||
			(GptMainHdr->SizeOfPartitionEntry < sizeof(EFI_PARTITION_ENTRY))) {
			res = EFI_CRC_ERROR;
			ERR_PRINT(L"Main GPT header: %r\n", res);
			return res;
		}
	}

	if (DeList->DE[DE_IDX_MAINGPTENTRYS].Type == DE_Sectors) {
		GptMainEntrys = (EFI_PARTITION_ENTRY*)(DeBuffer + DeList->DE[DE_IDX_MAINGPTENTRYS].Sectors.Offset);
		res = GptCheckEntryArray(GptMainHdr, GptMainEntrys);
		if (EFI_ERROR(res)) {
			ERR_PRINT(L"Main GPT: %r\n", res);
			return res;
		}
	}

	if (DeList->DE[DE_IDX_ALTGPTHDR].Type == DE_Sectors) {
		GptAltHdr = (EFI_PARTITION_TABLE_HEADER*)(DeBuffer + DeList->DE[DE_IDX_ALTGPTHDR].Sectors.Offset);
		if ((GptAltHdr->Header.Signature != EFI_PTAB_HEADER_ID) ||
			!GptHeaderCheckCrc(512, &GptAltHdr->Header) ||
			(DeList->DE[DE_IDX_ALTGPTHDR].Sectors.Start >> 9) != GptAltHdr->MyLBA ||
			(GptAltHdr->SizeOfPartitionEntry < sizeof(EFI_PARTITION_ENTRY))) {
			res = EFI_CRC_ERROR;
			ERR_PRINT(L"Alt GPT header: %r\n", res);
			return res;
		}
	}

	if (DeList->DE[DE_IDX_ALTGPTENTRYS].Type == DE_Sectors) {
		GptAltEntrys = (EFI_PARTITION_ENTRY*)(DeBuffer + DeList->DE[DE_IDX_ALTGPTENTRYS].Sectors.Offset);
		res = GptCheckEntryArray(GptAltHdr, GptAltEntrys);
		if (EFI_ERROR(res)) {
			ERR_PRINT(L"Alt GPT: %r\n", res);
			return res;
		}
	}

	if (GptMainEntrys != NULL && GptAltEntrys != NULL && GptMainHdr != NULL) {
		if (CompareMem(GptMainEntrys, GptAltEntrys, GptMainHdr->NumberOfPartitionEntries * GptMainHdr->SizeOfPartitionEntry) != 0) {
			ERR_PRINT(L"Alt GPT != Main GPT\n");
			return EFI_CRC_ERROR;
		}
	}
	return EFI_SUCCESS;
}

EFI_STATUS
DeListLoadFromFile()
{
	EFI_STATUS                  res = EFI_SUCCESS;
	UINTN                       len;
	UINT8                       *DeBuffer;

	InitFS();
	res = FileLoad(NULL, (CHAR16*)DcsDiskEntrysFileName, &DeBuffer, &len);
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Load: %r\n", res);
		return res;
	}
	return DeListParseSaved(DeBuffer);
}

EFI_STATUS
DeListApplySectorsToDisk(
	IN UINTN   diskIdx
	) 
{
	EFI_STATUS                  res = EFI_SUCCESS;
	UINTN                       i;
	UINT8                       *Mbr;

	InitBio();
	InitFS();
	BlockIo = EfiGetBlockIO(gBIOHandles[diskIdx]);
	if (BlockIo == NULL) {
		ERR_PRINT(L"Can't open device\n");
		return EFI_NOT_FOUND;
	}

	// Compare MBR disk ID
	Mbr = MEM_ALLOC(512);
	if (Mbr == NULL) {
		ERR_PRINT(L"Can't load MBR\n");
		return EFI_BUFFER_TOO_SMALL;
	}

	res = BlockIo->ReadBlocks(BlockIo, BlockIo->Media->MediaId, 0, 512, Mbr);
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Read MBR: %r\n", res);
		MEM_FREE(Mbr);
		return res;
	}

	if (CompareMem(Mbr + 0x1b8, &DeDiskId.MbrID, sizeof(UINT32)) != 0) {
		ERR_PRINT(L"Disk MBR ID %08x != %08x \n", *((UINT32*)(Mbr + 0x1b8)), DeDiskId.MbrID);
		MEM_FREE(Mbr);
		return res;
	}
	MEM_FREE(Mbr);

	// Save sectors
	for (i = 0; i < DeList->Count; ++i) {
		if (DeList->DE[i].Type == DE_Sectors) {
			OUT_PRINT(L"%d Write: %lld, %lld\n", i, DeList->DE[i].Sectors.Start, DeList->DE[i].Sectors.Length);
			res = BlockIo->WriteBlocks(BlockIo, BlockIo->Media->MediaId,
				DeList->DE[i].Sectors.Start >> 9,
				(UINTN)DeList->DE[i].Sectors.Length,
				DeCryptoHeader + DeList->DE[i].Sectors.Offset);
		}
		if (EFI_ERROR(res)) {
			ERR_PRINT(L"Write: %r\n", res);
			return res;
		}
	}
	return EFI_SUCCESS;
}


EFI_STATUS
GptSyncMainAlt() {
	EFI_STATUS                  res = EFI_SUCCESS;
	// Duplicate parts array
	CopyMem(GptAltEntrys, GptMainEntrys, GptMainHdr->NumberOfPartitionEntries * GptMainHdr->SizeOfPartitionEntry);

	res = GptUpdateCRC(GptMainHdr, GptMainEntrys);
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Main CRC: %r\n", res);
		return res;
	}
	GptUpdateCRC(GptAltHdr, GptAltEntrys);
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Alt CRC: %r\n", res);
		return res;
	}
	return res;
}

VOID
GptSqueze() {
	UINTN i = 0;
	UINTN emptyIdx = 0;
	UINTN count;
	count = GptMainHdr->NumberOfPartitionEntries;
	while (i < count) {
		if (CompareGuid(&GptMainEntrys[i].PartitionTypeGUID, &gEfiPartTypeUnusedGuid)) {
			SetMem(&GptMainEntrys[i], sizeof(*GptMainEntrys), 0);
			++i;
			continue;
		}
		else {
			if (emptyIdx != i) {
				CopyMem(&GptMainEntrys[emptyIdx], &GptMainEntrys[i], sizeof(*GptMainEntrys) * (count - i));
				SetMem(&GptMainEntrys[i], sizeof(*GptMainEntrys), 0);
			}
			++emptyIdx;
			i = emptyIdx;
		}
	}
}

VOID
GptSort() {
	UINTN i = 0;
	UINTN j = 0;
	UINTN n = 0;
	UINTN count;
	EFI_PARTITION_ENTRY         tmp;
	BOOLEAN swapped = TRUE;
	count = GptMainHdr->NumberOfPartitionEntries;

	while (n < count) {
		if (CompareGuid(&GptMainEntrys[n].PartitionTypeGUID, &gEfiPartTypeUnusedGuid)) {
			break;
		}
		++n;
	}

	while (swapped) {
		swapped = FALSE;
		j++;
		for (i = 0; i < n - j; ++i) {
			if (GptMainEntrys[i].StartingLBA > GptMainEntrys[i + 1].StartingLBA) {
				CopyMem(&tmp, &GptMainEntrys[i], sizeof(tmp));
				CopyMem(&GptMainEntrys[i], &GptMainEntrys[i + 1], sizeof(tmp));
				CopyMem(&GptMainEntrys[i + 1], &tmp, sizeof(tmp));
				swapped = TRUE;
			}
		}
	}
}

// Checks if two regions overlap (borders are parts of regions)
BOOLEAN
IsRegionOverlap(UINT64 start1, UINT64 end1, UINT64 start2, UINT64 end2) {
	return (start1 < start2) ? (end1 >= start2) : (start1 <= end2);
}

VOID
GptHideParts() {
	UINTN count;
	UINTN n;
	BOOLEAN set = FALSE;
	count = GptMainHdr->NumberOfPartitionEntries;

	for (n = 0; n < count; ++n) {
		if (CompareGuid(&GptMainEntrys[n].PartitionTypeGUID, &gEfiPartTypeUnusedGuid)) {
			continue;
		}
		if (IsRegionOverlap(
			GptMainEntrys[n].StartingLBA, GptMainEntrys[n].EndingLBA,
			DcsHidePart.StartingLBA, DcsHidePart.EndingLBA)) {
			if (set) {
				SetMem(&GptMainEntrys[n], sizeof(*GptMainEntrys), 0);
			}
			else {
				set = TRUE;
				CopyMem(&GptMainEntrys[n], &DcsHidePart, sizeof(*GptMainEntrys));
			}
		}
	}
	GptSqueze();
	GptSort();
	GptSyncMainAlt();
	if (DeCryptoHeader != NULL) {
		SetMem(DeCryptoHeader, 512, 0);
	}
}

BOOLEAN
GptAskGUID(
	IN     char* prompt,
	IN OUT EFI_GUID* guid)
{
	CHAR8      buf[128];
	UINTN      len = 0;
	EFI_GUID   result;
	BOOLEAN    ok = TRUE;
	OUT_PRINT(L"[%g] %a", guid, prompt);

	// (msr, data, oem, efi, del or guid)
	GetLine(&len, NULL, buf, sizeof(buf), 1);
	if (AsciiStrCmp(buf, "msr") == 0) {
		CopyMem(guid, &gEfiPartTypeMsReservedPartGuid, sizeof(EFI_GUID));
	}
	else if (AsciiStrCmp(buf, "data") == 0) {
		CopyMem(guid, &gEfiPartTypeBasicDataPartGuid, sizeof(EFI_GUID));
	}
	else if (AsciiStrCmp(buf, "wre") == 0) {
		CopyMem(guid, &gEfiPartTypeMsRecoveryPartGuid, sizeof(EFI_GUID));
	}
	else if (AsciiStrCmp(buf, "efi") == 0) {
		CopyMem(guid, &gEfiPartTypeSystemPartGuid, sizeof(EFI_GUID));
	}
	else if (AsciiStrCmp(buf, "del") == 0) {
		CopyMem(guid, &gEfiPartTypeUnusedGuid, sizeof(EFI_GUID));
	}
	else if (len == 0) {
		ok = TRUE;
	}
	else {
		ok = DcsAsciiStrToGuid(&result, buf);
		if (ok) {
			CopyMem(guid, &result, sizeof(result));
		}
	}
	return ok;
}

EFI_STATUS
DeListExecEdit() 
{
	UINTN     len;
	UINTN     i;
	CHAR16    execCmd[FIELD_SIZEOF(DCS_DEP_EXEC, ExecCmd)];
	if (DeExecParams == NULL) {
		DeExecParams = MEM_ALLOC(sizeof(*DeExecParams));
	}
	OUT_PRINT(L"Exec %g, %s\n", &DeExecParams->ExecPartGuid, &DeExecParams->ExecCmd);
	if (GptMainHdr != NULL) {
		for (i = 0; i < GptMainHdr->NumberOfPartitionEntries; ++i) {
			EFI_PARTITION_ENTRY *part;
			part = &GptMainEntrys[i];
			if (CompareMem(&gEfiPartTypeSystemPartGuid, &part->PartitionTypeGUID, sizeof(EFI_GUID)) == 0) {
		if (CompareMem(&DeExecParams->ExecPartGuid, &part->UniquePartitionGUID, sizeof(EFI_GUID)) != 0) {
				OUT_PRINT(L"EFI partition mismatched, updated");
				CopyMem(&DeExecParams->ExecPartGuid, &part->UniquePartitionGUID, sizeof(EFI_GUID));
			}
				break;
			}
		}
	}
	while (!GptAskGUID("\n\r:",(EFI_GUID*) &DeExecParams->ExecPartGuid));
	OUT_PRINT(L"[%s]\n\r:", &DeExecParams->ExecCmd);
	GetLine(&len, execCmd, NULL, sizeof(execCmd) / 2 - 1, 1);
	if (len != 0) {
		CopyMem(&DeExecParams->ExecCmd, execCmd, sizeof(execCmd));
	}
	return EFI_SUCCESS;
}

EFI_STATUS
DeListPwdCacheEdit()
{
	UINTN      count;
	UINTN      len;
	UINTN      i;
	UINT32     crc = 0;
	DePassword pwd;
	UINTN      pim;
	EFI_STATUS res;
	if (DePwdCache == NULL) {
		DePwdCache = MEM_ALLOC(sizeof(*DePwdCache));
		DePwdCache->Sign = DCS_DEP_PWD_CACHE_SIGN;
	}
	OUT_PRINT(L"PwdCache\n");
	do {
		count = (UINT32)AskUINTN("Count[0-4]:", DePwdCache->Count);
	} while (count > 4);
	DePwdCache->Count = (UINT32)count;
	for (i = 0; i < 4; ++i) {
		ZeroMem(&pwd, sizeof(pwd));
		pim = 0;
		if (i < DePwdCache->Count) {
			OUT_PRINT(L"%H%d%N [%a] [%d]\n:", i, DePwdCache->Pwd[i].Text, DePwdCache->Pim[i]);
			GetLine(&len, NULL, pwd.Text, DE_MAX_PASSWORD, 1);
			if (len != 0) {
				pwd.Length = (UINT32)len;
				pim = (UINT32)AskUINTN("Pim:", DePwdCache->Pim[i]);
			}
		}
		DePwdCache->Pim[i] = (UINT32)pim;
		CopyMem(&DePwdCache->Pwd[i], &pwd, sizeof(pwd));
	}
	ZeroMem(&DePwdCache->pad, sizeof(DePwdCache->pad));
	DePwdCache->CRC = 0;
	res =gBS->CalculateCrc32(DePwdCache, 512, &crc);
	DePwdCache->CRC = crc;
	MEM_BURN(&pwd, sizeof(pwd));
	MEM_BURN(&pim, sizeof(pim));
	return res;
}

EFI_STATUS
DeListRndSave()
{
	EFI_STATUS res;
	if (gRnd == NULL) {
		DeRndSaved = NULL;
		return EFI_SUCCESS;
	}
	res = RndSave(gRnd,&DeRndSaved);
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Random: %r\n", res);
		return res;
	}
	OUT_PRINT(L"Rnd selected:%d\n", DeRndSaved->Type);
	return res;
}

EFI_STATUS
DeListRndLoad()
{
	EFI_STATUS res = EFI_NOT_FOUND;
	if (DeRndSaved != NULL) {
		res = RndLoad(DeRndSaved,&gRnd);
		if (EFI_ERROR(res)) {
			ERR_PRINT(L"Random: %r\n", res);
			return res;
		}
		OUT_PRINT(L"Rnd selected:%d\n", gRnd->Type);
	}
	return res;
}

//////////////////////////////////////////////////////////////////////////
// Tables
//////////////////////////////////////////////////////////////////////////

CONST CHAR16*               DcsTablesFileName = L"DcsTables";
UINT8*                      gDcsTables = NULL;
UINTN                       gDcsTablesSize = 0;

BOOLEAN 
TablesList(
	IN UINTN maxSize, 
	IN VOID* tables
	) {
	EFI_TABLE_HEADER *mhdr = (EFI_TABLE_HEADER *)tables;
	if (tables != NULL &&
		mhdr->Signature == EFITABLE_HEADER_SIGN &&
		GptHeaderCheckCrc(maxSize, mhdr)) {
		UINT8* raw = (UINT8*)tables;
		UINTN  rawSize = mhdr->HeaderSize;
		UINTN tpos = sizeof(EFI_TABLE_HEADER);
		while (tpos < rawSize) {
			EFI_TABLE_HEADER *hdr = (EFI_TABLE_HEADER *)(raw + tpos);
			CHAR8            asc_sign[sizeof(hdr->Signature) + 1] = { 0 };
			CopyMem(asc_sign, &hdr->Signature, sizeof(hdr->Signature));
			asc_sign[sizeof(hdr->Signature)] = 0;
			OUT_PRINT(L"%a, SZ=%d", asc_sign, hdr->HeaderSize);
			if (!GptHeaderCheckCrc(rawSize - tpos, hdr)) {
				ERR_PRINT(L" - wrong crc\n");
				return FALSE;	// wrong crc
			}
			OUT_PRINT(L" - OK\n");
			tpos += hdr->HeaderSize;
		}
		return TRUE;
	}
	return FALSE;
}

EFI_STATUS
TablesLoad() {
	EFI_STATUS res = EFI_SUCCESS;
	if (EFI_ERROR(FileExist(NULL, (CHAR16*)DcsTablesFileName))) {
		EFI_TABLE_HEADER* mhdr = NULL;
		UINT32 Crc;
		gDcsTables = MEM_ALLOC(sizeof(EFI_TABLE_HEADER));
		gDcsTablesSize = sizeof(EFI_TABLE_HEADER);
		mhdr = (EFI_TABLE_HEADER*)gDcsTables;
		mhdr->HeaderSize = sizeof(EFI_TABLE_HEADER);
		mhdr->Signature = EFITABLE_HEADER_SIGN;
		mhdr->CRC32 = 0;
		if (EFI_ERROR(res = gBS->CalculateCrc32((UINT8 *)gDcsTables, mhdr->HeaderSize, &Crc))) {
			goto err;
		}
		mhdr->CRC32 = Crc;
		OUT_PRINT(L"New tables created %s\n", DcsTablesFileName);
	}	else {
		res = FileLoad(NULL, (CHAR16*)DcsTablesFileName, &gDcsTables, &gDcsTablesSize);
		if (!EFI_ERROR(res)) {
			res = TablesVerify(gDcsTablesSize, gDcsTables) ? EFI_SUCCESS : EFI_CRC_ERROR;
		}
	}
err:
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Tables load error %r\n", res);
	}
	return res;
}

EFI_STATUS
TablesDump(
	IN CHAR16 *prefix
	) {
	EFI_TABLE_HEADER *mhdr = NULL;
	EFI_STATUS res = EFI_SUCCESS;
	CHAR16            name[128];

	if (gDcsTables == NULL) {
		CE(TablesLoad());
	}

	mhdr = (EFI_TABLE_HEADER *)gDcsTables;
	if (gDcsTables != NULL &&
		mhdr->Signature == EFITABLE_HEADER_SIGN &&
		GptHeaderCheckCrc(gDcsTablesSize, mhdr)) {
		UINT8* raw = (UINT8*)gDcsTables;
		UINTN  rawSize = mhdr->HeaderSize;
		UINTN tpos = sizeof(EFI_TABLE_HEADER);
		while (tpos < rawSize) {
			EFI_TABLE_HEADER *hdr = (EFI_TABLE_HEADER *)(raw + tpos);
			CHAR8            asc_sign[sizeof(hdr->Signature) + 1] = { 0 };
			CopyMem(asc_sign, &hdr->Signature, sizeof(hdr->Signature));
			asc_sign[sizeof(hdr->Signature)] = 0;
			UnicodeSPrint(name, sizeof(name), L"%s%a", prefix, asc_sign);
			OUT_PRINT(L"%s, SZ=%d", name, hdr->HeaderSize);
			if (!GptHeaderCheckCrc(rawSize - tpos, hdr)) {
				ERR_PRINT(L" - wrong crc\n");
				return EFI_CRC_ERROR;	// wrong crc
			}
			CE(FileSave(NULL, name, raw + tpos + sizeof(EFI_TABLE_HEADER), hdr->HeaderSize - sizeof(EFI_TABLE_HEADER)));
			OUT_PRINT(L" - saved\n");
			tpos += hdr->HeaderSize;
		}
		return EFI_SUCCESS;
	}

err:
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Tables load error %r\n", res);
	}
	return res;
}

EFI_STATUS
TablesNew(
	IN CONST CHAR16* signStr, 
	IN CONST CHAR16* dataFileName
	) {
	EFI_STATUS res = EFI_SUCCESS;
	VOID* data;
	UINTN dataSize;
	UINT64 sign;
	EFI_TABLE_HEADER* mhdr;

	if (StrLen(signStr) != 8) {
		res = EFI_INVALID_PARAMETER;
		goto err;
	}
	sign = SIGNATURE_64(signStr[0], signStr[1], signStr[2], signStr[3], signStr[4], signStr[5], signStr[6], signStr[7]);

	CE(TablesLoad());
	TablesDelete(gDcsTables, sign);
	CE(FileLoad(NULL, (CHAR16*)dataFileName, &data, &dataSize));
	if (!TablesAppend(&gDcsTables, sign, data, dataSize)) {
		res = EFI_INVALID_PARAMETER;
		goto err;
	}
	mhdr = (EFI_TABLE_HEADER*)gDcsTables;
	gDcsTablesSize = mhdr->HeaderSize;
	res = FileSave(NULL, (CHAR16*)DcsTablesFileName, mhdr, mhdr->HeaderSize);

err:
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Tables append error %r\n", res);
	}
	return res;
}

EFI_STATUS
TablesDel(
	IN CONST CHAR16* signStr
	) {
	EFI_STATUS res = EFI_SUCCESS;
	UINT64 sign;
	EFI_TABLE_HEADER* mhdr;

	if (StrLen(signStr) != 8) {
		res = EFI_INVALID_PARAMETER;
		goto err;
	}
	sign = SIGNATURE_64(signStr[0], signStr[1], signStr[2], signStr[3], signStr[4], signStr[5], signStr[6], signStr[7]);

	CE(TablesLoad());
	if (!TablesDelete(gDcsTables, sign)) {
		res = EFI_INVALID_PARAMETER;
		goto err;
	}
	mhdr = (EFI_TABLE_HEADER*)gDcsTables;
	gDcsTablesSize = mhdr->HeaderSize;
	res = FileSave(NULL, (CHAR16*)DcsTablesFileName, gDcsTables, gDcsTablesSize);

err:
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Tables delete error %r\n", res);
	}
	return res;
}
