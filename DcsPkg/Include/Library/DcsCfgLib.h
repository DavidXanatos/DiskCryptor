/** @file
DCS configuration

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#ifndef __DCSCFGLIB_H__
#define __DCSCFGLIB_H__

#include <Uefi.h>

#include "CommonLib.h"
#include "../DeListDefines.h"

//////////////////////////////////////////////////////////////////////////
// DeList and GPT
//////////////////////////////////////////////////////////////////////////
#define EFI_PART_TYPE_BASIC_DATA_PART_GUID \
  { \
    0xEBD0A0A2, 0xB9E5, 0x4433, { 0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7 } \
  }

#define EFI_PART_TYPE_MS_RESERVED_PART_GUID \
  { \
    0xE3C9E316, 0x0B5C, 0x4DB8, { 0x81, 0x7D, 0xF9, 0x2D, 0xF0, 0x02, 0x15, 0xAE } \
  }

#define EFI_PART_TYPE_MS_RECOVERY_PART_GUID \
  { \
    0xDE94BBA4, 0x06D1, 0x06D1, { 0xA1, 0x6A, 0xBF, 0xD5, 0x01, 0x79, 0xD6, 0xAC } \
  }

extern EFI_GUID            gEfiPartTypeBasicDataPartGuid;
extern EFI_GUID            gEfiPartTypeMsReservedPartGuid;
extern EFI_GUID            gEfiPartTypeMsRecoveryPartGuid;

extern UINT64              gDcsDiskEntryListHeaderID;

extern DCS_DISK_ENTRY_LIST *DeList;
extern DCS_DEP_EXEC  *DeExecParams;
extern UINT8 *DeCryptoHeader;

// DcsCfg data
extern CONST CHAR16*       DcsDiskEntrysFileName;
extern EFI_PARTITION_ENTRY DcsHidePart;
extern EFI_PARTITION_ENTRY *GptMainEntrys;
extern UINTN               BootPartIdx;
extern UINTN               MirrorPartIdx;

EFI_STATUS
DeListParseSaved(
	IN UINT8 *DeBuffer
	);

EFI_STATUS
DeListLoadFromFile();

EFI_STATUS
DeListZero();

VOID
DeListPrint();

VOID
DeListSaveToFile();

EFI_STATUS
DeListApplySectorsToDisk(
	IN UINTN   diskIdx
	);

EFI_STATUS
DeListExecEdit();

EFI_STATUS
DeListPwdCacheEdit();

EFI_STATUS
DeListRndSave();

EFI_STATUS
DeListRndLoad();

EFI_STATUS
GptLoadFromDisk(
	IN UINTN   diskIdx
	);

VOID
GptHideParts();

VOID
GptSort();

VOID
GptSqueze();

EFI_STATUS
GptSyncMainAlt();

BOOLEAN
GptAskGUID(
	IN     char* prompt,
	IN OUT EFI_GUID* guid
	);

BOOLEAN
IsRegionOverlap(UINT64 start1, UINT64 end1, UINT64 start2, UINT64 end2);

//////////////////////////////////////////////////////////////////////////
// Tables
//////////////////////////////////////////////////////////////////////////
extern CONST CHAR16*               DcsTablesFileName;
extern UINT8*                      gDcsTables;
extern UINTN                       gDcsTablesSize;

EFI_STATUS
TablesDel(
	IN CONST CHAR16* sign
	);

EFI_STATUS
TablesNew(
	IN CONST CHAR16* sign,
	IN CONST CHAR16* dataFileName
	);

EFI_STATUS
TablesLoad();

BOOLEAN
TablesList(
	IN UINTN maxSize,
	IN VOID* tables
	);

EFI_STATUS
TablesDump(
	IN CHAR16 *prefix
	);

//////////////////////////////////////////////////////////////////////////
// Random
//////////////////////////////////////////////////////////////////////////
enum RndGeneratorTypes {
	RndTypeNone = 0,
	RndTypeFile,
	RndTypeRDRand,
	RndTypeDtrmHmacSha512,
	RndTypeOpenSSL,
	RndTypeTpm
};

#define RND_HEADER_SIGN SIGNATURE_64('D','C','S','_','R','A','N','D')

typedef struct _DCS_RND DCS_RND;

typedef
EFI_STATUS
(*DCS_RND_PREPARE)(
	IN OUT DCS_RND   *Rnd
	);

typedef
EFI_STATUS
(*DCS_RND_GET_BYTES)(
	IN     DCS_RND   *Rnd,
	OUT    UINT8     *buf,
	IN     UINTN      len
	);

#pragma pack(1)
/* state of DRBG HMAC SHA512 */
typedef struct _RND_DTRM_HMAC_SHA512_STATE
{
	UINT8 V[64];		/* internal state 10.1.1.1 1a) */
	UINT8 C[64];		/* hmac key */
	UINT64 ReseedCtr;	/* Number of RNG requests since last reseed --* 10.1.1.1 1c)*/
} RND_DTRM_HMAC_SHA512_STATE;

typedef struct _RND_FILE_STATE
{
	CHAR16 *FileName;
	UINT8  *Data;
	UINTN  Size;
	UINTN  Pos;
} RND_FILE_STATE;

typedef union _DCS_RND_STATE {
	RND_DTRM_HMAC_SHA512_STATE HMacSha512;
	RND_FILE_STATE             File;
} DCS_RND_STATE;

typedef struct _DCS_RND_SAVED {
	UINT64			Sign;
	UINT32			CRC;
	UINT32			Size;
	UINT32			Type;
	UINT32			Pad;
	EFI_TIME			SavedAt;
	DCS_RND_STATE	State;
	UINT8          pad[512 - 8 - 4 - 4 - 4 - 4 - sizeof(EFI_TIME) - sizeof(DCS_RND_STATE)];
} DCS_RND_SAVED;
#pragma pack()
CSTATIC_ASSERT(sizeof(DCS_RND_SAVED) == 512, Wrong_size_DCS_RND_SAVED);

typedef struct _DCS_RND {
	DCS_RND_PREPARE    Prepare;
	DCS_RND_GET_BYTES  GetBytes;
	UINT32				Type;
	UINT32				Pad;
	DCS_RND_STATE		State;
} DCS_RND;

EFI_STATUS
RndInit(
	IN UINTN   rndType,
	IN VOID*   Context,
	IN UINTN   ContextSize,
	OUT DCS_RND **rnd);

// Serialize rnd with state to/from memory
EFI_STATUS
RndLoad(
	IN DCS_RND_SAVED *rndSaved,
	OUT DCS_RND      **rndOut
	);

EFI_STATUS
RndSave(
	DCS_RND         *rnd,
	DCS_RND_SAVED  **rndSaved);

// Global RND
extern DCS_RND* gRnd;

EFI_STATUS
RndGetBytes(UINT8 *buf, UINTN len);

EFI_STATUS
RndPrepare();

#endif

