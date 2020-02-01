/** @file
DCS configuration

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the [to be defined License, Version]. The full text of the license may be found at
[opensource license  to be defined]
**/

#ifndef __DCSCFGDEFS_H__
#define __DCSCFGDEFS_H__

#ifdef _UEFI
#include <Uefi.h>
#endif

#define DCS_DISK_ENTRY_LIST_HEADER_SIGN      SIGNATURE_64 ('D','C','S','D','E','L','S','T')

#ifndef CSTATIC_ASSERT
#define CSTATIC_ASSERT(b, name) typedef int StaticAssertFailed##name[b ? 1 : -1];
#endif

#define DE_IDX_CRYPTOHEADER  0
#define DE_IDX_LIST          1
#define DE_IDX_DISKID        2
#define DE_IDX_MAINGPTHDR    3
#define DE_IDX_MAINGPTENTRYS 4
#define DE_IDX_ALTGPTHDR     5
#define DE_IDX_ALTGPTENTRYS  6
#define DE_IDX_EXEC          7
#define DE_IDX_PWDCACHE      8
#define DE_IDX_RND           9
#define DE_IDX_TOTAL         10
CSTATIC_ASSERT(DE_IDX_TOTAL <= 15, DE_IDX_TOTAL_too_big);

enum DcsDiskEntryTypes {
	DE_Unused = 0,
	DE_Sectors,
	DE_List,
	DE_DISKID,
	DE_ExecParams,
	DE_PwdCache,
	DE_Rnd
};

#pragma pack(1)
typedef struct _SECREGION_BOOT_PARAMS {
	UINT64               Ptr;
	UINT32               Size;
	UINT32               Crc;
} SECREGION_BOOT_PARAMS;

typedef struct {
	UINT32  Data1;
	UINT16  Data2;
	UINT16  Data3;
	UINT8   Data4[8];
} DCS_GUID;

// DE types
typedef struct _DCS_DISK_ENTRY_SECTORS {
	UINT32      Type;
	UINT32      Offset; // Offset in memory
	UINT64      Reserved;
	UINT64      Start;  // Start on disk (byte)
	UINT64      Length; // length on disk (byte)
} DCS_DISK_ENTRY_SECTORS;
CSTATIC_ASSERT(sizeof(DCS_DISK_ENTRY_SECTORS) ==	32, Wrong_size_DCS_DISK_ENTRY_SECTORS);

typedef struct _DCS_DISK_ENTRY_PARAMS {
	UINT32      Type;
	UINT32      Offset;
	UINT64      Reserved[2];
	UINT64      Length;           // size of data
} DCS_DISK_ENTRY_PARAMS;
CSTATIC_ASSERT(sizeof(DCS_DISK_ENTRY_PARAMS) == 32, Wrong_size_DCS_DISK_ENTRY_PARAMS);

typedef struct _DCS_DISK_ENTRY_DISKID {
	UINT32      Type;
	UINT32      MbrID;
	UINT64      ReservedDiskId;
	DCS_GUID    GptID;
} DCS_DISK_ENTRY_DISKID;
CSTATIC_ASSERT(sizeof(DCS_DISK_ENTRY_DISKID) == 32, Wrong_size_DCS_DISK_ENTRY_DISKID);

#pragma warning(disable:4201)
typedef struct _DCS_DISK_ENTRY {
	union {
		struct {
			UINT32      Type;
			UINT32      Offset;
			UINT8       reserved[16];
			UINT64      Length;           // size of structure at Offset
		};
		DCS_DISK_ENTRY_SECTORS Sectors;
		DCS_DISK_ENTRY_DISKID  DiskId;
		DCS_DISK_ENTRY_PARAMS  Prm;
	};
} DCS_DISK_ENTRY;
#pragma warning(default:4201)
CSTATIC_ASSERT(sizeof(DCS_DISK_ENTRY) == 32, Wrong_size_DCS_DISK_ENTRY);

// Static compile time checks field offsets
#ifndef FIELD_OFFSET
#define FIELD_OFFSET(t, f) ((UINTN)(&((t*)0)->f))
#endif
CSTATIC_ASSERT(FIELD_OFFSET(DCS_DISK_ENTRY, Type)   == FIELD_OFFSET(DCS_DISK_ENTRY_SECTORS, Type),   Wrong_Type_offset);
CSTATIC_ASSERT(FIELD_OFFSET(DCS_DISK_ENTRY, Type)   == FIELD_OFFSET(DCS_DISK_ENTRY_DISKID,  Type),   Wrong_Type_offset);
CSTATIC_ASSERT(FIELD_OFFSET(DCS_DISK_ENTRY, Type)   == FIELD_OFFSET(DCS_DISK_ENTRY_PARAMS,  Type),   Wrong_Type_offset);
CSTATIC_ASSERT(FIELD_OFFSET(DCS_DISK_ENTRY, Length) == FIELD_OFFSET(DCS_DISK_ENTRY_SECTORS, Length), Wrong_Length_offset);
CSTATIC_ASSERT(FIELD_OFFSET(DCS_DISK_ENTRY, Length) == FIELD_OFFSET(DCS_DISK_ENTRY_PARAMS,  Length), Wrong_Length_offset);
CSTATIC_ASSERT(FIELD_OFFSET(DCS_DISK_ENTRY, Offset) == FIELD_OFFSET(DCS_DISK_ENTRY_SECTORS, Offset), Wrong_Offset_offset);
CSTATIC_ASSERT(FIELD_OFFSET(DCS_DISK_ENTRY, Offset) == FIELD_OFFSET(DCS_DISK_ENTRY_PARAMS,  Offset), Wrong_Offset_offset);

// DE type specific data 
// DE List
typedef struct _DCS_DISK_ENTRY_LIST {
	//	EFI_TABLE_HEADER
	UINT64  Signature;
	UINT32  Revision;
	UINT32  HeaderSize;	//< The size, in bytes, of the entire table including the EFI_TABLE_HEADER.
	UINT32  CRC32;       //< The 32-bit CRC for the entire table. This value is computed by setting this field to 0, and computing the 32-bit CRC for HeaderSize bytes.
	UINT32  Reserved; 	//< Reserved field that must be set to 0.
								//
	UINT32  Count;
	UINT32  DataSize;
	//
	DCS_DISK_ENTRY  DE[15];
} DCS_DISK_ENTRY_LIST;
CSTATIC_ASSERT(sizeof(DCS_DISK_ENTRY_LIST) == 512, Wrong_size_DCS_DISK_ENTRY_LIST);

typedef struct _DCS_DEP_EXEC {
	DCS_GUID     ExecPartGuid;
	UINT16       ExecCmd[248];
} DCS_DEP_EXEC;
CSTATIC_ASSERT(sizeof(DCS_DEP_EXEC) == 512, Wrong_size_DCS_DEP_EXEC);

#define DE_MAX_PASSWORD			64		// Maximum possible password length

typedef struct
{
	// Modifying this structure can introduce incompatibility with previous versions
	unsigned __int32 Length;
	unsigned char Text[DE_MAX_PASSWORD + 1];
	char Pad[3]; // keep 64-bit alignment
} DePassword;

#define DCS_DEP_PWD_CACHE_SIGN      SIGNATURE_64 ('P','W','D','C','A','C','H','E')
typedef struct _DCS_DEP_PWD_CACHE {
	UINT64       Sign;
	UINT32       CRC;
	UINT32       Count;
	DePassword   Pwd[4];
	INT32        Pim[4];
	UINT8        pad[512 - 8 - 4 - 4 - (sizeof(DePassword) + 4) * 4];
} DCS_DEP_PWD_CACHE;
CSTATIC_ASSERT(sizeof(DCS_DEP_PWD_CACHE) == 512, Wrong_size_DCS_DEP_PWD_CACHE);
#pragma pack()


#endif

