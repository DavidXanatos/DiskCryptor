/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2008-2010
    * ntldr <ntldr@diskcryptor.net> PGP key ID - 0xC48251EB4F8E4E6E
    *

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 3 as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <ntifs.h>
#include <ntstrsafe.h>
#include "defines.h"
#include "devhook.h"
#include "misc.h"
#include "debug.h"
#include "storage.h"
#include "misc_mem.h"
#include "device_io.h"

#pragma pack (push, 1)

typedef struct _fat_bpb {
	s8	ignored[3];	/* Boot strap short or near jump */
	s8	system_id[8];	/* Name - can be used to special case
				   partition manager volumes */
	u8	bytes_per_sect[2];	/* bytes per logical sector */
	u8	sects_per_clust;/* sectors/cluster */
	u16	reserved_sects;	/* reserved sectors */
	u8	num_fats;	/* number of FATs */
	u16	dir_entries;	/* root directory entries */
	u8	short_sectors[2];	/* number of sectors */
	u8	media;		/* media code (unused) */
	u16	fat_length;	/* sectors/FAT */
	u16	secs_track;	/* sectors per track */
	u16	heads;		/* number of heads */
	u32	hidden;		/* hidden sectors (unused) */
	u32	long_sectors;	/* number of sectors (if short_sectors == 0) */

	/* The following fields are only used by FAT32 */
	u32	fat32_length;	/* sectors/FAT */
	u16	flags;		   /* bit 8: fat mirroring, low 4: active fat */
	u8	version[2];	   /* major, minor filesystem version */
	u32	root_cluster;	/* first cluster in root directory */
	u16	info_sector;	/* filesystem info sector */
	u16	backup_boot;	/* backup boot sector */
	u16	reserved2[6];	/* Unused */

} fat_bpb;

typedef struct exfat_bpb {
	u8	jmp_boot[3];	     /* boot strap short or near jump */
	u8	oem_id[8];		     /* oem-id */
	u8	unused0;		     /* 0x00... */
	u32	unused1[13];
	u64	start_sector;		 /* start sector of partition */
	u64	nr_sectors;		     /* number of sectors of partition */
	u32	fat_blocknr;		 /* start blocknr of FAT */
	u32	fat_block_counts;	 /* number of FAT blocks */
	u32	clus_blocknr;		 /* start blocknr of cluster */
	u32	total_clusters;		 /* number of total clusters */
	u32	rootdir_clusnr;		 /* start clusnr of rootdir */
	u32	serial_number;		 /* volume serial number */
	u8	xxxx01;			     /* ??? (0x00 or any value (?)) */
	u8	xxxx02;			     /* ??? (0x01 or 0x00 (?)) */
	u16	state;			     /* state of this volume */
	u8	blocksize_bits;		 /* bits of block size */
	u8	block_per_clus_bits; /* bits of blocks per cluster */
	u8	xxxx03;			     /* ??? (0x01 or 0x00 (?)) */
	u8	xxxx04;			     /* ??? (0x80 or any value (?)) */
	u8	allocated_percent;	 /* percentage of allocated space (?) */
	u8	xxxx05[397];		 /* ??? (0x00...) */
	u16	signature;		     /* 0xaa55 */

} exfat_bpb; 

#pragma pack (pop)

#define FAT_DIRENTRY_LENGTH 32
#define MAX_RETRY           128

static int dc_fill_dcsys(HANDLE h_file)
{
	FILE_FS_SIZE_INFORMATION info;
	IO_STATUS_BLOCK          iosb;
	NTSTATUS                 status;
	u32                      length;
	void                    *buff;
	u64                      state = COMPRESSION_FORMAT_NONE;

	status = ZwQueryVolumeInformationFile(
		h_file, &iosb, &info, sizeof(info), FileFsSizeInformation);

	if (NT_SUCCESS(status) == FALSE) {
		return 0;
	} else {
		length = max(info.SectorsPerAllocationUnit * info.BytesPerSector, sizeof(dc_header));
	}
	if ( (buff = mm_pool_alloc(length)) == NULL )
	{
		return 0;
	}
	memset(buff, 0, length);
	
	ZwFsControlFile(h_file, NULL, NULL, NULL, &iosb, FSCTL_SET_COMPRESSION, &state, sizeof(state), NULL, 0);
	status = ZwWriteFile(h_file, NULL, NULL, NULL, &iosb, buff, length, NULL, NULL);

	mm_pool_free(buff);
	return NT_SUCCESS(status) != FALSE;
}

static void dc_delete_file(HANDLE h_file)
{
	FILE_BASIC_INFORMATION       binf = { {0}, {0}, {0}, {0}, FILE_ATTRIBUTE_NORMAL };
	FILE_DISPOSITION_INFORMATION dinf = { TRUE };
	IO_STATUS_BLOCK              iosb;
	
	ZwSetInformationFile(h_file, &iosb, &binf, sizeof(binf), FileBasicInformation);
	ZwSetInformationFile(h_file, &iosb, &dinf, sizeof(dinf), FileDispositionInformation);
}

static void dc_rename_file(HANDLE h_file)
{
	char                     buff[sizeof(FILE_RENAME_INFORMATION) + 64];
	PFILE_RENAME_INFORMATION info = pv(buff);
	IO_STATUS_BLOCK          iosb;
	
	info->ReplaceIfExists = TRUE;
	info->RootDirectory   = NULL;
	RtlStringCchPrintfW(info->FileName, 32, L"$dcsys$_fail_%x", __rdtsc());
	info->FileNameLength = wcslen(info->FileName) * sizeof(wchar_t);

	ZwSetInformationFile(h_file, &iosb, info, sizeof(buff), FileRenameInformation);
}

static HANDLE dc_create_dcsys(dev_hook *hook, int is_open)
{
	OBJECT_ATTRIBUTES obj_a;
	UNICODE_STRING    u_name;	
	IO_STATUS_BLOCK   iosb;
	wchar_t           buff[MAX_PATH];
	HANDLE            h_file;
	NTSTATUS          status;
	
	status = RtlStringCchPrintfW(buff, MAX_PATH, L"%s\\$dcsys$", hook->dev_name);
	if (NT_SUCCESS(status) == FALSE) return NULL;

	RtlInitUnicodeString(&u_name, buff);
	InitializeObjectAttributes(&obj_a, &u_name, OBJ_KERNEL_HANDLE, NULL, NULL);

	status = ZwCreateFile(&h_file, (is_open != 0 ? FILE_WRITE_ATTRIBUTES | DELETE : GENERIC_WRITE), 
		&obj_a, &iosb, NULL, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_READONLY, 0, 
		(is_open != 0 ? FILE_OPEN : FILE_CREATE), 
		FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE | FILE_WRITE_THROUGH, NULL, 0);

	if (NT_SUCCESS(status) == FALSE) {
		return NULL;
	}
	if ( (is_open == 0) && (dc_fill_dcsys(h_file) == 0) ) {
		dc_delete_file(h_file);
		ZwClose(h_file); h_file = NULL;
	}
	return h_file;
}

static int dc_num_fragments(HANDLE h_file, u64 *cluster)
{
	char                       buff[sizeof(RETRIEVAL_POINTERS_BUFFER) + 16*4];
	STARTING_VCN_INPUT_BUFFER  svcn = {0};
	RETRIEVAL_POINTERS_BUFFER *prpb = pv(buff);
	IO_STATUS_BLOCK            iosb;
	NTSTATUS                   status;
	
	status = ZwFsControlFile(
		h_file, NULL, NULL, NULL, &iosb, FSCTL_GET_RETRIEVAL_POINTERS, &svcn, sizeof(svcn), prpb, sizeof(buff));

	if (NT_SUCCESS(status) != FALSE) {
		cluster[0] = prpb->Extents[0].Lcn.QuadPart; 
		return prpb->ExtentCount;
	}
	return 0;
}

static int dc_first_cluster_offset(HANDLE h_dev, u32 bps, u64 *offset)
{
	u8                             buff[sizeof(FILE_FS_ATTRIBUTE_INFORMATION) + 0x20];
	PFILE_FS_ATTRIBUTE_INFORMATION ainf = pv(buff);
	LARGE_INTEGER                  vofs = {0};
	IO_STATUS_BLOCK                iosb;
	void                          *head;
	int                            resl;
	
	if (NT_SUCCESS(ZwQueryVolumeInformationFile(
		           h_dev, &iosb, ainf, sizeof(buff), FileFsAttributeInformation)) == FALSE) 
	{
		return ST_ERROR;
	} else {
		ainf->FileSystemName[ainf->FileSystemNameLength >> 1] = 0;
	}
	if (_wcsicmp(ainf->FileSystemName, L"NTFS") == 0) {
		*offset = 0; return ST_OK;
	}
	if ( (head = mm_pool_alloc(bps)) == NULL ) {
		return ST_NOMEM;
	}
	if (NT_SUCCESS(ZwReadFile(h_dev, NULL, NULL, NULL, &iosb, head, bps, &vofs, NULL)) == FALSE) {
		mm_pool_free(head); return ST_RW_ERR;
	}
	if ( (_wcsicmp(ainf->FileSystemName, L"FAT") == 0) || (_wcsicmp(ainf->FileSystemName, L"FAT32") == 0) )
	{
		fat_bpb *bpb = head;
		u32      fat_offset = bpb->reserved_sects;
		u32      fat_length = bpb->fat_length ? bpb->fat_length : bpb->fat32_length;
		u32      root_offs  = fat_offset + (bpb->num_fats * fat_length);
		u32      root_max, data_offs;

		if (root_max = bpb->dir_entries * FAT_DIRENTRY_LENGTH) {
			data_offs = root_offs + ((root_max - 1) / bps) + 1;
		} else {
			data_offs = root_offs;
		}
		*offset = data_offs; resl = ST_OK;
	} else if (_wcsicmp(ainf->FileSystemName, L"exFAT") == 0) {
		exfat_bpb *bpb = head; *offset = bpb->clus_blocknr; 
		resl = ST_OK;
	} else {
		resl = ST_UNK_FS;
	}
	mm_pool_free(head); return resl;
}

static int dc_cluster_to_offset(dev_hook *hook, HANDLE h_file, u64 cluster, u64 *offset)
{
	FILE_FS_SIZE_INFORMATION sinf;
	IO_STATUS_BLOCK          iosb;
	NTSTATUS                 status;
	int                      resl;
	RETRIEVAL_POINTER_BASE   base;
	HANDLE                   h_dev;
	
	if (NT_SUCCESS(ZwQueryVolumeInformationFile(
		           h_file, &iosb, &sinf, sizeof(sinf), FileFsSizeInformation)) == FALSE)
	{
		return ST_ERROR;
	}
	if ( (h_dev = io_open_device(hook->dev_name)) == NULL ) {
		return ST_IO_ERROR;
	}
	status = ZwFsControlFile(
		h_dev, NULL, NULL, NULL, &iosb, FSCTL_GET_RETRIEVAL_POINTER_BASE, NULL, 0, &base, sizeof(base));

	if (NT_SUCCESS(status) == FALSE) {
		resl = dc_first_cluster_offset(h_dev, sinf.BytesPerSector, &base.FileAreaOffset.QuadPart);
	} else {
		resl = ST_OK;
	}
	if (resl == ST_OK) 
	{
		*offset = (base.FileAreaOffset.QuadPart * d64(sinf.BytesPerSector)) + 
			      (cluster * d64(sinf.SectorsPerAllocationUnit) * d64(sinf.BytesPerSector));
	}	
	ZwClose(h_dev); return resl;
}

int dc_create_storage(dev_hook *hook, u64 *storage)
{
	HANDLE h_files[MAX_RETRY];
	u32    n_files = 0;
	HANDLE h_file  = NULL;
	u64    cluster;
	int    i, resl;

	/* delete old storage first */
	dc_delete_storage(hook);
	
	/* try to create continuous $dcsys$ file */
	for (i = 0; (i < MAX_RETRY) && (h_file == NULL); i++)
	{
		if ( (h_file = dc_create_dcsys(hook, 0)) == NULL ) {
			continue;
		}
		if (dc_num_fragments(h_file, &cluster) != 1) {
			dc_rename_file(h_file);
			dc_delete_file(h_file);
			h_files[n_files++] = h_file; h_file = NULL;			
		}
	}
	/* close all fail handles */
	while (n_files != 0) {
		ZwClose(h_files[--n_files]);
	}
	if (h_file == NULL) {
		return ST_CLUS_USED;
	}
	DbgMsg("$dcsys$ created, cluster %x:%0.8x\n", d32(cluster >> 32), d32(cluster));

	if ( (resl = dc_cluster_to_offset(hook, h_file, cluster, storage)) != ST_OK ) {
		dc_delete_file(h_file);
	} else {
		DbgMsg("offset: %x:%0.8x\n", d32(*storage >> 32), d32(*storage));
	}
	ZwClose(h_file); return resl;
}

void dc_delete_storage(dev_hook *hook)
{
	HANDLE h_file;

	if (h_file = dc_create_dcsys(hook, 1)) {
		dc_delete_file(h_file);
		ZwClose(h_file);
	}
}