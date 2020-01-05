/*
    *
    * DiskCryptor - open source partition encryption tool
	* Copyright (c) 2009
	* ntldr <ntldr@diskcryptor.net> PGP key ID - 0xC48251EB4F8E4E6E
    * Lynn McGuire
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

#include <windows.h>
#include <aclapi.h>
#include <ntddscsi.h>
#include <stdio.h>
#include "drv_ioctl.h"
#include "misc.h"
#include "disk_name.h"

#pragma pack(push, 1)

#define IDENTIFY_BUFFER_SIZE  512

#define DFP_GET_VERSION          0x00074080
#define DFP_SEND_DRIVE_COMMAND   0x0007c084
#define DFP_RECEIVE_DRIVE_DATA   0x0007c088

typedef struct _GETVERSIONOUTPARAMS
{
   BYTE bVersion;      // Binary driver version.
   BYTE bRevision;     // Binary driver revision.
   BYTE bReserved;     // Not used.
   BYTE bIDEDeviceMap; // Bit map of IDE devices.
   DWORD fCapabilities; // Bit mask of driver capabilities.
   DWORD dwReserved[4]; // For future use.
} GETVERSIONOUTPARAMS, *PGETVERSIONOUTPARAMS, *LPGETVERSIONOUTPARAMS;

#define IDE_ATAPI_IDENTIFY  0xA1  //  Returns ID sector for ATAPI.
#define IDE_ATA_IDENTIFY    0xEC  //  Returns ID sector for ATA.

#pragma pack(pop)

static void id_sector_to_name(char *name, char *id_s)
{
	int i, j;

	for (j = 0, i = 27 * 2; i <= 46 * 2; i += 2) {
		name[j++] = id_s[i+1]; name[j++] = id_s[i];
	}
	
	name[j] = 0;

	for (i = j - 1; i > 0 && name[i] == ' '; i--) {
		name[i] = 0;
	}
}

static size_t code_bytes(char *str, int pos, char *buf)
{
   int  i;
   int  j = 0;
   int  k = 0;
   char p = 0;

   buf[0] = 0;   
   
   if (pos <= 0) { return 0; }

   // First try to gather all characters representing hex digits only.
   j = 1; k = 0; buf[k] = 0;

   for (i = pos; j && str[i] != '\0'; ++i) 
   {
	   char c = tolower(str[i]);

	   if (isspace(c) != 0) {
		   c = '0';
	   }

	   ++p; buf[k] <<= 4;

	   if (c >= '0' && c <= '9') {
		   buf[k] |= d8(c - '0');
	   } else if (c >= 'a' && c <= 'f') {
		   buf[k] |= d8(c - 'a' + 10);
	   } else { j = 0; break; }

	   if (p == 2)
	   {
		   if (buf[k] <= 0 || !isprint(buf[k])) {
			   j = 0; break; 
		   }

		   ++k; p = 0; buf[k] = 0;
	   }
   }

   if (j == 0)
   {
	   // There are non-digit characters, gather them as is.
	   j = 1; k = 0;

	   for (i = pos; j && str[i] != '\0'; ++i)
	   {
		   char c = str[i];

		   if (isprint(c) == 0) {
			   j = 0; break;
		   }

		   buf[k++] = c;
	   }
   }

   if (j == 0) {      
      k = 0; // The characters are not there or are not printable.
   }

   buf[k] = '\0';

   // Trim any beginning and end space
   i = j = -1;
   for (k = 0; buf[k] != '\0'; ++k)
   {
	   if (isspace(buf[k]) == 0) {
		   if (i < 0) i = k;
		   j = k;
	   }
   }

   if ( (i >= 0) && (j >= 0) )
   {
	   for (k = i; (k <= j) && (buf[k] != '\0'); ++k) {
		   buf[k - i] = buf[k];
	   }
	   
	   buf[k - i] = '\0';
   }

   return strlen(buf);
}

static int get_hdd_name_sqery(HANDLE hdisk, char *name)
{
	 STORAGE_PROPERTY_QUERY     query;
	 u8                         buff[2048];
	 STORAGE_DEVICE_DESCRIPTOR *desc = pv(buff);
	 u32                        bytes;
	 int                        succs;
	 char                      *pn;
	 
	 memset(&query, 0, sizeof(query));
	 memset(&buff, 0, sizeof(buff));

	 query.PropertyId = StorageDeviceProperty;
	 query.QueryType  = PropertyStandardQuery;

	 succs = DeviceIoControl(
		 hdisk, IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query), buff, sizeof(buff), &bytes, NULL
		 );

	 if (succs == 0) {
		 return ST_ERROR;
	 }

	 name[0] = 0; pn = name;

	 if (desc->VendorIdOffset != 0) {
		 pn += code_bytes(buff, desc->VendorIdOffset, pn);
	 }

	 if (desc->ProductIdOffset != 0) {
		 if (pn != name) { *pn++ = ' '; }
		 pn += code_bytes(buff, desc->ProductIdOffset, pn);
	 }

	 return (name[0] != 0) ? ST_OK : ST_ERROR;
}

static int get_hdd_name_ata(HANDLE hdisk, int dsk_num, char *name)
{
	GETVERSIONOUTPARAMS verp;
	SENDCMDINPARAMS     scip;
	u32                 bytes;
	int                 succs, resl;
	u8                  id_cmd;
	u8                  buff[sizeof(SENDCMDOUTPARAMS) + IDENTIFY_BUFFER_SIZE];
	PSENDCMDOUTPARAMS   id_out = pv(buff);

	do
	{
		succs = DeviceIoControl(
			hdisk, DFP_GET_VERSION, NULL, 0, &verp, sizeof(verp), &bytes, NULL);

		if ( (succs == 0) || (verp.bIDEDeviceMap == 0) ) {
			resl = ST_ERROR; break;
		}

		id_cmd = (verp.bIDEDeviceMap >> dsk_num & 0x10) ? IDE_ATAPI_IDENTIFY : IDE_ATA_IDENTIFY;
		memset(&scip, 0, sizeof(scip));
        memset(buff, 0, sizeof(buff));

		scip.cBufferSize = IDENTIFY_BUFFER_SIZE;
		scip.irDriveRegs.bSectorCountReg  = 1;
		scip.irDriveRegs.bSectorNumberReg = 1;
		scip.irDriveRegs.bDriveHeadReg = 0xA0 | ((dsk_num & 1) << 4);
		scip.irDriveRegs.bCommandReg   = id_cmd;
		scip.bDriveNumber = dsk_num;
		scip.cBufferSize  = IDENTIFY_BUFFER_SIZE;

		succs = DeviceIoControl(
			hdisk, DFP_RECEIVE_DRIVE_DATA, &scip, sizeof(scip),	id_out, sizeof(buff), &bytes, NULL);

		if (succs == 0) {
			resl = ST_ERROR; break;
		}
		id_sector_to_name(name, id_out->bBuffer); resl = ST_OK;
	} while (0);

	return resl;
}

int dc_get_hw_name(int dsk_num, int is_cd, wchar_t *name, size_t max_name)
{
	dc_disk_p *dp;
	char       c_name[MAX_PATH];
	int        resl;

	do
	{
		if ( (dp = dc_disk_open(dsk_num, is_cd)) == NULL ) {
			resl = ST_ACCESS_DENIED; break;
		}

		if ( (get_hdd_name_sqery(dp->hdisk, c_name) != ST_OK) &&
			 ( (is_cd != 0) || (get_hdd_name_ata(dp->hdisk, dsk_num, c_name) != ST_OK) ) )
		{
			if (is_cd == 0)
			{
				if (dp->media == RemovableMedia) {
					_snwprintf(name, max_name, L"Removable Medium %d", dsk_num);
				} else {
					_snwprintf(name, max_name, L"Hard disk %d", dsk_num);
				}
			} else {
				_snwprintf(name, max_name, L"Optical drive %d", dsk_num);
			}
		} else {
			mbstowcs(name, c_name, max_name);			
		}
		resl = ST_OK;
	} while (0);

	if (dp != NULL) {
		dc_disk_close(dp);
	}

	return resl;
}
