/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2025
    * 
    * TPM 2.0 User-Mode API Header

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

#ifndef _DC_TPM_API_H_
#define _DC_TPM_API_H_

#include <windows.h>

/* TPM Blob Constants */
#define DC_TPM_BLOB_MAGIC         0x544D5044   /* 'DPMT' */
#define DC_TPM_BLOB_VERSION       1
#define DC_TPM_MAX_SEALED_SIZE    512

/* TPM Authentication Modes */
#define DC_TPM_AUTH_NONE          0   /* TPM only */
#define DC_TPM_AUTH_PASSWORD      1   /* TPM + Password */
#define DC_TPM_AUTH_PIN           2   /* TPM + PIN */

/* PCR Selection Masks */
#define DC_TPM_PCR_BIOS           (1 << 0)
#define DC_TPM_PCR_BIOS_CFG       (1 << 1)
#define DC_TPM_PCR_OPTION_ROM     (1 << 2)
#define DC_TPM_PCR_MBR            (1 << 4)
#define DC_TPM_PCR_DEFAULT        (DC_TPM_PCR_BIOS | DC_TPM_PCR_BIOS_CFG | \
                                   DC_TPM_PCR_OPTION_ROM | DC_TPM_PCR_MBR)

/* TPM Information Structure */
typedef struct _dc_tpm_info {
    int   present;
    int   enabled;
    int   version_major;
    int   version_minor;
    UINT32 pcr_mask_available;
    int   owner_set;
    int   nv_available;
} dc_tpm_info;

/* Sealed Data Blob */
#pragma pack(push, 1)
typedef struct _dc_tpm_blob {
    UINT32 magic;
    UINT32 version;
    UINT32 auth_mode;
    UINT32 pcr_mask;
    UINT32 sealed_size;
    BYTE   sealed_data[DC_TPM_MAX_SEALED_SIZE];
} dc_tpm_blob;
#pragma pack(pop)

/*
 * Initialize TPM API
 * Returns: ST_OK on success
 */
int dc_tpm_init(void);

/*
 * Cleanup TPM API
 */
void dc_tpm_cleanup(void);

/*
 * Check if TPM 2.0 is available
 * info: Optional output for TPM details
 * Returns: ST_OK if available
 */
int dc_tpm_is_available(dc_tpm_info *info);

/*
 * Read PCR digest
 * pcr_mask: Bitmask of PCRs to read
 * pcr_digest: Output buffer (32 bytes for SHA256)
 * Returns: ST_OK on success
 */
int dc_tpm_read_pcrs(UINT32 pcr_mask, BYTE *pcr_digest);

/*
 * Seal data with TPM
 * data: Data to seal
 * data_size: Size of data
 * password: Optional password for hybrid mode
 * pcr_mask: PCRs to bind to
 * blob: Output sealed blob
 * Returns: ST_OK on success
 */
int dc_tpm_seal(
    const BYTE *data,
    UINT32 data_size,
    const wchar_t *password,
    UINT32 pcr_mask,
    dc_tpm_blob *blob
);

/*
 * Unseal data from TPM
 * blob: Sealed blob
 * password: Password if required
 * data: Output buffer
 * data_size: In: buffer size, Out: data size
 * Returns: ST_OK on success, ST_PASS_ERR on PCR mismatch
 */
int dc_tpm_unseal(
    const dc_tpm_blob *blob,
    const wchar_t *password,
    BYTE *data,
    UINT32 *data_size
);

#endif /* _DC_TPM_API_H_ */


