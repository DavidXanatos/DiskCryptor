/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2025
    * 
    * TPM 2.0 Key Sealing Interface
    *
    * This module provides TPM 2.0 integration for secure key storage.
    * Keys are sealed to specific PCR values, binding encryption to
    * the platform configuration.

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

#ifndef _TPM_SEAL_H_
#define _TPM_SEAL_H_

#include "defines.h"
#include "volume_header.h"

/* TPM Status codes */
#define TPM_OK                    0
#define TPM_ERR_NOT_PRESENT       1  /* No TPM found */
#define TPM_ERR_VERSION           2  /* TPM version not supported (need 2.0) */
#define TPM_ERR_INIT_FAILED       3  /* Failed to initialize TPM */
#define TPM_ERR_SEAL_FAILED       4  /* Failed to seal data */
#define TPM_ERR_UNSEAL_FAILED     5  /* Failed to unseal data (PCR mismatch) */
#define TPM_ERR_PCR_MISMATCH      6  /* PCR values don't match sealed values */
#define TPM_ERR_NV_FAILED         7  /* NV storage operation failed */
#define TPM_ERR_AUTH_FAILED       8  /* Authentication failed */
#define TPM_ERR_NOMEM             9  /* Out of memory */
#define TPM_ERR_INVALID_PARAM     10 /* Invalid parameter */
#define TPM_ERR_LOCKED            11 /* TPM is locked */
#define TPM_ERR_DISABLED          12 /* TPM is disabled */

/* TPM Authentication modes */
#define TPM_AUTH_NONE             0  /* TPM only (no password required) */
#define TPM_AUTH_PASSWORD         1  /* TPM + Password hybrid */
#define TPM_AUTH_PIN              2  /* TPM + PIN */

/* PCR Selection - which PCRs to bind to */
#define TPM_PCR_BIOS              (1 << 0)   /* PCR 0: BIOS */
#define TPM_PCR_BIOS_CONFIG       (1 << 1)   /* PCR 1: BIOS config */
#define TPM_PCR_OPTION_ROM        (1 << 2)   /* PCR 2: Option ROMs */
#define TPM_PCR_OPTION_ROM_CFG    (1 << 3)   /* PCR 3: Option ROM config */
#define TPM_PCR_MBR               (1 << 4)   /* PCR 4: MBR/Boot loader */
#define TPM_PCR_MBR_CONFIG        (1 << 5)   /* PCR 5: MBR config */
#define TPM_PCR_STATE_TRANS       (1 << 6)   /* PCR 6: State transitions */
#define TPM_PCR_MANUFACTURER      (1 << 7)   /* PCR 7: Manufacturer control */

/* Default PCR mask for boot integrity */
#define TPM_PCR_DEFAULT_MASK      (TPM_PCR_BIOS | TPM_PCR_BIOS_CONFIG | \
                                   TPM_PCR_OPTION_ROM | TPM_PCR_MBR)

/* Maximum sealed blob size */
#define TPM_MAX_SEALED_SIZE       512

/* TPM NV Index for DiskCryptor */
#define DC_TPM_NV_INDEX           0x01500000

/* Sealed key blob structure */
#pragma pack(push, 1)
typedef struct _dc_tpm_blob {
    u32  magic;              /* DC_TPM_BLOB_SIGN */
    u32  version;            /* Blob format version */
    u32  auth_mode;          /* Authentication mode */
    u32  pcr_mask;           /* PCRs used for sealing */
    u32  sealed_size;        /* Size of sealed data */
    u8   sealed_data[TPM_MAX_SEALED_SIZE];  /* TPM sealed blob */
} dc_tpm_blob;
#pragma pack(pop)

#define DC_TPM_BLOB_SIGN          0x544D5044  /* 'DPMT' */
#define DC_TPM_BLOB_VERSION       1

/* TPM Information structure */
typedef struct _dc_tpm_info {
    int  present;            /* TPM is present */
    int  enabled;            /* TPM is enabled */
    int  version_major;      /* TPM version major */
    int  version_minor;      /* TPM version minor */
    u32  pcr_mask_available; /* Available PCRs */
    int  owner_set;          /* Owner password is set */
    int  nv_available;       /* NV storage available */
} dc_tpm_info;

/*
 * Initialize TPM subsystem
 * Returns: TPM_OK on success, error code otherwise
 */
int tpm_init(void);

/*
 * Uninitialize TPM subsystem
 */
void tpm_uninit(void);

/*
 * Check if TPM is available and get information
 * info: output structure with TPM details
 * Returns: TPM_OK if TPM is available, error code otherwise
 */
int tpm_get_info(dc_tpm_info *info);

/*
 * Seal a key to the TPM
 * key:        Key data to seal (typically volume master key)
 * key_size:   Size of key in bytes
 * password:   Optional password for hybrid mode (can be NULL)
 * pcr_mask:   Bitmask of PCRs to bind to
 * auth_mode:  Authentication mode (TPM_AUTH_*)
 * blob:       Output sealed blob
 * Returns: TPM_OK on success, error code otherwise
 */
int tpm_seal_key(
    const u8 *key, 
    u32 key_size, 
    const dc_pass *password,
    u32 pcr_mask,
    int auth_mode,
    dc_tpm_blob *blob
);

/*
 * Unseal a key from the TPM
 * blob:       Sealed blob from tpm_seal_key
 * password:   Password if sealed with TPM_AUTH_PASSWORD
 * key:        Output buffer for unsealed key
 * key_size:   Input: buffer size, Output: actual key size
 * Returns: TPM_OK on success, TPM_ERR_PCR_MISMATCH if PCRs changed
 */
int tpm_unseal_key(
    const dc_tpm_blob *blob,
    const dc_pass *password,
    u8 *key,
    u32 *key_size
);

/*
 * Store sealed blob in TPM NV storage
 * blob:       Sealed blob to store
 * Returns: TPM_OK on success, error code otherwise
 */
int tpm_nv_write_blob(const dc_tpm_blob *blob);

/*
 * Read sealed blob from TPM NV storage
 * blob:       Output buffer for blob
 * Returns: TPM_OK on success, error code otherwise
 */
int tpm_nv_read_blob(dc_tpm_blob *blob);

/*
 * Delete sealed blob from TPM NV storage
 * Returns: TPM_OK on success, error code otherwise
 */
int tpm_nv_delete_blob(void);

/*
 * Read current PCR values
 * pcr_mask:   PCRs to read
 * pcr_values: Output buffer (32 bytes per PCR, in order)
 * Returns: TPM_OK on success, error code otherwise
 */
int tpm_read_pcrs(u32 pcr_mask, u8 *pcr_values);

/*
 * Verify platform integrity by comparing current PCRs to sealed values
 * blob:       Sealed blob containing expected PCRs
 * Returns: TPM_OK if PCRs match, TPM_ERR_PCR_MISMATCH otherwise
 */
int tpm_verify_platform(const dc_tpm_blob *blob);

#endif /* _TPM_SEAL_H_ */


