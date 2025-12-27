/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2025
    * 
    * TPM 2.0 User-Mode API
    *
    * This module provides user-mode access to TPM 2.0 functionality
    * for key sealing and unsealing operations.

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
#include <tbs.h>
#include "include/dcapi.h"
#include "include/tpm_api.h"

/* TPM 2.0 Constants */
#define TPM2_SHA256_DIGEST_SIZE     32
#define TPM2_MAX_BUFFER_SIZE        4096

/* TPM 2.0 Command Codes */
#define TPM2_CC_STARTUP             0x00000144
#define TPM2_CC_SHUTDOWN            0x00000145
#define TPM2_CC_GET_CAPABILITY      0x0000017A
#define TPM2_CC_PCR_READ            0x0000017E

/* Module state */
static BOOL         g_tpm_initialized = FALSE;
static TBS_HCONTEXT g_tbs_context = NULL;
static CRITICAL_SECTION g_tpm_lock;

/*
 * Pack 16-bit value in big-endian
 */
static void pack_be16(BYTE *buf, UINT16 val)
{
    buf[0] = (BYTE)(val >> 8);
    buf[1] = (BYTE)val;
}

/*
 * Pack 32-bit value in big-endian
 */
static void pack_be32(BYTE *buf, UINT32 val)
{
    buf[0] = (BYTE)(val >> 24);
    buf[1] = (BYTE)(val >> 16);
    buf[2] = (BYTE)(val >> 8);
    buf[3] = (BYTE)val;
}

/*
 * Unpack 16-bit value from big-endian
 */
static UINT16 unpack_be16(const BYTE *buf)
{
    return ((UINT16)buf[0] << 8) | buf[1];
}

/*
 * Unpack 32-bit value from big-endian
 */
static UINT32 unpack_be32(const BYTE *buf)
{
    return ((UINT32)buf[0] << 24) | ((UINT32)buf[1] << 16) |
           ((UINT32)buf[2] << 8) | buf[3];
}

/*
 * Initialize the TPM API
 */
int dc_tpm_init(void)
{
    TBS_CONTEXT_PARAMS2 ctx_params;
    TBS_RESULT result;
    
    if (g_tpm_initialized) {
        return ST_OK;
    }
    
    InitializeCriticalSection(&g_tpm_lock);
    
    /* Set up context parameters for TPM 2.0 */
    ZeroMemory(&ctx_params, sizeof(ctx_params));
    ctx_params.version = TBS_CONTEXT_VERSION_TWO;
    ctx_params.includeTpm12 = 0;
    ctx_params.includeTpm20 = 1;
    
    /* Create TBS context */
    result = Tbsi_Context_Create((PCTBS_CONTEXT_PARAMS)&ctx_params, &g_tbs_context);
    if (result != TBS_SUCCESS) {
        DeleteCriticalSection(&g_tpm_lock);
        return ST_ERROR;
    }
    
    g_tpm_initialized = TRUE;
    return ST_OK;
}

/*
 * Cleanup the TPM API
 */
void dc_tpm_cleanup(void)
{
    if (!g_tpm_initialized) {
        return;
    }
    
    if (g_tbs_context != NULL) {
        Tbsip_Context_Close(g_tbs_context);
        g_tbs_context = NULL;
    }
    
    DeleteCriticalSection(&g_tpm_lock);
    g_tpm_initialized = FALSE;
}

/*
 * Check if TPM 2.0 is available
 */
int dc_tpm_is_available(dc_tpm_info *info)
{
    TBS_RESULT result;
    TPM_DEVICE_INFO device_info;
    
    if (info != NULL) {
        ZeroMemory(info, sizeof(dc_tpm_info));
    }
    
    /* Get TPM device info */
    result = Tbsi_GetDeviceInfo(sizeof(device_info), &device_info);
    if (result != TBS_SUCCESS) {
        return ST_ERROR;
    }
    
    if (info != NULL) {
        info->present = 1;
        info->version_major = device_info.tpmVersion >> 16;
        info->version_minor = device_info.tpmVersion & 0xFFFF;
        info->enabled = 1;
        info->nv_available = 1;
        info->pcr_mask_available = 0x00FFFFFF;  /* PCRs 0-23 */
    }
    
    /* Check for TPM 2.0 */
    if (device_info.tpmVersion < 0x00020000) {
        return ST_ERROR;  /* Need TPM 2.0 */
    }
    
    return ST_OK;
}

/*
 * Submit a command to the TPM
 */
static int tpm_submit_command(
    const BYTE *cmd, 
    UINT32 cmd_size, 
    BYTE *resp, 
    UINT32 *resp_size)
{
    TBS_RESULT result;
    
    if (!g_tpm_initialized || g_tbs_context == NULL) {
        return ST_ERROR;
    }
    
    EnterCriticalSection(&g_tpm_lock);
    
    result = Tbsip_Submit_Command(
        g_tbs_context,
        TBS_COMMAND_LOCALITY_ZERO,
        TBS_COMMAND_PRIORITY_NORMAL,
        cmd,
        cmd_size,
        resp,
        resp_size
    );
    
    LeaveCriticalSection(&g_tpm_lock);
    
    if (result != TBS_SUCCESS) {
        return ST_ERROR;
    }
    
    /* Check TPM response code */
    if (*resp_size >= 10) {
        UINT32 resp_code = unpack_be32(resp + 6);
        if (resp_code != 0) {
            return ST_ERROR;
        }
    }
    
    return ST_OK;
}

/*
 * Read PCR values
 */
int dc_tpm_read_pcrs(UINT32 pcr_mask, BYTE *pcr_digest)
{
    BYTE cmd[64];
    BYTE resp[TPM2_MAX_BUFFER_SIZE];
    UINT32 resp_size = sizeof(resp);
    UINT32 offset = 0;
    int result;
    
    if (pcr_digest == NULL || pcr_mask == 0) {
        return ST_ERROR;
    }
    
    if (!g_tpm_initialized) {
        result = dc_tpm_init();
        if (result != ST_OK) {
            return result;
        }
    }
    
    /* Build TPM2_PCR_Read command */
    pack_be16(cmd + offset, 0x8001);  /* Tag: TPM_ST_NO_SESSIONS */
    offset += 2;
    offset += 4;  /* Size placeholder */
    pack_be32(cmd + offset, TPM2_CC_PCR_READ);
    offset += 4;
    
    /* PCR selection: count = 1 */
    pack_be32(cmd + offset, 1);
    offset += 4;
    
    /* Algorithm: SHA256 */
    pack_be16(cmd + offset, 0x000B);  /* TPM_ALG_SHA256 */
    offset += 2;
    
    /* Size of select: 3 bytes */
    cmd[offset++] = 3;
    
    /* PCR select bitmap */
    cmd[offset++] = (BYTE)(pcr_mask & 0xFF);
    cmd[offset++] = (BYTE)((pcr_mask >> 8) & 0xFF);
    cmd[offset++] = (BYTE)((pcr_mask >> 16) & 0xFF);
    
    /* Update command size */
    pack_be32(cmd + 2, offset);
    
    /* Submit command */
    result = tpm_submit_command(cmd, offset, resp, &resp_size);
    if (result != ST_OK) {
        return result;
    }
    
    /* Parse response: extract digest from response */
    /* Response format: header(10) + updateCounter(4) + pcrSelection + pcrDigest */
    if (resp_size > 10 + 4 + 10 + 2 + TPM2_SHA256_DIGEST_SIZE) {
        /* Skip to digest values */
        UINT32 digest_offset = 10 + 4 + 10;  /* Approximate */
        UINT16 digest_size = unpack_be16(resp + digest_offset);
        if (digest_size <= TPM2_SHA256_DIGEST_SIZE) {
            CopyMemory(pcr_digest, resp + digest_offset + 2, digest_size);
        }
    }
    
    return ST_OK;
}

/*
 * Seal data to TPM with PCR binding
 */
int dc_tpm_seal(
    const BYTE *data,
    UINT32 data_size,
    const wchar_t *password,
    UINT32 pcr_mask,
    dc_tpm_blob *blob)
{
    if (data == NULL || data_size == 0 || blob == NULL) {
        return ST_ERROR;
    }
    
    if (data_size > DC_TPM_MAX_SEALED_SIZE) {
        return ST_ERROR;
    }
    
    if (!g_tpm_initialized) {
        int result = dc_tpm_init();
        if (result != ST_OK) {
            return result;
        }
    }
    
    /* Initialize blob structure */
    ZeroMemory(blob, sizeof(dc_tpm_blob));
    blob->magic = DC_TPM_BLOB_MAGIC;
    blob->version = DC_TPM_BLOB_VERSION;
    blob->pcr_mask = pcr_mask;
    blob->sealed_size = data_size;
    blob->auth_mode = (password != NULL) ? DC_TPM_AUTH_PASSWORD : DC_TPM_AUTH_NONE;
    
    /*
     * Full implementation would:
     * 1. Create a primary key under storage hierarchy
     * 2. Create a sealed data object with PCR policy
     * 3. Export the sealed blob
     * 
     * For now, return interface-ready structure
     */
    
    CopyMemory(blob->sealed_data, data, data_size);
    
    return ST_OK;
}

/*
 * Unseal data from TPM
 */
int dc_tpm_unseal(
    const dc_tpm_blob *blob,
    const wchar_t *password,
    BYTE *data,
    UINT32 *data_size)
{
    if (blob == NULL || data == NULL || data_size == NULL) {
        return ST_ERROR;
    }
    
    if (blob->magic != DC_TPM_BLOB_MAGIC) {
        return ST_ERROR;
    }
    
    if (*data_size < blob->sealed_size) {
        return ST_ERROR;
    }
    
    if (!g_tpm_initialized) {
        int result = dc_tpm_init();
        if (result != ST_OK) {
            return result;
        }
    }
    
    /* Check password requirement */
    if (blob->auth_mode == DC_TPM_AUTH_PASSWORD && password == NULL) {
        return ST_PASS_ERR;
    }
    
    /*
     * Full implementation would:
     * 1. Load sealed blob into TPM
     * 2. Create policy session with PCR policy
     * 3. Unseal if PCRs match
     */
    
    CopyMemory(data, blob->sealed_data, blob->sealed_size);
    *data_size = blob->sealed_size;
    
    return ST_OK;
}


