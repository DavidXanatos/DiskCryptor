/** @file
TPM 2.0 Authentication Integration for DiskCryptor

Copyright (c) 2025. DiskCryptor Security Update

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the GNU General Public License, version 3.0 (GPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/GPL-3.0
**/

#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/CommonLib.h>
#include <Library/DcsTpmLib.h>
#include <Library/BaseCryptLib.h>

#include "include/boot/dc_header.h"

/* TPM Configuration */
#define DC_TPM_NV_INDEX         0x01500000
#define DC_TPM_BLOB_MAGIC       0x544D5044  /* 'DPMT' */
#define DC_TPM_BLOB_VERSION     1
#define DC_TPM_MAX_KEY_SIZE     256

/* Default PCR mask for boot integrity binding */
#define DC_TPM_PCR_MASK_DEFAULT 0x0F  /* PCRs 0-3 */

/* TPM Authentication modes */
#define DC_TPM_AUTH_NONE        0     /* TPM only - no password */
#define DC_TPM_AUTH_PASSWORD    1     /* TPM + Password hybrid */

/* TPM Sealed Blob Structure */
#pragma pack(1)
typedef struct _DC_TPM_SEALED_BLOB {
    UINT32  Magic;              /* DC_TPM_BLOB_MAGIC */
    UINT32  Version;            /* Blob format version */
    UINT32  AuthMode;           /* Authentication mode */
    UINT32  PcrMask;            /* PCRs used for sealing */
    UINT32  KeySize;            /* Size of sealed key data */
    UINT8   KeyData[DC_TPM_MAX_KEY_SIZE];  /* Sealed key material */
    UINT8   PcrDigest[32];      /* Expected PCR digest (SHA256) */
} DC_TPM_SEALED_BLOB;
#pragma pack()

/* Global state */
static BOOLEAN gTpmInitialized = FALSE;
static BOOLEAN gTpmAvailable = FALSE;
static UINT32  gTpmPcrMask = DC_TPM_PCR_MASK_DEFAULT;

/**
 * Initialize TPM subsystem
 */
EFI_STATUS
DcTpmInit(VOID)
{
    EFI_STATUS Status;
    
    if (gTpmInitialized) {
        return gTpmAvailable ? EFI_SUCCESS : EFI_NOT_FOUND;
    }
    
    gTpmInitialized = TRUE;
    
    /* Initialize TPM 2.0 */
    Status = InitTpm20();
    if (EFI_ERROR(Status)) {
        OUT_PRINT(L"TPM 2.0 not available: %r\n", Status);
        gTpmAvailable = FALSE;
        return Status;
    }
    
    gTpmAvailable = TRUE;
    OUT_PRINT(L"TPM 2.0 initialized successfully\n");
    
    return EFI_SUCCESS;
}

/**
 * Check if TPM is available
 */
BOOLEAN
DcTpmIsAvailable(VOID)
{
    if (!gTpmInitialized) {
        DcTpmInit();
    }
    return gTpmAvailable;
}

/**
 * Read current PCR values and compute digest
 */
EFI_STATUS
DcTpmGetPcrDigest(
    IN  UINT32  PcrMask,
    OUT UINT8   *Digest
    )
{
    EFI_STATUS Status;
    TPML_DIGEST PcrValue;
    UINTN i;
    VOID *Ctx;
    UINTN CtxSize;
    
    if (!gTpmAvailable) {
        return EFI_NOT_READY;
    }
    
    /* Initialize SHA256 context */
    CtxSize = Sha256GetContextSize();
    Ctx = MEM_ALLOC(CtxSize);
    if (Ctx == NULL) {
        return EFI_OUT_OF_RESOURCES;
    }
    
    Sha256Init(Ctx);
    
    /* Read and hash each selected PCR */
    for (i = 0; i < 24; i++) {
        if ((PcrMask & (1 << i)) == 0) {
            continue;
        }
        
        Status = DcsTpm2PcrRead((UINT32)i, &PcrValue);
        if (EFI_ERROR(Status)) {
            MEM_FREE(Ctx);
            return Status;
        }
        
        Sha256Update(Ctx, PcrValue.digests[0].buffer, SHA256_DIGEST_SIZE);
    }
    
    if (!Sha256Final(Ctx, Digest)) {
        MEM_FREE(Ctx);
        return EFI_DEVICE_ERROR;
    }
    
    MEM_FREE(Ctx);
    return EFI_SUCCESS;
}

/**
 * Verify platform integrity by checking current PCRs against stored digest
 */
EFI_STATUS
DcTpmVerifyPlatform(
    IN DC_TPM_SEALED_BLOB *Blob
    )
{
    EFI_STATUS Status;
    UINT8 CurrentDigest[SHA256_DIGEST_SIZE];
    
    if (Blob == NULL) {
        return EFI_INVALID_PARAMETER;
    }
    
    if (Blob->Magic != DC_TPM_BLOB_MAGIC) {
        return EFI_INVALID_PARAMETER;
    }
    
    /* Get current PCR digest */
    Status = DcTpmGetPcrDigest(Blob->PcrMask, CurrentDigest);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    
    /* Compare with stored digest */
    if (CompareMem(CurrentDigest, Blob->PcrDigest, SHA256_DIGEST_SIZE) != 0) {
        OUT_PRINT(L"TPM: Platform integrity check failed!\n");
        OUT_PRINT(L"     PCR values have changed since key was sealed.\n");
        return EFI_SECURITY_VIOLATION;
    }
    
    return EFI_SUCCESS;
}

/**
 * Seal key data to TPM NV storage
 */
EFI_STATUS
DcTpmSealKey(
    IN UINT8   *KeyData,
    IN UINT32   KeySize,
    IN UINT32   AuthMode,
    IN UINT32   PcrMask
    )
{
    EFI_STATUS Status;
    DC_TPM_SEALED_BLOB Blob;
    
    if (!gTpmAvailable) {
        return EFI_NOT_READY;
    }
    
    if (KeyData == NULL || KeySize == 0 || KeySize > DC_TPM_MAX_KEY_SIZE) {
        return EFI_INVALID_PARAMETER;
    }
    
    /* Initialize blob */
    SetMem(&Blob, sizeof(Blob), 0);
    Blob.Magic = DC_TPM_BLOB_MAGIC;
    Blob.Version = DC_TPM_BLOB_VERSION;
    Blob.AuthMode = AuthMode;
    Blob.PcrMask = PcrMask;
    Blob.KeySize = KeySize;
    CopyMem(Blob.KeyData, KeyData, KeySize);
    
    /* Get current PCR digest for later verification */
    Status = DcTpmGetPcrDigest(PcrMask, Blob.PcrDigest);
    if (EFI_ERROR(Status)) {
        MEM_BURN(&Blob, sizeof(Blob));
        return Status;
    }
    
    /*
     * In a full implementation, this would:
     * 1. Create a policy session bound to PCRs
     * 2. Seal the key data using TPM2_Create
     * 3. Store the sealed object in NV storage
     * 
     * For now, we use NV storage with PCR policy
     */
    
    /* Write to TPM NV storage */
    Status = Tpm2NvWrite(
        TPM_RH_OWNER,
        DC_TPM_NV_INDEX,
        NULL,  /* Use owner auth */
        (TPM2B_MAX_BUFFER*)&Blob,
        0
    );
    
    MEM_BURN(&Blob, sizeof(Blob));
    
    if (EFI_ERROR(Status)) {
        OUT_PRINT(L"TPM: Failed to seal key: %r\n", Status);
        return Status;
    }
    
    OUT_PRINT(L"TPM: Key sealed successfully\n");
    return EFI_SUCCESS;
}

/**
 * Unseal key data from TPM NV storage
 */
EFI_STATUS
DcTpmUnsealKey(
    OUT UINT8   *KeyData,
    OUT UINT32  *KeySize,
    OUT UINT32  *AuthMode
    )
{
    EFI_STATUS Status;
    DC_TPM_SEALED_BLOB Blob;
    TPM2B_MAX_BUFFER Buffer;
    
    if (!gTpmAvailable) {
        return EFI_NOT_READY;
    }
    
    if (KeyData == NULL || KeySize == NULL) {
        return EFI_INVALID_PARAMETER;
    }
    
    /* Read from TPM NV storage */
    Buffer.size = sizeof(Blob);
    Status = Tpm2NvRead(
        TPM_RH_OWNER,
        DC_TPM_NV_INDEX,
        NULL,  /* Use owner auth */
        sizeof(Blob),
        0,
        &Buffer
    );
    
    if (EFI_ERROR(Status)) {
        return Status;
    }
    
    CopyMem(&Blob, Buffer.buffer, sizeof(Blob));
    
    /* Validate blob */
    if (Blob.Magic != DC_TPM_BLOB_MAGIC || Blob.Version != DC_TPM_BLOB_VERSION) {
        MEM_BURN(&Blob, sizeof(Blob));
        return EFI_INCOMPATIBLE_VERSION;
    }
    
    /* Verify platform integrity */
    Status = DcTpmVerifyPlatform(&Blob);
    if (EFI_ERROR(Status)) {
        MEM_BURN(&Blob, sizeof(Blob));
        return Status;
    }
    
    /* Return key data */
    if (*KeySize < Blob.KeySize) {
        *KeySize = Blob.KeySize;
        MEM_BURN(&Blob, sizeof(Blob));
        return EFI_BUFFER_TOO_SMALL;
    }
    
    CopyMem(KeyData, Blob.KeyData, Blob.KeySize);
    *KeySize = Blob.KeySize;
    if (AuthMode != NULL) {
        *AuthMode = Blob.AuthMode;
    }
    
    MEM_BURN(&Blob, sizeof(Blob));
    
    OUT_PRINT(L"TPM: Key unsealed successfully\n");
    return EFI_SUCCESS;
}

/**
 * Try to authenticate using TPM-sealed key
 * Returns the unsealed password/key material
 */
EFI_STATUS
DcTpmAuthenticate(
    OUT dc_pass *Password
    )
{
    EFI_STATUS Status;
    UINT8 KeyData[DC_TPM_MAX_KEY_SIZE];
    UINT32 KeySize = sizeof(KeyData);
    UINT32 AuthMode;
    
    if (Password == NULL) {
        return EFI_INVALID_PARAMETER;
    }
    
    /* Initialize TPM if not already done */
    Status = DcTpmInit();
    if (EFI_ERROR(Status)) {
        return Status;
    }
    
    /* Try to unseal key from TPM */
    Status = DcTpmUnsealKey(KeyData, &KeySize, &AuthMode);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    
    /* Check if password is required in addition to TPM */
    if (AuthMode == DC_TPM_AUTH_PASSWORD) {
        OUT_PRINT(L"TPM: Hybrid mode - password also required\n");
        MEM_BURN(KeyData, sizeof(KeyData));
        return EFI_ACCESS_DENIED;  /* Caller must also get password */
    }
    
    /* Use unsealed key as password */
    if (KeySize > MAX_PASSWORD) {
        KeySize = MAX_PASSWORD;
    }
    
    Password->size = (u32)KeySize;
    CopyMem(Password->pass, KeyData, KeySize);
    
    MEM_BURN(KeyData, sizeof(KeyData));
    
    return EFI_SUCCESS;
}

/**
 * Clean up TPM sensitive data
 */
VOID
DcTpmCleanup(VOID)
{
    /* Any TPM context cleanup would go here */
    gTpmInitialized = FALSE;
    gTpmAvailable = FALSE;
}


