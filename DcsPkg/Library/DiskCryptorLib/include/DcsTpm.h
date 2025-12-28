/** @file
TPM 2.0 Authentication Integration Header for DiskCryptor

Copyright (c) 2025. DiskCryptor Security Update

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the GNU General Public License, version 3.0 (GPL-3.0).
**/

#ifndef _DCS_TPM_H_
#define _DCS_TPM_H_

#include <Uefi.h>
#include "boot/dc_header.h"

/* TPM Authentication modes */
#define DC_TPM_AUTH_NONE        0     /* TPM only - no password */
#define DC_TPM_AUTH_PASSWORD    1     /* TPM + Password hybrid */

/* Default PCR mask */
#define DC_TPM_PCR_MASK_DEFAULT 0x0F  /* PCRs 0-3 for BIOS/bootloader */

/**
 * Initialize TPM subsystem
 * @return EFI_SUCCESS if TPM is available
 */
EFI_STATUS
DcTpmInit(VOID);

/**
 * Check if TPM is available
 * @return TRUE if TPM 2.0 is present and initialized
 */
BOOLEAN
DcTpmIsAvailable(VOID);

/**
 * Seal key data to TPM with PCR binding
 * @param KeyData    Key material to seal
 * @param KeySize    Size of key data
 * @param AuthMode   DC_TPM_AUTH_NONE or DC_TPM_AUTH_PASSWORD
 * @param PcrMask    Bitmask of PCRs to bind to
 * @return EFI_SUCCESS on success
 */
EFI_STATUS
DcTpmSealKey(
    IN UINT8   *KeyData,
    IN UINT32   KeySize,
    IN UINT32   AuthMode,
    IN UINT32   PcrMask
);

/**
 * Unseal key data from TPM
 * @param KeyData    Buffer for unsealed key
 * @param KeySize    In: buffer size, Out: actual key size
 * @param AuthMode   Output: authentication mode of sealed key
 * @return EFI_SUCCESS on success, EFI_SECURITY_VIOLATION if PCRs changed
 */
EFI_STATUS
DcTpmUnsealKey(
    OUT UINT8   *KeyData,
    OUT UINT32  *KeySize,
    OUT UINT32  *AuthMode
);

/**
 * Authenticate using TPM-sealed key
 * @param Password   Output password/key structure
 * @return EFI_SUCCESS if TPM auth succeeded
 *         EFI_ACCESS_DENIED if password also required (hybrid mode)
 *         EFI_SECURITY_VIOLATION if PCRs don't match
 */
EFI_STATUS
DcTpmAuthenticate(
    OUT dc_pass *Password
);

/**
 * Clean up TPM resources and sensitive data
 */
VOID
DcTpmCleanup(VOID);

#endif /* _DCS_TPM_H_ */


