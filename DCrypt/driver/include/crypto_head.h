#ifndef _CRYPTO_HEAD_H_
#define _CRYPTO_HEAD_H_

#include "volume_header.h"
#include "xts_fast.h"

/*
 * Header decryption functions
 */

/* Decrypt header with automatic legacy detection */
int  cp_decrypt_header_ex(xts_key *hdr_key, dc_header *header, dc_pass *password, int *is_legacy);

/* Backward-compatible wrapper (no legacy detection) */
int  cp_decrypt_header(xts_key *hdr_key, dc_header *header, dc_pass *password);

/* Set header encryption key for new volumes */
void cp_set_header_key(xts_key *hdr_key, u8 salt[PKCS5_SALT_SIZE], int cipher, dc_pass *password);

/* Upgrade legacy header to modern iteration count */
int  cp_upgrade_header(dc_header *header, xts_key *old_key, dc_pass *password, int cipher);

#endif
