/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2010
    * ntldr <ntldr@diskcryptor.net> PGP key ID - 0xC48251EB4F8E4E6E
    *
    * Security updates (c) 2025
    * - Increased PBKDF2 iterations from 1000 to 600,000 (OWASP 2023 recommendation)
    * - Added HMAC-SHA256 header integrity check (replacing CRC32)

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

#include <stddef.h>
#include "defines.h"
#include "crypto_head.h"
#include "sha512_pkcs5_2.h"
#include "sha512.h"
#include "crc32.h"
#include "misc_mem.h"
#include "prng.h"

/*
 * Compute HMAC-SHA512 truncated to 256 bits (32 bytes)
 * Key is derived from the password-based key
 */
static void cp_compute_header_hmac(dc_header *hdr, const u8 *key, u8 *hmac_out)
{
    sha512_ctx ctx;
    u8 hmac_key[64];
    u8 ipad[128];
    u8 opad[128];
    u8 hash[SHA512_DIGEST_SIZE];
    int i;
    
    /* Derive HMAC key from first 64 bytes of XTS key material */
    memcpy(hmac_key, key, 64);
    
    /* Prepare IPAD and OPAD */
    for (i = 0; i < 64; i++) {
        ipad[i] = hmac_key[i] ^ 0x36;
        opad[i] = hmac_key[i] ^ 0x5C;
    }
    /* Extend with zeros */
    memset(ipad + 64, 0x36, 64);
    memset(opad + 64, 0x5C, 64);
    
    /* Inner hash: H(K XOR ipad || message) */
    sha512_init(&ctx);
    sha512_hash(&ctx, ipad, 128);
    /* Hash the header data excluding salt and HMAC field */
    sha512_hash(&ctx, (u8*)&hdr->sign, sizeof(hdr->sign));
    sha512_hash(&ctx, (u8*)&hdr->hdr_crc, sizeof(hdr->hdr_crc));
    sha512_hash(&ctx, (u8*)&hdr->version, sizeof(hdr->version));
    sha512_hash(&ctx, (u8*)&hdr->flags, 
                DC_ENCRYPTEDDATASIZE - offsetof(dc_header, flags) + offsetof(dc_header, salt) - DC_HMAC_SIZE);
    sha512_done(&ctx, hash);
    
    /* Outer hash: H(K XOR opad || inner_hash) */
    sha512_init(&ctx);
    sha512_hash(&ctx, opad, 128);
    sha512_hash(&ctx, hash, SHA512_DIGEST_SIZE);
    sha512_done(&ctx, hash);
    
    /* Truncate to 256 bits */
    memcpy(hmac_out, hash, DC_HMAC_SIZE);
    
    /* Prevent leaks */
    burn(hmac_key, sizeof(hmac_key));
    burn(ipad, sizeof(ipad));
    burn(opad, sizeof(opad));
    burn(hash, sizeof(hash));
    burn(&ctx, sizeof(ctx));
}

/*
 * Verify header integrity using either HMAC-SHA256 (v3+) or CRC32 (legacy)
 */
static int cp_verify_header_integrity(dc_header *hdr, const u8 *key)
{
    if (hdr->version >= DC_HDR_VERSION) {
        /* Version 3+: Use HMAC-SHA256 */
        u8 computed_hmac[DC_HMAC_SIZE];
        cp_compute_header_hmac(hdr, key, computed_hmac);
        
        int result = (memcmp(computed_hmac, hdr->hdr_hmac, DC_HMAC_SIZE) == 0);
        burn(computed_hmac, sizeof(computed_hmac));
        return result;
    } else {
        /* Legacy versions: Use CRC32 */
        return (hdr->hdr_crc == crc32(pv(&hdr->version), DC_CRC_AREA_SIZE));
    }
}

/*
 * Try to decrypt a header with the specified iteration count
 * Returns: 1 on success, 0 on failure
 */
static int cp_try_decrypt_header(xts_key *hdr_key, dc_header *header, dc_header *hcopy, 
                                  dc_pass *password, int iterations)
{
	u8  dk[DISKKEY_SIZE];
	int i, succs = 0;

	sha512_pkcs5_2(
		iterations, password->pass, password->size, 
		header->salt, PKCS5_SALT_SIZE, dk, PKCS_DERIVE_MAX);

	for (i = 0; i < CF_CIPHERS_NUM; i++)
	{
		xts_set_key(dk, i, hdr_key);

		xts_decrypt(
			pv(header), pv(hcopy), sizeof(dc_header), 0, hdr_key);

		/* Magic 'DCRP' */
		if (hcopy->sign != DC_VOLUME_SIGN) {
			continue;
		}
		
		/* Verify header integrity (HMAC for v3+, CRC32 for legacy) */
		if (!cp_verify_header_integrity(hcopy, dk)) {
			continue;
		}
		
		/* copy decrypted part to output */
		memcpy(&header->sign, &hcopy->sign, DC_ENCRYPTEDDATASIZE);
		succs = 1; 
		break;
	}

	/* prevent leaks */
	burn(dk, sizeof(dk));

	return succs;
}

/*
 * Decrypt volume header with automatic legacy detection
 * 
 * Parameters:
 *   hdr_key   - output: XTS key for header encryption
 *   header    - input/output: encrypted header, decrypted portion is overwritten on success
 *   password  - input: user password
 *   is_legacy - output: set to 1 if legacy (insecure) header detected, 0 otherwise (can be NULL)
 * 
 * Returns: 1 on success, 0 on failure
 * 
 * Security Note: If is_legacy is set to 1, the caller should prompt the user to upgrade
 * the volume to the modern iteration count for improved security against brute-force attacks.
 */
int cp_decrypt_header_ex(xts_key *hdr_key, dc_header *header, dc_pass *password, int *is_legacy)
{
	dc_header *hcopy;
	int        succs = 0;

	if (is_legacy != NULL) *is_legacy = 0;

	if ( (hcopy = mm_secure_alloc(sizeof(dc_header))) == NULL ) {
		return 0;
	}

	/* Try modern iteration count first (600K iterations) */
	succs = cp_try_decrypt_header(hdr_key, header, hcopy, password, PBKDF2_ITERATIONS_CURRENT);

	/* If modern iterations failed, try legacy iteration count (1K iterations) */
	if (succs == 0) {
		succs = cp_try_decrypt_header(hdr_key, header, hcopy, password, PBKDF2_ITERATIONS_LEGACY);
		if (succs != 0 && is_legacy != NULL) {
			*is_legacy = 1;  /* Flag that this is a legacy header needing upgrade */
		}
	}

	mm_secure_free(hcopy);
	return succs;
}

/*
 * Backward-compatible wrapper for code that doesn't need legacy detection
 */
int cp_decrypt_header(xts_key *hdr_key, dc_header *header, dc_pass *password)
{
	return cp_decrypt_header_ex(hdr_key, header, password, NULL);
}

/*
 * Set header encryption key from password
 * Uses modern iteration count for new volumes
 */
void cp_set_header_key(xts_key *hdr_key, u8 salt[PKCS5_SALT_SIZE], int cipher, dc_pass *password)
{
	u8 dkey[DISKKEY_SIZE];
	
	sha512_pkcs5_2(
		PBKDF2_ITERATIONS_CURRENT, password->pass, password->size, 
		salt, PKCS5_SALT_SIZE, dkey, PKCS_DERIVE_MAX);

	xts_set_key(dkey, cipher, hdr_key);

	/* prevent leaks */
	burn(dkey, sizeof(dkey));
}

/*
 * Compute and set header integrity (HMAC for v3+, CRC32 for compatibility)
 */
static void cp_set_header_integrity(dc_header *header, const u8 *key)
{
    if (header->version >= DC_HDR_VERSION) {
        /* Version 3+: Use HMAC-SHA256 */
        cp_compute_header_hmac(header, key, header->hdr_hmac);
        header->hdr_crc = 0;  /* Clear legacy CRC field */
    } else {
        /* Legacy: Use CRC32 */
        header->hdr_crc = crc32((const unsigned char*)&header->version, DC_CRC_AREA_SIZE);
        memset(header->hdr_hmac, 0, DC_HMAC_SIZE);
    }
}

/*
 * Re-encrypt header with modern iteration count and HMAC-SHA256
 * Used for migrating legacy volumes to secure format
 */
int cp_upgrade_header(dc_header *header, xts_key *old_key, dc_pass *password, int cipher)
{
	xts_key *new_key;
	u8       new_salt[PKCS5_SALT_SIZE];
	u8       dkey[DISKKEY_SIZE];
	
	if ( (new_key = mm_secure_alloc(sizeof(xts_key))) == NULL ) {
		return 0;
	}

	/* Generate new salt for upgraded header */
	cp_rand_bytes(new_salt, PKCS5_SALT_SIZE);

	/* Copy new salt to header */
	memcpy(header->salt, new_salt, PKCS5_SALT_SIZE);

	/* Update header version to indicate modern format with HMAC */
	header->version = DC_HDR_VERSION;

	/* Derive new key with modern iteration count */
	sha512_pkcs5_2(
		PBKDF2_ITERATIONS_CURRENT, password->pass, password->size, 
		new_salt, PKCS5_SALT_SIZE, dkey, PKCS_DERIVE_MAX);

	/* Set header integrity using HMAC-SHA256 */
	cp_set_header_integrity(header, dkey);

	xts_set_key(dkey, cipher, new_key);

	/* Encrypt header with new key */
	xts_encrypt(pv(&header->sign), pv(&header->sign), DC_ENCRYPTEDDATASIZE, 0, new_key);

	/* prevent leaks */
	burn(dkey, sizeof(dkey));
	burn(new_salt, sizeof(new_salt));
	mm_secure_free(new_key);

	return 1;
}
