/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2010
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

#include "defines.h"
#include "crypto_head.h"
#ifdef _M_ARM64
#include "sha512_pkcs5_2_small.h"
#else
#include "sha512_pkcs5_2.h"
#endif
#include "crc32.h"
#include "misc_mem.h"
#include "../crypto/Argon2/argon2.h"

int dc_derive_key(dc_pass* password, u8* salt, u8* dk)
{
	if (password->cost == 0) {
		/* Existing SHA512-PBKDF2 */
		sha512_pkcs5_2(1000, password->pass, password->size, salt, PKCS5_SALT_SIZE, dk, PKCS_DERIVE_MAX);
	} else {
		/* Argon2id key derivation */

		// Compute the memory cost (m_cost) in MiB
		int m_cost_mib = 64 + (password->cost - 1) * 32;
		if (m_cost_mib > 1024) // Cap the memory cost at 1024 MiB
			m_cost_mib = 1024;

		// Convert memory cost to KiB for Argon2
		u32 memory_cost = m_cost_mib * 1024;

		// Compute the time cost
		u32 time_cost;
		if (password->cost <= 31)
			time_cost = 3 + ((password->cost - 1) / 3);
		else
			time_cost = 13 + (password->cost - 31);

		// single-threaded
		u32 parallelism = 1;

		int ret = argon2id_hash_raw(time_cost, memory_cost, parallelism, password->pass, password->size, salt, PKCS5_SALT_SIZE, dk, PKCS_DERIVE_MAX, NULL);
		if (ret != ARGON2_OK) {
			return 0;
		}
	}
	return 1;
}

int cp_decrypt_header(xts_key *hdr_key, dc_header *header, dc_pass *password)
{
	u8        dk[DISKKEY_SIZE];
	int       i, succs = 0;
	dc_header *hcopy;

	if ( (hcopy = mm_secure_alloc(sizeof(dc_header))) == NULL ) {
		return 0;
	}
	
	if (!dc_derive_key(password, header->salt, dk))
		return 0;

	for (i = 0; i < CF_CIPHERS_NUM; i++)
	{
		xts_set_key(dk, i, hdr_key);

		xts_decrypt(
			pv(header), pv(hcopy), sizeof(dc_header), 0, hdr_key);

		/* Magic 'DCRP' */
		if (hcopy->sign != DC_VOLUME_SIGN) {
			continue;
		}
		/* Check CRC of header */
		if (hcopy->hdr_crc != crc32(pv(&hcopy->version), DC_CRC_AREA_SIZE)) {
			continue;
		}			
		/* copy decrypted part to output */
		memcpy(&header->sign, &hcopy->sign, DC_ENCRYPTEDDATASIZE);
		succs = 1; break;
	}
	/* prevent leaks */
	burn(dk, sizeof(dk));
	mm_secure_free(hcopy);

	return succs;
}

int cp_set_header_key(xts_key *hdr_key, u8 salt[PKCS5_SALT_SIZE], int cipher, dc_pass *password)
{
	u8 dkey[DISKKEY_SIZE];
	
	if ( !dc_derive_key(password, salt, dkey) ) {
		return 0;
	}

	xts_set_key(dkey, cipher, hdr_key);

	/* prevent leaks */
	burn(dkey, sizeof(dkey));

	return 1;
}