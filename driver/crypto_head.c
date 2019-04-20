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
#include "sha512_pkcs5_2.h"
#include "crc32.h"
#include "misc_mem.h"

int cp_decrypt_header(xts_key *hdr_key, dc_header *header, dc_pass *password)
{
	u8        dk[DISKKEY_SIZE];
	int       i, succs = 0;
	dc_header *hcopy;

	if ( (hcopy = mm_secure_alloc(sizeof(dc_header))) == NULL ) {
		return 0;
	}
	sha512_pkcs5_2(
		1000, password->pass, password->size, 
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

void cp_set_header_key(xts_key *hdr_key, u8 salt[PKCS5_SALT_SIZE], int cipher, dc_pass *password)
{
	u8 dkey[DISKKEY_SIZE];
	
	sha512_pkcs5_2(
		1000, password->pass, password->size, salt, PKCS5_SALT_SIZE, dkey, PKCS_DERIVE_MAX);

	xts_set_key(dkey, cipher, hdr_key);

	/* prevent leaks */
	burn(dkey, sizeof(dkey));
}