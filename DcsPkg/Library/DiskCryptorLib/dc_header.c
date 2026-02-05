#include <Library/BaseMemoryLib.h>

#include "include\defines.h"
#include "include\boot\dc_header.h"
#ifdef SMALL
#include "crypto_small\sha512_pkcs5_2_small.h"
#else
#include "crypto_fast/sha512_pkcs5_2.h"
#endif
#include "include\boot\boot.h"
#include "Argon2\argon2.h"


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
		UINT32 memory_cost = m_cost_mib * 1024;

		// Compute the time cost
		UINT32 time_cost;
		if (password->cost <= 31)
			time_cost = 3 + ((password->cost - 1) / 3);
		else
			time_cost = 13 + (password->cost - 31);

		// single-threaded
		UINT32 parallelism = 1;

		int ret = argon2id_hash_raw(time_cost, memory_cost, parallelism, password->pass, password->size, salt, PKCS5_SALT_SIZE, dk, PKCS_DERIVE_MAX, NULL);
		if (ret != ARGON2_OK) {
			return 0;
		}
	}
	return 1;
}


int dc_decrypt_header(dc_header *header, dc_pass *password)
{
	u8        dk[DISKKEY_SIZE];
	int       i, succs = 0;
	xts_key   hdr_key;
	dc_header hcopy;
	
	if (!dc_derive_key(password, header->salt, dk))
		return 0;

	for (i = 0; i < CF_CIPHERS_NUM; i++)
	{
		xts_set_key(dk, i, &hdr_key);

		xts_decrypt(pv(header), pv(&hcopy), sizeof(dc_header), 0, &hdr_key);

		/* Magic 'DCRP' */
		if (hcopy.sign != DC_VOLUME_SIGN) {
			continue;
		}
		/* copy decrypted part to output */
		autocpy(&header->sign, &hcopy.sign, DC_ENCRYPTEDDATASIZE);
		succs = 1; break;
	}

	/* prevent leaks */
	zeroauto(dk, sizeof(dk));
	zeroauto(&hdr_key, sizeof(xts_key));
	zeroauto(&hcopy, sizeof(dc_header));

	return succs;
}
