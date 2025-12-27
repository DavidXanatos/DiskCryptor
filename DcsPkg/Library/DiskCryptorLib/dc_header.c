#include "include\defines.h"
#include "include\boot\dc_header.h"
#ifdef SMALL
#include "crypto_small\sha512_pkcs5_2_small.h"
#else
#include "crypto_fast/sha512_pkcs5_2.h"
#endif
#include "include\boot\boot.h"

/* PBKDF2 iteration counts - must match volume_header.h */
#define PBKDF2_ITERATIONS_CURRENT 600000  /* Modern secure iteration count */
#define PBKDF2_ITERATIONS_LEGACY  1000    /* Legacy iteration count (insecure) */

/*
 * Try to decrypt header with specified iteration count
 */
static int dc_try_decrypt_header(dc_header *header, dc_pass *password, 
                                  dc_header *hcopy, xts_key *hdr_key, int iterations)
{
	u8  dk[DISKKEY_SIZE];
	int i, succs = 0;
	
	sha512_pkcs5_2(
		iterations, password->pass, password->size, 
		header->salt, PKCS5_SALT_SIZE, dk, PKCS_DERIVE_MAX);

	for (i = 0; i < CF_CIPHERS_NUM; i++)
	{
		xts_set_key(dk, i, hdr_key);

		xts_decrypt(pv(header), pv(hcopy), sizeof(dc_header), 0, hdr_key);

		/* Magic 'DCRP' */
		if (hcopy->sign != DC_VOLUME_SIGN) {
			continue;
		}
		/* copy decrypted part to output */
		autocpy(&header->sign, &hcopy->sign, DC_ENCRYPTEDDATASIZE);
		succs = 1; 
		break;
	}

	/* prevent leaks */
	zeroauto(dk, sizeof(dk));

	return succs;
}

/*
 * Decrypt volume header with automatic legacy detection
 * Tries modern iteration count first, then falls back to legacy
 */
int dc_decrypt_header(dc_header *header, dc_pass *password)
{
	xts_key   hdr_key;
	dc_header hcopy;
	int       succs = 0;

	/* Try modern iteration count first (600K iterations) */
	succs = dc_try_decrypt_header(header, password, &hcopy, &hdr_key, PBKDF2_ITERATIONS_CURRENT);

	/* If modern iterations failed, try legacy iteration count (1K iterations) */
	if (succs == 0) {
		succs = dc_try_decrypt_header(header, password, &hcopy, &hdr_key, PBKDF2_ITERATIONS_LEGACY);
	}

	/* prevent leaks */
	zeroauto(&hdr_key, sizeof(xts_key));
	zeroauto(&hcopy, sizeof(dc_header));

	return succs;
}
