#include "defines.h"
#include "dc_header.h"
#include "sha512_pkcs5_2_small.h"
#include "boot.h"
#include "boot_vtab.h"

int dc_decrypt_header(xts_key *hdr_key, dc_header *header, dc_pass *password)
{
	u8        dk[DISKKEY_SIZE];
	int       i, succs = 0;
	dc_header hcopy;
	
	sha512_pkcs5_2(
		1000, password->pass, password->size, 
		header->salt, PKCS5_SALT_SIZE, dk, PKCS_DERIVE_MAX);

	for (i = 0; i < CF_CIPHERS_NUM; i++)
	{
		btab->p_xts_set_key(dk, i, hdr_key);

		btab->p_xts_decrypt(
			pv(header), pv(&hcopy), sizeof(dc_header), 0, hdr_key);

		/* Magic 'DCRP' */
		if (hcopy.sign != DC_VOLM_SIGN) {
			continue;
		}
		/* copy decrypted part to output */
		autocpy(&header->sign, &hcopy.sign, DC_ENCRYPTEDDATASIZE);
		succs = 1; break;
	}
	/* prevent leaks */
	zeroauto(dk, sizeof(dk));
	zeroauto(&hcopy, sizeof(dc_header));

	return succs;
}
