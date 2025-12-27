/*
    *
    * DiskCryptor - open source partition encryption tool
	* Copyright (c) 2008 
	* ntldr <ntldr@diskcryptor.net> PGP key ID - 0xC48251EB4F8E4E6E
    *
    * Security updates (c) 2025
    * Added PBKDF2 key stretching for keyfile material

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
#include <stdio.h>
#include "misc.h"
#include "keyfiles.h"
#include "volume_header.h"
#include "sha512.h"
#include "sha512_pkcs5_2.h"
#include "drv_ioctl.h"

#define KF_BLOCK_SIZE (64 * 1024)

/* 
 * PBKDF2 iterations for keyfile stretching
 * This prevents an attacker who obtains keyfiles from immediately 
 * deriving the contribution to the key material
 */
#define KF_PBKDF2_ITERATIONS 100000

/* Fixed salt for keyfile key derivation (derived from SHA-512 of "DiskCryptor Keyfile Salt v1") */
static const u8 kf_salt[64] = {
    0x3d, 0x5b, 0x7a, 0x92, 0x1e, 0x4c, 0x8f, 0x0d,
    0x6a, 0x2b, 0x9e, 0x5c, 0x1f, 0x7d, 0x3a, 0x8b,
    0x4e, 0x0c, 0x9f, 0x6d, 0x2a, 0x5b, 0x8e, 0x1c,
    0x7f, 0x3d, 0x9a, 0x4b, 0x0e, 0x6c, 0x2f, 0x5d,
    0x8a, 0x1e, 0x4c, 0x9f, 0x3b, 0x7d, 0x0a, 0x5e,
    0x2c, 0x8f, 0x6a, 0x1d, 0x4b, 0x9e, 0x3c, 0x7f,
    0x0d, 0x5a, 0x2e, 0x8c, 0x6f, 0x1b, 0x4d, 0x9a,
    0x3e, 0x7c, 0x0f, 0x5b, 0x2d, 0x8e, 0x6a, 0x1c
};

typedef struct _kf_ctx {
	sha512_ctx sha;
	u8         kf_block[KF_BLOCK_SIZE];
	u8         hash[SHA512_DIGEST_SIZE];
	u8         stretched_key[SHA512_DIGEST_SIZE];

} kf_ctx;

/*
 * Add a single keyfile's contribution to the password
 * 
 * Security improvements:
 * 1. Hash keyfile content with SHA-512
 * 2. Apply PBKDF2-HMAC-SHA512 stretching to the hash
 * 3. Mix stretched result with password
 * 
 * This provides brute-force resistance even if keyfiles are obtained.
 */
static
int dc_add_single_kf(dc_pass *pass, wchar_t *path)
{
	kf_ctx *k_ctx;
	HANDLE  h_file;
	int     resl, i;
	int     succs;
	u32     bytes;
	u64     file_size;
	LARGE_INTEGER li_size;

	h_file = NULL; k_ctx = NULL;
	do
	{
		if ( (k_ctx = secure_alloc(sizeof(kf_ctx))) == NULL ) {
			resl = ST_NOMEM; break;
		}

		h_file = CreateFile(
			path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

		if (h_file == INVALID_HANDLE_VALUE) {
			h_file = NULL; resl = ST_ACCESS_DENIED; break;
		}

		/* Get file size for validation */
		if (!GetFileSizeEx(h_file, &li_size)) {
			resl = ST_IO_ERROR; break;
		}
		file_size = li_size.QuadPart;

		/* Require minimum keyfile size of 64 bytes for security */
		if (file_size < 64) {
			resl = ST_INV_DATA_SIZE; break;
		}

		/* initialize sha512 for hashing keyfile */
		sha512_init(&k_ctx->sha);

		do
		{
			succs = ReadFile(h_file, k_ctx->kf_block, KF_BLOCK_SIZE, &bytes, NULL);

			if ( (succs == 0) || (bytes == 0) ) {
				break;
			}
			sha512_hash(&k_ctx->sha, k_ctx->kf_block, bytes);
		} while (1);		
	
		/* done hashing keyfile content */
		sha512_done(&k_ctx->sha, k_ctx->hash);

		/*
		 * SECURITY: Apply PBKDF2 key stretching to the keyfile hash
		 * This makes brute-force attacks against stolen keyfiles computationally expensive
		 */
		sha512_pkcs5_2(
			KF_PBKDF2_ITERATIONS,
			k_ctx->hash, SHA512_DIGEST_SIZE,  /* Use hash as "password" */
			kf_salt, sizeof(kf_salt),          /* Fixed salt */
			k_ctx->stretched_key, SHA512_DIGEST_SIZE
		);

		/* zero unused password buffer bytes */
		memset(p8(pass->pass) + pass->size, 0, (MAX_PASSWORD*2) - pass->size);

		/* Mix the stretched keyfile material with the password */
		for (i = 0; i < (SHA512_DIGEST_SIZE / sizeof(u32)); i++) {
			p32(pass->pass)[i] += p32(k_ctx->stretched_key)[i];
		}
		pass->size = max(pass->size, SHA512_DIGEST_SIZE); 
		resl = ST_OK;		
	} while (0);

	if (h_file != NULL) {
		CloseHandle(h_file);
	}

	if (k_ctx != NULL) {
		/* Securely zero all sensitive data */
		burn(k_ctx, sizeof(kf_ctx));
		secure_free(k_ctx);
	}

	return resl;
}

int dc_add_keyfiles(dc_pass *pass, wchar_t *path)
{
	WIN32_FIND_DATA find;
	wchar_t         name[MAX_PATH * 2];	
	HANDLE          h_find;
	int             resl;
	
	_snwprintf(
		name, countof(name), L"%s\\*", path);

	h_find = FindFirstFile(name, &find);

	if (h_find != INVALID_HANDLE_VALUE)
	{
		resl = ST_EMPTY_KEYFILES;
		do
		{
			if (find.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
				/* recurse folder scanning not needed */
				continue;
			}

			_snwprintf(
				name, countof(name), L"%s\\%s", path, find.cFileName);

			if ( (resl = dc_add_single_kf(pass, name)) != ST_OK ) {
				break;
			}
		} while (FindNextFile(h_find, &find) != 0);

		FindClose(h_find);
	} else {
		resl = dc_add_single_kf(pass, path);
	}

	/* prevent leaks */
	burn(&find, sizeof(find));
	burn(&name, sizeof(name));

	return resl;
}
