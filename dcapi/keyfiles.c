/*
    *
    * DiskCryptor - open source partition encryption tool
	* Copyright (c) 2008 
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

#include <windows.h>
#include <stdio.h>
#include "misc.h"
#include "keyfiles.h"
#include "volume_header.h"
#include "sha512.h"
#include "drv_ioctl.h"

#define KF_BLOCK_SIZE (64 * 1024)

typedef struct _kf_ctx {
	sha512_ctx sha;
	u8         kf_block[KF_BLOCK_SIZE];
	u8         hash[SHA512_DIGEST_SIZE];

} kf_ctx;

static
int dc_add_single_kf(dc_pass *pass, wchar_t *path)
{
	kf_ctx *k_ctx;
	HANDLE  h_file;
	int     resl, i;
	int     succs;
	u32     bytes;

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
	
		/* done hasing */
		sha512_done(&k_ctx->sha, k_ctx->hash);

		/* zero unused password buffer bytes */
		memset(p8(pass->pass) + pass->size, 0, (MAX_PASSWORD*2) - pass->size);

		/* mix the keyfile hash and password */
		for (i = 0; i < (SHA512_DIGEST_SIZE / sizeof(u32)); i++) {
			p32(pass->pass)[i] += p32(k_ctx->hash)[i];
		}
		pass->size = max(pass->size, SHA512_DIGEST_SIZE); 
		resl = ST_OK;		
	} while (0);

	if (h_file != NULL) {
		CloseHandle(h_file);
	}

	if (k_ctx != NULL) {
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