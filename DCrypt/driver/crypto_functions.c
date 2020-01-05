/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2012
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
#include <ntifs.h>
#include "driver.h"
#include "debug.h"
#include "crypto_functions.h"
#include "xts_fast.h"
#include "aes_padlock.h"
#include "xts_serpent_sse2.h"
#include "xts_serpent_avx.h"
#include "sha512_pkcs5_2.h"
#include "crc32.h"
#include "misc_mem.h"

typedef struct _XTS_TEST_CONTEXT {
	unsigned char  key[XTS_FULL_KEY];
	unsigned short test[XTS_SECTOR_SIZE*8 / sizeof(unsigned short)];
	unsigned short buff[XTS_SECTOR_SIZE*8 / sizeof(unsigned short)];
	xts_key        xkey;

} XTS_TEST_CONTEXT, *PXTS_TEST_CONTEXT;

static const struct { /* These values were obtained using Brian Gladman's XTS implementation */
	int alg;
	unsigned long e_crc;
	unsigned long d_crc;

} xts_crc_vectors[] = {
	{ CF_AES,                 0xd5faad12, 0xf78e1ee6 },
	{ CF_TWOFISH,             0x63f53fab, 0xf0bf3fe2 },
	{ CF_SERPENT,             0xc63098ff, 0xa27615ad },
	{ CF_AES_TWOFISH,         0xeb80c77a, 0x05c1f39c },
	{ CF_TWOFISH_SERPENT,     0x1f5b5c3a, 0x533b76ca },
	{ CF_SERPENT_AES,         0x1604a6b2, 0x637378c7 },
	{ CF_AES_TWOFISH_SERPENT, 0x48deea37, 0x02b2a064 }
};

static const struct {
  int          i_count;
  const char*  password;
  const char*  salt;
  int          dklen;
  const char*  key;
} pkcs5_vectors[] = {
	{ 5, "password", "\x12\x34\x56\x78", 4, "\x13\x64\xae\xf8" },
	{ 5, "password", "\x12\x34\x56\x78", 144, "\x13\x64\xae\xf8\x0d\xf5\x57\x6c\x30\xd5\x71\x4c\xa7\x75\x3f"
	                                          "\xfd\x00\xe5\x25\x8b\x39\xc7\x44\x7f\xce\x23\x3d\x08\x75\xe0"
											  "\x2f\x48\xd6\x30\xd7\x00\xb6\x24\xdb\xe0\x5a\xd7\x47\xef\x52"
											  "\xca\xa6\x34\x83\x47\xe5\xcb\xe9\x87\xf1\x20\x59\x6a\xe6\xa9"
											  "\xcf\x51\x78\xc6\xb6\x23\xa6\x74\x0d\xe8\x91\xbe\x1a\xd0\x28"
											  "\xcc\xce\x16\x98\x9a\xbe\xfb\xdc\x78\xc9\xe1\x7d\x72\x67\xce"
											  "\xe1\x61\x56\x5f\x96\x68\xe6\xe1\xdd\xf4\xbf\x1b\x80\xe0\x19"
											  "\x1c\xf4\xc4\xd3\xdd\xd5\xd5\x57\x2d\x83\xc7\xa3\x37\x87\xf4"
											  "\x4e\xe0\xf6\xd8\x6d\x65\xdc\xa0\x52\xa3\x13\xbe\x81\xfc\x30"
											  "\xbe\x7d\x69\x58\x34\xb6\xdd\x41\xc6" }
};

static void dc_simple_encryption_test()
{
	PXTS_TEST_CONTEXT ctx;
	unsigned char     dk[256];
	unsigned long     e_crc, d_crc, i;

	// test PKDBF2
	for (i = 0; i < (sizeof(pkcs5_vectors) / sizeof(pkcs5_vectors[0])); i++)
	{
		sha512_pkcs5_2(pkcs5_vectors[i].i_count,
			           pkcs5_vectors[i].password, strlen(pkcs5_vectors[i].password),
					   pkcs5_vectors[i].salt, strlen(pkcs5_vectors[i].salt),
					   dk, pkcs5_vectors[i].dklen);

		if (memcmp(dk, pkcs5_vectors[i].key, pkcs5_vectors[i].dklen) != 0)
		{
			KeBugCheckEx(STATUS_ENCRYPTION_FAILED, 'DCRP', i, 0, 0);
		}
	}
	DbgMsg("PKDBF2 test passed\n");

	// test XTS engine if memory may be allocated
	if ( (KeGetCurrentIrql() <= DISPATCH_LEVEL) &&
		 (ctx = (PXTS_TEST_CONTEXT)mm_secure_alloc(sizeof(XTS_TEST_CONTEXT))) != NULL )
	{
		// fill key and test buffer
		for (i = 0; i < (sizeof(ctx->key) / sizeof(ctx->key[0])); i++) ctx->key[i] = (unsigned char)i;
		for (i = 0; i < (sizeof(ctx->test) / sizeof(ctx->test[0])); i++) ctx->test[i] = (unsigned short)i;

		// run test cases
		for (i = 0; i < (sizeof(xts_crc_vectors) / sizeof(xts_crc_vectors[0])); i++)
		{
			xts_set_key(ctx->key, xts_crc_vectors[i].alg, &ctx->xkey);

			xts_encrypt((const unsigned char*)ctx->test, (unsigned char*)ctx->buff, sizeof(ctx->test), 0x3FFFFFFFC00, &ctx->xkey);
			e_crc = crc32((const unsigned char*)ctx->buff, sizeof(ctx->buff));

			xts_decrypt((const unsigned char*)ctx->test, (unsigned char*)ctx->buff, sizeof(ctx->test), 0x3FFFFFFFC00, &ctx->xkey);
			d_crc = crc32((const unsigned char*)ctx->buff, sizeof(ctx->buff));

			if ( e_crc != xts_crc_vectors[i].e_crc || d_crc != xts_crc_vectors[i].d_crc )
			{
				KeBugCheckEx(STATUS_ENCRYPTION_FAILED, 'DCRP', 0xFF00 | i, e_crc, d_crc);
			}
		}

		DbgMsg("XTS test passed\n");
		mm_secure_free(ctx);
	}
}

void dc_init_encryption()
{
	DbgMsg("dc_init_encryption\n");

	if (aes256_padlock_available() != 0) {
		SetFlag(dc_load_flags, DST_VIA_PADLOCK);
		DbgMsg("CpuFlags_VIA_PadLock: Yes\n");
	} else {
		ClearFlag(dc_load_flags, DST_VIA_PADLOCK);
		DbgMsg("CpuFlags_VIA_PadLock: No\n");
	}
	
	if (xts_aes_ni_available() != 0) {
		SetFlag(dc_load_flags, DST_INTEL_NI);
		DbgMsg("CpuFlags_AES_NI: Yes\n");
	} else {
		ClearFlag(dc_load_flags, DST_INTEL_NI);
		DbgMsg("CpuFlags_AES_NI: No\n");
	}

#ifdef _M_IX86
	if (xts_serpent_sse2_available() != 0) {
		SetFlag(dc_load_flags, DST_INSTR_SSE2);
		DbgMsg("CpuFlags_SSE2: Yes\n");
	} else {
		ClearFlag(dc_load_flags, DST_INSTR_SSE2);
		DbgMsg("CpuFlags_SSE2: No\n");
	}
#else
	DbgMsg("CpuFlags_SSE2: Yes\n");
	SetFlag(dc_load_flags, DST_INSTR_SSE2);
#endif

	if (xts_serpent_avx_available() != 0) {
		SetFlag(dc_load_flags, DST_INSTR_AVX);
		DbgMsg("CpuFlags_AVX: Yes\n");
	} else {
		ClearFlag(dc_load_flags, DST_INSTR_AVX);
		DbgMsg("CpuFlags_AVX: No\n");
	}

	// initialize XTS mode engine and run small encryption test
	xts_init(dc_conf_flags & CONF_HW_CRYPTO);
	dc_simple_encryption_test();
}

void dc_free_encryption()
{
}
