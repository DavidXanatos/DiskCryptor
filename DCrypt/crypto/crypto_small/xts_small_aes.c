/*
    *
    * Copyright (c) 2010-2012
    * ntldr <ntldr@diskcryptor.net> PGP key ID - 0xC48251EB4F8E4E6E
    * based on rijndael-alg-fst.c
    *  @author Vincent Rijmen <vincent.rijmen@esat.kuleuven.ac.be>
    *  @author Antoon Bosselaers <antoon.bosselaers@esat.kuleuven.ac.be>
    *  @author Paulo Barreto <paulo.barreto@terra.com.br>
	*  @author Serge Trusov <serge.trusov@gmail.com>
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
#include "xts_small_aes.h"

typedef __declspec(align(1)) union _m128 {
    unsigned long    v32[4];    
    unsigned __int64 v64[2];    
} m128;

typedef void (*encrypt_p)(const unsigned char *in, unsigned char *out, void *key);

static encrypt_p aes_encrypt = (encrypt_p) aes256_encrypt;
static encrypt_p aes_decrypt = (encrypt_p) aes256_decrypt;

static void xts_process(const unsigned char *in, unsigned char *out, unsigned long len, unsigned __int64 offset, encrypt_p crypt_p, xts_key *key)
{
	__declspec(align(16)) unsigned char tmp[XTS_BLOCK_SIZE];
	__declspec(align(16)) m128 t, idx;
	unsigned long         i, cf;
	
	idx.v64[0] = offset / XTS_SECTOR_SIZE;
	idx.v64[1] = 0;

	for (; len; len -= XTS_SECTOR_SIZE)
	{
#ifdef _M_IX86
		if (aes_encrypt == (encrypt_p) aes256_padlock_encrypt) {
			aes256_padlock_rekey();
		}
#endif
		/* update tweak unit index */
		idx.v64[0]++;
		/* derive first tweak value */
		aes_encrypt((unsigned char*)&idx, (unsigned char*)&t, &key->tweak_k);
#ifdef _M_IX86
		if (aes_encrypt == (encrypt_p) aes256_padlock_encrypt) {
			aes256_padlock_rekey();
		}
#endif
		for (i = 0; i < XTS_BLOCKS_IN_SECTOR; i++)
		{
			((unsigned __int64*)tmp)[0] = ((unsigned __int64*)in)[0] ^ t.v64[0];
			((unsigned __int64*)tmp)[1] = ((unsigned __int64*)in)[1] ^ t.v64[1];
			
			crypt_p(tmp, tmp, &key->crypt_k);

			((unsigned __int64*)out)[0] = ((unsigned __int64*)tmp)[0] ^ t.v64[0];
			((unsigned __int64*)out)[1] = ((unsigned __int64*)tmp)[1] ^ t.v64[1];

			/* update pointers */
			in += XTS_BLOCK_SIZE; out += XTS_BLOCK_SIZE;
			/* derive next tweak value */
			cf = (t.v32[3] >> 31) * 135;
			t.v64[1] <<= 1;
			t.v32[2] |= t.v32[1] >> 31;
			t.v64[0] <<= 1;
			t.v32[0] ^= cf;
		}
	}
}

void xts_aes_set_key(const unsigned char *key, int alg, xts_key *skey) {
	aes256_set_key(key, &skey->crypt_k);
	aes256_set_key(key + XTS_KEY_SIZE, &skey->tweak_k);
}
void xts_aes_encrypt(const unsigned char *in, unsigned char *out, unsigned long len, unsigned __int64 offset, xts_key *key) {
	xts_process(in, out, len, offset, aes_encrypt, key);
}
void xts_aes_decrypt(const unsigned char *in, unsigned char *out, unsigned long len, unsigned __int64 offset, xts_key *key) {
	xts_process(in, out, len, offset, aes_decrypt, key);
}

void xts_aes_init(int hw_crypt)
{
	aes256_gentab();
#ifdef _M_IX86
	if ( (hw_crypt != 0) && (aes256_padlock_available() != 0) ) {
		aes_encrypt = (encrypt_p) aes256_padlock_encrypt;
		aes_decrypt = (encrypt_p) aes256_padlock_decrypt;
	}
#endif
}