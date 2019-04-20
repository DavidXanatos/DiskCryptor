#if !defined(_AES_PADLOCK_SMALL_H_) && defined(_M_IX86)
#define _AES_PADLOCK_SMALL_H_

#include "aes_small.h"

static void __forceinline aes256_padlock_rekey() {
	__asm {
		 pushfd
		 popfd
	 }
}

int  aes256_padlock_available();
void aes256_padlock_encrypt(const unsigned char *in, unsigned char *out, aes256_key *key);
void aes256_padlock_decrypt(const unsigned char *in, unsigned char *out, aes256_key *key);

#endif