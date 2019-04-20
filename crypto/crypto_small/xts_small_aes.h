#ifndef _XTS_SMALL_AES_H_
#define _XTS_SMALL_AES_H_

#include "aes_small.h"
#include "aes_padlock_small.h"

#define CF_AES               0
#define CF_CIPHERS_NUM       1

#define XTS_SECTOR_SIZE      512
#define XTS_BLOCK_SIZE       16
#define XTS_BLOCKS_IN_SECTOR (XTS_SECTOR_SIZE / XTS_BLOCK_SIZE)
#define XTS_KEY_SIZE         32

#define MAX_CIPHER_KEY  (sizeof(aes256_key))
#define XTS_FULL_KEY    (XTS_KEY_SIZE*2)

typedef __declspec(align(16)) struct _xts_key {
	aes256_key crypt_k;
	aes256_key tweak_k;
} xts_key;

void xts_aes_set_key(const unsigned char *key, int alg, xts_key *skey);
void xts_aes_encrypt(const unsigned char *in, unsigned char *out, unsigned long len, unsigned __int64 offset, xts_key *key);
void xts_aes_decrypt(const unsigned char *in, unsigned char *out, unsigned long len, unsigned __int64 offset, xts_key *key);
void xts_aes_init(int hw_crypt);

typedef void (*xts_setkey_proc)(const unsigned char *key, int alg, xts_key *skey);
typedef void (*xts_crypt_proc) (const unsigned char *in, unsigned char *out, unsigned long len, unsigned __int64 offset, xts_key *key);
typedef void (*xts_init_proc)  (int hw_crypt);

#define xts_set_key xts_aes_set_key
#define xts_encrypt xts_aes_encrypt
#define xts_decrypt xts_aes_decrypt
#define xts_init    xts_aes_init

#endif