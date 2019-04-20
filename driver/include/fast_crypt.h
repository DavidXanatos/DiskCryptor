#ifndef _FAST_CRYPT_
#define _FAST_CRYPT_

int  cp_init_fast_crypt();
void cp_free_fast_crypt();

#define F_MIN_REQ      2048 /* minimum block size for one request */
#define F_OP_THRESOLD  4096 /* parallelized crypt thresold */

typedef void (*fc_callback)(void*);

void cp_parallelized_crypt(
	   int   is_encrypt, xts_key *key, fc_callback on_complete, 
	   void *param, const unsigned char *in, unsigned char *out, u32 len, u64 offset);

void cp_fast_crypt_op(
		int   is_encrypt, xts_key *key,
		const unsigned char *in, unsigned char *out, u32 len, u64 offset);

#define cp_fast_encrypt(in, out, len, offset, key) cp_fast_crypt_op(1, key, in, out, len, offset)
#define cp_fast_decrypt(in, out, len, offset, key) cp_fast_crypt_op(0, key, in, out, len, offset)

#endif