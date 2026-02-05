#ifndef _CRYPTO_HEAD_H_
#define _CRYPTO_HEAD_H_

#include "volume_header.h"
#ifdef _M_ARM64
#include "xts_small.h"
#else
#include "xts_fast.h"
#endif

int cp_decrypt_header(xts_key *hdr_key, dc_header *header, dc_pass *password);
int cp_set_header_key(xts_key *hdr_key, u8 salt[PKCS5_SALT_SIZE], int cipher, dc_pass *password);

#endif