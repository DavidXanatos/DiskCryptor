#ifndef _CRYPTO_HEAD_H_
#define _CRYPTO_HEAD_H_

#include "volume_header.h"
#include "xts_fast.h"

int  cp_decrypt_header(xts_key *hdr_key, dc_header *header, dc_pass *password);
void cp_set_header_key(xts_key *hdr_key, u8 salt[PKCS5_SALT_SIZE], int cipher, dc_pass *password);

#endif