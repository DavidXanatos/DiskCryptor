#include <windows.h>
#include "xts_small_aes.h"
#include "xts_aes_test.h"

#ifndef SMALL_CODE
	#error Unsupported
#endif

static unsigned long crc32(const unsigned char *p, unsigned long len)
{
	unsigned long crc = 0xFFFFFFFF;
	unsigned long temp;
	int j;

	while (len--)
	{
		temp = (unsigned long)((crc & 0xFF) ^ *p++);
		for (j = 0; j < 8; j++) temp = (temp >> 1) ^ (temp & 1 ? 0xEDB88320 : 0);
		crc = (crc >> 8) ^ temp;
	}
	return crc ^ 0xFFFFFFFF;
}

static int do_test_aes_xts()
{
	unsigned char  key[XTS_FULL_KEY];
	unsigned short test[XTS_SECTOR_SIZE*8 / sizeof(unsigned short)];
	unsigned short buff[XTS_SECTOR_SIZE*8 / sizeof(unsigned short)];
	xts_key xkey;
	int     i;

	// fill key and test buffer
	for (i = 0; i < _countof(key); i++) key[i] = i;
	for (i = 0; i < _countof(test); i++) test[i] = i;

	// do test
	xts_aes_set_key(key, CF_AES, &xkey);
	
	xts_aes_encrypt((const unsigned char*)test, (unsigned char*)buff, sizeof(test), 0x3FFFFFFFC00, &xkey);
	if (crc32((const unsigned char*)buff, sizeof(buff)) != 0xd5faad12) return 0;

	xts_aes_decrypt((const unsigned char*)test, (unsigned char*)buff, sizeof(test), 0x3FFFFFFFC00, &xkey);
	if (crc32((const unsigned char*)buff, sizeof(buff)) != 0xf78e1ee6) return 0;

	return 1;
}

int test_xts_aes_only()
{
	xts_aes_init(0);
	if (do_test_aes_xts() == 0) return 0;

	xts_aes_init(1);
	if (do_test_aes_xts() == 0) return 0;

	return 1;
}
