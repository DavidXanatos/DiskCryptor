#include "crc32.h"

int test_crc32()
{
	unsigned long test[256], i;
	
	for (i = 0; i < 256; i++) test[i] = i;
	if (crc32((const unsigned char*)test, sizeof(test)) != 0xf0e359bb) return 0;
	return 1;
}