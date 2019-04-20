/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2007-2011
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
#include "defines.h"
#include "driver.h"
#include "xts_fast.h"
#include "prng.h"
#include "fast_crypt.h"
#include "benchmark.h"
#include "misc_mem.h"

#define TEST_BLOCK_LEN (1024*1024*8)
#define TEST_BLOCK_NUM (4)

int dc_k_benchmark(int cipher, dc_bench_info *info)
{
	UCHAR    dkey[DISKKEY_SIZE];	
	xts_key* xkey = NULL;
	PUCHAR   buff = NULL;
	int      resl = ST_NOMEM, i;
	u64      offs = 0, time;

	/* allocate memory */
	if ( (buff = mm_pool_alloc(TEST_BLOCK_LEN)) == NULL ) goto exit;
	if ( (xkey = mm_secure_alloc(sizeof(xts_key))) == NULL ) goto exit;
	
	/* setup initial test block and key */
	for (i = 0; i < TEST_BLOCK_LEN; i++) buff[i] = i % 256;
	for (i = 0; i < DISKKEY_SIZE; i++) dkey[i] = i % 256;
	xts_set_key(dkey, cipher, xkey);
	/* query perfomance frequency */
	KeQueryPerformanceCounter((PLARGE_INTEGER)&info->cpufreq);
	if (info->cpufreq == 0) goto exit;

	/* repeat benchmark some times */
	for (info->enctime = 0, info->datalen = 0; ((info->enctime * 10) / info->cpufreq) < 5;)
	{
		/* do benchmark */
		time = KeQueryPerformanceCounter(NULL).QuadPart;

		for (i = 0; i < TEST_BLOCK_NUM; i++) {
			cp_fast_encrypt(buff, buff, TEST_BLOCK_LEN, offs, xkey);
			offs += TEST_BLOCK_LEN;
		}
		info->enctime += KeQueryPerformanceCounter(NULL).QuadPart - time;
		info->datalen += TEST_BLOCK_LEN * TEST_BLOCK_NUM;
	}
	resl = ST_OK;
exit:
	if (buff != NULL) mm_pool_free(buff);
	if (xkey != NULL) mm_secure_free(xkey);
	return resl;
}