#ifndef _DATA_WIPE_
#define _DATA_WIPE_

#include "prng.h"

typedef struct _wipe_mode {
	int passes; /* number of wipe passes */
	struct {
		int type;    /* pass type      */		
		u8  patt[3]; /* pattern data   */
	} pass[];
} wipe_mode;

#define P_PAT   0 /* three-byte pattern   */
#define P_RAND  1 /* random data        */

typedef struct wipe_ctx {
	xts_key   *key;
	wipe_mode *mode;
	void      *hook;
	u8        *buff;
	int        size;
	u64        offs;

} wipe_ctx;

int  dc_wipe_init(wipe_ctx *ctx, void *hook, int max_size, int method, int cipher);
int  dc_wipe_process(wipe_ctx *ctx, u64 offset, int size);
void dc_wipe_free(wipe_ctx *ctx);

#endif