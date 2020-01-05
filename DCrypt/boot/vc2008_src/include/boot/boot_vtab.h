#ifndef _BOOT_VTAB_H_
#define _BOOT_VTAB_H_

#ifdef AES_ONLY
 #include "xts_small_aes.h"
#else
 #include "xts_small.h"
#endif
#include "bios.h"
#include "boot_hook.h"
#include "hdd.h"
#include "hdd_io.h"

typedef struct _boot_vtab {
	xts_setkey_proc p_xts_set_key;
	xts_crypt_proc  p_xts_encrypt;
	xts_crypt_proc  p_xts_decrypt;
	xts_init_proc   p_xts_init;
	set_ctx_proc    p_set_ctx;
	bios_call_proc  p_bios_call;	
	phddio          p_hdd_io;
	phddio          p_dc_io;
	io_db          *p_iodb;
} boot_vtab;

extern boot_vtab *btab;
extern bd_data   *bdat;

#endif