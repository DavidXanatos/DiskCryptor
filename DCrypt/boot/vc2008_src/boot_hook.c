/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2008-2009 
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

#include "boot.h"
#include "bios.h"
#include "boot_vtab.h"
#include "hdd.h"
#include "dc_io.h"

boot_vtab *btab;
bd_data   *bdat;
io_db      iodb;

void set_ctx(u16 ax, rm_ctx *ctx)
{
	/* zero all registers */
	zeroauto(ctx, sizeof(rm_ctx));
	/* set initial segments */
	ctx->ds = rm_seg(bdat->bd_base);
	ctx->es = ctx->ds;
	/* set AX value */
	ctx->ax = ax;
}

int bios_call(int num, rm_ctx *ctx)
{
	/* copy initial context to real mode buffer */
	if (ctx != NULL) {
		autocpy(&bdat->rmc, ctx, sizeof(rm_ctx));
	}
	/* get interrupt seg/off */
	if ( (num == 0x13) && (bdat->old_int13 != 0) ) {
		bdat->segoff = bdat->old_int13;
	} else {
		bdat->segoff = p32(0)[num];
	}
	bdat->rmc.efl = FL_IF;
	/* call to real mode */
	bdat->call_rm();
	
	/* copy changed context */
	if (ctx != NULL) {
		autocpy(ctx, &bdat->rmc, sizeof(rm_ctx));
	}
	return (bdat->rmc.efl & FL_CF) == 0;
}

static void int13_callback()
{
	rm_ctx ctx;
	u16      p_efl = bdat->push_fl;
	int      need  = 0;
	hdd_inf *hdd   = NULL;
	lba_p   *lba   = NULL;
	void    *buff;
	u16      numb;
	u64      start;
	int      hdd_n;

	if (bdat->rmc.dl == 0x80) {
		bdat->rmc.dl = bdat->boot_dsk;
	} else if (bdat->rmc.dl == bdat->boot_dsk) {
		bdat->rmc.dl = 0x80;
	}
	/* copy context to temporary buffer */
	autocpy(&ctx, &bdat->rmc, sizeof(rm_ctx));

	if ( ((hdd_n = dos2hdd(ctx.dl)) >= 0) && (hdd_n < iodb.n_hdd) ) {
		hdd = &iodb.p_hdd[hdd_n];
	}
	if (hdd != NULL)
	{
		if ( (ctx.ah == 0x02) || (ctx.ah == 0x03) )
		{
			start = ((ctx.ch + ((ctx.cl & 0xC0) << 2)) * 
				    hdd->max_head + ctx.dh) * hdd->max_sect + (ctx.cl & 0x3F) - 1;
			buff  = pm_off(ctx.es, ctx.bx);
			numb  = ctx.al;
			need  = 1; 
		}
		if ( (ctx.ah == 0x42) || (ctx.ah == 0x43) )
		{
			lba   = pm_off(ctx.ds, ctx.si);
			start = lba->sector;
			buff  = pm_off(lba->dst_sel, lba->dst_off);
			numb  = lba->numb;
			need  = 1; 
		}
	}

	if (need != 0) 
	{
		if (dc_disk_io(hdd_n, buff, numb, start, (ctx.ah == 0x02) || (ctx.ah == 0x42)) != 0) 
		{
			ctx.ah   = 0;
			ctx.efl &= ~FL_CF;

			if (lba != NULL) {
				lba->numb = numb;
			} else {
				ctx.al = d8(numb);
			}
		} else {
			ctx.efl |= FL_CF;
		}		
		/* setup new context */
		autocpy(&bdat->rmc, &ctx, sizeof(rm_ctx));
	} else 
	{
		/* interrupt is not processed, call original handler */
		bdat->rmc.efl = FL_IF; /* enable interrupts */
		bdat->segoff  = bdat->old_int13;
		bdat->call_rm();		
	}
	/* copy saved interrupt flag to exit context */
	bdat->rmc.efl = (bdat->rmc.efl & ~FL_IF) | (p_efl & FL_IF);
}

void boot_hook_main(bd_data *db, boot_vtab *vt)
{
	bdat = db, btab = vt;
	/* setup boot_vtab table */
	vt->p_xts_set_key = xts_set_key;
	vt->p_xts_encrypt = xts_encrypt;
	vt->p_xts_decrypt = xts_decrypt;
	vt->p_xts_init    = xts_init;
	vt->p_set_ctx     = set_ctx;
	vt->p_bios_call   = bios_call;	
	vt->p_hdd_io      = hdd_io;
	vt->p_dc_io       = dc_disk_io;
	vt->p_iodb        = &iodb;
	/* setup initial pointers */
	db->int_cbk = int13_callback;
}
