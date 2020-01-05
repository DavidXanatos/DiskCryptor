#include "boot.h"
#include "bios.h"
#include "hdd_io.h"
#include "boot_hook.h"

int hdd_io(int hdd_n, void *buff, u16 sectors, u64 start, int read)
{
	u8       sbuf[32];
	rm_ctx   ctx;
	u32      head, cyl;
	u8       dos_n = hdd2dos(hdd_n);
	hdd_inf *hdd   = &iodb.p_hdd[hdd_n];
	lba_p   *lba   = pv(0x580); /* this needed for avoid stupid actions by buggy BIOSes */	
	int      succs = 0;

	/* setup initial context */
	set_ctx(0, &ctx);

	if (hdd->flags & HDD_LBA)
	{
		/* save old buffer */
		autocpy(sbuf, lba, sizeof(sbuf));

		/* setup LBA block */
		lba->size    = sizeof(lba_p);
		lba->unk     = 0;
		lba->dst_sel = rm_seg(buff);
		lba->dst_off = rm_off(buff);
		lba->numb    = sectors; 
		lba->sector  = start;
		
		ctx.ah = read ? 0x42:0x43;
		ctx.dl = dos_n; 
		ctx.si = 0x180; 
		ctx.ds = 0x40; /* if DS can be 0x40, we can avoid AWARD BIOS bug of int13/AX=4B01 */ 
		/* set additional registers to serve buggy BIOSes. */
		ctx.es = ctx.ds;
		ctx.di = ctx.si;
		ctx.bx = ctx.si;
		ctx.cx = ctx.ds;
		/* do not check AH because some buggy USB BIOSes fail to clear AH on success */
		succs = bios_call(0x13, &ctx);

		/* restore saved buffer */
		autocpy(lba, sbuf, sizeof(sbuf));
	} else
	{
		head = d32(start) / hdd->max_sect;		
		cyl  = head / hdd->max_head;

		ctx.ah = read ? 0x02:0x03;
		ctx.al = d8(sectors);
		ctx.ch = d8(cyl);
		ctx.cl = d8(((cyl & 0x0300) >> 2) | (d32(start) % hdd->max_sect + 1));
		ctx.dh = head % hdd->max_head;
		ctx.dl = dos_n;
		ctx.es = rm_seg(buff);
		ctx.bx = rm_off(buff);

		/* do not check AH because some buggy USB BIOSes fail to clear AH on success */
		succs = bios_call(0x13, &ctx);
	}
	return succs;
}