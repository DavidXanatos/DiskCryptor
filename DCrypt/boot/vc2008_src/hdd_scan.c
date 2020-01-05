#include "boot.h"
#include "bios.h"
#include "boot_vtab.h"
#include "hdd_scan.h"
#include "hdd.h"
#include "misc.h"
#include "boot_load.h"

int dc_find_hdds()
{
	hdd_inf *hdd;
	char     buf[SECTOR_SIZE];
	rm_ctx   ctx;	
	u8       dos;	
	int      i;

	for (i = 0; i < HDD_MAX; i++)
	{
		hdd = &btab->p_iodb->p_hdd[i];
		dos = hdd2dos(i);

		/* check for LBA support */
		btab->p_set_ctx(0x4100, &ctx);
		ctx.bx = 0x55AA; 
		ctx.dl = dos;

		if ( (btab->p_bios_call(0x13, &ctx) != 0) && 
			 (ctx.bx == 0xAA55) ) 
		{
			hdd->flags |= HDD_LBA;
		}

		btab->p_set_ctx(0x0800, &ctx);
		ctx.dl = dos;

		if ( (btab->p_bios_call(0x13, &ctx) != 0) && (ctx.ah == 0) ) {
			hdd->max_head = ctx.dh + 1;
			hdd->max_sect = ctx.cl & 0x3F;
		} else {
			hdd->max_head = 1;
			hdd->max_sect = 1;
		}
		if (btab->p_hdd_io(i, buf, 1, 0, 1) != 0) {
			hdd->flags |= HDD_OK; btab->p_iodb->n_hdd++;
		} else break;
	}
	return btab->p_iodb->n_hdd;
}

static int scan_hdd_off(int hdd_n, u64 off, u64 ext_off)
{
	u8      d_mbr[SECTOR_SIZE];
	int     found = 0;
	pt_ent *pt;
	int     i;
	u64     pt_off;
	u64     ex_off;

	do
	{
		/* read MBR */
		if (btab->p_hdd_io(hdd_n, d_mbr, 1, off + ext_off, 1) == 0) {
			break;
		}
		/* check MBR signature */
		if (p16(d_mbr+510)[0] != 0xAA55) {
			break;
		}
		for (pt = pv(d_mbr + 446), i = 4; i; i--, pt++)
		{
			if (pt->prt_size == 0) {
				continue;
			}
			pt_off = pt->start_sect;

			if ( (pt->os == 5) || (pt->os == 0x0F) ) 
			{
				if (ext_off == 0) {
					ex_off = pt_off;
					pt_off = 0;
				} else {
					ex_off = ext_off;
				}
				found += scan_hdd_off(hdd_n, pt_off, ex_off);
			} else 
			{
				if (n_parts < PART_MAX) 
				{
					p_parts[n_parts].hdd_n = hdd_n;
					p_parts[n_parts].begin = pt_off + off + ext_off;
					p_parts[n_parts].size  = pt->prt_size;
					p_parts[n_parts].flags = (pt->active == 0x80 ? PT_ACTIVE : 0) |
						                     (ext_off != 0 ? PT_EXTENDED : 0);
					n_parts++, found++;
				}
			}			
		}
	} while (0);

	return found;
}

int dc_find_partitions()
{
	int found = 0;
	int i;

	for (i = 0; i < btab->p_iodb->n_hdd; i++) {
		found += scan_hdd_off(i, 0, 0);
	}
	return found;
}