/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2008 
    * ntldr <ntldr@diskcryptor.net> PGP key ID - 0xC48251EB4F8E4E6E
    *

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "boot.h"
#include "bios.h"
#include "misc.h"
#include "hdd.h"
#include "crypto.h"
#include "malloc.h"

list_entry hdd_head;
list_entry prt_head;

static 
int hdd_chs_io(
	   u8 dos_numb, void *buff, u16 sectors, u16 cyl, u8 head, u8 sect, int read)
{
	rm_ctx ctx;

	/* setup initial context */
	set_ctx(0, &ctx);

	ctx.ah = read ? 0x02:0x03;
	ctx.al = d8(sectors);
	ctx.ch = d8(cyl);
	ctx.cl = d8(((cyl & 0x0300) >> 2) | sect);
    ctx.dh = head; 
	ctx.dl = dos_numb;
	ctx.es = rm_seg(buff);
	ctx.bx = rm_off(buff);

	/* do not check AH because some buggy USB BIOSes fail to clear AH on success */
	return bios_call(0x13, &ctx);
}

static 
int hdd_lba_io(
	   u8 dos_numb, void *buff, u16 sectors, u64 start, int read)
{
	u8     sbuf[32];
	rm_ctx ctx;
	lba_p *lba = pv(0x580); /* this needed for avoid stupid actions by buggy BIOSes */
	int    succs = 0;

	/* save old buffer */	
	autocpy(sbuf, lba, sizeof(sbuf));

	/* setup LBA block */
	lba->size    = sizeof(lba_p);
	lba->unk     = 0;
	lba->dst_sel = rm_seg(buff);
	lba->dst_off = rm_off(buff);
	lba->numb    = sectors; 
	lba->sector  = start;

	/* setup initial context */
	set_ctx(0, &ctx);
	ctx.ah = read ? 0x42:0x43;
	ctx.dl = dos_numb; 
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
	
	return succs;
}

static int hdd_is_lba(u8 dos_numb)
{
	rm_ctx ctx;
	int    is_lba = 0;

	/* check for LBA support */
	set_ctx(0x4100, &ctx);
	ctx.bx = 0x55AA; 
	ctx.dl = dos_numb;

	if (bios_call(0x13, &ctx) != 0) {
		is_lba = (ctx.bx == 0xAA55);
	}
	
	return is_lba;
}

static void hdd_get_geometry(hdd_inf *hdd)
{
	rm_ctx ctx;

	set_ctx(0x0800, &ctx); 
	ctx.dl = hdd->dos_numb;
	
	if ( (bios_call(0x13, &ctx) != 0) && (ctx.ah == 0) ) {
		hdd->max_head = ctx.dh + 1;
		hdd->max_sect = ctx.cl & 0x3F;
	} else {
		hdd->max_head = 1;
		hdd->max_sect = 1;
	}
}

int dc_bios_io(
	  hdd_inf *hdd, void *buff, u16 sectors, u64 start, int read)
{
	u32 soff, head;
	u32 hoff, coff;
	
	if (hdd->lba_mode == 0)
	{
		soff = d32(start) % hdd->max_sect + 1;
		head = d32(start) / hdd->max_sect;
		hoff = head % hdd->max_head;
		coff = head / hdd->max_head;
		
		return hdd_chs_io(
			hdd->dos_numb, buff, sectors, d16(coff), d8(hoff), d8(soff), read);
	} else {
		return hdd_lba_io(hdd->dos_numb, buff, sectors, start, read);
	}
}

static int dc_find_hdds() 
{
	hdd_inf *hdd;
	u8      *mbr = pv(0x5000); /* free memory location */
	int      num = 0;
	int      i, lba;

	/* detect all HDDs */
	for (i = 0x80; i < 0x8F; i++) 
	{
		/* probe to read drive MBR  */
		if (lba = hdd_is_lba(i))
		{
			if (hdd_lba_io(i, mbr, 1, 0, 1) == 0) {
				break; /* no more HDDs */
			}
		} else
		{
			if (hdd_chs_io(i, mbr, 1, 0, 0, 1, 1) == 0) {
				break; /* no more HDDs */
			}
		}
		
		/* insert HDD to list */
		hdd = malloc(sizeof(hdd_inf));
		hdd->dos_numb = i;
		hdd->lba_mode = lba;
		_init_list_head(&hdd->part_head);
		_insert_tail_list(&hdd_head, &hdd->entry);
		/* get drive geometry */
		hdd_get_geometry(hdd);
		/* increase number of detected drives */
		num++; 
	}

	return num;	
}

hdd_inf *find_hdd(u8 num)
{
	list_entry *entry;
	hdd_inf    *hdd;

	/* find HDD */
	entry = hdd_head.flink;

	while (entry != &hdd_head)
	{
		hdd   = contain_record(entry, hdd_inf, entry);
		entry = entry->flink;

		if (hdd->dos_numb == num) {
			return hdd;
		}
	}

	return NULL;
}

static int scan_hdd_off(hdd_inf *hdd, u64 off, u64 ext_off, int level)
{
	u8      *mbr = pv(0x5000 + (level << SECT_SHIFT)); /* free memory location */
	pt_ent  *pt;
	prt_inf *prt;
	int      num;
	int      found = 0;
	u64      pt_off;
	u64      ex_off;

	do
	{
		/* read MBR */
		if (dc_bios_io(hdd, mbr, 1, off + ext_off, 1) == 0) {
			break;
		}

		/* check MBR signature */
		if (p16(mbr+510)[0] != 0xAA55) {
			break;
		}

		pt = (void *)(mbr + 446);

		for (num = 4; num; num--, pt++)
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

				found += scan_hdd_off(hdd, pt_off, ex_off, ++level);
			} else 
			{
				prt = malloc(sizeof(prt_inf));
				zeroauto(prt, sizeof(prt_inf));
				prt->begin  = pt_off + off + ext_off;
				prt->end    = prt->begin + pt->prt_size;
				prt->size   = pt->prt_size;
				prt->active = (pt->active == 0x80);
				prt->extend = (ext_off != 0);			
				prt->hdd    = hdd; found++;

				_insert_tail_list(&hdd->part_head, &prt->entry_hdd);
				_insert_tail_list(&prt_head, &prt->entry_glb);				
			}			
		}
	} while (0);

	return found;
}

static u16 intersect(u64 *i_st, u64 start1, u32 size1, u64 start2, u64 size2)
{
	u64 end, i;	
	end = min(start1 + size1, start2 + size2);
	*i_st = i = max(start1, start2);
	return d16((i < end) ? end - i : 0);
}

static boot_key *last_k;
static dc_key    benc_k;

static
int dc_partition_enc_io(
	  prt_inf *prt, u8 *buff, u16 sectors, u64 start, int read, boot_key *key
	  )
{
	int res;

	if (key != last_k) 
	{
		dc_cipher_init(
			&benc_k, key->alg, key->key_d);
		last_k = key;
	}

	if (read != 0)
	{
		res = dc_bios_io(
			prt->hdd, buff, sectors, prt->begin + start, 1);

		if (res != 0) {
			dc_cipher_decrypt(buff, buff, (sectors << SECT_SHIFT), (start << SECT_SHIFT), &benc_k);
		}
	} else 
	{
		/* encrypt buffer */
		dc_cipher_encrypt(buff, buff, (sectors << SECT_SHIFT), (start << SECT_SHIFT), &benc_k);

		/* write buffer to disk */
		res = dc_bios_io(
			prt->hdd, buff, sectors, start + prt->begin, 0);

		/* decrypt buffer to save original data */
		dc_cipher_decrypt(buff, buff, (sectors << SECT_SHIFT), (start << SECT_SHIFT), &benc_k);	
	}

	return res;
}

int dc_partition_io(
	  prt_inf *prt, u8 *buff, u16 sectors, u64 start, int read
	  )
{
	u64 o1, o2, o3;
	u16 s1, s2, s3;
	u8 *p2, *p3; 
	int res;

	if (prt->mnt_ok == 0)
	{
		return dc_bios_io(
			prt->hdd, buff, sectors, prt->begin + start, read);
	}

	s1 = intersect(&o1, start, sectors, 0, DC_AREA_SECTORS);
	
	if (prt->flags & VF_TMP_MODE) {
		s2 = intersect(&o2, start, sectors, DC_AREA_SECTORS, (prt->tmp_size - DC_AREA_SECTORS));
		s3 = intersect(&o3, start, sectors, prt->tmp_size, prt->size);		
	} else {
		s2 = intersect(&o2, start, sectors, DC_AREA_SECTORS, prt->size);
		s3 = 0;
	}
	p2 = buff + (s1 * SECTOR_SIZE);
	p3 = p2   + (s2 * SECTOR_SIZE);

	/*
	   normal mode:
	    o1:s1 - redirected part
		o2:s2 - encrypted part
		o3:s3 - unencrypted part
	   reencrypt mode:
	   o1:s1 - redirected part
	   o2:s2 - key_1 encrypted part
	   o3:s3 - key_2 encrypted part
	*/
	do
	{
		if (s1 != 0)
		{
			res = dc_partition_io(
				prt, buff, s1, prt->stor_off + o1, read);

			if (res == 0) {
				break;
			}
		}

		if (s2 != 0)
		{
			res = dc_partition_enc_io(
				prt, p2, s2, o2, read, &prt->d_key);

			if (res == 0) {
				break;
			}
		}

		if (s3 != 0)
		{
			if (prt->flags & VF_REENCRYPT) 
			{
				res = dc_partition_enc_io(
					prt, p3, s3, o3, read, &prt->o_key);
			} else 
			{
				res = dc_bios_io(
					prt->hdd, p3, s3, prt->begin + o3, read);
			}
		}
	} while (0);

	return res;
}


int dc_disk_io(
	  hdd_inf *hdd, void *buff, u16 sectors, u64 start, int read
	  )
{
	list_entry *entry;
	prt_inf    *prt;
	u8          old[512];
	u16         ov_size;
	int         saved = 0;
	int         res   = 0;
	int         found = 0;

	entry = hdd->part_head.flink;

	while (entry != &hdd->part_head)
	{
		prt   = contain_record(entry, prt_inf, entry_hdd);
		entry = entry->flink;

		/* overlapped partition start IO  */
		if ( (start < prt->begin) && (start + sectors > prt->begin) ) 
		{
			ov_size = (u16)(prt->begin - start);
			
			res = dc_disk_io(hdd, buff, ov_size, start, read) && 
				  dc_disk_io(hdd, p8(buff) + ov_size * 512,  
				    sectors - ov_size, prt->begin, read);

			found = 1; break;
		} else 

		/* overlapped partition end IO  */
		if ( (start < prt->end) && (start + sectors > prt->end) ) 
		{
			ov_size = (u16)(prt->end - start);
						
			res = dc_disk_io(hdd, buff, ov_size, start, read) && 
				  dc_disk_io(hdd, p8(buff) + ov_size * 512,
				    sectors - ov_size, prt->end, read);

			found = 1; break;
		} else

		/* normal partition IO */
		if ( (start >= prt->begin) && (start + sectors < prt->end) )
		{
			res = dc_partition_io(
				prt, buff, sectors, start - prt->begin, read);
			found = 1; break;
		}  
	}

	if (found == 0) 
	{
		/* emulate write to MBR */
		if ( !(conf.options & OP_EXTERNAL) && (hdd->dos_numb == boot_dsk) &&
			  (start == 0) && (read == 0) ) 
		{
			/* save old buffer */
			autocpy(old, buff, SECTOR_SIZE);
			/* read my MBR */
			dc_bios_io(hdd, buff, 1, 0, 1);
			/* copy partition table to MBR */
			autocpy(p8(buff) + 432, old + 432, 80);
			saved = 1;
		}

		res = dc_bios_io(hdd, buff, sectors, start, read);

		if (saved != 0) {
			/* restore old buffer */
			autocpy(buff, old, SECTOR_SIZE);
		}
	}

	return res;
}

int dc_scan_partitions()
{
	list_entry *entry;
	hdd_inf    *hdd;
	int         found = 0;

	/* initialize lists */
	_init_list_head(&hdd_head);
	_init_list_head(&prt_head);

	/* find all HDDs */
	if (dc_find_hdds() != 0)
	{
		/* find all partitions on HDD */
		entry = hdd_head.flink;

		while (entry != &hdd_head)
		{
			hdd   = contain_record(entry, hdd_inf, entry);
			entry = entry->flink;
			found += scan_hdd_off(hdd, 0, 0, 0);
		}
	}

	return found;
}
