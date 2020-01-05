#include "boot.h"
#include "bios.h"
#include "hdd_io.h"
#include "boot_hook.h"
#include "boot_vtab.h"

static u16 intersect(u64 *i_st, u64 start1, u32 size1, u64 start2, u64 size2)
{
	u64 end, i;	
	end = min(start1 + size1, start2 + size2);
	*i_st = i = max(start1, start2);
	return d16((i < end) ? end - i : 0);
}

static boot_key *last_k;
static xts_key   benc_k;

static
int dc_crypt_io(mount_inf *mount, u8 *buff, u16 sectors, u64 start, int read, boot_key *key)
{
	int succs;

	if (key != last_k) {
		xts_set_key(key->key, key->alg, &benc_k); last_k = key;
	}
	if (read != 0)
	{
		succs = hdd_io(mount->hdd_n, buff, sectors, mount->begin + start, 1);

		if (succs != 0) {
			xts_decrypt(buff, buff, (sectors << SECT_SHIFT), (start << SECT_SHIFT), &benc_k);
		}
	} else 
	{
		/* encrypt buffer */
		xts_encrypt(buff, buff, (sectors << SECT_SHIFT), (start << SECT_SHIFT), &benc_k);

		/* write buffer to disk */
		succs = hdd_io(mount->hdd_n, buff, sectors, mount->begin + start, 0);

		/* decrypt buffer to save original data */
		xts_decrypt(buff, buff, (sectors << SECT_SHIFT), (start << SECT_SHIFT), &benc_k);	
	}
	return succs;
}

static int dc_mount_io(mount_inf *mount, u8 *buff, u16 sectors, u64 start, int read)
{
	u64 o1, o2, o3;
	u16 s1, s2, s3;
	u8 *p2, *p3; 
	int res;

	s1 = intersect(&o1, start, sectors, 0, DC_AREA_SECTORS);
	
	if (mount->flags & VF_TMP_MODE) {
		s2 = intersect(&o2, start, sectors, DC_AREA_SECTORS, (mount->tmp_size - DC_AREA_SECTORS));
		s3 = intersect(&o3, start, sectors, mount->tmp_size, mount->size);		
	} else {
		s2 = intersect(&o2, start, sectors, DC_AREA_SECTORS, mount->size);
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
			if ( (res = dc_mount_io(mount, buff, s1, mount->stor_off + o1, read)) == 0 ) {
				break;
			}
		}
		if (s2 != 0)
		{
			if ( (res = dc_crypt_io(mount, p2, s2, o2, read, mount->d_key)) == 0 ) {
				break;
			}
		}
		if (s3 != 0)
		{
			if (mount->flags & VF_REENCRYPT) {
				res = dc_crypt_io(mount, p3, s3, o3, read, mount->o_key);
			} else {
				res = hdd_io(mount->hdd_n, p3, s3, mount->begin + o3, read);
			}
		}
	} while (0);

	return res;
}

int dc_disk_io(int hdd_n, void *buff, u16 sectors, u64 start, int read)
{
	mount_inf *mount;
	u8         old[512];
	u16        ov_size;
	int        saved = 0;
	int        res   = 0;
	int        found = 0;
	int        i;

	for (i = 0; i < iodb.n_mount; i++)
	{
		if ((mount = &iodb.p_mount[i])->hdd_n != hdd_n) {
			continue;
		}		
		/* overlapped partition start IO  */
		if ( (start < mount->begin) && (start + sectors > mount->begin) ) 
		{
			ov_size = d16(mount->begin - start);
			
			res = dc_disk_io(hdd_n, buff, ov_size, start, read) && 
				  dc_disk_io(hdd_n, p8(buff) + ov_size * 512, sectors - ov_size, mount->begin, read);

			found = 1; break;
		} else 

		/* overlapped partition end IO  */
		if ( (start < mount->end) && (start + sectors > mount->end) ) 
		{
			ov_size = d16(mount->end - start);
						
			res = dc_disk_io(hdd_n, buff, ov_size, start, read) && 
				  dc_disk_io(hdd_n, p8(buff) + ov_size * 512, sectors - ov_size, mount->end, read);

			found = 1; break;
		} else

		/* normal partition IO */
		if ( (start >= mount->begin) && (start + sectors < mount->end) )
		{
			res = dc_mount_io(mount, buff, sectors, start - mount->begin, read);
			found = 1; break;
		}  
	}
	
	if (found == 0) 
	{
		/* emulate write to MBR */
		if ( !(iodb.options & OP_EXTERNAL) && (hdd_n == iodb.ldr_dsk) &&
			  (start == 0) && (read == 0) ) 
		{
			/* save old buffer */
			autocpy(old, buff, SECTOR_SIZE);
			/* read my MBR */
			hdd_io(hdd_n, buff, 1, 0, 1);
			/* copy partition table to MBR */
			autocpy(p8(buff) + 432, old + 432, 80);
			saved = 1;
		}
		res = hdd_io(hdd_n, buff, sectors, start, read);

		if (saved != 0) {
			/* restore old buffer */
			autocpy(buff, old, SECTOR_SIZE);
		}
	}
	return res;
}
