/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2008-2009
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
#include "kbd_layout.h"
#include "pkcs5.h"
#include "malloc.h"
#include "sha512.h"

ldr_config conf = {
	CFG_SIGN1, CFG_SIGN2,
	DC_BOOT_VER, 
	LT_GET_PASS | LT_MESSAGE | LT_DSP_PASS,
	ET_MESSAGE | ET_RETRY,
	BT_MBR_BOOT,
	0, 
	OP_HW_CRYPTO,  /* options         */
	KB_QWERTY,     /* keyboard layout */
	"enter password: ",
	"password incorrect\n",
	{ 0 }, 
	0, /* timeout */
	{ 0 } /* embedded key */
};

extern bd_data *bd_dat;
       u8       boot_dsk;

int on_int13(rm_ctx *ctx)
{
	hdd_inf *hdd;
	void    *buff;
	lba_p   *lba = NULL;
	u16      numb;
	u64      start;
	int      need = 0;
	int      res;
	u8       func;

	if (hdd = find_hdd(ctx->dl)) 
	{
		func = ctx->ah;

		if ( (func == 0x02) || (func == 0x03) )
		{
			start = ((ctx->ch + ((ctx->cl & 0xC0) << 2)) * 
				     hdd->max_head + ctx->dh) * hdd->max_sect + (ctx->cl & 0x3F) - 1;
			buff  = pm_off(ctx->es, ctx->bx);
			numb  = ctx->al;
			need  = 1; 
		}

		if ( (func == 0x42) || (func == 0x43) )
		{
			lba   = pm_off(ctx->ds, ctx->si);
			start = lba->sector;
			buff  = pm_off(lba->dst_sel, lba->dst_off);
			numb  = lba->numb;
			need  = 1; 
		}
	}

	if (need != 0) 
	{
		res = dc_disk_io(
			    hdd, buff, numb, start, 
				(func == 0x02) || (func == 0x42));

		if (res != 0) 
		{
			ctx->ah   = 0;
			ctx->efl &= ~FL_CF;

			if (lba != NULL) {
				lba->numb = numb;
			} else {
				ctx->al = d8(numb);
			}
		} else {
			ctx->efl |= FL_CF;
		}
	}

	return need;
}

static int dc_get_password() 
{
	u32 s_time;
	u32 pos;
	u8  ch;	

	/* clear keyboard buffer */
	while (_kbhit() != 0) {
		_getch();
	}

	if (conf.logon_type & LT_MESSAGE) {
		puts(conf.eps_msg);
	}

	if (conf.options & OP_EPS_TMO) {
		s_time = get_rtc_time();
	}

	for (pos = 0;;)
	{
		if (conf.options & OP_EPS_TMO)
		{
			do
			{
				if (get_rtc_time() - s_time >= conf.timeout) {
					pos = 0; goto ep_exit;
				}
			} while (_kbhit() == 0);

			if (conf.options & OP_TMO_STOP) {
				conf.options &= ~OP_EPS_TMO;
			}
		}

		ch = _getch();

		if (conf.kbd_layout == KB_QWERTZ) {
			ch = to_qwertz(ch);
		}

		if (conf.kbd_layout == KB_AZERTY) {
			ch = to_azerty(ch);
		}

		if (ch == '\r') {
			break;
		}

		if (ch == 8) 
		{
			if (pos > 0) 
			{
				if (conf.logon_type & LT_DSP_PASS) {
					puts("\x8 \x8");
				}
				bd_dat->password.pass[--pos] = 0;
			}			
			continue;
		}

		if ( (ch < ' ') || (ch > '~') || (pos == MAX_PASSWORD) ) {
			continue;
		}

		bd_dat->password.pass[pos++] = ch;

		if (conf.logon_type & LT_DSP_PASS) {
			_putch('*');
		}
	}
ep_exit:;
	if (conf.logon_type & LT_DSP_PASS) {
		_putch('\n');
	}

	bd_dat->password.size = pos * 2; 

	/* clear BIOS keyboard buffer to prevent password leakage */
	/* see http://www.ouah.org/Bios_Information_Leakage.txt for more details */
	zeroauto(pv(0x41E), 32);

	return (pos != 0);
}


static int dc_mount_parts()
{
	dc_header  *header  = pv(0x5000); /* free memory location */
	dc_key     *hdr_key = pv(0x5000 + sizeof(dc_header));
	list_entry *entry;
	prt_inf    *prt;
	int         n_mount;

	/* mount partitions on all disks */
	n_mount = 0;
	entry   = prt_head.flink;

	while ( (entry != &prt_head) && (n_mount < MAX_MOUNT) )
	{
		prt   = contain_record(entry, prt_inf, entry_glb);
		entry = entry->flink;

		do
		{
			/* read volume header */
			if (dc_partition_io(prt, header, DC_AREA_SECTORS, 0, 1) == 0) {					
				break;
			}

			if (dc_decrypt_header(hdr_key, header, &bd_dat->password) == 0) {
				break;
			}

			if (header->flags & VF_REENCRYPT) {
				prt->o_key.key_d = malloc(PKCS_DERIVE_MAX);
				autocpy(prt->o_key.key_d, header->key_2, PKCS_DERIVE_MAX);
			}

			prt->d_key.key_d = malloc(PKCS_DERIVE_MAX);
			autocpy(prt->d_key.key_d, header->key_1, PKCS_DERIVE_MAX);

			prt->flags     = header->flags;
			prt->tmp_size  = header->tmp_size / SECTOR_SIZE;
			prt->stor_off  = header->stor_off / SECTOR_SIZE;
			prt->disk_id   = header->disk_id; 
			prt->d_key.alg = header->alg_1;
			prt->o_key.alg = header->alg_2;
			prt->mnt_ok   = 1; n_mount++;
		} while (0);
	}

	/* prevent leaks */
	zeroauto(header,  sizeof(dc_header));
	zeroauto(hdr_key, sizeof(dc_key));

	return n_mount;
}

static void boot_from_mbr(hdd_inf *hdd, int n_mount)
{
	if ( !(conf.options & OP_EXTERNAL) && (hdd->dos_numb == boot_dsk) ) {
		autocpy(pv(0x7C00), conf.save_mbr, SECTOR_SIZE);
	} else {
		dc_disk_io(hdd, pv(0x7C00), 1, 0, 1);
	}
	bios_jump_boot(hdd->dos_numb, n_mount);
}

static void boot_from_partition(prt_inf *prt, int n_mount)
{
	dc_partition_io(prt, pv(0x7C00), 1, 0, 1);

	/* check MBR signature */
	if (p16(0x7C00+510)[0] != 0xAA55) {
		puts("partition unbootable\n");
	} else {
		bios_jump_boot(prt->hdd->dos_numb, n_mount);
	}
}


static void dc_password_error(prt_inf *active) 
{
	if (conf.error_type & ET_MESSAGE) {
		puts(conf.err_msg);
	}

	if (conf.error_type & ET_REBOOT) {
		bios_reboot();
	}

	if (conf.error_type & ET_BOOT_ACTIVE)
	{
		if (active == NULL) {
			puts("active partition not found\n");
		} else {
			boot_from_partition(active, 0);
		}
	}

	if (conf.error_type & ET_EXIT_TO_BIOS) {
		bios_call(0x18, NULL);
	}

	if (conf.error_type & ET_MBR_BOOT) {
		autocpy(pv(0x7C00), conf.save_mbr, SECTOR_SIZE);
		bios_jump_boot(boot_dsk, 0);
	}
}

/* find first HDD contain active partition */
static hdd_inf *find_bootable_hdd() 
{
	list_entry *entry;
	prt_inf    *prt;

	entry = prt_head.flink;

	while (entry != &prt_head)
	{
		prt   = contain_record(entry, prt_inf, entry_glb);
		entry = entry->flink;

		if ( (prt->active != 0) && 
			 ( !(conf.options & OP_EXTERNAL) || (prt->hdd->dos_numb != boot_dsk) ) )
		{
			return prt->hdd;
		}
	}

	return NULL;
}


void boot_main()
{
	list_entry *entry;
	hdd_inf    *hdd;
	prt_inf    *prt, *active;
	char       *error;
	int         login, i;
	int         n_mount;

	active = NULL; error = NULL;
	login = 0; n_mount = 0;

	/* init crypto */
	dc_init_crypto(conf.options & OP_HW_CRYPTO);

	/* prepare MBR copy buffer */
	autocpy(conf.save_mbr + 432, p8(0x7C00) + 432, 80);

	if (dc_scan_partitions() == 0) {
		error = "partitions not found\n";
		goto error;
	}

	if (hdd = find_hdd(boot_dsk))
	{
		/* find active partition on boot disk */
		entry = hdd->part_head.flink;
		
		while (entry != &hdd->part_head)
		{
			prt   = contain_record(entry, prt_inf, entry_hdd);
			entry = entry->flink;

			if (prt->active != 0) {
				active = prt; break;
			}
		}
	}
retry_auth:;	
	if (conf.logon_type & LT_GET_PASS) 
	{
		login = dc_get_password();

		if ( (conf.options & OP_NOPASS_ERROR) && (login == 0) ) 
		{
			dc_password_error(active);

			if (conf.error_type & ET_RETRY) {
				goto retry_auth;
			} else {
				/* halt system */
				__halt();
			}
		}
	}

	/* add embedded keyfile to password buffer */
	if (conf.logon_type & LT_EMBED_KEY) 
	{
		sha512_ctx sha;
		u8         hash[SHA512_DIGEST_SIZE];

		sha512_init(&sha);
		sha512_hash(&sha, conf.emb_key, sizeof(conf.emb_key));
		sha512_done(&sha, hash);

		/* mix the keyfile hash and password */
		for (i = 0; i < (SHA512_DIGEST_SIZE / sizeof(u32)); i++) {
			p32(bd_dat->password.pass)[i] += p32(hash)[i];
		}
		bd_dat->password.size = max(bd_dat->password.size, SHA512_DIGEST_SIZE);

		/* prevent leaks */
		zeroauto(hash, sizeof(hash));
		zeroauto(&sha, sizeof(sha));
	}

	if (bd_dat->password.size != 0) 
	{
		if (n_mount = dc_mount_parts()) {
			/* hook BIOS interrupts */
			bios_hook_ints();
		} else {
			/* clean password buffer to prevent leaks */
			zeroauto(&bd_dat->password, sizeof(dc_pass));
		}
	}

	if ( (n_mount == 0) && (login != 0) ) 
	{
		dc_password_error(active);

		if (conf.error_type & ET_RETRY) {
			goto retry_auth;
		} else {
			/* halt system */
			__halt();
		}
	}
	
	switch (conf.boot_type)
	{
		case BT_MBR_BOOT: 			  
		  {
			  if (hdd == NULL) {
				  error = "boot disk not found\n";
				  goto error;
			  }
			  boot_from_mbr(hdd, n_mount);
		  }
	    break;
		case BT_MBR_FIRST: 
		  {
			  if ( (hdd = find_bootable_hdd()) == NULL ) {
				  error = "boot disk not found\n";
				  goto error;
			  }			 			  
			  boot_from_mbr(hdd, n_mount);
		  }
	    break;
		case BT_ACTIVE:
		  {
			  if (active == NULL) {
				  error = "active partition not found\n";
				  goto error;
			  } else {	  
				  boot_from_partition(active, n_mount);
			  }
		  }
	  	break;
		case BT_AP_PASSWORD:
		  {
			  /* find first partition with appropriate password */
			  entry = prt_head.flink;

			  while (entry != &prt_head)
			  {
				  prt   = contain_record(entry, prt_inf, entry_glb);
				  entry = entry->flink;

				  if ( (prt->extend == 0) && (prt->mnt_ok != 0) ) {
					  boot_from_partition(prt, n_mount);
				  }
			  }

			  error = "bootable partition not mounted\n";
			  goto error;
		  }
	    break;
		case BT_DISK_ID:
		  {
			  /* find partition by disk_id */
			  entry = prt_head.flink;

			  while (entry != &prt_head)
			  {
				  prt   = contain_record(entry, prt_inf, entry_glb);
				  entry = entry->flink;

				  if ( (prt->extend == 0) && (prt->mnt_ok != 0) &&
					   (prt->disk_id == conf.disk_id) ) 
				  {
					  boot_from_partition(prt, n_mount);
				  }
			  }
			  
			  error = "disk_id equal partition not found\n";
			  goto error;
		  }
		break;
	}

error:;
	if (error != NULL) {
		puts(error); 
	}	
	while (1);
}
