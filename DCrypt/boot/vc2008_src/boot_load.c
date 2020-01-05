#include "boot.h"
#include "boot_vtab.h"
#include "misc.h"
#include "bios_misc.h"
#include "hdd_scan.h"
#include "boot_load.h"
#include "kbd_layout.h"
#include "sha512_small.h"
#include "dc_header.h"

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
	0,    /* timeout */
	{ 0 } /* embedded key */
};

boot_vtab *btab;
bd_data   *bdat;
partition  p_parts[PART_MAX];
int        n_parts;

static void die(char *msg)
{
	/* zero configuration area and password buffer to prevent leaks */
	zeroauto(&conf, sizeof(conf));
	zeroauto(&bdat->password, sizeof(dc_pass));
	/* print message and halt */
	puts(msg); __halt();
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
				bdat->password.pass[--pos] = 0;
			}			
			continue;
		}
		if ( (ch < ' ') || (ch > '~') || (pos == MAX_PASSWORD) ) {
			continue;
		}
		bdat->password.pass[pos++] = ch;

		if (conf.logon_type & LT_DSP_PASS) {
			_putch('*');
		}
	}
ep_exit:;
	if (conf.logon_type & LT_DSP_PASS) {
		_putch('\n');
	}
	bdat->password.size = pos * 2; 

	/* clear BIOS keyboard buffer to prevent password leakage */
	/* see http://www.ouah.org/Bios_Information_Leakage.txt for more details */
	zeroauto(pv(0x41E), 32);

	return (pos != 0);
}

static void boot_from_sector(int hdd_n, u64 sector, int n_mount)
{
	if ( (sector == 0) && 
		!(conf.options & OP_EXTERNAL) && (hdd2dos(hdd_n) == bdat->boot_dsk) )
	{
		autocpy(pv(0x7C00), conf.save_mbr, SECTOR_SIZE);
	} else
	{
		if (btab->p_dc_io(hdd_n, pv(0x7C00), 1, sector, 1) == 0) {
			die("I/O Error\n");
		}
	}
	/* check boot signature */
	if (p16(0x7C00+510)[0] != 0xAA55) { 
		die("partition unbootable\n"); 
	}
	bios_jump_boot(hdd_n, n_mount);
}

static void dc_password_error(partition *active, int boot_d) 
{
	if (conf.error_type & ET_MESSAGE) {
		puts(conf.err_msg);
	}
	if (conf.error_type & ET_REBOOT) {
		bios_reboot();
	}
	if (conf.error_type & ET_BOOT_ACTIVE)
	{
		if (active != NULL) {
			boot_from_sector(active->hdd_n, active->begin, 0);		
		} else {
			die("active partition not found\n");			
		}
	}
	if (conf.error_type & ET_EXIT_TO_BIOS) {
		/* zero configuration area to prevent leaks */
		zeroauto(&conf, sizeof(conf));
		/* exit to BIOS */
		btab->p_bios_call(0x18, NULL);
	}
	if (conf.error_type & ET_MBR_BOOT) 
	{
		if (boot_d >= 0) {
			boot_from_sector(boot_d, 0, 0);
		} else {
			die("this disk is unbootable\n");
		}
	}
}

static int dc_mount_parts()
{
	dc_header  header;
	xts_key    hdr_key;
	partition *part;	
	mount_inf *mount;
	int        i;
	
	for (i = 0; i < n_parts; i++)
	{
		part  = &p_parts[i];
		mount = &btab->p_iodb->p_mount[btab->p_iodb->n_mount];

		if (btab->p_hdd_io(part->hdd_n, &header, DC_AREA_SECTORS, part->begin, 1) == 0) {
			continue;
		}
		if (dc_decrypt_header(&hdr_key, &header, &bdat->password) == 0) {
			continue;
		}
		if ( (btab->p_iodb->n_mount >= MOUNT_MAX) ||
			 (btab->p_iodb->n_key >= MOUNT_MAX - ((header.flags & VF_REENCRYPT) != 0)) )
		{
			puts("Not enough memory to mount all partitions\n");
			continue;
		}
		mount->hdd_n    = part->hdd_n;
		mount->begin    = part->begin;
		mount->end      = part->begin + part->size;
		mount->size     = part->size;
		mount->flags    = header.flags;
		mount->tmp_size = header.tmp_size / SECTOR_SIZE;
		mount->stor_off = header.stor_off / SECTOR_SIZE;
		mount->disk_id  = header.disk_id;
		
		mount->d_key      = &btab->p_iodb->p_key[btab->p_iodb->n_key++];
		mount->d_key->alg = header.alg_1;
		autocpy(mount->d_key->key, header.key_1, PKCS_DERIVE_MAX);
		
		if (header.flags & VF_REENCRYPT) {
			mount->o_key      = &btab->p_iodb->p_key[btab->p_iodb->n_key++];
			mount->o_key->alg = header.alg_2;
			autocpy(mount->o_key->key, header.key_2, PKCS_DERIVE_MAX);
		}
		if (part->flags & PT_EXTENDED) {
			mount->flags |= VF_EXTENDED;
		}
		btab->p_iodb->n_mount++;
	}
	/* prevent leaks */
	zeroauto(&header,  sizeof(dc_header));
	zeroauto(&hdr_key, sizeof(xts_key));

	return btab->p_iodb->n_mount;
}

void boot_load_main(bd_data *db, boot_vtab *vt)
{
	partition *active  = NULL;
	int        login   = 0;
	int        n_mount = 0;
	int        i, boot_d;
	mount_inf *mount;
	partition *part;
		
	bdat = db, btab = vt;
	/* create new memory map */
	bios_create_smap();
	/* init crypto */
	vt->p_xts_init(conf.options & OP_HW_CRYPTO);
	/* prepare MBR copy buffer */
	autocpy(conf.save_mbr + 432, p8(0x7C00) + 432, 80);

	if (dc_find_hdds() == 0) {
		die("disks not found\n");
	}
	if (dc_find_partitions() == 0) {
		die("partitions not found\n");
	}
	if ( (boot_d = dos2hdd(db->boot_dsk)) >= 0 )
	{
		for (i = 0; i < n_parts; i++)
		{
			if ( (p_parts[i].hdd_n == boot_d) && 
				 (p_parts[i].flags & PT_ACTIVE) ) 
			{
				active = &p_parts[i]; break;
			}
		}
	}
	/* save bootloader options */
	vt->p_iodb->options = conf.options;
	vt->p_iodb->ldr_dsk = boot_d;

retry_auth:;	
	if (conf.logon_type & LT_GET_PASS) 
	{
		login = dc_get_password();

		if ( (conf.options & OP_NOPASS_ERROR) && (login == 0) ) 
		{
			dc_password_error(active, boot_d);

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
			p32(db->password.pass)[i] += p32(hash)[i];
		}
		db->password.size = max(db->password.size, SHA512_DIGEST_SIZE);

		/* prevent leaks */
		zeroauto(hash, sizeof(hash));
		zeroauto(&sha, sizeof(sha));
	}
	if (db->password.size != 0) 
	{
		if (n_mount = dc_mount_parts()) {
			/* hook BIOS interrupts */
			bios_hook_ints();
		} else {
			/* zero password buffer to prevent leaks */
			zeroauto(&db->password, sizeof(dc_pass));
		}
	}

	if ( (n_mount == 0) && (login != 0) ) 
	{
		dc_password_error(active, boot_d);

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
			  if (boot_d < 0) {
				  die("boot disk not found\n");
			  }
			  boot_from_sector(boot_d, 0, n_mount);
		  }
	    break;
		case BT_MBR_FIRST: 
		  {
			  for (i = 0; i < n_parts; i++)
			  {
				  part = &p_parts[i];

				  if ( (part->flags & PT_ACTIVE) &&
					   (!(conf.options & OP_EXTERNAL) || (hdd2dos(part->hdd_n) != db->boot_dsk)) )
				  {
					  boot_from_sector(part->hdd_n, 0, n_mount);
				  }
			  }
			  die("boot disk not found\n");
		  }
	    break;
		case BT_ACTIVE:
		  {
			  if (active == NULL) {
				  die("active partition not found\n");
			  } else {	  
				  boot_from_sector(active->hdd_n, active->begin, n_mount);
			  }
		  }
	  	break;
		case BT_AP_PASSWORD:
		  {
			  /* find first mount with appropriate password */
			  for (i = 0; i < vt->p_iodb->n_mount; i++)
			  {
				  mount = &vt->p_iodb->p_mount[i];

				  if ((mount->flags & VF_EXTENDED) == 0) {
					  boot_from_sector(mount->hdd_n, mount->begin, n_mount);
				  }
			  }
			  die("bootable partition not mounted\n");
		  }
	    break;
		case BT_DISK_ID:
		  {
			  /* find mount by disk_id */
			  for (i = 0; i < vt->p_iodb->n_mount; i++)
			  {
				  mount = &vt->p_iodb->p_mount[i];

				  if ( ((mount->flags & VF_EXTENDED) == 0) &&
					   (mount->disk_id == conf.disk_id) )
				  {
					  boot_from_sector(mount->hdd_n, mount->begin, n_mount);
				  }
			  }
			  die("disk_id equal partition not found\n");
		  }
		break;
	}

}