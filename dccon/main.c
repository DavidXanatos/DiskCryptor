/*
    *
    * DiskCryptor - open source partition encryption tool
	* Copyright (c) 2008-2010 
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
#include <windows.h>
#include <stdio.h>
#include <conio.h>
#include "defines.h"
#include "main.h"
#include "version.h"
#include "boot_menu.h"
#include "misc.h"
#include "mbrinst.h"
#include "drv_ioctl.h"
#include "drvinst.h"
#include "rand.h"
#include "keyfiles.h"
#include "cd_enc.h"
#include "bootloader.h"
#include "console.h"

typedef struct _bench_item {
	wchar_t *alg;
	double   speed;

} bench_item;

       vol_inf   volumes[MAX_VOLUMES];
       u32       vol_cnt;
extern int       g_argc;
extern wchar_t **g_argv;
static int       rng_inited;
static wchar_t   boot_dev[MAX_PATH];

static void print_usage()
{
	wprintf(
		L"DiskCryptor (c) <ntldr@diskcryptor.net> PGP key ID - 0xC48251EB4F8E4E6E\n"
		L"\n"
		L"Usage: dccon [key] [param]\n"
		L"________________________________________________________________________________\n"
		L"\n"
		L" -enum                           Enum all volume devices in system\n"
		L" -info [dev]                     Display information about device\n"
		L" -version                        Display DiskCryptor version\n"
		L" -benchmark                      Encryption benchmark\n"
		L" -config                         Change program configuration\n"
		L" -keygen [file]                  Make 64 bytes random keyfile\n"
		L" -bsod                           Erase all keys in memory and generate BSOD\n"
		L"________________________________________________________________________________\n"
		L"\n"
		L" -addpass [param]                Add password to password cache\n"
		L"    -p  [password]        Get password from command line\n"
		L"    -kf [keyfiles path]   Use keyfiles\n"
		L" -clean                          Wipe cached passwords in memory\n"
		L"________________________________________________________________________________\n"
		L"\n"
		L" -mount [dev] [param]            Mount encrypted device\n"
		L"    -mp [mount point]     Add volume mount point\n"
		L"    -p  [password]        Get password from command line\n"
		L"    -kf [keyfiles path]   Use keyfiles\n"
		L" -mountall [param]               Mount all encrypted devices\n"
		L"    -p  [password]        Get password from command line\n"
		L"    -kf [keyfiles path]   Use keyfiles\n"
		L" -unmount [dev] [param]          Unmount encrypted device\n"
		L"    -f                    Force unmount with close all opened files\n"
		L"    -dp                   Delete volume mount point\n"
		L" -unmountall                     Force unmount all devices\n"
		L"________________________________________________________________________________\n"
		L"\n"
		L" -encrypt [dev] [param]          Encrypt volume device\n"
		L"    -p  [password]        Get password from command line\n"
		L"    -kf [keyfiles path]   Use keyfiles\n"
		L"             ======  Cipher settings:   ======\n"
		L"    -a                    AES cipher\n"
		L"    -t                    Twofish cipher\n"
		L"    -s                    Serpent cipher\n"
		L"    -at                   AES-Twofish ciphers chain\n"
		L"    -ts                   Twofish-Serpent ciphers chain\n"
		L"    -sa                   Serpent-AES ciphers chain\n"
		L"    -ats                  AES-Twofish-Serpent ciphers chain\n"
		L"             ======  Original data wipe settings:  ======\n"
		L"    -dod_e                US DoD 5220.22-M (8-306./E)          (3 passes)\n"
		L"    -dod                  US DoD 5220.22-M (8-306./E, C and E) (7 passes)\n"
		L"    -g                    Gutmann mode                         (35 passes)\n"
		L" -decrypt [dev] [param]          Decrypt volume device\n"
		L"    -p  [password]        Get password from command line\n"
		L"    -kf [keyfiles path]   Use keyfiles\n"
		L" -reencrypt [dev] [param]        Re-encrypt device with new parameters,\n"
		L"                                 parameters are equal to -encrypt\n"
		L" -format [dev] [param]           Format volume device with encryption,\n"
		L"                                 parameters are equal to -encrypt\n"
		L"    -q                    Quick format\n"
		L"    -fat                  Format to FAT file system\n"
		L"    -fat32                Format to FAT32 file system\n"
		L"    -exfat                Format to exFAT file system\n"
		L"    -ntfs                 Format to NTFS file system\n"
		L"    -raw                  File system does not needed\n"
		L" -enciso [src] [dst] [param]     Encrypt .iso image,\n"
		L"                                 parameters are equal to -encrypt\n"
		L"    -src                  Source file\n"
		L"    -dst                  Destination file\n"
		L"________________________________________________________________________________\n"
		L"\n"
		L" -chpass [dev] [param]           Change volume password\n"
		L"    -op  [password]       Get old password from command line\n"
		L"    -np  [password]       Get new password from command line\n"
		L"    -okf [keyfiles path]  Old keyfiles\n"
		L"    -nkf [keyfiles path]  New keyfiles\n"
		L" -backup [dev] [file] [param]    Backup volume header to file\n"
		L"    -p  [password]        Get password from command line\n"
		L"    -kf [keyfiles path]   Use keyfiles\n"
		L" -restore [dev] [file] [param]   Restore volume header from file\n"
		L"    -p  [password]        Get password from command line\n"
		L"    -kf [keyfiles path]   Use keyfiles\n"
		L"________________________________________________________________________________\n"
		L"\n"
		L" -boot [action]\n"
		L"    -enum                        Enumerate all HDDs\n"
		L"    -config  [hdd/file]          Change bootloader configuration\n"
		L"    -setmbr  [hdd] [opt]         Setup bootloader to HDD master boot record\n"
		L"    -updmbr  [hdd]               Update bootloader on HDD master boot record\n"
		L"    -delmbr  [hdd]               Delete bootloader from HDD master boot record\n"
		L"    -setpar  [root par] [opt]    Setup bootloader to bootable partition\n"
		L"    -makeiso [file] [opt]        Make bootloader image (.iso)\n"
		L"    -makepxe [file] [opt]        Make bootloader image for PXE network booting\n"
		L"       -small             Use small bootloader, only with AES\n"
		);
}

static void make_dev_status(vol_inf *inf, wchar_t *status)
{
	wcscpy(status, L"unmounted");

	if (inf->status.flags & F_ENABLED) {
		wcscpy(status, L"mounted");
	}

	if (inf->status.flags & F_UNSUPRT) {
		wcscpy(status, L"unsupported");
	}

	if (wcscmp(inf->device, boot_dev) == 0) {
		wcscat(status, L", boot");
	}

	if (inf->status.flags & F_SYSTEM) {
		wcscat(status, L", system");
	}
}

static void print_devices()
{
	wchar_t  stat[MAX_PATH];
	wchar_t  size[MAX_PATH];
	wchar_t *mnt;
	u32      i;

	wprintf(
		L"------------------------------------------------------------------\n"
		L"volume |     mount point      |   size  |       status\n"
		L"-------+----------------------+---------+-------------------------\n");

	for (i = 0; i < vol_cnt; i++)
	{
		dc_format_byte_size(
			size, countof(size), volumes[i].status.dsk_size);

		make_dev_status(&volumes[i], stat);

		if (volumes[i].status.mnt_point[0] != L'\\') {
			mnt = volumes[i].status.mnt_point;
		} else mnt = L"";
		
		wprintf(L"pt%d    | %-20s | %-7s | %-23s\n", i, mnt, size, stat);
	}
}

static void enum_devices()
{
	vol_inf info;
	
	if (dc_first_volume(&info) == ST_OK)
	{
		do
		{
			volumes[vol_cnt++] = info;
		} while (dc_next_volume(&info) == ST_OK);
	}
}

static vol_inf *find_device(wchar_t *name)
{
	wchar_t w_name[MAX_PATH];
	u32     i;

	if (name == NULL) 
	{
		for (i = 0; i < vol_cnt; i++) {
			if (volumes[i].status.flags & F_SYSTEM) return &volumes[i];
		}
		return NULL;
	}
	wcscpy(w_name, name); _wcslwr(w_name);

	if ( (w_name[0] == L'p') && (w_name[1] == L't') && (isdigit(name[2]) != 0) ) {
		if ( (i = _wtoi(name+2)) < vol_cnt ) return &volumes[i];
	} else 
	{
		if (w_name[1] == L':') {
			w_name[2] = 0;
		}
		for (i = 0; i < vol_cnt; i++) {
			if (_wcsicmp(w_name, volumes[i].status.mnt_point) == 0) return &volumes[i];
		}
	}
	return NULL;
}

static 
void dc_getpass_loop(dc_pass *pass)
{
	wchar_t ch;
	u32     pos;

	for (pos = 0;;)
	{
		ch = _getch();

		if (ch == '\r') {
			break;
		}

		/* reseed RNG */
		if (rng_inited != 0) {
			rnd_reseed_now();
		}

		if (ch == 8)
		{
			if (pos > 0) {
				_putch(8); pos--;
			}
			_putch(' '); _putch(8);
			continue;
		}

		if ( (ch == 0) || (ch == 0xE0) ) {
			_getch();
		}

		if ( (ch < ' ') || (ch > '~') || (pos == MAX_PASSWORD) ) {
			continue;
		}

		pass->pass[pos++] = ch; _putch('*');
	}

	_putch('\n');

	pass->size = pos * 2;
}

static
int dc_get_password(int confirm, dc_pass *pass)
{
	dc_pass *cfm_p;
	int      succs;

	cfm_p = NULL; succs = 0;
	do
	{
		dc_getpass_loop(pass);

		if (confirm != 0) 
		{
			if ( (cfm_p = secure_alloc(sizeof(dc_pass))) == NULL ) {
				break;
			}
			wprintf(L"Confirm password: ");
			dc_getpass_loop(cfm_p);

			if (IS_EQUAL_PASS(pass, cfm_p) == 0)
			{
				wprintf(L"The password was not correctly confirmed.\n");
				break;
			}
		}
		succs = 1;
	} while (0);

	if (cfm_p != NULL) {
		secure_free(cfm_p);
	}

	return succs;
}

static int dc_encrypt_loop(vol_inf *inf, int wp_mode)
{
	dc_status status;
	int       i = 0;
	wchar_t  *wp_str;
	char      ch;
	int       resl;

bgn_loop:;
	cls_console();

	switch (wp_mode)
	{
		case WP_NONE: wp_str = L"None"; break;
		case WP_DOD_E: wp_str = L"US DoD 5220.22-M (8-306. / E) (3 passes)"; break;
		case WP_DOD: wp_str = L"US DoD 5220.22-M (8-306. / E, C and E) (7 passes)"; break;
		case WP_GUTMANN: wp_str = L"Gutmann (35 passes)"; break;
	}
	
	wprintf(
		L"Encrypting progress...\n"
		L"Old data wipe mode: %s\n\n"
		L"Press ESC to cancel encrypting or press \"W\" to change wipe mode\n", wp_str);

	do
	{
		if (_kbhit() != 0)
		{
			if ( (ch = _getch()) == 0x1B )
			{
				wprintf(L"\nEncryption cancelled\n");
				dc_sync_enc_state(inf->device);
				break;
			}

			if (tolower(ch) == 'w')
			{
				wprintf(L"\n"
					L"1 - None (fastest)\n"
					L"2 - US DoD 5220.22-M (8-306. / E) (3 passes)\n"
					L"3 - US DoD 5220.22-M (8-306. / E, C and E) (7 passes)\n"
					L"4 - Gutmann (35 passes)\n");

				switch (getchr('1', '4'))
				{
					case '1': wp_mode = WP_NONE; break;
					case '2': wp_mode = WP_DOD_E; break;
					case '3': wp_mode = WP_DOD; break;
					case '4': wp_mode = WP_GUTMANN; break;
				}

				goto bgn_loop;
			}
		}

		if (i-- == 0) {
			dc_sync_enc_state(inf->device); i = 20;
		}

		dc_get_device_status(
			inf->device, &status);

		wprintf(
			L"\r%-.3f %%", 
			(double)(status.tmp_size) / (double)(status.dsk_size) * 100);

		resl = dc_enc_step(inf->device, wp_mode);

		if (resl == ST_FINISHED) {
			wprintf(L"\nEncryption finished\n"); break;
		}

		if ( (resl != ST_OK) && (resl != ST_RW_ERR) ) {
			wprintf(L"\nEncryption error %d\n", resl); break;
		}
	} while (1);

	return ST_OK;
}

static int dc_format_loop(vol_inf *inf, int wp_mode)
{
	dc_status status;
	wchar_t  *wp_str;
	char      ch;
	int       resl;

bgn_loop:;
	cls_console();

	switch (wp_mode)
	{
		case WP_NONE: wp_str = L"None"; break;
		case WP_DOD_E: wp_str = L"US DoD 5220.22-M (8-306. / E) (3 passes)"; break;
		case WP_DOD: wp_str = L"US DoD 5220.22-M (8-306. / E, C and E) (7 passes)"; break;
		case WP_GUTMANN: wp_str = L"Gutmann (35 passes)"; break;
	}
	
	wprintf(
		L"Formatting progress...\n"
		L"Old data wipe mode: %s\n\n"
		L"Press ESC to cancel encrypting or press \"W\" to change wipe mode\n", wp_str);

	do
	{
		if (_kbhit() != 0)
		{
			if ( (ch = _getch()) == 0x1B )
			{
				wprintf(L"\nFormatting cancelled\n");
				resl = ST_OK; break;
			}

			if (tolower(ch) == 'w')
			{
				wprintf(L"\n"
					L"1 - None (fastest)\n"
					L"2 - US DoD 5220.22-M (8-306. / E) (3 passes)\n"
					L"3 - US DoD 5220.22-M (8-306. / E, C and E) (7 passes)\n"
					L"4 - Gutmann (35 passes)\n");

				switch (getchr('1', '4'))
				{
					case '1': wp_mode = WP_NONE; break;
					case '2': wp_mode = WP_DOD_E; break;
					case '3': wp_mode = WP_DOD; break;
					case '4': wp_mode = WP_GUTMANN; break;
				}

				goto bgn_loop;
			}
		}

		dc_get_device_status(inf->device, &status);

		wprintf(
			L"\r%-.3f %%", 
			(double)(status.tmp_size) / (double)(status.dsk_size) * 100);

		resl = dc_format_step(inf->device, wp_mode);

		if (resl == ST_FINISHED) {
			_putch('\n'); break;
		}

		if ( (resl != ST_OK) && (resl != ST_RW_ERR) ) {
			wprintf(L"\nFormatting error %d\n", resl);
			break;
		}
	} while (1);

	if (resl != ST_FINISHED) {
		dc_done_format(inf->device);
	}

	return ST_OK;
}

static int dc_decrypt_loop(vol_inf *inf)
{
	dc_status status;
	int       i = 0;
	int       resl;

	cls_console();
	
	wprintf(
		L"Decrypting progress...\n"
		L"Press ESC to cancel decrypting\n");

	do
	{
		if ( (_kbhit() != 0) && (_getch() == 0x1B) ) {
			wprintf(L"\nDecryption cancelled\n");
			dc_sync_enc_state(inf->device); break;
		}

		if (i-- == 0) {
			dc_sync_enc_state(inf->device); i = 20;					
		}

		dc_get_device_status(inf->device, &status);

		wprintf(
			L"\r%-.3f %%", 
			100 - ((double)(status.tmp_size) / (double)(status.dsk_size) * 100));

		resl = dc_dec_step(inf->device);

		if (resl == ST_FINISHED) {
			wprintf(L"\nDecryption finished\n"); break;
		}

		if ( (resl != ST_OK) && (resl != ST_RW_ERR) ) {
			wprintf(L"\nDecryption error %d\n", resl); break;
		}
	} while (1);

	return ST_OK;
}

static BOOL dc_cd_callback(ULONGLONG isosize, ULONGLONG encsize, PVOID param)
{
	if ( (_kbhit() != 0) && (_getch() == 0x1B) ) {
		wprintf(L"\nEncryption cancelled\n");
		return FALSE;
	}

	wprintf(
		L"\r%-.3f %%", 
		(double)(encsize) / (double)(isosize) * 100);

	return TRUE;
}

int dc_set_boot_interactive(int d_num, int small_boot)
{
	ldr_config conf;
	int        resl;

	if ( (resl = dc_set_mbr(d_num, 0, small_boot)) == ST_NF_SPACE )
	{
		wprintf(
			L"Not enough space after partitions to install bootloader.\n"
			L"Install bootloader to first HDD track (incompatible with third-party bootmanagers, like GRUB) Y/N?\n");

		if (tolower(_getch()) == 'y') 
		{
			if ( ((resl = dc_set_mbr(d_num, 1, small_boot)) == ST_OK) && 
				 (dc_get_mbr_config(d_num, NULL, &conf) == ST_OK) )
			{
				conf.boot_type = LDR_BT_ACTIVE;
						
				if ( (resl = dc_set_mbr_config(d_num, NULL, &conf)) != ST_OK ) {
					dc_unset_mbr(d_num);
				}
			}
		} 
	}

	return resl;
}


static 
dc_pass* dc_load_pass_and_keyfiles(
		   wchar_t *p_param, wchar_t *kf_param, wchar_t *gp_msg, int confirm
		   )
{
	dc_pass *pass;
	int      clean = 0;
	wchar_t *cmde;
	size_t   plen;
	int      resl;

	if ( (pass = secure_alloc(sizeof(dc_pass))) == NULL ) {
		clean_cmd_line();
		return NULL;
	}

	if (p_param == NULL)  p_param = L"-p";
	if (kf_param == NULL) kf_param = L"-kf";
	if (gp_msg == NULL)   gp_msg = L"Enter password: ";
	
	if (cmde = get_param(p_param))
	{
		plen       = wcslen(cmde) * sizeof(wchar_t);
		pass->size = d32(min(plen, MAX_PASSWORD * sizeof(wchar_t)));
		mincpy(&pass->pass, cmde, pass->size);
		memset(cmde, 0, plen); clean = 1;
	} else 
	{
		wprintf(gp_msg);
		
		if (dc_get_password(confirm, pass) == 0) {
			secure_free(pass); clean_cmd_line();
			return NULL;
		}
	}

	if (cmde = get_param(kf_param)) 
	{
		if ( (resl = dc_add_keyfiles(pass, cmde)) != ST_OK) 
		{
			printf("Keyfiles not loaded, error %d\n", resl);
			secure_free(pass); pass = NULL;
		}
		burn(cmde, wcslen(cmde) * sizeof(wchar_t)); 
		clean = 1;
	}

	if (clean != 0) {
		clean_cmd_line();
	}

	if (pass->size == 0) {
		secure_free(pass); pass = NULL;
	}

	return pass;
}

static void get_crypt_info(crypt_info *crypt)
{
	/* get cipher */
	if (is_param(L"-a") != 0) {
		crypt->cipher_id = CF_AES;
	} else if (is_param(L"-t") != 0) {
		crypt->cipher_id = CF_TWOFISH;
	} else if (is_param(L"-s") != 0) {
		crypt->cipher_id = CF_SERPENT;
	} else if (is_param(L"-at") != 0) {
		crypt->cipher_id = CF_AES_TWOFISH;
	} else if (is_param(L"-ts") != 0) {
		crypt->cipher_id = CF_TWOFISH_SERPENT;
	} else if (is_param(L"-sa") != 0) {
		crypt->cipher_id = CF_SERPENT_AES;
	} else if (is_param(L"-ats") != 0) {
		crypt->cipher_id = CF_AES_TWOFISH_SERPENT;
	}

	/* get wipe mode */
	if (is_param(L"-dod_e") != 0) {
		crypt->wp_mode = WP_DOD_E;
	} else if (is_param(L"-dod") != 0) {
		crypt->wp_mode = WP_DOD;
	} else if (is_param(L"-g") != 0) {
		crypt->wp_mode = WP_GUTMANN;
	}
}


static int dc_bench_cmp(const bench_item *arg1, const bench_item *arg2)
{
	if (arg1->speed > arg2->speed) {
		return -1;
	} else {
		return (arg1->speed < arg2->speed);
	}
}

int wmain(int argc, wchar_t *argv[])
{
	vol_inf *inf;
	int      resl;
	int      vers;
	int      d_inited;

	g_argc = argc; g_argv = argv;
	do
	{
#ifdef _M_IX86 
		if (is_wow64() != 0) {
			wprintf(L"Please use x64 version of DiskCryptor\n");
			resl = ST_ERROR; break;
		}
#endif
		if (is_admin() != ST_OK) {
			wprintf(L"Administrator privilegies required\n");
			resl = ST_NO_ADMIN; break;
		}

		if (argc < 2) {
			print_usage();
			resl = ST_OK; break;
		}

		d_inited = 0;

		if ( dc_is_driver_works() && (dc_open_device() == ST_OK) )
		{
			if ((vers = dc_get_version()) == DC_DRIVER_VER) {
				/* get information of all volumes in system */
				enum_devices(); d_inited = 1;
			}
		}

		if ( (argc >= 2) && (wcscmp(argv[1], L"-version") == 0) ) 
		{
			wprintf(L"DiskCryptor %S console\n", DC_FILE_VER);
			resl = ST_OK; break;
		}

		if (dc_is_old_runned() != 0)
		{
			wprintf(L"DiskCryptor 0.1-0.4 installed, please completely "
				L"uninstall it before use this version\n");
			resl = ST_OK; break;
		}

		if ( (argc >= 3) && (wcscmp(argv[1], L"-boot") == 0) ) 
		{
			resl = boot_menu(argc, argv);
			break;
		}	

		if (dc_is_driver_works() == FALSE) 
		{
			wprintf(
				L"DiskCryptor is not installed,\n"
				L"please install DiskCryptor and reboot you system\n");
			resl = ST_OK; break;
		}

		if (d_inited == 0)
		{
			if (vers > DC_DRIVER_VER) 
			{
				wprintf(
					L"DiskCryptor driver ver %d detected\n"
					L"Please use last program version\n", vers);
				resl = ST_OK; break;
			}

			if (vers < DC_DRIVER_VER)
			{
				wprintf(
					L"Old DiskCryptor driver detected\n"
					L"please update DiskCryptor and reboot you system\n");
				resl = ST_OK; break;
			}

			resl = ST_ERROR; break;
		}

		/* initialize user mode RNG part */
		if ( (resl = rnd_init()) != ST_OK ) {
			break;
		}
		rng_inited = 1;

		/* get boot device */
		if (dc_get_boot_device(boot_dev) != ST_OK) {
			boot_dev[0] = 0;
		}

		if ( (argc == 2) && (wcscmp(argv[1], L"-enum") == 0) ) {
			print_devices();
			resl = ST_OK; break;
		}

		if ( (argc == 3) && (wcscmp(argv[1], L"-info") == 0) ) 
		{
			wchar_t stat[MAX_PATH];
			wchar_t size[MAX_PATH];

			if ( (inf = find_device(argv[2])) == NULL ) {
				resl = ST_NF_DEVICE; break;
			}

			dc_format_byte_size(
				size, countof(size), inf->status.dsk_size);

			make_dev_status(inf, stat);

			wprintf(
				L"Device:            %s\n"
				L"SymLink:           %s\n"
				L"Mount point:       %s\n"
				L"Capacity:          %s\n"
				L"Status:            %s\n",
				inf->device, inf->w32_device, inf->status.mnt_point,
				size, stat);

			if (inf->status.flags & F_ENABLED)
			{
				double portion;

				if (inf->status.flags & F_SYNC) 
				{
					portion = (double)(inf->status.tmp_size) / 
						(double)(inf->status.dsk_size) * 100;
				} else {
					portion = 100;
				}

				wprintf(
					L"Cipher:            %s\n"
					L"Encryption mode:   XTS\n"
					L"Pkcs5.2 prf:       HMAC-SHA-512\n"
					L"Encrypted portion: %-.3f%%\n",
					dc_get_cipher_name(inf->status.crypt.cipher_id),
					portion);
			}

			resl = ST_OK; break;
		}

		if ( (argc >= 3) && (wcscmp(argv[1], L"-mount") == 0) ) 
		{
			wchar_t  vol_n[MAX_PATH];
			wchar_t  mnt_p[MAX_PATH];
			dc_pass *pass;
			wchar_t *mp_c;
			size_t   s;

			if ( (inf = find_device(argv[2])) == NULL ) {
				resl = ST_NF_DEVICE; break;
			}

			if (inf->status.flags & F_ENABLED) {
				wprintf(L"This device is already mounted\n");
				resl = ST_OK; break;
			}

			if (inf->status.flags & (F_UNSUPRT | F_DISABLE | F_FORMATTING)) {
				wprintf(L"Invalid device state\n");
				resl = ST_OK; break;
			}

			pass = dc_load_pass_and_keyfiles(NULL, NULL, NULL, 0);
			mp_c = get_param(L"-mp");

			if (pass == NULL) {
				resl = ST_OK; break;
			}

			if ( (mp_c != NULL) && (inf->status.mnt_point[0] == L'\\') ) {
				resl = dc_mount_volume(inf->device, pass, MF_DELMP);
			} else {
				resl = dc_mount_volume(inf->device, pass, 0);
			}

			if ( (resl == ST_OK) && (mp_c != NULL) )
			{
				if (inf->status.mnt_point[0] != L'\\') {
					wprintf(L"device %s already have mount point\n", argv[2]);						
				} else 
				{
					_snwprintf(
						vol_n, countof(vol_n), L"%s\\", inf->w32_device);

					wcsncpy(mnt_p, mp_c, countof(mnt_p));
					if ( (s = wcslen(mnt_p)) && (mnt_p[s-1] != L'\\') ) {
						mnt_p[s] = L'\\'; mnt_p[s+1] = 0;
					}

					if (SetVolumeMountPoint(mnt_p, vol_n) == 0) {
						wprintf(L"Error when adding mount point\n");
					}
				}
			}

			if (resl == ST_OK) {
				wprintf(L"device %s mounted\n", argv[2]);
			}

			secure_free(pass);
			break;
		}

		if ( (argc >= 2) && (wcscmp(argv[1], L"-mountall") == 0) ) 
		{
			dc_pass *pass;
			int      n_mount;

			pass = dc_load_pass_and_keyfiles(NULL, NULL, NULL, 0);
			resl = dc_mount_all(pass, &n_mount, 0);

			if (resl == ST_OK) {
				wprintf(L"%d devices mounted\n", n_mount);
			}

			if (pass != NULL) {
				secure_free(pass);
			}
			break;
		}

		if ( (argc >= 3) && (wcscmp(argv[1], L"-unmount") == 0) )
		{
			int flags = 0;

			if ( (inf = find_device(argv[2])) == NULL ) {
				resl = ST_NF_DEVICE; break;
			}

			if (is_param(L"-f") != 0) {
				flags |= MF_FORCE;
			}

			if (is_param(L"-dp") != 0) {
				flags |= MF_DELMP;
			}

			if ( !(inf->status.flags & F_ENABLED) ) {
				wprintf(L"This device is not mounted\n");
				resl = ST_OK; break;
			}

			resl = dc_unmount_volume(inf->device, flags);

			if (resl == ST_LOCK_ERR)
			{
				wprintf(
					L"This volume contains opened files.\n"
					L"Would you like to force a unmount on this volume? (Y/N)\n");

				if (tolower(_getch()) == 'y') {
					resl = dc_unmount_volume(inf->device, flags | MF_FORCE);
				}
			}

			if (resl == ST_OK) {
				wprintf(L"device %s unmounted\n", argv[2]);
			}
			break;
		}

		if ( (argc >= 2) && (wcscmp(argv[1], L"-unmountall") == 0) ) 
		{
			resl = dc_unmount_all();

			if (resl == ST_OK) {
				wprintf(L"all devices unmounted\n");
			}
			break;
		}

		if ( (argc >= 2) && (wcscmp(argv[1], L"-clean") == 0) ) 
		{
			resl = dc_device_control(DC_CTL_CLEAR_PASS, NULL, 0, NULL, 0) == NO_ERROR ? ST_OK : ST_ERROR;

			if (resl == ST_OK) {
				wprintf(L"passwords has been erased in memory\n");
			}
			break;
		}

		if ( (argc >= 2) && (wcscmp(argv[1], L"-addpass") == 0) )
		{
			dc_pass *pass;

			pass = dc_load_pass_and_keyfiles(NULL, NULL, NULL, 0);

			if (pass == NULL) {
				resl = ST_OK; break;
			}

			resl = dc_add_password(pass);

			secure_free(pass);
		}

		if ( (argc >= 3) && (wcscmp(argv[1], L"-encrypt") == 0) )
		{
			dc_pass   *pass;			
			crypt_info crypt;

			if ( (inf = find_device(argv[2])) == NULL ) {
				resl = ST_NF_DEVICE; break;
			}

			/* set default params */
			crypt.cipher_id = CF_AES;
			crypt.wp_mode   = WP_NONE;

			get_crypt_info(&crypt);

			if (inf->status.flags & F_SYNC) 
			{
				if (crypt.wp_mode == WP_NONE) {
					crypt.wp_mode = inf->status.crypt.wp_mode;
				}
				resl = dc_encrypt_loop(inf, crypt.wp_mode);
				break;
			}

			if (inf->status.flags & F_ENABLED) {
				wprintf(L"This device is already encrypted\n");
				resl = ST_OK; break;
			}

			if (inf->status.flags & (F_UNSUPRT | F_DISABLE)) {
				wprintf(L"Invalid device state\n");
				resl = ST_OK; break;
			}

			if ( (inf->status.flags & F_SYSTEM) || (wcscmp(inf->device, boot_dev) == 0) )
			{
				ldr_config conf;
				DC_FLAGS   flags;
				int        dsk_1, dsk_2;

				if ( (crypt.cipher_id != CF_AES) && (dc_device_control(DC_CTL_GET_FLAGS, NULL, 0, &flags, sizeof(flags)) == NO_ERROR) && 
					 (flags.load_flags & DST_SMALL_MEM) )
				{
					wprintf(
						L"Your BIOS does not provide enough base memory, "
						L"you can only use AES to encrypt the boot partition.");
					resl = ST_OK; break;
				}				
				if (dc_get_boot_disk(&dsk_1, &dsk_2) != ST_OK)
				{
					wprintf(
						L"This partition needed for system booting and bootable HDD not found\n"
						L"You must be use external bootloader\n"
						L"Continue operation (Y/N)?\n\n"
						);

					if (tolower(_getch()) != 'y') {
						resl = ST_OK; break;
					}
				} else if (dc_get_mbr_config(dsk_1, NULL, &conf) != ST_OK)
				{
					wprintf(
						L"This partition needed for system booting\n"
						L"You must install bootloader to HDD, or use external bootloader\n\n"
						L"1 - Install to HDD\n"
						L"2 - I already have external bootloader\n"
						);

					if (getchr('1', '2') == '1') 
					{
						if ( (resl = dc_set_boot_interactive(-1, -1)) != ST_OK ) {
							break;
						}
					}
				}				
			}

			pass = dc_load_pass_and_keyfiles(NULL, NULL, NULL, 1);

			if (pass == NULL) {
				resl = ST_OK; break;
			}

			resl = dc_start_encrypt(inf->device, pass, &crypt);

			secure_free(pass);

			if (resl == ST_OK ) {
				resl = dc_encrypt_loop(inf, crypt.wp_mode);
			}
			break;
		}

		if ( (argc >= 3) && (wcscmp(argv[1], L"-decrypt") == 0) ) 
		{
			dc_pass *pass;
			DC_FLAGS flags;

			if ( (inf = find_device(argv[2])) == NULL ) {
				resl = ST_NF_DEVICE; break;
			}

			if (inf->status.flags & F_SYNC) {
				resl = dc_decrypt_loop(inf);
				break;
			}

			if ( !(inf->status.flags & F_ENABLED) ) {
				wprintf(L"This device is not mounted\n");
				resl = ST_OK; break;
			}

			if (inf->status.flags & F_FORMATTING) {
				wprintf(L"Invalid device state\n");
				resl = ST_OK; break;
			}
			if ( (inf->status.flags & F_SYSTEM) && 
				 (dc_device_control(DC_CTL_GET_FLAGS, NULL, 0, &flags, sizeof(flags)) == NO_ERROR) && (flags.conf_flags & CONF_BLOCK_UNENC_HDDS) )
			{
				wprintf(L"This device can not be decrypted because "
					    L"'Deny access to unencrypted HDD's' option enabled.\n");
				resl = ST_OK; break;
			}
			pass = dc_load_pass_and_keyfiles(NULL, NULL, NULL, 0);

			if (pass == NULL) {
				resl = ST_OK; break;
			}

			resl = dc_start_decrypt(inf->device, pass);

			secure_free(pass);

			if (resl == ST_OK ) {
				resl = dc_decrypt_loop(inf);
			}
			break;
		}

		if ( (argc >= 3) && (wcscmp(argv[1], L"-reencrypt") == 0) ) 
		{
			crypt_info crypt;
			dc_pass   *pass;

			if ( (inf = find_device(argv[2])) == NULL ) {
				resl = ST_NF_DEVICE; break;
			}

			crypt = inf->status.crypt;
			get_crypt_info(&crypt);

			if ( !(inf->status.flags & F_ENABLED) ) {
				wprintf(L"This device is not mounted\n");
				resl = ST_OK; break;
			}

			if (inf->status.flags & F_FORMATTING) {
				wprintf(L"Invalid device state\n");
				resl = ST_OK; break;
			}

			if (inf->status.flags & F_SYNC)
			{
				if (inf->status.flags & F_REENCRYPT)
				{
					resl = dc_encrypt_loop(inf, crypt.wp_mode);
					break;
				} else 
				{
					wprintf(L"This device is not complete encrypted\n");
					resl = ST_OK; break;
				}
			}

			pass = dc_load_pass_and_keyfiles(NULL, NULL, NULL, 0);

			if (pass == NULL) {
				resl = ST_OK; break;
			}

			resl = dc_start_re_encrypt(inf->device, pass, &crypt);

			secure_free(pass);

			if (resl == ST_OK ) {
				resl = dc_encrypt_loop(inf, crypt.wp_mode);
			}
			break;
		}		

		if ( (argc >= 3) && (wcscmp(argv[1], L"-chpass") == 0) ) 
		{
			crypt_info crypt;
			dc_pass   *old_p, *new_p;
			
			if ( (inf = find_device(argv[2])) == NULL ) {
				resl = ST_NF_DEVICE; break;
			}

			if ( !(inf->status.flags & F_ENABLED) ) {
				wprintf(L"This device is not mounted\n");
				resl = ST_OK; break;
			}

			if (inf->status.flags & F_SYNC) {
				wprintf(L"This device is not complete encrypted\n");
				resl = ST_OK; break;
			}

			if (inf->status.flags & F_FORMATTING) {
				wprintf(L"Invalid device state\n");
				resl = ST_OK; break;
			}

			crypt = inf->status.crypt;

			get_crypt_info(&crypt);

			old_p = NULL; new_p = NULL;
			do
			{
				old_p = dc_load_pass_and_keyfiles(
					L"-op", L"-okf", L"Enter old password: ", 0);

				if (old_p == NULL) {
					resl = ST_OK; break;
				}

				new_p = dc_load_pass_and_keyfiles(
					L"-np", L"-nkf", L"Enter new password: ", 1);

				if (new_p == NULL) {
					resl = ST_OK; break;
				}

				resl = dc_change_password(inf->device, old_p, new_p);

				if (resl == ST_OK) {
					wprintf(L"The password successfully changed\n");
				}
			} while (0);

			if (old_p != NULL) {
				secure_free(old_p);
			}

			if (new_p != NULL) {
				secure_free(new_p);
			}
			break;
		}

		if ( (argc >= 3) && (wcscmp(argv[1], L"-format") == 0) ) 
		{
			crypt_info crypt;
			dc_pass   *pass;
			wchar_t   *fs;

			if ( (inf = find_device(argv[2])) == NULL ) {
				resl = ST_NF_DEVICE; break;
			}

			crypt = inf->status.crypt;
			get_crypt_info(&crypt);

			if (inf->status.flags & F_FORMATTING) {				
				resl = ST_OK;
			} else 
			{
				if (inf->status.flags & F_ENABLED) {
					wprintf(L"This device is mounted, please unmount it\n");
					resl = ST_OK; break;
				}

				pass = dc_load_pass_and_keyfiles(NULL, NULL, NULL, 1);

				if (pass == NULL) {
					resl = ST_OK; break;
				}

				resl = dc_start_format(inf->device, pass, &crypt);

				secure_free(pass);
			}

			if (resl == ST_OK) 
			{
				if (is_param(L"-q") != 0) {
					resl = dc_done_format(inf->device);
				} else {
					resl = dc_format_loop(inf, crypt.wp_mode);
				}

				if (is_param(L"-ntfs") != 0) {
					fs = L"NTFS";
				} else if (is_param(L"-fat") != 0) {
					fs = L"FAT";
				} else if (is_param(L"-fat32") != 0) {
					fs = L"FAT32";
				} else if (is_param(L"-exfat") != 0) {
					fs = L"exFAT";
				} else fs = NULL;

				if (resl == ST_OK) 
				{
					wprintf(L"Creating file system...\n");

					if (fs != NULL) {
						resl = dc_format_fs(inf->w32_device, fs);
					}

					if (resl == ST_OK) {
						wprintf(L"Formatting successfully completed.\n");
					}
				}
			}
			break;
		}

		if ( (argc >= 2) && (wcscmp(argv[1], L"-benchmark") == 0) ) 
		{
			dc_bench_info info;
			bench_item    bench[CF_CIPHERS_NUM];
			int           i;			

			for (i = 0; i < CF_CIPHERS_NUM; i++) {
				if (dc_benchmark(i, &info) != ST_OK) break;
				bench[i].alg   = dc_get_cipher_name(i);
				bench[i].speed = (double)info.datalen / ( (double)info.enctime / (double)info.cpufreq) / 1024 / 1024;
			}
			qsort(&bench, CF_CIPHERS_NUM, sizeof(bench[0]), dc_bench_cmp);

			wprintf(
				L"---------------------+--------------\n"
				L"        cipher       |     speed\n"
				L"---------------------+--------------\n");			

			for (i = 0; i < CF_CIPHERS_NUM; i++) {
				wprintf(L" %-19s | %-.2f mb/s\n", bench[i].alg, bench[i].speed);
			}
			resl = ST_OK; break;
		}

		if ( (argc >= 4) && (wcscmp(argv[1], L"-backup") == 0) ) 
		{
			dc_pass *pass;
			u8       backup[DC_AREA_SIZE];

			if ( (inf = find_device(argv[2])) == NULL ) {
				resl = ST_NF_DEVICE; break;
			}

			if (inf->status.flags & F_SYNC) {
				wprintf(L"This device is not complete encrypted\n");
				resl = ST_OK; break;
			}

			pass = dc_load_pass_and_keyfiles(NULL, NULL, NULL, 0);

			if (pass == NULL) {
				resl = ST_OK; break;
			}

			resl = dc_backup_header(inf->device, pass, backup);

			secure_free(pass);

			if (resl == ST_OK) {
				resl = save_file(argv[3], backup, sizeof(backup));
			}

			if (resl == ST_OK) {
				wprintf(L"Volume header backup successfully saved.\n");
			}			
		}

		if ( (argc >= 4) && (wcscmp(argv[1], L"-restore") == 0) ) 
		{
			dc_pass *pass;
			u8      *backup;
			u32      bytes;

			if ( (inf = find_device(argv[2])) == NULL ) {
				resl = ST_NF_DEVICE; break;
			}

			if (inf->status.flags & F_ENABLED) {
				wprintf(L"Please unmount device first\n");
				resl = ST_OK; break;
			}

			do
			{
				if ( (resl = load_file(argv[3], &backup, &bytes)) != ST_OK ) {
					backup = NULL; break;
				}

				if (bytes != DC_AREA_SIZE) {
					resl = ST_NOT_BACKUP; break;
				}

				pass = dc_load_pass_and_keyfiles(NULL, NULL, NULL, 0);

				if (pass == NULL) {
					resl = ST_OK; break;
				}

				resl = dc_restore_header(inf->device, pass, backup);

				secure_free(pass);
			} while (0);

			/* prevent leaks */
			if (backup != NULL) {
				burn(backup, DC_AREA_SIZE);
				free(backup);
			}

			if (resl == ST_OK) {
				wprintf(L"Volume header successfully restored.\n");
			}
		}

		if ( (argc >= 2) && (wcscmp(argv[1], L"-config") == 0) ) 
		{
			dc_conf_data dc_conf;

			if ( (resl = dc_load_config(&dc_conf) == NO_ERROR ? ST_OK : ST_ERROR) != ST_OK ) {
				break;
			}

			do
			{
				vol_inf *inf = find_device(NULL);
				int      onoff;
				char     ch;	

				cls_console();

				wprintf(
					L"0 - On/Off passwords caching (%s)\n"
					L"1 - On/Off hiding $dcsys$ files (%s)\n"
					L"2 - On/Off hardware cryptography support (%s)\n"
					L"3 - On/Off automounting at boot time (%s)\n"
					L"4 - On/Off optimization for SSD disks (%s)\n"
					L"5 - On/Off disable TRIM on encrypted SSD disks (%s)\n"
					L"--------------------------------------------------\n"
					L"6 - On/Off Deny access to unencrypted removable devices (%s)\n"
					L"7 - On/Off Deny access to unencrypted HDD's (%s)\n"
					L"8 - On/Off Deny access to unencrypted CDROM (%s)\n"
					L"--------------------------------------------------\n"
					L"9 - Save changes and exit\n\n",				
					on_off(dc_conf.conf_flags & CONF_CACHE_PASSWORD),
					on_off(dc_conf.conf_flags & CONF_HIDE_DCSYS),
					(dc_conf.load_flags & DST_HW_CRYPTO) ? 
					    on_off(dc_conf.conf_flags & CONF_HW_CRYPTO) : L"not available",
					on_off(dc_conf.conf_flags & CONF_AUTOMOUNT_BOOT),
					on_off(dc_conf.conf_flags & CONF_ENABLE_SSD_OPT),
					on_off(dc_conf.conf_flags & CONF_DISABLE_TRIM),
					on_off(dc_conf.conf_flags & CONF_BLOCK_UNENC_REMOVABLE),
					(inf != NULL && IS_BLOCK_UNENC_HDDS_DISABLED(inf->status.flags) == 0) ?
					    on_off(dc_conf.conf_flags & CONF_BLOCK_UNENC_HDDS) : L"non permitted",
					on_off(dc_conf.conf_flags & CONF_BLOCK_UNENC_CDROM)
					);

				if ( (ch = getchr('0', '9')) == '9' ) {
					break;
				}

				if ( ((ch == '2') && (dc_conf.load_flags & DST_HW_CRYPTO) == 0) ||
					 ((ch == '7') && (inf == NULL || IS_BLOCK_UNENC_HDDS_DISABLED(inf->status.flags))) )
				{
					continue;
				}

				wprintf(L"0 - OFF\n1 - ON\n"); onoff = (getchr('0', '1') == '1');

				switch (ch) {
					case '0': set_flag(dc_conf.conf_flags, CONF_CACHE_PASSWORD, onoff); break;
					case '1': set_flag(dc_conf.conf_flags, CONF_HIDE_DCSYS, onoff); break;
					case '2': set_flag(dc_conf.conf_flags, CONF_HW_CRYPTO, onoff); break;
					case '3': set_flag(dc_conf.conf_flags, CONF_AUTOMOUNT_BOOT, onoff); break;
					case '4': set_flag(dc_conf.conf_flags, CONF_ENABLE_SSD_OPT, onoff); break;
					case '5': set_flag(dc_conf.conf_flags, CONF_DISABLE_TRIM, onoff); break;
					/**/
					case '6': set_flag(dc_conf.conf_flags, CONF_BLOCK_UNENC_REMOVABLE, onoff); break;
					case '7': set_flag(dc_conf.conf_flags, CONF_BLOCK_UNENC_HDDS, onoff); break;
					case '8': set_flag(dc_conf.conf_flags, CONF_BLOCK_UNENC_CDROM, onoff); break;
				}
			} while (1);

			if ( (resl = dc_save_config(&dc_conf) == NO_ERROR ? ST_OK : ST_ERROR) == ST_OK ) {
				wprintf(L"Configuration successfully saved\n");
			}
		}

		if ( (argc >= 3) && (wcscmp(argv[1], L"-keygen") == 0) )
		{
			u8 kf[64];

			resl = dc_device_control(DC_CTL_GET_RAND, NULL, 0, kf, sizeof(kf)) == NO_ERROR ? ST_OK : ST_ERROR;

			if ( resl != ST_OK ) {
				break;
			}
			resl = save_file(argv[2], kf, sizeof(kf));
			/* prevent leaks */
			burn(kf, sizeof(kf));
		}

		if ( (argc >= 2) && (wcscmp(argv[1], L"-bsod") == 0) ) 
		{
			dc_get_bsod(); resl = ST_OK;
			break;
		}

		if ( (argc >= 4) && (wcscmp(argv[1], L"-enciso") == 0) ) 
		{
			dc_pass   *pass;			
			crypt_info crypt;
			
			/* get encryption params */
			crypt.cipher_id = CF_AES;
			get_crypt_info(&crypt);

			pass = dc_load_pass_and_keyfiles(NULL, NULL, NULL, 1);

			if (pass == NULL) {
				resl = ST_OK; break;
			}

			resl = (dc_encrypt_iso_image(argv[2], argv[3], pass, crypt.cipher_id, dc_cd_callback, NULL) == NO_ERROR) ? ST_OK : ST_ERROR;

			_putch('\n');

			secure_free(pass);

			if (resl == ST_OK) {
				wprintf(L"ISO image successfully encrypted.\n");
			}
			if (resl == ST_CANCEL) { resl = ST_OK; }
		}
	} while (0);

	if (resl != ST_OK) {
		wprintf(L"Error: %d\n", resl);
	}

	return resl;
}
