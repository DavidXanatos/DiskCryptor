/*
    *
    * DiskCryptor - open source partition encryption tool
	* Copyright (c) 2008
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
#include "drv_ioctl.h"
#include "bootloader.h"
#include "misc.h"
#include "mbrinst.h"
#include "disk_name.h"
#include "console.h"

static int onoff_req()
{
	wprintf(L"0 - OFF\n1 - ON\n");

	return getchr('0', '1') == '1';
}

static void menu_0_1(ldr_config *conf)
{
	wchar_t  auth[MAX_PATH];
	wchar_t *dp_type;
	char     ch;
			
	do
	{
		cls_console();

		if (conf->options & LDR_OP_EPS_TMO) 
		{
			_snwprintf(
				auth, countof(auth), L"%d seconds", conf->timeout);
		} else {
			wcscpy(auth, L"disabled");
		}

		if (conf->logon_type & LDR_LT_DSP_PASS) {
			dp_type = L"display \"*\"";
		} else {
			dp_type = L"disabled";
		}

		wprintf(
			L"1 - On/Off \"enter password\" message (%s)\n"
			L"2 - Change display password type (%s)\n"
			L"3 - Change password prompt text (%S)\n"
			L"4 - Enable embedded keyfile (%s)\n"
			L"5 - Change authentication timeout (%s)\n"
			L"6 - Cancel timeout if any key pressed (%s)\n"
			L"7 - Return to main menu\n\n",
			on_off(conf->logon_type & LDR_LT_MESSAGE),
			dp_type,
			conf->eps_msg,
			conf->logon_type & LDR_LT_EMBED_KEY ? L"enabled":L"disabled",
			auth,
			on_off(conf->options & LDR_OP_TMO_STOP));

		if ( (ch = getchr('1', '7')) == '7' ) {
			break;
		}

		if (ch == '1') {
			set_flag(conf->logon_type, LDR_LT_MESSAGE, onoff_req());
		}

		if (ch == '2')
		{
			wprintf(
				L"1 - disabled\n"
				L"2 - display \"*\"\n");

			if (getchr('1', '2') == '2') {
				conf->logon_type |= LDR_LT_DSP_PASS;
			} else {
				conf->logon_type &= ~LDR_LT_DSP_PASS;
			}
		}

		if (ch == '3') 
		{
			wprintf(L"Enter new prompt text: ");

			memset(conf->eps_msg, 0, sizeof(conf->eps_msg));
			fgets(conf->eps_msg, _countof(conf->eps_msg), stdin);
			conf->eps_msg[strlen(conf->eps_msg) - 1] = 0;
		}

		if (ch == '4')
		{
			wchar_t path[MAX_PATH];
			u8     *keyfile;
			u32     keysize;

			wprintf(L"Please enter path to keyfile: ");

			memset(&conf->emb_key, 0, sizeof(conf->emb_key));
			conf->logon_type &= ~LDR_LT_EMBED_KEY;
			conf->logon_type |= LDR_LT_GET_PASS;
			
			fgetws(path, _countof(path), stdin);
			path[wcslen(path) - 1] = 0;
			
			if (path[0] != 0)
			{
				if (load_file(path, &keyfile, &keysize) != ST_OK) {
					wprintf(L"keyfile not loaded\n");
					Sleep(1000);
				} else
				{
					if (keysize != 64) {
						wprintf(L"Embedded keyfile must be 64byte size\n");						
						Sleep(1000);
					} else 
					{
						wprintf(
							L"1 - Use embedded keyfile and password\n"
							L"2 - Use only embedded keyfile\n");

						if (getchr('1', '2') == '2') {							
							conf->logon_type &= ~LDR_LT_GET_PASS;
						}

						memcpy(&conf->emb_key, keyfile, sizeof(conf->emb_key));
						conf->logon_type |= LDR_LT_EMBED_KEY;
					}
					burn(keyfile, keysize);
					free(keyfile);
				}
			}
		}

		if (ch == '5')
		{				
			wprintf(L"Enter new timeout in seconds or 0 to disable: ");

			if (wscanf(L"%d", &conf->timeout) == 0) {
				conf->timeout = 0;
			}

			set_flag(conf->options, LDR_OP_EPS_TMO, (conf->timeout != 0));
		}

		if (ch == '6') {
			set_flag(conf->options, LDR_OP_TMO_STOP, onoff_req());
		}
	} while (1);
}

static void menu_0_2(ldr_config *conf)
{
	wchar_t *action;
	char     inv_msg[MAX_PATH];
	int      msgf, i, j;
	char     ch;	

	do
	{
		cls_console();

		action = L"halt system";

		if (conf->error_type & LDR_ET_REBOOT) {
			action = L"reboot system";
		}

		if (conf->error_type & LDR_ET_BOOT_ACTIVE) {
			action = L"boot from active partition";
		}

		if (conf->error_type & LDR_ET_EXIT_TO_BIOS) {
			action = L"exit to BIOS";
		}

		if (conf->error_type & LDR_ET_RETRY) {
			action = L"retry authentication";
		}

		if (conf->error_type & LDR_ET_MBR_BOOT) {
			action = L"load boot disk MBR";
		}

		for (i = 0, j = 0; i < sizeof(conf->err_msg); i++) {
			if (conf->err_msg[i] != '\n') {
				inv_msg[j++] = conf->err_msg[i];
			}
		}

		inv_msg[j] = 0;

		wprintf(
			L"1 - On/Off invalid password message (%s)\n"
			L"2 - Invalid password action (%s)\n"
			L"3 - Invalid password message (%S)\n"
			L"4 - Return to main menu\n\n",
			on_off(conf->error_type & LDR_ET_MESSAGE),
			action, inv_msg);

		if ( (ch = getchr('1', '4')) == '4' ) {
			break;
		}

		if (ch == '1') {
			set_flag(conf->error_type, LDR_ET_MESSAGE, onoff_req());
		}

		if (ch == '2')
		{
			wprintf(
				L"1 - halt system\n"
				L"2 - reboot system\n"
				L"3 - boot from active partition\n"
				L"4 - load boot disk MBR\n"
				L"5 - exit to BIOS\n"
				L"6 - retry authentication\n");

			msgf = (conf->error_type & LDR_ET_MESSAGE);

			switch (getchr('1', '6'))
			{
				case '1': conf->error_type = 0; break;
				case '2': conf->error_type = LDR_ET_REBOOT; break;
				case '3': conf->error_type = LDR_ET_BOOT_ACTIVE; break;
				case '4': conf->error_type = LDR_ET_MBR_BOOT; break;
				case '5': conf->error_type = LDR_ET_EXIT_TO_BIOS; break;
				case '6': conf->error_type = LDR_ET_RETRY; break;
			}

			conf->error_type |= msgf;
		}

		if (ch == '3') 
		{
			wprintf(L"Enter new message text: ");

			memset(conf->err_msg, 0, sizeof(conf->err_msg));
			fgets(conf->err_msg, _countof(conf->err_msg), stdin);
		}
	} while (1);
}

static u32 disk_id_select()
{
	vol_inf *vol;
	u32      i, idn = 0;
	u32      ids[MAX_VOLUMES];
	wchar_t  s_size[MAX_PATH];
	u32      id = 0;

	for (i = 0; i < vol_cnt; i++)
	{
		vol = &volumes[i];

		if ( (vol->status.flags & F_ENABLED) && (vol->status.disk_id != 0) ) 
		{
			dc_format_byte_size(
				s_size, countof(s_size), vol->status.dsk_size
				);

			if (idn == 0) {
				wprintf(L"\nSelect partition:\n");
			}

			ids[idn++] = vol->status.disk_id;

			wprintf(
				L"%d - pt%d (%s) (%s)\n", 
				idn, i, vol->status.mnt_point, s_size);		
		}
	}

	if (idn == 0) {
		wprintf(L"Mounted partitions with valid disk_id not found\n");
		_getch();
	} else {
		id = ids[getchr('1', '1'+(u8)idn-1) - '1'];
	}

	return id;
}

static void menu_0_3(ldr_config *conf)
{
	wchar_t *methd = NULL;
	wchar_t  part[MAX_PATH];
	wchar_t  s_size[MAX_PATH];
	u32      i, found, id;
	char     ch;
	vol_inf *vol;	

	do
	{
		cls_console();

		switch (conf->boot_type)
		{
			case LDR_BT_MBR_BOOT: methd = L"load boot disk MBR"; break;
			case LDR_BT_MBR_FIRST: methd = L"load first disk MBR"; break;
			case LDR_BT_ACTIVE: methd = L"load OS from active partition"; break;
			case LDR_BT_AP_PASSWORD: methd = L"boot from first partition with appropriate password"; break;
			case LDR_BT_DISK_ID:
				{
					/* find partition by disk_id */
					found = 0;
					for (i = 0; i < vol_cnt; i++)
					{
						vol = &volumes[i];

						if ( (vol->status.flags & F_ENABLED) && (vol->status.disk_id == conf->disk_id) ) 
						{
							dc_format_byte_size(
								s_size, countof(s_size), vol->status.dsk_size);

							_snwprintf(
								part, countof(part), L"boot from pt%d (%s) (%s)", 
								i, vol->status.mnt_point, s_size);
							found = 1;
						}
					}

					if (found == 0) 
					{
						_snwprintf(
							part, countof(part), L"boot from unknown partition, id %0.8x", conf->disk_id);
					}
					methd = part;
				}
			break;
		}

		if (conf->options & LDR_OP_EXTERNAL)
		{
			wprintf(
				L"Current booting method: %s\n\n"
				L"1 - Set \"load first disk MBR\"\n"
				L"2 - Set \"boot from first partition with appropriate password\"\n"
				L"3 - Set \"boot from specified partition\"\n"
				L"4 - Return to main menu\n\n",
				methd);
		} else 
		{
			wprintf(
				L"Current booting method: %s\n\n"
				L"1 - Set \"load boot disk MBR\"\n"
				L"2 - Set \"load first disk MBR\"\n"
				L"3 - Set \"load OS from active partition\"\n"
				L"4 - Set \"boot from first partition with appropriate password\"\n"
				L"5 - Set \"boot from specified partition\"\n"
				L"6 - Return to main menu\n\n",
				methd);
		}

		if (conf->options & LDR_OP_EXTERNAL)
		{
			if ( (ch = getchr('1', '4')) == '4' ) {
				break;
			}

			switch (ch)
			{
				case '1': conf->boot_type = LDR_BT_MBR_FIRST; break;
				case '2': conf->boot_type = LDR_BT_AP_PASSWORD; break;
				case '3': 
					{
						if ( (id = disk_id_select()) != 0 ) {
							conf->disk_id   = id;
							conf->boot_type = LDR_BT_DISK_ID;
						}
					}
				break;
			}
		} else 
		{
			if ( (ch = getchr('1', '6')) == '6' ) {
				break;
			}

			switch (ch)
			{
				case '1': conf->boot_type = LDR_BT_MBR_BOOT; break;
				case '2': conf->boot_type = LDR_BT_MBR_FIRST; break;
				case '3': conf->boot_type = LDR_BT_ACTIVE; break;
				case '4': conf->boot_type = LDR_BT_AP_PASSWORD; break;
				case '5':
					{
						if ( (id = disk_id_select()) != 0 ) {
							conf->disk_id   = id;
							conf->boot_type = LDR_BT_DISK_ID;
						}
					}
				break;
			}
		}
	} while (1);
}

static void menu_0_4(ldr_config *conf)
{
	wchar_t *layout = NULL;
	char     ch; 

	do
	{
		cls_console();

		switch (conf->kbd_layout)
		{
			case LDR_KB_QWERTY: layout = L"QWERTY"; break;
			case LDR_KB_QWERTZ: layout = L"QWERTZ"; break;
			case LDR_KB_AZERTY: layout = L"AZERTY"; break;
		}

		wprintf(
			L"Current keyboard layout: %s\n\n"
			L"1 - Set layout to \"QWERTY\"\n"
			L"2 - Set layout to \"QWERTZ\"\n"
			L"3 - Set layout to \"AZERTY\"\n"
			L"4 - Return to main menu\n\n",
			layout);

		if ( (ch = getchr('1', '4')) == '4' ) {
			break;
		}

		switch (ch)
		{
			case '1': conf->kbd_layout = LDR_KB_QWERTY; break;
			case '2': conf->kbd_layout = LDR_KB_QWERTZ; break;
			case '3': conf->kbd_layout = LDR_KB_AZERTY; break;			
		}
	} while (1);
}

void boot_conf_menu(ldr_config *conf, wchar_t *msg)
{
	char ch;

	do
	{
		cls_console();

		if (msg != NULL) {
			wprintf(L"%s\n\n", msg);
		}

		wprintf(
			L"1 - Change logon options\n"
			L"2 - Change incorrect password action\n"
			L"3 - Use incorrect password action if no password entered (%s)\n"
			L"4 - Use hardware cryptography when possible (%s)\n"
			L"5 - Set booting method\n"
			L"6 - Set bootauth keyboard layout\n"
			L"7 - Save changes and exit\n\n",
			on_off(conf->options & LDR_OP_NOPASS_ERROR),
			on_off(conf->options & LDR_OP_HW_CRYPTO)
			);

		if ( (ch = getchr('1', '7')) == '7' ) {
			break;
		}

		switch (ch)
		{
			case '1': menu_0_1(conf); break;
			case '2': menu_0_2(conf); break;
			case '3': {
				set_flag(conf->options, LDR_OP_NOPASS_ERROR, onoff_req());
			}
			break;
			case '4': {
				set_flag(conf->options, LDR_OP_HW_CRYPTO, onoff_req());
			}
			break;
			case '5': menu_0_3(conf); break;
			case '6': menu_0_4(conf); break;
		}
	} while (1);
}

static int dsk_num(wchar_t *str, int *num) 
{
	if ( (str[0] == L'h') && (str[1] == L'd') && (isdigit(str[2]) != 0) ) {
		num[0] = _wtoi(str+2);
		return 1;
	} else {
		return 0;
	}
}

int boot_menu(int argc, wchar_t *argv[])
{
	ldr_config conf;
	int        resl;
	int        is_small;

	is_small = is_param(L"-small");
	do
	{
		if ( (argc == 3) && (wcscmp(argv[2], L"-enum") == 0) )
		{
			wchar_t  s_size[MAX_PATH];
			wchar_t  h_name[MAX_PATH];
			wchar_t *str;
			u64      size;
			int      i, bd_1, bd_2;

			wprintf(
				L"--------------------------------------------------------------\n"
				L"HDD |           name           |  size   | bootable | bootloader\n" 
				L"----+--------------------------+---------+----------+-----------\n");

			if (dc_get_boot_disk(&bd_1, &bd_2) != ST_OK) {
				bd_1 = bd_2 = -1;
			}

			for (i = 0; i < 100; i++)
			{
				if (size = dc_dsk_get_size(i, 0)) 
				{
					dc_format_byte_size(s_size, countof(s_size), size);

					if (dc_get_hw_name(i, 0, h_name, countof(h_name)) != ST_OK) {
						h_name[0] = 0;
					}
					
					if (dc_get_mbr_config(i, NULL, &conf) == ST_OK) {
						str = L"installed"; 
					} else {
						str = L"none";
					}

					wprintf(
						L"hd%d | %-24s | %-8s| %-8s | %s\n", 
						i, h_name, s_size, (i == bd_1) || (i == bd_2) ? L"yes":L"no", str
						);
				} 
			}
			resl = ST_OK; break;
		}

		if ( (argc >= 4) && (wcscmp(argv[2], L"-setmbr") == 0) )
		{
			int d_num;
			
			if (dsk_num(argv[3], &d_num) == 0) {
				resl = ST_OK; break;
			}			

			if ( (resl = dc_set_boot_interactive(d_num, is_small)) == ST_OK) {
				wprintf(L"Bootloader successfully installed to %s\n", argv[3]);
			}
			break; 
		}

		if ( (argc == 4) && (wcscmp(argv[2], L"-delmbr") == 0) )
		{
			int d_num;
			
			if (dsk_num(argv[3], &d_num) == 0) {
				resl = ST_OK; break;
			}

			if ( (resl = dc_unset_mbr(d_num)) == ST_OK ) {
				wprintf(L"Bootloader successfully removed from %s\n", argv[3]);
			}
			break;
		}

		if ( (argc == 4) && (wcscmp(argv[2], L"-updmbr") == 0) )
		{
			int d_num;
			
			if (dsk_num(argv[3], &d_num) == 0) {
				resl = ST_OK; break;
			}

			if ( (resl = dc_update_boot(d_num)) == ST_OK ) {
				wprintf(L"Bootloader on %s successfully updated\n", argv[3]);
			}
			break;
		}	

		if ( (argc >= 4) && (wcscmp(argv[2], L"-setpar") == 0) )
		{
			if ( (resl = dc_set_boot(argv[3], 0, is_small)) == ST_FORMAT_NEEDED )
			{
				wprintf(
				   L"Removable media not correctly formatted\n"
				   L"Format media? (Y/N)\n"
				   );

				if (tolower(_getch()) == 'y') {
					resl = dc_set_boot(argv[3], 1, is_small);
				} else {
					resl = ST_OK; break;
				}
			}

			if (resl != ST_OK) {
				break;
			}

			if ( (resl = dc_mbr_config_by_partition(argv[3], 0, &conf)) != ST_OK ) {
				break;
			}

			conf.options  |= LDR_OP_EXTERNAL;
			conf.boot_type = LDR_BT_AP_PASSWORD;

			boot_conf_menu(
				&conf, L"Please set bootloader options:");

			if ( (resl = dc_mbr_config_by_partition(argv[3], 1, &conf)) == ST_OK ) {
				wprintf(L"Bootloader successfully installed\n");
			}
			break;
		}

		if ( (argc >= 4) && (wcscmp(argv[2], L"-makeiso") == 0) )
		{
			if ( (resl = dc_make_iso(argv[3], is_small)) != ST_OK ) {
				break;
			}

			if ( (resl = dc_get_mbr_config(0, argv[3], &conf)) != ST_OK ) {
				break;
			}

			conf.options  |= LDR_OP_EXTERNAL;
			conf.boot_type = LDR_BT_MBR_FIRST;

			boot_conf_menu(
				&conf, L"Please set bootloader options:");

			if ( (resl = dc_set_mbr_config(0, argv[3], &conf)) == ST_OK ) {
				wprintf(L"Bootloader .iso image successfully created\n", argv[3]);
			}
			break;
		}

		if ( (argc >= 4) && (wcscmp(argv[2], L"-makepxe") == 0) )
		{
			if ( (resl = dc_make_pxe(argv[3], is_small)) != ST_OK ) {
				break;
			}

			if ( (resl = dc_get_mbr_config(0, argv[3], &conf)) != ST_OK ) {
				break;
			}

			conf.options  |= LDR_OP_EXTERNAL;
			conf.boot_type = LDR_BT_MBR_FIRST;

			boot_conf_menu(
				&conf, L"Please set bootloader options:");

			if ( (resl = dc_set_mbr_config(0, argv[3], &conf)) == ST_OK ) {
				wprintf(L"Bootloader PXE image successfully created\n", argv[3]);
			}
			break;
		}

		if ( (argc == 4) && (wcscmp(argv[2], L"-config") == 0) )
		{
			int      d_num;
			wchar_t *file;
			int      ispar;
			
			if ( ((argv[3][1] == L':')  && (argv[3][2] == 0)) ||
				 ((argv[3][0] == L'\\') && (argv[3][5] == L':')) )
			{
				ispar = 1;
			} else 
			{
				if (dsk_num(argv[3], &d_num) == 0) {
					file = argv[3]; d_num = 0;
				} else {
					file = NULL;
				}

				ispar = 0;
			}

			if (ispar != 0) {
				resl = dc_mbr_config_by_partition(argv[3], 0, &conf);
			} else {
				resl = dc_get_mbr_config(d_num, file, &conf);
			}

			if (resl != ST_OK) {
				break;
			}

			boot_conf_menu(
				&conf, L"Please change bootloader options:");

			if (ispar != 0) {
				resl = dc_mbr_config_by_partition(argv[3], 1, &conf);
			} else {
				resl = dc_set_mbr_config(d_num, file, &conf);
			}

			if (resl == ST_OK) {
				wprintf(L"Bootloader configuration successfully changed\n");
			}
			break;
		}
	} while (0);

	return resl;
}