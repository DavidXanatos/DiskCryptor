/*
    *
    * DiskCryptor - open source partition encryption tool
	* Copyright (c) 2019-2026
	* DavidXanatos <info@diskcryptor.org>
	* Copyright (c) 2007-2010
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

#include "main.h"
#include "dlg_menu.h"

#include "xts_fast.h"
#include "threads.h"
#include "prc_pass.h"
#include "prc_wizard_encrypt.h"

void _state_menu(
		HMENU	menu,
		UINT	state
	)
{
	int count = GetMenuItemCount(menu);
	char k = 0;

	for ( ; k < count; k++ ) 
	{
		EnableMenuItem( menu, GetMenuItemID(menu, k), state );
	}
}


void _refresh_menu( )
{
	HMENU   h_menu       = GetMenu( __dlg );
	_dnode *node         = pv(_get_sel_item( __lists[HMAIN_DRIVES] ));
	_dact  *act          = _create_act_thread( node, -1, -1 );
	wchar_t ws_display[MAX_PATH];
	wchar_t ws_new_display[MAX_PATH];

	BOOL    unmount      = FALSE, mount		= FALSE;
	BOOL    decrypt      = FALSE, encrypt	= FALSE;
	BOOL    backup       = FALSE, restore	= FALSE;
	BOOL    format       = FALSE, reencrypt	= FALSE;
	BOOL    del_mntpoint = FALSE, ch_pass	= FALSE;

	if ( node && ListView_GetSelectedCount( __lists[HMAIN_DRIVES] ) && 
		 !_is_root_item( (LPARAM)node ) &&
	 	  _is_active_item( (LPARAM)node )
		 )
	{
		int flags = node->mnt.info.status.flags;
	
		del_mntpoint = 
			wcsstr( node->mnt.info.status.mnt_point, L"\\\\?\\" ) == 0 && 
			IS_UNMOUNTABLE( &node->mnt.info.status );

		if ( flags & F_CDROM )
		{
			if ( flags & F_ENABLED )
			{
				unmount = TRUE;
			} else 
			{
				if ( *node->mnt.fs == '\0' )
				{
					mount = TRUE;
				}
			}
		} else 
		{
			backup = !( flags & F_SYNC );
	
			if ( flags & F_ENABLED )
			{
				if ( flags & F_FORMATTING )
				{
					format = TRUE;
				} else 
				{
					if ( IS_UNMOUNTABLE( &node->mnt.info.status ) ) 
					{
						unmount = TRUE;
					}
					if (! (act && act->status == ACT_RUNNING) )
					{
						if (! (flags & F_REENCRYPT) ) decrypt = TRUE;
						if (! (flags & F_SYNC) ) ch_pass = TRUE;

						if ( flags & F_SYNC )
						{
							encrypt = TRUE;
						} else {
							reencrypt = TRUE;
						}
					}
				}
			} else 
			{
				restore = TRUE;
				if ( IS_UNMOUNTABLE( &node->mnt.info.status ) ) 
				{
					format = TRUE;
				}	
				if ( *node->mnt.fs == '\0' )
				{
					mount = TRUE;
				}	else {
					encrypt = TRUE;
				}
			}
		}
	}
	{
		HWND h_mount = GetDlgItem(__dlg, IDC_BTN_MOUNT_);

		GetWindowText( h_mount, ws_display, countof(ws_display) );
		wcscpy( ws_new_display, unmount ? IDS_UNMOUNT : IDS_MOUNT );

		if ( ( wcscmp( ws_display, ws_new_display ) != 0 ) || ( IsWindowEnabled(h_mount) != ( unmount || mount ) ) )
		{
			SetWindowText( h_mount, unmount ? IDS_UNMOUNT : IDS_MOUNT );
			EnableWindow( h_mount, unmount || mount );
#ifdef LOG_FILE
			_log( 
				L"func:menu refresh; mount button from \"%s\" %d to \"%s\" %d", 
				ws_display, IsWindowEnabled( h_mount ), ws_new_display, unmount || mount 
				);
#endif
		}
	}
	EnableWindow( GetDlgItem(__dlg, IDC_BTN_ENCRYPT_), encrypt );
	EnableWindow( GetDlgItem(__dlg, IDC_BTN_DECRYPT_), decrypt );

	EnableMenuItem( h_menu, ID_VOLUMES_MOUNT, _menu_onoff(mount) );
	EnableMenuItem( h_menu, ID_VOLUMES_ENCRYPT, _menu_onoff(encrypt) );

	EnableMenuItem( h_menu, ID_VOLUMES_DISMOUNT, _menu_onoff(unmount) );
	EnableMenuItem( h_menu, ID_VOLUMES_DECRYPT, _menu_onoff(decrypt) );

	EnableMenuItem( h_menu, ID_VOLUMES_BACKUPHEADER, _menu_onoff(backup) );
	EnableMenuItem( h_menu, ID_VOLUMES_RESTOREHEADER, _menu_onoff(restore) );

	EnableMenuItem( h_menu, ID_VOLUMES_CHANGEPASS, _menu_onoff(ch_pass) );
	EnableMenuItem( h_menu, ID_VOLUMES_DELETE_MNTPOINT, _menu_onoff(del_mntpoint) );

	EnableMenuItem( h_menu, ID_VOLUMES_FORMAT, _menu_onoff(format) );
	EnableMenuItem( h_menu, ID_VOLUMES_REENCRYPT, _menu_onoff(reencrypt) );

}


int _finish_formatting(
		_dnode *node
	)
{
	int rlt;

	if ( wcscmp(node->dlg.fs_name, L"RAW") != 0 )
	{
		rlt = dc_format_fs( node->mnt.info.w32_device, node->dlg.fs_name );
	}
	if (rlt != ST_OK) 
	{
		__error_s(
			__dlg, L"Error formatting volume [%s]", rlt, node->mnt.info.status.mnt_point
			);
	}
	return rlt;
}


static 
int _bench_cmp(
		const bench_item *arg1, 
		const bench_item *arg2
	)
{
	if ( arg1->speed > arg2->speed )
	{
		return -1;
	} else {
		return ( arg1->speed < arg2->speed );
	}
}


int _benchmark(
		bench_item *bench	
	)
{
	dc_bench_info info;
	int           i;

	for ( i = 0; i < CF_CIPHERS_NUM; i++ )
	{
		if ( dc_benchmark(i, &info) != ST_OK ) break;
		bench[i].alg   = dc_get_cipher_name(i);
		bench[i].speed = (double)info.datalen / ( (double)info.enctime / (double)info.cpufreq) / 1024 / 1024;
	}
	qsort( bench, CF_CIPHERS_NUM, sizeof(bench[0]), _bench_cmp );
	return CF_CIPHERS_NUM;
}


int _menu_update_loader(
		HWND     hwnd,
		wchar_t *vol,
		int      dsk_num
	)
{
	int rlt = ST_ERROR;
	int is_dcs;

	is_dcs = dc_is_dcs_on_disk(dsk_num);
	if (is_dcs)
		rlt = dc_update_efi_boot (dsk_num);
	else
		rlt = dc_update_boot(dsk_num);

	if ( rlt == ST_OK )
	{
		__msg_i( hwnd, L"%s Bootloader on [%s] successfully updated\n", is_dcs ? L"EFI" : L"MBR", vol );
	} else {
		__error_s( hwnd, L"Error update %s bootloader\n", rlt, is_dcs ? L"EFI" : L"MBR");
	}

	return rlt;
}


int _menu_unset_loader(
		HWND     hwnd,
		wchar_t *vol,
		int      dsk_num,
		int      type
	)
{
	int rlt = ST_ERROR;
	int is_dcs;

	if ( type == CTL_LDR_STICK )
	{
		wchar_t dev[MAX_PATH];
		drive_inf inf;

		_snwprintf( dev, countof(dev), L"\\\\.\\%s", vol );
		rlt = dc_get_drive_info(dev, &inf);

		if ( rlt == ST_OK )
		{
			if ( inf.dsk_num == 1 )
			{
				dsk_num = inf.disks[0].number;
			} else {
				__msg_w( hwnd, L"One volume on two disks\nIt's very strange..." );
				return rlt;
			}								
		}
	}

	if ( __msg_q(
			hwnd, 
			L"Are you sure you want to remove bootloader\n"
			L"from [%s]?", vol)
			)
	{
		is_dcs = dc_is_dcs_on_disk(dsk_num);
		if ( is_dcs ) {
			rlt = dc_unset_efi_boot(dsk_num);

			if ( rlt == ST_OK && dc_efi_is_bme_set(dsk_num) ) {
				dc_efi_del_bme();
			}
		}
		else
			rlt = dc_unset_mbr(dsk_num);

		if ( rlt == ST_OK )
		{
			__msg_i( hwnd, L"%s Bootloader successfully removed from [%s]\n", is_dcs ? L"EFI" : L"MBR", vol );
		} else {
			__error_s( hwnd, L"Error removing %s bootloader\n", rlt, is_dcs ? L"EFI" : L"MBR" );
		}
		return rlt;
	} else {
		return ST_CANCEL;
	}
}


int _menu_set_loader_mbr(
		HWND     hwnd,
		wchar_t *vol,
		int      dsk_num,
		int      type,
		int      is_small
	)
{
	ldr_config conf;
	int rlt = ST_ERROR;

	if ( type == CTL_LDR_STICK )
	{
		if ( (rlt = dc_set_boot( vol, FALSE, is_small )) == ST_FORMAT_NEEDED )
		{
			if ( __msg_q(
					hwnd,
					L"Removable media not correctly formatted\n"
					L"Format media?\n")
					)
			{
				rlt = dc_set_boot( vol, TRUE, is_small );
			}
		}
		if ( rlt == ST_OK )
		{
			if ( (rlt = dc_mbr_config_by_partition(vol, FALSE, &conf)) == ST_OK )
			{				
				conf.options  |= LDR_OP_EXTERNAL;
				conf.boot_type = LDR_BT_AP_PASSWORD;

				rlt = dc_mbr_config_by_partition(vol, TRUE, &conf);
			}
		}
	} else {							
		rlt = _set_boot_loader_mbr( hwnd, dsk_num, is_small );
	}

	if ( rlt == ST_OK )
	{
		__msg_i( hwnd, L"MBR Bootloader successfully installed to [%s]", vol );
	} else {
		__error_s( hwnd, L"Error installing MBR bootloader", rlt );
	}
	return rlt;

}

int _menu_set_loader_efi(
		HWND     hwnd,
		wchar_t *vol,
		int      dsk_num,
		int      type,
		int      is_shim
	)
{
	ldr_config conf;
	int rlt = ST_ERROR;

	if (type == CTL_LDR_STICK)
	{
		if ( (rlt = dc_mk_efi_rec( vol, FALSE, is_shim )) == ST_FORMAT_NEEDED )
		{
			if ( __msg_q(
					hwnd,
					L"Removable media not correctly formatted\n"
					L"Format media?\n")
					)
			{
				rlt = dc_mk_efi_rec( vol, TRUE, is_shim);
			}
		}
		if (rlt == ST_OK)
		{
			if ((rlt = dc_efi_config_by_partition(vol, FALSE, &conf)) == ST_OK)
			{
				conf.options |= LDR_OP_EXTERNAL;
				conf.boot_type = LDR_BT_AP_PASSWORD;

				rlt = dc_efi_config_by_partition(vol, TRUE, &conf);
			}
		}
	}
	else {

		rlt = _set_boot_loader_efi( hwnd, dsk_num, is_shim );
	}

	if (rlt == ST_OK)
	{
		__msg_i(hwnd, L"EFI Bootloader successfully installed to [%s]", vol);
	} else {
		__error_s(hwnd, L"Error install EFI bootloader", rlt);
	}
	return rlt;

}


int _menu_set_loader_file(
		HWND     hwnd,
		wchar_t *path,
		BOOL     iso,
		int      is_small
	)
{
	ldr_config conf;

	int rlt = ST_ERROR;
	wchar_t *s_img = iso ? L"ISO" : L"PXE";

	rlt = iso ? dc_make_iso( path, is_small ) : dc_make_pxe( path, is_small );
	if ( rlt == ST_OK )
	{
		if ( (rlt = dc_get_mbr_config( 0, path, &conf )) == ST_OK )
		{
			conf.options   |= LDR_OP_EXTERNAL;
			conf.boot_type  = LDR_BT_MBR_FIRST;

			rlt = dc_set_mbr_config( 0, path, &conf );
		}			
	}
	if ( rlt == ST_OK )
	{
		__msg_i( hwnd, L"Bootloader %s image file \"%s\" successfully created", s_img, path );
	} else {
		__error_s( hwnd, L"Error creating %s image", rlt, s_img );
	}
	return rlt;

}


void _menu_decrypt(
		_dnode *node
	)
{
	dlgpass dlg_info = { node, NULL, NULL, NULL, 0 };

	int rlt;
	if ( !_create_act_thread(node, -1, -1) )
	{
		rlt = _dlg_get_pass( __dlg, &dlg_info );
		if ( rlt == ST_OK )
		{
			rlt = dc_start_decrypt( node->mnt.info.device, dlg_info.pass );
			secure_free( dlg_info.pass );

			if ( rlt != ST_OK )
			{
				__error_s(
					__dlg, L"Error start decrypt volume [%s]", rlt, node->mnt.info.status.mnt_point
					);
			}
		}
	} else 
	{
		rlt = ST_OK;
	}
	if ( rlt == ST_OK )
	{
		_create_act_thread( node, ACT_DECRYPT, ACT_RUNNING );
		_activate_page( );
	}
}


int _set_boot_loader_mbr(
		HWND hwnd,
		int  dsk_num,
		int  is_small
	)
{
	int boot_disk_1 = dsk_num;
	ldr_config conf;

	int rlt;

	if ( (rlt = dc_set_mbr( boot_disk_1, 0, is_small ) ) == ST_NF_SPACE )
	{
		if (__msg_w( hwnd,
				L"Not enough space after partitions to install bootloader.\n\n"
				L"Install bootloader to the first HDD track?\n"
				L"(incompatible with third-party boot managers, like GRUB)"
				)
			) 
		{
			if ( (( rlt = dc_set_mbr( boot_disk_1, 1, is_small ) ) == ST_OK ) && 
				  ( dc_get_mbr_config( boot_disk_1, NULL, &conf ) == ST_OK )
				) 
			{
				conf.boot_type = LDR_BT_ACTIVE;						
				if ( (rlt = dc_set_mbr_config( boot_disk_1, NULL, &conf )) != ST_OK )
				{
					dc_unset_mbr( boot_disk_1 );
				}
			}
		}
	}
	return rlt;

}

int _set_boot_loader_efi(
		HWND hwnd,
		int  dsk_num,
		int  is_shim
	)
{
	int add_bme = 0;
	int sb_no_pass = (dc_efi_is_secureboot() && !dc_efi_dcs_is_signed());

	if (sb_no_pass && !dc_efi_shim_available()) {
		__msg_e(hwnd, 
			L"For compatibility with secure boot a shim loader must be installed, however the required archive is missing from the application directory.\n"
			L"Bootloader installation therefore cannot continue, please reboot and disable secure boot in your firmware settings to resolve this issue.\n"
		);
		return ST_CANCEL;
	}

	if (!is_shim && sb_no_pass) {
		if (__msg_w(hwnd, L"This machine's EFI firmware is configured for secure boot.\n"
			L"Without the shim loader, or YOU manually signing the bootloader files, it won't be able to boot.\n"
			L"Do you want to install the shim loader?")
			) {
			is_shim = 1;
		}
	}

	if (is_shim && !__msg_w(hwnd, 
		L"For compatibility with secure boot the shim loader will be installed.\n"
		L"Upon first boot you will be encounter an 'Access denied' error message, "
		L"to resolve this, you will need to start the 'MOK Manager' and enroll a certificate located at \\EFI\\Boot\\MOK.der\n"
		L"After one more reboot the DCS loader should boot and show you a password prompt.\n"
		L"Do you want to continue?")
		) {
		return ST_CANCEL;
	}

	if (__msg_w(hwnd, L"Do you want to add a DCS loader boot menu entry (recommended).")) {
		add_bme = 1;

#ifndef _M_ARM64
		if (!sb_no_pass && dc_efi_is_msft_on_disk(dsk_num))
		{
			if (__msg_w(hwnd, L"Note: Some EFI implementations are not adhering to the standard and always start the windows bootloader.\n"
				L"Do you want to replace the windows bootloader file (BOOTMGFW.EFI) with a redirection to the DCS loader as a workaround?")) {
				add_bme = 2;
			}
		}
#endif
	}

	//if (sb_no_pass) {
	//	if (!__msg_w(hwnd, 
	//		L"This system's UEFI firmware has Secure Boot enabled. "
	//		L"You must manually sign the DCS bootloader files or disable Secure Boot, "
	//		L"otherwise THE SYSTEM WILL NOT BOOT!!!\n"
	//		L"Do you want to continue?")
	//		) {
	//		return ST_CANCEL;
	//	}
	//}

	int rlt;

	rlt = dc_set_efi_boot(dsk_num, add_bme == 2, is_shim);

	if (rlt == ST_OK && add_bme != 0) {
		rlt = dc_efi_set_bme(L"DiskCrypto (DCS) loader", dsk_num);
	}

	return rlt;

}


int _menu_add_bme(
	HWND     hwnd,
	wchar_t *vol,
	int      dsk_num
)
{
	int rlt = ST_ERROR;

	rlt = dc_efi_set_bme(L"DiskCrypto (DCS) loader", dsk_num);

	if ( rlt == ST_OK )
	{
		__msg_i( hwnd, L"DCS Boot Menu Entry successfully added\n");
	} else {
		__error_s( hwnd, L"Error adding DCS Boot Menu Entry\n", rlt );
	}
	return rlt;

}

int _menu_del_bme(
	HWND     hwnd,
	wchar_t *vol,
	int      dsk_num
)
{
	int rlt = ST_ERROR;

	rlt = dc_efi_del_bme();

	if ( rlt == ST_OK )
	{
		__msg_i( hwnd, L"DCS Boot Menu Entry successfully removed\n");
	} else {
		__error_s( hwnd, L"Error removing DCS Boot Menu Entry\n", rlt );
	}
	return rlt;

}

int _menu_repalce_msldr(
	HWND     hwnd,
	wchar_t *vol,
	int      dsk_num
)
{
	int rlt = ST_ERROR;

	rlt = dc_efi_replace_msft_boot(dsk_num);

	if ( rlt == ST_OK )
	{
		__msg_i( hwnd, L"Microsoft Boot Manager successfully replaced on [%s]\n", vol );
	} else {
		__error_s( hwnd, L"Error replacing Microsoft Boot Manager on [%s]\n", rlt, vol );
	}
	return rlt;

}

int _menu_restore_msldr(
	HWND     hwnd,
	wchar_t *vol,
	int      dsk_num
)
{
	int rlt = ST_ERROR;

	rlt = dc_efi_restore_msft_boot(dsk_num);

	if ( rlt == ST_OK )
	{
		__msg_i( hwnd, L"Microsoft Boot Manager successfully restored on [%s]\n", vol );
	} else {
		__error_s( hwnd, L"Error restoring Microsoft Boot Manager on [%s]\n", rlt, vol );
	}
	return rlt;

}


void _menu_encrypt_cd(  )
{
	_dnode *node = pv( malloc(sizeof(_dnode)) );		
	memset( node, 0, sizeof(_dnode) );
	
	wcscpy( node->mnt.info.device, L"Encrypt ISO file" );
	node->dlg.act_type = ACT_ENCRYPT_CD;

	DialogBoxParam(
		__hinst, MAKEINTRESOURCE(IDD_WIZARD_ENCRYPT), __dlg, pv(_wizard_encrypt_dlg_proc), (LPARAM)node
		);

	if ( node->dlg.rlt == ST_CANCEL ) 
	{
		return;
	}
	if ( node->dlg.rlt == ST_OK )
	{
		__msg_i( 
			__dlg, L"ISO image \"%s\" successfully encrypted to \"%s\"", 
			_extract_name(node->dlg.iso.s_iso_src), 
			_extract_name(node->dlg.iso.s_iso_dst)
			);		
	} else 
	{
		__error_s(
			__dlg, 
			L"Error encrypting ISO image \"%s\"", node->dlg.rlt, _extract_name(node->dlg.iso.s_iso_src) 
			);
	}
	free(node);
}


void _menu_encrypt(
		_dnode *node
	)
{
	int rlt;

	if ( __is_efi_boot )
	{
		wchar_t s_boot_dev[MAX_PATH];
		if ( (dc_get_boot_device(s_boot_dev) == ST_OK) && (wcscmp(node->mnt.info.device, s_boot_dev) == 0) ){
			__msg_e(__dlg, L"The EFI boot partition cannot be encrypted because the UEFI firmware itself needs ability to read it.");
			return;
		}
	}

	if ( _create_act_thread(node, -1, -1) == 0 )
	{
		node->dlg.act_type = ACT_ENCRYPT;

		DialogBoxParam(
			__hinst, MAKEINTRESOURCE(IDD_WIZARD_ENCRYPT), __dlg, pv(_wizard_encrypt_dlg_proc), (LPARAM)node
			);

		rlt = node->dlg.rlt;
	} else {
		rlt = ST_OK;
	}
	
	if ( rlt == ST_CANCEL ) return;
	if ( rlt != ST_OK ) 
	{
		__error_s(
			__dlg, L"Error start encrypt volume [%s]", rlt, node->mnt.info.status.mnt_point
			);
	} else {
		_create_act_thread(node, ACT_ENCRYPT, ACT_RUNNING);		
		_activate_page( );

	}
}

void _menu_encrypt2(
	_dnode *node
)
{
	int rlt = ST_OK;
	wchar_t path[MAX_PATH];

	rlt = dc_get_pending_header_nt(node->mnt.info.device, path);
	if ( rlt == ST_OK )
	{
		rlt = dc_start_encrypt2(node->mnt.info.device, path);
	}

	if ( rlt != ST_OK ) 
	{
		__error_s(
			__dlg, L"Error start pending encrypt volume [%s]", rlt, node->mnt.info.status.mnt_point
		);
	} else {
		_create_act_thread(node, ACT_ENCRYPT, ACT_RUNNING);		
		_activate_page( );

	}
}

void _menu_wizard(
		_dnode *node
	)
{
	wchar_t *s_act;
	int      rlt;

	if ( _create_act_thread(node, -1, -1) == 0 )
	{
		node->dlg.act_type = -1;

		DialogBoxParam(__hinst, 
			MAKEINTRESOURCE(IDD_WIZARD_ENCRYPT), __dlg, pv(_wizard_encrypt_dlg_proc), (LPARAM)node);

		rlt = node->dlg.rlt;

	} else {
		rlt = ST_OK;
	}
	
	if (rlt == ST_CANCEL) return;
	if (rlt != ST_OK) 
	{
		switch (node->dlg.act_type) 
		{
			case ACT_REENCRYPT: s_act = L"reencrypt"; break;
			case ACT_ENCRYPT:   s_act = L"encrypt";   break;
			case ACT_FORMAT:    s_act = L"format";    break;
		};
		__error_s(
			__dlg, L"Error start %s volume [%s]", rlt, s_act, node->mnt.info.status.mnt_point
			);
	} else {
		_create_act_thread(node, node->dlg.act_type, ACT_RUNNING);
		_activate_page( );

	}
}


void _menu_reencrypt(
		_dnode *node
	)
{
	int rlt;
	node->dlg.act_type = ACT_REENCRYPT;

	if ( _create_act_thread(node, -1, -1) == 0 && 
		 !(node->mnt.info.status.flags & F_REENCRYPT)
		)
	{
		DialogBoxParam(
			__hinst, MAKEINTRESOURCE(IDD_WIZARD_ENCRYPT), __dlg, pv(_wizard_encrypt_dlg_proc), (LPARAM)node
			);

		rlt = node->dlg.rlt;
	} else {
		rlt = ST_OK;
	}
	
	if ( rlt == ST_CANCEL ) return;
	if ( rlt != ST_OK ) 
	{
		__error_s(
			__dlg, L"Error start reencrypt volume [%s]", rlt, node->mnt.info.status.mnt_point
			);
	} else {
		_create_act_thread( node, ACT_REENCRYPT, ACT_RUNNING );
		_activate_page( );

	}
}


void _menu_format(
		_dnode *node
	)
{
	int rlt;

	node->dlg.act_type = ACT_FORMAT;
	node->dlg.q_format = FALSE;

	node->dlg.fs_name  = L"FAT32";

	if ( _create_act_thread(node, -1, -1) == 0 && 
		 !(node->mnt.info.status.flags & F_FORMATTING)
		)
	{
		DialogBoxParam(
			__hinst, MAKEINTRESOURCE(IDD_WIZARD_ENCRYPT), __dlg, pv(_wizard_encrypt_dlg_proc), (LPARAM)node
			);

		rlt = node->dlg.rlt;
	} else {
		rlt = ST_OK;
	}
	
	if ( rlt == ST_CANCEL ) return;
	if ( rlt != ST_OK ) 
	{
		__error_s(
			__dlg, L"Error start format volume [%s]", rlt, node->mnt.info.status.mnt_point
			);
	} else 
	{
		if ( node->dlg.q_format )
		{
			rlt = dc_done_format( node->mnt.info.device );
			if ( rlt == ST_OK )
			{
				_finish_formatting(node);
			}
		} else {
			_create_act_thread(node, ACT_FORMAT, ACT_RUNNING);
			_activate_page( );
		}
	}
}


void _menu_unmount(
		_dnode *node
	)
{
	int resl  = ST_ERROR;
	int flags = __config.conf_flags & CONF_FORCE_DISMOUNT ? MF_FORCE : 0;

	if ( __msg_q( __dlg, L"Unmount volume [%s]?", node->mnt.info.status.mnt_point ) )
	{
		resl = dc_unmount_volume( node->mnt.info.device, flags );

		if ( resl == ST_LOCK_ERR )
		{
			if ( __msg_w( __dlg,
					L"This volume contains opened files.\n"
					L"Would you like to force an unmount on this volume?" )
				)
			{
				resl = dc_unmount_volume( node->mnt.info.device, MF_FORCE );
			} else {
				resl = ST_OK;
			}
		}

		if ( resl != ST_OK )
		{
			__error_s(
				__dlg, L"Error unmount volume [%s]", resl, node->mnt.info.status.mnt_point
				);
		} else {
			_dact *act;

			EnterCriticalSection(&crit_sect);
			if ( act = _create_act_thread(node, -1, -1) ) 
			{
				act->status = ACT_STOPPED;
			}
			LeaveCriticalSection(&crit_sect);
		}
	}
}


void _menu_mount(
		_dnode *node
	)
{
	wchar_t mnt_point[MAX_PATH] = { 0 };
	wchar_t vol[MAX_PATH];

	dlgpass dlg_info = { node, NULL, NULL, mnt_point, 0 };

	int rlt;
	rlt = 
		dc_mount_volume(
			node->mnt.info.device, NULL, (mnt_point[0] != 0) ? MF_DELMP : 0
		);

	if ( rlt != ST_OK )
	{
		if ( _dlg_get_pass(__dlg, &dlg_info) == ST_OK )
		{
			rlt = dc_mount_volume( node->mnt.info.device, dlg_info.pass, ( (mnt_point[0] != 0) ? MF_DELMP : 0 ) | ( dlg_info.mnt_ro ? MF_READ_ONLY  : 0 ) );
			secure_free( dlg_info.pass );

			if ( rlt == ST_OK )
			{						
				if ( mnt_point[0] != 0 )
				{
					_snwprintf( vol, countof(vol), L"%s\\", node->mnt.info.w32_device );
					_set_trailing_slash(mnt_point);

					if ( SetVolumeMountPoint(mnt_point, vol) == 0 )
					{
						__error_s( __dlg, L"Error when adding mount point", rlt );
					}
				}
			} else 
			{
				__error_s(
					__dlg, L"Error mount volume [%s]", rlt, node->mnt.info.status.mnt_point
					);
			}
		}
	}
	if ( (rlt == ST_OK) && (__config.conf_flags & CONF_EXPLORER_MOUNT) )
	{
		__execute(node->mnt.info.status.mnt_point);
	}
}


void _menu_mountall( )
{
	dlgpass dlg_info  = { NULL, NULL, NULL, NULL, 0 };
	int     mount_cnt = 0;	

	dc_mount_all(NULL, &mount_cnt, 0); 
	if ( mount_cnt == 0 )
	{
		if ( _dlg_get_pass(__dlg, &dlg_info) == ST_OK )
		{
			dc_mount_all( dlg_info.pass, &mount_cnt, ( dlg_info.mnt_ro ? MF_READ_ONLY : 0 ) );
			secure_free( dlg_info.pass );

			__msg_i( __dlg, L"Mounted devices: %d", mount_cnt );
		}
	}
}


void _menu_unmountall( )
{
	list_entry *node = __action.flink;

	if ( __msg_q( __dlg, L"Unmount all volumes?" ) )
	{
		dc_unmount_all( );
		for ( ;node != &__action; node = node->flink ) 
		{
			((_dact *)node)->status = ACT_STOPPED;
		}
	}
}


void _menu_change_pass(
		_dnode *node
	)
{
	dlgpass dlg_info = { node, NULL, NULL, NULL };
	int     resl     = ST_ERROR;

	if ( _dlg_change_pass( __dlg, &dlg_info ) == ST_OK )
	{
		resl = dc_change_password(
			node->mnt.info.device, dlg_info.pass, dlg_info.new_pass
			);

		secure_free( dlg_info.pass );
		secure_free( dlg_info.new_pass );

		if ( resl != ST_OK )
		{
			__error_s( __dlg, L"Error change password", resl );
		} else {
			__msg_i( __dlg, L"Password successfully changed for [%s]", node->mnt.info.status.mnt_point );
		}
	}
}


void _menu_clear_cache( )
{
	if ( __msg_q( __dlg, L"Wipe All Passwords?" ) )
	{
		dc_device_control(DC_CTL_CLEAR_PASS, NULL, 0, NULL, 0);
	}
}


void _menu_backup_header(
		_dnode *node
	)
{
	dlgpass dlg_info = { node, NULL, NULL, NULL, 0 };
	BYTE backup[DC_AREA_SIZE];

	wchar_t s_path[MAX_PATH];
	int rlt = _dlg_get_pass( __dlg, &dlg_info );

	if ( rlt == ST_OK )
	{
		rlt = dc_backup_header( node->mnt.info.device, dlg_info.pass, backup );
		secure_free( dlg_info.pass );

		if ( rlt == ST_OK )
		{
			_snwprintf( s_path, countof(s_path), L"%s.bin", wcsrchr(node->mnt.info.device, '\\') + 1 );
			if ( _save_file_dialog( __dlg, s_path, countof(s_path), L"Save backup volume header to file" ) )
			{
				rlt = save_file( s_path, backup, sizeof(backup) );
			} else {
				return;
			}
		}
	} else return;

	if ( rlt == ST_OK )
	{
		__msg_i( __dlg, L"Volume header backup successfully saved to\n\"%s\"", s_path );
	} else {
		__error_s( __dlg, L"Error save volume header backup", rlt );

	}
}


void _menu_restore_header(
		_dnode *node 
	)
{
	dlgpass dlg_info = { node, NULL, NULL, NULL, 0 };

	BYTE   backup[DC_AREA_SIZE];
	HANDLE hfile;

	wchar_t s_path[MAX_PATH] = { 0 };
	int     rlt = ST_ERROR;
	int     bytes;

	if ( _open_file_dialog( __dlg, s_path, countof(s_path), L"Open backup volume header" ) )
	{		
		hfile = CreateFile(
			s_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL
			);

		if ( hfile != INVALID_HANDLE_VALUE )
		{
			ReadFile( hfile, backup, sizeof(backup), &bytes, NULL );
			CloseHandle( hfile );

			if ( _dlg_get_pass(__dlg, &dlg_info) == ST_OK )
			{
				rlt = dc_restore_header( node->mnt.info.device, dlg_info.pass, backup );
				secure_free( dlg_info.pass );

			} else return;
		} else rlt = ST_NF_FILE;
	} else return;

	if ( rlt == ST_OK )
	{
		__msg_i( __dlg, L"Volume header successfully restored from\n\"%s\"", s_path );
	} else {
		__error_s( __dlg, L"Error restore volume header from backup", rlt );

	}
}
