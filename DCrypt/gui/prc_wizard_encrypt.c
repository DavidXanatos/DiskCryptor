/*
    *
    * DiskCryptor - open source partition encryption tool
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
#include "prc_wizard_encrypt.h"

#include "prc_keyfiles.h"
#include "pass.h"
#include "prc_common.h"
#include "xts_fast.h"
#include "dlg_drives_list.h"
#include "prc_pass.h"

wchar_t *fs_names[ ] = 
{
	L"RAW", L"FAT", L"FAT32", L"NTFS" //, L"exFAT"
};

static HWND     h_wizard;
static HHOOK    h_hook;

int combo_sel[ ] = 
{
	IDC_COMBO_ALGORT, IDC_COMBO_HASH,
	IDC_COMBO_MODE, IDC_COMBO_PASSES
};

int _update_layout(
		_dnode *node,
		int     new_layout,  /* -1 - init */
		int    *old_layout

	)
{
	BOOL boot_dev = _is_boot_device( &node->mnt.info );
	ldr_config conf;

	int kbd_layout = LDR_KB_QWERTY;
	int rlt = ST_OK;

	if ( new_layout != -1 )
	{
		if ( boot_dev )
		{
			if ( (rlt = dc_get_mbr_config( -1, NULL, &conf )) != ST_OK )
			{
				return rlt;
			}
			conf.kbd_layout = new_layout;

			if ( (rlt = dc_set_mbr_config( -1, NULL, &conf )) != ST_OK )
			{
				return rlt;
			}
		}
		return rlt;
	} 
	else 
	{
		BOOL result = dc_get_mbr_config( -1, NULL, &conf ) == ST_OK;

		if ( old_layout )
		{
			*old_layout = result ? conf.kbd_layout : LDR_KB_QWERTY;
		}
		return result;
	}
}


void _run_wizard_action(
		HWND        hwnd,
		_wz_sheets *sheets,
		_dnode     *node
												
	)
{
	BOOL set_loader = (BOOL)
		SendMessage(
			GetDlgItem(sheets[WPAGE_ENC_BOOT].hwnd, IDC_COMBO_BOOT_INST), CB_GETCURSEL, 0, 0
			);

	wchar_t *fs_name = 
		fs_names[SendMessage(
			GetDlgItem(sheets[WPAGE_ENC_FRMT].hwnd, IDC_COMBO_FS_LIST), CB_GETCURSEL, 0, 0
			)];

	int  kb_layout = _get_combo_val( GetDlgItem(sheets[WPAGE_ENC_PASS].hwnd, IDC_COMBO_KBLAYOUT), kb_layouts );
	BOOL q_format  = _get_check( sheets[WPAGE_ENC_FRMT].hwnd, IDC_CHECK_QUICK_FORMAT );

	int is_small = (
		IsWindowEnabled( GetDlgItem( sheets[WPAGE_ENC_CONF].hwnd, IDC_COMBO_ALGORT ) ) ? FALSE : TRUE
	);

	crypt_info  crypt;
	dc_pass    *pass = NULL;

	crypt.cipher_id  = _get_combo_val( GetDlgItem(sheets[WPAGE_ENC_CONF].hwnd, IDC_COMBO_ALGORT), cipher_names );
	crypt.wp_mode    = _get_combo_val( GetDlgItem(sheets[WPAGE_ENC_CONF].hwnd, IDC_COMBO_PASSES), wipe_modes );
 
	node->dlg.rlt = ST_ERROR;

	switch ( node->dlg.act_type )
	{
	///////////////////////////////////////////////////////////////
	case ACT_REENCRYPT :
	///////////////////////////////////////////////////////////////
	/////// REENCRYPT VOLUME //////////////////////////////////////
	{
		wchar_t mnt_point[MAX_PATH] = { 0 };
		wchar_t vol[MAX_PATH];

		dlgpass dlg_info = { node, NULL, NULL, mnt_point };

		ShowWindow(hwnd, FALSE);
		if ( _dlg_get_pass(__dlg, &dlg_info) == ST_OK )
		{
			node->mnt.info.status.crypt.wp_mode = crypt.wp_mode;
			node->dlg.rlt = dc_start_re_encrypt( node->mnt.info.device, dlg_info.pass, &crypt );

			secure_free( dlg_info.pass );
			if ( mnt_point[0] != 0 )
			{
				_snwprintf( vol, countof(vol), L"%s\\", node->mnt.info.w32_device );
				_set_trailing_slash( mnt_point );

				if ( SetVolumeMountPoint(mnt_point, vol) == 0 )
				{
					__error_s( __dlg, L"Error when adding mount point", node->dlg.rlt );
				}
			}
		} else {
			node->dlg.rlt = ST_CANCEL;
		}
	}
	break;
	///////////////////////////////////////////////////////////////
	case ACT_ENCRYPT_CD :
	///////////////////////////////////////////////////////////////
	/////// ENCRYPT CD ////////////////////////////////////////////
	{
		_init_speed_stat( &node->dlg.iso.speed );
		pass = _get_pass_keyfiles( sheets[WPAGE_ENC_PASS].hwnd, IDE_PASS, IDC_USE_KEYFILES, KEYLIST_CURRENT );		

		if ( pass )
		{
			DWORD resume;
			{
				wchar_t s_src_path[MAX_PATH] = { 0 };
				wchar_t s_dst_path[MAX_PATH] = { 0 };

				GetWindowText( GetDlgItem(sheets[WPAGE_ENC_ISO].hwnd, IDE_ISO_SRC_PATH), s_src_path, countof(s_src_path) );
				GetWindowText( GetDlgItem(sheets[WPAGE_ENC_ISO].hwnd, IDE_ISO_DST_PATH), s_dst_path, countof(s_dst_path) );

				wcscpy( node->dlg.iso.s_iso_src, s_src_path );
				wcscpy( node->dlg.iso.s_iso_dst, s_dst_path );

				node->dlg.iso.cipher_id = crypt.cipher_id;
				node->dlg.iso.pass      = pass;
			}

			node->dlg.iso.h_thread = 
				CreateThread(
					NULL, 0, _thread_enc_iso_proc, pv(node), CREATE_SUSPENDED, NULL
					);

			SetThreadPriority( node->dlg.iso.h_thread, THREAD_PRIORITY_LOWEST );
			resume = ResumeThread( node->dlg.iso.h_thread );

			if ( !node->dlg.iso.h_thread || resume == (DWORD) -1 )
			{
				__error_s( hwnd, L"Error create thread", -1 );
				secure_free(pass);
			}
		}		
	}
	break;
	///////////////////////////////////////////////////////////////
	default :
	///////////////////////////////////////////////////////////////
	{
		node->mnt.info.status.crypt.wp_mode = crypt.wp_mode;
		node->dlg.rlt = ST_OK;

		if ( sheets[WPAGE_ENC_BOOT].show )
		{
			if ( set_loader )
			{
				node->dlg.rlt = _set_boot_loader( hwnd, -1, is_small );
			}
		}
		if ( ( node->dlg.rlt == ST_OK ) && 
			 ( IsWindowEnabled( GetDlgItem( sheets[WPAGE_ENC_PASS].hwnd, IDC_LAYOUTS_LIST ) ) ) 
		   )
		{
			node->dlg.rlt = _update_layout( node, kb_layout, NULL );
		}
		if ( node->dlg.rlt == ST_OK )
		{
			switch ( node->dlg.act_type )
			{
		///////////////////////////////////////////////////////////////
			case ACT_ENCRYPT :
		///////////////////////////////////////////////////////////////
		/////// ENCRYPT VOLUME ////////////////////////////////////////
			{
				pass = _get_pass_keyfiles( sheets[WPAGE_ENC_PASS].hwnd, IDE_PASS, IDC_USE_KEYFILES, KEYLIST_CURRENT );

				if ( pass != NULL )
				{
					node->dlg.rlt = dc_start_encrypt( node->mnt.info.device, pass, &crypt );
					secure_free(pass);
				}
			}
			break;
		///////////////////////////////////////////////////////////////
			case ACT_FORMAT :
		///////////////////////////////////////////////////////////////
		/////// FORMAT VOLUME /////////////////////////////////////////
			{
				pass = _get_pass_keyfiles( sheets[WPAGE_ENC_PASS].hwnd, IDE_PASS, IDC_USE_KEYFILES, KEYLIST_CURRENT );
				if ( pass )
				{
					node->dlg.rlt = dc_start_format( node->mnt.info.device, pass, &crypt );
					secure_free(pass);
				}
			}
			break;
			}
		}
	}
	}
	node->dlg.q_format = q_format;
	node->dlg.fs_name  = fs_name;

	if ( !node->dlg.iso.h_thread )
	{
		EndDialog( hwnd, 0 );
	}
}


int _get_info_install_boot_page(
		vol_inf    *vol,
		_wz_sheets *sheets,
		int        *dsk_num	
	)
{				
	ldr_config conf;
	drive_inf  drv;

	int boot_disk_1;
	int boot_disk_2;

	int rlt = ST_ERROR;

	sheets[WPAGE_ENC_BOOT].show = FALSE;	
	if ( _is_boot_device(vol) )
	{
		sheets[WPAGE_ENC_BOOT].show = TRUE;
	}

	rlt = dc_get_drive_info( vol->w32_device, &drv );
	if ( ( rlt && dsk_num ) == ST_OK )
	{
		*dsk_num = drv.disks[0].number;
	}

	rlt = dc_get_boot_disk( &boot_disk_1, &boot_disk_2 );
	if ( rlt == ST_OK )
	{	
		if ( dc_get_mbr_config( boot_disk_1, NULL, &conf ) == ST_OK )
		{
			sheets[WPAGE_ENC_BOOT].show = FALSE;
		}
	}
	return rlt;

}


int _init_wizard_encrypt_pages(
		HWND        parent,
		_wz_sheets *sheets,
		_dnode     *node
	)
{
	wchar_t *static_head[ ] = 
	{
		L"# Choice iso-file",
		L"# Format Options",
		L"# Encryption Settings",
		L"# Boot Settings",
		L"# Volume Password",
		L"# Encryption Progress"
	};

	HWND     hwnd;
	DC_FLAGS flags;
	int      k, count = 0;

	BOOL    boot_device = (
		_is_boot_device( &node->mnt.info )
	);
	BOOL    force_small = (
		boot_device && ( dc_device_control(DC_CTL_GET_FLAGS, NULL, 0, &flags, sizeof(flags)) == NO_ERROR ) && ( flags.load_flags & DST_SMALL_MEM )
	);

	while ( sheets[count].id != -1 )
	{
		HWND hwnd;

		sheets[count].hwnd = 
			CreateDialog(
				__hinst, MAKEINTRESOURCE(sheets[count].id), GetDlgItem(parent, IDC_TAB), _tab_proc
				);

		hwnd = sheets[count].hwnd;

		EnumChildWindows( hwnd, __sub_enum, (LPARAM)NULL );

		SetWindowText( GetDlgItem( hwnd, IDC_HEAD ), static_head[count] );
		SendMessage( GetDlgItem( hwnd, IDC_HEAD ), (UINT)WM_SETFONT, (WPARAM)__font_bold, 0 );

		sheets[count].first_tab_hwnd = 
			(
				( sheets[count].first_tab_id != -1 ) ? GetDlgItem( hwnd, sheets[count].first_tab_id ) : HWND_NULL
			);

		count++;
	}
	///////////////////////////////////////////////////////////////
	hwnd = sheets[WPAGE_ENC_FRMT].hwnd;
	///////////////////////////////////////////////////////////////
	/////// FORMAT OPTIONS PAGE ///////////////////////////////////
	{
		HWND h_fs = GetDlgItem(hwnd, IDC_COMBO_FS_LIST);

		_sub_class( GetDlgItem(hwnd, IDC_CHECK_QUICK_FORMAT), SUB_STATIC_PROC, HWND_NULL );
		_set_check( hwnd, IDC_CHECK_QUICK_FORMAT, FALSE );

		for ( k = 0; k < countof(fs_names); k++ )
		{
			SendMessage( h_fs, (UINT)CB_ADDSTRING, 0, (LPARAM)fs_names[k] );
		}
		SendMessage( h_fs, CB_SETCURSEL, 2, 0 );			
	}
	///////////////////////////////////////////////////////////////
	hwnd = sheets[WPAGE_ENC_CONF].hwnd;
	///////////////////////////////////////////////////////////////
	/////// ENCRYPTION SETTINGS PAGE //////////////////////////////
	{
		HWND h_combo_wipe = GetDlgItem(hwnd, IDC_COMBO_PASSES);

		_init_combo( h_combo_wipe, wipe_modes, WP_NONE, FALSE, -1 );

		EnableWindow( h_combo_wipe, node->dlg.act_type != ACT_ENCRYPT_CD);
		EnableWindow( GetDlgItem(hwnd, IDC_STATIC_PASSES_LIST), node->dlg.act_type != ACT_ENCRYPT_CD );

		_init_combo(
			GetDlgItem(hwnd, IDC_COMBO_ALGORT), cipher_names, CF_AES, FALSE, -1
			);

		if ( force_small )
		{
			EnableWindow( GetDlgItem(hwnd, IDC_COMBO_ALGORT), FALSE );
			SendMessage( GetDlgItem(hwnd, IDC_WIZ_CONF_WARNING), (UINT)WM_SETFONT, (WPARAM)__font_bold, 0 );

			SetWindowText( 
				GetDlgItem(hwnd, IDC_WIZ_CONF_WARNING),
				L"Your BIOS does not provide enough base memory,\n"
				L"you can only use AES to encrypt the boot partition!"
			);
		}
		for ( k = 0; k < countof(combo_sel); k++ )
		{
			SendMessage( GetDlgItem(hwnd, combo_sel[k]), CB_SETCURSEL, 0, 0 );
		}	
	}
	///////////////////////////////////////////////////////////////
	hwnd = sheets[WPAGE_ENC_BOOT].hwnd;
	///////////////////////////////////////////////////////////////
	/////// BOOT SETTINGS PAGE ////////////////////////////////////
	{
		int dsk_num = -1;
		int rlt = _get_info_install_boot_page( &node->mnt.info, sheets, &dsk_num );

		__lists[HENC_WIZARD_BOOT_DEVS] = GetDlgItem(hwnd, IDC_BOOT_DEVS);

		_list_devices( __lists[HENC_WIZARD_BOOT_DEVS], TRUE, dsk_num );
		SendMessage( GetDlgItem(hwnd, IDC_COMBO_BOOT_INST), (UINT)CB_ADDSTRING, 0, (LPARAM)L"Use external bootloader" ); 

		if ( rlt != ST_OK )
		{
			SetWindowText( GetDlgItem(hwnd, IDC_WARNING), L"Bootable HDD not found!" );
			SendMessage( GetDlgItem(hwnd, IDC_COMBO_BOOT_INST), CB_SETCURSEL, 0, 0 );

			SendMessage( GetDlgItem(hwnd, IDC_WARNING), (UINT)WM_SETFONT, (WPARAM)__font_bold, 0 );
			EnableWindow( GetDlgItem(hwnd, IDB_BOOT_PREF), TRUE );
		} else {		
			SendMessage( GetDlgItem(hwnd, IDC_COMBO_BOOT_INST), (UINT)CB_ADDSTRING, 0, (LPARAM)L"Install to HDD" );
			SendMessage( GetDlgItem(hwnd, IDC_COMBO_BOOT_INST), CB_SETCURSEL, 1, 0 );
		}
	}
	///////////////////////////////////////////////////////////////
	hwnd = sheets[WPAGE_ENC_PASS].hwnd;
	///////////////////////////////////////////////////////////////
	/////// VOLUME PASSWORD PAGE //////////////////////////////////
	{
		int kbd_layout;
		_update_layout( node, -1, &kbd_layout );

		_init_combo( GetDlgItem(hwnd, IDC_COMBO_KBLAYOUT), kb_layouts, kbd_layout, FALSE, -1 );
		SetWindowText(GetDlgItem( hwnd, IDC_USE_KEYFILES), boot_device ? IDS_USE_KEYFILE : IDS_USE_KEYFILES );

		_sub_class( GetDlgItem(hwnd, IDC_CHECK_SHOW), SUB_STATIC_PROC, HWND_NULL );
		_set_check( hwnd, IDC_CHECK_SHOW, FALSE );

		_sub_class( GetDlgItem(hwnd, IDC_USE_KEYFILES), SUB_STATIC_PROC, HWND_NULL );
		_set_check( hwnd, IDC_USE_KEYFILES, FALSE );

		SendMessage(
			GetDlgItem( hwnd, IDP_BREAKABLE ),
			PBM_SETBARCOLOR, 0, _cl( COLOR_BTNSHADOW, DARK_CLR-20 )
		);	
		SendMessage(
			GetDlgItem(hwnd, IDP_BREAKABLE),
			PBM_SETRANGE, 0, MAKELPARAM(0, 193)
		);
		SetWindowText( GetDlgItem(hwnd, IDC_HEAD2), L"# Password Rating" );
		SendMessage( GetDlgItem(hwnd, IDC_HEAD2), (UINT)WM_SETFONT, (WPARAM)__font_bold, 0 );

		SendMessage( GetDlgItem(hwnd, IDE_PASS), EM_LIMITTEXT, MAX_PASSWORD, 0 );
		SendMessage( GetDlgItem(hwnd, IDE_CONFIRM), EM_LIMITTEXT, MAX_PASSWORD, 0 );
	}
	///////////////////////////////////////////////////////////////
	hwnd = sheets[WPAGE_ENC_PROGRESS].hwnd;
	///////////////////////////////////////////////////////////////
	/////// ENCRYPTION PROGRESS PAGE //////////////////////////////
	{
		_colinfo _progress_iso_crypt_headers[ ] = 
		{
			{ STR_HEAD_NO_ICONS, 100, LVCFMT_LEFT, FALSE },
			{ STR_HEAD_NO_ICONS, 120, LVCFMT_LEFT, FALSE },
			{ STR_NULL }
		};

		HWND h_list = GetDlgItem( hwnd, IDC_ISO_PROGRESS );
		int  rlt    = ST_OK;
		int  j      = 0;

		ListView_SetBkColor( h_list, GetSysColor(COLOR_BTNFACE) );
		_init_list_headers( h_list, _progress_iso_crypt_headers );

		while ( wcslen(_act_table_items[j]) > 0 )
		{
			_list_insert_item( h_list, j, 0, _act_table_items[j], 0 );
			if ( j != 2 ) ListView_SetItemText( h_list, j, 1, STR_EMPTY );

			j++;
		}
		SendMessage(
			GetDlgItem( hwnd, IDC_PROGRESS_ISO ),
			PBM_SETBARCOLOR, 0, _cl(COLOR_BTNSHADOW, DARK_CLR-20)
		);

		SendMessage(
			GetDlgItem( hwnd, IDC_PROGRESS_ISO ),
			PBM_SETRANGE, 0, MAKELPARAM(0, PRG_STEP)
		);
	}

	return count;

}


BOOL _wizard_step(
		_dnode     *node,
		_wz_sheets *sheets,
		int        *index,
		int         id_back,
		int         id_next,
		int         id
	)
{
	HWND h_parent = GetParent( GetParent(sheets[WPAGE_ENC_CONF].hwnd) );
	BOOL enb_back = FALSE;

	int next = 0;
	int back = 0;
	int k    = 0;

	ShowWindow( sheets[*index].hwnd, SW_HIDE );

	if ( id == id_next )
	{
		while ( sheets[++*index].show == 0 );
	} else {
		while ( sheets[--*index].show == 0 );
	}

	next = *index;
	while ( sheets[++next].show == 0 );

	back = *index - 1;
	while ( ( back >= 0 ) && ( sheets[back].show == 0 ) )
	{
		back--;
	}

	EnableWindow( GetDlgItem(h_parent, id_back), !(back < 0 && node->dlg.act_type != -1) );

	if ( ( sheets[*index].id == -1 ) || ( sheets[next].id == -1 ) )
	{
		SetWindowText( GetDlgItem(h_parent, id_next), L"OK" );
		EnableWindow( GetDlgItem(h_parent, id_next), FALSE );
	} else {
		SetWindowText( GetDlgItem(h_parent, id_next), L"&Next" );
		EnableWindow( GetDlgItem(h_parent, id_next), TRUE );
	}

	ShowWindow( sheets[*index].hwnd, SW_SHOW );
	if ( (*index) < 0 )
	{
		while ( sheets[k].id != -1 )
		{
			sheets[k++].show = TRUE;
		}
		_get_info_install_boot_page( &node->mnt.info, sheets, NULL );
	}

	return (
		sheets[*index].id == -1
	);
}


static
LRESULT 
CALLBACK 
_get_msg_proc(
		int    code,
		WPARAM wparam,
		LPARAM lparam
	)
{
	MSG *p_msg = pv(lparam);

	if ( p_msg->message >= WM_KEYFIRST && p_msg->message <= WM_KEYLAST )
	{
		if ( TranslateAccelerator( h_wizard, __hacc, p_msg ) ) 
		{
			p_msg->message = WM_NULL;
		}
	}
	return (
		CallNextHookEx( h_hook, code, wparam, lparam )
	);
}


INT_PTR 
CALLBACK
_wizard_encrypt_dlg_proc(
		HWND	hwnd,
		UINT	message,
		WPARAM	wparam,
		LPARAM	lparam
	)
{
	WORD code = LOWORD(wparam);
	WORD id   = LOWORD(wparam);

	static _wz_sheets 
	sheets[ ] = 
	{
		{ DLG_WIZ_ISO,      0, TRUE,	IDE_ISO_SRC_PATH,    0 },
		{ DLG_WIZ_FORMAT,   0, TRUE,	IDC_COMBO_FS_LIST,   0 },
		{ DLG_WIZ_CONF,     0, TRUE,	IDC_COMBO_ALGORT,    0 },
		{ DLG_WIZ_LOADER,   0, TRUE,	IDC_COMBO_BOOT_INST, 0 },
		{ DLG_WIZ_PASS,     0, TRUE,	IDE_PASS,            0 },
		{ DLG_WIZ_PROGRESS, 0, TRUE,	-1,                  0 },
		{ -1, 0, TRUE }
	};

	static int enc_sheets[ ][WZR_MAX_STEPS] = 
	{
		{ 2,  3,  4, -1  }, // ACT_ENCRYPT
		{ 2,  4, -1, -1  }, // ACT_DECRYPT
		{ 2, -1, -1, -1  }, // ACT_REENCRYPT
		{ 1,  2,  4, -1  }, // ACT_FORMAT
		{ 0,  2,  4,  5  }  // ACT_ENCRYPT_CD
	};

	static vol_inf *vol;
	static _dnode  *node;

	static index = 0;
	static count = 0;

    int    k     = 0;
	int    cr    = 0;
	int    check = 0; 	

	switch ( message )
	{
		case WM_INITDIALOG :
		{
			{
				node = (_dnode *)lparam;
				if ( node == NULL )
				{
					EndDialog(hwnd, 0);
					return 0L;
				}
				vol = &((_dnode *)lparam)->mnt.info;
			}
			h_wizard = hwnd;
			h_hook   = SetWindowsHookEx( WH_GETMESSAGE, (HOOKPROC)_get_msg_proc, NULL, GetCurrentThreadId( ) );

			SetWindowText(hwnd, vol->device);

			count = _init_wizard_encrypt_pages( hwnd, pv(&sheets), node );
			sheets[count].hwnd = (HWND)lparam;

			node->dlg.h_page = sheets[WPAGE_ENC_PROGRESS].hwnd;

			k = 0;
			while ( sheets[k].id != -1 )
			{
				if ( ! _array_include(enc_sheets[node->dlg.act_type], k) )
				{
					sheets[k].show = FALSE;
				}
				k++;
			}

			index = enc_sheets[node->dlg.act_type][0];
			ShowWindow( sheets[index].hwnd, SW_SHOW );

			if ( node->dlg.act_type == ACT_ENCRYPT_CD )
			{
				EnableWindow( GetDlgItem(hwnd, IDOK), FALSE );
			}

			SetForegroundWindow(hwnd);
			return 1L;
		}
		break;

		case WM_COMMAND: 
		{
			switch ( id )
			{
			case ID_SHIFT_TAB :
			case ID_TAB :
			{
				_focus_tab( 
					IDC_BACK, hwnd, sheets[index].hwnd, sheets[index].first_tab_hwnd, id == ID_TAB 
					);
			}
			break;

			case IDOK :
			case IDC_BACK :
			{
				BOOL set_loader = (BOOL) (
						( sheets[WPAGE_ENC_BOOT].show && SendMessage(GetDlgItem(sheets[WPAGE_ENC_BOOT].hwnd, IDC_COMBO_BOOT_INST), CB_GETCURSEL, 0, 0) ) ||
						( _is_boot_device(vol) && _update_layout(node, -1, NULL) )
					);

				if ( node->dlg.act_type == ACT_REENCRYPT )
				{
					k = 0;
					while ( combo_sel[k] != -1 )
					{
						SendMessage( GetDlgItem(hwnd, combo_sel[k++]), CB_RESETCONTENT, 0, 0 );
					}
					_init_combo(
						GetDlgItem(hwnd, IDC_COMBO_ALGORT), cipher_names, node->mnt.info.status.crypt.cipher_id, FALSE, -1
						);
					_init_combo(
						GetDlgItem(hwnd, IDC_COMBO_PASSES), wipe_modes, node->mnt.info.status.crypt.wp_mode, FALSE, -1
						);
				}

				EnableWindow( GetDlgItem(sheets[WPAGE_ENC_PASS].hwnd, IDC_LAYOUTS_LIST), set_loader );
				EnableWindow( GetDlgItem(sheets[WPAGE_ENC_PASS].hwnd, IDC_COMBO_KBLAYOUT), set_loader );

				if ( _wizard_step(node, pv(&sheets), &index, IDC_BACK, IDOK, id) )
				{
					_run_wizard_action( hwnd, pv(&sheets), node );
				} else 
				{
					if ( sheets[index].id == DLG_WIZ_PROGRESS && node->dlg.act_type == ACT_ENCRYPT_CD )
					{
						_run_wizard_action(hwnd, pv(&sheets), node);
					}
				}
				if ( node->dlg.act_type == ACT_REENCRYPT )
				{
					EnableWindow(GetDlgItem(hwnd, IDOK), TRUE);
				}
				SetFocus(GetDlgItem(sheets[index].hwnd, IDE_PASS));

				SendMessage(
					sheets[index].hwnd, WM_COMMAND, MAKELONG(IDE_PASS, EN_CHANGE), (LPARAM)GetDlgItem(sheets[index].hwnd, IDE_PASS)
					);
			}
			break;

			case IDCANCEL:
			{
				BOOL b_close = TRUE;
				if ( node->dlg.iso.h_thread != NULL )
				{
					SuspendThread( node->dlg.iso.h_thread );
					if ( __msg_w( hwnd, L"Do you really want to interrupt the encryption\nof an iso-file?" ) == 0 ) 
					{						
						b_close = FALSE;
					}
					ResumeThread( node->dlg.iso.h_thread );
				}
				if ( b_close )
				{
					node->dlg.rlt = ST_CANCEL;
					SendMessage( hwnd, WM_CLOSE_DIALOG, 0, 0 );
				}
				return 0L;
			}
			break;
			}
		}
		break;

		case WM_CLOSE_DIALOG :
		{
			if ( node->dlg.iso.h_thread != NULL )
			{
				CloseHandle( node->dlg.iso.h_thread );
			}
			EndDialog(hwnd, 0);
		}
		break;

		case WM_DESTROY : 
		{
			node = NULL;			
			vol  = NULL;

			_wipe_pass_control( sheets[WPAGE_ENC_PASS].hwnd, IDE_PASS );
			_wipe_pass_control( sheets[WPAGE_ENC_PASS].hwnd, IDE_CONFIRM );

			_keyfiles_wipe(KEYLIST_CURRENT);

			count = 0;
			while ( sheets[count].id != -1 )
			{
				sheets[count].show = TRUE;
				DestroyWindow(sheets[count++].hwnd);
			}
			__lists[HENC_WIZARD_BOOT_DEVS] = HWND_NULL;

			UnhookWindowsHookEx(h_hook);
			count = index = 0;

			return 0L;
		}
		break;

		default:
		{
			int rlt = _draw_proc(message, lparam);
			if ( rlt != -1 )
			{
				return rlt;
			}
		}
	}
	return 0L;

}

