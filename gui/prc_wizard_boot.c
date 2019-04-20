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
#include <richedit.h>

#include "main.h"
#include "prc_wizard_boot.h"

#include "prc_common.h"
#include "prc_keyfiles.h"
#include "dlg_drives_list.h"
#include "dlg_menu.h"
#include "hotkeys.h"

static HWND     h_wizard;
static HHOOK    h_hook;

void _refresh_boot_buttons(
		HWND hwnd,
		HWND h_list,
		int  item
	)
{
	BOOL       remove      = FALSE;
	BOOL	   update      = FALSE;
	BOOL	   enable      = FALSE;
	BOOL       boot_device = FALSE;
	BOOL       force_small = FALSE;
	HWND       h_parent    = GetParent( GetParent( hwnd ) );

	int        sel_disk    = _ext_disk_num(h_list);
	wchar_t	   s_item[MAX_PATH];

	ldr_config conf;
	DC_FLAGS   flags;

	if ( ListView_GetSelectedCount(h_list) )
	{		
		int     boot_disk_1 = -1;
		int     boot_disk_2 = -1;

		if ( dc_get_boot_disk( &boot_disk_1, &boot_disk_2 ) != ST_NF_BOOT_DEV )
		{
			force_small = (
				( boot_disk_1 == sel_disk || boot_disk_2 == sel_disk ) && 
				( dc_device_control(DC_CTL_GET_FLAGS, NULL, 0, &flags, sizeof(flags)) == NO_ERROR ) && ( flags.load_flags & DST_SMALL_MEM )
			);
		}
		enable = TRUE;

		_get_item_text( h_list, item, 2, s_item, countof(s_item) );
		if ( !wcscmp(s_item, L"installed") )
		{
			remove = TRUE;
			update = dc_get_mbr_config( sel_disk, NULL, &conf ) == ST_OK && conf.ldr_ver < DC_BOOT_VER;
		}
	}
	SetWindowText( GetDlgItem( h_parent, IDC_BTN_INSTALL ), remove ? IDS_BOOTREMOVE : IDS_BOOTINSTALL );
	EnableWindow( GetDlgItem( h_parent, IDC_BTN_INSTALL ), enable );

	EnableWindow( GetDlgItem( h_parent, IDC_BTN_CHANGE_CONF ), remove );
	EnableWindow( GetDlgItem( h_parent, IDC_BTN_UPDATE ), update );

	EnableWindow( GetDlgItem( hwnd, IDC_USE_SMALL_BOOT ), enable && !remove && !force_small );
	_set_check( hwnd, IDC_USE_SMALL_BOOT, _get_check( hwnd, IDC_USE_SMALL_BOOT ) || force_small );


}


int _init_boot_config(
		HWND        hwnd,
		int         type,
		int         dsk_num,
		wchar_t    *vol,
		wchar_t    *path,
		ldr_config *conf
	)
{
	HWND   h_tab    = GetDlgItem(hwnd, IDT_BOOT_TAB);
	TCITEM tab_item = { TCIF_TEXT };

	wchar_t s_title[MAX_PATH];

	_tab_data *d_tab = NULL;
	_wnd_data *wnd;

	int rlt;

	switch ( type )
	{
		case CTL_LDR_MBR:   rlt = dc_get_mbr_config( dsk_num, NULL, conf ); break;
		case CTL_LDR_STICK: rlt = dc_mbr_config_by_partition(vol, FALSE, conf); break;
		case CTL_LDR_ISO:
		case CTL_LDR_PXE:   rlt = dc_get_mbr_config( 0, path, conf ); break;
	}

	if ( rlt != ST_OK )
	{
		__error_s( hwnd, L"Error getting bootloader configuration", rlt );
		return rlt;
	}

	d_tab = malloc(sizeof(_tab_data));
	memset( d_tab, 0, sizeof(_tab_data) );
	
	wnd_set_long(hwnd, GWL_USERDATA, d_tab);

	wnd = _sub_class(
		h_tab, SUB_NONE,
		CreateDialog( __hinst, MAKEINTRESOURCE(DLG_BOOT_CONF_MAIN),    GetDlgItem(hwnd, IDC_BOOT_TAB), _tab_proc ),
		CreateDialog( __hinst, MAKEINTRESOURCE(DLG_BOOT_CONF_LOGON),   GetDlgItem(hwnd, IDC_BOOT_TAB), _tab_proc ),
		CreateDialog( __hinst, MAKEINTRESOURCE(DLG_BOOT_CONF_BADPASS), GetDlgItem(hwnd, IDC_BOOT_TAB), _tab_proc ),
		CreateDialog( __hinst, MAKEINTRESOURCE(DLG_BOOT_CONF_OTHER),   GetDlgItem(hwnd, IDC_BOOT_TAB), _tab_proc ),
		HWND_NULL
		);

	d_tab->curr_tab = 1;
	d_tab->active   = wnd->dlg[0];

	__lists[HBOT_PART_LIST_BY_ID] = GetDlgItem( wnd->dlg[0], IDC_PART_LIST_BY_ID );
	///////////////////////////////////////////////////////////////
	/////// MAIN PAGE /////////////////////////////////////////////
	{
	///////////////////////////////////////////////////////////////
		_init_combo(
			GetDlgItem(wnd->dlg[0], IDC_COMBO_KBLAYOUT), kb_layouts, conf->kbd_layout, FALSE, -1
			);

		_init_combo(
			GetDlgItem(wnd->dlg[0], IDC_COMBO_METHOD), 
			conf->options & LDR_OP_EXTERNAL ? boot_type_ext : boot_type_all, conf->boot_type, FALSE, -1
			);

		_list_part_by_disk_id( 
			__lists[HBOT_PART_LIST_BY_ID], conf->disk_id 
			);

		SendMessage(
			wnd->dlg[0], WM_COMMAND, MAKELONG(IDC_COMBO_METHOD, CBN_SELCHANGE), (LPARAM)GetDlgItem(wnd->dlg[0], IDC_COMBO_METHOD)
			);

	}
	///////////////////////////////////////////////////////////////
	/////// AUTHENTICATION PAGE ///////////////////////////////////
	{
	///////////////////////////////////////////////////////////////
		HWND h_auth_combo = GetDlgItem( wnd->dlg[1], IDC_COMBO_AUTH_TYPE );
		HWND h_msg = GetDlgItem( wnd->dlg[1], IDE_RICH_BOOTMSG );

		int bits = 0;

		if (conf->logon_type & LDR_LT_GET_PASS)
		{
			bits++;
		}
		if (conf->logon_type & LDR_LT_EMBED_KEY) 
		{
			bits++;
		}

		_init_combo( h_auth_combo, auth_type, conf->logon_type, TRUE, bits );

		_sub_class( GetDlgItem(wnd->dlg[1], IDC_BT_ENTER_PASS_MSG), SUB_STATIC_PROC, HWND_NULL );
		_set_check( wnd->dlg[1], IDC_BT_ENTER_PASS_MSG, conf->logon_type & LDR_LT_MESSAGE );

		EnableWindow( h_msg, conf->logon_type & LDR_LT_MESSAGE );
		_init_combo( GetDlgItem(wnd->dlg[1], IDC_COMBO_SHOW_PASS), show_pass, conf->logon_type, TRUE, -1 );

		SetWindowTextA( h_msg, conf->eps_msg );

		SendMessage( h_msg, EM_SETBKGNDCOLOR, 0, _cl(COLOR_BTNFACE, LGHT_CLR) );
		SendMessage( h_msg, EM_EXLIMITTEXT,	0, sizeof(conf->eps_msg) - 1 );

		_init_combo(
			GetDlgItem(wnd->dlg[1], IDC_COMBO_AUTH_TMOUT), auth_tmount, conf->timeout, FALSE, -1
			);

		_sub_class( GetDlgItem(wnd->dlg[1], IDC_BT_CANCEL_TMOUT), SUB_STATIC_PROC, HWND_NULL );
		_set_check( wnd->dlg[1], IDC_BT_CANCEL_TMOUT, conf->options & LDR_OP_TMO_STOP );

		EnableWindow( GetDlgItem(wnd->dlg[1], IDC_BT_CANCEL_TMOUT), conf->timeout );
		SendMessage( wnd->dlg[1], WM_COMMAND, MAKELONG(IDC_COMBO_AUTH_TYPE, CBN_SELCHANGE), (LPARAM)h_auth_combo );

	}
	///////////////////////////////////////////////////////////////
	/////// INVALID PASSWORD PAGE /////////////////////////////////
	{
	///////////////////////////////////////////////////////////////
		HWND err_mes = GetDlgItem( wnd->dlg[2], IDE_RICH_ERRPASS_MSG );

		_sub_class( GetDlgItem(wnd->dlg[2], IDC_BT_BAD_PASS_MSG), SUB_STATIC_PROC, HWND_NULL );
		_set_check( wnd->dlg[2], IDC_BT_BAD_PASS_MSG, conf->error_type & LDR_ET_MESSAGE );

		EnableWindow( GetDlgItem(wnd->dlg[2], IDE_RICH_ERRPASS_MSG), conf->error_type & LDR_ET_MESSAGE );

		_sub_class( GetDlgItem(wnd->dlg[2], IDC_BT_ACTION_NOPASS), SUB_STATIC_PROC, HWND_NULL );
		_set_check( wnd->dlg[2], IDC_BT_ACTION_NOPASS, conf->options & LDR_OP_NOPASS_ERROR );

		_init_combo( GetDlgItem(wnd->dlg[2], IDC_COMBO_BAD_PASS_ACT), bad_pass_act, conf->error_type, TRUE, -1 );

		SetWindowTextA( err_mes, conf->err_msg );
		SendMessage( err_mes, EM_EXLIMITTEXT, 0, sizeof(conf->err_msg) - 1 );

		SendMessage( GetDlgItem(wnd->dlg[2], IDE_RICH_ERRPASS_MSG), EM_SETBKGNDCOLOR, 0, _cl(COLOR_BTNFACE, LGHT_CLR) );
	}
	///////////////////////////////////////////////////////////////
	/////// OTHER SETTINGS PAGE ///////////////////////////////////
	{
	///////////////////////////////////////////////////////////////
		_sub_class( GetDlgItem(wnd->dlg[3], IDC_USE_HARD_CRYPTO), SUB_STATIC_PROC, HWND_NULL );
		_set_check( wnd->dlg[3], IDC_USE_HARD_CRYPTO, conf->options & LDR_OP_HW_CRYPTO );
	}

	tab_item.pszText = L"Main";
	TabCtrl_InsertItem(h_tab, 0, &tab_item);

	tab_item.pszText = L"Authentication";
	TabCtrl_InsertItem(h_tab, 1, &tab_item);

	tab_item.pszText = L"Invalid password";
	TabCtrl_InsertItem(h_tab, 2, &tab_item);

	tab_item.pszText = L"Other Settings";
	TabCtrl_InsertItem(h_tab, 3, &tab_item);

	{
		NMHDR mhdr = { 0, 0, TCN_SELCHANGE };
		TabCtrl_SetCurSel(h_tab, 0);

		SendMessage( hwnd, WM_NOTIFY, IDT_BOOT_TAB, (LPARAM)&mhdr );
	}

	_snwprintf( s_title, countof(s_title), L"Bootloader config for [%s]", path[0] ? path : vol );
	SetWindowText( GetParent(GetParent(hwnd)), s_title );

	return rlt;
						
}


int _save_boot_config(
		HWND        hwnd,
		int         type,
		int         dsk_num,
		wchar_t    *vol,
		wchar_t    *path,
		ldr_config *conf
	)
{
	_wnd_data *wnd;
	int rlt = ST_OK;

	wnd = wnd_get_long( GetDlgItem(hwnd, IDT_BOOT_TAB), GWL_USERDATA );

	if ( wnd )
	///////////////////////////////////////////////////////////////
	/////// MAIN PAGE /////////////////////////////////////////////
	{
	///////////////////////////////////////////////////////////////
		conf->kbd_layout = _get_combo_val( GetDlgItem( wnd->dlg[0], IDC_COMBO_KBLAYOUT ), kb_layouts );
		conf->boot_type  = _get_combo_val( GetDlgItem( wnd->dlg[0], IDC_COMBO_METHOD ), boot_type_all );

		if ( conf->boot_type == LDR_BT_DISK_ID )
		{
			wchar_t text[MAX_PATH];

			_get_item_text( 
				__lists[HBOT_PART_LIST_BY_ID], ListView_GetSelectionMark(__lists[HBOT_PART_LIST_BY_ID]), 2, text, countof(text) 
				);

			if ( wcslen(text) && ListView_GetSelectedCount( __lists[HBOT_PART_LIST_BY_ID] ) )
			{
				conf->disk_id = wcstoul(text, L'\0', 16);
			} else {
				__msg_e( hwnd, L"You must select partition by id" );
				return ST_ERROR;
			}
		}
	}
	///////////////////////////////////////////////////////////////
	/////// AUTHENTICATION PAGE ///////////////////////////////////
	{
	///////////////////////////////////////////////////////////////
		HWND auth_combo = GetDlgItem( wnd->dlg[1], IDC_COMBO_AUTH_TYPE );
		HWND show_combo = GetDlgItem( wnd->dlg[1], IDC_COMBO_SHOW_PASS );

		BOOL dsp_pass;
		int timeout = _get_combo_val( GetDlgItem(wnd->dlg[1], IDC_COMBO_AUTH_TMOUT), auth_tmount );

		BOOL show_text = _get_check( wnd->dlg[1], IDC_BT_ENTER_PASS_MSG );
		BOOL embed_key = _get_combo_val( auth_combo, auth_type) & LDR_LT_EMBED_KEY;

		conf->logon_type &= ~( LDR_LT_GET_PASS | LDR_LT_EMBED_KEY );
		conf->logon_type |= _get_combo_val( auth_combo, auth_type );

		if ( show_text )
		{
			GetWindowTextA( GetDlgItem(wnd->dlg[1], IDE_RICH_BOOTMSG), conf->eps_msg, sizeof(conf->eps_msg) );
		}
		set_flag( conf->logon_type, LDR_LT_MESSAGE, show_text );

		dsp_pass = _get_combo_val( show_combo, show_pass ) == LDR_LT_DSP_PASS;
		set_flag( conf->logon_type, LDR_LT_DSP_PASS, dsp_pass );

		conf->timeout = timeout;

		set_flag( conf->options, LDR_OP_EPS_TMO, timeout != 0 );
		set_flag( conf->options, LDR_OP_TMO_STOP, _get_check(wnd->dlg[1], IDC_BT_CANCEL_TMOUT) );

		if ( embed_key )
		{
			if ( _keyfiles_count(KEYLIST_EMBEDDED) )
			{
				int   keysize;
				byte *keyfile;

				memset( conf->emb_key, 0, sizeof(conf->emb_key) );
				set_flag( conf->logon_type, LDR_LT_EMBED_KEY, 0 );

				if ( load_file(_first_keyfile(KEYLIST_EMBEDDED)->path, &keyfile, &keysize) != ST_OK )
				{
					__msg_e( hwnd, L"Keyfile not loaded\n" );
					rlt = ST_ERROR;
				} else 
				{
					memcpy( &conf->emb_key, keyfile, sizeof(conf->emb_key) );
					set_flag( conf->logon_type, LDR_LT_EMBED_KEY, 1 );
				}				
				burn(keyfile, keysize);
				free(keyfile);							
			}
		} else {
			memset(conf->emb_key, 0, sizeof(conf->emb_key));
		}
	}
	///////////////////////////////////////////////////////////////
	/////// INVALID PASSWORD PAGE /////////////////////////////////
	{
	///////////////////////////////////////////////////////////////
		BOOL show_err    = _get_check( wnd->dlg[2], IDC_BT_BAD_PASS_MSG );
		BOOL act_no_pass = _get_check( wnd->dlg[2], IDC_BT_ACTION_NOPASS );

		conf->error_type = _get_combo_val( GetDlgItem(wnd->dlg[2], IDC_COMBO_BAD_PASS_ACT), bad_pass_act );

		set_flag( conf->error_type, LDR_ET_MESSAGE, show_err );
		set_flag( conf->options, LDR_OP_NOPASS_ERROR, act_no_pass );

		if ( show_err )
		{
			GetWindowTextA(
				GetDlgItem( wnd->dlg[2], IDE_RICH_ERRPASS_MSG), conf->err_msg, sizeof(conf->err_msg) 
				);
		}						
	}
	///////////////////////////////////////////////////////////////
	/////// OTHER SETTINGS PAGE ///////////////////////////////////
	{
	///////////////////////////////////////////////////////////////
		set_flag( 
			conf->options, LDR_OP_HW_CRYPTO, _get_check(wnd->dlg[3], IDC_USE_HARD_CRYPTO) 
			);
	}

	if ( rlt != ST_OK )
	{
		return rlt;
	}
	switch ( type )
	{
		case CTL_LDR_MBR:   rlt = dc_set_mbr_config( dsk_num, NULL, conf ); break;
		case CTL_LDR_STICK: rlt = dc_mbr_config_by_partition( vol, TRUE, conf ); break;
		case CTL_LDR_ISO:
		case CTL_LDR_PXE:   rlt = dc_set_mbr_config( 0, path, conf ); break;
	}
	if ( rlt != ST_OK )
	{
		__error_s( hwnd, L"Error set bootloader configuration", rlt );
		return rlt;				
	}
	EndDialog( GetParent(GetParent(hwnd)), IDOK );

	return rlt;

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
_wizard_boot_dlg_proc(
		HWND	hwnd,
		UINT	message,
		WPARAM	wparam,
		LPARAM	lparam
	)
{

	WORD   code             = HIWORD(wparam);
    WORD   id               = LOWORD(wparam);
	DWORD _flags            = 0;
	DWORD _hotkeys[HOTKEYS] = { 0 };

	static _wz_sheets
	bt_sheets[ ] =
	{
		{ DLG_BOOT_SET,  0, TRUE, IDC_COMBO_LOADER_TYPE, 0 },
		{ DLG_BOOT_CONF, 0, TRUE, IDT_BOOT_TAB,          0 },
		{ -1 }
	};
	static ldr_config *ldr;

	int check = 0; 
	int count = 0;
	
	switch ( message )
	{
		case WM_CLOSE:
		case WM_DESTROY:
		{
			_keyfiles_wipe(KEYLIST_EMBEDDED);

			__lists[HBOT_WIZARD_BOOT_DEVS] = HWND_NULL;
			__lists[HBOT_PART_LIST_BY_ID]  = HWND_NULL;
		}
		break;

		case WM_INITDIALOG: 
		{
			h_wizard = hwnd;
			h_hook   = SetWindowsHookEx( WH_GETMESSAGE, (HOOKPROC)_get_msg_proc, NULL, GetCurrentThreadId( ) );

			while ( bt_sheets[count].id != -1 )
			{
				bt_sheets[count].hwnd = CreateDialog(
					__hinst, MAKEINTRESOURCE( bt_sheets[count].id ), GetDlgItem( hwnd, IDC_TAB ), _tab_proc
					);

				//EnumChildWindows( bt_sheets[count].hwnd, __sub_enum, (LPARAM)NULL );

				bt_sheets[count].first_tab_hwnd = 
				(
					( bt_sheets[count].first_tab_id != -1 ) ? 
					GetDlgItem( bt_sheets[count].hwnd, bt_sheets[count].first_tab_id ) : HWND_NULL
				);
				count++;
			}

			hwnd = bt_sheets[0].hwnd;
			{
				__lists[HBOT_WIZARD_BOOT_DEVS] = GetDlgItem( hwnd, IDC_WZD_BOOT_DEVS );

				_init_combo(
					GetDlgItem(hwnd, IDC_COMBO_LOADER_TYPE), loader_type, lparam ? CTL_LDR_ISO : CTL_LDR_MBR, FALSE, -1
					);

				_list_devices( __lists[HBOT_WIZARD_BOOT_DEVS], TRUE, -1 );
				SendMessage( hwnd, WM_COMMAND, MAKELONG(IDC_COMBO_LOADER_TYPE, CBN_SELCHANGE), 0 );

				_sub_class( GetDlgItem(hwnd, IDC_CHECK_CONFIG), SUB_STATIC_PROC, HWND_NULL );
				_set_check( hwnd, IDC_CHECK_CONFIG, FALSE );	

				_sub_class( GetDlgItem(hwnd, IDC_USE_SMALL_BOOT), SUB_STATIC_PROC, HWND_NULL );
				_set_check( hwnd, IDC_USE_SMALL_BOOT, FALSE );

			}
			ShowWindow(bt_sheets[0].hwnd, SW_SHOW);

		}
		break;

		case WM_COMMAND: 
		{
			int  type     = _get_combo_val( GetDlgItem(bt_sheets[0].hwnd, IDC_COMBO_LOADER_TYPE), loader_type );
			int  is_small = _get_check( bt_sheets[0].hwnd, IDC_USE_SMALL_BOOT );			
			int  dsk_num  = _ext_disk_num( __lists[HBOT_WIZARD_BOOT_DEVS] );

			int rlt;

			wchar_t vol[MAX_PATH]  = { 0 };
			wchar_t path[MAX_PATH] = { 0 };

			static ldr_config conf = { 0 };

			_get_item_text( __lists[HBOT_WIZARD_BOOT_DEVS], ListView_GetSelectionMark(__lists[HBOT_WIZARD_BOOT_DEVS]), 0, vol, countof(vol) );
			GetWindowText( GetDlgItem(bt_sheets[0].hwnd, IDE_BOOT_PATH), path, countof(path) );

			switch ( id )
			{
				case ID_SHIFT_TAB :
				case ID_TAB :
				{
					int index = IsWindowVisible( bt_sheets[0].hwnd ) ? 0 : 1;

					_focus_tab( 
						IDC_BTN_INSTALL, hwnd, 
						bt_sheets[index].hwnd, 
						bt_sheets[index].first_tab_hwnd, id == ID_TAB 
						);
				}
				break;

				case IDC_BTN_INSTALL:
				{
					wchar_t btn_text[MAX_PATH];				
					GetWindowText( (HWND)lparam, btn_text, countof(btn_text) );

					if ( wcscmp(btn_text, IDS_BOOTINSTALL) == 0 )
					{
						_menu_set_loader_vol( hwnd, vol, dsk_num, type, is_small );
					}
					if ( wcscmp(btn_text, IDS_BOOTREMOVE) == 0 )
					{
						_menu_unset_loader_mbr(hwnd, vol, dsk_num, type);
					}
					if ( wcscmp(btn_text, IDS_BOOTCREATE) == 0 )
					{
						_menu_set_loader_file( hwnd, path, type == CTL_LDR_ISO, is_small );

						SendMessage(
							bt_sheets[0].hwnd, WM_COMMAND, MAKELONG(IDE_BOOT_PATH, EN_CHANGE), (LPARAM)GetDlgItem(bt_sheets[0].hwnd, IDE_BOOT_PATH)
							);

						return 0L;
					}
					if ( wcscmp(btn_text, IDS_SAVECHANGES) == 0 )
					{
						_save_boot_config(bt_sheets[1].hwnd, type, dsk_num, vol, path, &conf);
						return 0L;
					}
					_list_devices( __lists[HBOT_WIZARD_BOOT_DEVS], type == CTL_LDR_MBR, -1 );
					_refresh_boot_buttons( bt_sheets[0].hwnd, __lists[HBOT_WIZARD_BOOT_DEVS], -1 );

				} 
				break;

				case IDC_BTN_UPDATE:
				{
					_menu_update_loader( hwnd, vol, dsk_num );
				}
				break;

				case IDC_BTN_CHANGE_CONF:
				{
					rlt = _init_boot_config( bt_sheets[1].hwnd, type, dsk_num, vol, path, &conf );
					if ( rlt == ST_OK )
					{
						SetWindowText( GetDlgItem(hwnd, IDC_BTN_INSTALL), IDS_SAVECHANGES );
						EnableWindow( GetDlgItem(hwnd, IDC_BTN_INSTALL), TRUE );

						ShowWindow( GetDlgItem(hwnd, IDC_BTN_CHANGE_CONF), FALSE );
						ShowWindow( GetDlgItem(hwnd, IDC_BTN_UPDATE), FALSE );

						ShowWindow( bt_sheets[0].hwnd, SW_HIDE );
						ShowWindow( bt_sheets[1].hwnd, SW_SHOW );
					}
				}
				break;

				case IDCANCEL: 
				{
					EndDialog( hwnd, IDCANCEL );
				}
				break;
			}
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
		break;
	}
	return 0L;

}


int _dlg_config_loader(
		HWND hwnd,
		BOOL external
	)
{
	int result =
		(int)DialogBoxParam(
				NULL, 
				MAKEINTRESOURCE(IDD_WIZARD_BOOT),
				hwnd,
				pv(_wizard_boot_dlg_proc),
				(LPARAM)external
		);

	return (
		result == IDOK ? ST_OK : ST_CANCEL
	);
}