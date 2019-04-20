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
#include "prc_options.h"

#include "hotkeys.h"
#include "prc_common.h"
#include "autorun.h"

INT_PTR 
CALLBACK
_options_dlg_proc(
		HWND	hwnd,
		UINT	message,
		WPARAM	wparam,
		LPARAM	lparam
	)
{
	_ctl_init ctl_chk_general[ ] =
	{
		{ STR_NULL, IDC_AUTO_MOUNT_ON_BOOT,		CONF_AUTOMOUNT_BOOT		},
		{ STR_NULL, IDC_EXPLORER_ON_MOUNT,		CONF_EXPLORER_MOUNT		},
		{ STR_NULL, IDC_CACHE_PASSWORDS,		CONF_CACHE_PASSWORD		},
		{ STR_NULL, IDC_UNMOUNT_LOGOFF,			CONF_DISMOUNT_LOGOFF	},
		{ STR_NULL, IDC_FORCE_UNMOUNT,			CONF_FORCE_DISMOUNT		},
		{ STR_NULL, IDC_WIPE_LOGOFF,			CONF_WIPEPAS_LOGOFF		},
		{ STR_NULL, IDC_AUTO_START,				CONF_AUTO_START			}
	};

	_ctl_init ctl_chk_extended[ ] =
	{
		{ STR_NULL, IDC_HARD_CRYPTO_SUPPORT,	CONF_HW_CRYPTO		},
		{ STR_NULL, IDC_HIDE_FILES,				CONF_HIDE_DCSYS		},
		{ STR_NULL, IDC_DISABLE_TRIM,			CONF_DISABLE_TRIM	},
		{ STR_NULL, IDC_SSD_OPTIMIZATION,		CONF_ENABLE_SSD_OPT	}
	};

	_ctl_init static_head_general[ ] = 
	{
		{ L"# Mount Settings",		IDC_HEAD1, 0 },
		{ L"# Password Caching",	IDC_HEAD2, 0 },
		{ L"# Boot Options",		IDC_HEAD3, 0 }
	};

	_ctl_init static_head_extended[ ] = 
	{
		{ L"# Extended Settings",	IDC_HEAD1, 0 }
	};

	WORD   code             = LOWORD(wparam);
	WORD   id               = LOWORD(wparam);
	DWORD _flags            = 0;
	DWORD _hotkeys[HOTKEYS] = { 0 };

	_wnd_data *wnd;

	int check = 0; 
	int k     = 0;

	switch ( message )
	{
		case WM_INITDIALOG :
		{
			TCITEM     tab_item = { TCIF_TEXT };
			HWND       h_tab    = GetDlgItem( hwnd, IDT_TAB );
			_tab_data *d_tab    = malloc(sizeof(_tab_data));

			wnd = _sub_class(
				h_tab, SUB_NONE,
				CreateDialog( __hinst, MAKEINTRESOURCE(DLG_CONF_GENERAL), GetDlgItem(hwnd, IDC_TAB), _tab_proc ),
				CreateDialog( __hinst, MAKEINTRESOURCE(DLG_CONF_EXTNDED), GetDlgItem(hwnd, IDC_TAB), _tab_proc ),
				CreateDialog( __hinst, MAKEINTRESOURCE(DLG_CONF_HOTKEYS), GetDlgItem(hwnd, IDC_TAB), _tab_proc ),
				HWND_NULL
				);

			memset(d_tab, 0, sizeof(_tab_data));

			d_tab->active = wnd->dlg[0];
			wnd_set_long(hwnd, GWL_USERDATA, d_tab);
			{
				for ( k = 0; k < countof(ctl_chk_general); k++ )
				{
					_sub_class( GetDlgItem( wnd->dlg[0], ctl_chk_general[k].id ), SUB_STATIC_PROC, HWND_NULL );
					_set_check( wnd->dlg[0], ctl_chk_general[k].id, __config.conf_flags & ctl_chk_general[k].val );
				}
				for ( k = 0; k < countof(ctl_chk_extended); k++ )
				{
					_sub_class( GetDlgItem( wnd->dlg[1], ctl_chk_extended[k].id ), SUB_STATIC_PROC, HWND_NULL );
					_set_check( wnd->dlg[1], ctl_chk_extended[k].id, __config.conf_flags & ctl_chk_extended[k].val );
				}
				if ( ! (__config.load_flags & DST_HW_CRYPTO) )
				{
					wchar_t s_ch_label[MAX_PATH] = { 0 };

					HWND h_check = GetDlgItem( wnd->dlg[1], IDC_HARD_CRYPTO_SUPPORT );
					EnableWindow( h_check, FALSE );

					GetWindowText( h_check, s_ch_label, countof(s_ch_label) );
					wcscat( s_ch_label, L" (not supported)" );

					SetWindowText( h_check, s_ch_label );
				}
				for ( k = 0; k < countof(static_head_general); k++ )
				{
					SetWindowText(GetDlgItem(wnd->dlg[0], static_head_general[k].id), static_head_general[k].display);
					SendMessage(GetDlgItem(wnd->dlg[0], static_head_general[k].id), (UINT)WM_SETFONT, (WPARAM)__font_bold, 0);
				}
				for ( k = 0; k < countof(static_head_extended); k++ )
				{
					SetWindowText(GetDlgItem(wnd->dlg[1], static_head_extended[k].id), static_head_extended[k].display);
					SendMessage(GetDlgItem(wnd->dlg[1], static_head_extended[k].id), (UINT)WM_SETFONT, (WPARAM)__font_bold, 0);
				}
				SendMessage(
					wnd->dlg[0], WM_USER_CLICK, (WPARAM)GetDlgItem(wnd->dlg[0], IDC_AUTO_START), 0
					);

				_sub_class(
					GetDlgItem(wnd->dlg[2], IDC_KEY_USEEXT), SUB_STATIC_PROC, HWND_NULL
					);

				k = 0;
				while ( hotks_edit[k].id != -1 )
				{
					wchar_t key[200] = { 0 };

					_sub_class(
						GetDlgItem(wnd->dlg[2], hotks_edit[k].id), SUB_KEY_PROC, HWND_NULL
						);

					_sub_class(
						GetDlgItem(wnd->dlg[2], hotks_chk[k].id), SUB_STATIC_PROC, HWND_NULL
						);

					_set_check( wnd->dlg[2], hotks_chk[k].id, __config.hotkeys[k] );
					SendMessage(
						wnd->dlg[2], WM_USER_CLICK, (WPARAM)GetDlgItem(wnd->dlg[2], hotks_chk[k].id), 0
						);

					_key_name(HIWORD( __config.hotkeys[k]), LOWORD(__config.hotkeys[k]), key );
					SetWindowText(GetDlgItem(wnd->dlg[2], hotks_edit[k].id), key);

					((_wnd_data *)wnd_get_long(
						GetDlgItem(wnd->dlg[2], hotks_edit[k].id), GWL_USERDATA)
						)->vk = __config.hotkeys[k];

					k++;
				}
			}
			tab_item.pszText = L"General";
			TabCtrl_InsertItem(h_tab, 0, &tab_item);

			tab_item.pszText = L"Extended";
			TabCtrl_InsertItem(h_tab, 1, &tab_item);

			tab_item.pszText = L"Hot Keys";
			TabCtrl_InsertItem(h_tab, 2, &tab_item);
			{
				k = 1;
				while ( wnd->dlg[k] != 0 )
				{
					ShowWindow( wnd->dlg[k], SW_HIDE );
					k++;
				}
			}
			SetForegroundWindow( hwnd );
			return 1L;
		}
		break;

		case WM_NOTIFY :
		{		
			if ( wparam == IDT_TAB )
			{
				if ( ((NMHDR *)lparam)->code == TCN_SELCHANGE )
				{
					HWND h_tab = GetDlgItem(hwnd, IDT_TAB);

					if ( !_is_curr_in_group(h_tab) )
					{
						_change_page( h_tab, TabCtrl_GetCurSel(h_tab) );
					}
				}
			}
		}
		break;

		case WM_COMMAND :
		{
			/*
			switch (id) 
			{
			case ID_SHIFT_TAB :
			case ID_TAB :
			{
				HWND h_current = GetFocus( );
				HWND h_next    = GetNextDlgTabItem( sheets[index].hwnd, h_current, id == ID_SHIFT_TAB );

				SetFocus( h_next );
			}
			break;
			*/

			if ( (id == IDOK) || (id == IDCANCEL) )
			{
				wnd = wnd_get_long( GetDlgItem(hwnd, IDT_TAB), GWL_USERDATA );
				if ( wnd ) 
				{
					for ( k = 0; k < countof(ctl_chk_general); k++ )
					{	
						_flags |= _get_check(wnd->dlg[0], ctl_chk_general[k].id) ? ctl_chk_general[k].val : FALSE;
					}
					for ( k = 0; k < countof(ctl_chk_extended); k++ )
					{	
						_flags |= _get_check(wnd->dlg[1], ctl_chk_extended[k].id) ? ctl_chk_extended[k].val : FALSE;
					}
					k = 0;
					while ( hotks_edit[k].id != -1 )
					{					
						if ( _get_check(wnd->dlg[2], hotks_chk[k].id) )
						{
							_hotkeys[k] = (
								(_wnd_data *)wnd_get_long(GetDlgItem(wnd->dlg[2], hotks_edit[k].id), GWL_USERDATA)
								)->vk;
						}
						k++;
					}
				}
				
				if ( id == IDCANCEL ) check = TRUE;
				if ( id == IDOK ) 
				{
					_unset_hotkeys(__config.hotkeys);	
					check = _check_hotkeys(wnd->dlg[0], _hotkeys);					

					if ( check )
					{
						if ( _hotkeys[3] && !__config.hotkeys[3] ) {
							if (! __msg_w( hwnd, L"Set Hotkey for call BSOD?" ) )
							{
								_hotkeys[3] = 0;
							}
						}
						if ( (_flags & CONF_AUTO_START) != (__config.conf_flags & CONF_AUTO_START) )
						{
							autorun_set(_flags & CONF_AUTO_START);
						}
						__config.conf_flags = _flags;
						memcpy(&__config.hotkeys, &_hotkeys, sizeof(DWORD)*HOTKEYS);

						dc_save_config(&__config);

					}
					_set_hotkeys(hwnd, __config.hotkeys, FALSE);

				}
				if ( check )
				{
					EndDialog (hwnd, id);
				}
				return 1L;
			}
		}
		break;

		case WM_DESTROY : 
		{
			wnd = wnd_get_long( GetDlgItem(hwnd, IDT_TAB), GWL_USERDATA );
			if ( wnd )
			{
				for ( k = 0; k < countof(ctl_chk_general); k++ )
				{
					__unsub_class(GetDlgItem(wnd->dlg[0], ctl_chk_general[k].id));
				}
				for ( k = 0; k < countof(ctl_chk_extended); k++ )
				{
					__unsub_class(GetDlgItem(wnd->dlg[1], ctl_chk_extended[k].id));
				}
				__unsub_class(GetDlgItem(wnd->dlg[1], IDC_KEY_USEEXT));

				k = 0;
				while ( hotks_edit[k].id != -1 )
				{
					__unsub_class(GetDlgItem(wnd->dlg[2], hotks_edit[k].id));
					__unsub_class(GetDlgItem(wnd->dlg[2], hotks_chk[k].id));
					k++;
				}
			}
			__unsub_class(GetDlgItem(hwnd, IDT_TAB));

		}
		break;

		default :
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


int _dlg_options(
		HWND hwnd
	)
{
	int result =
		(int)DialogBoxParam(
				NULL,
				MAKEINTRESOURCE(IDD_DIALOG_OPTIONS),
				hwnd,
				pv( _options_dlg_proc ),
				(LPARAM)NULL
		);

	return (
		result == IDOK ? ST_OK : ST_CANCEL
	);
}