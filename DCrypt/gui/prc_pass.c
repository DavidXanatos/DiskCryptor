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
#include "prc_pass.h"

#include "prc_keyfiles.h"
#include "pass.h"

INT_PTR CALLBACK
_password_change_dlg_proc(
		HWND	hwnd,
		UINT	message,
		WPARAM	wparam,
		LPARAM	lparam
	)
{
	WORD code = HIWORD(wparam);
	WORD id   = LOWORD(wparam);

	wchar_t display[MAX_PATH] = { 0 };
	static  dlgpass *info;
	int     k;

	int check_init[ ] = {
		IDC_CHECK_SHOW_CURRENT, IDC_USE_KEYFILES_CURRENT,
		IDC_CHECK_SHOW_NEW, IDC_USE_KEYFILES_NEW,
		-1
	};

	_ctl_init static_head[ ] = {
		{ L"# Current Password", IDC_HEAD_PASS_CURRENT, 0 },
		{ L"# New Password",     IDC_HEAD_PASS_NEW,     0 },
		{ L"# Password Rating",  IDC_HEAD_RATING,       0 },
		{ STR_NULL, -1, -1 }
	};

	switch (message) 
	{
		case WM_CTLCOLOREDIT : return _ctl_color(wparam, _cl(COLOR_BTNFACE, LGHT_CLR));
			break;

		case WM_CTLCOLORSTATIC : 
		{
			HDC dc = (HDC)wparam;
			COLORREF bgcolor, fn = 0;

			SetBkMode(dc, TRANSPARENT);

			k = 0;
			while (pass_gr_ctls[k].id != -1) 
			{
				if (pass_gr_ctls[k].hwnd == (HWND)lparam)
					fn = pass_gr_ctls[k].color;

				if (pass_pe_ctls[k].hwnd == (HWND)lparam)
					fn = pass_pe_ctls[k].color;

				k++;
			}
			SetTextColor(dc, fn);

			bgcolor = GetSysColor(COLOR_BTNFACE);
			SetDCBrushColor(dc, bgcolor);
			
			return (INT_PTR)GetStockObject(DC_BRUSH);
		
		}
		break;
		case WM_INITDIALOG : 
		{
			info = (dlgpass *)lparam;

			SendMessage(GetDlgItem(hwnd, IDE_PASS_NEW_CONFIRM), EM_LIMITTEXT, MAX_PASSWORD, 0);
			SendMessage(GetDlgItem(hwnd, IDE_PASS_CURRENT),     EM_LIMITTEXT, MAX_PASSWORD, 0);
			SendMessage(GetDlgItem(hwnd, IDE_PASS_NEW),         EM_LIMITTEXT, MAX_PASSWORD, 0);			

			SendMessage(hwnd, WM_COMMAND, 
				MAKELONG(IDE_PASS_NEW, EN_CHANGE), (LPARAM)GetDlgItem(hwnd, IDE_PASS_NEW));

			if (info->node) {
				_snwprintf(display, countof(display), L"[%s] - %s", 
					info->node->mnt.info.status.mnt_point, info->node->mnt.info.device);

			} else {
				wcscpy(display, L"Change password");

			}
			SetWindowText(hwnd, display);
		
			SendMessage(
				GetDlgItem(hwnd, IDP_BREAKABLE),
				PBM_SETBARCOLOR, 0, _cl(COLOR_BTNSHADOW, DARK_CLR-20)
			);

			SendMessage(
				GetDlgItem(hwnd, IDP_BREAKABLE),
				PBM_SETRANGE, 0, MAKELPARAM(0, 193)
			);

			k = 0;
			while (static_head[k].id != -1) {

				SetWindowText(GetDlgItem(hwnd, static_head[k].id), static_head[k].display);
				SendMessage(GetDlgItem(hwnd, static_head[k].id), (UINT)WM_SETFONT, (WPARAM)__font_bold, 0);
				k++;
			}

			k = 0;
			while (check_init[k] != -1) {

				_sub_class(GetDlgItem(hwnd, check_init[k]), SUB_STATIC_PROC, HWND_NULL);
				_set_check(hwnd, check_init[k], FALSE);
				k++;
			}	
			SetForegroundWindow(hwnd);
			return 1L;

		}
		break;
		case WM_USER_CLICK : 
		{
			if ( (HWND)wparam == GetDlgItem(hwnd, IDC_CHECK_SHOW_CURRENT) )
			{
				SendMessage(GetDlgItem(hwnd, IDE_PASS_CURRENT), 
					EM_SETPASSWORDCHAR, _get_check(hwnd, IDC_CHECK_SHOW_CURRENT) ? 0 : '*', 0
					);

				InvalidateRect(GetDlgItem(hwnd, IDE_PASS_CURRENT), NULL, TRUE);
				return 1L;

			}
			if ( (HWND)wparam == GetDlgItem(hwnd, IDC_CHECK_SHOW_NEW) )
			{
				int mask = _get_check(hwnd, IDC_CHECK_SHOW_NEW) ? 0 : '*';

				SendMessage(GetDlgItem(hwnd, IDE_PASS_NEW), EM_SETPASSWORDCHAR,	mask, 0);
				SendMessage(GetDlgItem(hwnd, IDE_PASS_NEW_CONFIRM), EM_SETPASSWORDCHAR,	mask, 0);

				InvalidateRect(GetDlgItem(hwnd, IDE_PASS_NEW), NULL, TRUE);
				InvalidateRect(GetDlgItem(hwnd, IDE_PASS_NEW_CONFIRM), NULL, TRUE);
				return 1L;

			}
			if ( (HWND)wparam == GetDlgItem(hwnd, IDC_USE_KEYFILES_CURRENT) ) 
			{
				SendMessage(
					hwnd, WM_COMMAND, MAKELONG(IDE_PASS_CURRENT, EN_CHANGE), (LPARAM)GetDlgItem(hwnd, IDE_PASS_CURRENT)
					);
				EnableWindow(
					GetDlgItem(hwnd, IDB_USE_KEYFILES_CURRENT), _get_check(hwnd, IDC_USE_KEYFILES_CURRENT)
					);
				return 1L;
			}
			if ( (HWND)wparam == GetDlgItem(hwnd, IDC_USE_KEYFILES_NEW) ) 
			{
				SendMessage(
					hwnd, WM_COMMAND, MAKELONG(IDE_PASS_NEW, EN_CHANGE), (LPARAM)GetDlgItem(hwnd, IDE_PASS_NEW)
					);
				EnableWindow(
					GetDlgItem(hwnd, IDB_USE_KEYFILES_NEW), _get_check(hwnd, IDC_USE_KEYFILES_NEW
					));
				return 1L;
			}
		}
		break;
		case WM_COMMAND :

			if ( id == IDB_USE_KEYFILES_CURRENT )
			{
				_dlg_keyfiles( hwnd, KEYLIST_CURRENT );

				SendMessage(
					hwnd, WM_COMMAND, MAKELONG(IDE_PASS_CURRENT, EN_CHANGE), (LPARAM)GetDlgItem(hwnd, IDE_PASS_CURRENT)
					);
			}
			if ( id == IDB_USE_KEYFILES_NEW )
			{
				_dlg_keyfiles( hwnd, KEYLIST_CHANGE_PASS );

				SendMessage(
					hwnd, WM_COMMAND, MAKELONG(IDE_PASS_NEW, EN_CHANGE), (LPARAM)GetDlgItem(hwnd, IDE_PASS_NEW)
					);
			}

			if ( code == EN_CHANGE ) 
			{
				BOOL correct_current, correct_new;
				int  id_stat_current, id_stat_new;

				dc_pass *pass;
				dc_pass *verify;

				ldr_config conf;

				int kb_layout = -1;
				int keylist;

				if ( info->node && _is_boot_device(&info->node->mnt.info) )
				{
					if (dc_get_mbr_config( -1, NULL, &conf ) == ST_OK)
					{
						kb_layout = conf.kbd_layout;
					}
				}
				if ( id == IDE_PASS_NEW )
				{
					int entropy;
					dc_pass *pass;

					pass = _get_pass(hwnd, IDE_PASS_NEW);

					_draw_pass_rating(hwnd, pass, kb_layout, &entropy);
					secure_free(pass);

					SendMessage(
						GetDlgItem(hwnd, IDP_BREAKABLE),
						PBM_SETPOS,
						(WPARAM)entropy, 0
						);
				}
				
				pass    = _get_pass(hwnd, IDE_PASS_CURRENT);
				keylist = _get_check(hwnd, IDC_USE_KEYFILES_CURRENT) ? KEYLIST_CURRENT : KEYLIST_NONE;

				correct_current = 
					_input_verify(pass, NULL, keylist, -1, &id_stat_current
				);

				secure_free(pass);

				pass    = _get_pass(hwnd, IDE_PASS_NEW);
				verify  = _get_pass(hwnd, IDE_PASS_NEW_CONFIRM);
				keylist = _get_check(hwnd, IDC_USE_KEYFILES_NEW) ? KEYLIST_CHANGE_PASS : KEYLIST_NONE;

				correct_new =
					_input_verify(pass, verify, keylist, kb_layout, &id_stat_new
					);

				secure_free(pass);
				secure_free(verify);				

				SetWindowText(GetDlgItem(hwnd, IDC_PASS_STATUS_CURRENT), _get_text_name(id_stat_current, pass_status));
				SetWindowText(GetDlgItem(hwnd, IDC_PASS_STATUS_NEW), _get_text_name(id_stat_new, pass_status));

				EnableWindow(GetDlgItem(hwnd, IDOK), correct_current && correct_new);

				return 1L;
		
			}
			if ( (id == IDCANCEL) || (id == IDOK) )
			{
				if ( id == IDOK )
				{
					info->pass     = _get_pass_keyfiles(hwnd, IDE_PASS_CURRENT, IDC_USE_KEYFILES_CURRENT, KEYLIST_CURRENT);
					info->new_pass = _get_pass_keyfiles(hwnd, IDE_PASS_NEW,     IDC_USE_KEYFILES_NEW,     KEYLIST_CHANGE_PASS);

					if ( IsWindowEnabled(GetDlgItem(hwnd, IDC_COMBO_MNPOINT)) && 
						 info->mnt_point
						 )
					{
						GetWindowText(
							GetDlgItem(hwnd, IDC_COMBO_MNPOINT), 
							(wchar_t *)info->mnt_point, 
							MAX_PATH
							);
					}
				}
				EndDialog (hwnd, id);
				return 1L;
	
			}
		break;
		case WM_DESTROY: 
		{
			_wipe_pass_control(hwnd, IDE_PASS_NEW_CONFIRM);
			_wipe_pass_control(hwnd, IDE_PASS_CURRENT);
			_wipe_pass_control(hwnd, IDE_PASS_NEW);		

			_keyfiles_wipe(KEYLIST_CURRENT);
			_keyfiles_wipe(KEYLIST_CHANGE_PASS);

			return 0L;
		}
		break;
		default:
		{
			int rlt = _draw_proc(message, lparam);
			if (rlt != -1) return rlt;
		}
	}
	return 0L;

}


INT_PTR CALLBACK
_password_dlg_proc(
		HWND	hwnd,
		UINT	message,
		WPARAM	wparam,
		LPARAM	lparam
	)
{
	WORD code	= HIWORD(wparam);
	WORD id		= LOWORD(wparam);

	wchar_t display[MAX_PATH] = { 0 };
	static dlgpass *info;

	static RECT rc_left  = { 0, 0, 0, 0 };
	static RECT rc_right = { 0, 0, 0, 0 };

	static cut;
	switch ( message )
	{
		case WM_DRAWITEM : 
		{
			DRAWITEMSTRUCT *draw = pv(lparam);

			static RECT left;
			static RECT right;

			switch ( draw->CtlID )
			{
				case IDC_FRAME_LEFT: 
				{
					if ( !rc_left.right )
					{
						_relative_rect( draw->hwndItem, &rc_left );
						rc_left.bottom -= cut;
					}
					MoveWindow(
						draw->hwndItem, rc_left.left, rc_left.top, rc_left.right, rc_left.bottom, TRUE
						);
				}
				break;
				case IDC_FRAME_RIGHT:
				{					
					if ( !rc_right.right )
					{
						_relative_rect( draw->hwndItem, &rc_right );
						rc_right.bottom -= cut;
					}
					MoveWindow(
						draw->hwndItem, rc_right.left, rc_right.top, rc_right.right, rc_right.bottom, TRUE
						);
				}
				break;
			}
			_draw_static( draw );
			return 1L;		
		}
		break;
		case WM_CTLCOLOREDIT : 
		{
			return (
				_ctl_color( wparam, _cl(COLOR_BTNFACE, LGHT_CLR) )
			);
		}
		break;
		case WM_INITDIALOG : 
		{
			int ctl_resize[ ] = {
				IDC_FRAME_LEFT,
				IDC_FRAME_RIGHT,
				-1
			};

			info = (dlgpass *)lparam;			
			_init_mount_points( GetDlgItem(hwnd, IDC_COMBO_MNPOINT) );

			SendMessage( GetDlgItem(hwnd, IDC_COMBO_MNPOINT), CB_SETCURSEL, 1, 0 );
			SendMessage( GetDlgItem(hwnd, IDE_PASS), EM_LIMITTEXT, MAX_PASSWORD, 0 );

			if ( info->node )
			{
				_snwprintf(
					display, countof(display), L"[%s] - %s", 
					info->node->mnt.info.status.mnt_point, info->node->mnt.info.device
					);
			} else
			{
				wcscpy(display, L"Enter password");
			}

			SetWindowText( hwnd, display );

			SetWindowText( GetDlgItem(hwnd, IDC_HEAD_PASS), L"# Current Password" );
			SendMessage( GetDlgItem(hwnd, IDC_HEAD_PASS), WM_SETFONT, (WPARAM)__font_bold, 0 );

			SetWindowText( GetDlgItem(hwnd, IDC_HEAD_MOUNT_OPTIONS), L"# Mount Options" );
			SendMessage( GetDlgItem(hwnd, IDC_HEAD_MOUNT_OPTIONS), WM_SETFONT, (WPARAM)__font_bold, 0 );

			_sub_class( GetDlgItem(hwnd, IDC_CHECK_SHOW), SUB_STATIC_PROC, HWND_NULL );
			_set_check( hwnd, IDC_CHECK_SHOW, FALSE );

			_sub_class( GetDlgItem(hwnd, IDC_USE_KEYFILES), SUB_STATIC_PROC, HWND_NULL );
			_set_check( hwnd, IDC_USE_KEYFILES, FALSE );

			{
				HWND mnt_combo = GetDlgItem( hwnd, IDC_COMBO_MNPOINT );
				HWND mnt_check = GetDlgItem( hwnd, IDC_CHECK_MNT_SET );
				HWND mnt_label = GetDlgItem( hwnd, IDC_MNT_POINT );

				BOOL enable;
				RECT rc_main;

				GetWindowRect(hwnd, &rc_main);
				enable = info->node && ( info->node->mnt.info.status.mnt_point[0] == L'\\' );

				EnableWindow( mnt_combo, enable );
				EnableWindow( mnt_check, enable );
				EnableWindow( mnt_label, enable );

				_sub_class( GetDlgItem(hwnd, IDC_CHECK_MNT_SET), SUB_STATIC_PROC, HWND_NULL );
				_set_check( hwnd, IDC_CHECK_MNT_SET, enable );

			}
			SendMessage(
				hwnd, WM_COMMAND, MAKELONG(IDE_PASS, EN_CHANGE), (LPARAM)GetDlgItem(hwnd, IDE_PASS)
				);

			SetForegroundWindow(hwnd);
			return 1L;

		}
		break;
		case WM_USER_CLICK : 
		{
			if ( (HWND)wparam == GetDlgItem(hwnd, IDC_CHECK_MNT_SET) )
			{
				EnableWindow(
					GetDlgItem(hwnd, IDC_COMBO_MNPOINT), _get_check(hwnd, IDC_CHECK_MNT_SET)
					);
				EnableWindow(
					GetDlgItem(hwnd, IDC_MNT_POINT), _get_check(hwnd, IDC_CHECK_MNT_SET)
					);
				return 1L;
			}

			if ( (HWND)wparam == GetDlgItem(hwnd, IDC_CHECK_SHOW) )
			{
				int mask = _get_check(hwnd, IDC_CHECK_SHOW) ? 0 : '*';

				SendMessage(GetDlgItem(hwnd, IDE_PASS), EM_SETPASSWORDCHAR, mask, 0 );
				InvalidateRect(GetDlgItem(hwnd, IDE_PASS), NULL, TRUE);

				return 1L;
			}

			if ( (HWND)wparam == GetDlgItem(hwnd, IDC_USE_KEYFILES) ) 
			{
				SendMessage(
					hwnd, WM_COMMAND, 
					MAKELONG(IDE_PASS, EN_CHANGE), (LPARAM)GetDlgItem(hwnd, IDE_PASS)
					);

				EnableWindow(GetDlgItem(hwnd, IDB_USE_KEYFILES), _get_check(hwnd, IDC_USE_KEYFILES));
				return 1L;
			}
		}
		break;
		case WM_COMMAND :

			if ( id == IDB_USE_KEYFILES )
			{
				_dlg_keyfiles(hwnd, KEYLIST_CURRENT);

				SendMessage(
					hwnd, WM_COMMAND, MAKELONG(IDE_PASS, EN_CHANGE), (LPARAM)GetDlgItem(hwnd, IDE_PASS)
					);
			}

			if ( code == CBN_SELCHANGE && id == IDC_COMBO_MNPOINT )
			{
				if ( SendMessage((HWND)lparam, CB_GETCURSEL, 0, 0) == 0 )
				{
					HWND h_combo = GetDlgItem(hwnd, IDC_COMBO_MNPOINT);

					int sel_item = 1;
					wchar_t path[MAX_PATH];

					if ( _folder_choice(hwnd, path, L"Choice folder for mount point") )
					{
						sel_item = (int)SendMessage(h_combo, CB_GETCOUNT, 0, 0);
						SendMessage(h_combo, CB_ADDSTRING, 0, (LPARAM)path);						
					}
					SendMessage(h_combo, CB_SETCURSEL, sel_item, 0);

				}
			}
			if (code == EN_CHANGE)
			{
				BOOL correct;
				int idx_status;

				dc_pass *pass = _get_pass(hwnd, IDE_PASS);
				int keylist = _get_check(hwnd, IDC_USE_KEYFILES) ? KEYLIST_CURRENT : KEYLIST_NONE;

				correct = 
					_input_verify(pass, NULL, keylist, -1, &idx_status
				);

				secure_free(pass);

				SetWindowText(GetDlgItem(hwnd, IDC_PASS_STATUS), _get_text_name(idx_status, pass_status));
				EnableWindow(GetDlgItem(hwnd, IDOK), correct);

				return 1L;
		
			}
			if ((id == IDCANCEL) || (id == IDOK)) 
			{
				if (id == IDOK)
				{
					info->pass = _get_pass_keyfiles(hwnd, IDE_PASS, IDC_USE_KEYFILES, KEYLIST_CURRENT);

					if (IsWindowEnabled(GetDlgItem(hwnd, IDC_COMBO_MNPOINT)) && 
							info->mnt_point) 
					{
						GetWindowText(
								GetDlgItem(hwnd, IDC_COMBO_MNPOINT), 
								(wchar_t *)info->mnt_point, 
								MAX_PATH
						);
					}
				}
				EndDialog (hwnd, id);
				return 1L;
	
			}
		break;
		case WM_DESTROY: 
		{
			_wipe_pass_control(hwnd, IDE_PASS);
			_keyfiles_wipe(KEYLIST_CURRENT);

			memset(&rc_right, 0, sizeof(rc_right));
			memset(&rc_left, 0, sizeof(rc_left));

			cut = 0;
			return 0L;

		}
		break;
		case WM_MEASUREITEM: 
		{
			MEASUREITEMSTRUCT *item = pv(lparam);

			if (item->CtlType != ODT_LISTVIEW)
				item->itemHeight -= 3;
 
		}
		break; 
	}
	return 0L;

}


int _dlg_get_pass(
		HWND	 hwnd,
		dlgpass	*pass
	)
{
	int result =
		(int)DialogBoxParam(
				NULL, 
				MAKEINTRESOURCE(IDD_DIALOG_PASS),
				hwnd,
				pv(_password_dlg_proc),
				(LPARAM)pass
		);

	return (
		result == IDOK ? ST_OK : ST_CANCEL
	);
}


int _dlg_change_pass(
		HWND	 hwnd,
		dlgpass	*pass
	)
{
	int result =
		(int)DialogBoxParam(
				NULL, 
				MAKEINTRESOURCE(IDD_DIALOG_CHANGE_PASS),
				hwnd,
				pv(_password_change_dlg_proc),
				(LPARAM)pass
		);

	return (
		result == IDOK ? ST_OK : ST_CANCEL
	);
}
