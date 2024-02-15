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
#include "prc_main.h"

#include "dlg_drives_list.h"
#include "drives_list.h"
#include "dlg_menu.h"

#include "hotkeys.h"
#include "threads.h"

#include "prc_common.h"
#include "prc_options.h"
#include "prc_wizard_boot.h"

static int _dlg_height;
static int _dlg_width;

static int _dlg_right;
static int _dlg_left;
static int _dlg_bottom;

void _init_main_dlg(
		HWND hwnd
	)
{
	MENUITEMINFO mnitem = { sizeof(mnitem) };
	wchar_t      display[MAX_PATH];

	_snwprintf(
		display, countof(display), L"%s %S", DC_NAME, DC_FILE_VER
		);

	SetWindowText( hwnd, display );

	SendMessage( hwnd, WM_SYSCOLORCHANGE, 0, 0 );
	_set_hotkeys( hwnd, __config.hotkeys, TRUE );

	_tray_icon( TRUE );

	mnitem.fMask = MIIM_FTYPE;
	mnitem.fType = MFT_RIGHTJUSTIFY;
	SetMenuItemInfo( GetMenu( hwnd ), ID_HOMEPAGE, FALSE, &mnitem );

	SendMessage( GetDlgItem( hwnd, IDC_DRIVES_HEAD ), WM_SETFONT, (WPARAM)__font_bold, 0 );
	{
		RECT  rc, cr;
		void *res;
		int   size;

		GetClientRect(hwnd, &rc);
		GetWindowRect(hwnd, &cr);

		if ( ( res = _extract_rsrc(IDD_MAIN_DLG, RT_DIALOG, &size) ) != NULL )
		{
			_dlg_templateex *rs_template = pv(res);		
			RECT rect = { rs_template->x, rs_template->y, rs_template->cx, rs_template->cy };

			MapDialogRect(hwnd, &rect);

			_dlg_height = rect.bottom;
			_dlg_width  = rect.right;

			_dlg_right  = cr.right;
			_dlg_bottom = cr.bottom;

			if ( _dlg_height != rc.bottom )
			{
				SendMessage( hwnd, WM_SIZE, 0, MAKELONG(rc.right, rc.bottom) );
			}
		}
	}
}


INT_PTR 
CALLBACK
_main_dialog_proc(
		HWND	hwnd,
		UINT	message,
		WPARAM	wparam,
		LPARAM	lparam
	)
{
	WORD id		= LOWORD(wparam);
	WORD code	= HIWORD(wparam);

	_wnd_data	*wnd;
	_dnode		*sel;
	_dmnt		*mnt;

	int k = 0;
	switch ( message )
	{
		case WM_INITDIALOG :
		{
			memset( __lists, 0, sizeof(__lists) );

			__lists[HMAIN_DRIVES] = GetDlgItem( hwnd, IDC_DISKDRIVES );
			__dlg = hwnd;

			_init_main_dlg( hwnd );

			_load_diskdrives( hwnd, &__drives, _list_volumes(0) );
			{
				TCITEM     tab_item = { TCIF_TEXT };
				HWND       h_tab    = GetDlgItem(hwnd, IDT_INFO);
				_tab_data *d_tab    = malloc(sizeof(_tab_data));

				memset( d_tab, 0, sizeof(_tab_data) );
				d_tab->curr_tab = 1;

				wnd_set_long( hwnd, GWL_USERDATA, d_tab );

				wnd = _sub_class(
						h_tab, SUB_NONE,
						CreateDialog( __hinst, MAKEINTRESOURCE(DLG_MAIN_INFO),   GetDlgItem(hwnd, IDC_MAIN_TAB), _tab_proc ),
						CreateDialog( __hinst, MAKEINTRESOURCE(DLG_MAIN_ACTION), GetDlgItem(hwnd, IDC_MAIN_TAB), _tab_proc ),
						HWND_NULL
					);
				{
					__lists[HMAIN_INFO] = GetDlgItem( wnd->dlg[0], IDC_INF_TABLE );
					__lists[HMAIN_ACT]  = GetDlgItem( wnd->dlg[1], IDC_ACT_TABLE );
				}
				{
					__dlg_act_info = wnd->dlg[1];

					_list_insert_col( __lists[HMAIN_INFO], 380 );
					_list_insert_col( __lists[HMAIN_INFO], 90 );
					
					while (
						_list_insert_item( __lists[HMAIN_INFO], k, 0, _info_table_items[k], 0 )
						) k++;

					_set_header_text( 
						__lists[HMAIN_INFO], 0, STR_HEAD_NO_ICONS, countof(STR_HEAD_NO_ICONS) 
						);

					_list_insert_col( __lists[HMAIN_ACT], 90 );
					_list_insert_col( __lists[HMAIN_ACT], 70 );

					_list_insert_col( __lists[HMAIN_ACT], 85 );
					_list_insert_col( __lists[HMAIN_ACT], 50 );
						
					_list_insert_item( __lists[HMAIN_ACT],    0, 0, _act_table_items[0], 0 );
					ListView_SetItemText( __lists[HMAIN_ACT], 0, 2, _act_table_items[3] );

					_list_insert_item( __lists[HMAIN_ACT],    1, 0, _act_table_items[1], 0 );
					ListView_SetItemText( __lists[HMAIN_ACT], 1, 2, _act_table_items[4] );

					_init_combo(
						GetDlgItem( __dlg_act_info, IDC_COMBO_PASSES), wipe_modes, WP_NONE, FALSE, -1
						);

					SendMessage(
						GetDlgItem( __dlg_act_info, IDC_PROGRESS ),
						PBM_SETBARCOLOR, 0, _cl( COLOR_BTNSHADOW, DARK_CLR - 20 )
						);

					SendMessage(
						GetDlgItem( __dlg_act_info, IDC_PROGRESS ),
						PBM_SETRANGE, 0, MAKELPARAM(0, PRG_STEP)
						);
				}
				tab_item.pszText = L"Info";
				TabCtrl_InsertItem( h_tab, 0, &tab_item );
				{
					NMHDR mhdr = { 0, 0, TCN_SELCHANGE };
					TabCtrl_SetCurSel( h_tab, 0 );

					SendMessage(hwnd, WM_NOTIFY, IDT_INFO, (LPARAM)&mhdr);
				}
			}
			SendMessage( hwnd, WM_SYSCOLORCHANGE, 0, 0 );

			_set_timer( MAIN_TIMER, TRUE, TRUE );
			_set_timer( RAND_TIMER, TRUE, FALSE );
			_set_timer( POST_TIMER, TRUE, FALSE );

			return 0L;
		} 
		break;

		case WM_WINDOWPOSCHANGED :
		{
			WINDOWPOS *pos = (WINDOWPOS *)lparam;
			int flags = pos->flags;

			_dlg_right  = pos->cx + pos->x;
			_dlg_bottom = pos->cy + pos->y;
			_dlg_left   = pos->x;

			if ( ( flags & SWP_SHOWWINDOW ) || ( flags & SWP_HIDEWINDOW ) )
			{
				_set_timer( MAIN_TIMER, flags & SWP_SHOWWINDOW, TRUE );
			}
			return 0L;
		}
		break;

		case WM_ENTERSIZEMOVE :
		{
			//_middle_ctl(
			//	GetDlgItem(hwnd, IDC_DISKDRIVES),
			//	GetDlgItem(hwnd, IDC_RESIZING),
			//	TRUE
			//	);

			//ShowWindow(GetDlgItem(hwnd, IDC_DISKDRIVES), SW_HIDE);
			return 0L;
		}
		break;

		case WM_EXITSIZEMOVE :
		{
			//ShowWindow(GetDlgItem(hwnd, IDC_DISKDRIVES), SW_SHOW);
			return 0L;
		}
		break;

		case WM_SIZING :
		{
			RECT *rect = ((RECT *)lparam);

			rect->right = _dlg_right;
			rect->left  = _dlg_left;

			if ( rect->bottom - rect->top < MAIN_DLG_MIN_HEIGHT ) 
			{
				rect->bottom = rect->top + MAIN_DLG_MIN_HEIGHT;
			}
			return 1L;
		}
		break;

		case WM_SIZE :
		{
			int height = HIWORD(lparam);
			int width  = LOWORD(lparam);
			int k;

			_size_move_ctls _resize[ ] = 
			{
				{ -1, IDC_DISKDRIVES,   FALSE, 0, 0 },
				{ -1, IDC_STATIC_LIST,  TRUE,  0, 0 },
				{ -1, IDC_STATIC_RIGHT, TRUE,  0, 0 }
			};

			_size_move_ctls _move[ ] =
			{
				{ IDC_STATIC_LIST, IDC_MAIN_TAB,    TRUE,  0, 6 },
				{ IDC_STATIC_LIST, IDT_INFO,        FALSE, 0, 3 },
				{ IDT_INFO,        IDC_LINE_BOTTOM, TRUE,  0, 2 }
			};
			{
				int c_size_hide = _main_headers[1].width;
				int c_size_show = c_size_hide - GetSystemMetrics(SM_CXVSCROLL);
				int c_size_curr = ListView_GetColumnWidth( __lists[HMAIN_DRIVES], 1 );

				if ( GetWindowLong(__lists[HMAIN_DRIVES], GWL_STYLE) & WS_VSCROLL )
				{
					if ( c_size_curr != c_size_show ) ListView_SetColumnWidth( __lists[HMAIN_DRIVES], 1, c_size_show );
				} else {
					if ( c_size_curr != c_size_hide ) ListView_SetColumnWidth( __lists[HMAIN_DRIVES], 1, c_size_hide );
				}
			}

			if ( height == 0 || width == 0 )
			{
				return 0L;
			}
			for ( k = 0; k < countof(_resize); k++ )
			{
				_resize_ctl(
					GetDlgItem(hwnd, _resize[k].id), height - _dlg_height, 0, _resize[k].val
					);
			}
			_dlg_height = height;

			for ( k = 0; k < countof(_move); k++ )
			{
				_relative_move(
					GetDlgItem( hwnd, _move[k].anchor ), GetDlgItem( hwnd, _move[k].id ), _move[k].dy, _move[k].dy, _move[k].val
					);
				InvalidateRect( GetDlgItem( hwnd, _move[k].id ), NULL, TRUE );
			}
			_middle_ctl(
				GetDlgItem( hwnd, IDC_DISKDRIVES ),
				GetDlgItem( hwnd, IDC_RESIZING ),
				TRUE
				);

			return 0L;
		}
		break;

		case WM_SYSCOMMAND :
		{
			if ( wparam == SC_MINIMIZE || wparam == SC_RESTORE )
			{
				_set_timer( MAIN_TIMER, wparam == SC_RESTORE, TRUE );
			}
			return 0L;
		}
		break;

		case WM_APP + WM_APP_SHOW :
		{
			ShowWindow( hwnd, SW_HIDE );
		}
		break;

		case WM_NOTIFY :
		{
			if ( wparam == IDT_INFO )
			{
				if ( ((NMHDR *)lparam)->code == TCN_SELCHANGE )
				{
					HWND h_tab = GetDlgItem( hwnd, IDT_INFO );
					if ( !_is_curr_in_group(h_tab) )
					{
						_change_page( h_tab, TabCtrl_GetCurSel(h_tab) );
					}
				}
			}
			if ( wparam == IDC_DISKDRIVES )
			{
				sel = pv( _get_sel_item( __lists[HMAIN_DRIVES] ) );
				mnt = &sel->mnt;

				if ( ((NMHDR *)lparam)->code == LVN_ITEMCHANGED &&
					 (((NMLISTVIEW *)lparam)->uNewState & LVIS_FOCUSED ) )
				{
					_update_info_table( FALSE );
					_activate_page( );
					_refresh_menu( );					

					return 1L;
				}
				if ( ((NMHDR *)lparam)->code == LVN_ITEMACTIVATE )
				{
					BOOL mount = 
						( !(sel->mnt.info.status.flags & F_ENABLED) ) && 
						( sel->mnt.fs[0] == '\0' );
					
					if (! mount )
					{
						if (! sel->is_root ) __execute( mnt->info.status.mnt_point );
					} else {
						_menu_mount( sel );
					}
				}
				switch( ((NM_LISTVIEW *)lparam)->hdr.code )
				{
					case LVN_KEYDOWN : 
					{
						WORD key = ((NMLVKEYDOWN *)lparam)->wVKey;
						int item = ListView_GetSelectionMark( __lists[HMAIN_DRIVES] );

						switch ( key )
						{
							case VK_UP:   item -= 1; break;
							case VK_DOWN: item += 1; break;
						}
						if ( _is_root_item(_get_item_index( __lists[HMAIN_DRIVES], item )) )
						{
							ListView_SetItemState( __lists[HMAIN_DRIVES], item, LVIS_FOCUSED, TRUE );
						}
						if ( key != VK_APPS )
						{
							break;
						}
					}

					case NM_RCLICK :
					{
						int item;
						HMENU h_popup = CreatePopupMenu( );

						_dact *act = _create_act_thread( sel, -1, -1 );

						_update_info_table( FALSE );
						_activate_page( );

						_set_timer(MAIN_TIMER, FALSE, FALSE);

						_refresh_menu( );
						
						if ( ListView_GetSelectedCount( __lists[HMAIN_DRIVES] ) && 
							 !_is_root_item((LPARAM)sel) && _is_active_item((LPARAM)sel)
							 )
						{
							if ( mnt->info.status.flags & F_ENABLED )
							{
								if ( mnt->info.status.flags & F_CDROM )
								{
									AppendMenu( h_popup, MF_STRING, ID_VOLUMES_UNMOUNT, IDS_UNMOUNT );
								} else 
								{
									if ( mnt->info.status.flags & F_FORMATTING )
									{
										AppendMenu( h_popup, MF_STRING, ID_VOLUMES_FORMAT, IDS_FORMAT );
									} else
									{
										if ( IS_UNMOUNTABLE(&mnt->info.status) )
										{
											AppendMenu( h_popup, MF_STRING, ID_VOLUMES_UNMOUNT, IDS_UNMOUNT );
										}
										if ( !(mnt->info.status.flags & F_SYNC) )
										{
											AppendMenu( h_popup, MF_SEPARATOR, 0, NULL );
											AppendMenu( h_popup, MF_STRING, ID_VOLUMES_CHANGEPASS, IDS_CHPASS );
										}
										if ( !(act && act->status == ACT_RUNNING) )
										{
											if ( mnt->info.status.flags & F_SYNC )
											{
												if ( GetMenuItemCount(h_popup) > 0 )
												{
													AppendMenu( h_popup, MF_SEPARATOR, 0, NULL );
												}
												AppendMenu( h_popup, MF_STRING, ID_VOLUMES_ENCRYPT, IDS_ENCRYPT );
											} else
											{
												if ( GetMenuItemCount(h_popup) > 0 )
												{
													AppendMenu( h_popup, MF_SEPARATOR, 0, NULL );
												}
												AppendMenu( h_popup, MF_STRING, ID_VOLUMES_REENCRYPT, IDS_REENCRYPT );
											}
											AppendMenu( h_popup, MF_STRING, ID_VOLUMES_DECRYPT, IDS_DECRYPT );
										}
									}								
								}
							} else 
							{
								if ( mnt->info.status.flags & F_CDROM )
								{
									if ( *mnt->fs == '\0' )
									{
										AppendMenu( h_popup, MF_STRING, ID_VOLUMES_MOUNT, IDS_MOUNT );
									}
								} else {
									if ( *mnt->fs == '\0' )
									{
										AppendMenu( h_popup, MF_STRING, ID_VOLUMES_MOUNT, IDS_MOUNT );
									} else {
										AppendMenu( h_popup, MF_STRING, ID_VOLUMES_ENCRYPT, IDS_ENCRYPT );
									}
									if ( IS_UNMOUNTABLE(&mnt->info.status) )
									{
										AppendMenu( h_popup, MF_SEPARATOR, 0, NULL );
										AppendMenu( h_popup, MF_STRING, ID_VOLUMES_FORMAT, IDS_FORMAT );
									}
								}
							}
						}
						/*
						_state_menu(
							popup, sel && sel->status.flags & F_LOCKED ? MF_GRAYED : MF_ENABLED
							);
						*/
						item = TrackPopupMenu(
							h_popup,
							TPM_RETURNCMD | TPM_LEFTBUTTON,
							LOWORD(GetMessagePos( )),
							HIWORD(GetMessagePos( )),
							0,
							hwnd,
							NULL
						);

						DestroyMenu( h_popup );
						switch ( item )
						{
							case ID_VOLUMES_DECRYPT		: _menu_decrypt(sel);	break;
							case ID_VOLUMES_ENCRYPT		: _menu_encrypt(sel);	break;

							case ID_VOLUMES_FORMAT		: _menu_format(sel);	break;
							case ID_VOLUMES_REENCRYPT	: _menu_reencrypt(sel);	break;

							case ID_VOLUMES_UNMOUNT		: _menu_unmount(sel);	break;
							case ID_VOLUMES_MOUNT		: _menu_mount(sel);		break;

							case ID_VOLUMES_CHANGEPASS	: _menu_change_pass(sel); break;						
						}
						if ( item )
						{
							_refresh( TRUE );
						}
						_set_timer( MAIN_TIMER, TRUE, TRUE );

					}
					break;

					case NM_CLICK :
					{
						sel = pv(
							_get_item_index( __lists[HMAIN_DRIVES], ((NM_LISTVIEW *)lparam)->iItem )
							);

						_update_info_table( FALSE );
						_activate_page( );
						_refresh_menu( );						
					}
					break;

				}
			}
			if ( ((NMHDR *)lparam)->code == HDN_ITEMCHANGED )
			{
				InvalidateRect( __lists[HMAIN_DRIVES], NULL, TRUE );
			}
			if ( ((NMHDR *)lparam)->code == HDN_ITEMCHANGING )
			{
				return 0L;
			}
			if ( ((NMHDR *)lparam)->code == HDN_BEGINTRACK )
			{
				return 1L;
			}
		}
		break;

		case WM_COMMAND: 
		{
			_dnode *node = pv( _get_sel_item( __lists[HMAIN_DRIVES] ) );

			switch (id) 
			{
			case ID_SHIFT_TAB :
			case ID_TAB :
			{
				HWND h_current = GetFocus( );
				HWND h_next    = GetNextDlgTabItem( hwnd, h_current, id == ID_SHIFT_TAB );

				SetFocus( h_next );
			}
			break;

			case ID_TOOLS_DRIVER :
			{
				if ( __msg_q( __dlg, L"Remove DiskCryptor driver?") )
				{
					int rlt;
					if ( (rlt = _drv_action(DA_REMOVE, 0)) != NO_ERROR )
					{
						__error_s( __dlg, L"Error remove DiskCryptor driver", -rlt );
					} else {
						return 0L;
					}
				}
			}
			break;

			case ID_TOOLS_BENCHMARK : _dlg_benchmark( __dlg ); break;
			case ID_HELP_ABOUT :      _dlg_about( __dlg ); break;
			
			case ID_HOMEPAGE : __execute( DC_HOMEPAGE ); break;			
			case ID_EXIT :
			{
				SendMessage( hwnd, WM_CLOSE, 0, 1 );
			}
			break;

			case IDC_BTN_WIZARD : _menu_wizard(node); break;
			case ID_VOLUMES_DELETE_MNTPOINT :
			{
				wchar_t *mnt_point = node->mnt.info.status.mnt_point;				
				if ( __msg_q( __dlg, L"Are you sure you want to delete mount point [%s]?", mnt_point ) )
				{
					_set_trailing_slash(mnt_point);
					DeleteVolumeMountPoint(mnt_point);
				}
			}
			break;

			case IDC_BTN_DECRYPT_ :
			case ID_VOLUMES_DECRYPT : _menu_decrypt( node ); break;

			case IDC_BTN_ENCRYPT_ :
			case ID_VOLUMES_ENCRYPT : _menu_encrypt( node ); break;

			case ID_VOLUMES_MOUNTALL : 
			case IDC_BTN_MOUNTALL_ : _menu_mountall( ); break;

			case ID_VOLUMES_DISMOUNTALL : 
			case IDC_BTN_UNMOUNTALL_ : _menu_unmountall( ); break;

			case ID_VOLUMES_DISMOUNT : _menu_unmount( node ); break;
			case ID_VOLUMES_MOUNT :    _menu_mount( node ); break;

			case ID_VOLUMES_FORMAT :    _menu_format(node); break;
			case ID_VOLUMES_REENCRYPT : _menu_reencrypt( node ); break;

			case ID_TOOLS_SETTINGS : _dlg_options( __dlg ); break;
			case ID_BOOT_OPTIONS :   _dlg_config_loader( __dlg, FALSE ); break;

			case ID_VOLUMES_CHANGEPASS : _menu_change_pass( node ); break;
			case ID_TOOLS_CLEARCACHE :   _menu_clear_cache( ); break;

			case ID_VOLUMES_BACKUPHEADER :  _menu_backup_header( node ); break;
			case ID_VOLUMES_RESTOREHEADER : _menu_restore_header( node ); break;

			case ID_TOOLS_ENCRYPT_CD: _menu_encrypt_cd( ); break;

			}
			switch ( id ) {
			case IDC_BTN_MOUNT_: 
			{		
				node->mnt.info.status.flags & F_ENABLED ?
					_menu_unmount(node) : 
					_menu_mount(node);
			}
			break;
			case ID_TOOLS_BSOD : 
			{
				if ( __msg_q( __dlg, L"Crash?" ) ) 
				{
					dc_get_bsod( );
				}
			}
			break;
			}
			if ( id == IDCANCEL )
			{
				ShowWindow(hwnd, SW_HIDE);
			}
			_refresh(TRUE);
		}
		break;

		case WM_CLOSE :
		{
			if ( lparam )
			{
				_tray_icon(FALSE);

				EndDialog(hwnd, 0);
				ExitProcess(0);
			} else {
				ShowWindow(hwnd, SW_HIDE);
			}
			return 0L;
		}
		break;

		case WM_DESTROY : 
		{
			PostQuitMessage(0);
			return 0L;
		}
		break;

		case WM_HOTKEY :
		{
			switch (wparam) 
			{
				case 0 : 
				{
					int mount_cnt;
					dc_mount_all(NULL, &mount_cnt, 0); 
				}
				break;

				case 1 : dc_unmount_all( ); break;
				case 2 : dc_device_control(DC_CTL_CLEAR_PASS, NULL, 0, NULL, 0); break;
				case 3 : dc_get_bsod( ); break;
			}
			return 1L;
		}
		break;

		case WM_ENDSESSION : 
		{
			if ( lparam & ENDSESSION_LOGOFF ) 
			{
				if ( __config.conf_flags & CONF_DISMOUNT_LOGOFF ) 
				{
					dc_unmount_all( );
				}
				if ( __config.conf_flags & CONF_WIPEPAS_LOGOFF ) 
				{
					dc_device_control(DC_CTL_CLEAR_PASS, NULL, 0, NULL, 0);
				}
			}
		}
		break;

		case WM_SYSCOLORCHANGE :
		{
			COLORREF cl_light = _cl( COLOR_BTNFACE, LGHT_CLR );
			COLORREF cl_button = GetSysColor( COLOR_BTNFACE );

			int k;
			for ( k = 0; k < countof(__lists); k++ )
			{
				if ( ( __lists[k] != HWND_NULL ) && ( __lists[k] != NULL ) )
				{
					ListView_SetBkColor( __lists[k], cl_button );
					ListView_SetTextBkColor( __lists[k], cl_button );
					ListView_SetExtendedListViewStyle( __lists[k], LVS_EX_FULLROWSELECT );

					if ( !IsWindowEnabled( __lists[k] ) )
					{
						// EnableWindow( __lists[k], TRUE );
						// EnableWindow( __lists[k], FALSE );
					}
				}
			}
			TreeView_SetBkColor( GetDlgItem(hwnd, IDC_TREE), cl_light );

			ListView_SetBkColor( __lists[HMAIN_DRIVES], cl_light );
			ListView_SetTextBkColor( __lists[HMAIN_DRIVES], cl_light );

			ListView_SetExtendedListViewStyle( __lists[HMAIN_DRIVES], LVS_EX_FULLROWSELECT );
			ListView_SetImageList( __lists[HMAIN_DRIVES], __dsk_img, LVSIL_SMALL );

		}
		break;

		case WM_APP + WM_APP_TRAY :
		{
			switch ( lparam ) 
			{
			case WM_LBUTTONDOWN : 
			{
				BOOL show = !IsWindowVisible(hwnd);				
				ShowWindow(hwnd, show ? SW_SHOW : SW_HIDE);

				if ( show )
				{
					SetForegroundWindow(hwnd);
				}
			}
			break;

			case WM_RBUTTONDOWN : 
			{
				POINT pt; int item;
				HMENU menu = CreatePopupMenu( );				

				AppendMenu( menu, MF_STRING, ID_VOLUMES_UNMOUNTALL, IDS_UNMOUNTALL );
				AppendMenu( menu, MF_STRING, ID_VOLUMES_MOUNTALL, IDS_MOUNTALL );
				AppendMenu( menu, MF_SEPARATOR, 0, NULL );

				AppendMenu( menu, MF_STRING, ID_TOOLS_SETTINGS, IDS_SETTINGS );
				AppendMenu( menu, MF_STRING, ID_HELP_ABOUT, IDS_ABOUT );
				AppendMenu( menu, MF_SEPARATOR, 0, NULL );
				AppendMenu( menu, MF_STRING, ID_EXIT, IDS_EXIT );

				GetCursorPos(&pt);
				SetForegroundWindow( hwnd );

				item = TrackPopupMenu ( menu,
					TPM_RETURNCMD | TPM_LEFTALIGN | TPM_BOTTOMALIGN | TPM_RIGHTBUTTON,
					pt.x, pt.y, 0, hwnd,
					NULL
				);

				DestroyMenu( menu );

				switch (item) {

				case ID_VOLUMES_UNMOUNTALL : _menu_unmountall( ); break;
				case ID_VOLUMES_MOUNTALL :   _menu_mountall( ); break;

				case ID_HELP_ABOUT :         _dlg_about( HWND_DESKTOP ); break;
				case ID_TOOLS_SETTINGS :     _dlg_options( __dlg ); break;

				case ID_EXIT : 
				{
					SendMessage(hwnd, WM_CLOSE, 0, 1);
				}
				break;
				}
			}
			break;
			}
		}
		break;

		default:
		{
			int rlt = _draw_proc( message, lparam );
			if (rlt != -1) 
			{
				return rlt;
			}
		}
	}	
	return 0L; 

}

