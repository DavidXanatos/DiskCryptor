/*  *
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
#include <shlwapi.h>

#include "main.h"
#include "prc_common.h"

#include "prc_keyfiles.h"
#include "prc_wizard_boot.h"
#include "dlg_menu.h"
#include "pass.h"
#include "threads.h"
#include "dlg_drives_list.h"

INT_PTR
CALLBACK
_tab_proc(
		HWND   hwnd,
		UINT   message,
		WPARAM wparam,
		LPARAM lparam
	)
{
	WORD code = HIWORD(wparam);
	WORD id   = LOWORD(wparam);
	HDC dc;

	wchar_t tmpb[MAX_PATH];
	int k;

	switch ( message )
	{
		case WM_NOTIFY:
		{
			if ( wparam == IDT_BOOT_TAB )
			{
				if ( ((NMHDR *)lparam)->code == TCN_SELCHANGE )
				{
					HWND h_tab = GetDlgItem(hwnd, IDT_BOOT_TAB);

					if ( !_is_curr_in_group(h_tab) )
					{
						_change_page(h_tab, TabCtrl_GetCurSel(h_tab));
					}
				}
			}
			if ( wparam == IDC_WZD_BOOT_DEVS )
			{
				NM_LISTVIEW	*msg_info = pv(lparam);
				NMHDR		*msg_hdr  = pv(lparam);

				if ( msg_hdr->code == LVN_ITEMACTIVATE )
				{
					_get_item_text( __lists[HBOT_WIZARD_BOOT_DEVS], msg_info->iItem, 2, tmpb, countof(tmpb) );

					if ( wcscmp(tmpb, L"installed") == 0 )
					{
						SendMessage( GetParent(GetParent(hwnd)), WM_COMMAND, MAKELONG(IDC_BTN_CHANGE_CONF, 0), 0 );
					} else 
					{
						wchar_t vol[MAX_PATH];

						int dsk_num;

						int type = _get_combo_val( GetDlgItem(hwnd, IDC_COMBO_LOADER_TYPE), loader_type );
						int is_small = _get_check( hwnd, IDC_USE_SMALL_BOOT );

						_get_item_text( __lists[HBOT_WIZARD_BOOT_DEVS], msg_info->iItem, 0, vol, countof(vol) );
						dsk_num = _ext_disk_num( __lists[HBOT_WIZARD_BOOT_DEVS] );

						_menu_set_loader_vol( hwnd, vol, dsk_num, type, is_small );

						_list_devices( __lists[HBOT_WIZARD_BOOT_DEVS], type == CTL_LDR_MBR, -1 );
						_refresh_boot_buttons( hwnd, msg_hdr->hwndFrom, msg_info->iItem );

					}
				}
				if ( ( msg_hdr->code == LVN_ITEMCHANGED ) && ( msg_info->uNewState & LVIS_FOCUSED ) )
				{
					_refresh_boot_buttons( hwnd, msg_hdr->hwndFrom, msg_info->iItem );
					return 1L;
				}
				if ( msg_hdr->code == NM_CLICK )
				{
					_refresh_boot_buttons( hwnd, msg_hdr->hwndFrom, msg_info->iItem );
					return 1L;
				}					
				if ( msg_hdr->code == NM_RCLICK )
				{
					HMENU popup       = CreatePopupMenu( );
					BOOL  item_update = FALSE;

					int type     = _get_combo_val( GetDlgItem(hwnd, IDC_COMBO_LOADER_TYPE), loader_type );
					int is_small = _get_check( hwnd, IDC_USE_SMALL_BOOT );

					ldr_config conf;

					int dsk_num = -1;
					int item;					

					wchar_t vol[MAX_PATH];					

					_get_item_text( __lists[HBOT_WIZARD_BOOT_DEVS], msg_info->iItem, 0, vol, countof(vol) );
					dsk_num = _ext_disk_num( __lists[HBOT_WIZARD_BOOT_DEVS] );

					if ( ListView_GetSelectedCount( __lists[HBOT_WIZARD_BOOT_DEVS] ) )
					{
						_get_item_text( __lists[HBOT_WIZARD_BOOT_DEVS], msg_info->iItem, 2, tmpb, countof(tmpb) );

						if ( !wcscmp(tmpb, L"installed") )
						{
							AppendMenu(popup, MF_STRING, ID_BOOT_REMOVE, IDS_BOOTREMOVE);

							if ( !type )
							{
								item_update = 
									dc_get_mbr_config( dsk_num, NULL, &conf ) == ST_OK && 
									conf.ldr_ver < DC_BOOT_VER;
								
								if ( item_update )
								{
									AppendMenu(popup, MF_STRING, ID_BOOT_UPDATE, IDS_BOOTUPDATE);
								}
								AppendMenu(popup, MF_SEPARATOR, 0, NULL);	
							}
							AppendMenu(popup, MF_STRING, ID_BOOT_CHANGE_CONFIG, IDS_BOOTCHANGECGF);
						} else {
							AppendMenu(popup, MF_STRING, ID_BOOT_INSTALL, IDS_BOOTINSTALL);
						}
					}
					item = TrackPopupMenu(
							popup,
							TPM_RETURNCMD | TPM_LEFTBUTTON,
							LOWORD(GetMessagePos( )),
							HIWORD(GetMessagePos( )),
							0,
							hwnd,
							NULL
						);

					DestroyMenu( popup );
					switch ( item )
					{
						case ID_BOOT_INSTALL: _menu_set_loader_vol( hwnd, vol, dsk_num, type, is_small ); break;
						case ID_BOOT_REMOVE:  _menu_unset_loader_mbr(hwnd, vol, dsk_num, type ); break;

						case ID_BOOT_UPDATE: _menu_update_loader( hwnd, vol, dsk_num ); break;
						case ID_BOOT_CHANGE_CONFIG: 
						{
							SendMessage(GetParent(GetParent(hwnd)), WM_COMMAND, MAKELONG(IDC_BTN_CHANGE_CONF, 0), 0);
						}
						break;
					}
					if ( ( item == ID_BOOT_INSTALL ) || ( item == ID_BOOT_REMOVE ) )
					{
						_list_devices( __lists[HBOT_WIZARD_BOOT_DEVS], type == CTL_LDR_MBR, -1 );
						_refresh_boot_buttons( hwnd, msg_hdr->hwndFrom, msg_info->iItem );
					}
				}
			}
		}
		break;
		case WM_USER_CLICK : 
		{
			HWND ctl_wnd = (HWND)wparam;
			if ( ctl_wnd == GetDlgItem(hwnd, IDC_AUTO_START) )
			{
				BOOL enable = _get_check(hwnd, IDC_AUTO_START);
				EnableWindow(GetDlgItem(hwnd, IDC_WIPE_LOGOFF), enable);
				EnableWindow(GetDlgItem(hwnd, IDC_UNMOUNT_LOGOFF), enable);

				InvalidateRect(GetDlgItem(hwnd, IDC_WIPE_LOGOFF), NULL, TRUE);
				InvalidateRect(GetDlgItem(hwnd, IDC_UNMOUNT_LOGOFF), NULL, TRUE);

				if ( !enable )
				{
					_set_check(hwnd, IDC_WIPE_LOGOFF, enable);
					_set_check(hwnd, IDC_UNMOUNT_LOGOFF, enable);
				}
				return 1L;
			}
			if ( ctl_wnd == GetDlgItem(hwnd, IDC_BT_ENTER_PASS_MSG) )
			{
				EnableWindow(GetDlgItem(hwnd, IDE_RICH_BOOTMSG), _get_check(hwnd, IDC_BT_ENTER_PASS_MSG));
				return 1L;
			}
			if ( ctl_wnd == GetDlgItem(hwnd, IDC_BT_BAD_PASS_MSG) )
			{
				EnableWindow(GetDlgItem(hwnd, IDE_RICH_ERRPASS_MSG), _get_check(hwnd, IDC_BT_BAD_PASS_MSG));
				return 1L;
			}
			if ( ctl_wnd == GetDlgItem(hwnd, IDC_CHECK_SHOW) )
			{
				int mask = _get_check(hwnd, IDC_CHECK_SHOW) ? 0 : '*';

				SendMessage(
					GetDlgItem(hwnd, IDE_PASS), EM_SETPASSWORDCHAR,	mask, 0
				);
				SendMessage(
					GetDlgItem(hwnd, IDE_CONFIRM), EM_SETPASSWORDCHAR,	mask, 0
				);
				InvalidateRect(GetDlgItem(hwnd, IDE_PASS), NULL, TRUE);
				InvalidateRect(GetDlgItem(hwnd, IDE_CONFIRM), NULL, TRUE);
				return 1L;
			}
			if ( ctl_wnd == GetDlgItem(hwnd, IDC_USE_KEYFILES) )
			{
				SendMessage(
					hwnd, WM_COMMAND, MAKELONG(IDE_PASS, EN_CHANGE), (LPARAM)GetDlgItem(hwnd, IDE_PASS)
					);

				EnableWindow(GetDlgItem(hwnd, IDB_USE_KEYFILES), _get_check(hwnd, IDC_USE_KEYFILES));
				return 1L;
			}
			{
				_wnd_data *data = wnd_get_long(ctl_wnd, GWL_USERDATA);

				k = 0;
				while ( hotks_chk[k].id != -1 )
				{
					if( ctl_wnd == GetDlgItem(hwnd, hotks_chk[k].id) )
					{
						EnableWindow(GetDlgItem(hwnd, hotks_edit[k].id), data->state);
						EnableWindow(GetDlgItem(hwnd, hotks_static[k].id), data->state);
						SetFocus(GetDlgItem(hwnd, hotks_edit[k].id));

						return 1L;												
					}
					k++;
				}
			}
		}
		break;

		case WM_COMMAND : 
		{
			_dnode	*node = pv( _get_sel_item( __lists[HMAIN_DRIVES] ) );
			_dact	*act  = _create_act_thread( node, -1, -1 );

			switch (id)
			{
				case IDB_USE_KEYFILES :
				{
					wchar_t text[MAX_PATH];
					int     keylist;

					GetWindowText( GetDlgItem(hwnd, IDC_USE_KEYFILES), text, countof(text) );
					keylist = wcscmp(text, IDS_USE_KEYFILE) == 0 ? KEYLIST_EMBEDDED : KEYLIST_CURRENT;

					_dlg_keyfiles( hwnd, keylist );

					SendMessage(
						hwnd, WM_COMMAND, MAKELONG(IDE_PASS, EN_CHANGE), (LPARAM)GetDlgItem(hwnd, IDE_PASS)
						);

				}
				break;

				case IDB_BOOT_PREF :
				{
					_dlg_config_loader( hwnd, TRUE );
				}
				break;

				case IDB_BT_CONF_EMB_KEY : 
				{
					_dlg_keyfiles( hwnd, KEYLIST_EMBEDDED );
				}
				break;

				case IDB_ACT_PAUSE :
				{
					if ( node )
					{	
						if (act->status == ACT_RUNNING) 
						{
							act->status	= act->act != ACT_FORMAT ? ACT_PAUSED : ACT_STOPPED;
							act->act	= ACT_ENCRYPT;
						}
					}
					_refresh(TRUE);
				}
				break;

				case IDB_BOOT_PATH :
				{
					int boot_type = _get_combo_val( GetDlgItem(hwnd, IDC_COMBO_LOADER_TYPE), loader_type );

					wchar_t s_file[MAX_PATH];					
					wcscpy( s_file, boot_type == CTL_LDR_ISO ? L"loader.iso" : L"loader.img" );

					if ( _save_file_dialog(hwnd, s_file, countof(s_file), L"Save Bootloader File As") ) 
					{
						SetWindowText( GetDlgItem(hwnd, IDE_BOOT_PATH), s_file );
					}
				}
				break;

				case IDB_ISO_OPEN_SRC :
				{
					wchar_t s_file[MAX_PATH] = { 0 };

					if ( _open_file_dialog(hwnd, s_file, countof(s_file), L"Open iso-file to encrypt") ) 
					{
						SetWindowText(GetDlgItem(hwnd, IDE_ISO_SRC_PATH), s_file);
					}
				}
				break;

				case IDB_ISO_OPEN_DST :
				{
					wchar_t  s_dst_file[MAX_PATH] = { L"encrypted." };
					wchar_t  s_src_file[MAX_PATH] = { 0 };

					wchar_t *s_name;

					GetWindowText( GetDlgItem(hwnd, IDE_ISO_SRC_PATH), s_src_file, countof(s_src_file ));

					s_name = _extract_name(s_src_file);
					wcsncat(s_dst_file, (s_name != NULL) ? s_name : L"iso", countof(s_dst_file) - wcslen(s_src_file));

					if ( _save_file_dialog(hwnd, s_dst_file, countof(s_dst_file), L"Save encrypted iso-file to...") ) 
					{						
						SetWindowText(GetDlgItem(hwnd, IDE_ISO_DST_PATH), s_dst_file);
					}
				}
				break;
			}

			switch (code) 
			{
				case CBN_SELCHANGE :
				{
					switch ( id )
					{
						case IDC_COMBO_AUTH_TYPE :
						{
							BOOL b_pass   = _get_combo_val( (HWND)lparam, auth_type ) & LDR_LT_GET_PASS;
							BOOL b_keyfie = _get_combo_val( (HWND)lparam, auth_type ) & LDR_LT_EMBED_KEY;

							_enb_but_this( hwnd, IDC_COMBO_AUTH_TYPE, b_pass );

							EnableWindow( GetDlgItem(hwnd, IDC_STATIC_AUTH_TYPE), TRUE );
							EnableWindow( GetDlgItem(hwnd, IDC_CNT_BOOTMSG), FALSE );

							EnableWindow( GetDlgItem(hwnd, IDB_BT_CONF_EMB_PASS), b_keyfie );

							if ( b_pass )
							{
								EnableWindow(
									GetDlgItem(hwnd, IDE_RICH_BOOTMSG), _get_check(hwnd, IDC_BT_ENTER_PASS_MSG)
									);
								EnableWindow(
									GetDlgItem(hwnd, IDC_BT_CANCEL_TMOUT), (BOOL)SendMessage(GetDlgItem(hwnd, IDC_COMBO_AUTH_TMOUT), CB_GETCURSEL, 0, 0)
									);
							}
						}
						break;

						case IDC_COMBO_AUTH_TMOUT :
						{						
							EnableWindow(
								GetDlgItem(hwnd, IDC_BT_CANCEL_TMOUT), (BOOL)SendMessage((HWND)lparam, CB_GETCURSEL, 0, 0)
								);

							InvalidateRect( GetDlgItem(hwnd, IDC_BT_CANCEL_TMOUT), NULL, TRUE );

						}
						break;

						case IDC_COMBO_METHOD :
						{
							wchar_t text[MAX_PATH];
							BOOL enable;

							_get_item_text( __lists[HBOT_PART_LIST_BY_ID], 0, 0, text, countof(text) );
							enable = _get_combo_val((HWND)lparam, boot_type_ext) == LDR_BT_DISK_ID && !wcsstr(text, L"not found");

							EnableWindow( GetDlgItem(hwnd, IDC_STATIC_SELECT_PART), enable );
							EnableWindow( __lists[HBOT_PART_LIST_BY_ID], enable );

						}
						break;

						case IDC_COMBO_LOADER_TYPE : 
						{
							int k;
							int ctl_enb[ ] =
							{
								IDC_HEAD_BOOT_DEV, IDC_WZD_BOOT_DEVS,
								IDC_HEAD_BOOT_FILE, IDE_BOOT_PATH, IDB_BOOT_PATH
							};

							int type = (int)SendMessage( GetDlgItem(hwnd, IDC_COMBO_LOADER_TYPE), CB_GETCURSEL, 0, 0 );
							for ( k = 0; k < countof(ctl_enb); k++ )
							{
								EnableWindow(
									GetDlgItem( hwnd, ctl_enb[k] ), ( type < 2 && k < 2 ) || ( type > 1 && k > 1 )
									);
							}
							if ( type < 2 ) 
							{
								_list_devices( __lists[HBOT_WIZARD_BOOT_DEVS], !type, -1 );
							}
							SetWindowText(
								GetDlgItem(GetParent(GetParent(hwnd)), IDC_BTN_INSTALL), type > 1 ? IDS_BOOTCREATE : IDS_BOOTINSTALL
								);

							EnableWindow( GetDlgItem(GetParent(GetParent(hwnd)), IDC_BTN_INSTALL), FALSE );

							SetWindowText( GetDlgItem(hwnd, IDE_BOOT_PATH), STR_NULL );
							SetFocus( GetDlgItem(hwnd, IDE_BOOT_PATH) );

						}
						break;

						case IDC_COMBO_BOOT_INST :
						{
							BOOL ext_loader = SendMessage((HWND)lparam, CB_GETCURSEL, 0, 0) == 0;

							EnableWindow( GetDlgItem(hwnd, IDC_USE_SMALL_BOOT), !ext_loader );
							EnableWindow( GetDlgItem(hwnd, IDB_BOOT_PREF), ext_loader );
						}
						break;

						case IDC_COMBO_KBLAYOUT :
						{
							SendMessage( hwnd, WM_COMMAND, MAKELONG(IDE_PASS, EN_CHANGE), lparam );
						}
						break;

						case IDC_COMBO_PASSES : 
						{
							_dact *act = _create_act_thread(node, -1, -1);
							if ( act )
							{
								act->wp_mode = (int)(SendMessage((HWND)lparam, CB_GETCURSEL, 0, 0));
							}
						}
						break;
					}
				}
				break;

				case EN_CHANGE : 
				{
					switch (id)
					{
						case IDE_RICH_BOOTMSG : //#
						{	
							char s_msg[MAX_PATH];
							char s_count[MAX_PATH];

							GetWindowTextA( (HWND)lparam, s_msg, sizeof(s_msg) );

							_snprintf( s_count, sizeof(s_count), "%d / %d", strlen(s_msg), 0 );
							SetWindowTextA( GetDlgItem(hwnd, IDC_CNT_BOOTMSG), s_count );
					
						}
						break;

						case IDE_RICH_ERRPASS_MSG :
						{

						}
						break;

						case IDE_ISO_SRC_PATH :
						case IDE_ISO_DST_PATH :
						{
							HWND h_wiz_parent = GetParent(GetParent(hwnd));
							HWND h_ctl_parent = GetParent((HWND)lparam);
							
							wchar_t s_src_path[MAX_PATH] = { 0 };
							wchar_t s_dst_path[MAX_PATH] = { 0 };

							if ( h_wiz_parent != NULL && h_ctl_parent != NULL )
							{
								GetWindowText( GetDlgItem(h_ctl_parent, IDE_ISO_SRC_PATH), s_src_path, countof(s_src_path) );
								GetWindowText( GetDlgItem(h_ctl_parent, IDE_ISO_DST_PATH), s_dst_path, countof(s_dst_path) );

								EnableWindow(
									GetDlgItem(h_wiz_parent, IDOK), ( PathFileExists(s_src_path) && (s_dst_path[0] != 0) )
									);
							}					
						}
						break;

						case IDE_BOOT_PATH :
						{
							wchar_t s_path[MAX_PATH] = { 0 };
							GetWindowText( (HWND)lparam, s_path, countof(s_path) );

							EnableWindow( GetDlgItem(GetParent(GetParent(hwnd)), IDC_BTN_INSTALL), s_path[0] != 0 );
							EnableWindow( GetDlgItem(GetParent(GetParent(hwnd)), IDC_BTN_CHANGE_CONF), PathFileExists(s_path) );
						}
						break;

						case IDE_PASS :
						case IDE_CONFIRM :
						{
							BOOL correct;

							int kb_layout = -1;
							int idx_status;
							int entropy;

							dc_pass *pass;

							if (IsWindowEnabled(GetDlgItem(hwnd, IDC_COMBO_KBLAYOUT))) 
							{
								kb_layout = _get_combo_val(GetDlgItem(hwnd, IDC_COMBO_KBLAYOUT), kb_layouts);
							}			
							pass = _get_pass(hwnd, IDE_PASS);

							_draw_pass_rating(hwnd, pass, kb_layout, &entropy);
							secure_free(pass);

							SendMessage(
									GetDlgItem(hwnd, IDP_BREAKABLE),
									PBM_SETPOS,
									(WPARAM)entropy, 0
								);						

							if ( IsWindowVisible(GetDlgItem(hwnd, IDE_PASS)) )
							{
								dc_pass *pass   = _get_pass(hwnd, IDE_PASS);
								dc_pass *verify = _get_pass(hwnd, IDE_CONFIRM);
	
								int keylist = _get_check( hwnd, IDC_USE_KEYFILES ) ? KEYLIST_CURRENT : KEYLIST_NONE;

								correct = _input_verify( pass, verify, keylist, kb_layout, &idx_status );
						
								secure_free( pass );
								secure_free( verify );

								SetWindowText( GetDlgItem(hwnd, IDC_PASS_STATUS), _get_text_name(idx_status, pass_status) );
								EnableWindow( GetDlgItem(GetParent(GetParent(hwnd)), IDOK), correct );
							}
							return 1L;	
						}
						break;
					} // switch id
				} // case en_change
				break;
			}
		}
		break;

		case WM_CTLCOLOREDIT :
		case WM_CTLCOLORSTATIC :
		case WM_CTLCOLORLISTBOX : 
		{
			COLORREF bgcolor, fn = 0;
		
			dc = (HDC)wparam;
			SetBkMode(dc, TRANSPARENT);

			if ( WM_CTLCOLORSTATIC == message )
			{
				k = 0;
				while ( pass_gr_ctls[k].id != -1 )
				{
					if ( pass_gr_ctls[k].hwnd == (HWND)lparam )
					{
						fn = pass_gr_ctls[k].color;
					}
					if ( pass_pe_ctls[k].hwnd == (HWND)lparam )
					{
						fn = pass_pe_ctls[k].color;
					}
					k++;
				}
				SetTextColor(dc, fn);
				bgcolor = GetSysColor(COLOR_BTNFACE);

			} else bgcolor = _cl(COLOR_BTNFACE, LGHT_CLR);

			SetDCBrushColor(dc, bgcolor);
			return (INT_PTR)GetStockObject(DC_BRUSH);
		
		}
		break;
		/*
		case WM_KEYDOWN: 
		{
			if (wparam == VK_TAB) 
			{
				HWND edit = GetDlgItem(hwnd, IDE_PASS);
				if (edit && (GetFocus( ) == edit)) 
				{
					SetFocus(GetDlgItem(hwnd, IDE_NEW_PASS));
				}
			}
		}
		break;
		*/
		default:
		{
			int rlt = _draw_proc( message, lparam );
			if ( rlt != -1 )
			{
				return rlt;
			}
		}
	}
	return 0L;

}

