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
#include "prc_code.h"

#include "rand.h"
#include "cd_enc.h"
#include "threads.h"

#include "dlg_menu.h"
#include "dlg_drives_list.h"

#if (_MSC_VER >= 1300) && _M_IX86
	extern long _ftol(double);
	extern long _ftol2(double dblSource) { return _ftol(dblSource); }
	extern long _ftol2_sse(double dblSource) { return _ftol2(dblSource); }
#endif

INT_PTR CALLBACK
_link_proc(
		HWND   hwnd,
		UINT   message,
		WPARAM wparam,
		LPARAM lparam
	)
{
	WNDPROC old_proc = pv( GetWindowLongPtr(hwnd, GWL_USERDATA) );
	static BOOL over = FALSE;

	switch (message)
	{
		case WM_SETCURSOR : 
		{
			if ( !over )
			{
				TRACKMOUSEEVENT	track = { sizeof(track) };

				track.dwFlags   = TME_LEAVE;
				track.hwndTrack = hwnd;
	
				over = TrackMouseEvent(&track);
				SetCursor( __cur_hand );	
			}
			return 0L;
		}
		break;

		case WM_MOUSELEAVE : 
		{
			over = FALSE;
			SetCursor( __cur_arrow );

			return 0L;
		}
		break;
	}
	return (
		CallWindowProc(
			old_proc, hwnd, message, wparam, lparam
		)
	);
}


INT_PTR CALLBACK
_benchmark_dlg_proc(
		HWND	hwnd,
		UINT	message,
		WPARAM	wparam,
		LPARAM	lparam
	)
{
	switch ( message )
	{
		case WM_CLOSE :
		{
			__lists[HBENCHMARK] = HWND_NULL;

			EndDialog( hwnd, 0 );
			return 0L;
		}
		break;

		case WM_COMMAND :
		{
			int code = HIWORD(wparam);			
			int id = LOWORD(wparam);

			if ( ( id == IDOK ) || ( id == IDCANCEL ) )
			{
				EndDialog( hwnd, 0 );
			}
			if ( id == IDB_REFRESH_TEST )
			{
				HWND h_button = GetDlgItem( hwnd, IDB_REFRESH_TEST );

				SetCursor( __cur_wait );
				EnableWindow( h_button, FALSE );
				{
					bench_item bench[CF_CIPHERS_NUM];

					wchar_t s_speed[50];
					int cnt;

					int lvcount = 0;
					int k = 0;

					cnt  = _benchmark(pv(&bench));
					ListView_DeleteAllItems( __lists[HBENCHMARK] );
						
					for ( k = 0; k < cnt; k++ )
					{
						_list_insert_item( __lists[HBENCHMARK], lvcount, 0, bench[k].alg, 0 );
						_list_set_item( __lists[HBENCHMARK], lvcount, 1, STR_EMPTY );

						_snwprintf( s_speed, countof(s_speed), L"%-.2f mb/s", bench[k].speed );
						_list_set_item( __lists[HBENCHMARK], lvcount++, 2, s_speed );
					}
				}
				EnableWindow( h_button, TRUE );
				SetCursor( __cur_arrow );
			}
		}
		break;

		case WM_INITDIALOG : 
		{
			__lists[HBENCHMARK] = GetDlgItem( hwnd, IDC_LIST_BENCHMARK );
			_init_list_headers( __lists[HBENCHMARK], _benchmark_headers );

			ListView_SetBkColor( __lists[HBENCHMARK], GetSysColor(COLOR_BTNFACE) );
			ListView_SetTextBkColor( __lists[HBENCHMARK], GetSysColor(COLOR_BTNFACE) );
			ListView_SetExtendedListViewStyle( __lists[HBENCHMARK], LVS_EX_FLATSB | LVS_EX_FULLROWSELECT );

			SetForegroundWindow(hwnd);

			_sub_class(GetDlgItem(hwnd, IDC_BUTTON), SUB_STATIC_PROC, HWND_NULL);
			return 1L;
		}
		break;

		case WM_CTLCOLOREDIT :
		{
			return (
				_ctl_color(wparam, _cl(COLOR_BTNFACE, LGHT_CLR))
			);
		}
		break;

		default:
		{
			int rlt = _draw_proc(message, lparam);
			if (rlt != -1)
			{
				return rlt;
			}
		}
	}
	return 0L;

}


INT_PTR CALLBACK
_about_dlg_proc(
		HWND	hwnd,
		UINT	message,
		WPARAM	wparam,
		LPARAM	lparam
	)
{
	_ctl_init ctl_links[ ] = 
	{
		{ DC_HOMEPAGE,  IDC_ABOUT_URL1, 0 },
		{ DC_FORUMPAGE, IDC_ABOUT_URL2, 0 }
	};
	static HICON h_icon;

	switch ( message )
	{
		case WM_DESTROY :
		{
			DestroyIcon(h_icon);
			return 0L;
		}
		break;			

		case WM_CLOSE : 
		{
			EndDialog(hwnd, 0);
			return 0L;
		}
		break;

		case WM_COMMAND : 
		{
			int id   = LOWORD(wparam);
			int code = HIWORD(wparam);
			int k;

			if ( code == EN_SETFOCUS )
			{
				SendMessage( (HWND)lparam, EM_SETSEL, -1, 0 );
			}

			if ( id == IDCANCEL || id == IDOK )
			{
				EndDialog(hwnd, 0);
			}
			for ( k = 0; k < countof(ctl_links); k++ )
			{
				if ( id == ctl_links[k].id )
				{
					__execute(ctl_links[k].display);
				}
			}
		}
		break;

		case WM_SHOWWINDOW :
		{
			SetFocus( GetDlgItem(hwnd, IDC_EDIT_NOTICE) );
			SendMessage( GetDlgItem(hwnd, IDC_EDIT_NOTICE), EM_SETSEL, -1, 0 );
		}
		break;

		case WM_INITDIALOG : 
		{
			HWND    h_notice = GetDlgItem(hwnd, IDC_EDIT_NOTICE);
			wchar_t s_display[MAX_PATH];
			BYTE   *res;
			int     size, id_icon;
			int     k = 0;

			res = _extract_rsrc( IDI_ICON_TRAY, RT_GROUP_ICON, &size );

			id_icon = LookupIconIdFromDirectoryEx( res, TRUE, 48, 48, 0 );
			res = _extract_rsrc( id_icon, RT_ICON, &size );
 
			h_icon = CreateIconFromResourceEx( res, size, TRUE, 0x00030000, 48, 48, 0 );
			SendMessage( GetDlgItem(hwnd, IDC_ICON_MAIN), STM_SETICON, (WPARAM)h_icon, 0 );
			{
				HWND h_title = GetDlgItem( hwnd, IDC_ABOUT1 );

				_snwprintf(
					s_display, countof(s_display), L"%s %S", DC_NAME, DC_FILE_VER
					);

				SetWindowText( h_title, s_display );
				SetWindowText( h_notice,
					L"This program is free software: you can redistribute "
					L"it under the terms of the GNU General Public License "
					L"version 3 as published by the Free Software Foundation.\r\n\r\n"
					L"Contacts:\r\n"
					L"ntldr@diskcryptor.net (PGP key ID 0xC48251EB4F8E4E6E)\r\n\r\n"
					L"Special thanks to:\r\n"
					L"Aleksey Bragin and ReactOS Foundation\r\n\r\n"
					L"Portions of this software:\r\n"
					L"Copyright \xa9 1998, 2001, 2002 Brian Palmer\r\n"
					L"Copyright \xa9 2003, Dr Brian Gladman, Worcester, UK\r\n"
					L"Copyright \xa9 2006, Rik Snel <rsnel@cube.dyndns.org>\r\n"
					L"Copyright \xa9 Vincent Rijmen <vincent.rijmen@esat.kuleuven.ac.be>\r\n"
					L"Copyright \xa9 Antoon Bosselaers <antoon.bosselaers@esat.kuleuven.ac.be>\r\n"
					L"Copyright \xa9 Paulo Barreto <paulo.barreto@terra.com.br>\r\n"
					L"Copyright \xa9 Tom St Denis <tomstdenis@gmail.com>\r\n"
					L"Copyright \xa9 Juergen Schmied and Jon Griffiths\r\n"
					L"Copyright \xa9 Lynn McGuire\r\n"
					L"Copyright \xa9 Matthew Skala <mskala@ansuz.sooke.bc.ca>\r\n"
					L"Copyright \xa9 Werner Koch\r\n"
					L"Copyright \xa9 Dag Arne Osvik <osvik@ii.uib.no>\r\n"
					L"Copyright \xa9 Herbert Valerio Riedel <hvr@gnu.org>\r\n"
					L"Copyright \xa9 Wei Dai\r\n"
					L"Copyright \xa9 Ruben Jesus Garcia Hernandez <ruben@ugr.es>\r\n"
					L"Copyright \xa9 Serge Trusov <serge.trusov@gmail.com>"
				);

				SendMessage( h_title, WM_SETFONT, (WPARAM)__font_bold, 0 );
				for ( k = 0; k < countof(ctl_links); k++ )
				{
					HWND h_ctl = GetDlgItem(hwnd, ctl_links[k].id);

					SetWindowLongPtr( h_ctl, GWL_USERDATA, (LONG_PTR)GetWindowLongPtr( h_ctl, GWL_WNDPROC ) );
					SetWindowLongPtr( h_ctl, GWL_WNDPROC, (LONG_PTR)_link_proc );

					SetWindowText( h_ctl, ctl_links[k].display );
					SendMessage( h_ctl, WM_SETFONT, (WPARAM)__font_link, 0 );
					{
						WINDOWINFO pwi;
						SIZE       size;
						HDC        h_dc = GetDC( h_ctl );

						SelectObject( h_dc, __font_link );
						GetTextExtentPoint32( h_dc, ctl_links[k].display, d32(wcslen(ctl_links[k].display)), &size );

						GetWindowInfo( h_ctl, &pwi );
						ScreenToClient( hwnd, pv(&pwi.rcClient) );

						MoveWindow( h_ctl, pwi.rcClient.left, pwi.rcClient.top, size.cx, size.cy, TRUE );
						ReleaseDC( h_ctl, h_dc );
					}
				}
				{
					DC_FLAGS flags;
					
					if ( dc_device_control(DC_CTL_GET_FLAGS, NULL, 0, &flags, sizeof(flags)) == NO_ERROR )
					{
						wchar_t *s_using = L"Not supported";
						wchar_t *s_inset = L"Not supported";

						if ( flags.load_flags & DST_HW_CRYPTO )
						{
							s_using = (
								flags.conf_flags & CONF_HW_CRYPTO ? L"Enabled" : L"Disabled"
							);
							if ( flags.load_flags & DST_INTEL_NI ) s_inset = L"Intel® AES Instructions Set (AES-NI)";
							if ( flags.load_flags & DST_VIA_PADLOCK ) s_inset = L"The VIA PadLock Advanced Cryptography Engine (ACE)";
						}
						_snwprintf( s_display, countof(s_display), 
							L"Hardware Cryptography: %s\r\n"
							L"Instruction Set: %s",
							s_using, s_inset
						);
						SetWindowText( GetDlgItem(hwnd, IDC_EDIT_CIPHER_INFO), s_display );
						EnableWindow( GetDlgItem(hwnd, IDC_EDIT_CIPHER_INFO), flags.load_flags & DST_HW_CRYPTO );
					}
				}
			}
			SendMessage( h_notice, EM_SCROLLCARET, 0, 0 );
			SetForegroundWindow( hwnd );

			return 1L;
		}
		break;

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


void _dlg_about(
		HWND hwnd
	)
{
	DialogBoxParam(
			NULL,
			MAKEINTRESOURCE( IDD_DIALOG_ABOUT ),
			hwnd,
			pv( _about_dlg_proc ),
			0
	);
}


void _dlg_benchmark(
		HWND hwnd
	)
{
	DialogBoxParam(
			NULL,
			MAKEINTRESOURCE( IDD_DIALOG_BENCHMARK ),
			hwnd,
			pv( _benchmark_dlg_proc ),
			0
	);
}


static BOOL cd_encryption_callback(ULONGLONG isosize, ULONGLONG encsize, PVOID param)
{
	_dnode *node = (_dnode*)param;
	if ( node != NULL )
	{
		HWND h_iso_info = GetDlgItem( node->dlg.h_page, IDC_ISO_PROGRESS );

		wchar_t s_enc_size[MAX_PATH]  = { 0 };
		wchar_t s_ttl_size[MAX_PATH]  = { 0 };

		wchar_t s_done[MAX_PATH]      = { STR_EMPTY };
		wchar_t s_speed[MAX_PATH]     = { STR_EMPTY };
		wchar_t s_percent[MAX_PATH]   = { STR_EMPTY };

		wchar_t s_elapsed[MAX_PATH]   = { STR_EMPTY };
		wchar_t s_estimated[MAX_PATH] = { STR_EMPTY };

		int speed   = _speed_stat_event( s_speed, countof(s_speed), &node->dlg.iso.speed, encsize, TRUE );
		int new_pos = (int)( encsize / ( isosize / PRG_STEP ) );

		if ( speed != 0 )
		{
			_get_time_period( ( ( isosize - encsize ) / 1024 / 1024 ) / speed, s_estimated, TRUE );					
		}
		dc_format_byte_size( s_enc_size, countof(s_enc_size), encsize );
		dc_format_byte_size( s_ttl_size, countof(s_ttl_size), isosize );

		_snwprintf( s_done, countof(s_done), L"%s / %s", s_enc_size, s_ttl_size );

		_get_time_period( node->dlg.iso.speed.t_begin.QuadPart, s_elapsed, FALSE );

		_list_set_item_text( h_iso_info, 0, 1, _wcslwr( s_done ) );
		_list_set_item_text( h_iso_info, 1, 1, _wcslwr( s_speed ) );
		
		_list_set_item_text( h_iso_info, 3, 1, _wcslwr( s_elapsed ) );
		_list_set_item_text( h_iso_info, 4, 1, _wcslwr( s_estimated ) );

		SendMessage(
			GetDlgItem( node->dlg.h_page, IDC_PROGRESS_ISO ), PBM_SETPOS, (WPARAM)new_pos, 0
			);

		_snwprintf(
			s_percent, countof(s_percent), L"%.2f %%", (double)(encsize) / (double)(isosize) * 100 
			);

		SetWindowText( GetDlgItem(node->dlg.h_page, IDC_STATUS_PROGRESS), s_percent);

		return node->dlg.rlt == ST_OK ? TRUE : FALSE;
	}
	return TRUE;	
}


DWORD 
WINAPI 
_thread_enc_iso_proc(
		LPVOID lparam
	)
{
	_dnode *node;
	dc_open_device( );

	if ( (node = pv(lparam)) != NULL )
	{
		node->dlg.rlt = ST_OK;

		node->dlg.rlt = dc_encrypt_iso_image(node->dlg.iso.s_iso_src,
			                                 node->dlg.iso.s_iso_dst,
											 node->dlg.iso.pass,
											 node->dlg.iso.cipher_id,
											 cd_encryption_callback, lparam) == NO_ERROR ? ST_OK : ST_ERROR;
		{
			secure_free( node->dlg.iso.pass );
			SendMessage( GetParent(GetParent(node->dlg.h_page)), WM_CLOSE_DIALOG, 0, 0 );
		}

	}
	//EnterCriticalSection(&crit_sect);
	//LeaveCriticalSection(&crit_sect);

	return 1L;
}


void _activate_page( )
{
	HWND h_tab  = GetDlgItem( __dlg, IDT_INFO );

	_dnode *node = pv( _get_sel_item( __lists[HMAIN_DRIVES] ) );
	_dact  *act  = _create_act_thread( node, -1, -1 );

	if ( ListView_GetSelectedCount( __lists[HMAIN_DRIVES] ) && node && !node->is_root && act )
	{
		NMHDR mhdr = { 0, 0, TCN_SELCHANGE };

		TabCtrl_SetCurSel( h_tab, 1 );
		SendMessage( __dlg, WM_NOTIFY, IDT_INFO, (LPARAM)&mhdr );
	}
}


void _is_breaking_action( )
{
	list_entry *node;
	list_entry *sub;

	int count = 0;
	int k, flag;

	BOOL resume;

	wchar_t s_vol[MAX_PATH] = { 0 };

	for ( k = 0; k < 4; k++ )
	{
		if (k % 2 == 0)
		{
			memset(s_vol, 0, countof(s_vol)); // WTF?
			count = 0;
			resume = FALSE;
		}

		for ( node = __drives.flink;
					node != &__drives;
					node = node->flink 
					)
		{
			_dnode *root = contain_record(node, _dnode, list);
			
			for ( sub = root->root.vols.flink;
						sub != &root->root.vols;
						sub = sub->flink 
					)
			{
				_dnode *mnt = contain_record(sub, _dnode, list);
				switch (k)
				{
					case 0:
					case 1:  flag = F_FORMATTING; break;
					case 2:
					case 3:  flag = F_SYNC; break;
					default: flag = -1; break;
				}
				if (mnt->mnt.info.status.flags & flag)
				{
					if (k % 2 == 0)
					{
						if (s_vol[0] != L'\0') wcscat(s_vol, L", ");
						wcscat(s_vol, mnt->mnt.info.status.mnt_point);

						count++;

					} else {
						if (resume)
						{
							if (k == 1) _menu_format(mnt);
							if (k == 3) _menu_encrypt(mnt);
						}
					}
				}
			}
		}
		if ((k % 2 == 0) && count > 0)
		{
			if (__msg_q(
					__dlg,
					L"%s was suspended for volume%s %s.\n\n"
					L"Continue %s?", 
					k != 0 ? L"Encrypting/decrypting" : L"Formatting",
					count > 1 ? L"s" : STR_NULL, 
					s_vol,
					k != 0 ? L"encrypting" : L"formatting")
					) 
			{
				resume = TRUE;
			}
		}
	}
}


void __stdcall 
_timer_handle(
		HWND     hwnd,
		UINT     msg,
		UINT_PTR id,
		DWORD    tickcount
	)
{
	int j = 0;
	switch ( id - IDC_TIMER )
	{
		case PROC_TIMER :
		{		
			_update_info_table( FALSE );
		}
		break;

		case MAIN_TIMER :
		{
			EnterCriticalSection( &crit_sect );

			_load_diskdrives( hwnd, &__drives, _list_volumes(0) );
			_update_info_table( FALSE );

			_set_timer( PROC_TIMER, IsWindowVisible(__dlg_act_info), FALSE );
			_refresh_menu( );

			LeaveCriticalSection( &crit_sect );
		}
		break;

		case RAND_TIMER : 
		{
			rnd_reseed_now( );
			_tray_icon(TRUE);
		}
		break;

		case POST_TIMER :
		{
			_set_timer( POST_TIMER, FALSE, FALSE );
			_is_breaking_action( );
		}
		break;
	}
}



