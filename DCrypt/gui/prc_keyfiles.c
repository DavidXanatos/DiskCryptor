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
#include "prc_keyfiles.h"

list_entry __key_files;
list_entry __key_files_new;

_colinfo _keyfiles_headers[ ] = 
{
	{ L"File / Folder Path", 375, LVCFMT_LEFT, FALSE },
	{ STR_NULL }
};


void _init_keyfiles_list( )
{
	_init_list_head(& __key_files );
	_init_list_head(& __key_files_new );
}


_list_key_files *_first_keyfile(int key_list)
{
	list_entry      *head = _KEYFILES_HEAD_(key_list);
	_list_key_files *keyfile;

	if ( _is_list_empty(head) == FALSE )
	{
		keyfile = contain_record(head->flink, _list_key_files, next);
	} else 
	{
		keyfile = NULL;
	}
	return keyfile;
}


_list_key_files *_next_keyfile(
		_list_key_files	*keyfile,
		int				 key_list
	)
{
	_list_key_files *next;

	if ( keyfile->next.flink != _KEYFILES_HEAD_(key_list) )
	{
		next = contain_record( keyfile->next.flink, _list_key_files, next );
	} else 
	{
		next = NULL;
	}	
	return next;
}


void _keyfiles_wipe(
		int key_list
	)
{
	_list_key_files *node, *next;
	if ( next = _first_keyfile(key_list) )
	{
		do 
		{
			node = next;
			next = _next_keyfile( node, key_list );

			_remove_entry_list( &node->next );
			secure_free( node );

		} while ( next != NULL );
	} 
}


int _keyfiles_count(
		int key_list
	)
{
	_list_key_files *node;
	int              count = 0;

	if ( key_list == KEYLIST_NONE )
	{
		return count;
	}
	if ( node = _first_keyfile(key_list) )
	{
		do 
		{
			count++;
			node = _next_keyfile(node, key_list);

		} while ( node != NULL );
	}
	return count;
}


static
void _ui_keys_list_refresh(
		HWND hwnd
	)
{
	HWND h_list = GetDlgItem( hwnd, IDC_LIST_KEYFILES );

	if ( !IsWindowEnabled(h_list) )
	{
		ListView_DeleteAllItems( h_list );

		EnableWindow( h_list, TRUE );
		EnableWindow( GetDlgItem(hwnd, IDB_REMOVE_ITEMS), TRUE );

	} else 
	{
		if ( !ListView_GetItemCount( h_list ) )
		{
			EnableWindow( h_list, FALSE );
			_list_insert_item( h_list, 0, 0, IDS_EMPTY_LIST, 0 );

			EnableWindow( GetDlgItem(hwnd, IDB_REMOVE_ITEM), FALSE );
			EnableWindow( GetDlgItem(hwnd, IDB_REMOVE_ITEMS), FALSE );
		}
	}
}


static
void _ui_embedded(
		HWND hwnd, 
		int  key_list
	)
{
	HWND h_list = GetDlgItem( hwnd, IDC_LIST_KEYFILES );

	EnableWindow( GetDlgItem(hwnd, IDB_ADD_FOLDER), key_list != KEYLIST_EMBEDDED );

	EnableWindow( GetDlgItem(hwnd, IDB_ADD_FILE ), 
			!(key_list == KEYLIST_EMBEDDED && IsWindowEnabled( h_list ) && ListView_GetItemCount( h_list ) > 0)
		);
}


static
void _add_item(
		HWND     h_list,
		wchar_t *s_file
	)
{
	if (_is_duplicated_item(h_list, s_file))
	{
		__msg_i(
			GetParent(h_list), 
			L"%s \"%s\" already exists in keyfiles list", 
			s_file[wcslen(s_file) - 1] == L'\\' ? L"Folder" : L"File", s_file
			);
	} else {
		_list_insert_item(h_list, ListView_GetItemCount(h_list), 0, s_file, 0);
	}
}


static
INT_PTR CALLBACK
_keyfiles_dlg_proc(
		HWND	hwnd,
		UINT	message,
		WPARAM	wparam,
		LPARAM	lparam
	)
{
	static int			key_list;
	static list_entry  *head;

	switch ( message )
	{
		case WM_CLOSE : 
		{
			EndDialog( hwnd, 0 );
			return 0L;
		}
		break;		

		case WM_NOTIFY : 
		{
			if( wparam == IDC_LIST_KEYFILES )
			{
				if ( ((NMHDR *)lparam)->code == LVN_ITEMCHANGED &&
					 (((NMLISTVIEW *)lparam)->uNewState & LVIS_FOCUSED ) )
				{
					HWND h_list = GetDlgItem( hwnd, IDC_LIST_KEYFILES );

					EnableWindow(GetDlgItem( hwnd, IDB_REMOVE_ITEM), ListView_GetSelectedCount( h_list ) );

					return 1L;
				}
				if ( ((NM_LISTVIEW *)lparam)->hdr.code == NM_CLICK )
				{
					HWND h_list = GetDlgItem( hwnd, IDC_LIST_KEYFILES );

					EnableWindow( GetDlgItem( hwnd, IDB_REMOVE_ITEM), ListView_GetSelectedCount( h_list ) );
				}
			}
		}
		case WM_COMMAND :
		{
			HWND h_list = GetDlgItem( hwnd, IDC_LIST_KEYFILES );

			int code = HIWORD(wparam);
			int id   = LOWORD(wparam);

			switch ( id )
			{
				case IDB_GENERATE_KEYFILE :
				{
					wchar_t s_file[MAX_PATH] = { L"keyfile" };

					byte keyfile[64];
					int rlt;					

					if ( _save_file_dialog(
							hwnd, s_file, countof(s_file), L"Save 64 bytes random keyfile as.."
						) )
					{
						rlt = dc_device_control(DC_CTL_GET_RAND, NULL, 0, keyfile, sizeof(keyfile)) == NO_ERROR ? ST_OK : ST_ERROR;

						if ( rlt == ST_OK ) 
						{
							rlt = save_file(s_file, keyfile, sizeof(keyfile));
							burn(keyfile, sizeof(keyfile));
						}
						if ( rlt == ST_OK )
						{							
							if ( __msg_q(hwnd, 
								L"Keyfile \"%s\" successfully created\n\n"
								L"Add this file to the keyfiles list?", 
								s_file
								)	)
							{
								_ui_keys_list_refresh(hwnd);

								if ( key_list == KEYLIST_EMBEDDED ) 
								{
									ListView_DeleteAllItems( h_list );
								}
								_add_item( h_list, s_file );

								_ui_embedded( hwnd, key_list );
							}							
						} else {
							__error_s( hwnd, L"Error creating Keyfile", rlt );
						}
					}
				}
				break;
				case IDB_REMOVE_ITEM :
				{					
					ListView_DeleteItem( h_list, ListView_GetSelectionMark(h_list) );

					_ui_keys_list_refresh( hwnd );
					_ui_embedded( hwnd, key_list );
				}
				break;
				case IDB_REMOVE_ITEMS :
				{
					ListView_DeleteAllItems( h_list );

					_ui_keys_list_refresh( hwnd );
					_ui_embedded( hwnd, key_list );
				}
				break;
				case IDB_ADD_FOLDER :
				{
					wchar_t path[MAX_PATH];
					if ( _folder_choice(hwnd, path, L"Choice folder..") )
					{
						_ui_keys_list_refresh( hwnd );

						_set_trailing_slash( path );
						_add_item( h_list, path );
					}
				}
				break;
				case IDB_ADD_FILE :
				{
					wchar_t s_path[MAX_PATH] = { 0 };
					if ( _open_file_dialog(hwnd, s_path, countof(s_path), L"Select File..") )
					{					
						if ( key_list == KEYLIST_EMBEDDED )
						{
							HWND h_file = 
								CreateFile(
									s_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL
									);

							if ( h_file != INVALID_HANDLE_VALUE )
							{
								if ( GetFileSize( h_file, NULL ) != 64 )
								{
									__error_s( hwnd, L"Embedded keyfile must be 64 byte size", ST_ERROR );
								} else 
								{
									_ui_keys_list_refresh( hwnd );
									_add_item( h_list, s_path );
								}
								CloseHandle( h_file );
							}
							_ui_embedded( hwnd, key_list );
						} else 
						{
							_ui_keys_list_refresh( hwnd );
							_add_item( h_list, s_path );
						}
					}
				}
				break;
			}
			if ( id == IDCANCEL )
			{
				EndDialog(hwnd, 0);
			}
			if ( id == IDOK )
			{
				int k = 0;

				_keyfiles_wipe(key_list);

				for ( ; k < ListView_GetItemCount( h_list ); k ++ )
				{
					wchar_t item[MAX_PATH];
					_get_item_text( h_list, k, 0, item, countof(item) );

					if ( wcscmp(item, IDS_EMPTY_LIST) != 0 )
					{
						_list_key_files *new_node;

						if ( (new_node = secure_alloc(sizeof(_list_key_files))) == NULL )
						{
							__error_s( hwnd, L"Can't allocate memory", ST_NOMEM );
							_keyfiles_wipe(key_list);
							break;
						}
						wcsncpy(new_node->path, item, countof(new_node->path));
						_insert_tail_list(head, &new_node->next);
					}
				}
				EndDialog(hwnd, 0);

			}
		}
		break;
		case WM_INITDIALOG : 
		{
			HWND h_list = GetDlgItem(hwnd, IDC_LIST_KEYFILES);
			
			_list_key_files *key_file;

			key_list = (int)lparam;
			head     = _KEYFILES_HEAD_( key_list );

			_init_list_headers( h_list, _keyfiles_headers );

			if ( key_file = _first_keyfile( key_list ) )
			{
				EnableWindow( GetDlgItem(hwnd, IDB_REMOVE_ITEMS), TRUE );
				do 
				{
					_list_insert_item( h_list, ListView_GetItemCount(h_list), 0, key_file->path, 0 );
					key_file = _next_keyfile( key_file, key_list );

				} while ( key_file != NULL );
			} 

			_ui_keys_list_refresh( hwnd );
			_ui_embedded( hwnd, key_list );

			ListView_SetBkColor( h_list, GetSysColor(COLOR_BTNFACE) );
			ListView_SetTextBkColor( h_list, GetSysColor(COLOR_BTNFACE) );
			ListView_SetExtendedListViewStyle( h_list, LVS_EX_FLATSB | LVS_EX_FULLROWSELECT );

			SetForegroundWindow(hwnd);
			return 1L;
		}
		break;
		case WM_CTLCOLOREDIT :
		{
			return _ctl_color(wparam, _cl(COLOR_BTNFACE, LGHT_CLR));
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


void _dlg_keyfiles(
		HWND hwnd,
		int  key_list
	)
{
	DialogBoxParam(
			NULL,
			MAKEINTRESOURCE(IDD_DIALOG_KEYFILES),
			hwnd,
			pv(_keyfiles_dlg_proc),
			key_list
	);
}





