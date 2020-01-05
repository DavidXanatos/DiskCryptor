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
#include "hotkeys.h"

BOOL _key_name(
		WPARAM   code,
		UINT     shift,
		wchar_t *text
	)
{
	BOOL     resolve = TRUE;
	wchar_t *key     = NULL;

	text[0] = L'\0';

	if ( shift & MOD_CONTROL ) text += _snwprintf(text, 7, L"Ctrl + ");
	if ( shift & MOD_SHIFT )   text += _snwprintf(text, 8, L"Shift + ");
	if ( shift & MOD_ALT )     text += _snwprintf(text, 6, L"Alt + ");

	if ( code >= 0x30 && code <= 0x5a )
	{
		_snwprintf( text, 1, L"%c", code );

	} else if ( code >= VK_F1 && code <= VK_F24 )
	{
		_snwprintf( text, 3, L"F%d", code - VK_F1 + 1 );

	} else if ( code >= VK_NUMPAD0 && code <= VK_NUMPAD9 )
	{
		_snwprintf( text, 9, L"NumPad %d", code - VK_NUMPAD0 );
	}
	else {
		switch ( code ) {
		case VK_MULTIPLY   : key = L"NumPad *"; break;
		case VK_SUBTRACT   : key = L"NumPad -"; break;
		case VK_DECIMAL    : key = L"NumPad ."; break;
		case VK_DIVIDE     : key = L"NumPad /"; break;
		case VK_ADD        : key = L"NumPad +"; break;

		case VK_OEM_PERIOD : key = L"."; break;
		case VK_OEM_MINUS  : key = L"-"; break;
		case VK_OEM_COMMA  : key = L","; break;
		case VK_OEM_PLUS   : key = L"+"; break;

		case VK_CAPITAL    : key = L"Caps Lock";   break;
		case VK_NUMLOCK    : key = L"Num Lock";    break;
		case VK_SCROLL     : key = L"Scroll Lock"; break;
		case VK_INSERT     : key = L"Insert";      break;
		case VK_DELETE     : key = L"Delete";      break;

		case VK_OEM_1      : key = L";" ; break;
		case VK_OEM_2      : key = L"/" ; break;
		case VK_OEM_3      : key = L"`" ; break;
		case VK_OEM_4      : key = L"[" ; break;
		case VK_OEM_5      : key = L"\\"; break;
		case VK_OEM_6      : key = L"]" ; break;
		case VK_OEM_7      : key = L"'" ; break;
		case VK_OEM_8      : key = L"8" ; break;

		case VK_PAUSE      : key = L"Pause";       break;
		case VK_SPACE      : key = L"Spacebar";    break;
		case VK_PRIOR      : key = L"Page Up";     break;
		case VK_RIGHT      : key = L"Right Arrow"; break;
		case VK_BACK       : key = L"Backspace";   break;
		case VK_HOME       : key = L"Home";        break;
		case VK_LEFT       : key = L"Left Arrow";  break;
		case VK_NEXT       : key = L"Page Down";   break;
		case VK_DOWN       : key = L"Down Arrow";  break;
		case VK_END        : key = L"End";         break;
		case VK_UP         : key = L"Up Arrow";    break;

		case VK_TAB        : key = L"Tab";   break;
		case VK_RETURN     : key = L"Enter"; break;

		case VK_LWIN       : key = L"Left Windows";  break;
		case VK_RWIN       : key = L"Right Windows"; break;
		case VK_APPS       : key = L"Applications key"; break;
		/*
		case 0xFF :
		{
			_snwprintf( text, 1, L"Multimedia Key %d", code );
			return TRUE;
		}
		*/
		default :
		{
			switch ( code )
			{
			case VK_BROWSER_BACK        : key = L"Browser Back";           break;
			case VK_BROWSER_FORWARD     : key = L"Browser Forward";        break;
			case VK_BROWSER_REFRESH     : key = L"Browser Refresh";        break;
			case VK_BROWSER_STOP        : key = L"Browser Stop";           break;
			case VK_BROWSER_SEARCH      : key = L"Browser Search";         break;
			case VK_BROWSER_FAVORITES   : key = L"Browser Favorites";      break;
			case VK_BROWSER_HOME        : key = L"Browser Start and Home"; break;

			case VK_VOLUME_MUTE         : key = L"Volume Mute";      break;
			case VK_VOLUME_DOWN         : key = L"Volume Down";      break;
			case VK_VOLUME_UP           : key = L"Volume Up";        break;
			case VK_MEDIA_NEXT_TRACK    : key = L"Next Track";       break;
			case VK_MEDIA_PREV_TRACK    : key = L"Previous Track";   break;
			case VK_MEDIA_STOP          : key = L"Stop Media";       break;
			case VK_MEDIA_PLAY_PAUSE    : key = L"Play/Pause Media"; break;

			case VK_LAUNCH_MAIL         : key = L"Start Mail";   break;
			case VK_LAUNCH_MEDIA_SELECT : key = L"Select Media"; break;

			case VK_LAUNCH_APP1         : key = L"Start Application 1"; break;
			case VK_LAUNCH_APP2         : key = L"Start Application 2"; break;

			default:
			{
				resolve = FALSE;
				break;
			}
			}
		}
		}
	}	
	if ( key )
	{
		wcscpy( text, key );
	}
	return resolve;

}


char _check_hotkeys(
		HWND  hwnd,
		DWORD hotkeys[ ]
	)
{
	wchar_t display[400];
	wchar_t key[200];
	int     k = 0;
	int     j;	

	for ( ; k < HOTKEYS; k++ ) 
	{
		for ( j = 0; j < HOTKEYS; j++ )
		{
			if ( k != j && hotkeys[k] && hotkeys[k] == hotkeys[j] )
			{
				_key_name( HIWORD(hotkeys[k]), LOWORD(hotkeys[k]), key );
				_snwprintf( display, countof(display), L"Duplicated Hotkey: \"%s\"", key );

				MessageBox( hwnd, display, L"Error", MB_OK | MB_ICONERROR );
				return FALSE;
			}
		}
		if ( hotkeys[k] && !RegisterHotKey( __dlg, k, LOWORD(hotkeys[k]), HIWORD(hotkeys[k]) ) ) 
		{
			_key_name( HIWORD(hotkeys[k]), LOWORD(hotkeys[k]), key );
			return FALSE;
		} else {
			UnregisterHotKey( __dlg, k );
		}
	}

	return TRUE;

}


void _set_hotkeys(
		HWND  hwnd,
		DWORD hotkeys[ ],
		BOOL  check
	)
{
	int k = 0;

	if ( check )
	{
		_check_hotkeys( hwnd, hotkeys );
	}
	for ( ; k < HOTKEYS; k++ ) 
	{
		if ( hotkeys[k] )
		{
			RegisterHotKey(	__dlg, k, LOWORD(hotkeys[k]), HIWORD(hotkeys[k]) );
		}
	}
}


void _unset_hotkeys(
		DWORD hotkeys[ ]
	)
{
	int k = 0;
	for ( ; k < HOTKEYS; k++ ) 
	{
		if ( hotkeys[k] )
		{
			UnregisterHotKey( __dlg, k );
		}
	}
}

