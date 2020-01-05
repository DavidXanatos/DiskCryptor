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
#include <math.h>

#include "main.h"
#include "pass.h"

#include "prc_keyfiles.h"
#include "keyfiles.h"

static void _check_password(dc_pass *pass, _pass_inf *inf)
{
	wchar_t c;
	int     flags = 0;
	int     chars = 0;
	int     i, len;

	len = pass->size / sizeof(wchar_t);
	
	for ( i = 0; i < len; i++ )
	{
		c = pass->pass[i];
		do
		{
			if ( (c >= L'a') && (c <= L'z') ) {
				flags |= P_AZ_L; break;
			}
			if ( (c >= L'A') && (c <= L'Z') ) {
				flags |= P_AZ_H; break;
			}
			if ( (c >= L'0') && (c <= L'9') ) {
				flags |= P_09; break;
			}
			if (c == L' ') {
				flags |= P_SPACE; break;
			}
			if ( ((c >= L'!') && (c <= L'/')) ||
				 ((c >= L':') && (c <= L'@')) ||
				 ((c >= L'[') && (c <= L'`')) ||
				 ((c >= L'{') && (c <= L'~')) ||
				 ((c >= L'‘') && (c <= L'—')) ||				 
				 (c == L'‚') || (c == L'„') || (c == L'…') || 
				 (c == L'‹') || (c == L'›') || (c == L'¦') ) 
			{
				flags |= P_SPCH; break;
			} else {
				flags |= P_NCHAR;
			}
		} while (0);
	}

	if (flags & P_09) {
		chars += '9' - '0' + 1;
	}
	if (flags & P_AZ_L) {
		chars += 'z' - 'a' + 1;
	}
	if (flags & P_AZ_H) {
		chars += 'Z' - 'A' + 1;
	}
	if (flags & P_SPACE) {
		chars++;
	}
	if (flags & P_SPCH) {
		chars += ('/' - '!') + ('@' - ':') + ('`' - '[') + ('~' - '{') + ('—' - '‘') + 6;
	}
	if (flags & P_NCHAR) {
		chars += 64;
	}	
	inf->flags   = flags;
	inf->entropy = len * log(chars) / log(2);
	inf->length  = len;
}


void _draw_pass_rating(
		HWND     hwnd,
		dc_pass *pass,
		int      kb_layout,
		int     *entropy
	)
{
	int k = 0;
	int idx = -1;

	_pass_inf inf;			
	_check_password(pass, &inf);

	while ( pass_gr_ctls[k].id != -1 )
	{	
		pass_gr_ctls[k].hwnd = GetDlgItem( hwnd, pass_gr_ctls[k].id );
		pass_pe_ctls[k].hwnd = GetDlgItem( hwnd, pass_pe_ctls[k].id );

		pass_gr_ctls[k].color = 		
		pass_pe_ctls[k].color = _cl(COLOR_BTNFACE, 70);

		k++;		
	};

	if ( inf.flags & P_AZ_L  ) pass_gr_ctls[0].color = CL_BLUE;
	if ( inf.flags & P_AZ_H  ) pass_gr_ctls[1].color = CL_BLUE;
	if ( inf.flags & P_09    ) pass_gr_ctls[2].color = CL_BLUE;
	if ( inf.flags & P_SPACE ) pass_gr_ctls[3].color = CL_BLUE;
	if ( inf.flags & P_SPCH  ) pass_gr_ctls[4].color = CL_BLUE;
	if ( inf.flags & P_NCHAR ) pass_gr_ctls[5].color = CL_BLUE;

	if ( kb_layout != -1 )
	{
		pass_gr_ctls[5].color = GetSysColor(COLOR_GRAYTEXT);
		if ( kb_layout != LDR_KB_QWERTY )
		{
			pass_gr_ctls[4].color = pass_gr_ctls[5].color;
		}
	}	
	*entropy = (int)inf.entropy;

	if ( inf.entropy > 192 ) idx = 4;
	if ( inf.entropy < 193 ) idx = 3;
	if ( inf.entropy < 129 ) idx = 2;
	if ( inf.entropy < 81  ) idx = 1;
	if ( inf.entropy < 65  ) idx = 0;

	if ( !inf.entropy )
	{
		idx = 5;
	}
	pass_pe_ctls[idx].color = CL_BLUE;

	k = 0;
	while ( pass_gr_ctls[k].id != -1 )
	{						
		if ( pass_gr_ctls[k].hwnd )
		{
			InvalidateRect(pass_gr_ctls[k].hwnd, NULL, TRUE);
		}
		if ( pass_pe_ctls[k].hwnd )
		{
			InvalidateRect(pass_pe_ctls[k].hwnd, NULL, TRUE);
		}
		k++;
	}
}


dc_pass *__get_pass_keyfiles(
		HWND h_pass,
		BOOL use_keyfiles,
		int  key_list
	)
{
	dc_pass *pass;
	wchar_t *s_pass;
	size_t   plen;
	int      rlt;

	if ( (pass = secure_alloc(sizeof(dc_pass))) == NULL )
	{
		return NULL;
	}
	if ( (s_pass = secure_alloc((MAX_PASSWORD + 1) * sizeof(wchar_t))) == NULL) 
	{
		return NULL;
	}
	GetWindowText( h_pass, s_pass, MAX_PASSWORD + 1 );
	if ( wcslen(s_pass) > 0 )
	{
		plen       = wcslen(s_pass) * sizeof(wchar_t);
		pass->size = d32( min( plen, MAX_PASSWORD * sizeof(wchar_t) ) );

		mincpy( &pass->pass, s_pass, pass->size );
		secure_free( s_pass );
	}
	if ( use_keyfiles )
	{
		_list_key_files *key_file;

		if ( key_file = _first_keyfile(key_list) )
		{
			do {
				rlt = dc_add_keyfiles( pass, key_file->path );
				if ( rlt != ST_OK )
				{
					__error_s( GetParent(h_pass), L"Keyfiles not loaded", rlt );

					secure_free( pass );
					pass = NULL;

					break;
				}
				key_file = _next_keyfile( key_file, key_list );

			} while ( key_file != NULL );
		} 
	}

	return pass;
}


void _wipe_pass_control(
		HWND hwnd,
		int  edit_pass
	)
{
	wchar_t wipe[MAX_PASSWORD + 1];
	wipe[MAX_PASSWORD] = 0;

	memset( wipe, '#', MAX_PASSWORD * sizeof(wchar_t) );
	SetWindowText( GetDlgItem(hwnd, edit_pass), wipe );	
}


BOOL _input_verify(
		dc_pass *pass,
		dc_pass *verify,
		int      keyfiles_list,
		int      kb_layout,
		int     *msg_idx
	)
{
	BOOL correct = FALSE;

	_pass_inf info;
	_check_password( pass, &info );

	*msg_idx = ST_PASS_CORRRECT;
	if ( info.length )
	{		
		if ( (kb_layout == LDR_KB_QWERTY && info.flags & P_NCHAR) || 
			 ((kb_layout == LDR_KB_QWERTZ || kb_layout == LDR_KB_AZERTY) && 
			 (info.flags & P_NCHAR || info.flags & P_SPCH))) 
		{
				 
			*msg_idx = ST_PASS_SPRS_SYMBOLS;
		} else {
			correct = TRUE;
		}
	} else {
		*msg_idx = ST_PASS_EMPTY;
	}

	if ( correct && verify != NULL )
	{
		if ( !IS_EQUAL_PASS(pass, verify) )
		{
			*msg_idx = ST_PASS_NOT_CONFIRMED;
		}
		if ( verify->size == 0 ) 
		{
			*msg_idx = ST_PASS_EMPTY_CONFIRM;
		}		
	} else
	{
		if ( keyfiles_list != KEYLIST_NONE )
		{
			if ( _keyfiles_count(keyfiles_list) == 0 )
			{
				*msg_idx = ST_PASS_EMPTY_KEYLIST;
			}
		}
	}
	return (
		(  info.length && !verify ) || 
		(  info.length &&  verify && IS_EQUAL_PASS(pass, verify) ) || 
		( !info.length && _keyfiles_count(keyfiles_list) )
	);

}


