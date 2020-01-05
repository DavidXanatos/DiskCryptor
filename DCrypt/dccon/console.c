/*
    *
    * DiskCryptor - open source partition encryption tool
	* Copyright (c) 2008-2009
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
#include <stdio.h>
#include <conio.h>
#include "defines.h"

int       g_argc;
wchar_t **g_argv;

void cls_console() 
{
	CONSOLE_SCREEN_BUFFER_INFO csbi;
	COORD                      pos;
	u32                        bytes;
	HANDLE                     console = GetStdHandle(STD_OUTPUT_HANDLE);

	GetConsoleScreenBufferInfo(console, &csbi);

	pos.X = 0; pos.Y = 0;
	FillConsoleOutputCharacter(
		console, ' ', csbi.dwSize.X * csbi.dwSize.Y, pos, &bytes);

	SetConsoleCursorPosition(console, pos); 
}

char getchr(char min, char max) 
{
	char ch;

	do
	{
		ch = _getch();
	} while ( (ch < min) || (ch > max) );

	return ch;
}

int is_param(wchar_t *name)
{
	int i;
	
	for (i = 0; i < g_argc; i++) {
		if (_wcsicmp(g_argv[i], name) == 0) return 1;
	}
	return 0;
}

wchar_t *get_param(wchar_t *name)
{
	int i;
	
	for (i = 0; i < g_argc-1; i++) {
		if (_wcsicmp(g_argv[i], name) == 0) return g_argv[i+1];
	}
	return NULL;
}

void clean_cmd_line()
{
	wchar_t *cmd_w = GetCommandLineW();
	char    *cmd_a = GetCommandLineA();
	burn(cmd_w, wcslen(cmd_w) * sizeof(wchar_t));
	burn(cmd_a, strlen(cmd_a) * sizeof(char));	
}
