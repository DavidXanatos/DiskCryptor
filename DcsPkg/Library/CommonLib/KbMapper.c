/** @file
EFI keyboard layout mapper

Copyright (c) 2019. DiskCryptor, David Xanatos

This program and the accompanying materials are licensed and made available
under the terms and conditions of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#include <Library/CommonLib.h>

int gKeyboardLayout = 0;

CHAR16 to_qwertz(CHAR16 c) 
{
	switch (c) {
		case L'y': return L'z';
		case L'Y': return L'Z';
		case L'z': return L'y';
		case L'Z': return L'Y';
	}
	return c;
}

CHAR16 to_azerty(CHAR16 c) 
{
	switch (c) {
		case L'q': return L'a';
		case L'Q': return L'A';
		case L'w': return L'z';
		case L'W': return L'Z';
		case L'a': return L'q';
		case L'A': return L'Q';
		case L';': return L'm';
		case L':': return L'M';
		case L'z': return L'w';
		case L'Z': return L'W';
	}
	return c;
}

EFI_INPUT_KEY MapKeyboardKey(EFI_INPUT_KEY key)
{
	switch (gKeyboardLayout)
	{
	case KB_MAP_QWERTZ: key.UnicodeChar = to_qwertz(key.UnicodeChar); break;
	case KB_MAP_AZERTY: key.UnicodeChar = to_azerty(key.UnicodeChar); break;
	}
	return key;
}