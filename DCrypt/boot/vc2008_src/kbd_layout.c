/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2008 
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

#include "boot.h"
#include "kbd_layout.h"


s8 to_qwertz(s8 c) 
{
	switch (c) {
		case 'y': c = 'z'; break;
		case 'Y': c = 'Z'; break;
		case 'z': c = 'y'; break;
		case 'Z': c = 'Y'; break;
	}

	return c;
}

s8 to_azerty(s8 c) 
{
	switch (c) {
		case 'q': c = 'a'; break;
		case 'Q': c = 'A'; break;
		case 'w': c = 'z'; break;
		case 'W': c = 'Z'; break;
		case 'a': c = 'q'; break;
		case 'A': c = 'Q'; break;
		case ';': c = 'm'; break;
		case ':': c = 'M'; break;
		case 'z': c = 'w'; break;
		case 'Z': c = 'W'; break;
	}

	return c;
}
