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

#include <stdarg.h>
#include "boot.h"
#include "bios.h"
#include "boot_vtab.h"

#define bcd2int(bcd) (((bcd & 0xf0) >> 4) * 10 + (bcd & 0x0f))

u32 get_rtc_time()
{
	rm_ctx ctx;
	u32    hrs, mins;
	u32    sec;

	btab->p_set_ctx(0x0200, &ctx);
	btab->p_bios_call(0x1A, &ctx);
	hrs  = bcd2int(ctx.ch);
	mins = bcd2int(ctx.cl);
	sec  = bcd2int(ctx.dh);

	return (hrs * 3600) + (mins * 60) + sec;
}

void _putch(char ch)
{
	rm_ctx ctx;

	if (ch == '\n') {
		_putch('\r');
	}
	btab->p_set_ctx(0x0E00 | ch, &ctx);	
	btab->p_bios_call(0x10, &ctx);
}

int _kbhit() 
{
	rm_ctx ctx;
	btab->p_set_ctx(0x0100, &ctx);	
	btab->p_bios_call(0x16, &ctx);
	return (ctx.efl & FL_ZF) == 0;
}

char _getch()
{
	rm_ctx ctx;

	/* work around for Apple BIOS bug
	   check the keyboard buffer, until there is a keypress.
	*/
	do { } while (_kbhit() == 0);
	/* read character from keyboard */
	btab->p_set_ctx(0, &ctx);	
	btab->p_bios_call(0x16, &ctx);
	return ctx.al;
}


void puts(char *msg)
{
	while (*msg) {
		_putch(*msg++);
	}		
}

int isdigit(int c)
{
	return (c >= '0' && c <= '9');
}

char *strncpy(char *dest, const char *src, int c)
{
	char *p = dest;

	while ((*p++ = *src++) != '\0' && --c);
	
	return dest;
}

int isspace(int c)
{
	return (c == '\n' || c == '\r' || c == ' ' || c == '\t');
}

int tolower(int c)
{
	if (c >= 'A' && c <= 'Z') {
		return c - 'A' + 'a';
	}
	return c;
} 


unsigned long
strtoull (const char *str, char **end, int base)
{
  unsigned long num = 0;
  int found = 0;
  
  /* Skip white spaces.  */
  while (*str && isspace (*str)) {
	  str++;
  }
  
  /* Guess the base, if not specified. The prefix `0x' means 16, and
     the prefix `0' means 8.  */
  if (base == 0 && str[0] == '0')
  {
	  if (str[1] == 'x')
	  {
		  if (base == 0 || base == 16) {
			  base = 16;
			  str += 2;
		  }
	  } else if (str[1] >= '0' && str[1] <= '7') {
		  base = 8;
	  }
  }

  if (base == 0) {
	  base = 10;
  }

  while (*str)
  {
	  unsigned long digit;

	  digit = tolower (*str) - '0';

	  if (digit > 9) 
	  {
		  digit += '0' - 'a' + 10;
		  if (digit >= (unsigned long) base) {
			  break;
		  }
	  }

	  num = num * base + digit;
	  str++;
  }

  if (end) {
	  *end = (char *) str;
  }

  return num;
} 

void fillchar(const char ch, int n)
{
	int i;

	for (i = 0; i < n; i++) {
		_putch(ch);
	}
}

static char *
itoa (char *str, int c, unsigned n)
{
	unsigned base = (c == 'x') ? 16 : 10;
	char *p, *x, tmp;

	if ((int) n < 0 && c == 'd') {
		n = (unsigned) (-((int) n));
		*str++ = '-';
    }

	p = str;
    do
    {
		unsigned d = n % base;
		*p++ = (d > 9) ? d + 'a' - 10 : d + '0';
    }
	while (n /= base); 
	*p = 0;

	 x = str + strlen (str) - 1;

	 while (str < x)
	 {
		 tmp = *str; *str = *x;
		 *x = tmp; str++; x--;
	 }
	 return p;
}
 

void printf (const char *fmt, ...)
{
  char c;
  int count = 0;
  va_list args;

  va_start(args, fmt);
  
  while ((c = *fmt++) != 0)
  {
	  if (c != '%') {
		  _putch(c);
	  } else 
	  {
		  char tmp[32];
		  char *p;
		  unsigned int format1 = 0;
		  unsigned int format2 = 3;
		  char zerofill = ' ';
		  int rightfill = 0;
		  int n;
		  int longfmt = 0;
		  int longlongfmt = 0;

		  if (*fmt && *fmt =='-') {
			  rightfill = 1;
			  fmt++;
		  }

		  p = (char *) fmt;
		  /* Read formatting parameters.  */
		  while (*p && isdigit(*p)) {
			  p++;
		  }

		  if (p > fmt)
		  {
			  char s[100];

			  strncpy(s, fmt, p - fmt);
			  s[p - fmt] = 0;

			  if (s[0] == '0') {
				  zerofill = '0';
			  }
			  format1 = (u32)strtoull (s, 0, 10);
			  fmt = p;

			  if (*p && *p == '.')
			  {
				  p++; fmt++;

				  while (*p && isdigit (*p)) {
					  p++;
				  }

				  if (p > fmt)
				  {
					  char fstr[100];

					  strncpy (fstr, fmt, p - fmt);
					  format2 = (u32)strtoull (fstr, 0, 10);
					  fmt = p;
				  }
			  }
		  }

		  c = *fmt++;

		  if (c == 'l') 
		  {
			  longfmt = 1;
			  c = *fmt++;
		  }

	  switch (c)
	  {
		  case 'p':
			  puts("0x");
			  c = 'x';			  
			  /* fall through */
		  case 'x':
		  case 'u':
		  case 'd':
			  if (longfmt) {
				  n = va_arg (args, long);
			  }  else {
				  n = va_arg (args, int);
			  }
			  itoa(tmp, c, n);

			  if (! rightfill && strlen (tmp) < format1) {
				  fillchar (zerofill, format1 - strlen (tmp));
			  }

			  puts(tmp);

			  if (rightfill && strlen (tmp) < format1) {
				  fillchar (zerofill, format1 - strlen (tmp));
			  }
		break;	      
	    case 'c':
	      n = va_arg (args, int);
	      _putch(n & 0xff);
	    break;      
	    case 's':
	      p = va_arg (args, char *);
	      
		  if (p) 
		  {
			  if (!rightfill && strlen (p) < format1) {
				  fillchar (zerofill, format1 - strlen (p));
			  }

			  puts(p);
		  
			  if (rightfill && strlen (p) < format1) {
				  fillchar (zerofill, format1 - strlen (p));
			  }
		  }  else {
			  puts("(null)");
		  }
	    break;
		default:
	      _putch (c);
	    break;
	  }
	}
  }

  /* delay one second */
/*  {
	  u32 t = get_rtc_time();
	  while (get_rtc_time() - t < 1);
  }
*/
  va_end(args);
}

void print_dword(u32 val)
{
	u8  b;
	int i;

	for (i = 0; i < 8; i++)
	{
		b = (val >> 28) & 0x0F; val <<= 4;
		if (b < 10) b += '0'; else b += 'A'-10;
		_putch(b);
	}
	_putch('\n');
}