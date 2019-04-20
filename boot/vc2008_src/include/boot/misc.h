#ifndef _MISC_
#define _MISC_

u32  get_rtc_time();
void _putch(char ch);
char _getch();
int  _kbhit();
void puts(char *msg);
int  isdigit(int c);
char *strncpy(char *dest, const char *src, int c);
int  isspace(int c);
int  tolower(int c);

unsigned long
strtoull (const char *str, char **end, int base);

void fillchar (const char ch, int n);
void printf (const char *fmt, ...);

void print_dword(u32 val);

#endif
