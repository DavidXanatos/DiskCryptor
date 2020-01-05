#ifndef _SUBS_
#define _SUBS_

#define LOG_FILE_NAME L"dcrypt.log"

#define set_flag(var,flag,value) if ((value) == 0) { (var) &= ~(flag); } else { (var) |= (flag); } 	

#define __msg_w( hwnd, display ) ( \
		MessageBox( hwnd, display, L"Warning", MB_YESNO | MB_ICONWARNING) == IDYES \
	)

int __msg_i( HWND hwnd, wchar_t *format, ... );
int __msg_q( HWND hwnd, wchar_t *format, ... );

#define __msg_e( hwnd, display ) ( \
		MessageBox( hwnd, display, L"Error", MB_OK | MB_ICONERROR) \
	)

void __error_s(
		HWND hwnd,
		wchar_t *format, 
		int e_code, 
		...
	);

void _get_status_text(
		_dnode *st,
		wchar_t *text,
		int len
	);

wchar_t *_mark(
		double digit,
		wchar_t *text,
		wchar_t dec
	);

void *_extract_rsrc(
		int id,
		LPWSTR type,
		int *size
	);

void _set_trailing_slash( 
		wchar_t *path 
	);

wchar_t *_extract_name(
		wchar_t *s_path 
	);

void _reboot( );

int _bitcount( 
		DWORD n 
	);

BOOL _array_include( 
		int arr[ ], 
		int find 
	);

int _ext_disk_num(
		HWND hwnd
	);

void _log(
		wchar_t *pws_message,
		...
	);

#endif
