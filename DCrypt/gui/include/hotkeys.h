#ifndef _HOTKEYS_
#define _HOTKEYS_

#define HOTKEYS 4

char _check_hotkeys(
		HWND hwnd,
		DWORD hotkeys[]
	);

void _set_hotkeys(
		HWND hwnd,
		DWORD hotkeys[],
		BOOL check
	);

void _unset_hotkeys(
		DWORD hotkeys[]
	);

BOOL _key_name(
		WPARAM  code,
		UINT    shift,
		wchar_t *text
	);

#endif

