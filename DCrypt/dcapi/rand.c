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
#include <windows.h>
#include <wincrypt.h>
#include <psapi.h>
#include "rand.h"
#include "misc.h"
#include "drv_ioctl.h"

#define SEED_MAX (1024 * 8)

typedef struct _seed_data {
	HWND                    seed1;
	HWND                    seed2;
	HWND                    seed3;
	HWND                    seed4;
	HWND                    seed5;
	HWND                    seed6;
	DWORD                   seed7;
	DWORD                   seed8;
	DWORD                   seed9;
	HWND                    seed10;
	HWND                    seed11;
	UINT                    seed12;
	HCURSOR                 seed13;
	HWND                    seed14;
	HANDLE                  seed15;
	DWORD                   seed16;
	BOOL                    seed17;
	LONG                    seed18;
	UINT                    seed19;
	CURSORINFO              seed20;
	POINT                   seed21;
	FILETIME                seed22;
	FILETIME                seed23;
	FILETIME                seed24;
	FILETIME                seed25;
	FILETIME                seed26;
	FILETIME                seed27;
	FILETIME                seed28;
	FILETIME                seed29;
	LARGE_INTEGER           seed30;
	MEMORYSTATUSEX          seed31;
	PROCESS_MEMORY_COUNTERS seed32;
	
} seed_data;

typedef struct _wnd_seed {
	HWND          seed1;
	RECT          seed2;
	RECT          seed3;
	DWORD         seed5;
	DWORD         seed6;
	WINDOWINFO    seed7;
	GUITHREADINFO seed8;
	
} wnd_seed;

typedef struct _mouse_seed {
	u64             seed1;
	WPARAM          seed2;
	LPARAM          seed3;
	MOUSEHOOKSTRUCT seed4;

} mouse_seed;

typedef struct _kbd_seed {
	u64    seed1;
	WPARAM seed2;
	LPARAM seed3;

} kbd_seed;

static u8   *seed_buff;
static u32   seed_size;
static HHOOK mouse_hook;
static HHOOK kbd_hook;

static void seed_send()
{
	/* send seed to driver */
	dc_device_control(DC_CTL_ADD_SEED, seed_buff, seed_size, NULL, 0);

	/* prevent leaks */
	burn(seed_buff, SEED_MAX);
	seed_size = 0;
}

void seed_collect(u8 *data, int size)
{
	int i;

	for (i = 0; i < size; i++) {
		seed_buff[seed_size++] = data[i];

		if (seed_size == SEED_MAX) {
			seed_send();
		}
	}

	/* prevent leaks */
	burn(data, size);
}


static BOOL CALLBACK rnd_enum_proc(HWND hwnd,  LPARAM lParam)
{
	wnd_seed seed;
	wchar_t  text[MAX_PATH];
	int      size; 

	seed.seed1 = hwnd;
	seed.seed5 = GetWindowThreadProcessId(hwnd, &seed.seed6);

	seed.seed7.cbSize = sizeof(seed.seed7);
	seed.seed8.cbSize = sizeof(seed.seed8);

	GetClientRect(hwnd, &seed.seed2);
	GetWindowRect(hwnd, &seed.seed3); 	
	GetWindowInfo(hwnd, &seed.seed7);
	GetGUIThreadInfo(seed.seed5, &seed.seed8);

	if (size = GetWindowText(hwnd, text, countof(text))) {
		seed_collect(pv(text), size * sizeof(wchar_t));
	}
	
	seed_collect(pv(&seed), sizeof(seed));

	return TRUE;
}

static LRESULT CALLBACK rnd_mouse_hook(int code, WPARAM wparam,  LPARAM lparam)
{
	mouse_seed seed;

	if (code >= 0) 
	{
		seed.seed1 = __rdtsc();
		seed.seed2 = wparam;
		seed.seed3 = lparam;
		memcpy(&seed.seed4, pv(lparam), sizeof(MOUSEHOOKSTRUCT));

		seed_collect(pv(&seed), sizeof(seed));

		/* if 512 seed bytes collected then send it to driver now */
		if (seed_size >= 512) {			
			seed_send();
		}
	}

	return CallNextHookEx(
		mouse_hook, code, wparam, lparam);
}

static LRESULT CALLBACK rnd_kbd_hook(int code, WPARAM wparam,  LPARAM lparam)
{
	kbd_seed seed;

	if (code >= 0)
	{
		seed.seed1 = __rdtsc();
		seed.seed2 = wparam;
		seed.seed3 = lparam;

		seed_collect(pv(&seed), sizeof(seed));

		/* send seed to driver every key press */
		seed_send();
	}

	return CallNextHookEx(
		kbd_hook, code, wparam, lparam);
}

void rnd_reseed_now( )
{
	seed_data seed;
	
	seed.seed1  = GetDesktopWindow();
	seed.seed2  = GetForegroundWindow();
	seed.seed3  = GetShellWindow();
	seed.seed4  = GetCapture();
	seed.seed5  = GetClipboardOwner();
	seed.seed6  = GetOpenClipboardWindow();
	seed.seed7  = GetCurrentProcessId();
	seed.seed8  = GetCurrentThreadId();
	seed.seed9  = GetTickCount();
	seed.seed10 = GetFocus();
	seed.seed11 = GetActiveWindow();
	seed.seed12 = GetKBCodePage();
	seed.seed13 = GetCursor();
	seed.seed14 = GetLastActivePopup(seed.seed1);
	seed.seed15 = GetProcessHeap();
	seed.seed16 = GetQueueStatus(QS_ALLEVENTS);
	seed.seed17 = GetInputState();
	seed.seed18 = GetMessageTime();
	seed.seed19 = GetOEMCP();

	seed.seed20.cbSize   = sizeof(seed.seed20);
	seed.seed31.dwLength = sizeof(seed.seed31);
	seed.seed32.cb       = sizeof(seed.seed32);

	GetCursorInfo(&seed.seed20);
	GetCaretPos(&seed.seed21);

	GetThreadTimes(
		GetCurrentThread(), &seed.seed22,
		&seed.seed23, &seed.seed24, &seed.seed25);

	GetProcessTimes(
		GetCurrentProcess(), &seed.seed26,
		&seed.seed27, &seed.seed28, &seed.seed29);

	GetProcessMemoryInfo(
		GetCurrentProcess(), &seed.seed32, sizeof(seed.seed32));

	QueryPerformanceCounter(&seed.seed30);
	GlobalMemoryStatusEx(&seed.seed31);

	/* add global statistic to seed */
	seed_collect(pv(&seed), sizeof(seed));

	/* enum all windows and add to seed information about it */
	EnumWindows(rnd_enum_proc, 0);

	/* send seed to driver */
	seed_send();
}

int rnd_init()
{
	HCRYPTPROV hprov;
	u8         rand[512];

	if ( (seed_buff = secure_alloc(SEED_MAX)) == NULL ) {
		return ST_NOMEM;
	}

	mouse_hook = SetWindowsHookEx(
		WH_MOUSE, rnd_mouse_hook, NULL, GetCurrentThreadId());

	kbd_hook = SetWindowsHookEx(
		WH_KEYBOARD, rnd_kbd_hook, NULL, GetCurrentThreadId());

	/* get random data from Windows PRNG */
	if (CryptAcquireContext(&hprov, NULL, NULL, PROV_RSA_FULL, 0) ||
		CryptAcquireContext(&hprov, NULL, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET)) 
	{
		CryptGenRandom(hprov, sizeof(rand), rand);

		seed_collect(rand, sizeof(rand));

		CryptReleaseContext(hprov, 0);
	}

	rnd_reseed_now();

	return ST_OK;
}