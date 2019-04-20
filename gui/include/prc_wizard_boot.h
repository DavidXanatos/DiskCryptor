#ifndef _PRCBOOT_
#define _PRCBOOT_

#define BOOT_WZR_SHEETS		2

int _dlg_config_loader(
		HWND hwnd,
		BOOL external
	);

void _refresh_boot_buttons(
		HWND hwnd,
		HWND h_list,
		int  item
	);

#endif