#ifndef _DLGDRIVESLIST_
#define _DLGDRIVESLIST_

int _list_volumes(
		list_entry *volumes
	);

void _load_diskdrives(
		HWND        hwnd,
		list_entry *volumes,
		char        vcount
	);

void _list_devices(
		HWND h_list,
		BOOL fixed,
		int  sel
	);

BOOL _list_part_by_disk_id(
		HWND hwnd,
		int  disk_id
	);


#endif