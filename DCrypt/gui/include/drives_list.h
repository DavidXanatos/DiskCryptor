#ifndef _DRIVESLIST_
#define _DRIVESLIST_

int
_list_volumes(
		list_entry *volumes
	);

_dnode 
*_scan_vols_tree(
		vol_inf *vol,
		int     *count
	);

void 
_add_drive_node(
		_dnode    *exist_node,
		drive_inf *new_drv,
		vol_inf   *vol, 
		int        disk_number
	);

#endif