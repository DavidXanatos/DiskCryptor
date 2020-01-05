#ifndef _DLGMENU_
#define _DLGMENU_

int _finish_formating(
		_dnode *node
	);

void _refresh_menu( );

void _state_menu(
		HMENU menu,
		UINT state
	);

void _menu_decrypt( 
		_dnode *node 
	);

void _menu_encrypt(
		_dnode *node
	);

void _menu_reencrypt( 
		_dnode *node 
	);

void _menu_format( 
		_dnode *node 
	);

void _menu_unmount( 
		_dnode *node 
	);

void _menu_mount( 
		_dnode *node 
	);

void _menu_encrypt_cd( );
void _menu_mountall( );
void _menu_unmountall( );

void _menu_change_pass( 
		_dnode *node 
	);

void _menu_clear_cache( );
void _menu_about( );

void _menu_backup_header( 
		_dnode *node 
	);

void _menu_restore_header( 
		_dnode *node 
	);

void _menu_wizard( 
		_dnode *node 
	);

int _menu_set_loader_vol(
		HWND     hwnd,
		wchar_t *vol,
		int      dsk_num,
		int      type,
		int      is_small
	);

int _menu_unset_loader_mbr(
		HWND     hwnd,
		wchar_t *vol,
		int      dsk_num,
		int      type
	);

int _menu_update_loader(
		HWND     hwnd,
		wchar_t *vol,
		int      dsk_num
	);

int _menu_set_loader_file(
		HWND     hwnd,
		wchar_t *path,
		BOOL     iso,
		int      is_small
	);

#endif