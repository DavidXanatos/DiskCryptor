#ifndef _KEYFILES_
#define _KEYFILES_

#include "linklist.h"

typedef struct __list_key_files 
{
	list_entry next;
	wchar_t path[MAX_PATH];
	
} _list_key_files;

extern _colinfo _keyfiles_headers[ ];

extern list_entry __key_files;
extern list_entry __key_files_new;

#define _KEYFILES_HEAD_(key_list) ( \
		key_list == KEYLIST_CHANGE_PASS ? &__key_files_new : &__key_files \
	)

#define KEYLIST_NONE			-1
#define KEYLIST_CURRENT			 0
#define KEYLIST_CHANGE_PASS		 1
#define KEYLIST_EMBEDDED		 2

void _init_keyfiles_list( );

void _keyfiles_wipe(
		int key_list
	);

int _keyfiles_count(
		int key_list
	);

_list_key_files *_first_keyfile(
		int key_list
	);

_list_key_files *_next_keyfile(
		_list_key_files *keyfile,
		int key_list
	);

void _dlg_keyfiles(
		HWND hwnd,
		int key_list
	);


#endif
