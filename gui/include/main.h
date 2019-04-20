#ifndef _MAIN_
#define _MAIN_

#include "linklist.h"
#include "dlg_code.h"
#include "prc_code.h"
#include "misc.h"
#include "ui_utils.h"
#include "defines.h"
#include "main.h"
#include "subs.h"
#include "resource.h"
#include "drvinst.h"
#include "stat.h"

extern list_entry __drives;
extern list_entry __volumes;
extern list_entry __action;

extern CRITICAL_SECTION crit_sect;
extern int _tmr_elapse[ ];

typedef struct _timer_info 
{
	int id;
	int elapse;

} timer_info;

extern int          __status;
extern dc_conf_data __config;

extern CRITICAL_SECTION CritSection;

static wchar_t drv_msk[ ] = L"%s\\drivers\\%s.sys";

#define __execute( path ) (  \
		ShellExecuteW( NULL, L"open", path, NULL, NULL, SW_SHOWNORMAL ) \
	)

void _refresh(
		char main
	);

int _benchmark( 
		bench_item *bench
	);

int _set_boot_loader(
		HWND  hwnd,
		int   dsk_num,
		int   is_small
	);

BOOL _is_boot_device(
		vol_inf *vol 
	);

BOOL _is_removable_media( 
		int dsk_num 
	);

void _activate_page( );

void _set_timer(
		int  index,
		BOOL set,
		BOOL refresh
	);

void _check_driver(
		HWND   hwnd,
		size_t buff_size,
		char   set
	);

void _get_driver_path(
		wchar_t *name, 
		wchar_t *path
	);


#endif
