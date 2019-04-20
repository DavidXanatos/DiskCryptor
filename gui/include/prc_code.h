#ifndef _PRCCODE_
#define _PRCCODE_

#include "drv_ioctl.h"
#include "mbrinst.h"

#define IDC_TIMER			0x4100

#define MAIN_TIMER			0
#define PROC_TIMER			1
#define RAND_TIMER			2
#define SHRN_TIMER			3
#define POST_TIMER			4

#define DA_INSTAL			1
#define DA_REMOVE			2
#define DA_UPDATE			3

#define ACT_STOPPED			1
#define ACT_PAUSED			2
#define ACT_RUNNING			3

#define ACT_ENCRYPT			0
#define ACT_DECRYPT			1
#define ACT_REENCRYPT		2
#define ACT_FORMAT			3
#define ACT_ENCRYPT_CD		4

#define SPEED_TIMER_QUANTS	40
#define SPEED_EVENT_QUANTS	20
#define SPEED_QUANTS		( SPEED_TIMER_QUANTS + SPEED_EVENT_QUANTS )

#define HWND_NULL			( ( HWND ) - 1 )

#define MAIN_SHEETS			2
#define WZR_MAX_STEPS		4

typedef struct __dspeed 
{	
	LARGE_INTEGER t_begin;
	LARGE_INTEGER time_stat[SPEED_QUANTS];
	__int64       speed_stat[SPEED_QUANTS];
	__int64       tmp_size;

} _dspeed;

typedef struct __dact 
{	
	list_entry    list;	
	HANDLE        h_thread;
	int           act;
	int           status;
	int           wp_mode;
	_dspeed       speed;
	wchar_t       device[MAX_PATH];

} _dact;

typedef struct __dmnt 
{	
	vol_inf info;
	wchar_t label[MAX_PATH];
	wchar_t fs[MAX_PATH];

} _dmnt;

typedef struct __droot 
{
	list_entry vols;
	u32        dsk_num;
	drive_inf  info;
	wchar_t    dsk_name[MAX_PATH];

} _droot;

typedef struct __iso_info
{
	dc_pass *pass;
	int      cipher_id;
	wchar_t  s_iso_src[MAX_PATH];
	wchar_t  s_iso_dst[MAX_PATH];
	HANDLE   h_thread;
	_dspeed  speed;

} _iso_info;

typedef struct __dlg 
{
	HANDLE    h_page;
	BOOL      q_format;
	wchar_t  *fs_name;
	int       act_type;
	int       rlt;
	_iso_info iso;

} _dlg;

typedef struct __dnode 
{
	list_entry list;	
	BOOL       is_root;
	BOOL       exists;
	_droot     root;
	_dmnt      mnt;
	_dlg       dlg;

} _dnode;

typedef struct _bench_item 
{
	wchar_t *alg;
	double   speed;

} bench_item;

typedef struct _dlgpass 
{
	_dnode  *node;
	dc_pass *pass;
	dc_pass *new_pass;
	wchar_t *mnt_point;

} dlgpass, *pdlgpass;

typedef struct __wz_sheets 
{
	int  id;
	HWND hwnd;
	BOOL show;
	int  first_tab_id;
	HWND first_tab_hwnd;

} _wz_sheets;

INT_PTR 
CALLBACK
_install_dlg_proc(
		HWND   hwnd,
		UINT   message,
		WPARAM wparam,
		LPARAM lparam
	);

void _dlg_about(
		HWND hwnd
	);

void _dlg_benchmark(
		HWND hwnd
	);

INT_PTR CALLBACK
_main_dialog_proc(
		HWND   hwnd,
		UINT   message,
		WPARAM wparam,
		LPARAM lparam
	);

void __stdcall 
_timer_handle(
		HWND     hwnd,
		UINT     msg,
		UINT_PTR id,
		DWORD    tickcount
	);

DWORD 
WINAPI 
_thread_enc_iso_proc(
		LPVOID lparam
	);



#endif
