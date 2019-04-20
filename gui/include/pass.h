#ifndef _PASS_CHECK_
#define _PASS_CHECK_

#define ST_PASS_SPRS_SYMBOLS		1
#define ST_PASS_EMPTY				2
#define ST_PASS_NOT_CONFIRMED		3
#define ST_PASS_EMPTY_CONFIRM		4
#define ST_PASS_EMPTY_KEYLIST		5
#define ST_PASS_CORRRECT			6

typedef struct __pass_inf 
{
	int    flags;      // character groups flags
	double entropy;    // password entropy (in bits)
	int    length;     // password length

} _pass_inf;

#define P_AZ_L		1
#define P_AZ_H		2
#define P_09		4
#define P_SPACE		8
#define P_SPCH		16
#define P_NCHAR		32

#define _get_pass_keyfiles(hwnd, id_pass, id_check_key, key_list_id) ( \
		__get_pass_keyfiles(					\
				GetDlgItem(hwnd, id_pass),		\
				_get_check(hwnd, id_check_key),	\
				key_list_id						\
				)								\
	)

#define _get_pass(hwnd, id_pass) (				\
		__get_pass_keyfiles(					\
				GetDlgItem(hwnd, id_pass),		\
				FALSE, -1						\
				)								\
	)

void _draw_pass_rating(
		HWND     hwnd,
		dc_pass *pass,
		int      kb_layout,
		int     *entropy
	);

BOOL _input_verify(
		dc_pass *pass,
		dc_pass *verify,
		int      keyfiles_list,
		int      kb_layout,
		int     *msg_idx
	);

dc_pass *__get_pass_keyfiles(
		HWND h_pass,
		BOOL use_keyfiles,
		int  key_list
	);

void _wipe_pass_control(
		HWND hwnd,
		int  edit_pass
	);

#endif