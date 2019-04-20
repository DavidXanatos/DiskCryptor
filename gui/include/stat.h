#ifndef _STAT_
#define _STAT_

void _get_time_period(
		__int64  begin,
		wchar_t *display,
		BOOL     abs
	);

void _init_speed_stat( 
		_dspeed *speed 
	);

int _speed_stat_event(
		wchar_t *s_speed,
		size_t   chars,
		_dspeed *speed,
		__int64  tmp_size,
		BOOL     is_running
	);

void _update_info_table( 
		BOOL iso_info 
	);


#endif