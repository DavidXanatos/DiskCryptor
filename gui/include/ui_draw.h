#ifndef _UIDRAW_
#define _UIDRAW_

#define modify_rect( rc, x, y, dx, dy ) \
	( rc.left   += x  ); \
	( rc.top    += y  ); \
	( rc.right  += dx ); \
	( rc.bottom += dy );	

int _draw_proc(
		int    message,
		LPARAM lparam
	);

#endif