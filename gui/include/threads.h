#ifndef _THREADS_
#define _THREADS_

DWORD _drv_action(int action, int version);

_dact *_create_act_thread(
		_dnode *node,
		int     act_type,   // -1 - search
		int     act_status
	);


#endif