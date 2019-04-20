/*
    *
    * DiskCryptor - open source partition encryption tool
	* Copyright (c) 2007-2010
	* ntldr <ntldr@diskcryptor.net> PGP key ID - 0xC48251EB4F8E4E6E
    *

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 3 as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <windows.h>

#include "main.h"
#include "threads.h"

#include "dlg_menu.h"

DWORD 
WINAPI 
_thread_format_proc(
		LPVOID lparam
	)
{
	int i = 0;
	int rlt, wp_mode;

	wchar_t device[MAX_PATH];
	_dnode *node;
	_dact  *act;

	dc_open_device( );
	EnterCriticalSection(&crit_sect);

	node = pv(lparam);
	act = _create_act_thread(node, -1, -1);

	if ( !node || !act ) 
	{
		return 0L;
	}
	wcscpy(device, act->device);
	do 
	{
		if ( act->status != ACT_RUNNING )
		{
			break;
		}
		if ( i-- == 0 )
		{
			dc_sync_enc_state(device); 
			i = 20;
		}
		wp_mode = act->wp_mode;
		LeaveCriticalSection( &crit_sect );

		rlt = dc_format_step( device, wp_mode );
		
		EnterCriticalSection( &crit_sect );
		if ( rlt == ST_FINISHED )
		{
			act->status = ACT_STOPPED;
			break;
		}
		if ( ( rlt != ST_OK ) && ( rlt != ST_RW_ERR ) )
		{
			dc_status st;
			dc_get_device_status( device, &st );

			__error_s(
				HWND_DESKTOP,
				L"Format error on volume [%s]", rlt, st.mnt_point
				);
			
			act->status = ACT_STOPPED;
			break;
		}
	} while (1);

	if ( rlt == ST_FINISHED )
	{
		_finish_formating( node );
	}
	LeaveCriticalSection( &crit_sect );

	return 1L;

}


static
DWORD WINAPI 
_thread_enc_dec_proc(
		LPVOID lparam
	)
{
	BOOL encrypting;
	int i = 0;
	int rlt, wp_mode;

	wchar_t device[MAX_PATH];
	_dnode *node;
	_dact *act;

	dc_open_device( );
	EnterCriticalSection( &crit_sect );

	node = pv(lparam);
	act = _create_act_thread(node, -1, -1);

	if ( !node || !act )
	{
		return 0L;
	}

	wcscpy( device, act->device );
	do 
	{
		if ( act->status != ACT_RUNNING )
		{
			break;
		}
		if ( i-- == 0 )
		{
			dc_sync_enc_state( device );
			i = 20;
		}
		encrypting = act->act != ACT_DECRYPT;
		wp_mode = act->wp_mode;

		LeaveCriticalSection( &crit_sect );

		rlt = encrypting ?
			dc_enc_step(device, wp_mode) :
			dc_dec_step(device);

		EnterCriticalSection(&crit_sect);
		if ( rlt == ST_FINISHED )
		{
			act->status = ACT_STOPPED;
			break;
		}
		if ( rlt == ST_CANCEL )
		{
			Sleep(5000);
		}
		if ( ( rlt != ST_OK ) && ( rlt != ST_RW_ERR ) && ( rlt != ST_CANCEL ) )
		{
			dc_status st;
			wchar_t *act_name;

			dc_get_device_status( device, &st );
			switch ( act->act )
			{
				case ACT_ENCRYPT:   act_name = L"Encryption";   break;
				case ACT_DECRYPT:   act_name = L"Decryption";   break;
				case ACT_REENCRYPT: act_name = L"Reencryption"; break;
			}
			__error_s(
				HWND_DESKTOP,
				L"%s error on volume [%s]", rlt, act_name, st.mnt_point
				);
			
			act->status = ACT_STOPPED;
			break;
		}
	} while (1);

	dc_sync_enc_state(device);
	LeaveCriticalSection(&crit_sect);

	return 1L;

}


void _clear_act_list( )
{
	list_entry *node = __action.flink;
	list_entry *del = NULL;

	list_entry *head = &__action;

	for ( ;
		node != &__action;		
	)
	{
		_dact *act = contain_record(node, _dact, list);
		if ( ACT_STOPPED == act->status )
		{
			if ( WaitForSingleObject(act->h_thread, 0) == WAIT_OBJECT_0 )
			{
				del = node;
				node = node->flink;

				_remove_entry_list(del); 

				CloseHandle(act->h_thread);
				free(del);
			
				continue;
			}
		}
		node = node->flink;
	}

}


_dact *_create_act_thread(
		_dnode *node,
		int     act_type,   // -1 - search
		int     act_status  //
	)
{
	list_entry *item;
	_dact      *act;

	DWORD resume;	
	BOOL  exist = FALSE;

	if ( !node )
	{
		return NULL;
	}
	_clear_act_list( );

	for ( 
		item = __action.flink;
		item != &__action; 
		item = item->flink 
		) 
	{
		act = contain_record(item, _dact, list);
		if ( !wcscmp(act->device, node->mnt.info.device) )
		{
			exist = TRUE;
			if ( act_type == -1 )
			{
				return act; 
			} else {
				break;
			}
		}
	}
	if ( act_type != -1 )
	{
		if ( !exist )
		{
			act = malloc(sizeof(_dact));
			memset(act, 0, sizeof(_dact));
		
			act->wp_mode = node->mnt.info.status.crypt.wp_mode;
			wcsncpy( act->device, node->mnt.info.device, MAX_PATH );
			
			_init_speed_stat( &act->speed );
		}
		act->h_thread = NULL;
		act->status   = act_status;					
		act->act      = act_type;	

		if ( act_status == ACT_RUNNING )
		{
			void *proc;
			switch (act_type) 
			{
				case ACT_REENCRYPT:
				case ACT_ENCRYPT:
				case ACT_DECRYPT:   proc = _thread_enc_dec_proc; break;
				case ACT_FORMAT:    proc = _thread_format_proc;  break;				
			}
			act->h_thread = CreateThread(
				NULL, 0, proc, pv(node), CREATE_SUSPENDED, NULL
				);

			SetThreadPriority(act->h_thread, THREAD_PRIORITY_LOWEST);
			resume = ResumeThread(act->h_thread);

			if ( !act->h_thread || resume == (DWORD)-1 )
			{
				free(act);
				
				__error_s( __dlg, L"Error create thread", -1 );
				return NULL;
			}
		}
		if ( !exist )
		{
			_insert_tail_list(&__action, &act->list);
		}
		return act;			
	}
 	return NULL;

}
