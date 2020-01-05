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
#include "autorun.h"

#include "ntdll.h"

static wchar_t run_key[ ]      = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
static wchar_t run_once_key[ ] = L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce";
static wchar_t run_v_name[ ]   = L"DiskCryptor";

int autorun_set(
		int run
	)
{
	wchar_t  name[MAX_PATH];
	wchar_t  path[MAX_PATH];
	HKEY     h_key = NULL;
	wchar_t *kname;
	int      resl;	
	u32      cb;
	
	GetModuleFileName(
		NULL, name, countof(name)
		);

	_snwprintf(
		path, countof(path), L"\"%s\" -h", name
		);	

	if ( is_win_vista( ) != 0 )
	{
		kname = run_once_key;
	} else {
		kname = run_key;
	}
	do
	{
		if ( run != 0 )
		{
			if ( RegCreateKey( HKEY_LOCAL_MACHINE, kname, &h_key ) ) 
			{
				resl = ST_ACCESS_DENIED; 
				break;
			}
			cb = (u32)(wcslen(path) * sizeof(wchar_t));

			if ( RegSetValueEx( h_key, run_v_name, 0, REG_SZ, pv(path), cb ) )
			{
				resl = ST_ACCESS_DENIED; 
				break;
			}
			resl = ST_OK;
		} else 
		{
			if ( RegOpenKey( HKEY_LOCAL_MACHINE, kname, &h_key ) )
			{
				resl = ST_ACCESS_DENIED; 
				break;
			}
			if ( RegDeleteValue( h_key, run_v_name ) )
			{
				resl = ST_ACCESS_DENIED;
				break;
			}
			resl = ST_OK;
		}
	} while (0);

	if ( h_key != NULL )
	{
		RegCloseKey( h_key );
	}

	return resl;
}


int on_app_start(
		wchar_t *cmd_line
	)
{
	PROCESS_BASIC_INFORMATION pbi;
	wchar_t                   name[MAX_PATH];
	wchar_t                   path[MAX_PATH];
	HKEY                      h_key;	
	int                       resl, autorn;
	u32                       cb, pid;
	int                       isvista;	
	NTSTATUS                  status;
	HANDLE                    h_proc;
	STARTUPINFO               si;
	PROCESS_INFORMATION       pi;
	wchar_t                  *w_pid;
 
    pid    = 0; 
	autorn = 0;

#ifdef LOG_FILE
	_log( L"func:app start; cmd line == \"%s\"", cmd_line );
#endif
	
	if ( wcsstr( cmd_line, L"-h" ) != NULL )
	{
		autorn = 1;
	} else 
	{
		if ( w_pid = wcsstr( cmd_line, L"-p" ) )
		{
			autorn = 1; 
			pid = wcstoul( w_pid + 2, NULL, 10 ); 
		}
	}

#ifdef LOG_FILE
	_log( L"func:app start; autorn == %d", autorn );
#endif

	isvista = is_win_vista( );

#ifdef LOG_FILE
	_log( L"func:app start; isvista == %d", isvista );
#endif

	if ( isvista != 0 )
	{
		/* update autorun if old autorun found */
		if ( RegCreateKey(HKEY_LOCAL_MACHINE, run_key, &h_key ) == 0)
		{
			cb = sizeof(path);

			if ( RegQueryValueEx( h_key, run_v_name, 0, NULL, pv(path), &cb ) == 0 )
			{
#ifdef LOG_FILE
	_log( L"func:app start; autorun set" );
#endif
				RegDeleteValue( h_key, run_v_name );
				autorun_set(1);
			}
			RegCloseKey(h_key);
		}
	}
	do
	{
		if ( autorn == 0 )
		{
			resl = ST_OK;
			break;
		}
		if ( isvista != 0 )
		{
			if ( pid == 0 )
			{
				status = 
					NtQueryInformationProcess(
						GetCurrentProcess( ), ProcessBasicInformation, &pbi, sizeof(pbi), NULL
						);
#ifdef LOG_FILE
	_log( L"func:app start; %0.8X query information process" );
#endif
				if ( status == 0 ) 
				{
					GetModuleFileName(
						NULL, name, sizeof(name)
						);
#ifdef LOG_FILE
	_log( L"func:app start; module file name == %s", name );
#endif
					_snwprintf(
						path, countof(path), L"\"%s\" -p%u", name, (u32)(pbi.InheritedFromUniqueProcessId)
						);

					memset( &si, 0, sizeof(si) );
					si.cb = sizeof(si);

#ifdef LOG_FILE
	_log( L"func:app start; before create process \"%s\"", path );
#endif
					if ( CreateProcess(
							NULL, path, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi
						) )
					{
#ifdef LOG_FILE
	_log( L"func:app start; process created" );
#endif
						CloseHandle(pi.hProcess);
						CloseHandle(pi.hThread);
					}
				}
				resl = ST_NEED_EXIT;
			} else 
			{
				if ( h_proc = OpenProcess( SYNCHRONIZE, FALSE, pid ) )
				{
#ifdef LOG_FILE
	_log( L"func:app start; %0.8X open process", h_proc );
#endif
					WaitForSingleObject( h_proc, INFINITE );
					CloseHandle( h_proc );
#ifdef LOG_FILE
	_log( L"func:app start; return wait for single object", h_proc );
#endif
				} else {
					Sleep( 500 );
				}
				autorun_set(1);
				resl = ST_AUTORUNNED;
			}
		} else 
		{
			resl = ST_AUTORUNNED;
		}
	} while (0);

#ifdef LOG_FILE
	_log( L"func:app start; %0.8X return", resl );
#endif

	return resl;

}