/*
    *
    * DiskCryptor - open source partition encryption tool
	* Copyright (c) 2009-2013
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
#include "defines.h"
#include "dcapi.h"

static HANDLE g_dc_mutex;
HINSTANCE     g_inst_dll;
DWORD         g_tls_index;

void *dc_extract_rsrc(int *size, int id)
{
	HGLOBAL hglb;
	HRSRC   hres;
	PVOID   data = NULL;

	hres = FindResource(
		g_inst_dll, MAKEINTRESOURCE(id), L"EXEFILE");
	
	if (hres != NULL) 
	{
		size[0] = SizeofResource(g_inst_dll, hres);
		hglb  = LoadResource(g_inst_dll, hres);
		data  = LockResource(hglb);
	} 

	return data;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpvReserved)
{
	HANDLE h_device;

	switch (dwReason)
	{
		case DLL_PROCESS_ATTACH:
			if ( (g_tls_index = TlsAlloc()) == TLS_OUT_OF_INDEXES ) return FALSE;
			g_dc_mutex = CreateMutex(NULL, FALSE, L"DISKCRYPTOR_MUTEX");
			g_inst_dll = hinstDLL;
		break;
		case DLL_PROCESS_DETACH:
			if (g_dc_mutex != NULL) CloseHandle(g_dc_mutex);
			TlsFree(g_tls_index);
		break;
		case DLL_THREAD_DETACH:
			if ( (h_device = TlsGetValue(g_tls_index)) != NULL ) CloseHandle(h_device);
		break;
	}
	return TRUE;
}
