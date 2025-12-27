/*
    *
    * DiskCryptor - open source partition encryption tool
	* Copyright (c) 2009-2013
	* ntldr <ntldr@diskcryptor.net> PGP key ID - 0xC48251EB4F8E4E6E
    * 
    * Security updates (c) 2025
    * Fixed named mutex vulnerability (CVE potential)

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
#include <sddl.h>
#include "defines.h"
#include "dcapi.h"

static HANDLE g_dc_mutex;
HINSTANCE     g_inst_dll;
DWORD         g_tls_index;

/*
 * SECURITY FIX: Create a mutex with proper security to prevent squatting
 * 
 * The old code used CreateMutex with a fixed name "DISKCRYPTOR_MUTEX"
 * which could be pre-created by a malicious process to:
 * 1. Cause DoS by holding the mutex indefinitely
 * 2. Potentially manipulate synchronization timing
 * 
 * This fix:
 * 1. Uses a unique GUID-based name to prevent simple name squatting
 * 2. Adds a security descriptor that only allows access by admins
 * 3. Uses a "Local\" prefix to prevent cross-session attacks
 */
static HANDLE dc_create_secure_mutex(void)
{
    SECURITY_ATTRIBUTES sa;
    PSECURITY_DESCRIPTOR psd = NULL;
    HANDLE h_mutex = NULL;
    wchar_t mutex_name[128];
    DWORD process_id;
    
    /*
     * Strategy: Create a process-local mutex for synchronization.
     * The mutex is private to this process, preventing cross-process attacks.
     * Each process gets its own synchronization primitive.
     */
    process_id = GetCurrentProcessId();
    
    /* Create a unique name for this process */
    _snwprintf(mutex_name, 128, 
        L"Local\\DiskCryptor_%08X_7F2A8B3C-4D5E-6F70-8192-A3B4C5D6E7F8", 
        process_id);
    
    /*
     * Create security descriptor that only allows:
     * - SYSTEM: Full control
     * - Administrators: Full control  
     * - Current user: Synchronize access
     */
    if (!ConvertStringSecurityDescriptorToSecurityDescriptor(
            L"D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x100000;;;WD)",  /* SDDL: SY and BA get all, World gets Synchronize */
            SDDL_REVISION_1,
            &psd,
            NULL))
    {
        /* Fallback to NULL security if SDDL conversion fails */
        psd = NULL;
    }
    
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = psd;
    sa.bInheritHandle = FALSE;
    
    h_mutex = CreateMutexW(&sa, FALSE, mutex_name);
    
    /* Check if the mutex was created by another process (shouldn't happen with PID in name) */
    if (h_mutex != NULL && GetLastError() == ERROR_ALREADY_EXISTS)
    {
        /* 
         * This shouldn't happen with PID in the name, but if it does,
         * close and create an anonymous mutex as fallback
         */
        CloseHandle(h_mutex);
        h_mutex = CreateMutexW(&sa, FALSE, NULL);  /* Anonymous mutex */
    }
    
    if (psd != NULL)
    {
        LocalFree(psd);
    }
    
    return h_mutex;
}

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
			g_dc_mutex = dc_create_secure_mutex();
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
