#ifndef _DCAPI_
#define _DCAPI_

#include "defines.h"

#ifdef DCAPI_DLL
 #define dc_api __declspec(dllexport)
#else
 #define dc_api __declspec(dllimport)
#endif

#ifdef DCAPI_DLL
 dc_api void *dc_extract_rsrc(int *size, int id);
#endif

#ifdef DCAPI_DLL
 extern HINSTANCE g_inst_dll;
 extern DWORD     g_tls_index;
#endif

#endif