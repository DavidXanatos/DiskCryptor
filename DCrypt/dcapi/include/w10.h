#ifndef _W10_
#define _W10_

#include "dcapi.h"

int dc_api is_w10_reflect_supported();
int dc_api update_w10_reflect_driver();
int dc_api remove_w10_reflect_driver();
int dc_api install_dc_offline(const wchar_t* windows_path);
int dc_api remove_dc_offline(const wchar_t* windows_path);

#endif