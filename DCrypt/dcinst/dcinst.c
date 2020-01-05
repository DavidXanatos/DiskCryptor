/*  *
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
#include <tchar.h>
#include "drv_ioctl.h"
#include "drvinst.h"
#include "mbrinst.h"

/*
    -setup  - install or update driver (update bootloader when needed)
	-unins  - uninstall driver
	-unldr  - uninstall bootloader
	-isenc  - check for boot device encryption
	-isboot - check for bootloader on boot device
*/

int APIENTRY _tWinMain(HINSTANCE hInstance,
                       HINSTANCE hPrevInstance,
                       LPTSTR    lpCmdLine,
                       int       nCmdShow)
{
	DWORD status = ERROR_INVALID_FUNCTION;

	if (dc_is_old_runned() != 0) return ERROR_REVISION_MISMATCH;
	dc_open_device();

	if (_tcsicmp(lpCmdLine, _T("-setup")) == 0)
	{
		if (dc_is_driver_installed() != FALSE)
		{
			if ( (status = dc_update_boot(-1)) != ST_OK && status != ST_BLDR_NOTINST )
			{
				return 100000 + status;
			}
			status = dc_update_driver();
		} else {
			status = dc_install_driver();
		}
	}
	if (_tcsicmp(lpCmdLine, _T("-unins")) == 0)
	{
		if (dc_is_driver_installed() == FALSE)
		{
			return ERROR_PRODUCT_UNINSTALLED;
		}
		status = dc_remove_driver();
	}
	if (_tcsicmp(lpCmdLine, _T("-unldr")) == 0)
	{
		if ( (status = dc_unset_mbr(-1)) != ST_OK )
		{
			return 100000 + status; 
		}
	}
	if (_tcsicmp(lpCmdLine, _T("-isboot")) == 0)
	{
		ldr_config conf;
		
		if ( (status = dc_get_mbr_config(-1, NULL, &conf)) != ST_OK )
		{
			return 100000 + status; 
		}
	}		

	if (_tcsicmp(lpCmdLine, _T("-isenc")) == 0)
	{
		vol_inf info;
		DWORD   flags;
		wchar_t boot_dev[MAX_PATH];
		int     is_enc = 0;

		if (dc_open_device() != ST_OK)
		{
			return 100000 + ST_ERROR;
		}

		if (dc_get_boot_device(boot_dev) != ST_OK) {
			boot_dev[0] = 0;
		}
	
		if (dc_first_volume(&info) == ST_OK)
		{
			do
			{
				flags = info.status.flags;

				if ( ((flags & F_SYSTEM) || 
					  (wcscmp(info.device, boot_dev) == 0)) && (flags & F_ENABLED) )
				{
					is_enc = 1;
				}
			} while (dc_next_volume(&info) == ST_OK);
		}
		status = is_enc != 0 ? ST_ENCRYPTED : NO_ERROR;
	}
	return status;
}