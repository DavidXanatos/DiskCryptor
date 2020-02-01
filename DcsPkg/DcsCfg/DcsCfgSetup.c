/** @file
DCS configuration tool. Interactive setup.

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov, Alex Kolotnikov
Copyright (c) 2016. VeraCrypt, Mounir IDRASSI 

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#include <Library/CommonLib.h>
#include <Library/GraphLib.h>
#include <Library/UefiBootServicesTableLib.h>

#include <Library/DevicePathLib.h>
#include <Library/DebugLib.h>

#include "DcsCfg.h"

//////////////////////////////////////////////////////////////////////////
// Interactive setup
//////////////////////////////////////////////////////////////////////////

EFI_STATUS
DcsInteractiveSetup() {
	EFI_STATUS res = EFI_SUCCESS;
	CHAR8		cmd[128];
	InitBio();
	InitFS();
	InitGraph();
	gST->ConOut->EnableCursor(gST->ConOut, TRUE);
	ERR_PRINT(L"\n\rInteractive setup is not implemented! Press enter to continue\n\r");
	AskAsciiString("\rDCS>", cmd, sizeof(cmd), 1, NULL);
	return res;
}
