/** @file
DiskCryptor configuration menu

Copyright (c) 2026. DiskCryptor, David Xanatos

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the GNU General Public License, version 3.0 (GPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/GPL-3.0
**/

#ifndef _DCSCONFIGMENU_H_
#define _DCSCONFIGMENU_H_

#include <Uefi.h>

VOID
DcsShowHelp(
	VOID
);

// Returns TRUE if values were applied (Enter), FALSE if discarded (Esc)
BOOLEAN
DcsConfigMenuShow(
	VOID
);

#endif // _DCSCONFIGMENU_H_
