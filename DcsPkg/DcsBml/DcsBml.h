/** @file
This is DCS boot menu lock application

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#ifndef __EFI_DCSBML_H__
#define __EFI_DCSBML_H__

#include <Uefi.h>

//
// Libraries
//
#include <Library/UefiBootServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BaseLib.h>
#include <Library/UefiLib.h>
#include <Library/DevicePathLib.h>
#include <Library/DebugLib.h>

//
// UEFI Driver Model Protocols
//
#include <Protocol/ComponentName2.h>
#include <Protocol/ComponentName.h>

//
// Consumed Protocols
//

//
// Produced Protocols
//
#include <Protocol/DcsBmlProto.h>


//
// Protocol instances
//
extern EFI_COMPONENT_NAME2_PROTOCOL  gDcsBmlComponentName2;
extern EFI_COMPONENT_NAME_PROTOCOL  gDcsBmlComponentName;
extern EFI_DCSBML_PROTOCOL gEfiDcsBmlProtocol;

//
// Include files with function prototypes
//
#include "ComponentName.h"

EFI_STATUS
BootMenuLock(
    IN EFI_DCSBML_PROTOCOL     *This,
    IN UINT32                  LockFlags
    );


#endif
