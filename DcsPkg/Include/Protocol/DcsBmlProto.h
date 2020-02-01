/** @file
This is DCS boot menu lock protocol

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#ifndef _EFI_DCSBMLPROTO_H
#define _EFI_DCSBMLPROTO_H

#include <Uefi.h>
#include <ProcessorBind.h>
#include <Base.h>

//
// Global Id for DcsBml Interface
// {7FB6D090-8755-43FC-84B5-6E297F9EC1CD}
//
#define EFI_DCSBML_INTERFACE_PROTOCOL_GUID \
  { \
    0x7fb6d090, 0x8755, 0x43fc, 0x84, 0xb5, 0x6e, 0x29, 0x7f, 0x9e, 0xc1, 0xcd \
  }

typedef struct _EFI_DCSBML_PROTOCOL  EFI_DCSBML_PROTOCOL;

#define BML_LOCK_SETVARIABLE    0x1
#define BML_UPDATE_BOOTORDER    0x2
#define BML_SET_BOOTNEXT        0x4

//
// Lock boot menu
//
typedef
EFI_STATUS
(EFIAPI *EFI_BOOT_MENU_LOCK) (
  IN EFI_DCSBML_PROTOCOL                *This,
  IN     UINT32                          LockFlags
  );


//
// Protocol definition
//
struct _EFI_DCSBML_PROTOCOL {
    EFI_BOOT_MENU_LOCK BootMenuLock;
} ;

extern EFI_GUID gEfiDcsBmlProtocolGuid;
#endif
