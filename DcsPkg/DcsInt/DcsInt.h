/** @file
Block R/W interceptor

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov
Copyright (c) 2016. VeraCrypt, Mounir IDRASSI 
Copyright (c) 2019. DiskCryptor, David Xanatos

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#ifndef __DCSINT_H__
#define __DCSINT_H__

#include <Uefi.h>

typedef EFI_STATUS (*DCS_IMPL)(IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE *SystemTable);

/**
  VeraCrypt Implementation

  @param[in] ImageHandle    The firmware allocated handle for the EFI image.
  @param[in] SystemTable    A pointer to the EFI System Table.

  @retval EFI_SUCCESS       The entry point executed successfully.
  @retval other             Some error occur when executing this entry point.

**/
EFI_STATUS
DcsVeraCrypt(
  IN EFI_HANDLE ImageHandle,
  IN EFI_SYSTEM_TABLE *SystemTable
  );

/**
  DiskCryptor Implementation

  @param[in] ImageHandle    The firmware allocated handle for the EFI image.
  @param[in] SystemTable    A pointer to the EFI System Table.

  @retval EFI_SUCCESS       The entry point executed successfully.
  @retval other             Some error occur when executing this entry point.

**/
EFI_STATUS
DcsDiskCryptor(
  IN EFI_HANDLE ImageHandle,
  IN EFI_SYSTEM_TABLE *SystemTable
  );

#endif