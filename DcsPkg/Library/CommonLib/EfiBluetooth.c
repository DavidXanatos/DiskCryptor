/** @file
EFI BLUETOOTH helpers

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov
Copyright (c) 2016. VeraCrypt, Mounir IDRASSI

This program and the accompanying materials are licensed and made available
under the terms and conditions of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#include <Library/CommonLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DevicePathLib.h>
#include <Library/PrintLib.h>
#include <Protocol/BluetoothIo.h>
#include <Protocol/BluetoothConfig.h>
#include <Protocol/BluetoothHc.h>

EFI_HANDLE* gBluetoothIoHandles = NULL;
UINTN       gBluetoothIoCount = 0;

EFI_HANDLE* gBluetoothHcHandles = NULL;
UINTN       gBluetoothHcCount = 0;

EFI_HANDLE* gBluetoothConfigHandles = NULL;
UINTN       gBluetoothConfigCount = 0;

EFI_STATUS
InitBluetooth() {
	EFI_STATUS res;
	res = EfiGetHandles(ByProtocol, &gEfiBluetoothIoProtocolGuid, 0, &gBluetoothIoHandles, &gBluetoothIoCount);
	res = EfiGetHandles(ByProtocol, &gEfiBluetoothHcProtocolGuid, 0, &gBluetoothHcHandles, &gBluetoothHcCount);
	res = EfiGetHandles(ByProtocol, &gEfiBluetoothConfigProtocolGuid, 0, &gBluetoothConfigHandles, &gBluetoothConfigCount);
	return res;
}

EFI_STATUS
BluetoothGetIO(
	IN    EFI_HANDLE							Handle,
	OUT   EFI_BLUETOOTH_IO_PROTOCOL**	io
	) {
	if (!io) {
		return EFI_INVALID_PARAMETER;
	}
	return gBS->HandleProtocol(Handle, &gEfiBluetoothIoProtocolGuid, (VOID**)io);
}

