/** @file
EFI execute helpers

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov
Copyright (c) 2016. VeraCrypt, Mounir IDRASSI 

This program and the accompanying materials are licensed and made available
under the terms and conditions of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#include <Library/CommonLib.h>

#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DevicePathLib.h>
#include <Library/MemoryAllocationLib.h>

EFI_STATUS 
EfiExec(
   IN    EFI_HANDLE  deviceHandle,
   IN    CHAR16*     path
   )
{
   EFI_STATUS                  res;
   EFI_DEVICE_PATH*            DevicePath;
   EFI_HANDLE                  ImageHandle;
   UINTN                       ExitDataSize;
   CHAR16                      *ExitData;
   if (deviceHandle == NULL) {
      deviceHandle = gFileRootHandle;
   }
   if (!path || !deviceHandle) return EFI_INVALID_PARAMETER;
   DevicePath = FileDevicePath(deviceHandle, path);

   res = gBS->LoadImage(FALSE, gImageHandle, DevicePath, NULL, 0, &ImageHandle);
   if (EFI_ERROR(res)) {
      return res;
   }
   res = gBS->StartImage(ImageHandle, &ExitDataSize, &ExitData);
   if (EFI_ERROR(res)) {
      return res;
   }
   return res;
}

/**
This function will connect all current system handles recursively. The
connection will finish until every handle's child handle created if it have.

@retval EFI_SUCCESS           All handles and it's child handle have been
connected
@retval EFI_STATUS            Return the status of gBS->LocateHandleBuffer().

**/
EFI_STATUS
ConnectAllEfi(
   VOID
   )
{
   EFI_STATUS  Status;
   UINTN       HandleCount;
   EFI_HANDLE  *HandleBuffer;
   UINTN       Index;

   Status = gBS->LocateHandleBuffer(
      AllHandles,
      NULL,
      NULL,
      &HandleCount,
      &HandleBuffer
      );
   if (EFI_ERROR(Status)) {
      return Status;
   }

   for (Index = 0; Index < HandleCount; Index++) {
      Status = gBS->ConnectController(HandleBuffer[Index], NULL, NULL, TRUE);
   }

   if (HandleBuffer != NULL) {
      FreePool(HandleBuffer);
   }

   return EFI_SUCCESS;
}