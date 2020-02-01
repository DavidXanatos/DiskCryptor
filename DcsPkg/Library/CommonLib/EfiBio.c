/** @file
EFI block I/O helpers routines/wrappers

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
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <Protocol/LoadedImage.h>

//////////////////////////////////////////////////////////////////////////
// Print handle info
//////////////////////////////////////////////////////////////////////////

VOID
EfiPrintDevicePath(
   IN EFI_HANDLE handle)
{
   CHAR16                      *StrPath;
   EFI_DEVICE_PATH             *DevicePath;
   OUT_PRINT(L"(%0X): ", handle);
   DevicePath = DevicePathFromHandle(handle);
   if (DevicePath == NULL) {
      ERR_PRINT(L"No path found");
      return;
   }
   StrPath = ConvertDevicePathToText(DevicePath, FALSE, FALSE);
   OUT_PRINT(StrPath);
   MEM_FREE(StrPath);
}

VOID
EfiPrintPath(
   IN EFI_DEVICE_PATH  *DevicePath)
{
   CHAR16 *StrPath;
   StrPath = ConvertDevicePathToText(DevicePath, FALSE, FALSE);
   OUT_PRINT(StrPath);
   MEM_FREE(StrPath);
}

VOID
EfiPrintProtocols(
   IN EFI_HANDLE handle)
{
   EFI_GUID       **guids;
   UINTN          count;
   EFI_STATUS     status;
   status = gBS->ProtocolsPerHandle(handle, &guids, &count);
   if (!EFI_ERROR(status)) {
      UINTN i;
      for (i = 0; i < count; ++i) {
         OUT_PRINT(L"%d: %g\n", i, guids[i]);
      }
      FreePool(guids);
   }
}

//////////////////////////////////////////////////////////////////////////
// Handles
//////////////////////////////////////////////////////////////////////////

EFI_STATUS
EfiGetHandles(
   IN  EFI_LOCATE_SEARCH_TYPE   SearchType,
   IN  EFI_GUID                 *Protocol,    OPTIONAL
   IN  VOID                     *SearchKey,   OPTIONAL
   OUT EFI_HANDLE               **Buffer,
   OUT UINTN                    *Count
   ) 
{
   EFI_STATUS res = EFI_BUFFER_TOO_SMALL;
   UINTN      BufferSize;
	if ((Buffer == NULL) || (Count == NULL)) return EFI_INVALID_PARAMETER;
   if(*Buffer != NULL) MEM_FREE(*Buffer);
   *Count = 0;
   *Buffer = (EFI_HANDLE*) MEM_ALLOC(sizeof(EFI_HANDLE));
   if (*Buffer) {
      BufferSize = sizeof(EFI_HANDLE);
      res = gBS->LocateHandle(SearchType, Protocol, SearchKey, &BufferSize, *Buffer);
      if (res == RETURN_BUFFER_TOO_SMALL) {
         MEM_FREE(*Buffer);
         *Buffer = (EFI_HANDLE*)MEM_ALLOC(BufferSize);
         if (*Buffer == NULL) {
            return EFI_OUT_OF_RESOURCES;
         }
         res = gBS->LocateHandle(SearchType, Protocol, SearchKey, &BufferSize, *Buffer);
         if(res != EFI_SUCCESS) {
            MEM_FREE(*Buffer);
            *Buffer = (EFI_HANDLE*)NULL;
            return res;
         }
      } else if (EFI_ERROR(res)) {
         MEM_FREE(*Buffer);
         *Buffer = (EFI_HANDLE*)NULL;
         return res;
      }
      *Count = (UINTN)(BufferSize / sizeof(EFI_HANDLE));
   }
   return res;
}

EFI_STATUS 
EfiGetStartDevice(
   OUT EFI_HANDLE* handle) 
{
   EFI_STATUS                  Status;
   EFI_LOADED_IMAGE_PROTOCOL   *LoadedImage;
   Status = gBS->HandleProtocol(gImageHandle, &gEfiLoadedImageProtocolGuid, (VOID **)&LoadedImage);
   if (EFI_ERROR(Status)) {
      return Status;
   }
   *handle = LoadedImage->DeviceHandle;
   return Status;
}

//////////////////////////////////////////////////////////////////////////
// Block I/O
//////////////////////////////////////////////////////////////////////////

EFI_BLOCK_IO_PROTOCOL*
EfiGetBlockIO(
   IN EFI_HANDLE handle
   )
{
   EFI_STATUS res;
   EFI_BLOCK_IO_PROTOCOL* blockIOProtocol = NULL;
   res = gBS->HandleProtocol(handle, &gEfiBlockIoProtocolGuid, (VOID**)&blockIOProtocol);
   if (res == RETURN_SUCCESS &&
      blockIOProtocol != NULL &&
      blockIOProtocol->Media->MediaPresent) {
      return blockIOProtocol;
   }
   return NULL;
}


EFI_HANDLE* gBIOHandles;
UINTN       gBIOCount;

EFI_STATUS
InitBio() {
   EFI_STATUS res;
   res = EfiGetHandles(ByProtocol, &gEfiBlockIoProtocolGuid, 0, &gBIOHandles, &gBIOCount);
   return res;
}

BOOLEAN
EfiIsPartition(
	IN    EFI_HANDLE              h
	)
{
	EFI_DEVICE_PATH_PROTOCOL*  node;
	node = DevicePathFromHandle(h);
	if (node == NULL) return FALSE;
	while (!IsDevicePathEnd(node)) {
		if (node->Type == MEDIA_DEVICE_PATH && node->SubType == MEDIA_HARDDRIVE_DP) {
			return TRUE;
		}
		node = NextDevicePathNode(node);
	}
	return FALSE;
}

EFI_STATUS 
EfiGetPartDetails(
   IN    EFI_HANDLE              h,
   OUT   HARDDRIVE_DEVICE_PATH*  dpVolme,
   OUT   EFI_HANDLE*             hDisk)
{
   EFI_DEVICE_PATH_PROTOCOL*  node;
   EFI_DEVICE_PATH_PROTOCOL*  dpVolume;
   EFI_DEVICE_PATH_PROTOCOL*  dpDisk;
   EFI_STATUS                 res;
   dpVolume = DevicePathFromHandle(h);
   dpDisk = DuplicateDevicePath(dpVolume);
   node = (EFI_DEVICE_PATH_PROTOCOL *)dpDisk;
   while (!IsDevicePathEnd(node)) {
      if (node->Type == MEDIA_DEVICE_PATH && node->SubType == MEDIA_HARDDRIVE_DP) {
         CopyMem(dpVolme, node, sizeof(HARDDRIVE_DEVICE_PATH));
         SetDevicePathEndNode(node);
         res = gBS->LocateDevicePath(&gEfiBlockIoProtocolGuid, &dpDisk, hDisk);
         return res;
      }
      node = NextDevicePathNode(node);
   }
   return EFI_NOT_FOUND;
}

EFI_STATUS
EfiGetPartGUID(
	IN    EFI_HANDLE              h,
	OUT   EFI_GUID*               guid)
{
	EFI_DEVICE_PATH_PROTOCOL*  node;
	EFI_DEVICE_PATH_PROTOCOL*  dpVolume;
	if (guid == NULL) return EFI_INVALID_PARAMETER;
	dpVolume = DevicePathFromHandle(h);
	node = (EFI_DEVICE_PATH_PROTOCOL *)dpVolume;
	while (!IsDevicePathEnd(node)) {
		if (node->Type == MEDIA_DEVICE_PATH && node->SubType == MEDIA_HARDDRIVE_DP) {
			HARDDRIVE_DEVICE_PATH* hdpNode = (HARDDRIVE_DEVICE_PATH*)node;
			CopyMem(guid, hdpNode->Signature, sizeof(*guid));
			return EFI_SUCCESS;
		}
		node = NextDevicePathNode(node);
	}
	return EFI_NOT_FOUND;
}

EFI_STATUS
EfiFindPartByGUID(
	IN   EFI_GUID*               guid,
	OUT  EFI_HANDLE*             h
	)
{
	EFI_STATUS                 res;
	EFI_GUID                   guidI;
	UINTN                      i;
	if (guid == NULL || h == NULL) return EFI_INVALID_PARAMETER;
	for (i = 0; i < gBIOCount; ++i) {
		res = EfiGetPartGUID(gBIOHandles[i], &guidI);
		if (!EFI_ERROR(res)) {
			if (CompareMem(&guidI, guid, sizeof(guidI)) == 0) {
				*h = gBIOHandles[i];
				return EFI_SUCCESS;
			}
		}
	}
	return EFI_NOT_FOUND;
}


