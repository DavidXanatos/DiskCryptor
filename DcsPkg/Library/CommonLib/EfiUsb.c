/** @file
EFI USB helpers

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
#include <Protocol/UsbIo.h>
#include <Library/BaseMemoryLib.h>

EFI_HANDLE* gUSBHandles = NULL;
UINTN       gUSBCount = 0;
UINTN       gUSBSelect = 0;

EFI_STATUS
InitUsb() {
	EFI_STATUS res;
	res = EfiGetHandles(ByProtocol, &gEfiUsbIoProtocolGuid, 0, &gUSBHandles, &gUSBCount);
	return res;
}

EFI_STATUS
UsbGetIO(
	IN    EFI_HANDLE					Handle,
	OUT   EFI_USB_IO_PROTOCOL**	UsbIo
	) {
	if (!UsbIo) {
		return EFI_INVALID_PARAMETER;
	}
	return gBS->HandleProtocol(Handle, &gEfiUsbIoProtocolGuid, (VOID**)UsbIo);
}

EFI_STATUS
UsbGetIOwithDescriptor(
	IN    EFI_HANDLE					Handle,
	OUT   EFI_USB_IO_PROTOCOL**	UsbIo,
	OUT   EFI_USB_DEVICE_DESCRIPTOR* UsbDescriptor
	) {
	EFI_STATUS                    res;
	if (!UsbIo || !UsbDescriptor) {
		return EFI_INVALID_PARAMETER;
	}
	res = UsbGetIO(Handle, UsbIo);
	if (EFI_ERROR(res)) {
		return res;
	}
	return (*UsbIo)->UsbGetDeviceDescriptor(*UsbIo, UsbDescriptor);
}

EFI_STATUS
UsbGetId(
	IN    EFI_HANDLE		Handle,
	OUT   CHAR8**			id
	)
{
	EFI_STATUS                    res;
	EFI_USB_IO_PROTOCOL           *usbIO = NULL;
	EFI_USB_DEVICE_DESCRIPTOR     usbDescriptor;
	CHAR16*                       serial = NULL;
	CHAR8*                        buff;
	UINTN                         len;
	res = UsbGetIOwithDescriptor(Handle, &usbIO, &usbDescriptor);
	if (EFI_ERROR(res)) {
		return res;
	}
//	Print(L" %02x ", (UINTN)usbDescriptor.StrSerialNumber);
	res = usbIO->UsbGetStringDescriptor(usbIO, 0x409, usbDescriptor.StrSerialNumber, &serial);
	if (!EFI_ERROR(res)) {
		len = 11 + StrLen(serial);
		buff = (CHAR8*)MEM_ALLOC(len);
		AsciiSPrint(buff, len, "%04x_%04x_%s", usbDescriptor.IdVendor, usbDescriptor.IdProduct, serial);
	}	else {
//		Print(L" %04x %r ", res, res);
		len = 10;
		buff = (CHAR8*)MEM_ALLOC(len);
		AsciiSPrint(buff, len, "%04x_%04x", usbDescriptor.IdVendor, usbDescriptor.IdProduct);
	}
	*id = buff;
	return EFI_SUCCESS;
}

//////////////////////////////////////////////////////////////////////////
// Smart card over usb
//////////////////////////////////////////////////////////////////////////

/**
* Send APDU to smart card
* @param[IN] cmd command to send
* @param[IN] cmdLen size of Apdu command
* @param[OUT] resp smart card response
* @param[OUT] respLen smart card response length
* @param[OUT] statusSc smart card status (0x9000 - OK)
* @return  EFI_SUCCESS if send success. Or platform dependent error
*/
EFI_STATUS
UsbScTransmit(
	IN    EFI_USB_IO_PROTOCOL    *UsbIO,
	IN    UINT8*                 cmd,
	IN    UINTN                  cmdLen,
	OUT   UINT8*                 resp,
	OUT   UINTN*                 respLen,
	OUT   UINT16*                statusSc
	) {
	CCID_HEADER_OUT*   oheader = (CCID_HEADER_OUT*)cmd;
	CCID_HEADER_IN*    iheader = (CCID_HEADER_IN*)resp;
	EFI_STATUS         status;
	UINT32             usbres;
	UINTN              len;
	UINTN              resplen;
	// Init CCID HEADER
	SetMem(cmd,sizeof(CCID_HEADER_OUT), 0);
	oheader->bMessageType = PC_to_RDR_XfrBlock_Message;
	oheader->bSeq = 0x99;
	oheader->dwLength = (UINT32)(cmdLen - sizeof(CCID_HEADER_OUT));
	len = cmdLen;
	// Send APDU
	PrintBytes(cmd, len);
	OUT_PRINT(L"\n");
	status = UsbIO->UsbBulkTransfer(UsbIO, 2,cmd, &len, 5000, &usbres);
	if (EFI_ERROR(status)) {
		ERR_PRINT(L"SC send: %r\n", status);
		return status;
	}
	len = *respLen;
	SetMem(resp, len, 0);
	do {
		status = UsbIO->UsbBulkTransfer(UsbIO, 0x81, resp, &len, 5000, &usbres);
	} while ((status == EFI_SUCCESS) && ((iheader->bStatus & 0xC0) == 0x80)); // Timeout? => retry
	if (EFI_ERROR(status)) {
		ERR_PRINT(L"SC resp: %r\n", status);
		return status;
	}
	// Parse response
	resplen = iheader->dwLength;
	*respLen = iheader->dwLength + sizeof(CCID_HEADER_IN);
	*statusSc = (UINT16)(resp[sizeof(CCID_HEADER_IN) + resplen - 1]) | (((UINT16)resp[sizeof(CCID_HEADER_IN) + resplen - 2]) << 8);
	return EFI_SUCCESS;
}
