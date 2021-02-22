/** @file
Interface for DCS

Copyright (c) 2019. DiskCryptor, David Xanatos

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the GNU General Public License, version 3.0 (GPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/GPL-3.0
**/

#include <Uefi.h>
#include "DcsDiskCryptor.h"
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/DevicePathLib.h>
#include <Library/BaseMemoryLib.h>
#include <Guid/Gpt.h>

#include <Library/CommonLib.h>
#include <Library/GraphLib.h>
#include <Library/PasswordLib.h>
#include <Library/DcsCfgLib.h>
#include <Library/DcsIntLib.h>
#include <DcsConfig.h>

#include "include/boot/dc_header.h"
#include "include/boot/boot_hook.h"
#include "include/boot/dc_io.h"
#ifdef SMALL
#include "crypto_small/sha512_small.h"
#else
#include "crypto_fast/sha512.h"
#endif

// X-TODO: support SECTOR_SIZE other than 512 byte

typedef struct _DCRYPT_DISKIO
{
   EFI_DEVICE_PATH            *DevicePath;
   EFI_BLOCK_IO_PROTOCOL      *BlockIo;
   BOOLEAN                    Mount;
   unsigned long              DiskID;
} DCRYPT_DISKIO, *PDCRYPT_DISKIO;

DCRYPT_DISKIO* gDiskIo = NULL;
int gDiskCount = 0;

io_db iodb; // IO/Key Storage

dc_pass gDCryptPassword; // entered password
int gDCryptPwdCode = 1; // entry code
int gDCryptAuthRetry = 100;
UINT8 gDCryptFailOnTimeout = 0;

int gDCryptHwCrypto = 1;

UINT8 gDCryptBootMode = 0;
CHAR8* gDCryptBootPartition = NULL;
unsigned long gDCryptBootDiskID = 0;

bd_data* bootDataBlock = NULL; // data to be passed to the windows driver

VOID CleanSensitiveDataDC(BOOLEAN panic)
{
	MEM_BURN(&iodb, sizeof(iodb));

	MEM_BURN(&gDCryptPassword, sizeof(gDCryptPassword));

	if (panic && bootDataBlock != NULL) {
		MEM_BURN(bootDataBlock, sizeof(*bootDataBlock));
	}
}

//////////////////////////////////////////////////////////////////////////
// DCrypt Boot params memory
//////////////////////////////////////////////////////////////////////////

EFI_STATUS PrepLegacyBootDataBlock()
{
	EFI_STATUS ret = EFI_SUCCESS;
	UINTN addr;

	// Note: the legacy memory range is compatible with an unmodified dcrypt.sys but on some UEFI's its not free :/

	if (bootDataBlock != NULL) return ret;

	// select memory in range 500-640k
	for (addr = 500*1024; addr < 640*1024; addr += PAGE_SIZE) {
		ret = PrepareMemory(addr, sizeof(*bootDataBlock), &bootDataBlock);
		if (!EFI_ERROR(ret)) {
			break;
		}
	}

	if (EFI_ERROR(ret)) {
		return ret;
	}

	// set memory region to be zeroed by the driver
	bootDataBlock->bd_size = sizeof(*bootDataBlock);
	bootDataBlock->bd_base = (u32)addr;

	return ret;
}

EFI_STATUS PrepareBootDataBlock()
{
	EFI_STATUS ret = EFI_SUCCESS;
	UINTN addr;

	// Note: using the new ranges requirers a updated dcrypt.sys

	if (bootDataBlock != NULL) return ret;

	// select memory in range 1-16M in steps of 1M
	for (addr = 0x00100000; addr <= 0x01000000; addr += (256 * PAGE_SIZE)) {
		ret = PrepareMemory(addr, sizeof(*bootDataBlock), &bootDataBlock);
		if (!EFI_ERROR(ret)) {
			break;
		}
	}

	if (EFI_ERROR(ret)) {
		return ret;
	}

	if (gConfigDebug) {
		OUT_PRINT(L"DEBUG: bdb address 0x%08x\n", (u32)addr);
	}
	
	// set memory region to be zeroed by the driver
	bootDataBlock->bd_size = sizeof(*bootDataBlock);
	bootDataBlock->bd_base = (u32)addr;

	return ret;
}

EFI_STATUS SetBootDataBlock()
{
	if (bootDataBlock == NULL)
		return EFI_UNSUPPORTED;

	// setup boot data block signature
	bootDataBlock->sign1 = BDB_SIGN1;
	bootDataBlock->sign2 = BDB_SIGN2;

	// memory region gets already set by PrepareBootDataBlock

	// set password
	bootDataBlock->password.size = gDCryptPassword.size; // in bytes
	CopyMem(bootDataBlock->password.pass, gDCryptPassword.pass, bootDataBlock->password.size);

	// set original realmode interrupt values to be restored, does nothing when old_int13 is 0
	//bootDataBlock->old_int13 = 0;
	//bootDataBlock->old_int15 = 0;

	// Note: all other bdb values are ignored by the windows driver

	return EFI_SUCCESS;
}

//////////////////////////////////////////////////////////////////////////
// Read/Write
//////////////////////////////////////////////////////////////////////////
int hdd_io(int hdd_n, void *buff, u16 sectors, u64 start, int read)
{
	EFI_STATUS           Status;
	DCSINT_BLOCK_IO      *DcsIntBlockIo = NULL;
	PDCRYPT_DISKIO       DCryptDisk = NULL;

	DCryptDisk = GetDiskByNumber(hdd_n);
	
	DcsIntBlockIo = DCryptDisk ? GetBlockIoByProtocol(DCryptDisk->BlockIo) : NULL;
	if (DcsIntBlockIo == NULL) {
		ERR_PRINT(L"\nhdd_io Failed to get BlockIo\n");
		return 0;
	}

	//Print(L"This[0x%x] mid %x BlockIO: lba=%lld, size=%d %r\n", 0, _MediaId, start, sectors * SECTOR_SIZE, 0);
	if (read)
		Status = DcsIntBlockIo->LowRead(DcsIntBlockIo->BlockIo, DcsIntBlockIo->BlockIo->Media->MediaId, start, sectors * SECTOR_SIZE, buff);
	else
		Status = DcsIntBlockIo->LowWrite(DcsIntBlockIo->BlockIo, DcsIntBlockIo->BlockIo->Media->MediaId, start, sectors * SECTOR_SIZE, buff);
	return EFI_ERROR(Status) ? 0 : 1;
}

EFI_STATUS
DCBlockIO_Write(
	IN EFI_BLOCK_IO_PROTOCOL *This,
	IN UINT32                MediaId,
	IN EFI_LBA               Lba,
	IN UINTN                 BufferSize,
	IN VOID                  *Buffer
	)
{
	EFI_STATUS           Status = EFI_SUCCESS;
	DCSINT_BLOCK_IO      *DcsIntBlockIo = NULL;
	VOID				 *writeBuff;

	DcsIntBlockIo = GetBlockIoByProtocol(This);
	if (DcsIntBlockIo == NULL)
		return EFI_NOT_FOUND;

	// use a copy of the buffer to not change the inout buffer, although it works without that also
	writeBuff = MEM_ALLOC(BufferSize);
	if (writeBuff == NULL)
		return EFI_BAD_BUFFER_SIZE;
	CopyMem(writeBuff, Buffer, BufferSize);
		
	//Print(L"This[0x%x] mid %x Write: lba=%lld, size=%d %r\n", This, MediaId, Lba, BufferSize, Status);
	//Print(L"*");
	//if (!hdd_io((int)(UINTN)DcsIntBlockIo->FilterParams, writeBuff, (u16)(BufferSize / SECTOR_SIZE), Lba, 0))
	if (!dc_disk_io((int)(UINTN)DcsIntBlockIo->FilterParams, writeBuff, (u16)(BufferSize / SECTOR_SIZE), Lba, 0))
		Status = EFI_DEVICE_ERROR;

	MEM_FREE(writeBuff);

	return Status;
}

EFI_STATUS
DCBlockIO_Read(
	IN EFI_BLOCK_IO_PROTOCOL *This,
	IN UINT32                MediaId,
	IN EFI_LBA               Lba,
	IN UINTN                 BufferSize,
	OUT VOID                 *Buffer
	)
{
	EFI_STATUS           Status = EFI_SUCCESS;
	DCSINT_BLOCK_IO      *DcsIntBlockIo = NULL;
	
	DcsIntBlockIo = GetBlockIoByProtocol(This);
	if (DcsIntBlockIo == NULL)
		return EFI_NOT_FOUND;
	
	//Print(L"This[0x%x] mid %x ReadBlock: lba=%lld, size=%d %r\n", This, MediaId, Lba, BufferSize, Status);
	//Print(L".");
	//if(!hdd_io((int)(UINTN)DcsIntBlockIo->FilterParams, Buffer, (u16)(BufferSize / SECTOR_SIZE), Lba, 1))
	if(!dc_disk_io((int)(UINTN)DcsIntBlockIo->FilterParams, Buffer, (u16)(BufferSize / SECTOR_SIZE), Lba, 1))
		Status = EFI_DEVICE_ERROR;
	
	return Status;
}

//////////////////////////////////////////////////////////////////////////
// Mounting
//////////////////////////////////////////////////////////////////////////
EFI_STATUS
EnumDisks()
{
	UINTN i, j;
	UINTN count = 0;
	UINTN count2 = 0;

	for (i = 0; i < gBIOCount; ++i) {
		if (!EfiIsPartition(gBIOHandles[i])) count++;
		else								count2++;
	}

	if (count == 0)
		return EFI_NOT_FOUND;

	if (gConfigDebug) {
		OUT_PRINT(L"DEBUG: found %d disks and %d partitions\n", count, count2);
	}

	gDiskCount = (int)count;
	gDiskIo = MEM_ALLOC(sizeof(DCRYPT_DISKIO) * gDiskCount);
	if (gDiskIo == NULL) 
		return EFI_OUT_OF_RESOURCES;

	for (i = 0, j = 0; i < gBIOCount; ++i) {
		if (!EfiIsPartition(gBIOHandles[i])) {
			gDiskIo[j].DevicePath = DevicePathFromHandle(gBIOHandles[i]);
			gDiskIo[j].BlockIo = EfiGetBlockIO(gBIOHandles[i]);
			gDiskIo[j].DiskID = 0;
			gDiskIo[j++].Mount = FALSE;
		}
	}

	return EFI_SUCCESS;
}

int
FindDiskNumber(EFI_DEVICE_PATH* disk)
{
	for (int i = 0; i <= gDiskCount; i++) {
		if (CompareMem(disk, gDiskIo[i].DevicePath, GetDevicePathSize(gDiskIo[i].DevicePath)) == 0) {
			return (i + 1); // disk numbers start at 1, 0 means invalid
		}
	}
	return 0;
}

PDCRYPT_DISKIO
GetDiskByNumber(int number) 
{
	if (number == 0 || number > gDiskCount)
		return NULL;
	return &gDiskIo[number - 1];
}

EFI_STATUS
PartitionTryDecrypt()
{
	EFI_STATUS       ret = EFI_SUCCESS;
	UINTN            i;
	HARDDRIVE_DEVICE_PATH part;
	EFI_HANDLE       disk;
	EFI_DEVICE_PATH* disk_path;
	DCRYPT_DISKIO*   dc_disk;
	int              disk_num;
	int              found = 0;
	int              retry = gDCryptAuthRetry;

	MEM_BURN(&gDCryptPassword, sizeof(gDCryptPassword)); // zero memory
	do {
		// password prompt
		DCAskPwd(AskPwdLogin, &gDCryptPassword);

		if (gDCryptPwdCode == AskPwdRetCancel) {
			return EFI_DCS_USER_CANCELED;
		}
		if (gDCryptPwdCode == AskPwdRetTimeout) {
			if (gDCryptFailOnTimeout) {
				break;
			}
			return EFI_DCS_USER_TIMEOUT;
		}

		OUT_PRINT(L"%a\n", gDCryptStartMsg);

		dc_header  header;	
		mount_inf *mount;
		
		// check all partitions if the password works for one
		for (i = 0; i < gBIOCount; ++i) {

			ret = EfiGetPartDetails(gBIOHandles[i], &part, &disk);
			if (EFI_ERROR(ret)) continue; // means its not a partition same as EfiIsPartition() == FALSE

			disk_path = DevicePathFromHandle(disk);
			disk_num = FindDiskNumber(disk_path);

			dc_disk = GetDiskByNumber(disk_num);

			ret = dc_disk ? dc_disk->BlockIo->ReadBlocks(dc_disk->BlockIo, dc_disk->BlockIo->Media->MediaId, part.PartitionStart, DC_AREA_SIZE, (UINT8*)&header) : EFI_NOT_FOUND;
			if (EFI_ERROR(ret)) {
				ERR_PRINT(L"Can't read partition starting at %llu\n", part.PartitionStart);
				continue;
			}

			if (dc_decrypt_header(&header, &gDCryptPassword) == 0) {
				continue;
			}
			found++;

			if (gConfigDebug) {
				OUT_PRINT(L"Found Encrypted Partition ");
				OUT_PRINT(L"%d", part.PartitionNumber);
				//EfiPrintPath(disk_path);
				OUT_PRINT(L" on disk %d\n", disk_num);
			}

			if ( (iodb.n_mount >= MOUNT_MAX) ||
				 (iodb.n_key >= MOUNT_MAX - ((header.flags & VF_REENCRYPT) != 0)) ||
				 (disk_num > 255) ) // hdd_n is only u8
			{
				ERR_PRINT(L"Not enough memory to mount all partitions\n");
				continue;
			}
			mount = &iodb.p_mount[iodb.n_mount];
			
			mount->hdd_n    = (u8)disk_num;
			mount->begin    = part.PartitionStart;
			mount->end      = part.PartitionStart + part.PartitionSize;
			mount->size     = part.PartitionSize;

			mount->flags    = header.flags;
			mount->tmp_size = header.tmp_size / SECTOR_SIZE;
			if (header.flags & VF_STORAGE_FILE) {
				mount->stor_off = header.stor_off / SECTOR_SIZE;
			} else {
				mount->stor_off = (mount->size - sizeof(dc_header)) / SECTOR_SIZE;
			}
			mount->disk_id  = header.disk_id;
		
			mount->d_key      = &iodb.p_key[iodb.n_key++];
			mount->d_key->alg = (u8)header.alg_1;
			autocpy(mount->d_key->key, header.key_1, PKCS_DERIVE_MAX);
		
			if (header.flags & VF_REENCRYPT) {
				mount->o_key      = &iodb.p_key[iodb.n_key++];
				mount->o_key->alg = (u8)header.alg_2;
				autocpy(mount->o_key->key, header.key_2, PKCS_DERIVE_MAX);
			}

			gDiskIo[disk_num - 1].DiskID = header.disk_id;
			gDiskIo[disk_num - 1].Mount = TRUE;
			iodb.n_mount++;
		}

		// clear data
		MEM_BURN(&header,  sizeof(dc_header));

		if (found > 0 || gDCryptPwdCode == AskPwdForcePass) {
			OUT_PRINT(L"%a\n", gDCryptSuccessMsg);
			return EFI_SUCCESS;
		}
		else {
			ERR_PRINT(L"%a\n", gDCryptErrorMsg);
			// clear previous failed authentication information
			//MEM_BURN(&gDCryptPassword, sizeof(gDCryptPassword));
		}

	} while (--retry > 0);

	return RETURN_ABORTED;
}

EFI_STATUS
MountDisks(
	IN EFI_HANDLE ImageHandle,
	IN EFI_SYSTEM_TABLE *SystemTable)
{
	EFI_STATUS ret = EFI_SUCCESS;

	if (iodb.n_mount == 0) return ret; // nothign to do just exit

	for (int i = 0; i < gDiskCount; i++) {
		if (gDiskIo[i].Mount) {
			if (gConfigDebug) {
				OUT_PRINT(L"Preparing hooking for disk %d\n", i + 1);
			}
			ret = AddCryptoMount(gDiskIo[i].DevicePath, DCBlockIO_Read, DCBlockIO_Write, (VOID*)(UINTN)(i + 1));
			if (EFI_ERROR(ret)) {
				ERR_PRINT(L"Mount %r\n", ret);
			}
		}
	}
	
	ret = DscInstallHook(ImageHandle, SystemTable);
	return ret;
}

EFI_STATUS
SelectBootPartition()
{
	EFI_STATUS   ret = EFI_SUCCESS;
	EFI_GUID     guid;

	if (gDCryptBootPartition[0] != L'\0')
	{
		DcsAsciiStrToGuid(&guid, gDCryptBootPartition);
		EFI_HANDLE h;
		ret = EfiFindPartByGUID(&guid, &h);
		if (!EFI_ERROR(ret)) {
			EfiSetVar(L"DcsExecPartGuid", NULL, &guid, sizeof(EFI_GUID), EFI_VARIABLE_BOOTSERVICE_ACCESS);
			//EfiSetVar(L"DcsExecCmd", NULL, &ExecCmd, (StrLen((CHAR16*)&ExecCmd) + 1) * 2, EFI_VARIABLE_BOOTSERVICE_ACCESS);
			return EFI_SUCCESS;
		}
	}

	if (gDCryptBootMode == BT_MBR_BOOT) {
		ret = EfiGetPartGUID(gFileRootHandle, &guid);
	}
	else
	{
		BOOLEAN found = FALSE;

		for (int d = 0; d < gDiskCount && !found; d++) {
			DCRYPT_DISKIO* dc_disk = &gDiskIo[d];
			EFI_PARTITION_TABLE_HEADER *gptHdr = NULL;
			EFI_PARTITION_ENTRY        *gptEntry = NULL;
			// Note: we are testing only EFI partitions here as windows can't boot in EFI mode from a MBR disk
			if (dc_disk->BlockIo != NULL &&
				!EFI_ERROR(ret = GptReadHeader(dc_disk->BlockIo, 1, &gptHdr)) &&
				!EFI_ERROR(ret = GptReadEntryArray(dc_disk->BlockIo, gptHdr, &gptEntry))) 
			{
				for (UINT32 i = 0; i < gptHdr->NumberOfPartitionEntries; ++i) {
					if (CompareGuid(&gptEntry[i].PartitionTypeGUID, &gEfiPartTypeSystemPartGuid)) {
						if (gDCryptBootMode == BT_AP_PASSWORD) {
							if (dc_disk->Mount == FALSE) continue;
						}
						if (gDCryptBootMode == BT_DISK_ID) {
							if(dc_disk->DiskID != gDCryptBootDiskID) continue;
						}
						// else if (gDCryptBootMode == BT_MBR_FIRST)
						CopyGuid(&guid, &gptEntry[i].UniquePartitionGUID);
						found = TRUE;
					}
				}
			}
		}

		if (!found) {
			ERR_PRINT(L"Failed to find boot partition\n");
			ret = EFI_NOT_FOUND;
		}
	}

	if (EFI_ERROR(ret)) {
		return ret;
	}
	
	if (gConfigDebug) {
		OUT_PRINT(L"Selected boot partition: %g\n", &guid);
	}

	EfiSetVar(L"DcsExecPartGuid", NULL, &guid, sizeof(EFI_GUID), EFI_VARIABLE_BOOTSERVICE_ACCESS);
	//EfiSetVar(L"DcsExecCmd", NULL, &ExecCmd, (StrLen((CHAR16*)&ExecCmd) + 1) * 2, EFI_VARIABLE_BOOTSERVICE_ACCESS);
	return EFI_SUCCESS;
}

typedef struct _ldr_version {
	unsigned long sign1;         // signature to search for bootloader in memory
	unsigned long sign2;         // signature to search for bootloader in memory
	unsigned long ldr_ver;       // bootloader version
} ldr_version;

#define CFG_SIGN1 0x1434A669
#define CFG_SIGN2 0x7269DA46

ldr_version ver = {
	CFG_SIGN1, CFG_SIGN2,
	DCS_VERSION
};


//////////////////////////////////////////////////////////////////////////
// DiskCryptor Entry Point
//////////////////////////////////////////////////////////////////////////
EFI_STATUS
DcsDiskCryptor(
	IN EFI_HANDLE ImageHandle,
	IN EFI_SYSTEM_TABLE *SystemTable)
{
	EFI_STATUS ret = EFI_SUCCESS;

	if (gConfigDebug) {
		OUT_PRINT(L"DiskCryptor UEFI bootloader version: %d.%02d\n", ver.ldr_ver / 100, ver.ldr_ver % 100);
	}

	// setup clear data inplementation callabck
	SetCleanSensitiveDataFunc(CleanSensitiveDataDC);

	// Load auth parameters
	DCAuthLoadConfig();

	// init structs
	zeroauto(&iodb, sizeof(iodb));

	// init crypto 
	gDCryptHwCrypto = xts_init(gDCryptHwCrypto);
	if (gConfigDebug && gDCryptHwCrypto != 0) {
		ERR_PRINT(L"Using Hardware Crypt, Type %d\n", gDCryptHwCrypto);
	}

	// enum disks
	ret = EnumDisks();
	if (EFI_ERROR(ret)) {
		ERR_PRINT(L"No disks found: %r\n", ret);
		return ret;
	}

	// prepare memory for boot data
	ret = PrepareBootDataBlock();
	if (EFI_ERROR(ret)) {
		ERR_PRINT(L"Failed to allocate required memory range for boot params: %r\n", ret);
		return ret;
	}

	// prompt for password nd try decrypt partitions
	ret = PartitionTryDecrypt();
	// Reset Console buffer
	gST->ConIn->Reset(gST->ConIn, FALSE);

	if (EFI_ERROR(ret)) {
		return ret; // returning error will trigger clearence of sensitive data
	}

	// set boot data values
	ret = SetBootDataBlock();
	if (EFI_ERROR(ret)) {
		ERR_PRINT(L"Can not set boot params for driver: %r\n", ret);
		return ret;
	}

	// after have set up iodb and gDCryptPassword we dont longer need the password, so clear it from memory
	MEM_BURN(&gDCryptPassword, sizeof(gDCryptPassword));

	// Install hooks
	ret = MountDisks(ImageHandle, SystemTable);
	if (EFI_ERROR(ret)) {
		ERR_PRINT(L"Bind %r\n", ret);
		return ret;
	}

	// Select boot partition
	ret = SelectBootPartition();
	if (EFI_ERROR(ret)) {
		ERR_PRINT(L"Select %r\n", ret);
		return ret;
	}

	return EFI_SUCCESS;
}

//////////////////////////////////////////////////////////////////////////
// UI section
//////////////////////////////////////////////////////////////////////////

int gDCryptTouchInput = 0;
UINT8 gDCryptAutoLogin = 0;
CHAR16* gDCryptAutoPassword = L"\0";
CHAR16*	gDCryptKeyFilePath = L"\0";

char* gDCryptPasswordMsg = NULL;
char* gDCryptStartMsg = NULL;
char* gDCryptSuccessMsg = NULL;
char* gDCryptErrorMsg = NULL;

VOID DCAuthLoadConfig()
{
// Main:
	// Keyboard Layout
		// QWERTY	0
		// QWERTZ	1
		// AZERTY	2
	gKeyboardLayout = ConfigReadInt("KeyboardLayout", 0);

	// Booting Method
		// First disk MBR								// BT_MBR_FIRST    2
		// First partition with appropriate password	// BT_AP_PASSWORD  4
		// Specified partition							// BT_DISK_ID      5
		// (Boot disk MBR)								// BT_MBR_BOOT     1 // default
		// (Active partition)							// BT_ACTIVE       3 // not supported in EFI mode
	gDCryptBootMode = (UINT8)ConfigReadInt("BootMode", 1);
	if (gDCryptBootMode == BT_ACTIVE || (gDCryptBootMode == BT_MBR_BOOT && gExternMode)) {
		gDCryptBootMode = BT_AP_PASSWORD;
	}
	gDCryptBootDiskID = (unsigned int)ConfigReadInt64("BootDiskID", 0);
	gDCryptBootPartition = ConfigReadString("BootPartition", "", NULL, 36 + 1);	// new

// Authentication:
	// Authenticaltion Method
		// Password and bootauth keyfile 3
		// Password request 1
		// Embedded bootauth keyfile 2
	gDCryptAutoLogin = (UINT8)ConfigReadInt("AutoLogin", 0); // set 1 and keep AutoPassword empty for key file only
	gDCryptAutoPassword = ConfigReadStringW("AutoPassword", L"", NULL, MAX_PASSWORD + 1);
	gDCryptKeyFilePath = ConfigReadStringW("KeyFilePath", L"", NULL, MAX_MSG);

	// Picture Password - new
	gDCryptTouchInput = ConfigReadInt("TouchInput", 0);
	gPasswordPictureFileName = ConfigReadStringW("PasswordPicture", L"\\EFI\\" DCS_DIRECTORY L"\\login.bmp", NULL, MAX_MSG); // h1630 v1090
	gPasswordPictureChars = ConfigReadString("PictureChars", gPasswordPictureCharsDefault, NULL, MAX_MSG);
	gPasswordPictureCharsLen = AsciiStrnLenS(gPasswordPictureChars, MAX_MSG);
	gPasswordVisible = (UINT8)ConfigReadInt("AuthorizeVisible", 0);   // show chars
	gPasswordHideLetters = ConfigReadInt("PasswordHideLetters", 0);   // always show letters in touch points
	gPasswordShowMark = ConfigReadInt("AuthorizeMarkTouch", 0);       // show touch points

	//
	//gPlatformLocked = ConfigReadInt("PlatformLocked", 0); // extern
	//gTPMLocked = ConfigReadInt("TPMLocked", 0); // extern
	//gTPMLockedInfoDelay = ConfigReadInt("TPMLockedInfoDelay", 9); // extern
	//gSCLocked = ConfigReadInt("SCLocked", 0); // extern

	// Password Prompt Message
	gDCryptPasswordMsg = ConfigReadString("PasswordMsg", "Enter password:", NULL, MAX_MSG);

	// Display Entered Password * or hide completly
	gPasswordProgress = (UINT8)ConfigReadInt("AuthorizeProgress", 1); // print "*"

	// Authentication TimeOut
	gPasswordTimeout = (UINT8)ConfigReadInt("PasswordTimeout", 180);   // If no password for <seconds> => <ESC>
	// cancel timeout when any key pressed [ ] - DCS always behaves this way

	// Trying password message - new
	gDCryptStartMsg = MEM_ALLOC(MAX_MSG); 
	ConfigReadString("AuthStartMsg", "Authorizing...", gDCryptStartMsg, MAX_MSG);

	// Success message - new
	gDCryptSuccessMsg = MEM_ALLOC(MAX_MSG); 
	ConfigReadString("AuthSuccessMsg", "Password correct", gDCryptSuccessMsg, MAX_MSG);

// Invalid Password:
	// use incorrect action if no password entered [ ]
	gDCryptFailOnTimeout = (UINT8)ConfigReadInt("FailOnTimeout", 0);

	// Invalid Password message
	gDCryptErrorMsg = MEM_ALLOC(MAX_MSG); 
	ConfigReadString("AuthFailedMsg", "Password incorrect", gDCryptErrorMsg, MAX_MSG);

	// Invalid Password action			ConfigReadString("ActionFailed", ...
		// Halt system					"halt"      EFI_DCS_HALT_REQUESTED
		// Reboot system				"reboot"    EFI_DCS_REBOOT_REQUESTED
		// Boot from active partition	"cancel"	EFI_DCS_USER_CANCELED
		// Exit to BIOS
		// Retry authentication			"exit"  &&  gDCryptAuthRetry > 0; else gDCryptAuthRetry == 0;
		// Load Boot Disk MBR			"cancel"	EFI_DCS_USER_CANCELED
		//								"shutdown"  EFI_DCS_SHUTDOWN_REQUESTED

	// Authentication Tries - new
	gDCryptAuthRetry = ConfigReadInt("AuthorizeRetry", 100);

// Other

	gDCryptHwCrypto = ConfigReadInt("UseHardwareCrypto", 1);
}

VOID DCAskPwd(IN UINTN pwdType, OUT dc_pass* dcPwd) 
{
	BOOLEAN pwdReady;

	do {
		pwdReady = TRUE;
		/*if (pwdType == AskPwdNew) {
			EFI_INPUT_KEY key;
			key = KeyWait(L"Press 'c' to configure, others to skip %1d\r", 9, 0, 0);
			if (key.UnicodeChar == 'c') {
				PMENU_ITEM          item = NULL;
				EFI_STATUS          res;
				OUT_PRINT(L"\n%V%a %a configuration%N\n", DC_APP_NAME, DC_PRODUCT_VER);
				if (gCfgMenu == NULL) CfgMenuCreate();
				do {
					DcsMenuPrint(gCfgMenu);
					item = NULL;
					key.UnicodeChar = 0;
					while (item == NULL) {
						item = gCfgMenu;
						key = GetKey();
						while (item != NULL) {
							if (item->Select == key.UnicodeChar) break;
							item = item->Next;
						}
					}
					OUT_PRINT(L"%c\n", key.UnicodeChar);
					res = item->Action(item->Context);
					if (EFI_ERROR(res)) {
						ERR_PRINT(L"%r\n", res);
					}
				} while (gCfgMenuContinue);
				if ((gDCryptPwdCode == AskPwdRetCancel) || (gDCryptPwdCode == AskPwdRetTimeout)) {
					return;
				}
			}
		}*/

		if (gDCryptAutoLogin) {
			gDCryptAutoLogin = 0;
			gDCryptPwdCode = AskPwdRetLogin;
			if (!EFI_ERROR(StrCpyS(dcPwd->pass, MAX_PASSWORD, gDCryptAutoPassword))) {
				dcPwd->size = (int)StrLen(gDCryptAutoPassword);
			}
		}
		else {
			if (gDCryptTouchInput == 1 &&
				gGraphOut != NULL &&
				((gTouchPointer != NULL) || (gTouchSimulate != 0))) {
				AskPictPwdInt(pwdType, sizeof(dcPwd->pass), dcPwd->pass, &dcPwd->size, &gDCryptPwdCode, TRUE);
			}
			else {
				/*switch (pwdType) {
				case AskPwdNew:
					OUT_PRINT(L"New password:");
					break;
				case AskPwdConfirm:
					OUT_PRINT(L"Confirm password:");
					break;
				case AskPwdLogin:
				default:*/
					OUT_PRINT(L"%a", gDCryptPasswordMsg);
				/*	break;
				}*/
				AskConsolePwdInt(&dcPwd->size, dcPwd->pass, &gDCryptPwdCode, sizeof(dcPwd->pass), gPasswordVisible, TRUE);
			}

			if ((gDCryptPwdCode == AskPwdRetCancel) || (gDCryptPwdCode == AskPwdRetTimeout)) {
				return;
			}
		}
		
		if (gDCryptKeyFilePath[0] != L'\0') {
			EFI_STATUS ret = DCApplyKeyFile(dcPwd, gDCryptKeyFilePath);
			if (EFI_ERROR(ret)){
				ERR_PRINT(L"Failed to apply KeyFile: %r\n", ret);
				gDCryptPwdCode = AskPwdRetCancel;
			}
		}

		/*
		if (gSCLocked) {
			ERR_PRINT(L"Smart card is not configured\n");
		}

		if (gPlatformLocked) {
			if (gPlatformKeyFile == NULL) {
				ERR_PRINT(L"Platform key file is absent\n");
			}
			else {
				ApplyKeyFile(dcPwd, gPlatformKeyFile, gPlatformKeyFileSize);
			}
		}

		if (gTPMLocked) {
			if (gTpm != NULL) {
				pwdReady = !EFI_ERROR(gTpm->Apply(gTpm, dcPwd));
				if (!pwdReady) {
					ERR_PRINT(L"TPM error: DCS configuration ");
					if (!gTpm->IsConfigured(gTpm)) {
						ERR_PRINT(L"absent\n");
					}
					else {
						ERR_PRINT(L"locked\n");
					}
				}
			}	else {
				ERR_PRINT(L"No TPM found\n");
			}
		}
		*/
	} while (!pwdReady);
}

EFI_STATUS
DCApplyKeyFile(
	IN OUT dc_pass* password,
	IN     CHAR16*   keyfilePath
)
{
	EFI_STATUS  ret = EFI_SUCCESS;
	UINT8*      fileData = NULL;
	UINTN       fileSize = 0;

	ret = FileLoad(NULL, keyfilePath, &fileData, &fileSize);
	if (EFI_ERROR(ret)) {
		return ret;
	}

	return DCApplyKeyData(password, fileData, fileSize);
}

EFI_STATUS
DCApplyKeyData(
	IN OUT dc_pass* password,
	UINT8*      fileData,
	UINTN       fileSize
)
{
	sha512_ctx sha;
	u8         hash[SHA512_DIGEST_SIZE];

	sha512_init(&sha);
#ifdef SMALL
	sha512_add(&sha, fileData, (unsigned long)fileSize);
#else
	sha512_hash(&sha, fileData, (unsigned long)fileSize);
#endif
	sha512_done(&sha, hash);

	// mix the keyfile hash and password
	for (UINTN i = 0; i < (SHA512_DIGEST_SIZE / sizeof(u32)); i++) {
		p32(password->pass)[i] += p32(hash)[i];
	}
	password->size = max(password->size, SHA512_DIGEST_SIZE);

	// prevent leaks
	zeroauto(hash, sizeof(hash));
	zeroauto(&sha, sizeof(sha));

	return EFI_SUCCESS;
}

/*VOID DumpBlob(UINT8* sectorData, UINTN sectorSize)
{
	for (UINTN idx = 0; idx < sectorSize; idx++)
	{
		UINT8 c = sectorData[idx];
		if (c > 0x1f && c < 0x7f)
			OUT_PRINT(L"%c", c);
		else
			OUT_PRINT(L"_");
	}
	OUT_PRINT(L"\n");
}*/