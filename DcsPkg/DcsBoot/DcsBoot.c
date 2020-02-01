/** @file
  This is DCS boot loader application

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov
Copyright (c) 2016. VeraCrypt, Mounir IDRASSI 
Copyright (c) 2019. DiskCryptor, David Xanatos

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#include <Uefi.h>
#include <Library/CommonLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DevicePathLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PrintLib.h>
#include <Protocol/DcsBmlProto.h>
#include <DcsConfig.h>
#include <Guid/Gpt.h>
#include <Guid/GlobalVariable.h>

#ifdef _M_X64
#define ARCHdot L"x64."
#define ARCHdotEFI L"x64.efi"
#else
#define ARCHdot L"IA32."
#define ARCHdotEFI L"IA32.efi"
#endif

EFI_GUID          ImagePartGuid;
EFI_GUID          *gEfiExecPartGuid = &ImagePartGuid;
CHAR16            *gEfiExecCmdDefault = L"\\EFI\\Microsoft\\Boot\\Bootmgfw_ms.vc";
CHAR16            *gEfiExecCmdMS = L"\\EFI\\Microsoft\\Boot\\Bootmgfw.efi";
CHAR16            *gEfiExecCmd = NULL;
CHAR8             gDoExecCmdMsg[256];
CONST CHAR8* 	  g_szMsBootString = "bootmgfw.pdb";

//////////////////////////////////////////////////////////////////////////
// EFI boot
//////////////////////////////////////////////////////////////////////////
EFI_STATUS
DoExecCmd() 
{
	EFI_STATUS          res;
	gDoExecCmdMsg[0] = 0;
	res = EfiFindPartByGUID(gEfiExecPartGuid, &gFileRootHandle);
	if (!EFI_ERROR(res)) {
		res = FileOpenRoot(gFileRootHandle, &gFileRoot);
		if (!EFI_ERROR(res)) {
#ifndef NO_BML
            UINT32 lockFlags = 0;
            // Lock EFI boot variables
            InitBml();
            lockFlags = ConfigReadInt("DcsBmlLockFlags", BML_LOCK_SETVARIABLE | BML_SET_BOOTNEXT | BML_UPDATE_BOOTORDER);
            BmlLock(lockFlags);
#endif
			res = EfiExec(NULL, gEfiExecCmd);
			if (EFI_ERROR(res))
				AsciiSPrint(gDoExecCmdMsg, sizeof(gDoExecCmdMsg), "\nCan't exec %s start partition %g\n", gEfiExecCmd, gEfiExecPartGuid);
			else
				AsciiSPrint(gDoExecCmdMsg, sizeof(gDoExecCmdMsg), "\nDone exec %s start partition %g\n", gEfiExecCmd, gEfiExecPartGuid);
		}	else {
			AsciiSPrint(gDoExecCmdMsg, sizeof(gDoExecCmdMsg), "\nCan't open start partition %g\n", gEfiExecPartGuid);
		}
	}	else {
		AsciiSPrint(gDoExecCmdMsg, sizeof(gDoExecCmdMsg), "\nCan't find start partition %g\n", gEfiExecPartGuid);
	}
	return res;
}

EFI_STATUS
ExecMSWindowsLoader() 
{
	if (!EFI_ERROR(FileExist(NULL, gEfiExecCmdDefault)))
		return EfiExec(NULL, gEfiExecCmdDefault);
	else
	{
		if (!EFI_ERROR(FileExist(NULL, gEfiExecCmdMS)))
		{
			/* check if it is Microsoft one */
			UINT8*      fileData = NULL;
			UINTN       fileSize = 0;
			BOOLEAN		bFound = FALSE;
			if (!EFI_ERROR(FileLoad(NULL, gEfiExecCmdMS, &fileData, &fileSize)))
			{
				if ((fileSize > 32768) && !EFI_ERROR(MemoryHasPattern(fileData, fileSize, g_szMsBootString, AsciiStrLen(g_szMsBootString))))
				{
					bFound = TRUE;
				}
			}
			
			MEM_FREE(fileData);
			
			if (bFound)
				return EfiExec(NULL, gEfiExecCmdMS);
		}

		ERR_PRINT(L"Could not find the original Windows loader\r\n");

		return EFI_NOT_READY;
	}
}

//////////////////////////////////////////////////////////////////////////
// BML - Boot Menu Lock
//////////////////////////////////////////////////////////////////////////
#ifndef NO_BML
CHAR16* sDcsBmlEfi = L"EFI\\" DCS_DIRECTORY L"\\DcsBml.dcs";
CHAR16* sDcsBmlEfiDesc = _T(DCS_CAPTION) L"(DcsBml) driver";
CHAR16* sDcsBmlDriverVar = L"DriverDC5B";
UINT16  DcsBmlDriverNum = 0x0DC5B;

VOID
UpdateDriverBmlStart() {
    EFI_STATUS          res;
    UINTN               len;
    UINT32              attr;
    int                 drvInst;
    CHAR16*             tmp = NULL;

    // Driver load selected?
    drvInst = ConfigReadInt("DcsBmlDriver", 0);
    if (drvInst) {
        res = EfiGetVar(sDcsBmlDriverVar, &gEfiGlobalVariableGuid, &tmp, &len, &attr);
        // Driver installed?
        if (EFI_ERROR(res)) {
            // No -> install
            res = BootMenuItemCreate(sDcsBmlDriverVar, sDcsBmlEfiDesc, gFileRootHandle, sDcsBmlEfi, FALSE);
//            ERR_PRINT(L"Drv %s %r\n", sDcsBmlDriverVar, res);
            if (!EFI_ERROR(res)) {
                len = 0;
                res = EfiGetVar(L"DriverOrder", &gEfiGlobalVariableGuid, &tmp, &len, &attr);
                if (!EFI_ERROR(res)) len = len / 2;
                res = BootOrderInsert(L"DriverOrder", len, DcsBmlDriverNum);
            }
//            ERR_PRINT(L"Drv order %d %r\n", len, res);
        }
        MEM_FREE(tmp);
    }
    else {
        // uninstall driver
        res = EfiGetVar(sDcsBmlDriverVar, &gEfiGlobalVariableGuid, &tmp, &len, &attr);
        if (!EFI_ERROR(res)) {
            BootMenuItemRemove(sDcsBmlDriverVar);
            BootOrderRemove(L"DriverOrder", DcsBmlDriverNum);
        }
    }
    MEM_FREE(tmp);
}
#endif

/**
The actual entry point for the application.

@param[in] ImageHandle    The firmware allocated handle for the EFI image.
@param[in] SystemTable    A pointer to the EFI System Table.

@retval EFI_SUCCESS       The entry point executed successfully.
@retval other             Some error occur when executing this entry point.

**/
EFI_STATUS
EFIAPI
DcsBootMain(
   IN EFI_HANDLE        ImageHandle,
   IN EFI_SYSTEM_TABLE  *SystemTable
   )
{
	EFI_STATUS			res;
	UINTN               len;
	UINT32              attr;
	BOOLEAN             searchOnESP = FALSE;
	BOOLEAN             searchMsOnESP = FALSE;
	EFI_GUID			*pEfiExecPartBackup = NULL;
//	EFI_INPUT_KEY       key;

#ifdef DEBUG_BUILD
	OUT_PRINT(L"DcsBoot - DEBUG Build %s %s\n", _T(__DATE__), _T(__TIME__)); 
#endif

	InitBio();		// Initialize Block IO
	res = InitFS();	// Initialize FileSystem
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"InitFS %r\n", res);
	}
	InitConfig(CONFIG_FILE_PATH); // Initialize Config

	if (gConfigDebug) {
		OUT_PRINT(L"FS Root: ");
		EfiPrintDevicePath(gFileRootHandle);
		OUT_PRINT(L"\n");
	}

#ifndef NO_BML
	// BML installed?
	if (EFI_ERROR(InitBml())) {
       // if not -> execute
       EfiExec(NULL, sDcsBmlEfi); // Install the Boot Menu Lock
	}

	UpdateDriverBmlStart();
#endif

	// Dump platform info
	if (EFI_ERROR(FileExist(NULL, L"\\EFI\\" DCS_DIRECTORY L"\\PlatformInfo")) &&
		!EFI_ERROR(FileExist(NULL, L"\\EFI\\" DCS_DIRECTORY L"\\DcsInfo.dcs"))) {
		OUT_PRINT(L"Collecting Platform informations...\n");
		res = EfiExec(NULL, L"\\EFI\\" DCS_DIRECTORY L"\\DcsInfo.dcs");
		if (!EFI_ERROR(res) && 
			!EFI_ERROR(FileExist(NULL, L"\\EFI\\" DCS_DIRECTORY L"\\PlatformInfo"))) {
			KeyWait(L"PlatformInfo generated, rebooting in %02d s\r", 10, 0, 0);
			gST->RuntimeServices->ResetSystem(EfiResetCold, EFI_SUCCESS, 0, NULL);
		}
	}

	// Load all drivers
	EfiExec(NULL, L"\\EFI\\" DCS_DIRECTORY L"\\LegacySpeaker.dcs"); // driver for ordinary speaker (beep)

	res = EfiGetPartGUID(gFileRootHandle, &ImagePartGuid);
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"\nStart partition %r\n", res);
		return res;
	}

	// set default boot partition and file
	EfiSetVar(L"DcsExecPartGuid", NULL, &ImagePartGuid, sizeof(EFI_GUID), EFI_VARIABLE_BOOTSERVICE_ACCESS);
	EfiSetVar(L"DcsExecCmd", NULL, gEfiExecCmdDefault, (StrLen(gEfiExecCmdDefault) + 1) * 2, EFI_VARIABLE_BOOTSERVICE_ACCESS);

	// Authorize
	gBS->SetWatchdogTimer(0, 0, 0, NULL);
	res = EfiExec(NULL, L"\\EFI\\" DCS_DIRECTORY L"\\DcsInt.dcs");

	if (EFI_ERROR(res) && (res != EFI_DCS_POSTEXEC_REQUESTED)) {

      // Clear DcsExecPartGuid before execute OS to avoid problem in VirtualBox with reboot.
      EfiSetVar(L"DcsExecPartGuid", NULL, NULL, 0, EFI_VARIABLE_BOOTSERVICE_ACCESS);
      EfiSetVar(L"DcsExecCmd", NULL, NULL, 0, EFI_VARIABLE_BOOTSERVICE_ACCESS);
      // ERR_PRINT(L"\nDcsInt.efi %r\n",res);
	  if (res == EFI_DCS_SHUTDOWN_REQUESTED)
	  {
		res = EFI_SUCCESS;
		gST->RuntimeServices->ResetSystem(EfiResetShutdown, EFI_SUCCESS, 0, NULL);
	  }
	  else if (res == EFI_DCS_REBOOT_REQUESTED)
	  {
		res = EFI_SUCCESS;
		gST->RuntimeServices->ResetSystem(EfiResetCold, EFI_SUCCESS, 0, NULL);
	  }
	  else if (res == EFI_DCS_HALT_REQUESTED)
	  {
		  EfiCpuHalt();
	  }
	  else if (res == EFI_DCS_USER_CANCELED)
	  {
		  /* If user cancels password prompt, call original Windows loader */
		  res = ExecMSWindowsLoader();
	  }
      return res;
	}

	res = EfiGetVar(L"DcsExecPartGuid", NULL, &gEfiExecPartGuid, &len, &attr);
	if (EFI_ERROR(res)) {
		gEfiExecPartGuid = &ImagePartGuid;
	}
	
	pEfiExecPartBackup = gEfiExecPartGuid;

	res = EfiGetVar(L"DcsExecCmd", NULL, &gEfiExecCmd, &len, &attr);
	if (EFI_ERROR(res)) {
		gEfiExecCmd = gEfiExecCmdDefault;
	}

	searchOnESP = CompareGuid(gEfiExecPartGuid, &ImagePartGuid) &&
		EFI_ERROR(FileExist(NULL, gEfiExecCmd));
		
	searchMsOnESP = CompareGuid(gEfiExecPartGuid, &ImagePartGuid) &&
		EFI_ERROR(FileExist(NULL, gEfiExecCmdMS));
		
	if (gConfigDebug) {
		OUT_PRINT(L"DcsExecPartGuid %g\n", gEfiExecPartGuid);
		OUT_PRINT(L"DcsExecCmd %s\n", gEfiExecCmd);
	}

    // Clear DcsExecPartGuid before execute OS to avoid problem in VirtualBox with reboot.
    EfiSetVar(L"DcsExecPartGuid", NULL, NULL, 0, EFI_VARIABLE_BOOTSERVICE_ACCESS);
    EfiSetVar(L"DcsExecCmd", NULL, NULL, 0, EFI_VARIABLE_BOOTSERVICE_ACCESS);

	// Find new start partition
    ConnectAllEfi(); // this applyes the installed IO hook
	InitBio();
	res = InitFS();

	if (gConfigDebug) {
		KeyWait(L"Attempting to boot Windows in %02d s\r", 30, 0, 0);
		OUT_PRINT(L"\n");
	}

	while (1)
	{
		// Default load of bootmgfw?
		if (searchOnESP) {
			// gEfiExecCmd is not found on start partition. Try from ESP
			EFI_BLOCK_IO_PROTOCOL *bio = NULL;
			EFI_PARTITION_TABLE_HEADER *gptHdr = NULL;
			EFI_PARTITION_ENTRY        *gptEntry = NULL;
			HARDDRIVE_DEVICE_PATH hdp;
			EFI_HANDLE disk;
			if (!EFI_ERROR(res = EfiGetPartDetails(gFileRootHandle, &hdp, &disk))) {
				if ((bio = EfiGetBlockIO(disk)) != NULL) {
					if (!EFI_ERROR(res = GptReadHeader(bio, 1, &gptHdr)) &&
						!EFI_ERROR(res = GptReadEntryArray(bio, gptHdr, &gptEntry))) {
						UINT32 i;
						for (i = 0; i < gptHdr->NumberOfPartitionEntries; ++i) {
							if (CompareGuid(&gptEntry[i].PartitionTypeGUID, &gEfiPartTypeSystemPartGuid)) {
								// select ESP GUID
								CopyGuid(gEfiExecPartGuid, &gptEntry[i].UniquePartitionGUID);
								res = DoExecCmd();
								if(EFI_ERROR(res)) continue;
							}
						}
					}
				}
			}
		}	else {
			res = DoExecCmd();
		}
		
		if(EFI_ERROR(res))
		{
			if (0 == StrCmp (gEfiExecCmd, gEfiExecCmdDefault))
			{
				gEfiExecCmd = gEfiExecCmdMS;
				searchOnESP = searchMsOnESP;
				gEfiExecPartGuid = pEfiExecPartBackup;
			}
			else
				break;
		}
		else
			break;
	}
	ERR_PRINT(L"%a\nStatus -  %r", gDoExecCmdMsg, res);
	EfiCpuHalt();
    return EFI_INVALID_PARAMETER;
}
