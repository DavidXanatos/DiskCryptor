/** @file
This is DCS configuration tool. (EFI shell application/TODO:wizard)

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov
Copyright (c) 2016. VeraCrypt, Mounir IDRASSI 

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#include <Library/CommonLib.h>
#include <Library/GraphLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/ShellLib.h>

#include <Library/DevicePathLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <Guid/GlobalVariable.h>

#include "DcsCfg.h"
#include <Library/PasswordLib.h>
#include <DcsConfig.h>

#include "common/Tcdefs.h"
#include "crypto/cpu.h"
#include "Library/DcsCfgLib.h"
#include "../Include/Library/DcsTpmLib.h"


//////////////////////////////////////////////////////////////////////////
// Main
//////////////////////////////////////////////////////////////////////////
#define OPT_DISK_CHECK					L"-dc"
#define OPT_DISK_LIST					L"-dl"
#define OPT_DISK_START					L"-ds"
#define OPT_DISK_END						L"-de"
#define OPT_DISK_BOOT					L"-db"
#define OPT_USB_LIST						L"-ul"
#define OPT_USB_SELECT					L"-us"
#define OPT_SC_APDU						L"-scapdu"
#define OPT_TOUCH_LIST					L"-tl"
#define OPT_TOUCH_TEST					L"-tt"
#define OPT_GRAPH_LIST					L"-gl"
#define OPT_GRAPH_DEVICE				L"-gd"
#define OPT_GRAPH_MODE					L"-gm"
#define OPT_BEEP_LIST					L"-bl"
#define OPT_BEEP_TEST					L"-bt"
#define OPT_SETUP							L"-setup"

#define OPT_AUTH_ASK						L"-aa"
#define OPT_AUTH_CREATE_HEADER		L"-ach"
#define OPT_VOLUME_ENCRYPT				L"-vec"
#define OPT_VOLUME_DECRYPT				L"-vdc"
#define OPT_VOLUME_CHANGEPWD			L"-vcp"

#define OPT_RND							L"-rnd"
#define OPT_RND_GEN						L"-rndgen"
#define OPT_RND_LOAD						L"-rndload"
#define OPT_RND_SAVE						L"-rndsave"

#define OPT_PARTITION_LIST				L"-pl"
#define OPT_PARTITION_FILE				L"-pf"
#define OPT_PARTITION_SAVE				L"-ps"
#define OPT_PARTITION_ZERO				L"-pz"
#define OPT_PARTITION_APPLY			L"-pa"
#define OPT_PARTITION_ENCRYPT			L"-pe"
#define OPT_PARTITION_DECRYPT			L"-pd"
#define OPT_PARTITION_IDX_TEMPLATE	L"-pnt"
#define OPT_PARTITION_HIDE				L"-phide"
#define OPT_PARTITION_EDIT				L"-pedt"
#define OPT_PARTITION_EDIT_EXEC		L"-pexec"
#define OPT_PARTITION_RND_LOAD		L"-prndload"
#define OPT_PARTITION_RND_SAVE		L"-prndsave"
#define OPT_PARTITION_EDIT_PWD_CACHE L"-pwdcache"
#define OPT_KEYFILE_PLATFORM			L"-kp"

#define OPT_SECREGION_MARK				L"-srm"
#define OPT_SECREGION_WIPE				L"-srw"
#define OPT_SECREGION_ADD				L"-sra"
#define OPT_SECREGION_DUMP				L"-srdump"
#define OPT_WIPE							L"-wipe"

#define OPT_OS_DECRYPT					L"-osdecrypt"
#define OPT_OS_RESTORE_KEY				L"-osrestorekey"

#define OPT_TPM_PCRS						L"-tpmpcrs"
#define OPT_TPM_NVLIST					L"-tpmnvlist"
#define OPT_TPM_CFG						L"-tpmcfg"

#define OPT_TBL_FILE						L"-tbf"
#define OPT_TBL_ZERO						L"-tbz"
#define OPT_TBL_LIST						L"-tbl"
#define OPT_TBL_NAME						L"-tbn"
#define OPT_TBL_DELETE					L"-tbd"
#define OPT_TBL_APPEND					L"-tba"
#define OPT_TBL_DUMP						L"-tbdump"

#define OPT_OS_HIDE_PREP					L"-oshideprep"


STATIC CONST SHELL_PARAM_ITEM ParamList[] = {
	{ OPT_TBL_DUMP,      TypeValue },
	{ OPT_TBL_FILE,      TypeValue },
	{ OPT_TBL_ZERO,      TypeFlag },
	{ OPT_TBL_LIST,      TypeFlag },
	{ OPT_TBL_DELETE,    TypeFlag },
	{ OPT_TBL_NAME,      TypeValue },
	{ OPT_TBL_APPEND,    TypeValue },
	{ OPT_DISK_LIST,     TypeValue },
   { OPT_DISK_CHECK,    TypeFlag },
   { OPT_DISK_START,    TypeValue },
   { OPT_DISK_END,      TypeValue },
   { OPT_DISK_BOOT,     TypeValue },
   { OPT_AUTH_ASK,      TypeFlag },
	{ OPT_AUTH_CREATE_HEADER,      TypeFlag },
   { OPT_RND,           TypeDoubleValue },
	{ OPT_RND_GEN,       TypeDoubleValue },
	{ OPT_RND_LOAD,      TypeValue },
	{ OPT_RND_SAVE,      TypeValue },
	{ OPT_VOLUME_ENCRYPT,TypeValue },
   { OPT_VOLUME_DECRYPT,TypeValue },
	{ OPT_VOLUME_CHANGEPWD,TypeValue },
	{ OPT_USB_LIST,      TypeFlag },
	{ OPT_USB_SELECT,    TypeValue },
	{ OPT_SC_APDU,       TypeValue },
	{ OPT_TOUCH_LIST,    TypeFlag },
	{ OPT_TOUCH_TEST,    TypeValue },
	{ OPT_GRAPH_LIST,    TypeFlag },
	{ OPT_GRAPH_DEVICE,  TypeValue },
	{ OPT_GRAPH_MODE,    TypeValue },
	{ OPT_BEEP_LIST,     TypeFlag },
	{ OPT_BEEP_TEST,     TypeFlag },
	{ OPT_SETUP,         TypeFlag },
	{ OPT_PARTITION_LIST, TypeFlag },
	{ OPT_PARTITION_SAVE, TypeFlag },
	{ OPT_PARTITION_ZERO, TypeFlag },
	{ OPT_PARTITION_FILE, TypeValue },
	{ OPT_PARTITION_ENCRYPT,TypeFlag },
	{ OPT_PARTITION_DECRYPT,TypeFlag },
	{ OPT_PARTITION_APPLY,TypeFlag },
	{ OPT_PARTITION_HIDE,  TypeDoubleValue },
	{ OPT_PARTITION_IDX_TEMPLATE, TypeValue },
	{ OPT_PARTITION_EDIT,           TypeValue },
	{ OPT_PARTITION_EDIT_EXEC,      TypeFlag },
	{ OPT_PARTITION_EDIT_PWD_CACHE, TypeFlag },
	{ OPT_PARTITION_RND_LOAD, TypeFlag },
	{ OPT_PARTITION_RND_SAVE, TypeFlag },
	{ OPT_KEYFILE_PLATFORM,     TypeValue },
	{ OPT_SECREGION_MARK,       TypeValue },
	{ OPT_SECREGION_WIPE,       TypeValue },
	{ OPT_SECREGION_ADD,        TypeValue },
	{ OPT_SECREGION_DUMP,       TypeValue },
	{ OPT_WIPE,                 TypeDoubleValue },
	{ OPT_OS_DECRYPT,     TypeFlag },
	{ OPT_OS_RESTORE_KEY, TypeFlag },
	{ OPT_OS_HIDE_PREP,   TypeFlag },
	{ OPT_TPM_PCRS,       TypeDoubleValue },
	{ OPT_TPM_NVLIST,     TypeFlag },
	{ OPT_TPM_CFG,        TypeFlag },
	{ NULL, TypeMax }
};

/**
The actual entry point for the application.

@param[in] ImageHandle    The firmware allocated handle for the EFI image.
@param[in] SystemTable    A pointer to the EFI System Table.

@retval EFI_SUCCESS       The entry point executed successfully.
@retval other             Some error occurred when executing this entry point.

**/
EFI_STATUS
EFIAPI
DcsCfgMain(
   IN EFI_HANDLE        ImageHandle,
   IN EFI_SYSTEM_TABLE  *SystemTable
   )
{
   EFI_STATUS          res;
   LIST_ENTRY          *Package;
   SHELL_STATUS        ShellStatus;
   UINTN               ParamCount;
   CHAR16              *ProblemParam;
   UINTN               Size;
   CHAR16              *PrintString;
	CHAR16*             cmd;
	UINTN               cmdSize;
	UINT32              cmdAttr;

   Size = 0;
   ParamCount = 0;
   ProblemParam = NULL;
   PrintString = NULL;
   ShellStatus = SHELL_SUCCESS;

	InitBio();
	InitFS();
	InitConfig(CONFIG_FILE_PATH);
#if defined(_M_X64) || defined(_M_IX86) || defined(__x86_64__) || defined(__i386__)
	DetectX86Features();
#endif

	//
   // initialize the shell lib (we must be in non-auto-init...)
   //
	res = EfiGetVar(L"dcscfgcmd", NULL, &cmd, &cmdSize, &cmdAttr);
	if (!EFI_ERROR(res)) {
		res = EfiSetVar(L"dcscfgcmd", NULL, NULL, 0, cmdAttr);
		if (StrStr(cmd, OPT_OS_RESTORE_KEY) != NULL) {
			return OSRestoreKey();
		}
		if (StrStr(cmd, OPT_OS_DECRYPT) != NULL) {
			return OSDecrypt();
		}
		return EFI_INVALID_PARAMETER;
	}

	res = ShellInitialize();
	if (EFI_ERROR(res) || gEfiShellProtocol == NULL) {
		EFI_INPUT_KEY key;
		key = KeyWait(L"Press any key to start interactive DCS setup %02d\r", 20, 0, 0);
		if (key.UnicodeChar != 0) {
			return DcsInteractiveSetup();
		}
		return EFI_INVALID_PARAMETER;
   }

   InitGraph();
   //
   // parse the command line
   //
   res = ShellCommandLineParseEx(ParamList, &Package, &ProblemParam, TRUE, TRUE);
   if (EFI_ERROR(res)) {
      OUT_PRINT(L"syntax error:%s", ProblemParam);
      return res;
   }
	gShellReady = gEfiShellProtocol != NULL;
	if (gShellReady) {
		SetShellAPI(gEfiShellProtocol, gEfiShellParametersProtocol);
	}

   ParamCount = ShellCommandLineGetCount(Package);

	// Create random
	if (ShellCommandLineGetFlag(Package, OPT_RND)) {
		CONST CHAR16* opt = NULL;
		CHAR16* context = NULL;
		UINTN rndType;
		UINTN contextSize = 0;
		opt = ShellCommandLineGetValue(Package, OPT_RND);
		rndType = StrDecimalToUintn(opt);
		context = (CHAR16*)StrStr(opt, L" ");
		if (context != NULL) {
			context++;
			contextSize = StrLen(context) * 2;
			if (!EFI_ERROR(FileExist(NULL, context))) {
				FileLoad(NULL, context, &context, &contextSize);
			}
		}
		res = RndInit(rndType, context, contextSize, &gRnd);
		if (EFI_ERROR(res)) {
			ERR_PRINT(L"Random: %r\n", res);
		}
	}

	// Rescue
	if (ShellCommandLineGetFlag(Package, OPT_OS_DECRYPT)) {
		return OSDecrypt();
	}

	if (ShellCommandLineGetFlag(Package, OPT_OS_RESTORE_KEY)) {
		return OSRestoreKey();
	}

	if (ShellCommandLineGetFlag(Package, OPT_OS_HIDE_PREP)) {
		return OuterInit();
	}

	// Common parameters
	if (ShellCommandLineGetFlag(Package, OPT_DISK_START)) {
		CONST CHAR16* opt = NULL;
		opt = ShellCommandLineGetValue(Package, OPT_DISK_START);
		BioIndexStart = StrDecimalToUintn(opt);
	}

	if (ShellCommandLineGetFlag(Package, OPT_DISK_END)) {
		CONST CHAR16* opt = NULL;
		opt = ShellCommandLineGetValue(Package, OPT_DISK_END);
		BioIndexEnd = StrDecimalToUintn(opt);
	}

	if (ShellCommandLineGetFlag(Package, OPT_PARTITION_FILE)) {
		DcsDiskEntrysFileName = ShellCommandLineGetValue(Package, OPT_PARTITION_FILE);
	}

	if (ShellCommandLineGetFlag(Package, OPT_TBL_FILE)) {
		DcsTablesFileName = ShellCommandLineGetValue(Package, OPT_TBL_FILE);
	}

	if (ShellCommandLineGetFlag(Package, OPT_TBL_DELETE) && 
		ShellCommandLineGetFlag(Package, OPT_TBL_NAME)
		) {
		CONST CHAR16* opt1 = NULL;
		opt1 = ShellCommandLineGetValue(Package, OPT_TBL_NAME);
		res = TablesDel(opt1);
	}

	if (ShellCommandLineGetFlag(Package, OPT_TBL_APPEND) &&
		ShellCommandLineGetFlag(Package, OPT_TBL_NAME)
		) {
		CONST CHAR16* opt1 = NULL;
		CONST CHAR16* opt2 = NULL;
		opt1 = ShellCommandLineGetValue(Package, OPT_TBL_NAME);
		opt2 = ShellCommandLineGetValue(Package, OPT_TBL_APPEND);
		res = TablesNew(opt1, opt2);
	}

	if (ShellCommandLineGetFlag(Package, OPT_TBL_DUMP))
	{
		CONST CHAR16* opt = NULL;
		opt = ShellCommandLineGetValue(Package, OPT_TBL_DUMP);
		res = TablesDump((CHAR16*)opt);
	}

	if (ShellCommandLineGetFlag(Package, OPT_TBL_LIST)) {
		if (gDcsTables == NULL) TablesLoad();
		OUT_PRINT(L"Size = %d, Zones=%d\n", gDcsTablesSize, (gDcsTablesSize + 128 * 1024 - 1) / (128 * 1024));
		TablesList(gDcsTablesSize, gDcsTables);
	}

	if (ShellCommandLineGetFlag(Package, OPT_AUTH_ASK)) {
		TestAuthAsk();
	}

	// Beep
	if (ShellCommandLineGetFlag(Package, OPT_BEEP_LIST)) {
		PrintSpeakerList();
	}

	if (ShellCommandLineGetFlag(Package, OPT_BEEP_TEST)) {
		TestSpeaker();
	}

	// Touch
	if (ShellCommandLineGetFlag(Package, OPT_TOUCH_LIST)) {
		PrintTouchList();
	}

	if (ShellCommandLineGetFlag(Package, OPT_TOUCH_TEST)) {
		CONST CHAR16* opt = NULL;
		opt = ShellCommandLineGetValue(Package, OPT_TOUCH_TEST);
		TouchIndex= StrDecimalToUintn(opt);
		TestTouch();
	}

	// TPM
	if (ShellCommandLineGetFlag(Package, OPT_TPM_PCRS)) {
		CONST CHAR16* opt1 = NULL;
		CONST CHAR16* opt2 = NULL;
		UINT32 sPcr;
		UINT32 ePcr;
		opt1 = ShellCommandLineGetValue(Package, OPT_TPM_PCRS);
		sPcr = (UINT32)StrDecimalToUintn(opt1);
		opt2 = StrStr(opt1, L" ");
		if (opt2 != NULL) {
			opt2++;
		}
		ePcr = (UINT32)StrDecimalToUintn(opt2);
		res = GetTpm();
		if (!EFI_ERROR(res)) {
			if (gTpm->TpmVersion == 0x102) {
				Tpm12ListPcrs(sPcr, ePcr);
			}	else {
				Tpm2ListPcrs(sPcr, ePcr);
			}
		}
	}

	if (ShellCommandLineGetFlag(Package, OPT_TPM_NVLIST)) {
		Tpm12NvList();
	}

	if (ShellCommandLineGetFlag(Package, OPT_TPM_CFG)) {
		TpmDcsConfigure();
	}

	// Graph
	if (ShellCommandLineGetFlag(Package, OPT_GRAPH_DEVICE)) {
		CONST CHAR16* opt = NULL;
		UINTN	index;
		opt = ShellCommandLineGetValue(Package, OPT_GRAPH_DEVICE);
		index = StrDecimalToUintn(opt);
		if (index < gGraphCount) {
			GraphGetIO(gGraphHandles[index], &gGraphOut);
		} else{
			ERR_PRINT(L"Wrong graph device index");
		}
	}

	if (ShellCommandLineGetFlag(Package, OPT_GRAPH_MODE)) {
		CONST CHAR16* opt = NULL;
		UINTN	index;
		opt = ShellCommandLineGetValue(Package, OPT_GRAPH_MODE);
		index = StrDecimalToUintn(opt);
		if (index < gGraphOut->Mode->MaxMode) {
			gGraphOut->SetMode(gGraphOut, (UINT32)index);
		} else {
			ERR_PRINT(L"Wrong graph mode index");
		}
	}

	if (ShellCommandLineGetFlag(Package, OPT_GRAPH_LIST)) {
		PrintGraphList();
	}

	// USB
	if (ShellCommandLineGetFlag(Package, OPT_USB_LIST)) {
		PrintUsbList();
	}

	if (ShellCommandLineGetFlag(Package, OPT_USB_SELECT)) {
		CHAR16 * opt;
		opt = (CHAR16*)ShellCommandLineGetValue(Package, OPT_USB_SELECT);
		UsbIndex = StrDecimalToUintn(opt);
	}

	if (ShellCommandLineGetFlag(Package, OPT_SC_APDU)) {
		CHAR16 * opt;
		opt = (CHAR16*)ShellCommandLineGetValue(Package, OPT_SC_APDU);
		UsbScApdu(opt);
	}

	// Randoms
	if (ShellCommandLineGetFlag(Package, OPT_RND_LOAD)) {
		CONST CHAR16* opt = NULL;
		UINT8 temp[4];
		DCS_RND_SAVED *rndSaved;
		UINTN rndSavedSize;
		opt = ShellCommandLineGetValue(Package, OPT_RND_LOAD);
		res = FileLoad(NULL, (CHAR16*)opt, &rndSaved, &rndSavedSize);
		if (EFI_ERROR(res) ||
			rndSavedSize != sizeof(DCS_RND_SAVED) ||
			EFI_ERROR(res = RndLoad(rndSaved,&gRnd)) ||
			EFI_ERROR(res = RndPrepare()) ||
			EFI_ERROR(res = RndGetBytes(temp, sizeof(temp)))
			) {
			ERR_PRINT(L"Random: %r\n", res);
		}
	}

	if (ShellCommandLineGetFlag(Package, OPT_PARTITION_RND_LOAD)) {
		UINT8 temp[4];
		if (EFI_ERROR(res = DeListLoadFromFile()) || // Load DeList
			EFI_ERROR(res = DeListRndLoad()) ||       // Try to load gRdn from list
			EFI_ERROR(res = RndPrepare()) ||         // Prepare random
			EFI_ERROR(res = RndGetBytes(temp, sizeof(temp))) // Test
			) {
			ERR_PRINT(L"Random: %r\n", res);
		}
	}

	if (ShellCommandLineGetFlag(Package, OPT_RND_GEN)) {
		CONST CHAR16* optSize = NULL;
		UINTN  size;
		CONST CHAR16* optFile = NULL;
		UINT8* temp;
		optSize = ShellCommandLineGetValue(Package, OPT_RND_GEN);
		size = StrDecimalToUintn(optSize);
		optFile = StrStr(optSize, L" ");
		if (optFile != NULL) {
			optFile++;
		}
		res = EFI_BUFFER_TOO_SMALL;
		temp = MEM_ALLOC(size);
		if (temp == NULL ||
			EFI_ERROR(res = RndGetBytes(temp, size)) ||
				EFI_ERROR(res = FileSave(NULL, (CHAR16*)optFile, temp, size))
			) {
			ERR_PRINT(L"Random: %r\n", res);
		}
		MEM_FREE(temp);
	}

	if (ShellCommandLineGetFlag(Package, OPT_RND_SAVE)) {
		CONST CHAR16* opt = NULL;
		UINT8 temp[4];
		DCS_RND_SAVED  *rndSaved = NULL;
		opt = ShellCommandLineGetValue(Package, OPT_RND_SAVE);
		if (EFI_ERROR(res = RndPrepare()) ||
			EFI_ERROR(res = RndGetBytes(temp, sizeof(temp))) ||
			EFI_ERROR(res = RndSave(gRnd, &rndSaved)) ||
			EFI_ERROR(res = FileSave(NULL, (CHAR16*)opt, rndSaved, sizeof(DCS_RND_SAVED)))
			) {
			ERR_PRINT(L"Random: %r\n", res);
		}
		MEM_FREE(rndSaved);
	}


	// Disk
   if (ShellCommandLineGetFlag(Package, OPT_DISK_BOOT)) {
      CONST CHAR16* opt = NULL;
      opt = ShellCommandLineGetValue(Package, OPT_DISK_BOOT);
      BioIndexEnd = BioIndexStart = StrDecimalToUintn(opt);
      UpdateDcsBoot();
   }

   if (ShellCommandLineGetFlag(Package, OPT_DISK_LIST)) {
		CONST CHAR16* opt = NULL;
		opt = ShellCommandLineGetValue(Package, OPT_DISK_LIST);
		if (opt == NULL) {
			BioSkipPartitions = FALSE;
		}	else {
			BioSkipPartitions = (opt[0] == 'd');
		}
		PrintBioList();
   }

	// Authorization
	if (ShellCommandLineGetFlag(Package, OPT_AUTH_CREATE_HEADER)) {
		if (ShellCommandLineGetFlag(Package, OPT_DISK_START)) {
			res = CreateVolumeHeaderOnDisk(BioIndexStart, NULL, NULL, NULL);
			if (EFI_ERROR(res)) {
				return res;
			}
		}	else {
			ERR_PRINT(L"Select volume\n");
		}
	}

	// GPT and DeList
	if (ShellCommandLineGetFlag(Package, OPT_PARTITION_RND_SAVE)) {
		UINT8 temp[4];
		if (EFI_ERROR(res = DeListLoadFromFile()) ||           // Load DeList
			EFI_ERROR(res = RndGetBytes(temp, sizeof(temp))) || // Test Rnd
			EFI_ERROR(res = DeListRndSave())                    // Try to save RndRaw to DeList
			) {
			ERR_PRINT(L"Random: %r\n", res);
		}
	}

	if (ShellCommandLineGetFlag(Package, OPT_PARTITION_HIDE)) {
		CONST CHAR16* opt1 = NULL;
		CONST CHAR16* opt2 = NULL;
		UINTN idx;
		res = DeListLoadFromFile();
		if (EFI_ERROR(res)) {
			return res;
		}
		if (!ShellCommandLineGetFlag(Package, OPT_PARTITION_IDX_TEMPLATE)) {
			ERR_PRINT(L"No base partition index\n");
			return EFI_INVALID_PARAMETER;
		}
		opt1 = ShellCommandLineGetValue(Package, OPT_PARTITION_IDX_TEMPLATE);
		idx = StrDecimalToUintn(opt1);
		CopyMem(&DcsHidePart, &GptMainEntrys[idx], sizeof(DcsHidePart));
		opt1 = ShellCommandLineGetValue(Package, OPT_PARTITION_HIDE);
		DcsHidePart.StartingLBA = StrDecimalToUint64(opt1);
		opt2 = StrStr(opt1, L" ");
		if (opt2 == NULL) {
			EFI_ERROR(L"Select end sector\n");
			return EFI_INVALID_PARAMETER;
		}
		DcsHidePart.EndingLBA = StrDecimalToUint64(opt2);
		GptHideParts();
	}

	if (ShellCommandLineGetFlag(Package, OPT_PARTITION_EDIT_EXEC)) {
		res = DeListLoadFromFile();
		if (EFI_ERROR(res)) {
			return res;
		}
		DeListExecEdit();
	}

	if (ShellCommandLineGetFlag(Package, OPT_PARTITION_EDIT_PWD_CACHE)) {
		res = DeListLoadFromFile();
		if (EFI_ERROR(res)) {
			return res;
		}
		DeListPwdCacheEdit();
	}

	if (ShellCommandLineGetFlag(Package, OPT_PARTITION_EDIT)) {
		CONST CHAR16* opt1 = NULL;
		UINTN idx;
		res = DeListLoadFromFile();
		if (EFI_ERROR(res)) {
			return res;
		}

		opt1 = ShellCommandLineGetValue(Package, OPT_PARTITION_EDIT);
		idx = StrDecimalToUintn(opt1);
		GptEdit(idx);
	}


	if (ShellCommandLineGetFlag(Package, OPT_PARTITION_LIST)) {
		if (GptMainEntrys == NULL) {
			if (ShellCommandLineGetFlag(Package, OPT_DISK_START)) {
				res = GptLoadFromDisk(BioIndexStart);
				if (EFI_ERROR(res)) {
					return res;
				}
			} else {
				res = DeListLoadFromFile();
				if (EFI_ERROR(res)) {
					EFI_ERROR(L"Select file or disk\n");
					return res;
				}
			}
		}
		DeListPrint();
	}

	if (ShellCommandLineGetFlag(Package, OPT_PARTITION_ENCRYPT)) {
		GptCryptFile(TRUE);
	}

	if (ShellCommandLineGetFlag(Package, OPT_PARTITION_DECRYPT)) {
		GptCryptFile(FALSE);
	}

	if (ShellCommandLineGetFlag(Package, OPT_PARTITION_ZERO)) {
		res = DeListLoadFromFile();
		if (EFI_ERROR(res)) {
			return res;
		}
		DeListZero();
		DeListSaveToFile();
	}

	if (ShellCommandLineGetFlag(Package, OPT_PARTITION_SAVE)) {
		if (GptMainEntrys == NULL && DeList == NULL) {
			if (!ShellCommandLineGetFlag(Package, OPT_DISK_START)) {
				EFI_ERROR(L"Select disk\n");
				return EFI_INVALID_PARAMETER;
			}
			res = GptLoadFromDisk(BioIndexStart);
			if (EFI_ERROR(res)) {
				return res;
			}
		}
		DeListSaveToFile();
	}

	if (ShellCommandLineGetFlag(Package, OPT_PARTITION_APPLY)) {
		if (ShellCommandLineGetFlag(Package, OPT_DISK_START) && 
			ShellCommandLineGetFlag(Package, OPT_PARTITION_FILE)
			) {
			res = DeListLoadFromFile();
			if (EFI_ERROR(res)) {
				return res;
			}
			DeListApplySectorsToDisk(BioIndexStart);
		}	else {
			EFI_ERROR(L"Select file and disk\n");
		}
	}

	// Key file
	if (ShellCommandLineGetFlag(Package, OPT_KEYFILE_PLATFORM)) {
		CONST CHAR16* opt = NULL;
		CHAR8         *buf;
		UINTN         len;
		opt = ShellCommandLineGetValue(Package, OPT_KEYFILE_PLATFORM);
		res = SMBIOSGetSerials();
		if (EFI_ERROR(res)) {
			ERR_PRINT(L"SMBIOS: %r\n", res);
			return res;
		}
		res = PlatformGetID(gBIOHandles[BioIndexStart], &buf, &len);
		if (EFI_ERROR(res)) {
			ERR_PRINT(L"Platform ID: %r\n", res);
			return res;
		}
		res = FileSave(NULL, (CHAR16*)opt, buf, len);
		if (EFI_ERROR(res)) {
			ERR_PRINT(L"Save: %r\n", res);
			return res;
		}
	}

	if (ShellCommandLineGetFlag(Package, OPT_WIPE)) {
		CONST CHAR16* opt1 = NULL;
		CONST CHAR16* opt2 = NULL;
		UINT64 start;
		UINT64 end;
		if (!ShellCommandLineGetFlag(Package, OPT_DISK_START)) {
			ERR_PRINT(L"Select disk\n");
			return EFI_INVALID_PARAMETER;
		}
		opt1 = ShellCommandLineGetValue(Package, OPT_WIPE);
		start = StrDecimalToUint64(opt1);
		opt2 = StrStr(opt1, L" ") + 1;
		end = StrDecimalToUint64(opt2);
		return BlockRangeWipe(gBIOHandles[BioIndexStart], start, end);
	}


	// Security region
	if (ShellCommandLineGetFlag(Package, OPT_SECREGION_MARK)) {
		if (ShellCommandLineGetFlag(Package, OPT_DISK_START)) {
			CONST CHAR16* opt = NULL;
			opt = ShellCommandLineGetValue(Package, OPT_SECREGION_MARK);
			gSecRigonCount = StrDecimalToUintn(opt);
			SecRegionMark();
		}	else {
			ERR_PRINT(L"Select disk and security region count");
			return EFI_INVALID_PARAMETER;
		}
	}

	if (ShellCommandLineGetFlag(Package, OPT_SECREGION_WIPE)) {
		if (ShellCommandLineGetFlag(Package, OPT_DISK_START)) {
			CONST CHAR16* opt = NULL;
			opt = ShellCommandLineGetValue(Package, OPT_SECREGION_WIPE);
			gSecRigonCount = StrDecimalToUintn(opt);
			SecRegionWipe();
		}
		else {
			ERR_PRINT(L"Select disk and security region count");
			return EFI_INVALID_PARAMETER;
		}
	}

	if (ShellCommandLineGetFlag(Package, OPT_SECREGION_ADD)) {
		if (ShellCommandLineGetFlag(Package, OPT_PARTITION_FILE) &&
			ShellCommandLineGetFlag(Package, OPT_DISK_START)) {
			CONST CHAR16* opt = NULL;
			UINTN secRegionIdx;
			opt = ShellCommandLineGetValue(Package, OPT_SECREGION_ADD);
			secRegionIdx = StrDecimalToUintn(opt);
			SecRegionAdd(secRegionIdx);
		}
		else {
			ERR_PRINT(L"Select disk and GPT file");
			return EFI_INVALID_PARAMETER;
		}
	}

	if (ShellCommandLineGetFlag(Package, OPT_SECREGION_DUMP)) {
		if (ShellCommandLineGetFlag(Package, OPT_DISK_START)) {
			CONST CHAR16* opt = NULL;
			opt = ShellCommandLineGetValue(Package, OPT_SECREGION_DUMP);
			SecRegionDump(gBIOHandles[BioIndexStart], (CHAR16*)opt);
		}	else {
			ERR_PRINT(L"Select disk");
			return EFI_INVALID_PARAMETER;
		}
	}

	// Encrypt, decrypt, change password
	if (ShellCommandLineGetFlag(Package, OPT_DISK_CHECK)) {
		DisksAuthCheck();
	}

	if (ShellCommandLineGetFlag(Package, OPT_VOLUME_CHANGEPWD)) {
		CONST CHAR16* opt = NULL;
		UINTN disk;
		opt = ShellCommandLineGetValue(Package, OPT_VOLUME_CHANGEPWD);
		disk = StrDecimalToUintn(opt);
		VolumeChangePassword(disk);
	}

	if (ShellCommandLineGetFlag(Package, OPT_VOLUME_ENCRYPT)) {
      CONST CHAR16* opt = NULL;
      UINTN disk;
      opt = ShellCommandLineGetValue(Package, OPT_VOLUME_ENCRYPT);
      disk = StrDecimalToUintn(opt);
      VolumeEncrypt(disk);
   }

   if (ShellCommandLineGetFlag(Package, OPT_VOLUME_DECRYPT)) {
      CONST CHAR16* opt = NULL;
      UINTN disk;
      opt = ShellCommandLineGetValue(Package, OPT_VOLUME_DECRYPT);
      disk = StrDecimalToUintn(opt);
      VolumeDecrypt(disk);
   }

	
   return EFI_SUCCESS;
}
