/** @file
This is DCS configuration, volume crypt

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov, Alex Kolotnikov
Copyright (c) 2016. VeraCrypt, Mounir IDRASSI 

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#include <Library/UefiBootServicesTableLib.h>
#include <Library/ShellLib.h>
#include <Library/DevicePathLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PrintLib.h>
#include <Guid/Gpt.h>
#include <Guid/GlobalVariable.h>

#include <Library/CommonLib.h>
#include <Library/GraphLib.h>
#include <Library/PasswordLib.h>
#include <Library/DcsCfgLib.h>
#include <DcsConfig.h>

#include "common/Tcdefs.h"
#include "common/Endian.h"
#include "common/Crypto.h"
#include "common/Volumes.h"
#include "common/Pkcs5.h"
#include "common/Crc.h"
#include "crypto/cpu.h"
#include "DcsVeraCrypt.h"
#include "BootCommon.h"

#include "DcsCfg.h"

static PCRYPTO_INFO gAuthCryptInfo = NULL;
static PCRYPTO_INFO gHeaderCryptInfo = NULL;
static CHAR8 Header[512];
static CHAR8 BackupHeader[512];

static EFI_HANDLE              SecRegionHandle = NULL;
static UINT64                  SecRegionSector = 0;
static UINT8*                  SecRegionData = NULL;
static UINTN                   SecRegionSize = 0;
static UINTN                   SecRegionOffset = 0;
static PCRYPTO_INFO            SecRegionCryptInfo = NULL;

//////////////////////////////////////////////////////////////////////////
// Crypt helpers
//////////////////////////////////////////////////////////////////////////
int
AskEA() {
	int ea;
	CHAR16 name[128];
	for (ea = EAGetFirst(); ea != 0; ea = EAGetNext(ea))
	{
		EAGetName(name, ea, 1);
		OUT_PRINT(L"(%d) %s\n", ea, name);
	}
	ea = (int)AskUINTN(":", EAGetFirst());
	return ea;
}

int
AskMode(int ea) {
	int mode;
	for (mode = EAGetFirstMode(ea); mode != 0; mode = EAGetNextMode(ea, mode))
	{
		EAGetModeName(ea, mode, 1);
		OUT_PRINT(L"(%d) %s\n", mode, EAGetModeName(ea, mode, 1));
	}
	mode = (int)AskUINTN(":", EAGetFirstMode(ea));
	return mode;
}

int
AskPkcs5() {
	int pkcs5 = 1;
	Hash *hash;
	hash = HashGet(pkcs5);
	while (hash != NULL)
	{
		OUT_PRINT(L"(%d) %s\n", pkcs5, hash->Name);
		++pkcs5;
		hash = HashGet(pkcs5);
	};
	pkcs5 = (int)AskUINTN(":", gAuthHash);
	return pkcs5;
}

EFI_STATUS
TryHeaderDecrypt(
	IN  CHAR8*                  header,
	OUT PCRYPTO_INFO            *rci,
	OUT PCRYPTO_INFO            *rhci
	) 
{
	int                 vcres;
	PCRYPTO_INFO        cryptoInfo;
	PCRYPTO_INFO        headerCryptoInfo = NULL;

	if (rhci != NULL) {
		headerCryptoInfo = crypto_open();
	}

	vcres = ReadVolumeHeader(
		gAuthBoot,
		header,
		&gAuthPassword,
		gAuthHash,
		gAuthPim,
		gAuthTc,
		&cryptoInfo,
		headerCryptoInfo);

	if (vcres != 0) {
		ERR_PRINT(L"Authorization failed. Wrong password, PIM or hash. Decrypt error(%x)\n", vcres);
		return EFI_INVALID_PARAMETER;
	}
	OUT_PRINT(L"%H" L"Success\n" L"%N", vcres);
	OUT_PRINT(L"Start %lld length %lld\nVolumeSize %lld\nHiddenVolumeSize %lld\nflags 0x%x\n",
		cryptoInfo->EncryptedAreaStart.Value, (uint64)cryptoInfo->EncryptedAreaLength.Value,
		cryptoInfo->VolumeSize.Value,
		cryptoInfo->hiddenVolumeSize,
		cryptoInfo->HeaderFlags
		);
	if(rci != NULL) *rci = cryptoInfo;
	if (rhci != NULL) *rhci = headerCryptoInfo;
	return EFI_SUCCESS;
}

EFI_STATUS
ChangePassword(
	IN OUT CHAR8*                  header
	)
{
	Password                newPassword;
	Password                confirmPassword;
	EFI_STATUS              res;
	PCRYPTO_INFO            cryptoInfo, ci;
	int                     vcres;
	BOOL                    modified = FALSE;

	res = RndPreapare();
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Rnd: %r\n", res);
		return res;
	}

	if (gAuthPasswordMsg == NULL) {
		VCAuthAsk();
	}

	res = TryHeaderDecrypt(header, &cryptoInfo, NULL);
	if (EFI_ERROR(res)) return res;

	if (AskConfirm("Change password[N]?", 1)) {
		modified = TRUE;
		do {
			ZeroMem(&newPassword, sizeof(newPassword));
			ZeroMem(&confirmPassword, sizeof(newPassword));
			VCAskPwd(AskPwdNew, &newPassword);
			if (gAuthPwdCode == AskPwdRetCancel) {
				return EFI_DCS_USER_CANCELED;
			}
			if (gAuthPwdCode == AskPwdRetTimeout) {
				return EFI_TIMEOUT;
			}
			VCAskPwd(AskPwdConfirm, &confirmPassword);
			if (gAuthPwdCode == AskPwdRetCancel) {
				MEM_BURN(&newPassword, sizeof(newPassword));
				return EFI_DCS_USER_CANCELED;
			}
			if (gAuthPwdCode == AskPwdRetTimeout) {
				MEM_BURN(&newPassword, sizeof(newPassword));
				return EFI_TIMEOUT;
			}
			if (newPassword.Length == confirmPassword.Length) {
				if (CompareMem(newPassword.Text, confirmPassword.Text, confirmPassword.Length) == 0) {
					gAuthPassword = newPassword;
					break;
				}
			}

			if (AskConfirm("Password mismatch, retry[N]?", 1)) {
				break;
			}
		} while (TRUE);
	}

	if (AskConfirm("Change range of encrypted sectors[N]?", 1)) {
		modified = TRUE;
		cryptoInfo->VolumeSize.Value = AskUINT64("Volume size:", cryptoInfo->VolumeSize.Value >> 9) << 9;
		cryptoInfo->EncryptedAreaStart.Value = AskUINT64("Encrypted area start:", cryptoInfo->EncryptedAreaStart.Value >> 9) << 9;
		cryptoInfo->EncryptedAreaLength.Value = AskUINT64("Encrypted area length:", cryptoInfo->EncryptedAreaLength.Value >> 9) << 9;
	}

	if (modified) {
		vcres = CreateVolumeHeaderInMemory(
			gAuthBoot, header,
			cryptoInfo->ea,
			cryptoInfo->mode,
			&gAuthPassword,
			cryptoInfo->pkcs5,
			gAuthPim,
			cryptoInfo->master_keydata,
			&ci,
			cryptoInfo->VolumeSize.Value,
			cryptoInfo->hiddenVolumeSize,
			cryptoInfo->EncryptedAreaStart.Value,
			cryptoInfo->EncryptedAreaLength.Value,
			gAuthTc ? 0 : cryptoInfo->RequiredProgramVersion,
			cryptoInfo->HeaderFlags,
			cryptoInfo->SectorSize,
			FALSE);

		MEM_BURN(&newPassword, sizeof(newPassword));
		MEM_BURN(&confirmPassword, sizeof(confirmPassword));

		if (vcres != 0) {
			ERR_PRINT(L"header create error(%x)\n", vcres);
			return EFI_INVALID_PARAMETER;
		}
	}
	return EFI_SUCCESS;
}

EFI_STATUS
CreateVolumeHeader(
	IN OUT CHAR8*                  header,
	OUT PCRYPTO_INFO               *rci,
	IN UINT64                      defaultVS,
	IN UINT64                      defaultESS,
	IN UINT64                      defaultESE
	)
{
	INT32                   vcres;
	int mode = 0;
	int ea = 0;
	int pkcs5 = 0;
	UINT64 encSectorStart = defaultESS;
	UINT64 encSectorEnd = defaultESE;
	UINT64 hiddenVolumeSize = 0;
	UINT64 VolumeSize = defaultVS;
	UINT32 HeaderFlags = 0;
	int8 master_keydata[MASTER_KEYDATA_SIZE];

	if (!RandgetBytes(master_keydata, MASTER_KEYDATA_SIZE, FALSE)) {
		ERR_PRINT(L"No randoms\n");
		return EFI_CRC_ERROR;
	}

	if (gAuthPasswordMsg == NULL) {
		VCAuthAsk();
	}

	ea = AskEA();
	mode = AskMode(ea);
	pkcs5 = AskPkcs5();
	encSectorStart = AskUINT64("encryption start (sector):", encSectorStart);
	encSectorEnd = AskUINT64("encryption end (sector):", encSectorEnd);
	VolumeSize = AskUINT64("volume total (sectors):", VolumeSize);
	hiddenVolumeSize = AskUINT64("hidden volume total (sectors):", hiddenVolumeSize);
	HeaderFlags = (UINT32)AskUINTN("flags:", gAuthBoot ? TC_HEADER_FLAG_ENCRYPTED_SYSTEM : 0);

	vcres = CreateVolumeHeaderInMemory(
		gAuthBoot, Header,
		ea,
		mode,
		&gAuthPassword,
		pkcs5,
		gAuthPim,
		master_keydata,
		rci,
		VolumeSize << 9,
		hiddenVolumeSize << 9,
		encSectorStart << 9,
		(encSectorEnd - encSectorStart + 1) << 9,
		VERSION_NUM,
		HeaderFlags,
		512,
		FALSE);

	if (vcres != 0) {
		ERR_PRINT(L"Header error %d\n", vcres);
		return EFI_CRC_ERROR;
	}
	crypto_close(*rci);
	vcres = CreateVolumeHeaderInMemory(
		gAuthBoot, BackupHeader,
		ea,
		mode,
		&gAuthPassword,
		pkcs5,
		gAuthPim,
		master_keydata,
		rci,
		VolumeSize << 9,
		hiddenVolumeSize << 9,
		encSectorStart << 9,
		(encSectorEnd - encSectorStart + 1) << 9,
		VERSION_NUM,
		HeaderFlags,
		512,
		FALSE);

	if (vcres != 0) {
		ERR_PRINT(L"Header error %d\n", vcres);
		return EFI_CRC_ERROR;
	}
	return EFI_SUCCESS;
}

UINT8
AskChoice(
	CHAR8* prompt, 
	CHAR8* choice, 
	UINT8 visible) {
	CHAR16      buf[2];
	UINTN       len = 0;
	UINT8       ret = 0;
	UINT8       *pos = choice;
	while (ret == 0) {
		pos = choice;
		OUT_PRINT(L"%a", prompt);
		GetLine(&len, buf, NULL, sizeof(buf) / 2, visible);
		while (*pos != 0 && ret == 0) {
			if (buf[0] == *pos) {
				ret = *pos;
				break;
			}
			pos++;
		}
	}
	return ret;
}

UINT8
AskARI() {
	return AskChoice("[a]bort [r]etry [i]gnore?", "aArRiI", 1);
}

UINT8
AskAR() {
	return AskChoice("[a]bort [r]etry?", "aArR", 1);
}

UINTN gScndTotal = 0;
UINTN gScndCurrent = 0;
VOID
AddSecondsDelta() 
{
	EFI_STATUS res;
	EFI_TIME time;
	UINTN secs;
	UINTN secsDelta;
	res = gST->RuntimeServices->GetTime(&time, NULL);
	if (EFI_ERROR(res)) return;
	secs = (UINTN)time.Second + ((UINTN)time.Minute) * 60 + ((UINTN)time.Hour) * 60 * 60;
	if (gScndTotal == 0 && gScndCurrent == 0) {
		gScndCurrent = secs;
		return;
	}
	if (secs > gScndCurrent) {
		secsDelta = secs - gScndCurrent;
	}	else {
		secsDelta = 24 * 60 * 60 - gScndCurrent;
		secsDelta += secs;
	}
	gScndCurrent = secs;
	gScndTotal += secsDelta;
}

VOID
RangeCryptProgress(
	IN UINT64  size,
	IN UINT64  remains,
	IN UINT64  pos,
	IN UINT64  remainsOnStart
	) {
	UINTN  percent;
	percent = (UINTN)(100 * (size - remains) / size);
	OUT_PRINT(L"%H%d%%%N (%llds %llds) ", percent, pos, remains);
	AddSecondsDelta();
	if (gScndTotal > 10) {
		UINT64 doneBpS = (remainsOnStart - remains) * 512 / gScndTotal;
		if (doneBpS > 1024 * 1024) {
			OUT_PRINT(L"%lldMB/s", doneBpS / (1024 * 1024));
		}	else	if (doneBpS > 1024) {
			OUT_PRINT(L"%lldKB/s", doneBpS / 1024);
		}	else {
			OUT_PRINT(L"%lldB/s", doneBpS);
		}
		if (doneBpS > 0) {
			OUT_PRINT(L"(ETA: %lldm)", (remains * 512 / doneBpS) / 60);
		}
	}
	OUT_PRINT(L"        \r");
}

#define CRYPT_BUF_SECTORS 50*1024*2
EFI_STATUS
RangeCrypt(
	IN EFI_HANDLE             disk,
	IN UINT64                 start,
	IN UINT64                 size,
	IN UINT64                 enSize,
	IN PCRYPTO_INFO           info,
	IN BOOL                   encrypt,
	IN PCRYPTO_INFO           headerInfo,
	IN UINT64                 headerSector
	)
{
	EFI_STATUS              res = EFI_SUCCESS;
	EFI_BLOCK_IO_PROTOCOL  *io;
	UINT8*                  buf;
	UINT64                  remains;
	UINT64                  remainsOnStart;
	UINT64                  pos;
	UINTN                   rd;
	BOOL                    bIsSystemEncyption = FALSE;

	if (info->noIterations == get_pkcs5_iteration_count (info->pkcs5, info->volumePim, FALSE, TRUE))
		bIsSystemEncyption = TRUE;

	io = EfiGetBlockIO(disk);
	if (!io) {
		ERR_PRINT(L"no block IO\n");
		return EFI_INVALID_PARAMETER;
	}

	buf = MEM_ALLOC(CRYPT_BUF_SECTORS << 9);
	if (!buf) {
		ERR_PRINT(L"no memory for buffer\n");
		return EFI_INVALID_PARAMETER;
	}

	if (encrypt) {
		remains = size - enSize;
		pos = start + enSize;
		rd = (UINTN)((remains > CRYPT_BUF_SECTORS) ? CRYPT_BUF_SECTORS : remains);
	}	else {
		remains = enSize;
		rd = (UINTN)((remains > CRYPT_BUF_SECTORS) ? CRYPT_BUF_SECTORS : remains);
		pos = start + enSize - rd;
	}
	remainsOnStart = remains;
	// Start second
	gScndTotal = 0;
	gScndCurrent = 0;
	
	if (remainsOnStart > 0)
	{
		do {
			rd = (UINTN)((remains > CRYPT_BUF_SECTORS) ? CRYPT_BUF_SECTORS : remains);
			RangeCryptProgress(size, remains, pos, remainsOnStart);
			// Read
			do {
				res = io->ReadBlocks(io, io->Media->MediaId, pos, rd << 9, buf);
				if (EFI_ERROR(res)) {
					UINT8 ari;
					ERR_PRINT(L"Read error: %r\n", res);
					ari = AskARI();
					switch (ari)
					{
					case 'I':
					case 'i':
						res = EFI_SUCCESS;
						break;
					case 'A':
					case 'a':
						goto error;
					case 'R':
					case 'r':
					default:
						if (rd > 1) rd >>= 1;
						break;
					}
				}
			} while (EFI_ERROR(res));

			// Crypt
			if (encrypt) {
				EncryptDataUnits(buf, (UINT64_STRUCT*)&pos, (UINT32)(rd), info);
			}	else {
				if (bIsSystemEncyption && (pos == start) && (0xEB52904E54465320 == BE64 (*(uint64 *) buf)))
				{
					// first sector is not encrypted (e.g. because of Windows repair).
					// So we encrypt it so that decryption will lead to correct result
					EncryptDataUnits(buf, (UINT64_STRUCT*)&pos, 1, info);
				}
				
				DecryptDataUnits(buf, (UINT64_STRUCT*)&pos, (UINT32)(rd), info);
			}

			// Write
			do {
				res = io->WriteBlocks(io, io->Media->MediaId, pos, rd << 9, buf);
				if (EFI_ERROR(res)) {
					UINT8 ari;
					ERR_PRINT(L"Write error: %r\n", res);
					ari = AskARI();
					switch (ari)
					{
					case 'I':
					case 'i':
						res = EFI_SUCCESS;
						break;
					case 'A':
					case 'a':
						goto error;
					case 'R':
					case 'r':
					default:
						break;
					}
				}
			} while (EFI_ERROR(res));

			remains -= rd;
			if (encrypt) {
				pos += rd;
			}	else {
				pos -= (rd > remains) ? remains : rd;
			}

			// Update header
			if (headerInfo != NULL) {
				res = io->ReadBlocks(io, io->Media->MediaId, headerSector, 512, buf);
				if (!EFI_ERROR(res)) {
					UINT32 headerCrc32;
					UINT64 encryptedAreaLength;
					UINT8* headerData;
					if (encrypt) {
						encryptedAreaLength = (size - remains) << 9;
					}	else {
						encryptedAreaLength = remains << 9;
					}
					DecryptBuffer(buf + HEADER_ENCRYPTED_DATA_OFFSET, HEADER_ENCRYPTED_DATA_SIZE, headerInfo);
					if (GetHeaderField32(buf, TC_HEADER_OFFSET_MAGIC) == 0x56455241) {
						headerData = buf + TC_HEADER_OFFSET_ENCRYPTED_AREA_LENGTH;
						mputInt64(headerData, encryptedAreaLength);
						headerCrc32 = GetCrc32(buf + TC_HEADER_OFFSET_MAGIC, TC_HEADER_OFFSET_HEADER_CRC - TC_HEADER_OFFSET_MAGIC);
						headerData = buf + TC_HEADER_OFFSET_HEADER_CRC;
						mputLong(headerData, headerCrc32);
						EncryptBuffer(buf + HEADER_ENCRYPTED_DATA_OFFSET, HEADER_ENCRYPTED_DATA_SIZE, headerInfo);
						res = io->WriteBlocks(io, io->Media->MediaId, headerSector, 512, buf);
					}	else {
						res = EFI_CRC_ERROR;
					}
				}
				if (EFI_ERROR(res)) {
					ERR_PRINT(L"Header update: %r\n", res);
				}
			}

			// Check ESC
			{
				EFI_INPUT_KEY key;
				res = gBS->CheckEvent(gST->ConIn->WaitForKey);
				if(!EFI_ERROR(res)) {
					gST->ConIn->ReadKeyStroke(gST->ConIn, &key);
					if (key.ScanCode == SCAN_ESC) {
						if (AskConfirm("\n\rStop?", 1)) {
							res = EFI_NOT_READY;
							goto error;
						}
					}
				}
			}
		} while (remains > 0);
		RangeCryptProgress(size, remains, pos, remainsOnStart);
	}
	else if (!encrypt)
	{		
		if (bIsSystemEncyption)
		{
			res = io->ReadBlocks(io, io->Media->MediaId, start, 512, buf);
			if (!EFI_ERROR(res)) {
				/*
				 * Case of OS decryption by Rescue Disk
				 * Check if NTFS marker exists. If not, then probably disk affected by
				 * either Windows Repair overwriting first sector or the bug in 1.19 
				 * Rescue Disk which caused the first 50 MB of disk to be 
				 * decrypted in a wrong way. In this case, try to reverse the faulty decryption
				 * and then perform correct decryption
				 */
				if (0xEB52904E54465320 != BE64 (*(uint64 *) buf)) /* NTFS */
				{
					/* encrypt it to see if the first sector was unencrypted before decrypt done */
					EncryptDataUnits(buf, (UINT64_STRUCT*)&start, 1, info);
					
					if (0xEB52904E54465320 == BE64 (*(uint64 *) buf)) /* NTFS */
					{
						// Write corrected first sector
						do {
							res = io->WriteBlocks(io, io->Media->MediaId, start, 512, buf);
							if (EFI_ERROR(res)) {
								UINT8 ar;
								ERR_PRINT(L"Write error: %r\n", res);
								ar = AskAR();
								if (ar != 'R' && ar != 'r')
									break;
							}
						} while (EFI_ERROR(res));
						
						if (EFI_ERROR(res))
						{
							OUT_PRINT(L"\r\nThe corrected first sector could not be written.");
						}
					}
					else
					{
						/* restore original value */
						DecryptDataUnits(buf, (UINT64_STRUCT*)&start, 1, info);

						remains = size % CRYPT_BUF_SECTORS;
						if (remains > 0)
						{
							/* 1.19 bug appears only when size not multiple of 50 MB */																
							if (AskConfirm("\r\nSystem already decrypted but partition can't be recognized.\r\nDid you use 1.19 Rescue Disk previously to decrypt OS?", 1)) {
								OUT_PRINT(L"\r\nTrying to recover data corrupted by 1.19 Rescue Disk bug.");

								pos = start + remains - CRYPT_BUF_SECTORS;
								// Read
								do {
									res = io->ReadBlocks(io, io->Media->MediaId, pos, CRYPT_BUF_SECTORS << 9, buf);
									if (EFI_ERROR(res)) {
										UINT8 ar;
										ERR_PRINT(L"Read error: %r\n", res);
										ar = AskAR();
										if (ar != 'R' && ar != 'r')
											break;
									}
								} while (EFI_ERROR(res));
								
								if (EFI_ERROR(res))
								{
									OUT_PRINT(L"\r\nNo corrective action performed.");
								}
								else
								{
									UINT8* realEncryptedData = buf + ((CRYPT_BUF_SECTORS - remains) << 9);
									BOOL bPerformWrite = FALSE;

									// reverse faulty decryption
									EncryptDataUnits(buf, (UINT64_STRUCT*)&pos, (UINT32)(remains), info);
									
									// decrypt the correct data
									DecryptDataUnits(realEncryptedData, (UINT64_STRUCT*)&start, (UINT32)(remains), info);
							
									if (0xEB52904E54465320 == BE64 (*(uint64 *) realEncryptedData)) /* NTFS */
										bPerformWrite = TRUE;
									else
									{
										if (AskConfirm("\r\nDecrypted data don't contain valid partition information. Proceeed anyway?", 1))
											bPerformWrite = TRUE;
									}
									
									if (bPerformWrite)
									{
										// Write original encrypted data
										do {
											res = io->WriteBlocks(io, io->Media->MediaId, pos, (UINTN)((CRYPT_BUF_SECTORS - remains) << 9), buf);
											if (EFI_ERROR(res)) {
												UINT8 ar;
												ERR_PRINT(L"Write error: %r\n", res);
												ar = AskAR();
												if (ar != 'R' && ar != 'r')
													break;
											}
										} while (EFI_ERROR(res));
										
										if (EFI_ERROR(res))
										{
											OUT_PRINT(L"\r\nNo corrective action performed.");
										}
										else
										{										
											// Write correctly decrypted data
											do {
												res = io->WriteBlocks(io, io->Media->MediaId, start, (UINTN) (remains << 9), realEncryptedData);
												if (EFI_ERROR(res)) {
													UINT8 ar;
													ERR_PRINT(L"Write error: %r\n", res);
													ar = AskAR();
													if (ar != 'R' && ar != 'r')
														break;
												}
											} while (EFI_ERROR(res));
										
											if (EFI_ERROR(res))
											{
												OUT_PRINT(L"\r\nFailed to write decrypted data.");
											}
											else
											{
												OUT_PRINT(L"\r\nData recovered successfully!");											
											}
										}
									}
									else
									{
										OUT_PRINT(L"\r\nNo corrective action performed.");
									}								
								}							
							}
							else
							{
								OUT_PRINT(L"\n\rNo corrective action attempted.");
							}
							
						}
					}					
				}
			}
			 
			
		}
		
	}
	OUT_PRINT(L"\nDone");

error:
	OUT_PRINT(L"\n");
	MEM_BURN(buf, CRYPT_BUF_SECTORS << 9);
	MEM_FREE(buf);
	return res;
}

EFI_STATUS
VolumeEncrypt(
	IN UINTN index
	)
{
	EFI_STATUS              res;
	EFI_HANDLE              hDisk;
	int                     vcres;
	UINT64                  headerSector;
	EFI_BLOCK_IO_PROTOCOL*  io;

	// Write header
	res = CreateVolumeHeaderOnDisk(index, NULL, &hDisk, &headerSector);
	if (EFI_ERROR(res)) {
		return res;
	}

	// Verify header
	io = EfiGetBlockIO(hDisk);
	if (!io) {
		ERR_PRINT(L"can not get block IO\n");
		return EFI_INVALID_PARAMETER;
	}

	res = io->ReadBlocks(io, io->Media->MediaId, headerSector, 512, Header);
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Read error %r(%x)\n", res, res);
		return res;
	}

	res = TryHeaderDecrypt(Header, &gAuthCryptInfo, &gHeaderCryptInfo);
	if (EFI_ERROR(res)) {
		return res;
	}

	// Encrypt range
	vcres = AskConfirm("Encrypt?", 1);
	if (!vcres) {
		ERR_PRINT(L"Encryption stoped\n");
		return EFI_INVALID_PARAMETER;
	}

	res = RangeCrypt(hDisk, 
		gAuthCryptInfo->EncryptedAreaStart.Value >> 9, 
		gAuthCryptInfo->VolumeSize.Value >> 9,
		gAuthCryptInfo->EncryptedAreaLength.Value >> 9,
		gAuthCryptInfo, TRUE,
		gHeaderCryptInfo, headerSector);

	crypto_close(gAuthCryptInfo);
	crypto_close(gHeaderCryptInfo);
	return res;
}

EFI_STATUS
VolumeDecrypt(
	IN UINTN index)
{
	EFI_BLOCK_IO_PROTOCOL*  io;
	EFI_STATUS              res;
	EFI_LBA                 vhsector;
	BioPrintDevicePath(index);

	io = EfiGetBlockIO(gBIOHandles[index]);
	if (!io) {
		ERR_PRINT(L"can not get block IO\n");
		return EFI_INVALID_PARAMETER;
	}

	if (gAuthPasswordMsg == NULL) {
		VCAuthAsk();
	}

	vhsector = AskUINT64("header sector:", gAuthBoot? TC_BOOT_VOLUME_HEADER_SECTOR : 0);
	res = io->ReadBlocks(io, io->Media->MediaId, vhsector, 512, Header);
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Read error %r(%x)\n", res, res);
		return res;
	}

	res = TryHeaderDecrypt(Header, &gAuthCryptInfo, &gHeaderCryptInfo);
	if (EFI_ERROR(res)) {
		return res;
	}

	if (!AskConfirm("Decrypt?", 1)) {
		ERR_PRINT(L"Decryption stoped\n");
		res = EFI_INVALID_PARAMETER;
		goto error;
	}

	res = RangeCrypt(gBIOHandles[index], 
		gAuthCryptInfo->EncryptedAreaStart.Value >> 9, 
		gAuthCryptInfo->VolumeSize.Value >> 9,
		gAuthCryptInfo->EncryptedAreaLength.Value >> 9,
		gAuthCryptInfo, FALSE,
		gHeaderCryptInfo,
		vhsector);

error:
	crypto_close(gHeaderCryptInfo);
	crypto_close(gAuthCryptInfo);
	return res;
}


EFI_STATUS
VolumeChangePassword(
	IN UINTN index
	) 
{
	EFI_BLOCK_IO_PROTOCOL*  io;
	EFI_STATUS              res;
	EFI_LBA                 vhsector;

	BioPrintDevicePath(index);
	io = EfiGetBlockIO(gBIOHandles[index]);
	if (io == NULL) {
		ERR_PRINT(L" No BIO protocol\n");
		return EFI_INVALID_PARAMETER;
	}

	vhsector = gAuthBoot ? TC_BOOT_VOLUME_HEADER_SECTOR : 0;
	vhsector = AskUINT64("sector:", vhsector);
	res = io->ReadBlocks(io, io->Media->MediaId, vhsector, 512, Header);
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Read error %r(%x)\n", res, res);
		return res;
	}

	res = ChangePassword(Header);
	if (EFI_ERROR(res)) return res;

	if (AskConfirm("Save[N]?", 1)) {
		res = io->WriteBlocks(io, io->Media->MediaId, vhsector, 512, Header);
		ERR_PRINT(L"Header saved: %r\n", res);
	}
	return res;
}

//////////////////////////////////////////////////////////////////////////
// OS Rescue 
//////////////////////////////////////////////////////////////////////////

EFI_STATUS
OSDecrypt()
{

	EFI_STATUS              res;
	UINTN                   disk;
	BOOLEAN                 doDecrypt = FALSE;
	EFI_BLOCK_IO_PROTOCOL*  io;
	if (gAuthPasswordMsg == NULL) {
		VCAuthAsk();
	}

	for (disk = 0; disk < gBIOCount; ++disk) {
		if (EfiIsPartition(gBIOHandles[disk])) continue;
		io = EfiGetBlockIO(gBIOHandles[disk]);
		if (io == NULL) continue;
		res = io->ReadBlocks(io, io->Media->MediaId, 62, 512, Header);
		if (EFI_ERROR(res)) continue;
		BioPrintDevicePath(disk);
		res = TryHeaderDecrypt(Header, &gAuthCryptInfo, &gHeaderCryptInfo);
		if (EFI_ERROR(res)) continue;
		doDecrypt = TRUE;
		break;
	}

	if (doDecrypt) {
		if (!AskConfirm("Decrypt?", 1)) {
			ERR_PRINT(L"Decryption stoped\n");
			return EFI_INVALID_PARAMETER;
		}
		res = RangeCrypt(gBIOHandles[disk], 
			gAuthCryptInfo->EncryptedAreaStart.Value >> 9, 
			gAuthCryptInfo->VolumeSize.Value >> 9,
			gAuthCryptInfo->EncryptedAreaLength.Value >> 9, 
			gAuthCryptInfo, FALSE,
			gHeaderCryptInfo,
			62);
		crypto_close(gHeaderCryptInfo);
		crypto_close(gAuthCryptInfo);
	}
	else {
		res = EFI_NOT_FOUND;
	}
	return res;
}

CHAR16* sOSKeyBackup = L"EFI\\" DCS_DIRECTORY L"\\svh_bak";
// dirty import from GptEdit
extern DCS_DISK_ENTRY_DISKID       DeDiskId;

EFI_STATUS
OSBackupKeyLoad(
	UINTN                   *DiskOS
	)
{
	EFI_STATUS              res;
	UINT8                   *restoreData = NULL;
	UINTN                   restoreDataSize;
	UINTN                   disk;
	UINTN                   diskOS;
	EFI_BLOCK_IO_PROTOCOL*  io;
	UINT64                  startUnit = 0;
	INTN                    deListHdrIdOk;

	if (gAuthPasswordMsg == NULL) {
		VCAuthAsk();
	}

	res = FileLoad(NULL, sOSKeyBackup, &SecRegionData, &SecRegionSize);
	if (EFI_ERROR(res) || SecRegionSize < 512) {
		SecRegionSize = 0;
		MEM_FREE(SecRegionData);
		SecRegionData = NULL;
	}
	if (SecRegionSize == 0) {
		res = PlatformGetAuthData(&SecRegionData, &SecRegionSize, &SecRegionHandle);
		if (EFI_ERROR(res)) {
			SecRegionSize = 0;
		}
	}

	if (SecRegionSize == 0) {
		return EFI_INVALID_PARAMETER;
	}

	// Try decrypt/locate header (in file or on removable flash)
	do {
		CopyMem(Header, SecRegionData + SecRegionOffset, 512);
		res = TryHeaderDecrypt(Header, &gAuthCryptInfo, NULL);
		if (EFI_ERROR(res)) {
			SecRegionOffset += 128 * 1024;
			if (SecRegionOffset > SecRegionSize) {
				MEM_FREE(SecRegionData);
				SecRegionData = NULL;
				SecRegionOffset = 0;
				res = PlatformGetAuthData(&SecRegionData, &SecRegionSize, &SecRegionHandle);
				if (EFI_ERROR(res)) {
					return EFI_INVALID_PARAMETER;
				}
			}
		}
		restoreDataSize = (SecRegionSize - SecRegionOffset >= 128 * 1024)? 128 * 1024 : SecRegionSize - SecRegionOffset;
		restoreData = SecRegionData + SecRegionOffset;
	} while (EFI_ERROR(res));

	// Parse DE list if present
	SetMem(&DeDiskId.GptID, sizeof(DeDiskId.GptID), 0x55);
	SetMem(&DeDiskId.MbrID, sizeof(DeDiskId.MbrID), 0x55);
	if (restoreDataSize >= 1024) {
		deListHdrIdOk = CompareMem(restoreData + 512, &gDcsDiskEntryListHeaderID, sizeof(gDcsDiskEntryListHeaderID));
		if (deListHdrIdOk != 0) {
			DecryptDataUnits(restoreData + 512, (UINT64_STRUCT *)&startUnit, (UINT32)(restoreDataSize >> 9) - 1, gAuthCryptInfo);
			deListHdrIdOk = CompareMem(restoreData + 512, &gDcsDiskEntryListHeaderID, sizeof(gDcsDiskEntryListHeaderID));
			if (deListHdrIdOk != 0) {
				res = EFI_CRC_ERROR;
				goto error;
			}
		}
		res = DeListParseSaved(restoreData);
		if (EFI_ERROR(res)) goto error;
	}

	// Search and list all disks
	diskOS = 999;
	for (disk = 0; disk < gBIOCount; ++disk) {
		if (EfiIsPartition(gBIOHandles[disk])) continue;
		io = EfiGetBlockIO(gBIOHandles[disk]);
		if (io == NULL) continue;
		res = io->ReadBlocks(io, io->Media->MediaId, 0, 512, Header);
		if (EFI_ERROR(res)) continue;
		BioPrintDevicePath(disk);
		if (DeDiskId.MbrID == *(uint32 *)(Header + 0x1b8)) {
			res = io->ReadBlocks(io, io->Media->MediaId, 1, 512, Header);
			if (EFI_ERROR(res)) continue;
			if (CompareMem(&DeDiskId.GptID, &((EFI_PARTITION_TABLE_HEADER*)Header)->DiskGUID, sizeof(DeDiskId.GptID)) == 0) {
				diskOS = disk;
				OUT_PRINT(L"%H[found]%N");
			}
		}
		OUT_PRINT(L"\n");
	}
	diskOS = AskUINTN("Select disk:", diskOS);
	if (diskOS >= gBIOCount) {
		res = EFI_INVALID_PARAMETER;
		goto error;
	}

	if (EfiIsPartition(gBIOHandles[diskOS])) {
		res = EFI_INVALID_PARAMETER;
		goto error;
	}
	*DiskOS = diskOS;
	return EFI_SUCCESS;

error:
	MEM_FREE(SecRegionData);
	SecRegionData = NULL;
	SecRegionSize = 0;
	return res;
}

EFI_STATUS
OSRestoreKey()
{
	EFI_STATUS              res;
	UINTN                   disk;
	EFI_BLOCK_IO_PROTOCOL*  io;

	res = OSBackupKeyLoad(&disk);
	if (EFI_ERROR(res)) return res;

	if (!AskConfirm("Restore?", 1)) {
		res = EFI_INVALID_PARAMETER;
		goto error;
	}

	io = EfiGetBlockIO(gBIOHandles[disk]);
	if (io == NULL) {
		res = EFI_INVALID_PARAMETER;
		goto error;
	}

	res = io->WriteBlocks(io, io->Media->MediaId, 62, 512, SecRegionData + SecRegionOffset);

error: 
	MEM_FREE(SecRegionData);
	SecRegionData = NULL;
	SecRegionSize = 0;
	return res;
}

//////////////////////////////////////////////////////////////////////////
// Wipe
//////////////////////////////////////////////////////////////////////////
EFI_STATUS
BlockRangeWipe(
	IN EFI_HANDLE h,
	IN UINT64 start,
	IN UINT64 end
	)
{
	EFI_STATUS              res;
	EFI_BLOCK_IO_PROTOCOL*  bio;
	VOID*                   buf;
	UINT64                  remains;
	UINT64                  pos;
	UINTN                   rd;
	bio = EfiGetBlockIO(h);
	if (bio == 0) {
		ERR_PRINT(L"No block device");
		return EFI_NOT_FOUND;
	}

	res = RndPreapare();
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Rnd: %r\n", res);
		return res;
	}

	EfiPrintDevicePath(h);

	OUT_PRINT(L"\nSectors [%lld, %lld]", start, end);
	if (AskConfirm(", Wipe data?", 1) == 0) return EFI_NOT_READY;
	buf = MEM_ALLOC(CRYPT_BUF_SECTORS << 9);
	if (!buf) {
		ERR_PRINT(L"can not get buffer\n");
		return EFI_INVALID_PARAMETER;
	}
	remains = end -start + 1;
	pos = start;
	do {
		rd = (UINTN)((remains > CRYPT_BUF_SECTORS) ? CRYPT_BUF_SECTORS : remains);

		if (!RandgetBytes(buf, (UINT32)(rd << 9), FALSE)) {
			ERR_PRINT(L"No randoms. Wipe stopped.\n");
			res = EFI_CRC_ERROR;
			MEM_FREE(buf);
			return res;
		}	
		res = bio->WriteBlocks(bio, bio->Media->MediaId, pos, rd << 9, buf);
		if (EFI_ERROR(res)) {
			ERR_PRINT(L"Write error: %r\n", res);
			MEM_FREE(buf);
			return res;
		}
		pos += rd;
		remains -= rd;
		OUT_PRINT(L"%lld %lld       \r", pos, remains);
	} while (remains > 0);
	OUT_PRINT(L"\nDone\n", pos, remains);
	MEM_FREE(buf);
	return res;
}

//////////////////////////////////////////////////////////////////////////
// DCS authorization check
//////////////////////////////////////////////////////////////////////////
EFI_STATUS
IntCheckVolume(
	UINTN index
	)
{
	EFI_BLOCK_IO_PROTOCOL*  pBio;
	EFI_STATUS              res;
	EFI_LBA                 vhsector;

	BioPrintDevicePath(index);
	pBio = EfiGetBlockIO(gBIOHandles[index]);
	if (pBio == NULL) {
		ERR_PRINT(L" No BIO protocol\n");
		return EFI_NOT_FOUND;
	}

	vhsector = gAuthBoot ? TC_BOOT_VOLUME_HEADER_SECTOR : 0;
	res = pBio->ReadBlocks(pBio, pBio->Media->MediaId, vhsector, 512, Header);
	if (EFI_ERROR(res)) {
		ERR_PRINT(L" %r(%x)\n", res, res);
		return res;
	}
	
	res = TryHeaderDecrypt(Header, &gAuthCryptInfo, NULL);
	if (res != 0) {
		if (gAuthBoot == 0) {
			OUT_PRINT(L"Try hidden...");
			res = pBio->ReadBlocks(pBio, pBio->Media->MediaId, TC_VOLUME_HEADER_SIZE / 512, 512, Header);
			if (EFI_ERROR(res)) {
				ERR_PRINT(L" %r(%x)\n", res, res);
				return res;
			}
			res = TryHeaderDecrypt(Header, &gAuthCryptInfo, NULL);
		}
	}
	return res;
}

VOID
DisksAuthCheck() {
	UINTN i;
	if (BioIndexStart >= gBIOCount) return;
	i = BioIndexStart;
	do {
		IntCheckVolume(i);
		++i;
	} while ((i < gBIOCount) && (i <= BioIndexEnd));
}

VOID
TestAuthAsk() {
	VCAuthAsk();
}

EFI_STATUS
CreateVolumeHeaderOnDisk(
	IN UINTN      index,
	OUT VOID      **pinfo,
	OUT EFI_HANDLE *phDisk,
	OUT UINT64     *sector
	) 
{
	EFI_BLOCK_IO_PROTOCOL*  bio;
	EFI_STATUS              res;
	UINT64                  encSectorStart = 0;
	UINT64                  encSectorEnd = 0;
	UINT64                  VolumeSize = 0;
	PCRYPTO_INFO            ci = 0;
	EFI_LBA                 vhsector;
	EFI_LBA                 vhsector2;
	EFI_HANDLE              hDisk = NULL;
	HARDDRIVE_DEVICE_PATH   hdp;
	BOOLEAN                 isPart;

	BioPrintDevicePath(index);
	OUT_PRINT(L"\n");

	gAuthBoot = AskConfirm("Boot mode[N]?", 1);
	isPart = EfiIsPartition(gBIOHandles[index]);
	if (isPart) {
		res = EfiGetPartDetails(gBIOHandles[index], &hdp, &hDisk);
		if (!EFI_ERROR(res)) {
			if (gAuthBoot) {
				encSectorStart = hdp.PartitionStart;
				encSectorEnd = hdp.PartitionSize + encSectorStart - 1;
				VolumeSize = hdp.PartitionSize;
			}
			else {
				encSectorEnd = hdp.PartitionSize - encSectorStart - 256;
				VolumeSize = hdp.PartitionSize;
			}
		}
	}

	res = CreateVolumeHeader(Header, &ci, VolumeSize, encSectorStart, encSectorEnd);
	if (EFI_ERROR(res)) {
		return res;
	}

	if (isPart && gAuthBoot) {
		OUT_PRINT(L"Boot drive to save is selected. \n");
		EfiPrintDevicePath(hDisk);
		OUT_PRINT(L"\n");
	}	else {
		hDisk = gBIOHandles[index];
	}

	bio = EfiGetBlockIO(hDisk);
	if (bio == NULL) {
		ERR_PRINT(L"No BIO protocol\n");
		return EFI_NOT_FOUND;
	}

	vhsector  = AskUINT64("primary sector to save:", gAuthBoot ? 62 : 0);
	vhsector2 = vhsector;
	if (!gAuthBoot) {
		vhsector2 = AskUINT64("backup sector to save:", vhsector);
	}
	if (AskConfirm("Save [N]?", 1)) {
		res = bio->WriteBlocks(bio, bio->Media->MediaId, vhsector, 512, Header);
		ERR_PRINT(L"Write %lld: %r\n", vhsector, res);
		if (vhsector != vhsector2) {
			res = bio->WriteBlocks(bio, bio->Media->MediaId, vhsector2, 512, BackupHeader);
			ERR_PRINT(L"Write %lld: %r\n", vhsector2, res);
		}
	}

	if (phDisk != NULL) *phDisk = hDisk;
	if (pinfo != NULL) {
		*pinfo = ci;
	}	else {
		crypto_close(ci);
	}
	if (sector != NULL)*sector = vhsector;
	return res;
}

EFI_STATUS 
CreateVolumeHeadersInMemory(
	int ea,
	int mode,
	int pkcs5,
	UINT64 encSectorStart,
	UINT64 encSectorEnd,
	UINT64 VolumeSize,
	UINT64 hiddenVolumeSize,
	UINT32 HeaderFlags
) {
	int8 master_keydata[MASTER_KEYDATA_SIZE];
	INT32                   vcres;
	PCRYPTO_INFO            rci = 0;
	if (!RandgetBytes(master_keydata, MASTER_KEYDATA_SIZE, FALSE)) {
		ERR_PRINT(L"No randoms\n");
		return EFI_CRC_ERROR;
	}

	vcres = CreateVolumeHeaderInMemory(
		FALSE, Header,
		ea,
		mode,
		&gAuthPassword,
		pkcs5,
		gAuthPim,
		master_keydata,
		&rci,
		VolumeSize << 9,
		hiddenVolumeSize << 9,
		encSectorStart << 9,
		(encSectorEnd - encSectorStart + 1) << 9,
		VERSION_NUM,
		HeaderFlags,
		512,
		FALSE);

	if (vcres != 0) {
		ERR_PRINT(L"Header error %d\n", vcres);
		return EFI_CRC_ERROR;
	}
	crypto_close(rci);

	vcres = CreateVolumeHeaderInMemory(
		FALSE, BackupHeader,
		ea,
		mode,
		&gAuthPassword,
		pkcs5,
		gAuthPim,
		master_keydata,
		&rci,
		VolumeSize << 9,
		hiddenVolumeSize << 9,
		encSectorStart << 9,
		(encSectorEnd - encSectorStart + 1) << 9,
		VERSION_NUM,
		HeaderFlags,
		512,
		FALSE);

	if (vcres != 0) {
		ERR_PRINT(L"Header error %d\n", vcres);
		return EFI_CRC_ERROR;
	}
	crypto_close(rci);
	return EFI_SUCCESS;
}

EFI_STATUS 
PartitionOuterInit(
	UINTN diskIndex,
	UINTN outerIndex,
	UINTN endIndex)
{
	INT32                   vcres;
	int                     mode = 0;
	int                     ea = 0;
	int                     pkcs5 = 0;
	UINT64                  encSectorStart;
	UINT64                  encSectorEnd;
	UINT64                  hiddenVolumeSize;
	UINT64                  VolumeSize;
	int8                    master_keydata[MASTER_KEYDATA_SIZE];
	EFI_BLOCK_IO_PROTOCOL*  bio;
	EFI_STATUS              res;
	EFI_LBA                 vhsector;
	EFI_LBA                 vhsector2;
	UINT64                  savePadding = 256;

	if (!RandgetBytes(master_keydata, MASTER_KEYDATA_SIZE, FALSE)) {
		ERR_PRINT(L"No randoms\n");
		return EFI_CRC_ERROR;
	}

	if (CompareGuid(&GptMainEntrys[outerIndex].PartitionTypeGUID, &gEfiPartTypeUnusedGuid) ||
		CompareGuid(&GptMainEntrys[endIndex].PartitionTypeGUID, &gEfiPartTypeUnusedGuid)
		) {
		ERR_PRINT(L"Bad partition indexes %d %d\n", outerIndex, endIndex);
		return EFI_INVALID_PARAMETER;
	}
	if (EfiIsPartition(gBIOHandles[diskIndex])) {
		ERR_PRINT(L"Select disk (not partition)\n");
		return EFI_INVALID_PARAMETER;
	}

	bio = EfiGetBlockIO(gBIOHandles[diskIndex]);
	if (bio == NULL) {
		ERR_PRINT(L"No BIO protocol\n");
		return EFI_NOT_FOUND;
	}

	// Wipe Outer start, Outer end
	DeListPrint();
	BlockRangeWipe(gBIOHandles[diskIndex], GptMainEntrys[outerIndex].StartingLBA, GptMainEntrys[outerIndex].EndingLBA);
	BlockRangeWipe(gBIOHandles[diskIndex], GptMainEntrys[endIndex].StartingLBA, GptMainEntrys[endIndex].EndingLBA);

	if (AskConfirm("Init outer headers?", 1)) {
		// init header outer start
		if (gAuthPasswordMsg == NULL) {
			VCAuthAsk();
		}

		ea = AskEA();
		mode = AskMode(ea);
		pkcs5 = AskPkcs5();

		encSectorStart = 256;
		encSectorEnd = GptMainEntrys[endIndex].EndingLBA - GptMainEntrys[outerIndex].StartingLBA - 256;
		VolumeSize = GptMainEntrys[endIndex].EndingLBA - GptMainEntrys[outerIndex].StartingLBA - 512 + 1;
		hiddenVolumeSize = 0;
		res = CreateVolumeHeadersInMemory(
			ea, mode, pkcs5,
			encSectorStart, encSectorEnd, VolumeSize, hiddenVolumeSize, 0);
		vhsector = GptMainEntrys[outerIndex].StartingLBA;
		vhsector2 = GptMainEntrys[endIndex].EndingLBA - 255;
		if (EFI_ERROR(res)) {
			ERR_PRINT(L"Create header: %r\n", res);
		}
		EfiPrintDevicePath(gBIOHandles[diskIndex]);
		OUT_PRINT(L"[%lld, %lld] size %lld to %lld,%lld\n", encSectorStart, encSectorEnd, VolumeSize, vhsector, vhsector2);
		if (!AskConfirm("Save outer[N]?", 1)) {
			return EFI_NOT_READY;
		}
		res = bio->WriteBlocks(bio, bio->Media->MediaId, vhsector, 512, Header);
		ERR_PRINT(L"Write %lld: %r\n", vhsector, res);
		if (vhsector != vhsector2) {
			res = bio->WriteBlocks(bio, bio->Media->MediaId, vhsector2, 512, BackupHeader);
			ERR_PRINT(L"Write %lld: %r\n", vhsector2, res);
		}

		// init header outer end
		VCAuthAsk();
		encSectorStart = GptMainEntrys[endIndex].StartingLBA - GptMainEntrys[outerIndex].StartingLBA;
		encSectorEnd = GptMainEntrys[endIndex].EndingLBA - GptMainEntrys[outerIndex].StartingLBA - 256 - savePadding;
		VolumeSize = GptMainEntrys[endIndex].EndingLBA - GptMainEntrys[endIndex].StartingLBA - 256 + 1 - savePadding;
		hiddenVolumeSize = VolumeSize;
		res = CreateVolumeHeadersInMemory(
			ea, mode, pkcs5,
			encSectorStart, encSectorEnd, VolumeSize, hiddenVolumeSize, 0);
		if (EFI_ERROR(res)) {
			ERR_PRINT(L"Create header: %r\n", res);
		}
		vhsector = GptMainEntrys[outerIndex].StartingLBA + 128;
		vhsector2 = GptMainEntrys[endIndex].EndingLBA - 127;

		EfiPrintDevicePath(gBIOHandles[diskIndex]);
		OUT_PRINT(L"[%lld, %lld] size %lld to %lld,%lld\n", encSectorStart, encSectorEnd, VolumeSize, vhsector, vhsector2);
		if (!AskConfirm("Save outer[N]?", 1)) {
			return EFI_NOT_READY;
		}
		res = bio->WriteBlocks(bio, bio->Media->MediaId, vhsector, 512, Header);
		ERR_PRINT(L"Write %lld: %r\n", vhsector, res);
		if (vhsector != vhsector2) {
			res = bio->WriteBlocks(bio, bio->Media->MediaId, vhsector2, 512, BackupHeader);
			ERR_PRINT(L"Write %lld: %r\n", vhsector2, res);
		}
	}

	if (AskConfirm("Update main encryption header?", 1)) {
		PCRYPTO_INFO cryptoInfo;
		PCRYPTO_INFO ci;
		CHAR8 fname8[256];
		CHAR16 fname16[256];

		VCAuthAsk();
		res = TryHeaderDecrypt(DeCryptoHeader, &cryptoInfo, NULL);
		if (EFI_ERROR(res)) {
			ERR_PRINT(L"Decrypt: %r\n", res);
			return res;
		}

		if (cryptoInfo->EncryptedAreaLength.Value != 0) {
			ERR_PRINT(L"Encrypted already\n");
			return EFI_INVALID_PARAMETER;
		}

		encSectorStart = GptMainEntrys[outerIndex].EndingLBA + 1;
		encSectorEnd = GptMainEntrys[endIndex].StartingLBA - 1;
		VolumeSize = encSectorEnd - encSectorStart + 1;

		vcres = CreateVolumeHeaderInMemory(
			TRUE, Header,
			cryptoInfo->ea,
			cryptoInfo->mode,
			&gAuthPassword,
			cryptoInfo->pkcs5,
			gAuthPim,
			cryptoInfo->master_keydata,
			&ci,
			VolumeSize << 9,
			0,
			encSectorStart << 9,
			0,
			cryptoInfo->RequiredProgramVersion,
			cryptoInfo->HeaderFlags,
			cryptoInfo->SectorSize,
			FALSE);

		if (vcres != 0) {
			ERR_PRINT(L"header create error(%x)\n", vcres);
			return EFI_INVALID_PARAMETER;
		}
		crypto_close(ci);
		vhsector = 62;
		res = bio->WriteBlocks(bio, bio->Media->MediaId, vhsector, 512, Header);
		ERR_PRINT(L"Write %lld: %r\n", vhsector, res);

		vcres = CreateVolumeHeaderInMemory(
			TRUE, Header,
			cryptoInfo->ea,
			cryptoInfo->mode,
			&gAuthPassword,
			cryptoInfo->pkcs5,
			gAuthPim,
			cryptoInfo->master_keydata,
			&ci,
			VolumeSize << 9,
			0,
			encSectorStart << 9,
			VolumeSize << 9,
			cryptoInfo->RequiredProgramVersion,
			cryptoInfo->HeaderFlags,
			cryptoInfo->SectorSize,
			FALSE);

		if (vcres != 0) {
			ERR_PRINT(L"header create error(%x)\n", vcres);
			return EFI_INVALID_PARAMETER;
		}
		crypto_close(ci);
		MEM_FREE(DeCryptoHeader);
		DeCryptoHeader = Header;
		AskAsciiString("Encrypted GPT file name:", fname8, sizeof(fname8), 1, "gpt_enc");
		AsciiStrToUnicodeStr(fname8, fname16);
		DcsDiskEntrysFileName = fname16;
		DeListSaveToFile();
	}

	if (AskConfirm("Create GPT with one hidden volume?", 1)) {
		CHAR8 fname8[256];
		CHAR16 fname16[256];
		// Save hiding GPT
		CopyMem(&DcsHidePart, &GptMainEntrys[outerIndex], sizeof(DcsHidePart));
		DcsHidePart.EndingLBA = GptMainEntrys[endIndex].EndingLBA;
		GptHideParts();
		AskAsciiString("Hidden GPT file name:", fname8, sizeof(fname8), 1, "gpt_hidden");
		AsciiStrToUnicodeStr(fname8, fname16);
		DcsDiskEntrysFileName = fname16;
		DeListSaveToFile();
	}

	return EFI_SUCCESS;
}

EFI_STATUS
OuterInit() 
{
	UINTN disk;
	UINTN startOuter;
	UINTN endOuter;
	BioSkipPartitions = TRUE;
	PrintBioList();
	disk = AskUINTN("Disk:", 0);
	GptLoadFromDisk(disk);
	DeListPrint();
	startOuter = AskUINTN("Start outer:", 0);
	endOuter = AskUINTN("End outer:", startOuter + 3);
	return PartitionOuterInit(disk, startOuter, endOuter);
}

//////////////////////////////////////////////////////////////////////////
// USB
//////////////////////////////////////////////////////////////////////////
UINTN       UsbIndex = 0;
void UsbIoPrintDevicePath(UINTN uioIndex) {
	CHAR8*		id = NULL;
	OUT_PRINT(L"%V%d%N ", uioIndex);
	EfiPrintDevicePath(gUSBHandles[uioIndex]);
	UsbGetId(gUSBHandles[uioIndex], &id);
	if (id != NULL) {
		UINT32 rud;
		rud = (UINT32)GetCrc32((unsigned char*)id, (int)AsciiStrLen(id));
		OUT_PRINT(L" -(%d) %a", rud, id);
		MEM_FREE(id);
	}
}

void UsbIoPrintDevicePaths(CHAR16* msg) {
	UINTN i;
	OUT_PRINT(msg);
	for (i = 0; i < gUSBCount; ++i) {
		UsbIoPrintDevicePath(i);
		OUT_PRINT(L"\n");
	}
}

VOID
PrintUsbList() {
	InitUsb();
	UsbIoPrintDevicePaths(L"%HUSB IO handles%N\n");
}

EFI_STATUS
UsbScApdu(
	IN CHAR16* hexString) 
{
	UINT8     cmd[256];
	UINTN     cmdLen = sizeof(cmd) - sizeof(CCID_HEADER_OUT);
	UINT8     resp[256];
	UINTN     respLen = sizeof(resp);
	UINT16    statusSc = 0;
	EFI_USB_IO_PROTOCOL *UsbIo =NULL;
	EFI_STATUS res;
	CE(InitUsb());
	CE(UsbGetIO(gUSBHandles[UsbIndex], &UsbIo));
	DcsStrHexToBytes(cmd + sizeof(CCID_HEADER_OUT), &cmdLen, hexString);
	CE(UsbScTransmit(UsbIo, cmd, cmdLen + sizeof(CCID_HEADER_OUT), resp, &respLen, &statusSc));
	PrintBytes(resp, respLen);
	return res;
err:
	ERR_PRINT(L"Error(%d) %r\n", gCELine, res);
	return res;
}


//////////////////////////////////////////////////////////////////////////
// Set DcsInt parameters
//////////////////////////////////////////////////////////////////////////
VOID
UpdateDcsBoot() {
	EFI_STATUS res;
	HARDDRIVE_DEVICE_PATH   dpVolme;
	EFI_HANDLE              hDisk;
	if (BioIndexStart >= gBIOCount) {
		// Delete var
		res = EfiSetVar(DCS_BOOT_STR, &gEfiDcsVariableGuid, NULL, 0, 0);
	}
	else {
		// Set var
		EFI_DEVICE_PATH             *DevicePath;
		UINTN len;
		BioPrintDevicePath(BioIndexStart);
		res = EfiGetPartDetails(gBIOHandles[BioIndexStart], &dpVolme, &hDisk);
		if (EFI_ERROR(res)) {
			OUT_PRINT(L" %r\n", res);
			return;
		}
		DevicePath = DevicePathFromHandle(hDisk);
		len = GetDevicePathSize(DevicePath);
//		res = EfiSetVar(DCS_BOOT_STR, NULL, DevicePath, len, EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS);
		res = FileSave(NULL, DCS_BOOT_STR, DevicePath, len);
		if (EFI_ERROR(res)) {
			OUT_PRINT(L" %r\n", res);
			return;
		}
		else
		{
			OUT_PRINT(L"Boot:");
			EfiPrintDevicePath(hDisk);
			OUT_PRINT(L"\n");
		}
	}	
	OUT_PRINT(L" %r\n", res);
}

//////////////////////////////////////////////////////////////////////////
// Security region
//////////////////////////////////////////////////////////////////////////
UINTN gSecRigonCount = 0;

EFI_STATUS
SecRegionMark() 
{
	UINT32      crc;
	EFI_STATUS  res;
	DCS_AUTH_DATA_MARK* adm;
	EFI_BLOCK_IO_PROTOCOL* bio;

	res = PlatformGetIDCRC(gBIOHandles[BioIndexStart], &crc);
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"CRC: %r\n", res);
		return res;
	}

	adm = (DCS_AUTH_DATA_MARK*)MEM_ALLOC(512);
	if (adm == NULL) {
		ERR_PRINT(L"no memory\n");
		return EFI_BUFFER_TOO_SMALL;
	}

	adm->AuthDataSize = (UINT32)gSecRigonCount;
	adm->PlatformCrc = crc;
	res = gBS->CalculateCrc32(&adm->PlatformCrc, sizeof(*adm) - 4, &adm->HeaderCrc);

	if (EFI_ERROR(res)) {
		ERR_PRINT(L"CRC: %r\n", res);
		return res;
	}

	bio = EfiGetBlockIO(gBIOHandles[BioIndexStart]);
	if (bio == NULL) {
		MEM_FREE(adm);
		ERR_PRINT(L"No block IO");
		return EFI_ACCESS_DENIED;
	}
	res = bio->WriteBlocks(bio, bio->Media->MediaId, 61, 512, adm);
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Write: %r\n", res);
	}
	MEM_FREE(adm);
	return res;
}

EFI_STATUS
SecRegionWipe()
{
	EFI_STATUS  res;
	CHAR8*      buf;
	UINTN       i;
	EFI_BLOCK_IO_PROTOCOL* bio;

	buf = MEM_ALLOC(128 * 1024);
	if (buf == NULL) {
		ERR_PRINT(L"no memory\n");
		return EFI_BUFFER_TOO_SMALL;
	}

	bio = EfiGetBlockIO(gBIOHandles[BioIndexStart]);
	if (bio == NULL) {
		ERR_PRINT(L"No block IO");
		res = EFI_ACCESS_DENIED;
		goto error;
	}

	if (!RandgetBytes(buf, 512, FALSE)) {
		ERR_PRINT(L"No randoms\n");
		res = EFI_CRC_ERROR;
		goto error;
	}	
	
	// Wipe mark
	res = bio->WriteBlocks(bio, bio->Media->MediaId, 61, 512, buf);
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Write: %r\n", res);
		goto error;
	}

	// Wipe region
	for (i = 0; i < gSecRigonCount; ++i) {
		if (!RandgetBytes(buf, 128 * 1024, FALSE)) {
			ERR_PRINT(L"No randoms\n");
			res = EFI_CRC_ERROR;
			goto error;
		}
		res = bio->WriteBlocks(bio, bio->Media->MediaId, 62 + i * (128 * 1024 / 512), 128 * 1024, buf);
		if (EFI_ERROR(res)) {
			ERR_PRINT(L"Write: %r\n", res);
			goto error;
		}
	}
	return EFI_SUCCESS;

error:
	MEM_FREE(buf);
	return res;
}

EFI_STATUS
SecRegionDump(
	IN EFI_HANDLE   hBio,
	IN CHAR16       *prefix
	)
{
	EFI_STATUS              res = EFI_SUCCESS;
	EFI_BLOCK_IO_PROTOCOL*  bio;
	DCS_AUTH_DATA_MARK*     adm = NULL;
	UINT32                  crc;
	UINT8*                  SecRegionDumpData = NULL;
	UINTN                   SecRegionDumpSize = 0;
	UINTN                   SecRegionDumpOffset = 0;
	UINTN                   saveSize = 0;
	UINTN                   idx = 0;
	CHAR16                  name[128];

	adm = (DCS_AUTH_DATA_MARK*)MEM_ALLOC(512);
	if (adm == NULL) {
		ERR_PRINT(L"no memory\n");
		return EFI_BUFFER_TOO_SMALL;
	}

	bio = EfiGetBlockIO(hBio);
	if (bio == NULL) {
		ERR_PRINT(L"No block IO");
		res = EFI_ACCESS_DENIED;
		goto err;
	}

	CE(bio->ReadBlocks(bio, bio->Media->MediaId, 61, 512, adm));
	CE(gBS->CalculateCrc32(&adm->PlatformCrc, sizeof(*adm) - 4, &crc));

	if (adm->HeaderCrc != crc) {
		res = EFI_INVALID_PARAMETER;
	}

	SecRegionDumpSize = adm->AuthDataSize * 128 * 1024;
	SecRegionDumpData = MEM_ALLOC(SecRegionDumpSize);
	if (SecRegionDumpData == NULL) {
		res = EFI_BUFFER_TOO_SMALL;
		goto err;
	}
	CE(bio->ReadBlocks(bio, bio->Media->MediaId, 62, SecRegionDumpSize, SecRegionDumpData));

	do {
		// EFI tables?
		if (TablesVerify(SecRegionDumpSize - SecRegionDumpOffset, SecRegionDumpData + SecRegionDumpOffset)) {
			EFI_TABLE_HEADER *mhdr = (EFI_TABLE_HEADER *)(SecRegionDumpData + SecRegionDumpOffset);
			UINTN tblZones = (mhdr->HeaderSize + 1024 * 128 - 1) / (1024 * 128);
			saveSize = tblZones * 1024 * 128;
		}		else {
			saveSize = 1024 * 128;
		}
		UnicodeSPrint(name, sizeof(name), L"%s%d", prefix, idx);
		CE(FileSave(NULL, name, SecRegionDumpData + SecRegionDumpOffset, saveSize));
		OUT_PRINT(L"%s saved\n", name);
		idx += saveSize / (1024 * 128);
		SecRegionDumpOffset += saveSize;
	} while (SecRegionDumpOffset < SecRegionDumpSize);

err:
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"%r\n", res);
	}
	MEM_FREE(adm);
	MEM_FREE(SecRegionDumpData);
	return res;
}


EFI_STATUS
SecRegionAdd(
	IN UINTN       regIdx
)
{
	EFI_STATUS  res = EFI_SUCCESS;
	EFI_BLOCK_IO_PROTOCOL* bio;
	UINT8*      regionData;
	UINTN       regionSize;
	UINT8*      padding = NULL;
	UINTN       paddingSize = 0;
	INTN        deListHdrIdOk;
	res = FileLoad(NULL, (CHAR16*)DcsDiskEntrysFileName, &regionData, &regionSize);
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Load %s: %r\n", DcsDiskEntrysFileName, res);
		return res;
	}
	deListHdrIdOk = CompareMem(regionData + 512, &gDcsDiskEntryListHeaderID, sizeof(gDcsDiskEntryListHeaderID));

	if (deListHdrIdOk == 0) {
		ERR_PRINT(L"GPT has to be encrypted\n");
		res = EFI_CRC_ERROR;
		goto error;
	}

	bio = EfiGetBlockIO(gBIOHandles[BioIndexStart]);
	if (bio == NULL) {
		ERR_PRINT(L"No block IO");
		res = EFI_ACCESS_DENIED;
		goto error;
	}
	paddingSize = regionSize & 0x01FF;
	regionSize -= paddingSize;
	res = bio->WriteBlocks(bio, bio->Media->MediaId, 62 + regIdx * (128 * 1024 / 512), regionSize, regionData);

	if (!EFI_ERROR(res) && 
		  paddingSize != 0) {
		padding = MEM_ALLOC(512);
		CopyMem(padding, regionData + regionSize, paddingSize);
		res = bio->WriteBlocks(bio, bio->Media->MediaId, 62 + regIdx * ((128 * 1024 ) / 512) + regionSize / 512, 512, padding);
		MEM_FREE(padding);
	}

	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Write: %r\n", res);
		goto error;
	}

error:
	MEM_FREE(regionData);
	return res;
}

//////////////////////////////////////////////////////////////////////////
// GPT
//////////////////////////////////////////////////////////////////////////
EFI_STATUS
GptCryptFile(
	IN BOOLEAN  crypt
	)
{
	EFI_STATUS  res = EFI_SUCCESS;
	UINT64      startUnit = 0;
	UINT8*      regionData;
	UINTN       regionSize;
	INTN        deListHdrIdOk;

	res = FileLoad(NULL, (CHAR16*)DcsDiskEntrysFileName, &regionData, &regionSize);
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Load %s: %r\n", DcsDiskEntrysFileName, res);
		return res;
	}
	deListHdrIdOk = CompareMem(regionData + 512, &gDcsDiskEntryListHeaderID, sizeof(gDcsDiskEntryListHeaderID));

	if ((deListHdrIdOk != 0) && crypt) {
		ERR_PRINT(L"Already encrypted\n");
		res = EFI_CRC_ERROR;
		goto error;
	}

	if ((deListHdrIdOk == 0) && !crypt) {
		ERR_PRINT(L"Already decrypted\n");
		res = EFI_CRC_ERROR;
		goto error;
	}

	DetectX86Features();
	CopyMem(Header, regionData, sizeof(Header));
	res = TryHeaderDecrypt(Header, &gAuthCryptInfo, NULL);
	if(EFI_ERROR(res)){
		goto error;
	}
	startUnit = 0;
	if (crypt) {
		EncryptDataUnits(regionData + 512, (UINT64_STRUCT *)&startUnit, (UINT32)(regionSize >> 9) - 1, gAuthCryptInfo);
	}
	else {
		DecryptDataUnits(regionData + 512, (UINT64_STRUCT *)&startUnit, (UINT32)(regionSize >> 9) - 1, gAuthCryptInfo);
	}

	res = FileSave(NULL, (CHAR16*)DcsDiskEntrysFileName, regionData, regionSize);
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Save %s: %r\n", DcsDiskEntrysFileName, res);
		goto error;
	}

error:
	MEM_FREE(regionData);
	return res;
}

EFI_STATUS
GptEdit(
	IN UINTN index
	)
{

	EFI_PARTITION_ENTRY* part = &GptMainEntrys[index];
	
	///
	/// Null-terminated name of the partition.
	///
	CHAR16    PartitionName[36];
	UINTN     len;
	while (!GptAskGUID("type (msr, data, wre, efi, del or guid)\n\r:", &part->PartitionTypeGUID));
	if (CompareMem(&part->PartitionTypeGUID, &gEfiPartTypeUnusedGuid, sizeof(EFI_GUID)) == 0) {
		ZeroMem(part, sizeof(*part));
		GptSqueze();
		GptSort();
		GptSyncMainAlt();
		return EFI_SUCCESS;
	}
	while (!GptAskGUID("id\n\r:", &part->UniquePartitionGUID));
	part->StartingLBA = AskUINT64("StartingLBA:", part->StartingLBA);
	part->EndingLBA = AskUINT64("EndingLBA:", part->EndingLBA);
	part->Attributes = AskHexUINT64("Attributes\n\r:", part->Attributes);
	OUT_PRINT(L"[%s]\n\r:", part->PartitionName);
	GetLine(&len, PartitionName, NULL, sizeof(PartitionName) / 2 - 1, 1);
	if (len != 0) {
		CopyMem(&part->PartitionName, PartitionName, sizeof(PartitionName));
	}
	GptSqueze();
	GptSort();
	GptSyncMainAlt();
	return EFI_SUCCESS;
}
