/*
*
* DiskCryptor - open source partition encryption tool
* Copyright (c) 2025-2026
* DavidXanatos <info@diskcryptor.org>
*

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License version 3 as
published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <windows.h>
#include "misc/dirent.h"
#include <stdio.h>
#include <io.h>
#include <assert.h>
#include "dcconst.h"
#include "volume_header.h"
#include "bootloader.h"
#include "efiinst.h"
#include "misc.h"
#include "ntdll.h"
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")


// EFI Image Security Database GUID - used for Secure Boot variables (db, dbx, KEK, PK)
// {d719b2cb-3d3a-4596-a3bc-dad00e67656f}
const wchar_t* sb_var_guid = L"{D719B2CB-3D3A-4596-A3BC-DAD00E67656F}";

// EFI Global Variable GUID - alternative namespace for PK and KEK on some systems
// {8be4df61-93ca-11d2-aa0d-00e098032b8c}
//const wchar_t* efi_var_guid = L"{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}";


// EFI Signature Database structures
// Use standard Windows GUID for proper alignment and byte order
typedef struct {
	GUID SignatureType;
	DWORD SignatureListSize;
	DWORD SignatureHeaderSize;
	DWORD SignatureSize;
	// Followed by SignatureHeader[SignatureHeaderSize]
	// Followed by Signatures[]
} EFI_SIGNATURE_LIST;

typedef struct {
	GUID SignatureOwner;
	// Followed by SignatureData
} EFI_SIGNATURE_DATA;

// EFI Certificate type GUIDs using Windows GUID format (from UEFI Spec 2.10)

// EFI_CERT_SHA256_GUID = {c1c41626-504c-4092-aca9-41f936934328}
// Hash digest using SHA-256 (commonly used in dbx for forbidden binaries)
static const GUID EFI_CERT_SHA256_GUID =
{ 0xc1c41626, 0x504c, 0x4092, { 0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43, 0x28 } };

// EFI_CERT_RSA2048_GUID = {3c5766a8-1a4c-4a99-adb8-957f2cf94f0b}
// RSA-2048 key (deprecated, rarely used)
static const GUID EFI_CERT_RSA2048_GUID =
{ 0x3c5766a8, 0x1a4c, 0x4a99, { 0xad, 0xb8, 0x95, 0x7f, 0x2c, 0xf9, 0x4f, 0x0b } };

// EFI_CERT_RSA2048_SHA256_GUID = {e8663db0-69b0-4e30-a6c1-c83b3ab91f7e}
// RSA-2048 signature with SHA-256 hash (sometimes used in PK)
static const GUID EFI_CERT_RSA2048_SHA256_GUID =
{ 0xe8663db0, 0x69b0, 0x4e30, { 0xa6, 0xc1, 0xc8, 0x3b, 0x3a, 0xb9, 0x1f, 0x7e } };

// EFI_CERT_RSA2048_SHA256_GUID variant (Microsoft specific)
// {452e8ced-dfff-4b8c-ae01-5118862e682c}
static const GUID EFI_CERT_TYPE_RSA2048_SHA256_GUID =
{ 0x452e8ced, 0xdfff, 0x4b8c, { 0xae, 0x01, 0x51, 0x18, 0x86, 0x2e, 0x68, 0x2c } };

// EFI_CERT_SHA1_GUID = {826ca512-cf10-4ac9-b187-be01496631bd}
// Hash digest using SHA-1
static const GUID EFI_CERT_SHA1_GUID =
{ 0x826ca512, 0xcf10, 0x4ac9, { 0xb1, 0x87, 0xbe, 0x01, 0x49, 0x66, 0x31, 0xbd } };

// EFI_CERT_RSA2048_SHA1_GUID = {67f8444f-8743-48f1-a328-1eaab8736080}
// RSA-2048 signature with SHA-1 hash
static const GUID EFI_CERT_RSA2048_SHA1_GUID =
{ 0x67f8444f, 0x8743, 0x48f1, { 0xa3, 0x28, 0x1e, 0xaa, 0xb8, 0x73, 0x60, 0x80 } };

// EFI_CERT_X509_GUID = {a5c059a1-94e4-4aa7-87b5-ab155c2bf072}
// X.509 certificate (most commonly used in PK, KEK, db)
static const GUID EFI_CERT_X509_GUID =
{ 0xa5c059a1, 0x94e4, 0x4aa7, { 0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72 } };

// EFI_CERT_X509_SHA256_GUID = {3bd2a492-96c0-4079-b420-fcf98ef103ed}
// X.509 certificate with SHA-256 hash
static const GUID EFI_CERT_X509_SHA256_GUID =
{ 0x3bd2a492, 0x96c0, 0x4079, { 0xb4, 0x20, 0xfc, 0xf9, 0x8e, 0xf1, 0x03, 0xed } };

// EFI_CERT_X509_SHA384_GUID = {7076876e-80c2-4ee6-aad2-28b349a6865b}
// X.509 certificate with SHA-384 hash
static const GUID EFI_CERT_X509_SHA384_GUID =
{ 0x7076876e, 0x80c2, 0x4ee6, { 0xaa, 0xd2, 0x28, 0xb3, 0x49, 0xa6, 0x86, 0x5b } };

// EFI_CERT_X509_SHA512_GUID = {446dbf63-2502-4cda-bcfa-2465d2b0fe9d}
// X.509 certificate with SHA-512 hash
static const GUID EFI_CERT_X509_SHA512_GUID =
{ 0x446dbf63, 0x2502, 0x4cda, { 0xbc, 0xfa, 0x24, 0x65, 0xd2, 0xb0, 0xfe, 0x9d } };

// Structure to hold certificate thumbprint
typedef struct _cert_thumbprint {
	BYTE hash[20]; // SHA1 hash
	char CN[65];
	struct _cert_thumbprint* next;
} cert_thumbprint;

// List of allowed signers
static cert_thumbprint* g_allowed_signers = NULL;
static int g_secureboot_db_initialized = 0;

// Helper function to compare GUIDs
static int dc_compare_efi_guid(const GUID* guid1, const GUID* guid2)
{
	return memcmp(guid1, guid2, sizeof(GUID)) == 0;
}

// Debug helper to format GUID as string (for debugging)
#ifdef _DEBUG
static void dc_debug_guid(const GUID* guid, const char* label)
{
	char msg[256];
	sprintf_s(msg, sizeof(msg), "%s: {%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}\n",
		label,
		guid->Data1, guid->Data2, guid->Data3,
		guid->Data4[0], guid->Data4[1], guid->Data4[2], guid->Data4[3],
		guid->Data4[4], guid->Data4[5], guid->Data4[6], guid->Data4[7]);
	OutputDebugStringA(msg);
}
#endif

int dc_efi_is_sb_setupmode()
{
	byte tempBuf = 0;
	GetFirmwareEnvironmentVariableW(L"SetupMode", efi_var_guid, &tempBuf, sizeof(tempBuf));
	return tempBuf != 0;
}

// Calculate SHA1 thumbprint of certificate data
static int dc_calculate_thumbprint(const BYTE* certData, DWORD certSize, BYTE* thumbprint)
{
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	DWORD hashLen = 20;
	int result = ST_OK;

	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
		return ST_ERROR;
	}

	do {
		if (!CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash)) {
			result = ST_ERROR;
			break;
		}

		if (!CryptHashData(hHash, certData, certSize, 0)) {
			result = ST_ERROR;
			break;
		}

		if (!CryptGetHashParam(hHash, HP_HASHVAL, thumbprint, &hashLen, 0)) {
			result = ST_ERROR;
			break;
		}
	} while (0);

	if (hHash) CryptDestroyHash(hHash);
	if (hProv) CryptReleaseContext(hProv, 0);

	return result;
}

// Enumerate certificate from efi variable
int dc_efi_enum_var(const wchar_t* name, const wchar_t* guid, int(*cb)(const BYTE* hash, const char* name, PVOID param), PVOID param)
{
	DWORD pkSize = 0;
	BYTE* pkData = NULL;
	int resl = ST_NF_FILE;
	const DWORD MAX_PK_SIZE = 65536; // 64KB should be enough
	char certName[65];

	// Allocate buffer for data
	pkData = (BYTE*)malloc(MAX_PK_SIZE);
	if (pkData == NULL) {
		return ST_NOMEM;
	}

	// Read the EFI variable
	pkSize = GetFirmwareEnvironmentVariableW(name, guid, pkData, MAX_PK_SIZE);
	if (pkSize == 0) {
		// Failed to read - could be non-UEFI system, access denied, or variable doesn't exist
		free(pkData);
		return ST_NF_FILE;
	}

	// Validate the size is reasonable
	if (pkSize > MAX_PK_SIZE) {
		free(pkData);
		return ST_NOMEM;
	}

#ifdef _DEBUG
	char msg[256];
	sprintf_s(msg, sizeof(msg), "EFI Variable %S size: %u bytes\n", name, pkSize);
	OutputDebugStringA(msg);
#endif

	// Parse the EFI signature database
	// The contains EFI_SIGNATURE_LIST structures (usually just one)
	DWORD offset = 0;
	while (offset + sizeof(EFI_SIGNATURE_LIST) <= pkSize) {
		EFI_SIGNATURE_LIST* sigList = (EFI_SIGNATURE_LIST*)(pkData + offset);

		// Validate signature list size
		if (sigList->SignatureListSize == 0 ||
			sigList->SignatureListSize > pkSize - offset ||
			sigList->SignatureListSize < sizeof(EFI_SIGNATURE_LIST)) {
			break; // Invalid or end of list
		}

		// Calculate number of signatures in this list
		DWORD sigDataSize = sigList->SignatureListSize - sizeof(EFI_SIGNATURE_LIST) - sigList->SignatureHeaderSize;
		if (sigList->SignatureSize == 0 || sigDataSize % sigList->SignatureSize != 0) {
			offset += sigList->SignatureListSize;
			continue; // Skip invalid signature list
		}

		DWORD numSignatures = sigDataSize / sigList->SignatureSize;
		DWORD sigOffset = offset + sizeof(EFI_SIGNATURE_LIST) + sigList->SignatureHeaderSize;

		// Process each signature in the list (typically has only one)
		for (DWORD i = 0; i < numSignatures && sigOffset + sigList->SignatureSize <= pkSize; i++) {
			EFI_SIGNATURE_DATA* sigData = (EFI_SIGNATURE_DATA*)(pkData + sigOffset);
			BYTE* certData = (BYTE*)sigData + sizeof(GUID); // Skip SignatureOwner GUID
			DWORD certSize = sigList->SignatureSize - sizeof(GUID);

			// Process X.509 certificates (all variants)
			if (dc_compare_efi_guid(&sigList->SignatureType, &EFI_CERT_X509_GUID) ||
				dc_compare_efi_guid(&sigList->SignatureType, &EFI_CERT_X509_SHA256_GUID) ||
				dc_compare_efi_guid(&sigList->SignatureType, &EFI_CERT_X509_SHA384_GUID) ||
				dc_compare_efi_guid(&sigList->SignatureType, &EFI_CERT_X509_SHA512_GUID)) {
				// This is an X.509 certificate - calculate its thumbprint
				BYTE thumbprint[20];
				if (dc_calculate_thumbprint(certData, certSize, thumbprint) == ST_OK) {
					PCCERT_CONTEXT pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, certData, certSize);
					if (pCertContext != NULL) {
						CertGetNameStringA(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, certName, sizeof(certName));
						CertFreeCertificateContext(pCertContext);
					}
					else {
						strcpy_s(certName, _countof(certName), "Unknown");
					}

					// Call the callback with the certificate info
					resl = cb(thumbprint, certName, param);
					if (resl != ST_OK) {
						free(pkData);
						return resl;
					}
				}
			}
			//// Process SHA256 hashes (commonly found in dbx - forbidden signers)
			//else if (dc_compare_efi_guid(&sigList->SignatureType, &EFI_CERT_SHA256_GUID)) {
			//
			//}
			//// Process SHA1 hashes
			//else if (dc_compare_efi_guid(&sigList->SignatureType, &EFI_CERT_SHA1_GUID)) {
			//
			//}
			//// Process RSA2048 signatures with SHA256
			//else if (dc_compare_efi_guid(&sigList->SignatureType, &EFI_CERT_RSA2048_SHA256_GUID) ||
			//	     dc_compare_efi_guid(&sigList->SignatureType, &EFI_CERT_TYPE_RSA2048_SHA256_GUID)) {
			//
			//}
			//// Process RSA2048 signatures with SHA1
			//else if (dc_compare_efi_guid(&sigList->SignatureType, &EFI_CERT_RSA2048_SHA1_GUID)) {
			//
			//}
			//// Process bare RSA2048 keys (deprecated format)
			//else if (dc_compare_efi_guid(&sigList->SignatureType, &EFI_CERT_RSA2048_GUID)) {
			//
			//}
#ifdef _DEBUG
			else
			{
				dc_debug_guid(&sigList->SignatureType, "Unhandled SignatureType");
			}
#endif

			sigOffset += sigList->SignatureSize;
		}

		offset += sigList->SignatureListSize;
	}

	free(pkData);
	return resl;
}

// Helper function to add certificate thumbprint to allowed list
static int dc_add_allowed_signer(const BYTE* hash, const char* name)
{
	cert_thumbprint* entry = (cert_thumbprint*)malloc(sizeof(cert_thumbprint));
	if (entry == NULL) return ST_NOMEM;

	memcpy(entry->hash, hash, 20);
	strncpy_s(entry->CN, sizeof(entry->CN), name, _TRUNCATE);
	entry->next = g_allowed_signers;
	g_allowed_signers = entry;
	return ST_OK;
}

// Helper function to check if certificate is in allowed list
int dc_is_signer_allowed(const BYTE* hash)
{
	cert_thumbprint* current = g_allowed_signers;
	for (int i = 1; current != NULL; i++) {
		if (memcmp(current->hash, hash, 20) == 0) {
			return i;
		}
		current = current->next;
	}
	return 0;
}

// Free the allowed signers list
static void dc_free_allowed_signers()
{
	cert_thumbprint* current = g_allowed_signers;
	while (current != NULL) {
		cert_thumbprint* next = current->next;
		free(current);
		current = next;
	}
	g_allowed_signers = NULL;
}



int dc_process_secureboot_db(const BYTE* thumbprint, const char* name, PVOID param)
{
#ifdef _DEBUG
	char msg[512];
	sprintf_s(msg, sizeof(msg),
		"Added cert: %s (%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X)\n", name, 
		thumbprint[0], thumbprint[1], thumbprint[2], thumbprint[3],
		thumbprint[4], thumbprint[5], thumbprint[6], thumbprint[7],
		thumbprint[8], thumbprint[9], thumbprint[10], thumbprint[11],
		thumbprint[12], thumbprint[13], thumbprint[14], thumbprint[15],
		thumbprint[16], thumbprint[17], thumbprint[18], thumbprint[19]);
	OutputDebugStringA(msg);
#endif

	return dc_add_allowed_signer(thumbprint, name);
}

// Initialize the Secure Boot database by reading the UEFI DB variable
// and extracting X.509 certificate thumbprints for signature verification.
// The DB variable contains the list of trusted certificate authorities.
//
// Returns:
//   ST_OK - Initialization successful or already initialized
//   ST_NOMEM - Out of memory
//
// Note: If the DB variable cannot be read (e.g., on non-UEFI systems),
// the function will fall back to accepting any validly signed file.
int dc_init_secureboot_db()
{
	// Only initialize once
	if (g_secureboot_db_initialized) {
		return ST_OK;
	}

	int resl = dc_efi_enum_var(L"db", sb_var_guid, dc_process_secureboot_db, NULL);
	if (resl != ST_OK) return resl;

	g_secureboot_db_initialized = 1;

	return ST_OK;
}

int dc_efi_enum_allowed_signers(int(*cb)(const BYTE* hash, const char* name, PVOID param), PVOID param)
{
	int resl = ST_NF_FILE;

	if (dc_init_secureboot_db() != ST_OK) return resl;

	cert_thumbprint* current = g_allowed_signers;
	while (current != NULL) {
		resl = cb(current->hash, current->CN, param);
		if (resl != ST_OK)
			return resl;
		current = current->next;
	}
	return resl;
}

// Extract certificate thumbprint from a signed file
int dc_extract_cert_from_file(const wchar_t* filePath, BYTE* thumbprint)
{
	HCERTSTORE hStore = NULL;
	HCRYPTMSG hMsg = NULL;
	PCCERT_CONTEXT pCertContext = NULL;
	DWORD dwEncoding, dwContentType, dwFormatType;
	DWORD cbData;
	BYTE* pbData = NULL;
	int result = ST_ERROR;

	// Get the certificate store from the file
	if (!CryptQueryObject(
		CERT_QUERY_OBJECT_FILE,
		filePath,
		CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
		CERT_QUERY_FORMAT_FLAG_BINARY,
		0,
		&dwEncoding,
		&dwContentType,
		&dwFormatType,
		&hStore,
		&hMsg,
		NULL)) {
		return ST_ERROR;
	}

	do {
		// Get signer info size
		if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &cbData)) {
			break;
		}

		pbData = (BYTE*)malloc(cbData);
		if (pbData == NULL) {
			result = ST_NOMEM;
			break;
		}

		// Get signer info
		if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, pbData, &cbData)) {
			break;
		}

		CMSG_SIGNER_INFO* pSignerInfo = (CMSG_SIGNER_INFO*)pbData;

		// Find the signer certificate in the store
		CERT_INFO certInfo = { 0 };
		certInfo.Issuer = pSignerInfo->Issuer;
		certInfo.SerialNumber = pSignerInfo->SerialNumber;

		pCertContext = CertFindCertificateInStore(
			hStore,
			X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
			0,
			CERT_FIND_SUBJECT_CERT,
			&certInfo,
			NULL);

		if (pCertContext == NULL) {
			break;
		}

		// Calculate thumbprint of the certificate
		if (dc_calculate_thumbprint(
			pCertContext->pbCertEncoded,
			pCertContext->cbCertEncoded,
			thumbprint) != ST_OK) {
			break;
		}

		result = ST_OK;

	} while (0);

	if (pbData) free(pbData);
	if (pCertContext) CertFreeCertificateContext(pCertContext);
	if (hStore) CertCloseStore(hStore, 0);
	if (hMsg) CryptMsgClose(hMsg);

	return result;
}

// Extract certificate thumbprint from data in memory
int dc_extract_cert_from_memory(const void* data, size_t size, BYTE* thumbprint)
{
	HCERTSTORE hStore = NULL;
	HCRYPTMSG hMsg = NULL;
	PCCERT_CONTEXT pCertContext = NULL;
	DWORD dwEncoding, dwContentType, dwFormatType;
	DWORD cbData;
	BYTE* pbData = NULL;
	int result = ST_ERROR;
	CRYPT_DATA_BLOB blob;

	// Set up blob for memory data
	blob.cbData = (DWORD)size;
	blob.pbData = (BYTE*)data;

	// Get the certificate store from memory
	if (!CryptQueryObject(
		CERT_QUERY_OBJECT_BLOB,
		&blob,
		CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
		CERT_QUERY_FORMAT_FLAG_BINARY,
		0,
		&dwEncoding,
		&dwContentType,
		&dwFormatType,
		&hStore,
		&hMsg,
		NULL)) {
		return ST_ERROR;
	}

	do {
		// Get signer info size
		if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &cbData)) {
			break;
		}

		pbData = (BYTE*)malloc(cbData);
		if (pbData == NULL) {
			result = ST_NOMEM;
			break;
		}

		// Get signer info
		if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, pbData, &cbData)) {
			break;
		}

		CMSG_SIGNER_INFO* pSignerInfo = (CMSG_SIGNER_INFO*)pbData;

		// Find the signer certificate in the store
		CERT_INFO certInfo = { 0 };
		certInfo.Issuer = pSignerInfo->Issuer;
		certInfo.SerialNumber = pSignerInfo->SerialNumber;

		pCertContext = CertFindCertificateInStore(
			hStore,
			X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
			0,
			CERT_FIND_SUBJECT_CERT,
			&certInfo,
			NULL);

		if (pCertContext == NULL) {
			break;
		}

		// Calculate thumbprint of the certificate
		if (dc_calculate_thumbprint(
			pCertContext->pbCertEncoded,
			pCertContext->cbCertEncoded,
			thumbprint) != ST_OK) {
			break;
		}

		result = ST_OK;

	} while (0);

	if (pbData) free(pbData);
	if (pCertContext) CertFreeCertificateContext(pCertContext);
	if (hStore) CertCloseStore(hStore, 0);
	if (hMsg) CryptMsgClose(hMsg);

	return result;
}

/*
// Verify signature of a file on disk
int dc_verify_file_signature(const wchar_t* filePath)
{
	WINTRUST_FILE_INFO fileInfo = { 0 };
	WINTRUST_DATA trustData = { 0 };
	GUID actionGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	LONG result;
	int resl = ST_OK;
	BYTE thumbprint[20];

	// Set up WinVerifyTrust structures
	fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
	fileInfo.pcwszFilePath = filePath;
	fileInfo.hFile = NULL;
	fileInfo.pgKnownSubject = NULL;

	trustData.cbStruct = sizeof(WINTRUST_DATA);
	trustData.dwUIChoice = WTD_UI_NONE;
	trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
	trustData.dwUnionChoice = WTD_CHOICE_FILE;
	trustData.pFile = &fileInfo;
	trustData.dwStateAction = WTD_STATEACTION_VERIFY;
	trustData.dwProvFlags = WTD_SAFER_FLAG;

	// Verify the signature
	result = WinVerifyTrust(NULL, &actionGuid, &trustData);

	// Clean up trust state
	trustData.dwStateAction = WTD_STATEACTION_CLOSE;
	WinVerifyTrust(NULL, &actionGuid, &trustData);

	// Check result
	if (result != ERROR_SUCCESS && result != CERT_E_CHAINING) {
		// Signature verification failed
		resl = ST_BL_NOT_PASSED;
	}
	else if (g_allowed_signers != NULL) {
		// If we have an allowed signers list, verify the certificate is in it
		if (dc_extract_cert_from_file(filePath, thumbprint) == ST_OK) {
			if (!dc_is_signer_allowed(thumbprint)) {
				resl = ST_BL_NOT_PASSED; // Certificate not in UEFI DB
			}
		}
		else {
			resl = ST_BL_NOT_PASSED; // Could not extract certificate
		}
	}
	// else: No allowed signers list (fallback mode) - just check signature is valid

	return resl;
}

// Verify signature of a file in memory
// Note: WinVerifyTrust requires file-based verification for PE embedded signatures
// We use FILE_FLAG_DELETE_ON_CLOSE to ensure the file is auto-deleted and never persists
int dc_verify_memory_signature(const void* data, size_t size)
{
	WINTRUST_FILE_INFO fileInfo = { 0 };
	WINTRUST_DATA trustData = { 0 };
	GUID actionGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	LONG result;
	wchar_t tempPath[MAX_PATH];
	wchar_t tempFile[MAX_PATH];
	HANDLE hFile;
	DWORD written;
	int resl = ST_OK;
	BYTE thumbprint[20];

	// Get temp path for the auto-delete file
	if (GetTempPath(MAX_PATH, tempPath) == 0) {
		return ST_RW_ERR;
	}

	if (GetTempFileName(tempPath, L"dcs", 0, tempFile) == 0) {
		return ST_RW_ERR;
	}

	// Create file with DELETE_ON_CLOSE flag - it will be automatically deleted when handle closes
	// This ensures no persistent temp files and automatic cleanup even if process crashes
	// Use FILE_SHARE_READ so WinVerifyTrust can open the file while we still have it open
	hFile = CreateFile(tempFile,
		GENERIC_WRITE | GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE,
		NULL);

	if (hFile == INVALID_HANDLE_VALUE) {
		DeleteFile(tempFile); // Clean up the temp name created by GetTempFileName
		return ST_RW_ERR;
	}

	// Write data to the auto-delete file
	if (!WriteFile(hFile, data, (DWORD)size, &written, NULL) || written != size) {
		CloseHandle(hFile); // File auto-deletes on close
		return ST_RW_ERR;
	}

	// Set up WinVerifyTrust structures
	fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
	fileInfo.pcwszFilePath = tempFile;
	fileInfo.hFile = hFile;
	fileInfo.pgKnownSubject = NULL;

	trustData.cbStruct = sizeof(WINTRUST_DATA);
	trustData.dwUIChoice = WTD_UI_NONE;
	trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
	trustData.dwUnionChoice = WTD_CHOICE_FILE;
	trustData.pFile = &fileInfo;
	trustData.dwStateAction = WTD_STATEACTION_VERIFY;
	trustData.dwProvFlags = WTD_SAFER_FLAG;

	// Verify the signature
	result = WinVerifyTrust(NULL, &actionGuid, &trustData);

	// Clean up trust state
	trustData.dwStateAction = WTD_STATEACTION_CLOSE;
	WinVerifyTrust(NULL, &actionGuid, &trustData);

	// Check result
	if (result != ERROR_SUCCESS && result != CERT_E_CHAINING) {
		// Signature verification failed
		resl = ST_BL_NOT_PASSED;
	}
	else if (g_allowed_signers != NULL) {
		// If we have an allowed signers list, verify the certificate is in it
		if (dc_extract_cert_from_memory(data, size, thumbprint) == ST_OK) {
			if (!dc_is_signer_allowed(thumbprint)) {
				resl = ST_BL_NOT_PASSED; // Certificate not in UEFI DB
			}
		}
		else {
			resl = ST_BL_NOT_PASSED; // Could not extract certificate
		}
	}
	// else: No allowed signers list (fallback mode) - just check signature is valid

	// Close handle - file is automatically deleted due to DELETE_ON_CLOSE flag
	CloseHandle(hFile);

	return resl;
}
*/