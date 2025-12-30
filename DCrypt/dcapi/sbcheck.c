/*
*
* DiskCryptor - open source partition encryption tool
* Copyright (c) 2019-2026
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


static const wchar_t* sb_var_guid = L"{D719B2CB-3D3A-4596-A3BC-DAD00E67656F}";


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

// EFI Certificate type GUIDs using Windows GUID format
// EFI_CERT_SHA256_GUID = {c1c41b26-504e-4a37-8917-f82294feb5b8}
static const GUID EFI_CERT_SHA256_GUID =
{ 0xc1c41b26, 0x504e, 0x4a37, { 0x89, 0x17, 0xf8, 0x22, 0x94, 0xfe, 0xb5, 0xb8 } };

// EFI_CERT_RSA2048_GUID = {3c5f66a8-1a4c-4a99-adb8-957f2cf94f0b}
static const GUID EFI_CERT_RSA2048_GUID =
{ 0x3c5f66a8, 0x1a4c, 0x4a99, { 0xad, 0xb8, 0x95, 0x7f, 0x2c, 0xf9, 0x4f, 0x0b } };

// EFI_CERT_X509_GUID = {a5c059a1-944b-4bf5-b2ab-eb9aa10f118d}
static const GUID EFI_CERT_X509_GUID =
{ 0xa5c059a1, 0x944b, 0x4bf5, { 0xb2, 0xab, 0xeb, 0x9a, 0xa1, 0x0f, 0x11, 0x8d } };

// EFI_CERT_X509_SHA256_GUID = {3bd2a492-96c0-4079-b420-fcf98ef103ed}
static const GUID EFI_CERT_X509_SHA256_GUID =
{ 0x3bd2a492, 0x96c0, 0x4079, { 0xb4, 0x20, 0xfc, 0xf9, 0x8e, 0xf1, 0x03, 0xed } };

// Alternative/vendor-specific X509 GUID found in some systems
// {a5c059a1-94e4-4aa7-87b5-ab155c2bf072}
static const GUID EFI_CERT_X509_ALT_GUID =
{ 0xa5c059a1, 0x94e4, 0x4aa7, { 0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72 } };

// Structure to hold certificate thumbprint
typedef struct _cert_thumbprint {
	BYTE hash[20]; // SHA1 hash
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
#else
#define dc_debug_guid(guid, label) ((void)0)
#endif

// Helper function to compare certificate thumbprints
static int dc_compare_thumbprint(const BYTE* hash1, const BYTE* hash2)
{
	return memcmp(hash1, hash2, 20) == 0;
}

// Helper function to add certificate thumbprint to allowed list
static int dc_add_allowed_signer(const BYTE* hash)
{
	cert_thumbprint* entry = (cert_thumbprint*)malloc(sizeof(cert_thumbprint));
	if (entry == NULL) return ST_NOMEM;

	memcpy(entry->hash, hash, 20);
	entry->next = g_allowed_signers;
	g_allowed_signers = entry;
	return ST_OK;
}

// Helper function to check if certificate is in allowed list
static int dc_is_signer_allowed(const BYTE* hash)
{
	cert_thumbprint* current = g_allowed_signers;
	while (current != NULL) {
		if (dc_compare_thumbprint(current->hash, hash)) {
			return 1;
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
	DWORD dbSize = 0;
	BYTE* dbData = NULL;
	int resl = ST_OK;
	const DWORD MAX_DB_SIZE = 65536; // 64KB should be enough for UEFI DB

	// Only initialize once
	if (g_secureboot_db_initialized) {
		return ST_OK;
	}

	// Allocate buffer for DB data
	// GetFirmwareEnvironmentVariableW doesn't support querying size with NULL buffer,
	// so we allocate a reasonably large buffer
	dbData = (BYTE*)malloc(MAX_DB_SIZE);
	if (dbData == NULL) {
		return ST_NOMEM;
	}

	// Read the EFI DB variable
	// Returns number of bytes stored on success, 0 on failure
	dbSize = GetFirmwareEnvironmentVariableW(L"db", sb_var_guid, dbData, MAX_DB_SIZE);
	if (dbSize == 0) {
		// Failed to read DB - could be non-UEFI system, access denied, or variable doesn't exist
		// Fall back to accepting any validly signed file
		free(dbData);
		g_secureboot_db_initialized = 1;
		return ST_OK;
	}

	// Validate the size is reasonable
	if (dbSize > MAX_DB_SIZE) {
		// This shouldn't happen, but be defensive
		free(dbData);
		g_secureboot_db_initialized = 1;
		return ST_OK;
	}

	// Parse the EFI signature database
	// The DB contains EFI_SIGNATURE_LIST structures
	DWORD offset = 0;
	while (offset + sizeof(EFI_SIGNATURE_LIST) <= dbSize) {
		EFI_SIGNATURE_LIST* sigList = (EFI_SIGNATURE_LIST*)(dbData + offset);

		// Debug output
		dc_debug_guid(&sigList->SignatureType, "SignatureType");

		// Validate signature list size
		if (sigList->SignatureListSize == 0 ||
			sigList->SignatureListSize > dbSize - offset ||
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

		// Process each signature in the list
		for (DWORD i = 0; i < numSignatures && sigOffset + sigList->SignatureSize <= dbSize; i++) {
			EFI_SIGNATURE_DATA* sigData = (EFI_SIGNATURE_DATA*)(dbData + sigOffset);
			BYTE* certData = (BYTE*)sigData + sizeof(GUID); // Skip SignatureOwner GUID
			DWORD certSize = sigList->SignatureSize - sizeof(GUID);

			// Process X.509 certificates (check multiple GUID variants)
			if (dc_compare_efi_guid(&sigList->SignatureType, &EFI_CERT_X509_GUID) ||
				dc_compare_efi_guid(&sigList->SignatureType, &EFI_CERT_X509_SHA256_GUID) ||
				dc_compare_efi_guid(&sigList->SignatureType, &EFI_CERT_X509_ALT_GUID)) {
				// This is an X.509 certificate - calculate its thumbprint
				BYTE thumbprint[20];
				if (dc_calculate_thumbprint(certData, certSize, thumbprint) == ST_OK) {
					dc_add_allowed_signer(thumbprint);
#ifdef _DEBUG
					char msg[512];
					char certName[256] = "Unknown";

					PCCERT_CONTEXT pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, certData, certSize);
					if (pCertContext != NULL) {
						CertGetNameStringA(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, certName, sizeof(certName));
						CertFreeCertificateContext(pCertContext);
					}

					sprintf_s(msg, sizeof(msg),
						"Added cert: %s (%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X)\n", certName, 
						thumbprint[0], thumbprint[1], thumbprint[2], thumbprint[3],
						thumbprint[4], thumbprint[5], thumbprint[6], thumbprint[7],
						thumbprint[8], thumbprint[9], thumbprint[10], thumbprint[11],
						thumbprint[12], thumbprint[13], thumbprint[14], thumbprint[15],
						thumbprint[16], thumbprint[17], thumbprint[18], thumbprint[19]);
					OutputDebugStringA(msg);
#endif
				}
			}
			// Note: We could also handle SHA256 hashes directly if needed
			// else if (dc_compare_efi_guid(&sigList->SignatureType, &EFI_CERT_SHA256_GUID)) {
			//     // This is a SHA256 hash of an EFI binary - could store these separately
			// }

			sigOffset += sigList->SignatureSize;
		}

		offset += sigList->SignatureListSize;
	}

	free(dbData);
	g_secureboot_db_initialized = 1;

#ifdef _DEBUG
	{
		int count = 0;
		cert_thumbprint* current = g_allowed_signers;
		while (current != NULL) {
			count++;
			current = current->next;
		}
		char msg[128];
		sprintf_s(msg, sizeof(msg), "Loaded %d certificates from UEFI DB\n", count);
		OutputDebugStringA(msg);
	}
#endif

	return resl;
}

// Extract certificate thumbprint from a signed file
static int dc_extract_cert_from_file(const wchar_t* filePath, BYTE* thumbprint)
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
static int dc_extract_cert_from_memory(const void* data, size_t size, BYTE* thumbprint)
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
