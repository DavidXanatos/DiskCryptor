#ifndef _VOLUME_HEADER_H_
#define _VOLUME_HEADER_H_

// volume header signature, text value 'DCRP'
#define DC_VOLUME_SIGN 0x50524344

#define PKCS5_SALT_SIZE	64     // salt size in header = 512 bits
#define MAX_KEY_SIZE    (32*3) // maximum actual key size for cascade cipher = 768 bits
#define PKCS_DERIVE_MAX (MAX_KEY_SIZE*2) // maximum key size into which password is expanded
#define DISKKEY_SIZE	256    // number of key bytes stored in header (taken with reserve)

#define SECTOR_SIZE                 512
#define MAX_SECTOR_SIZE             2048
#define CD_SECTOR_SIZE              2048

#define MIN_PASSWORD 1	 // Minimum password length
#define MAX_PASSWORD 128 // Maximum password length

#define DC_HDR_VERSION 3           // Current header version (HMAC-SHA256 + 600K PBKDF2)
#define DC_HDR_VERSION_LEGACY 2    // Legacy header version (CRC32 + 1K iterations)

// Header integrity check size
#define DC_HMAC_SIZE 32            // HMAC-SHA256 output size

// PBKDF2 iteration counts
#define PBKDF2_ITERATIONS_CURRENT 600000  // Modern secure iteration count (OWASP 2023)
#define PBKDF2_ITERATIONS_LEGACY  1000    // Legacy iteration count (insecure, for migration only)

#define VF_NONE           0x00
#define VF_TMP_MODE       0x01 /* temporary encryption mode */
#define VF_REENCRYPT      0x02 /* volume re-encryption in progress */
#define VF_STORAGE_FILE   0x04 /* redirected area are placed in file */
#define VF_NO_REDIR       0x08 /* redirection area is not present */
#define VF_EXTENDED       0x10 /* this volume placed on extended partition */

#pragma pack (push, 1)

typedef struct _dc_pass {
	int     size; // password length in bytes without terminating null
	wchar_t pass[MAX_PASSWORD]; // password in UTF16-LE encoding
} dc_pass;

typedef struct _dc_header {
	unsigned char  salt[PKCS5_SALT_SIZE]; // pkcs5.2 salt
	unsigned long  sign;    // signature 'DCRP'
	unsigned long  hdr_crc; // crc32 of decrypted volume header
	unsigned short version; // volume format version
	unsigned long  flags;   // volume flags
	unsigned long  disk_id; // unique volume identifier
	int alg_1;  // crypt algo 1
	unsigned char key_1[DISKKEY_SIZE]; // crypt key 1
	int alg_2;  // crypt algo 2
	unsigned char key_2[DISKKEY_SIZE]; // crypt key 2

	union {
		unsigned __int64 stor_off; // redirection area offset
		unsigned __int64 data_off; // volume data offset, if redirection area is not used
	};
	unsigned char    deprecated[8];
	unsigned __int64 tmp_size;   // temporary part size
	unsigned char   tmp_wp_mode; // data wipe mode

	/* Version 3+: HMAC-SHA256 replaces CRC32 for integrity checking */
	unsigned char  hdr_hmac[DC_HMAC_SIZE]; // HMAC-SHA256 of header (v3+)

	/* Reserved space calculation:
	 * - Original reserved was 1421 bytes (1422 - 1, where -1 accounts for tmp_wp_mode)
	 * - hdr_hmac[32] uses 32 bytes from the original reserved space
	 * - New reserved = 1421 - 32 = 1389 bytes
	 * - Total (hdr_hmac + reserved) = 32 + 1389 = 1421 bytes (unchanged)
	 * - Overall structure size remains DC_AREA_SIZE (2048 bytes)
	 */
	unsigned char  reserved[1422 - 1 - DC_HMAC_SIZE];

} dc_header;

#define IS_INVALID_VOL_FLAGS(_f) ( ((_f) & VF_NO_REDIR) && \
	((_f) & (VF_TMP_MODE | VF_REENCRYPT | VF_STORAGE_FILE)) )

#define IS_INVALID_SECTOR_SIZE(_s) ( (_s) % SECTOR_SIZE )


#define DC_AREA_SIZE         (2 * 1024)
#define DC_AREA_SECTORS      (DC_AREA_SIZE / SECTOR_SIZE)
#define DC_ENCRYPTEDDATASIZE (DC_AREA_SIZE - PKCS5_SALT_SIZE)
#define DC_CRC_AREA_SIZE     (DC_ENCRYPTEDDATASIZE - 8)

/* Area covered by HMAC: everything after signature and HMAC fields */
#define DC_HMAC_AREA_OFFSET  (offsetof(dc_header, version))
#define DC_HMAC_AREA_SIZE    (DC_ENCRYPTEDDATASIZE - 4 - DC_HMAC_SIZE - 2) /* skip sign, hdr_crc, version */

/* Compile-time assertion to verify dc_header size matches DC_AREA_SIZE (2048 bytes) */
/* This ensures the reserved array calculation is correct */
typedef char _dc_header_size_check[(sizeof(dc_header) == DC_AREA_SIZE) ? 1 : -1];

#pragma pack (pop)


#endif