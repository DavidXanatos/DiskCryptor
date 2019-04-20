#ifndef _VOLUME_HEADER_H_
#define _VOLUME_HEADER_H_

// сигнатура заголовка, текстовое значение 'DCRP'
#define DC_VOLUME_SIGN 0x50524344

#define PKCS5_SALT_SIZE	64     // размер salt в заголовке = 512 бит
#define MAX_KEY_SIZE    (32*3) // максимальный реально размер ключа для каскадного шифра = 768 бит
#define PKCS_DERIVE_MAX (MAX_KEY_SIZE*2) // максимальный размер ключа в который разворачивается пароль
#define DISKKEY_SIZE	256    // сколько ключевых байт храним в заголовке (взято с запасом)

#define SECTOR_SIZE                 512
#define MAX_SECTOR_SIZE             2048
#define CD_SECTOR_SIZE              2048

#define MIN_PASSWORD 1	 // Minimum password length
#define MAX_PASSWORD 128 // Maximum password length

#define DC_HDR_VERSION 2

#define VF_NONE           0x00
#define VF_TMP_MODE       0x01 /* temporary encryption mode */
#define VF_REENCRYPT      0x02 /* volume re-encryption in progress */
#define VF_STORAGE_FILE   0x04 /* redirected area are placed in file */
#define VF_NO_REDIR       0x08 /* redirection area is not present */
#define VF_EXTENDED       0x10 /* this volume placed on extended partition */

#pragma pack (push, 1)

typedef struct _dc_pass {
	int     size; // длина пароля в байтах не без завершающего нуля
	wchar_t pass[MAX_PASSWORD]; // пароль в кодировке UTF16-LE
} dc_pass;

typedef struct _dc_header {
	unsigned char  salt[PKCS5_SALT_SIZE]; // pkcs5.2 salt
	unsigned long  sign;    // signature 'DCRP'
	unsigned long  hdr_crc; // crc32 of decrypted volume header
	unsigned short version; // volume format version
	unsigned long  flags;   // volume flags
	unsigned long  disk_id; // unigue volume identifier
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

	unsigned char  reserved[1422 - 1];

} dc_header;

#define IS_INVALID_VOL_FLAGS(_f) ( ((_f) & VF_NO_REDIR) && \
	((_f) & (VF_TMP_MODE | VF_REENCRYPT | VF_STORAGE_FILE)) )

#define IS_INVALID_SECTOR_SIZE(_s) ( (_s) % SECTOR_SIZE )


#define DC_AREA_SIZE         (2 * 1024)
#define DC_AREA_SECTORS      (DC_AREA_SIZE / SECTOR_SIZE)
#define DC_ENCRYPTEDDATASIZE (DC_AREA_SIZE - PKCS5_SALT_SIZE)
#define DC_CRC_AREA_SIZE     (DC_ENCRYPTEDDATASIZE - 8)


#pragma pack (pop)


#endif