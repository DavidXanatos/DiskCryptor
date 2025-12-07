#ifndef _DRIVER_
#define _DRIVER_

#include "defines.h"
#include "version.h"
#include "volume_header.h"
#include "dcconst.h"

#define DC_GET_VERSION       CTL_CODE(FILE_DEVICE_UNKNOWN, 0,  METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DC_CTL_ADD_PASS      CTL_CODE(FILE_DEVICE_UNKNOWN, 1,  METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DC_CTL_CLEAR_PASS    CTL_CODE(FILE_DEVICE_UNKNOWN, 2,  METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DC_CTL_MOUNT         CTL_CODE(FILE_DEVICE_UNKNOWN, 3,  METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DC_CTL_MOUNT_ALL     CTL_CODE(FILE_DEVICE_UNKNOWN, 4,  METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DC_CTL_UNMOUNT       CTL_CODE(FILE_DEVICE_UNKNOWN, 5,  METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DC_CTL_STATUS        CTL_CODE(FILE_DEVICE_UNKNOWN, 7,  METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DC_CTL_ADD_SEED      CTL_CODE(FILE_DEVICE_UNKNOWN, 8,  METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DC_CTL_CHANGE_PASS   CTL_CODE(FILE_DEVICE_UNKNOWN, 9,  METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DC_CTL_ENCRYPT_START CTL_CODE(FILE_DEVICE_UNKNOWN, 10, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DC_CTL_DECRYPT_START CTL_CODE(FILE_DEVICE_UNKNOWN, 11, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DC_CTL_RE_ENC_START  CTL_CODE(FILE_DEVICE_UNKNOWN, 12, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DC_CTL_ENCRYPT_STEP  CTL_CODE(FILE_DEVICE_UNKNOWN, 13, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DC_CTL_DECRYPT_STEP  CTL_CODE(FILE_DEVICE_UNKNOWN, 14, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DC_CTL_SYNC_STATE    CTL_CODE(FILE_DEVICE_UNKNOWN, 15, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DC_CTL_RESOLVE       CTL_CODE(FILE_DEVICE_UNKNOWN, 16, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DC_CTL_GET_RAND      CTL_CODE(FILE_DEVICE_UNKNOWN, 19, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define DC_CTL_BENCHMARK     CTL_CODE(FILE_DEVICE_UNKNOWN, 20, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DC_CTL_BSOD          CTL_CODE(FILE_DEVICE_UNKNOWN, 21, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DC_CTL_GET_FLAGS     CTL_CODE(FILE_DEVICE_UNKNOWN, 22, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DC_CTL_SET_FLAGS     CTL_CODE(FILE_DEVICE_UNKNOWN, 23, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DC_CTL_LOCK_MEM      CTL_CODE(FILE_DEVICE_UNKNOWN, 24, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DC_CTL_UNLOCK_MEM    CTL_CODE(FILE_DEVICE_UNKNOWN, 25, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DC_FORMAT_START      CTL_CODE(FILE_DEVICE_UNKNOWN, 26, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DC_FORMAT_STEP       CTL_CODE(FILE_DEVICE_UNKNOWN, 27, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DC_FORMAT_DONE       CTL_CODE(FILE_DEVICE_UNKNOWN, 28, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DC_BACKUP_HEADER     CTL_CODE(FILE_DEVICE_UNKNOWN, 29, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DC_RESTORE_HEADER    CTL_CODE(FILE_DEVICE_UNKNOWN, 30, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DC_GET_DUMP_HELPERS  CTL_CODE(FILE_DEVICE_UNKNOWN, 31, METHOD_NEITHER, FILE_ANY_ACCESS)
#define DC_CTL_ENCRYPT_START2 CTL_CODE(FILE_DEVICE_UNKNOWN, 32, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define FSCTL_LOCK_VOLUME               CTL_CODE(FILE_DEVICE_FILE_SYSTEM,  6, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_UNLOCK_VOLUME             CTL_CODE(FILE_DEVICE_FILE_SYSTEM,  7, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_DISMOUNT_VOLUME           CTL_CODE(FILE_DEVICE_FILE_SYSTEM,  8, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define MAX_DEVICE              64 // maximum device name length

#define DC_DEVICE_NAME     L"\\Device\\dcrypt"
#define DC_LINK_NAME       L"\\DosDevices\\dcrypt"
#define DC_WIN32_NAME      L"\\\\.\\dcrypt"
#define DC_OLD_WIN32_NAME  L"\\\\.\\TcWde"

#pragma pack (push, 1)

#ifndef BOOT_LDR

typedef struct _crypt_info {
	u8 cipher_id;  /* cipher id */
	u8 wp_mode;    /* data wipe mode (for encryption) */

} crypt_info;

typedef struct _dc_ioctl {
	dc_pass    passw1;  /* password                         */
	dc_pass    passw2;  /* new password (for changing pass) */
	wchar_t    device[MAX_DEVICE + 1];
	u32        flags;   /* mount/unmount flags             */
	int        status;  /* operation status code           */
	int        n_mount; /* number of mounted devices       */
	crypt_info crypt;
	wchar_t    path[MAX_PATH];
} dc_ioctl;

typedef struct {
	PVOID ptr;
	ULONG length;

} DC_LOCK_MEMORY, *PDC_LOCK_MEMORY;

typedef struct _dc_rand_ctl {
	void *buff;
	u32   size;

} dc_rand_ctl;

typedef struct _dc_backup_ctl {
	u16        device[MAX_DEVICE + 1];
	dc_pass    pass;
	u8         backup[DC_AREA_SIZE];
	int        status;

} dc_backup_ctl;

typedef struct _dc_status {
	u64        dsk_size;
	u64        tmp_size;
	u32        flags;
	u32        mnt_flags;
	u32        disk_id;
	s32        paging_count;	
	crypt_info crypt;
	u16        vf_version;   /* volume format version */
	wchar_t    mnt_point[MAX_PATH];

} dc_status;

typedef struct _dc_bench_info {
	u64 datalen; /* total encrypted data length */
	u64 enctime; /* encryption time in ticks */
	u64 cpufreq; /* ticks per second frequency */

} dc_bench_info;

typedef struct {
	ULONG conf_flags;
	ULONG load_flags;
	ULONG boot_flags;

} DC_FLAGS, *PDC_FLAGS;

#define IS_UNMOUNTABLE(d) ( !((d)->flags & (F_SYSTEM | F_HIBERNATE)) && \
                             ((d)->paging_count == 0) )

#define IS_EQUAL_PASS(p1,p2) ( (p1 && p2) && \
                               ((p1)->size == (p2)->size) && \
	                             (memcmp((p1)->pass, (p2)->pass, (p1)->size) == 0) )

#define IS_STORAGE_ON_END(_flags) (  ((_flags) & F_ENABLED)       && !((_flags) & F_CDROM) && \
	                                !((_flags) & F_PROTECT_DCSYS) && !((_flags) & F_NO_REDIRECT) )

#define IS_DEVICE_BLOCKED(_hook) (                                                     \
	((dc_conf_flags & CONF_BLOCK_UNENC_REMOVABLE) && (_hook->flags & F_REMOVABLE) &&   \
                                                     (_hook->flags & F_CDROM) == 0) || \
    ((dc_conf_flags & CONF_BLOCK_UNENC_CDROM)     && (_hook->flags & F_CDROM)) ||      \
	((dc_conf_flags & CONF_BLOCK_UNENC_HDDS)      && (_hook->flags & (F_REMOVABLE | F_CDROM)) == 0) )

#endif

#pragma pack (pop)

#define DC_MEM_RETRY_TIME    10
#define DC_MEM_RETRY_TIMEOUT (1000 * 30)
#define ENC_BLOCK_SIZE (1280 * 1024)

#ifdef IS_DRIVER
 extern PDEVICE_OBJECT  dc_device;
 extern volatile long   dc_io_count;
 extern ULONG           dc_conf_flags;
 extern ULONG           dc_load_flags;
 extern ULONG           dc_boot_flags;
 extern ULONG           dc_boot_kbs;
 extern ULONG           dc_cpu_count;
#endif


#endif