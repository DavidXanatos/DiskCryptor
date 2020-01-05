#ifndef _MBRINST_
#define _MBRINST_

#include "dcapi.h"
#include "bootloader.h"

typedef struct _drive_inf {
	u32 dsk_type;           /* disk type                     */
	u32 dsk_num;            /* number of disks in partition  */
	int par_numb;           /* partition number              */
	u64 par_size;           /* partition size                */
	struct {
		u32 number; /* disk number */
		u64 size;   /* disk size   */
		u64 prt_start; /* partition start position in disk */
		u64 prt_size;  /* partition size in disk           */
	} disks[128];	

} drive_inf;

#define DSK_BASIC       0
#define DSK_DYN_SIMPLE  1
#define DSK_DYN_SPANNED 2

int dc_api dc_set_boot(wchar_t *root, int format, int small_boot);
int dc_api dc_make_iso(wchar_t *file, int small_boot);
int dc_api dc_make_pxe(wchar_t *file, int small_boot);
int dc_api dc_set_mbr(int dsk_num, int begin, int small_boot);
int dc_api dc_unset_mbr(int dsk_num);
int dc_api dc_update_boot(int dsk_num);

int dc_api dc_get_boot_disk(int *dsk_1, int *dsk_2);

int dc_api dc_get_mbr_config(
	  int dsk_num, wchar_t *file, ldr_config *conf);

int dc_api dc_set_mbr_config(
	  int dsk_num, wchar_t *file, ldr_config *conf);

int dc_api dc_mbr_config_by_partition(
      wchar_t *root, int set_conf, ldr_config *conf);

int dc_api dc_get_drive_info(wchar_t *w32_name, drive_inf *info);

u64 dc_api dc_dsk_get_size(int dsk_num, int precision);

#pragma pack (push, 1)

typedef struct _dc_mbr {
	u8    jump[2];
	u32   sign;
	lba_p set;
	u8    data1[410];
	union 
	{
		u8  data2[78];
		struct {
			u8     pad[14];
			pt_ent pt[4];
		};
	};	
	u16   magic;

} dc_mbr;

typedef struct _dc_boot {
	u8    jump[3];
	s8    sys_id[8];	
	u8    data[501];
} dc_boot;

#pragma pack (pop)

#endif
