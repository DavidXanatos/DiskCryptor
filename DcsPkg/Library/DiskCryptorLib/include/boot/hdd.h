#ifndef _HDD_
#define _HDD_

#pragma pack (push, 1)

typedef struct _hdd_inf {
	u8 flags;
	u8 max_head;
	u8 max_sect;

} hdd_inf;

#define HDD_OK  0x01
#define HDD_LBA 0x02

typedef struct _partition {	
	u8  hdd_n; /* HDD number       */
	u8  flags; /* partition flags  */
	u64 begin; /* partition offset */
	u64 size;  /* partition length */
	
} partition;

#define PT_ACTIVE   0x01
#define PT_EXTENDED 0x02

#pragma pack (pop)

#define SECT_SHIFT 9
#define HDD_MAX    16 /* maximum number of HDD's      */
#define PART_MAX   64 /* maximum number of partitions */

#define dos2hdd(_x) ((((_x) >= 0x80) && ((_x) <= 0x8F)) ? (_x) - 0x80 : -1)
#define hdd2dos(_x) ( (_x) + 0x80 )

#endif