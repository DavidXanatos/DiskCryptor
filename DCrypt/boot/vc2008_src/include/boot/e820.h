#ifndef _E820_
#define _E820_

#define E820MAX	64		/* number of entries in E820MAP */

#define E820_RAM	1
#define E820_RESERVED	2
#define E820_ACPI	3
#define E820_NVS	4

#pragma pack (push, 1)

typedef struct _e820entry {
	u64 base;
	u64 size;
	u32 type;
} e820entry;

typedef struct _e820map {
	int       n_map;
	e820entry map[E820MAX];
} e820map;

#pragma pack (pop)

#endif 
