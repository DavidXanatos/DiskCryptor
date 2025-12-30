#ifndef _BIOS_
#define _BIOS_

#include "e820.h"

#define BDB_SIGN1 0x01F53F55
#define BDB_SIGN2 0x9E4361E4
#define BDB_SIGN3 0x55454649

#define BDB_BF_HDR_FOUND	1

#pragma pack (push, 1)

typedef struct _bd_data {	
	u32      sign1;        /* 0x01F53F55 */
	u32      sign2;        /* 0x9E4361E4 */
	u32      bd_base;      /* boot data block base */
	u32      bd_size;      /* boot data block size (including stack) */
	dc_pass  password;     /* bootauth password */

	u32		   sign3;        /* 0x55454649 */
	u32		   zero;         /* old_int13 */
	u32		   flags;	       /* misc boot flags */

	u64      bd_base64;    /* boot data block base past 4GB */

} bd_data;

#pragma pack (pop)

#endif
