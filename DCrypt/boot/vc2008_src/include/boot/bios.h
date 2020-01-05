#ifndef _BIOS_
#define _BIOS_

#include "e820.h"

#pragma pack (push, 1)

typedef struct _rm_ctx {
	union
	{
		u32 eax;
		union 
		{
			u16 ax;
			struct {
				u8  al;
				u8  ah;
			};
		};
	};
	union
	{
		u32 ecx;
		union 
		{
			u16 cx;
			struct {
				u8  cl;
				u8  ch;
			};
		};
	};
	
	union
	{
		u32 edx;
		union 
		{
			u16 dx;		
			struct {
				u8  dl;
				u8  dh;
			};
		};
	};

	union
	{
		u32 ebx;
		union 
		{
			u16 bx;
			struct {
				u8  bl;
				u8  bh;
			};
		};
	};

	union {
		u32 ebp;
		u16 bp;
	};
	
	union {
		u32 esi;
		u16 si;
	};
	
	union {
		u32 edi;
		u16 di;
	};

	u32 efl;	
	u16 ds;
	u16 es;

} rm_ctx;

typedef struct _bd_data {	
	u32      sign1;        /*  */
	u32      sign2;        /*  */
	u32      bd_base;      /* boot data block base                            */
	u32      bd_size;      /* boot data block size (including stack)          */
	dc_pass  password;     /* bootauth password */
	u32      old_int15;    /* old int15 handler         */
	u32      old_int13;    /* old int13 handler         */
	/* volatile data */
	u32      ret_32;       /* return address for RM <-> PM jump               */
	u32      esp_16;       /* real mode stack                                 */
	u16      ss_16;        /* real mode ss                                    */ 
	u32      esp_32;       /* pmode stack                                     */	
	u32      segoff;       /* real mode call seg/off    */	
	void   (*jump_rm)();   /* real mode jump proc       */
	void   (*call_rm)();   /* real mode call proc       */
	void   (*hook_ints)(); /* hook interrupts proc      */
	void    *int_cbk;      /* protected mode callback   */
	u8       boot_dsk;     /* boot disk number          */
	rm_ctx   rmc;          /* real mode call context    */
	u16      push_fl;      /* flags pushed to stack     */
	e820map  mem_map;      /* new memory map */
} bd_data;

#pragma pack (pop)

#define FL_CF		0x0001		// Carry Flag
#define FL_RESV1	0x0002		// Reserved - Must be 1
#define FL_PF		0x0004		// Parity Flag
#define FL_RESV2	0x0008		// Reserved - Must be 0
#define FL_AF		0x0010		// Auxiliary Flag
#define FL_RESV3	0x0020		// Reserved - Must be 0
#define FL_ZF		0x0040		// Zero Flag
#define FL_SF		0x0080		// Sign Flag
#define FL_TF		0x0100		// Trap Flag (Single Step)
#define FL_IF		0x0200		// Interrupt Flag
#define FL_DF		0x0400		// Direction Flag
#define FL_OF		0x0800		// Overflow Flag

#define pm_off(seg,off) pv((d32(seg) << 4) + d32(off))
#define rm_seg(off)     d16(d32(off) >> 4)
#define rm_off(off)     d16(d32(off) & 0x0F)

#endif
