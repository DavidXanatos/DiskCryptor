#ifndef _BOOTLOADER_H_
#define _BOOTLOADER_H_

#define LDR_MAX_MOUNT 8 // maximum mounted devices

#define LDR_LT_GET_PASS  1 // entering password needed
#define LDR_LT_EMBED_KEY 2 // use embedded key
#define LDR_LT_MESSAGE   4 // display enter password message
#define LDR_LT_DSP_PASS  8 // display '*'

#define LDR_ET_MESSAGE      1  // display error message
#define LDR_ET_REBOOT       2  // reboot after 1 second
#define LDR_ET_BOOT_ACTIVE  4  // boot from active partition
#define LDR_ET_EXIT_TO_BIOS 8  // exit to bios
#define LDR_ET_RETRY        16 // retry authentication again
#define LDR_ET_MBR_BOOT     32 // load boot disk MBR

#define LDR_BT_MBR_BOOT    1 // load boot disk MBR
#define LDR_BT_MBR_FIRST   2 // load first disk MBR
#define LDR_BT_ACTIVE      3 // boot from active partition on boot disk
#define LDR_BT_AP_PASSWORD 4 // boot from first partition with appropriate password
#define LDR_BT_DISK_ID     5 // find partition by disk_id

#define LDR_KB_QWERTY 0 // QWERTY keyboard layout
#define LDR_KB_QWERTZ 1 // QWERTZ keyboard layout
#define LDR_KB_AZERTY 2 // AZERTY keyboard layout

#define LDR_OP_EXTERNAL     0x01 // this option indicate external bootloader usage
#define LDR_OP_EPS_TMO      0x02 // set time limit for password entering
#define LDR_OP_TMO_STOP     0x04 // cancel timeout if any key pressed
#define LDR_OP_NOPASS_ERROR 0x08 // use incorrect password action if no password entered
#define LDR_OP_HW_CRYPTO    0x10 // use hardware cryptography when possible
#define LDR_OP_SMALL_BOOT   0x20 // this is a small (aes only) bootloader

#pragma pack (push, 1)

#define LDR_CFG_SIGN1 0x1434A669
#define LDR_CFG_SIGN2 0x7269DA46

typedef struct _ldr_config {
	unsigned long  sign1; // сигнатура для поиска загрузчика в памяти
	unsigned long  sign2; // сигнатура для поиска загрузчика в памяти
	unsigned long  ldr_ver;    // версия загрузчика
	unsigned char  logon_type; // настройки авторизации (константы LDR_LT_x)
	unsigned char  error_type; // настройки действия при ошибке авторизации (константы LDR_ET_x)
	unsigned char  boot_type;  // настройки загрузки авторизация успешно завершена (константы LDR_BT_x)
	unsigned long  disk_id; // ID раздела, используется при LDR_BT_DISK_ID
	unsigned short options; // прочик настройки и флаги (константы LDR_OP_x)
	unsigned char  kbd_layout; // раскладка клавиатуры загрузчика (константы LDR_KB_x)
	char  eps_msg[128]; // текст сообщения запроса авторизации
	char  err_msg[128]; // тест сообщения ошибки авторизации
	unsigned char save_mbr[512]; // сохраненный оригинальный MBR
	unsigned long timeout;  // таймаут авторизации (используется при включенном флаге LDR_OP_EPS_TMO)
	unsigned char emb_key[64]; // встроенный в загрузчик ключ

} ldr_config;

#define E820MAX	64 // number of entries in E820MAP

#define E820_RAM	1
#define E820_RESERVED	2
#define E820_ACPI	3
#define E820_NVS	4

typedef struct _e820entry {
	unsigned __int64 base;
	unsigned __int64 size;
	unsigned long    type;
} e820entry;

typedef struct _e820map {
	int       n_map;
	e820entry map[E820MAX];
} e820map;

typedef struct _rm_ctx {
	union { unsigned long eax; union { unsigned short ax; struct { unsigned char al; unsigned char ah; }; }; };
	union { unsigned long ecx; union { unsigned short cx; struct { unsigned char cl; unsigned char ch; }; }; };
	union { unsigned long edx; union { unsigned short dx; struct { unsigned char dl; unsigned char dh; }; }; };
	union { unsigned long ebx; union { unsigned short bx; struct { unsigned char bl; unsigned char bh; }; }; };

	union { unsigned long ebp; unsigned short bp; };
	union { unsigned long esi; unsigned short si; };
	union { unsigned long edi; unsigned short di; };

	unsigned long  efl;
	unsigned short ds;
	unsigned short es;

} rm_ctx;

typedef struct _pt_ent {
	unsigned char  active;
	unsigned char  start_head;
	unsigned short start_cyl;
	unsigned char  os;
	unsigned char  end_head;
	unsigned short end_cyl;
	unsigned long  start_sect;
	unsigned long  prt_size;

} pt_ent;

typedef struct _lba_p {
	unsigned char    size;
	unsigned char    unk;
	unsigned short   numb;
	unsigned short   dst_off;
	unsigned short   dst_sel;
	unsigned __int64 sector;

} lba_p;

typedef struct _bd_data {	
	unsigned long  sign1;
	unsigned long  sign2;
	unsigned long  bd_base;   // boot data block base
	unsigned long  bd_size;   // boot data block size (including stack)
	dc_pass        password;  // bootauth password
	unsigned long  old_int15; // old int15 handler
	unsigned long  old_int13; // old int13 handler
	
	// volatile data
	unsigned long  ret_32; // return address for RM <-> PM jump
	unsigned long  esp_16; // real mode stack
	unsigned short ss_16;  // real mode ss
	unsigned long  esp_32; // pmode stack
	unsigned long  segoff; // real mode call seg/off
	void   (*jump_rm)();   // real mode jump proc
	void   (*call_rm)();   // real mode call proc
	void   (*hook_ints)(); // hook interrupts proc
	void    *int_cbk;      // protected mode callback
	unsigned char  boot_dsk; // boot disk number
	rm_ctx         rmc;      // real mode call context
	unsigned short push_fl;  // flags pushed to stack
	e820map        mem_map;  // new memory map
} bd_data;

#pragma pack (pop)

#endif