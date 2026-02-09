#ifndef _BOOT_HOOK_H_
#define _BOOT_HOOK_H_

#include "hdd.h"

typedef struct _boot_key {
	u8 key[PKCS_DERIVE_MAX]; /* RAW key data    */
	u8 alg;                  /* cipher id       */
} boot_key;

typedef struct _mount_inf {	
	u8         hdd_n;	
	boot_key  *d_key;
	boot_key  *o_key;
	u64        begin;
	u64        end;
	u64        size;
	u32        flags;
	u64        tmp_size;
	u64        stor_off;	
	u32        disk_id;
	u32        bps;

} mount_inf;

#define MOUNT_MAX 8
#define KEY_MAX   8

typedef struct _io_db {
	//hdd_inf   p_hdd[HDD_MAX];
	//u8        n_hdd;
	mount_inf p_mount[MOUNT_MAX];
	u8        n_mount;
	boot_key  p_key[KEY_MAX];
	u8        n_key;
	u16       options;
	int       ldr_dsk;

} io_db;

extern io_db iodb;

#endif