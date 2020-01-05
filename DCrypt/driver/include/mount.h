#ifndef _MOUNT_
#define _MOUNT_

#include "devhook.h"
#include "enc_dec.h"

void dc_add_password(dc_pass *pass);
void dc_clean_pass_cache();
void dc_clean_keys();

int dc_mount_device(wchar_t *dev_name, dc_pass *password, u32 mnt_flags);
int dc_process_unmount(dev_hook *hook, int opt);

void dc_unmount_async(dev_hook *hook);

int dc_unmount_device(wchar_t *dev_name, int force);

int dc_mount_all(dc_pass *password, u32 flags);
int dc_num_mount();

NTSTATUS dc_probe_mount(dev_hook *hook, PIRP irp);

void dc_init_mount();

#define MAX_MNT_PROBES 32

#endif