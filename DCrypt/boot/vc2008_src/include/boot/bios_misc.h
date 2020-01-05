#ifndef _BIOS_MISC_H_
#define _BIOS_MISC_H_

void bios_jump_boot(int hdd_n, int n_mount);
void bios_reboot();
void bios_create_smap();
void bios_hook_ints();

#endif