#ifndef _EFIINST_
#define _EFIINST_

#include "dcapi.h"

void dc_api dc_efi_init();
int dc_api dc_efi_check();
int dc_api dc_efi_is_secureboot();

int dc_api dc_mk_efi_rec(const wchar_t *root, int format, int shim);
int dc_api dc_set_efi_boot(int dsk_num, int shim, int replace_ms);
int dc_api dc_update_efi_boot(int dsk_num);
int dc_api dc_unset_efi_boot(int dsk_num);

int dc_api dc_get_platform_info(int dsk_num, char** infoContent, int *size);

int dc_api dc_is_gpt_disk(int dsk_num);

int dc_api dc_efi_config_by_partition(
	const wchar_t *root, int set_conf, ldr_config *conf);

int dc_api dc_efi_config(
	int dsk_num, int set_conf, ldr_config *conf);

int dc_api dc_get_dcs_version(const wchar_t *root);

void dc_api dc_efi_config_init(ldr_config *conf);

int dc_api dc_efi_shim_available();
int dc_api dc_is_shim_on_partition(const wchar_t *root);
int dc_api dc_is_dcs_on_partition(const wchar_t *root);
int dc_api dc_is_dcs_on_disk(int dsk_num);
int dc_api dc_efi_is_msft_on_disk(int dsk_num);

int dc_api dc_efi_set_bme(wchar_t* description, int dsk_num);
int dc_api dc_efi_del_bme();
int dc_api dc_efi_is_bme_set(int dsk_num);

#endif
