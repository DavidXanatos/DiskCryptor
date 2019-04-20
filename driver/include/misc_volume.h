#ifndef _MISC_VOLUME_H_
#define _MISC_VOLUME_H_

int dc_backup_header(wchar_t *dev_name, dc_pass *password, void *out);
int dc_restore_header(wchar_t *dev_name, dc_pass *password, void *in);
int dc_change_pass(wchar_t *dev_name, dc_pass *old_pass, dc_pass *new_pass);

int  dc_format_start(wchar_t *dev_name, dc_pass *password, crypt_info *crypt);
int  dc_format_step(wchar_t *dev_name, int wp_mode);
int  dc_format_done(wchar_t *dev_name);
NTSTATUS dc_update_volume(dev_hook *hook);

#endif