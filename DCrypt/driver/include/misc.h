#ifndef _MISC_
#define _MISC_

#include "devhook.h"

int start_system_thread(PKSTART_ROUTINE thread_start, void *param, HANDLE *handle);

void wait_object_infinity(void *wait_obj);

int  dc_resolve_link(wchar_t *sym_link, wchar_t *target, u16 length);
int  dc_get_mount_point(dev_hook *hook, wchar_t *buffer, u16 length);
void dc_query_object_name(void *object, wchar_t *buffer, u16 length);

u64  intersect(u64 *i_st, u64 start1, u64 size1, u64 start2, u64 size2);
void dc_delay(u32 msecs);


#endif