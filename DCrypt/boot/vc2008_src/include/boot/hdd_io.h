#ifndef _HDD_IO_H_
#define _HDD_IO_H_

#include "hdd.h"

typedef int (*phddio)(int hdd_n, void *buff, u16 sectors, u64 start, int read);

int hdd_io(int hdd_n, void *buff, u16 sectors, u64 start, int read);

#endif