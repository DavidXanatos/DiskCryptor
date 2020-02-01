#ifndef _DC_IO_H_
#define _DC_IO_H_

int dc_disk_io(int hdd_n, void *buff, u16 sectors, u64 start, int read);

#endif