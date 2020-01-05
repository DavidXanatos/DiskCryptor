#ifndef _HEADER_IO_H_
#define _HEADER_IO_H_

int io_read_header(dev_hook *hook, dc_header **header, xts_key **out_key, dc_pass *password);
int io_write_header(dev_hook *hook, dc_header *header, xts_key *hdr_key, dc_pass *password);

BOOLEAN is_volume_header_correct(dc_header *header);

#endif