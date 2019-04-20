#ifndef _READWRITE_
#define _READWRITE_

NTSTATUS io_read_write_irp(dev_hook *hook, PIRP irp);
NTSTATUS io_encrypted_irp_io(dev_hook *hook, PIRP irp, BOOLEAN is_sync);

void io_init();
void io_free();

#endif
