#ifndef _IO_CONTROL_
#define _IO_CONTROL_

NTSTATUS dc_io_control_irp(dev_hook *hook, PIRP irp);
NTSTATUS dc_drv_control_irp(PDEVICE_OBJECT dev_obj, PIRP irp);

#endif