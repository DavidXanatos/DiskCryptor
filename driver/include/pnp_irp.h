#ifndef _PNP_IRP_
#define _PNP_IRP_

DRIVER_ADD_DEVICE dc_add_device;

NTSTATUS dc_pnp_irp(dev_hook *hook, PIRP irp);
NTSTATUS dc_add_device(PDRIVER_OBJECT drv_obj, PDEVICE_OBJECT pdo_dev);

#endif