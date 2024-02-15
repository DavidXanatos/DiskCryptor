/*
    *
    * DiskCryptor - open source partition encryption tool
	* Copyright (c) 2019-2023
	* DavidXanatos <info@diskcryptor.org>
    * Copyright (c) 2007-2013 
    * ntldr <ntldr@diskcryptor.net> PGP key ID - 0xC48251EB4F8E4E6E
    *

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 3 as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <ntifs.h>
#include <ntddcdrm.h>
#include <ntdddisk.h>
#include <ntddvol.h>
#include "defines.h"
#include "devhook.h"
#include "driver.h"
#include "mount.h"
#include "prng.h"
#include "benchmark.h"
#include "misc_irp.h"
#include "enc_dec.h"
#include "misc.h"
#include "debug.h"
#include "readwrite.h"
#include "misc_volume.h"
#include "misc_mem.h"
#include "device_io.h"
#include "disk_info.h"
#include "crypto_functions.h"
#include "dump_helpers.h"

#define IS_VERIFY_IOCTL(_ioctl) ( \
	(_ioctl) == IOCTL_DISK_CHECK_VERIFY || (_ioctl) == IOCTL_CDROM_CHECK_VERIFY || \
	(_ioctl) == IOCTL_STORAGE_CHECK_VERIFY || (_ioctl) == IOCTL_STORAGE_CHECK_VERIFY2 )

#define TRIM_BUFF_MAX(_set) ( \
	_align(sizeof(DEVICE_MANAGE_DATA_SET_ATTRIBUTES), sizeof(DEVICE_DATA_SET_RANGE)) + \
	((_set)->DataSetRangesLength * 2) + (sizeof(DEVICE_DATA_SET_RANGE) * 2) )

#define TRIM_BUFF_LENGTH(_set) ( \
	(_set)->DataSetRangesOffset + (_set)->DataSetRangesLength )

#define TRIM_ADD_RANGE(_set, _start, _size) if ((_size) != 0) { \
	PDEVICE_DATA_SET_RANGE _range = addof((_set), (_set)->DataSetRangesOffset + (_set)->DataSetRangesLength); \
	(_set)->DataSetRangesLength += sizeof(DEVICE_DATA_SET_RANGE); \
	_range->StartingOffset = (_start); \
	_range->LengthInBytes  = (_size); \
}

#define LEN_BEFORE_STORAGE(_hook) ( (_hook)->stor_off - (_hook)->head_len )
#define OFF_END_OF_STORAGE(_hook) ( (_hook)->stor_off + (_hook)->head_len )
#define LEN_AFTER_STORAGE(_hook)  ( (_hook)->dsk_size - OFF_END_OF_STORAGE(_hook) )

/* function types declaration */
IO_COMPLETION_ROUTINE dc_ioctl_complete;

static int dc_ioctl_process(u32 code, dc_ioctl *data)
{
	int resl = ST_ERROR;

	switch (code)
	{
		case DC_CTL_ADD_PASS:
			{
				dc_add_password(&data->passw1);
				resl = ST_OK;
			} 
		break;
		case DC_CTL_MOUNT:
			{
				resl = dc_mount_device(data->device, &data->passw1, data->flags);

				if ( (resl == ST_OK) && (dc_conf_flags & CONF_CACHE_PASSWORD) ) {
					dc_add_password(&data->passw1);
				}
			}
		break;
		case DC_CTL_MOUNT_ALL:
			{
				data->n_mount = dc_mount_all(&data->passw1, data->flags);
				resl          = ST_OK;

				if ( (data->n_mount != 0) && (dc_conf_flags & CONF_CACHE_PASSWORD) ) {
					dc_add_password(&data->passw1);
				}
			}
		break;
		case DC_CTL_UNMOUNT:
			{
				resl = dc_unmount_device(data->device, (data->flags & MF_FORCE));
			}
		break;
		case DC_CTL_CHANGE_PASS:
			{
				resl = dc_change_pass(data->device, &data->passw1, &data->passw2);

				if ( (resl == ST_OK) && (dc_conf_flags & CONF_CACHE_PASSWORD) ) {
					dc_add_password(&data->passw2);
				}
			}
		break;
		case DC_CTL_ENCRYPT_START:
			{
				resl = dc_encrypt_start(data->device, &data->passw1, &data->crypt, FALSE);

				if ( (resl == ST_OK) && (dc_conf_flags & CONF_CACHE_PASSWORD) ) {
					dc_add_password(&data->passw1);
				}
			}
		break;
		case DC_CTL_ENCRYPT_START2:
			{
				dc_pass* pass = NULL;
				crypt_info crypt;
				resl = dc_get_pending_encrypt(data->path, &pass, &crypt);

				if ( (resl == ST_OK) ) {
					resl = dc_encrypt_start(data->device, pass, &crypt, TRUE);
					mm_secure_free(pass);
				}
			}
		break;
		case DC_CTL_DECRYPT_START:
			{
				resl = dc_decrypt_start(data->device, &data->passw1);
			}
		break;
		case DC_CTL_RE_ENC_START:
			{
				resl = dc_reencrypt_start(data->device, &data->passw1, &data->crypt);
			}
		break;
		case DC_CTL_ENCRYPT_STEP:
			{
				resl = dc_send_sync_packet(data->device, S_OP_ENC_BLOCK, pv(data->crypt.wp_mode));
			}
		break;
		case DC_CTL_DECRYPT_STEP:
			{
				resl = dc_send_sync_packet(data->device, S_OP_DEC_BLOCK, 0);
			}
		break; 
		case DC_CTL_SYNC_STATE:
			{
				resl = dc_send_sync_packet(data->device, S_OP_SYNC, 0);
			}
		break;
		case DC_CTL_RESOLVE:
			{
				while (dc_resolve_link(data->device, data->device, sizeof(data->device)) == ST_OK) {
					resl = ST_OK;
				}
			}
		break;
		case DC_FORMAT_START:
			{
				resl = dc_format_start(data->device, &data->passw1, &data->crypt);

				if ( (resl == ST_OK) && (dc_conf_flags & CONF_CACHE_PASSWORD) ) {
					dc_add_password(&data->passw1);
				}
			}
		break;
		case DC_FORMAT_STEP: 
			{
				resl = dc_format_step(data->device, data->crypt.wp_mode);
			}
		break;
		case DC_FORMAT_DONE:
			{
				resl = dc_format_done(data->device);
			}
		break;
	}

	return resl;
}

NTSTATUS dc_drv_control_irp(PDEVICE_OBJECT dev_obj, PIRP irp)
{
	PIO_STACK_LOCATION irp_sp = IoGetCurrentIrpStackLocation(irp);
	NTSTATUS           status = STATUS_INVALID_DEVICE_REQUEST; // returned status
	ULONG              length = 0; // returned length
	//
	void              *data    = irp->AssociatedIrp.SystemBuffer;
	u32                in_len  = irp_sp->Parameters.DeviceIoControl.InputBufferLength;
	u32                out_len = irp_sp->Parameters.DeviceIoControl.OutputBufferLength;
	
	switch (irp_sp->Parameters.DeviceIoControl.IoControlCode)
	{
		case DC_GET_VERSION:
			if (irp_sp->Parameters.DeviceIoControl.OutputBufferLength != sizeof(ULONG))
			{
				status = STATUS_INVALID_PARAMETER;
				break;
			}
			*((PULONG)irp->AssociatedIrp.SystemBuffer) = DC_DRIVER_VER;
			status = STATUS_SUCCESS;
			length = sizeof(ULONG);
		break;
		case DC_CTL_CLEAR_PASS:
			dc_clean_pass_cache();
			status = STATUS_SUCCESS;
		break;
		case DC_CTL_ADD_SEED:
			if (irp_sp->Parameters.DeviceIoControl.InputBufferLength == 0)
			{
				status = STATUS_INVALID_PARAMETER;
				break;
			}
			cp_rand_add_seed(irp->AssociatedIrp.SystemBuffer, irp_sp->Parameters.DeviceIoControl.InputBufferLength);
			status = STATUS_SUCCESS;
			// prevent leaks
			RtlSecureZeroMemory(irp->AssociatedIrp.SystemBuffer, irp_sp->Parameters.DeviceIoControl.InputBufferLength);
		break;
		case DC_CTL_GET_RAND:
			if (irp_sp->Parameters.DeviceIoControl.OutputBufferLength == 0)
			{
				status = STATUS_INVALID_PARAMETER;
				break;
			}
			if ( (data = MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority)) == NULL )
			{
				status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}
			if (cp_rand_bytes(data, irp_sp->Parameters.DeviceIoControl.OutputBufferLength) == 0)
			{
				status = STATUS_INTERNAL_ERROR;
				break;
			}
			status = STATUS_SUCCESS;
			length = irp_sp->Parameters.DeviceIoControl.OutputBufferLength;
		break;
		case DC_CTL_LOCK_MEM:
			if (irp_sp->Parameters.DeviceIoControl.InputBufferLength != sizeof(DC_LOCK_MEMORY))
			{
				status = STATUS_INVALID_PARAMETER;
				break;
			}
			status = mm_lock_user_memory( PsGetProcessId(IoGetRequestorProcess(irp)), ((PDC_LOCK_MEMORY)irp->AssociatedIrp.SystemBuffer)->ptr,
				                                                                      ((PDC_LOCK_MEMORY)irp->AssociatedIrp.SystemBuffer)->length );
		break;
		case DC_CTL_UNLOCK_MEM:
			if (irp_sp->Parameters.DeviceIoControl.InputBufferLength != sizeof(PVOID*))
			{
				status = STATUS_INVALID_PARAMETER;
				break;
			}
			status = mm_unlock_user_memory( PsGetProcessId(IoGetRequestorProcess(irp)), *((PVOID*)irp->AssociatedIrp.SystemBuffer) );
		break;
		case DC_CTL_GET_FLAGS:
			if (irp_sp->Parameters.DeviceIoControl.OutputBufferLength != sizeof(DC_FLAGS))
			{
				status = STATUS_INVALID_PARAMETER;
				break;
			}
			((PDC_FLAGS)irp->AssociatedIrp.SystemBuffer)->conf_flags = dc_conf_flags;
			((PDC_FLAGS)irp->AssociatedIrp.SystemBuffer)->load_flags = dc_load_flags;
			((PDC_FLAGS)irp->AssociatedIrp.SystemBuffer)->boot_flags = dc_boot_flags;
			status = STATUS_SUCCESS;
			length = sizeof(DC_FLAGS);
		break;
		case DC_CTL_SET_FLAGS:
			if (irp_sp->Parameters.DeviceIoControl.InputBufferLength != sizeof(DC_FLAGS))
			{
				status = STATUS_INVALID_PARAMETER;
				break;
			}
			dc_conf_flags = ((PDC_FLAGS)irp->AssociatedIrp.SystemBuffer)->conf_flags;

			if ( !(dc_conf_flags & CONF_CACHE_PASSWORD) ) dc_clean_pass_cache();
			dc_init_encryption();

			status = STATUS_SUCCESS;
		break;
		case DC_CTL_BSOD:
			mm_clean_secure_memory();
			dc_clean_keys();

			KeBugCheck(IRQL_NOT_LESS_OR_EQUAL);
		break;
		case DC_GET_DUMP_HELPERS: // This IOCTL is allowed only from kernel mode
			if (irp->RequestorMode != KernelMode)
			{
				status = STATUS_ACCESS_DENIED;
				break;
			}
			if (irp_sp->Parameters.DeviceIoControl.OutputBufferLength != sizeof(DC_DUMP_HELPERS))
			{
				status = STATUS_INVALID_PARAMETER;
				break;
			}

			memcpy(irp->UserBuffer, &dc_dump_helpers, sizeof(DC_DUMP_HELPERS));
			status = STATUS_SUCCESS;
			length = sizeof(DC_DUMP_HELPERS);
		break;
		//
		case DC_CTL_STATUS:
			{
				dc_ioctl  *dctl = data;
				dc_status *stat = data;
				dev_hook  *hook;

				if ( (in_len == sizeof(dc_ioctl)) && (out_len == sizeof(dc_status)) )
				{
					dctl->device[MAX_DEVICE] = 0;

					if (hook = dc_find_hook(dctl->device))
					{
						if (hook->pdo_dev->Flags & DO_SYSTEM_BOOT_PARTITION) {
							hook->flags |= F_SYSTEM;
						}

						dc_get_mount_point(hook, stat->mnt_point, sizeof(stat->mnt_point));

						stat->crypt        = hook->crypt;
						stat->dsk_size     = hook->dsk_size;
						stat->tmp_size     = hook->tmp_size;
						stat->flags        = hook->flags;
						stat->mnt_flags    = hook->mnt_flags;
						stat->disk_id      = hook->disk_id;
						stat->paging_count = hook->paging_count;
						stat->vf_version   = hook->vf_version;
						status             = STATUS_SUCCESS; 
						length             = sizeof(dc_status);

						dc_deref_hook(hook);
					}
				}
			}
		break;
		case DC_CTL_BENCHMARK:
			{
				 if ( (in_len == sizeof(int)) && (out_len == sizeof(dc_bench_info)) )
				 {
					 if (dc_k_benchmark(p32(data)[0], pv(data)) == ST_OK) {
						 status = STATUS_SUCCESS; 
						 length = sizeof(dc_bench_info);
					 }
				 }
			}
		break;
		
		case DC_BACKUP_HEADER:
			{
				dc_backup_ctl *back = data;
				
				if ( (in_len == sizeof(dc_backup_ctl)) && (out_len == in_len) )
				{
					back->device[MAX_DEVICE] = 0;

					back->status = dc_backup_header(back->device, &back->pass, back->backup);

					/* prevent leaks */
					burn(&back->pass, sizeof(back->pass));

					status = STATUS_SUCCESS;
					length = sizeof(dc_backup_ctl);
				}
			}
		break;
		case DC_RESTORE_HEADER:
			{
				dc_backup_ctl *back = data;
				
				if ( (in_len == sizeof(dc_backup_ctl)) && (out_len == in_len) )
				{
					back->device[MAX_DEVICE] = 0;

					back->status = dc_restore_header(back->device, &back->pass, back->backup);

					/* prevent leaks */
					burn(&back->pass, sizeof(back->pass));

					status = STATUS_SUCCESS;
					length = sizeof(dc_backup_ctl);
				}
			}
		break;
		default: 
			{
				dc_ioctl *dctl = data;

				if ( (in_len == sizeof(dc_ioctl)) && (out_len == sizeof(dc_ioctl)) )
				{					
					/* limit null-terminated string length */
					dctl->device[MAX_DEVICE] = 0;
					
					/* process IOCTL */
					dctl->status = dc_ioctl_process(irp_sp->Parameters.DeviceIoControl.IoControlCode, dctl);

					/* prevent leaks  */
					burn(&dctl->passw1, sizeof(dctl->passw1));
					burn(&dctl->passw2, sizeof(dctl->passw2));

					status = STATUS_SUCCESS;
					length = sizeof(dc_ioctl);
				}
			}
		break;
	}
	return dc_complete_irp(irp, status, length);
}

static NTSTATUS dc_ioctl_complete(PDEVICE_OBJECT dev_obj, PIRP irp, void *param)
{
	PIO_STACK_LOCATION irp_sp = IoGetCurrentIrpStackLocation(irp);
	dev_hook          *hook   = dev_obj->DeviceExtension;
	u32                ioctl  = irp_sp->Parameters.DeviceIoControl.IoControlCode;
	NTSTATUS           status = irp->IoStatus.Status;
	u32               *chg_c;
    int                change;

	if (irp->PendingReturned) {
		IoMarkIrpPending(irp);
	}
	if ( NT_SUCCESS(status) && (hook->flags & F_ENABLED) )
	{
		switch (ioctl)
		{
			case IOCTL_DISK_GET_LENGTH_INFO:
			  {
				  PGET_LENGTH_INFORMATION gl = pv(irp->AssociatedIrp.SystemBuffer);
				  gl->Length.QuadPart = hook->use_size;
			  }
		    break;
			case IOCTL_DISK_GET_PARTITION_INFO:
			  {
				  PPARTITION_INFORMATION pi = pv(irp->AssociatedIrp.SystemBuffer);
				  pi->PartitionLength.QuadPart = hook->use_size;				
			  }
		    break;
			case IOCTL_DISK_GET_PARTITION_INFO_EX:
			  {
				  PPARTITION_INFORMATION_EX pi = pv(irp->AssociatedIrp.SystemBuffer);				  
				  pi->PartitionLength.QuadPart = hook->use_size;
			  }
		    break;
			case IOCTL_CDROM_GET_DRIVE_GEOMETRY_EX:
				{
					PDISK_GEOMETRY_EX dgx = pv(irp->AssociatedIrp.SystemBuffer);
					dgx->DiskSize.QuadPart = hook->use_size;
				}
			break;
		}
	}
	if ( (hook->flags & F_REMOVABLE) && (IS_VERIFY_IOCTL(ioctl) != 0) )
	{
		chg_c  = pv(irp->AssociatedIrp.SystemBuffer);
		change = NT_SUCCESS(status) == FALSE;
		
		if (irp->IoStatus.Information == sizeof(u32)) {
			change |= lock_xchg(&hook->chg_count, *chg_c) != *chg_c;
			*chg_c += hook->chg_mount;
		}

		if ( (change != 0) && (hook->dsk_size != 0) ) {
			DbgMsg("media removed\n");
			dc_unmount_async(hook);
		}	
	}
	IoReleaseRemoveLock(&hook->remove_lock, irp);

	return STATUS_SUCCESS;
}

static NTSTATUS dc_trim_irp(dev_hook *hook, PIRP irp)
{
	PIO_STACK_LOCATION                 irp_sp = IoGetCurrentIrpStackLocation(irp);
	PDEVICE_MANAGE_DATA_SET_ATTRIBUTES p_set  = irp->AssociatedIrp.SystemBuffer;
	u32                                length = irp_sp->Parameters.DeviceIoControl.InputBufferLength;	
	u64                                offset, rnglen;
	PDEVICE_DATA_SET_RANGE             range;
	PDEVICE_MANAGE_DATA_SET_ATTRIBUTES n_set;
	u64                                off1, off2;
	u64                                len1, len2;
	u32                                i;

	if ( (length < sizeof(DEVICE_MANAGE_DATA_SET_ATTRIBUTES)) ||
		 (p_set->Action != DeviceDsmAction_Trim) ||
		 (length < d64(p_set->DataSetRangesOffset) + d64(p_set->DataSetRangesLength)) )
	{
		return dc_forward_irp(hook, irp);
	}
	if (dc_conf_flags & CONF_DISABLE_TRIM)
	{
		return dc_release_irp(hook, irp, STATUS_SUCCESS);
	}
	if ( (n_set = mm_pool_alloc(TRIM_BUFF_MAX(p_set))) == NULL )
	{
		return dc_release_irp(hook, irp, STATUS_INSUFFICIENT_RESOURCES);
	}
	n_set->Size = sizeof(DEVICE_MANAGE_DATA_SET_ATTRIBUTES);
	n_set->Action = DeviceDsmAction_Trim;
	n_set->Flags = 0;
	n_set->ParameterBlockOffset = 0;
	n_set->ParameterBlockLength = 0;
	n_set->DataSetRangesOffset = _align(sizeof(DEVICE_MANAGE_DATA_SET_ATTRIBUTES), sizeof(DEVICE_DATA_SET_RANGE));
	n_set->DataSetRangesLength = 0;

	if (p_set->Flags & DEVICE_DSM_FLAG_ENTIRE_DATA_SET_RANGE)
	{
		if (hook->flags & F_NO_REDIRECT) {
			TRIM_ADD_RANGE(n_set, hook->head_len, hook->dsk_size - hook->head_len);
		} else {
			TRIM_ADD_RANGE(n_set, hook->head_len, LEN_BEFORE_STORAGE(hook));
			TRIM_ADD_RANGE(n_set, OFF_END_OF_STORAGE(hook), LEN_AFTER_STORAGE(hook));
		}
	} else
	{
		for (i = 0, range = addof(p_set, p_set->DataSetRangesOffset);
			 i < p_set->DataSetRangesLength / sizeof(DEVICE_DATA_SET_RANGE); i++, range++)
		{
			if ( (offset = range->StartingOffset) + (rnglen = range->LengthInBytes) > hook->use_size ) {
				continue;
			}
			if (hook->flags & F_NO_REDIRECT) {
				TRIM_ADD_RANGE(n_set, offset + hook->head_len, min(rnglen, hook->use_size - offset));
				continue;
			}
			len1 = intersect(&off1, offset, rnglen, hook->head_len, LEN_BEFORE_STORAGE(hook));
			len2 = intersect(&off2, offset, rnglen, OFF_END_OF_STORAGE(hook), LEN_AFTER_STORAGE(hook));

			TRIM_ADD_RANGE(n_set, off1, len1);
			TRIM_ADD_RANGE(n_set, off2, len2);
		}
	}
	if (n_set->DataSetRangesLength != 0) {
		io_hook_ioctl(hook, IOCTL_STORAGE_MANAGE_DATA_SET_ATTRIBUTES, n_set, TRIM_BUFF_LENGTH(n_set), NULL, 0);
	}
	mm_pool_free(n_set);

	return dc_release_irp(hook, irp, STATUS_SUCCESS);
}

NTSTATUS dc_io_control_irp(dev_hook *hook, PIRP irp)
{	
	PIO_STACK_LOCATION irp_sp = IoGetCurrentIrpStackLocation(irp);
	ULONG              iocode = irp_sp->Parameters.DeviceIoControl.IoControlCode;

	if (iocode == IOCTL_DISK_GET_LENGTH_INFO ||
		iocode == IOCTL_DISK_GET_PARTITION_INFO || 
		iocode == IOCTL_DISK_GET_PARTITION_INFO_EX ||
		iocode == IOCTL_CDROM_GET_DRIVE_GEOMETRY_EX || IS_VERIFY_IOCTL(iocode) )
	{
		IoCopyCurrentIrpStackLocationToNext(irp);
		IoSetCompletionRoutine(irp, dc_ioctl_complete, NULL, TRUE, TRUE, TRUE);
		return IoCallDriver(hook->orig_dev, irp);
	}
	if (hook->flags & F_ENABLED) {
		if (iocode == IOCTL_STORAGE_MANAGE_DATA_SET_ATTRIBUTES) return dc_trim_irp(hook, irp);
		if (iocode == IOCTL_VOLUME_UPDATE_PROPERTIES) return dc_release_irp(hook, irp, dc_update_volume(hook));
		if (iocode == IOCTL_DISK_IS_WRITABLE) {
			if ((hook->mnt_flags & MF_READ_ONLY)) {
				return dc_release_irp(hook, irp, STATUS_MEDIA_WRITE_PROTECTED);
			}
		}
	}
	return dc_forward_irp(hook, irp);
}
