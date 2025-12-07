/*
    *
    * DiskCryptor - open source partition encryption tool
	* Copyright (c) 2019-2023
	* DavidXanatos <info@diskcryptor.org>
    * Copyright (c) 2007-2008 
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
#include "defines.h"
#include "devhook.h"
#include "driver.h"
#include "misc.h"
#include "crc32.h"
#include "enc_dec.h"
#include "misc_irp.h"
#include "readwrite.h"
#include "mount.h"
#include "fast_crypt.h"
#include "misc_volume.h"
#include "debug.h"
#include "misc_mem.h"
#include "crypto_head.h"
#include "disk_info.h"
#include "device_io.h"
#include "header_io.h"
#include "storage.h"

typedef struct _dsk_pass {
	struct _dsk_pass *next;
	dc_pass           pass;
	
} dsk_pass;

typedef struct _mount_ctx {
	WORK_QUEUE_ITEM  wrk_item;
	PIRP             irp;
	dev_hook        *hook;
	
} mount_ctx;

/* function types declaration */
WORKER_THREAD_ROUTINE unmount_item_proc;
KSTART_ROUTINE        unmount_thread_proc;
WORKER_THREAD_ROUTINE mount_item_proc;

static dsk_pass *f_pass;
static ERESOURCE p_resource;


void dc_add_password(dc_pass *pass)
{
	dsk_pass *d_pass;

	if (pass->size != 0)
	{
		KeEnterCriticalRegion();
		ExAcquireResourceExclusiveLite(&p_resource, TRUE);

		for (d_pass = f_pass; d_pass; d_pass = d_pass->next)
		{
			if (IS_EQUAL_PASS(pass, &d_pass->pass)) {
				break;
			}
		}

		if ( (d_pass == NULL) && (d_pass = mm_secure_alloc(sizeof(dsk_pass))) )
		{
			memcpy(&d_pass->pass, pass, sizeof(dc_pass));

			d_pass->next = f_pass;
			f_pass       = d_pass;
		}

		ExReleaseResourceLite(&p_resource);
		KeLeaveCriticalRegion();
	}
}

void dc_clean_pass_cache()
{
	dsk_pass *d_pass;
	dsk_pass *c_pass;
	int       loirql;

	DbgMsg("dc_clean_pass_cache\n");

	if (loirql = (KeGetCurrentIrql() == PASSIVE_LEVEL)) {
		KeEnterCriticalRegion();
		ExAcquireResourceExclusiveLite(&p_resource, TRUE);
	}

	for (d_pass = f_pass; d_pass;)
	{
		c_pass = d_pass;
		d_pass = d_pass->next;
		/* zero password data */
		burn(c_pass, sizeof(dsk_pass));
		/* free memory if possible */
		if (loirql != 0) mm_secure_free(c_pass);
	}
	f_pass = NULL;

	if (loirql != 0) {
		ExReleaseResourceLite(&p_resource);
		KeLeaveCriticalRegion();
	}
}

void dc_clean_keys() 
{
	dev_hook *hook;

	for (hook = dc_first_hook(); hook != NULL; hook = dc_next_hook(hook))
	{
		if (hook->dsk_key != NULL) RtlSecureZeroMemory(hook->dsk_key, sizeof(xts_key));
		if (hook->tmp_key != NULL) RtlSecureZeroMemory(hook->tmp_key, sizeof(xts_key));
		if (hook->hdr_key != NULL) RtlSecureZeroMemory(hook->hdr_key, sizeof(xts_key));
		
		RtlSecureZeroMemory(&hook->tmp_header, sizeof(dc_header));
	}

	// Write Back and Invalidate CPU Caches
	__wbinvd();
}

static 
int dc_probe_decrypt(dev_hook *hook, dc_header **header, xts_key **res_key, dc_pass *password)
{
	xts_key  *hdr_key;
	dsk_pass *d_pass;	
	int       resl, succs;

	hdr_key = NULL; succs = 0; *header = NULL;
	do
	{
		/* read raw volume header */
		if ( (resl = io_read_header(hook, header, NULL, NULL)) != ST_OK ) {
			break;
		}
		if ( (hdr_key = mm_secure_alloc(sizeof(xts_key))) == NULL ) {
			resl = ST_NOMEM; break;
		}

		/* derive header key and decrypt header */
		do
		{
			if (password != NULL)
			{
				/* probe mount with entered password */
				if (succs = cp_decrypt_header(hdr_key, *header, password)) {
					break;
				}
			}

			KeEnterCriticalRegion();
			ExAcquireResourceSharedLite(&p_resource, TRUE);

			/* probe mount with cached passwords */
			for (d_pass = f_pass; d_pass; d_pass = d_pass->next)
			{
				if (succs = cp_decrypt_header(hdr_key, *header, &d_pass->pass)) {
					break;
				}
			}

			ExReleaseResourceLite(&p_resource);
			KeLeaveCriticalRegion();
		} while (0);

		if (succs != 0) {
			*res_key = hdr_key; hdr_key = NULL; resl = ST_OK; 
		} else {
			resl = ST_PASS_ERR;
		}
	} while (0);

	if (resl != ST_OK && *header != NULL) {
		mm_secure_free(*header); *header = NULL;
	}
	if (hdr_key != NULL) {
		mm_secure_free(hdr_key);
	}
	return resl;
}

int dc_mount_device(wchar_t *dev_name, dc_pass *password, u32 mnt_flags)
{
	dc_header *hcopy = NULL;
	dev_hook  *hook  = NULL;
	xts_key   *hdr_key = NULL;
	int        resl;
	
	DbgMsg("dc_mount_device %ws\n", dev_name);

	do 
	{
		if ( (hook = dc_find_hook(dev_name)) == NULL ) {
			resl = ST_NF_DEVICE; break;
		}

		wait_object_infinity(&hook->busy_lock);

		if (hook->flags & F_ENABLED) {
			resl = ST_ALR_MOUNT; break;
		}
		if (hook->flags & (F_UNSUPRT | F_DISABLE | F_FORMATTING)) {
			resl = ST_ERROR; break;
		}

		if ( !NT_SUCCESS(dc_fill_device_info(hook)) ) {
			resl = ST_IO_ERROR; break;
		}

		if ( ( (hook->flags & F_CDROM) && (hook->bps != CD_SECTOR_SIZE) ) ||
			 (!(hook->flags & F_CDROM) && IS_INVALID_SECTOR_SIZE(hook->bps) ) )
		{
			hook->flags |= F_UNSUPRT; resl = ST_ERROR; break;
		}
		if ( (resl = dc_probe_decrypt(hook, &hcopy, &hdr_key, password)) != ST_OK ) {
			break;
		}

		/* check volume header */		
		if ( (IS_INVALID_VOL_FLAGS(hcopy->flags) != 0) ||
			 ( (hcopy->flags & VF_STORAGE_FILE) && (hcopy->stor_off == 0) ) ||
			 (hcopy->alg_1 >= CF_CIPHERS_NUM) ||
			 (hcopy->alg_2 >= CF_CIPHERS_NUM) || 
			 (hcopy->tmp_wp_mode >= WP_NUM) ||
			 ( (hook->flags & F_CDROM) && (hcopy->flags & (VF_TMP_MODE | VF_STORAGE_FILE)) ) )
		{
			resl = ST_INV_VOLUME; break;
		}
		if (hcopy->version > DC_HDR_VERSION) {
			resl = ST_VOLUME_TOO_NEW; break;
		}
#if 0
		/* update volume header if needed */
		if ( (hcopy->version < DC_HDR_VERSION) && !(hook->flags & F_CDROM) )
		{
			hcopy->version = DC_HDR_VERSION;
			memset(hcopy->deprecated, 0, sizeof(hcopy->deprecated));
			
			io_write_header(hook, hcopy, hdr_key, NULL);
		}
#endif

		DbgMsg("hdr_key=%p, dsk_key=%p\n", hdr_key, hook->dsk_key);

		// initialize volume key
		if ( (hook->dsk_key = (xts_key*)mm_secure_alloc(sizeof(xts_key))) == NULL ) {
			resl = ST_NOMEM;
			break;
		}
		xts_set_key(hcopy->key_1, hcopy->alg_1, hook->dsk_key);

		DbgMsg("device mounted\n");

		if (hcopy->flags & VF_STORAGE_FILE) {
			hook->use_size = hook->dsk_size;
			hook->stor_off = hcopy->stor_off;
		} else {
			hook->use_size = hook->dsk_size - hook->head_len;
			hook->stor_off = hook->use_size;
		}		
		hook->crypt.cipher_id = d8(hcopy->alg_1);
		hook->disk_id    = hcopy->disk_id;
		hook->vf_version = hcopy->version;		
		hook->tmp_size   = 0;
		hook->mnt_flags  = mnt_flags;

		DbgMsg("hook->vf_version %d\n", hook->vf_version);
		DbgMsg("hook->bps %d\n", hook->bps);
		DbgMsg("hook->head_len %d\n", hook->head_len);		
		DbgMsg("flags %x\n", hcopy->flags);

		if (hcopy->flags & VF_STORAGE_FILE) {
			hook->flags |= F_PROTECT_DCSYS;
		}
		if (hcopy->flags & VF_NO_REDIR) {
			hook->flags   |= F_NO_REDIRECT;
			hook->stor_off = 0;			
		}

		if (hcopy->flags & VF_TMP_MODE)
		{
			hook->tmp_size      = hcopy->tmp_size;
			hook->hdr_key       = hdr_key;
			hook->crypt.wp_mode = hcopy->tmp_wp_mode;			

			if (hcopy->flags & VF_REENCRYPT) {
				hook->sync_init_type = S_CONTINUE_RE_ENC;
			} else {
				hook->sync_init_type = S_CONTINUE_ENC;
			}
				
			/* copy decrypted header to device data */
			memcpy(&hook->tmp_header, hcopy, sizeof(dc_header));
				
			if ( (resl = dc_enable_sync_mode(hook)) != ST_OK ) 
			{
				burn(&hook->tmp_header, sizeof(dc_header));
				hdr_key = hook->hdr_key;
			} else  {				
				hdr_key = NULL; /* prevent key wiping */
			}
		} else {			
			hook->flags |= F_ENABLED;
			resl = ST_OK;
		}
		if (resl == ST_OK) {
			/* increment mount changes counter */
			lock_inc(&hook->chg_mount);
		}
	} while (0);

	if (hdr_key != NULL) mm_secure_free(hdr_key);
	if (hcopy != NULL)   mm_secure_free(hcopy);

	if (hook != NULL)
	{
		if ((hook->flags & F_ENABLED) == 0 && hook->dsk_key != NULL) {
			mm_secure_free(hook->dsk_key);
			hook->dsk_key = NULL;
		}

		KeReleaseMutex(&hook->busy_lock, FALSE);
		dc_deref_hook(hook);
	}
	return resl;
}

/*
   this routine process unmounting the device
   unmount options:
    UM_NOFSCTL - unmount without reporting to FS
	UM_FORCE   - force unmounting
*/
int dc_process_unmount(dev_hook *hook, int opt)
{
	IO_STATUS_BLOCK iosb;
	NTSTATUS        status;
	HANDLE          h_dev  = NULL;
	int             locked = 0;
	int             resl;	

	DbgMsg("dc_process_unmount, dev=%ws\n", hook->dev_name);
	
	if ((hook->flags & F_ENABLED) == 0)
	{
		return ST_NO_MOUNT;
	}

	wait_object_infinity(&hook->busy_lock);

	if ((hook->flags & F_ENABLED) == 0)
	{
		resl = ST_NO_MOUNT;
		goto cleanup;
	}

	do
	{
		if (hook->flags & F_FORMATTING) {
			dc_format_done(hook->dev_name);
		}

		if ( !(hook->flags & F_SYSTEM) && !(opt & MF_NOFSCTL) )
		{
			h_dev = io_open_device(hook->dev_name);

			if ( (h_dev == NULL) && !(opt & MF_FORCE) )	{
				resl = ST_LOCK_ERR; break;
			}

			if (h_dev != NULL)
			{
				status = ZwFsControlFile(h_dev, NULL, NULL, NULL, &iosb, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0);

				if ( (NT_SUCCESS(status) == FALSE) && !(opt & MF_FORCE) ) {
					resl = ST_LOCK_ERR; break;
				}
				locked = (NT_SUCCESS(status) != FALSE);

				ZwFsControlFile(h_dev, NULL, NULL, NULL, &iosb, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0);				
			}
		}

		if ((opt & MF_NOSYNC) == 0)
		{
			// temporarily disable IRP processing
			hook->flags |= F_DISABLE;

			// wait for pending IRPs completion
			if ((opt & MF_NOWAIT_IO) == 0) {
				while (hook->remove_lock.Common.IoCount > 1) dc_delay(20);
			}
			if (hook->flags & F_SYNC) {
				// send signal to synchronous mode thread
				dc_send_sync_packet(hook->dev_name, S_OP_FINALIZE, 0);
			}			
		}

		hook->flags    &= ~F_CLEAR_ON_UNMOUNT;
		hook->use_size  = hook->dsk_size;
		hook->tmp_size  = 0;
		hook->mnt_flags = 0;
		resl            = ST_OK;

		// increment mount changes counter
		lock_inc(&hook->chg_mount);

		// free encryption key
		if (hook->dsk_key != NULL) {
			mm_secure_free(hook->dsk_key);
			hook->dsk_key = NULL;
		}

		if ( !(opt & MF_NOSYNC) ) {
			/* enable IRP processing */
			hook->flags &= ~F_DISABLE;
		}
	} while (0);

	if (h_dev != NULL) 
	{
		if (locked != 0) {
			ZwFsControlFile(h_dev, NULL, NULL, NULL, &iosb, FSCTL_UNLOCK_VOLUME, NULL, 0, NULL, 0);
		}
		ZwClose(h_dev);
	}

cleanup:
	KeReleaseMutex(&hook->busy_lock, FALSE);	
	return resl;
}

static void unmount_thread_proc(mount_ctx *mnt) 
{
	dev_hook *hook = mnt->hook;
	
	dc_process_unmount(hook, MF_NOFSCTL);

	hook->dsk_size      = 0;
	hook->use_size      = 0;
	hook->mnt_probed    = 0;
	hook->mnt_probe_cnt = 0;

	dc_deref_hook(hook);
	mm_pool_free(mnt);
	PsTerminateSystemThread(STATUS_SUCCESS);
}

static void unmount_item_proc(mount_ctx *mnt)
{
	if (start_system_thread(unmount_thread_proc, mnt, NULL) != ST_OK) {
		dc_deref_hook(mnt->hook);
		mm_pool_free(mnt);
	}
}

void dc_unmount_async(dev_hook *hook)
{
	mount_ctx *mnt;

	DbgMsg("dc_unmount_async at IRQL %d\n", KeGetCurrentIrql());

	if (mnt = mm_pool_alloc(sizeof(mount_ctx)))
	{
		mnt->hook = hook; dc_reference_hook(hook);

		if (KeGetCurrentIrql() != PASSIVE_LEVEL) 
		{
			ExInitializeWorkItem(&mnt->wrk_item, unmount_item_proc, mnt);
			ExQueueWorkItem(&mnt->wrk_item, DelayedWorkQueue);
		} else {
			unmount_item_proc(mnt);
		}
	}
}


int dc_unmount_device(wchar_t *dev_name, int force)
{
	dev_hook *hook;
	int       resl;

	DbgMsg("dc_unmount_device %ws\n", dev_name);

	if (hook = dc_find_hook(dev_name)) 
	{
		if (IS_UNMOUNTABLE(hook)) {
			resl = dc_process_unmount(hook, force);
		} else {
			resl = ST_UNMOUNTABLE;
		}
		dc_deref_hook(hook);
	} else {
		resl = ST_NF_DEVICE;
	}

	return resl;
}

int dc_mount_all(dc_pass *password, u32 flags)
{
	dev_hook *hook;
	int       num = 0;

	if (hook = dc_first_hook()) 
	{
		do 
		{
			if (dc_mount_device(hook->dev_name, password, flags) == ST_OK) {
				num++;
			}
		} while (hook = dc_next_hook(hook));
	}

	return num;
}

int dc_num_mount()
{
	dev_hook *hook;
	int       num = 0;

	if (hook = dc_first_hook()) 
	{
		do 
		{
			num += (hook->flags & F_ENABLED);		
		} while (hook = dc_next_hook(hook));
	}

	return num;
}

static void mount_item_proc(mount_ctx *mnt)
{
	dev_hook *hook;
	int       resl;
		
	hook = mnt->hook;
	resl = dc_mount_device(hook->dev_name, NULL, 0);

	if ( (resl != ST_RW_ERR) && (resl != ST_MEDIA_CHANGED) && (resl != ST_NO_MEDIA) ) {
		hook->mnt_probed = 1;
	}

	if (resl != ST_OK)
	{
		if (lock_inc(&hook->mnt_probe_cnt) > MAX_MNT_PROBES) {
			hook->mnt_probed = 1;
		}
	}

	if (hook->flags & F_ENABLED) {
		io_read_write_irp(hook, mnt->irp);
	} else 
	{
		if (IS_DEVICE_BLOCKED(hook) != 0) {
			dc_release_irp(hook, mnt->irp, STATUS_ACCESS_DENIED);			
		} else {
			dc_forward_irp(hook, mnt->irp);	
		}
	}
	mm_pool_free(mnt);
}

NTSTATUS dc_probe_mount(dev_hook *hook, PIRP irp)
{
	mount_ctx *mnt;

	if ( (mnt = mm_pool_alloc(sizeof(mount_ctx))) == NULL ) {
		return dc_release_irp(hook, irp, STATUS_INSUFFICIENT_RESOURCES);
	}
	IoMarkIrpPending(irp);

	mnt->irp  = irp;
	mnt->hook = hook;
		
	ExInitializeWorkItem(&mnt->wrk_item, mount_item_proc, mnt);
	ExQueueWorkItem(&mnt->wrk_item, DelayedWorkQueue);

	return STATUS_PENDING;
}

void dc_init_mount()
{
	ExInitializeResourceLite(&p_resource);
	f_pass = NULL;
}

int dc_get_pending_encrypt(wchar_t* path, dc_pass **pass, crypt_info *crypt)
{
	OBJECT_ATTRIBUTES obj_a;
	UNICODE_STRING    u_name;	
	IO_STATUS_BLOCK   iosb;
	HANDLE            h_file;
	xts_key			 *hdr_key;
	dsk_pass		 *d_pass;	
	int				  resl, succs;
	dc_header		 *header = NULL;

	RtlInitUnicodeString(&u_name, path);
	InitializeObjectAttributes(&obj_a, &u_name, OBJ_KERNEL_HANDLE, NULL, NULL);

	if (NT_SUCCESS(ZwCreateFile(&h_file, GENERIC_READ, &obj_a, &iosb, NULL, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_READONLY, 0, 
		FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE | FILE_WRITE_THROUGH, NULL, 0)) == FALSE) {
		return ST_NF_FILE;
	}

	do
	{
		if ( (header = mm_secure_alloc(sizeof(dc_header))) == NULL ) {
			resl = ST_NOMEM; break;
		}
		if ( (hdr_key = mm_secure_alloc(sizeof(xts_key))) == NULL ) {
			resl = ST_NOMEM; break;
		}

		if (!NT_SUCCESS(ZwReadFile(h_file, NULL, NULL, NULL, &iosb, header, sizeof(dc_header), NULL, NULL))) {
			resl = ST_RW_ERR; break;
		}
		
		KeEnterCriticalRegion();
		ExAcquireResourceSharedLite(&p_resource, TRUE);

		for (d_pass = f_pass; d_pass; d_pass = d_pass->next)
		{
			if (succs = cp_decrypt_header(hdr_key, header, &d_pass->pass)) {
				break;
			}
		}

		if (succs) {
			if ( (*pass = mm_secure_alloc(sizeof(dc_pass))) == NULL ) {
				resl = ST_NOMEM;
			} else {
				memcpy(*pass, &d_pass->pass, sizeof(dc_pass));
				resl = ST_OK;
			}
		} else {
			resl = ST_PASS_ERR;
		}

		ExReleaseResourceLite(&p_resource);
		KeLeaveCriticalRegion();

		if (resl != ST_OK) break;
		
		crypt->cipher_id = header->alg_1;
		crypt->wp_mode = header->tmp_wp_mode;

		dc_delete_file(h_file);

	} while (0);

	if (header != NULL) {
		mm_secure_free(header);
	}
	if (hdr_key != NULL) {
		mm_secure_free(hdr_key);
	}
	ZwClose(h_file);

	return resl;
}