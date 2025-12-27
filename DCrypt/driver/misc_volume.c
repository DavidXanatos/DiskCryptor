/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2008-2010
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
#include <ntddvol.h>
#include "defines.h"
#include "devhook.h"
#include "misc_volume.h"
#include "misc.h"
#include "mount.h"
#include "prng.h"
#include "fast_crypt.h"
#include "debug.h"
#include "crypto_head.h"
#include "misc_mem.h"
#include "disk_info.h"
#include "device_io.h"
#include "header_io.h"
#include "crc32.h"

int dc_backup_header(wchar_t *dev_name, dc_pass *password, void *out)
{
	dc_header *header = NULL;
	xts_key   *hdr_key = NULL;
	dev_hook  *hook    = NULL;
	int        resl;
	s8         salt[PKCS5_SALT_SIZE];

	do
	{
		if ( (hook = dc_find_hook(dev_name)) == NULL ) {
			resl = ST_NF_DEVICE; break;
		}
		wait_object_infinity(&hook->busy_lock);

		if (hook->flags & (F_SYNC | F_UNSUPRT | F_DISABLE | F_CDROM)) {
			resl = ST_ERROR; break;
		}
		if ( (hdr_key = mm_secure_alloc(sizeof(xts_key))) == NULL ) {
			resl = ST_NOMEM; break;
		}
		/* get device params */
		if (hook->dsk_size == 0)
		{
			if ( !NT_SUCCESS(dc_fill_device_info(hook)) ) {
				resl = ST_IO_ERROR; break;
			}
		}
		if ( (resl = io_read_header(hook, &header, NULL, password)) != ST_OK ) {
			break;
		}
		/* generate new salt */
		cp_rand_bytes(header->salt, PKCS5_SALT_SIZE);
		/* save original salt */
		memcpy(salt, header->salt, PKCS5_SALT_SIZE);		
		/* init new header key */
		cp_set_header_key(hdr_key, header->salt, header->alg_1, password);		
		/* encrypt header with new key */
		xts_encrypt(pv(header), pv(header), sizeof(dc_header), 0, hdr_key);
		/* restore original salt */
		memcpy(header->salt, salt, PKCS5_SALT_SIZE);

		/* copy header to output */
		memcpy(out, header, sizeof(dc_header));
		resl = ST_OK;
	} while (0);

	if (hook != NULL) {
		KeReleaseMutex(&hook->busy_lock, FALSE);
		dc_deref_hook(hook);
	}
	/* prevent leaks */
	burn(salt, sizeof(salt));
	/* free memory */	
	if (header != NULL) mm_secure_free(header);
	if (hdr_key != NULL) mm_secure_free(hdr_key);
	return resl;
}

int dc_restore_header(wchar_t *dev_name, dc_pass *password, void *in)
{
	dc_header *header = NULL;
	xts_key   *hdr_key = NULL;
	dev_hook  *hook = NULL;
	int        resl;

	do
	{
		if ( (hook = dc_find_hook(dev_name)) == NULL ) {
			resl = ST_NF_DEVICE; break;
		}
		wait_object_infinity(&hook->busy_lock);

		if (hook->flags & (F_ENABLED | F_CDROM)) {
			resl = ST_ERROR; break;
		}
		/* get device params */
		if (hook->dsk_size == 0)
		{
			if ( !NT_SUCCESS(dc_fill_device_info(hook)) ) {
				resl = ST_IO_ERROR; break;
			}
		}
		if ( (header = mm_secure_alloc(sizeof(dc_header))) == NULL ) {
			resl = ST_NOMEM; break;
		}
		/* copy header from input */
		memcpy(header, in, sizeof(dc_header));

		if ( (hdr_key = mm_secure_alloc(sizeof(xts_key))) == NULL ) {
			resl = ST_NOMEM; break;
		}
		/* decrypt header */
		if (cp_decrypt_header(hdr_key, header, password) == 0) {
			resl = ST_PASS_ERR; break;
		}
		/* write new volume header */
		resl = io_write_header(hook, header, NULL, password);
	} while (0);

	if (hook != NULL) {
		KeReleaseMutex(&hook->busy_lock, FALSE);
		dc_deref_hook(hook);
	}
	if (hdr_key != NULL) mm_secure_free(hdr_key);
	if (header != NULL) mm_secure_free(header);

	return resl;
}

int dc_format_start(wchar_t *dev_name, dc_pass *password, crypt_info *crypt)
{
	IO_STATUS_BLOCK iosb;
	NTSTATUS        status;
	dc_header      *header  = NULL;
	dev_hook       *hook    = NULL;
	xts_key        *tmp_key = NULL;
	HANDLE          h_dev   = NULL;
	u8             *buff    = NULL;
	int             w_init  = 0;
	u8              key_buf[32];
	int             resl;

	DbgMsg("dc_format_start\n");

	do
	{
		if ( (hook = dc_find_hook(dev_name)) == NULL ) {
			resl = ST_NF_DEVICE; break;
		}

		wait_object_infinity(&hook->busy_lock);

		if (hook->flags & (F_ENABLED | F_UNSUPRT | F_DISABLE | F_CDROM)) {
			resl = ST_ERROR; break;
		}

		/* verify encryption info */
		if ( (crypt->cipher_id >= CF_CIPHERS_NUM) || (crypt->wp_mode >= WP_NUM) ) {
			resl = ST_ERROR; break;
		}

		/* get device params */
		if ( !NT_SUCCESS(dc_fill_device_info(hook)) ) {
			resl = ST_IO_ERROR; break;
		}

		if ( (header = mm_secure_alloc(sizeof(dc_header))) == NULL ) {
			resl = ST_NOMEM; break;
		}
		if ( (buff = mm_pool_alloc(ENC_BLOCK_SIZE)) == NULL ) {
			resl = ST_NOMEM; break;
		}
		if ( (tmp_key = mm_secure_alloc(sizeof(xts_key))) == NULL ) {
			resl = ST_NOMEM; break;
		}		

		/* temporarily disable automounting */
		hook->flags |= F_NO_AUTO_MOUNT;

		/* open volume device */
		if ( (h_dev = io_open_device(hook->dev_name)) == NULL ) {
			resl = ST_LOCK_ERR; break; 
		}		
		/* lock volume */
		status = ZwFsControlFile(
			h_dev, NULL, NULL, NULL, &iosb, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0);

		if (NT_SUCCESS(status) == FALSE) {
			resl = ST_LOCK_ERR; break; 
		}

		/* enable automounting */
		hook->flags &= ~F_NO_AUTO_MOUNT;
		/* set encryption info */
		hook->crypt = *crypt;

		/* init data wiping */
		resl = dc_wipe_init(
			&hook->wp_ctx, hook, ENC_BLOCK_SIZE, crypt->wp_mode, crypt->cipher_id);

		if (resl == ST_OK) {
			w_init = 1;			
		} else break;

		/* wipe first sectors */
		dc_wipe_process(&hook->wp_ctx, 0, hook->head_len);

		/* create random temporary key */
		cp_rand_bytes(key_buf, sizeof(key_buf));

		xts_set_key(key_buf, crypt->cipher_id, tmp_key);

		/* create volume header */
		memset(header, 0, sizeof(dc_header));

		cp_rand_bytes(pv(header->salt),     PKCS5_SALT_SIZE);
		cp_rand_bytes(pv(&header->disk_id), sizeof(u32));
		cp_rand_bytes(pv(header->key_1),    DISKKEY_SIZE);

		header->sign    = DC_VOLUME_SIGN;
		header->version = DC_HDR_VERSION;
		header->alg_1   = crypt->cipher_id;
		header->hdr_crc = crc32((const unsigned char*)&header->version, DC_CRC_AREA_SIZE);

		/* write volume header */
		if ( (resl = io_write_header(hook, header, NULL, password)) != ST_OK ) {
			break;
		}
		/* mount device */
		if ( (resl = dc_mount_device(dev_name, password, 0)) != ST_OK ) {
			break;
		}		
		/* set hook fields */
		hook->flags    |= F_FORMATTING;
		hook->tmp_size  = hook->head_len;
		hook->tmp_buff  = buff;
		hook->tmp_key   = tmp_key;
	} while (0);

	if (resl != ST_OK)
	{
		if (w_init != 0) {
			dc_wipe_free(&hook->wp_ctx);
		}

		if (buff != NULL)
		{
			if (hook != NULL && hook->tmp_buff == buff) hook->tmp_buff = NULL;
			mm_pool_free(buff);
		}
		if (tmp_key != NULL)
		{
			if (hook != NULL && hook->tmp_key == tmp_key) hook->tmp_key = NULL;
			mm_secure_free(tmp_key);
		}
	}
	if (header != NULL) {
		mm_secure_free(header);
	}
	if (hook != NULL) { 
		KeReleaseMutex(&hook->busy_lock, FALSE);
		dc_deref_hook(hook);
	}
	/* prevent leaks */
	burn(key_buf, sizeof(key_buf));
	
	if (h_dev != NULL)
	{
		if (resl != ST_LOCK_ERR)
		{
			/* dismount volume */
			ZwFsControlFile(
				h_dev, NULL, NULL, NULL, &iosb, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0);

			/* unlock volume */
			ZwFsControlFile(
				h_dev, NULL, NULL, NULL, &iosb, FSCTL_UNLOCK_VOLUME, NULL, 0, NULL, 0);
		}
		/* close device */
		ZwClose(h_dev);
	}		

	return resl;
}

int dc_format_step(wchar_t *dev_name, int wp_mode)
{
	dev_hook *hook = NULL;
	u8       *buff;
	int       resl;
	u64       offs;
	u32       size;

	do
	{
		if ( (hook = dc_find_hook(dev_name)) == NULL ) {
			resl = ST_NF_DEVICE; break;
		}

		wait_object_infinity(&hook->busy_lock);

		if ( !(hook->flags & F_FORMATTING) ) {
			resl = ST_ERROR; break;
		}

		offs = hook->tmp_size;
		buff = hook->tmp_buff;
		size = d32(min(hook->dsk_size - offs, ENC_BLOCK_SIZE));

		if (size == 0) {
			dc_format_done(dev_name);
			resl = ST_FINISHED; break;
		}

		if (hook->crypt.wp_mode != wp_mode)
		{
			dc_wipe_free(&hook->wp_ctx);

			resl = dc_wipe_init(
				&hook->wp_ctx, hook, ENC_BLOCK_SIZE, wp_mode, hook->crypt.cipher_id);

			if (resl == ST_OK) {
				hook->crypt.wp_mode = d8(wp_mode);
			} else {
				dc_wipe_init(&hook->wp_ctx, hook, ENC_BLOCK_SIZE, WP_NONE, 0);
				hook->crypt.wp_mode = WP_NONE;
			}
		}

		/* wipe sectors */
		dc_wipe_process(&hook->wp_ctx, offs, size);

		/* zero buffer */
		memset(buff, 0, size);
		/* encrypt buffer with temporary key */
		cp_fast_encrypt(buff, buff, size, offs, hook->tmp_key);

		/* write pseudo-random data to device */
		resl = io_hook_rw(hook, buff, size, offs, 0);

		if ( (resl == ST_OK) || (resl == ST_RW_ERR) ) {
			hook->tmp_size += size;
		}
		if ( (resl == ST_MEDIA_CHANGED) || (resl == ST_NO_MEDIA) ) {			
			dc_process_unmount(hook, MF_NOFSCTL); resl = ST_FINISHED;
		}
	} while (0);

	if (hook != NULL) {
		KeReleaseMutex(&hook->busy_lock, FALSE);
		dc_deref_hook(hook);
	}
	return resl;
}

int dc_format_done(wchar_t *dev_name)
{
	dev_hook *hook = NULL;
	int       resl;

	DbgMsg("dc_format_done\n");

	do
	{
		if ( (hook = dc_find_hook(dev_name)) == NULL ) {
			resl = ST_NF_DEVICE; break;
		}
		wait_object_infinity(&hook->busy_lock);

		if ( !(hook->flags & F_FORMATTING) ) {
			resl = ST_ERROR; break;
		}
		/* set hook fields */
		hook->tmp_size = 0;
		hook->flags   &= ~F_FORMATTING;		
		
		// free resources
		dc_wipe_free(&hook->wp_ctx);
		
		if (hook->tmp_buff != NULL) {
			mm_pool_free(hook->tmp_buff);
			hook->tmp_buff = NULL;
		}
		
		if (hook->tmp_key != NULL) {
			mm_secure_free(hook->tmp_key);
			hook->tmp_key = NULL;
		}

		resl = ST_OK;
	} while (0);

	if (hook != NULL) {
		KeReleaseMutex(&hook->busy_lock, FALSE);
		dc_deref_hook(hook);
	}
	return resl;
}

int dc_change_pass(wchar_t *dev_name, dc_pass *old_pass, dc_pass *new_pass)
{
	dc_header *header = NULL;
	dev_hook  *hook   = NULL;
	int        wp_init = 0;
	int        resl;
	wipe_ctx   wipe;	
	
	do
	{
		if ( (hook = dc_find_hook(dev_name)) == NULL ) {
			resl = ST_NF_DEVICE; break;
		}
		wait_object_infinity(&hook->busy_lock);

		if ( !(hook->flags & F_ENABLED) ) {
			resl = ST_NO_MOUNT; break;
		}
		if (hook->flags & (F_SYNC | F_FORMATTING | F_CDROM)) {
			resl = ST_ERROR; break;
		}
		/* read old volume header */
		if ( (resl = io_read_header(hook, &header, NULL, old_pass)) != ST_OK ) {
			break;
		}
		/* init data wipe */
		if ( (resl = dc_wipe_init(
			&wipe, hook, hook->head_len, WP_GUTMANN, hook->crypt.cipher_id)) == ST_OK )
		{
			wp_init = 1;
		} else break;

		/* wipe volume header */
		dc_wipe_process(&wipe, 0, hook->head_len);		
		/* write new volume header */
		resl = io_write_header(hook, header, NULL, new_pass);
	} while (0);

	if (wp_init != 0) {
		dc_wipe_free(&wipe);
	}
	if (hook != NULL) {
		KeReleaseMutex(&hook->busy_lock, FALSE);
		dc_deref_hook(hook);
	}	
	if (header != NULL) mm_secure_free(header);
	return resl;
}

NTSTATUS dc_update_volume(dev_hook *hook)
{
	LARGE_INTEGER timeout = { 0xffe17b80, 0xffffffff }; // 200ms timeout
	ULONGLONG     old_len = hook->dsk_size;
	PVOID         pb_buff = NULL;
	NTSTATUS      status;

	if (KeWaitForSingleObject(&hook->busy_lock, Executive, KernelMode, FALSE, &timeout) == STATUS_TIMEOUT)
	{
		return STATUS_DEVICE_NOT_READY;
	}
	if (hook->dsk_size != old_len || hook->pnp_state != Started || (hook->flags & F_DISABLE))
	{
		status = STATUS_INVALID_DEVICE_STATE;
		goto cleanup;
	}

	if (IS_STORAGE_ON_END(hook->flags) != 0)
	{
		if ( (pb_buff = mm_secure_alloc(max(hook->head_len, PAGE_SIZE))) == NULL )
		{
			status = STATUS_INSUFFICIENT_RESOURCES;
			goto cleanup;
		}
		if ( !NT_SUCCESS(status = io_device_request(hook->hook_dev, IRP_MJ_READ, pb_buff, hook->head_len, 0)) ) goto cleanup;
	}

	if ( !NT_SUCCESS(status = io_device_control(hook->orig_dev, IOCTL_VOLUME_UPDATE_PROPERTIES, NULL, 0, NULL, 0)) ) goto cleanup;
	if ( !NT_SUCCESS(status = dc_fill_device_info(hook)) || hook->dsk_size == old_len )  goto cleanup;
	hook->use_size += hook->dsk_size - old_len;

	if (pb_buff != NULL) {
		hook->stor_off = hook->dsk_size - hook->head_len;
		status = io_device_request(hook->hook_dev, IRP_MJ_WRITE, pb_buff, hook->head_len, 0);
	}

cleanup:
	if (pb_buff != NULL) mm_secure_free(pb_buff);
	KeReleaseMutex(&hook->busy_lock, FALSE);
	return status;
}