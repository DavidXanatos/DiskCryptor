/*
    *
    * DiskCryptor - open source partition encryption tool
	* Copyright (c) 2019-2023
	* DavidXanatos <info@diskcryptor.org>
    * Copyright (c) 2007-2010
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
#include "prng.h"
#include "misc.h"
#include "readwrite.h"
#include "mount.h"
#include "enc_dec.h"
#include "data_wipe.h"
#include "misc_irp.h"
#include "fast_crypt.h"
#include "misc_volume.h"
#include "debug.h"
#include "storage.h"
#include "crypto_head.h"
#include "misc_mem.h"
#include "ssd_trim.h"
#include "disk_info.h"
#include "device_io.h"
#include "header_io.h"
#include "crc32.h"

typedef struct _sync_struct {
	KEVENT sync_event;
	int    status;

} sync_struct;

typedef struct _sync_context {
	int finish;
	int saved;
	int winit;

} sync_context;

/* function types declaration */
KSTART_ROUTINE dc_sync_op_routine;

static int dc_enc_update(dev_hook *hook)
{
	u8 *buff = hook->tmp_buff;
	u64 offs = hook->tmp_size;
	u32 size = d32(min(hook->dsk_size - offs, ENC_BLOCK_SIZE));
	int r_resl, w_resl;

	if (size == 0) {
		return ST_FINISHED;
	}

	do
	{
		r_resl = io_hook_rw_skip_bads(hook, buff, size, offs, 1);

		if ( (r_resl != ST_OK) && (r_resl != ST_RW_ERR) ) {
			break;
		}		
		cp_fast_encrypt(buff, buff, size, offs, hook->dsk_key);

		dc_wipe_process(&hook->wp_ctx, offs, size);

		w_resl = io_hook_rw_skip_bads(hook, buff, size, offs, 0);

		if (w_resl == ST_RW_ERR) {
			r_resl = w_resl;
		}
	} while (0);

	if ( (r_resl == ST_OK) || (r_resl == ST_RW_ERR) ) {
		hook->tmp_size += size;
	}	
	return r_resl;
}

static int dc_re_enc_update(dev_hook *hook)
{
	u8 *buff = hook->tmp_buff;
	u64 offs = hook->tmp_size;
	u32 size = d32(min(hook->dsk_size - offs, ENC_BLOCK_SIZE));	
	int r_resl, w_resl;
	
	if (size == 0) {
		return ST_FINISHED;
	}

	do
	{
		r_resl = io_hook_rw_skip_bads(hook, buff, size, offs, 1);

		if ( (r_resl != ST_OK) && (r_resl != ST_RW_ERR) ) {
			break;
		}

		/* wipe old data */
		dc_wipe_process(&hook->wp_ctx, offs, size);

		/* re-encrypt data */
		cp_fast_decrypt(buff, buff, size, offs, hook->tmp_key);
		cp_fast_encrypt(buff, buff, size, offs, hook->dsk_key);

		w_resl = io_hook_rw_skip_bads(hook, buff, size, offs, 0);

		if (w_resl == ST_RW_ERR) {
			r_resl = w_resl;
		}
	} while (0);

	if ( (r_resl == ST_OK) || (r_resl == ST_RW_ERR) ) {
		hook->tmp_size += size;
	}
	return r_resl;
}


static int dc_dec_update(dev_hook *hook)
{
	u8 *buff = hook->tmp_buff;
	u32 size = d32(min(hook->tmp_size, ENC_BLOCK_SIZE));
	u64 offs = hook->tmp_size - size;
	int r_resl, w_resl;
	
	if (size == 0)
	{
		/* write redirected part back to zero offset */
		w_resl = io_hook_rw(hook, buff, hook->head_len, hook->stor_off, 1);
		
		if (w_resl == ST_OK) {
			w_resl = io_hook_rw(hook, buff, hook->head_len, 0, 0);
		}
		if (w_resl == ST_OK) {
			w_resl = ST_FINISHED;
		}
		return w_resl;
	}

	do
	{
		r_resl = io_hook_rw_skip_bads(hook, buff, size, offs, 1);
		
		if ( (r_resl != ST_OK) && (r_resl != ST_RW_ERR) ) {
			break;
		}
		cp_fast_decrypt(buff, buff, size, offs, hook->dsk_key);

		w_resl = io_hook_rw_skip_bads(hook, buff, size, offs, 0);

		if (w_resl == ST_RW_ERR) {
			r_resl = w_resl;
		}
	} while (0);

	if ( (r_resl == ST_OK) || (r_resl == ST_RW_ERR) ) {
		hook->tmp_size -= size;
	}
	return r_resl;
}

static void dc_save_enc_state(dev_hook *hook, int finish)
{
	int i;

	DbgMsg("dc_save_enc_state\n");

	// check header for memory corruption, bugcheck if header invalid
	// and check encryption key for zeroed
	if (is_volume_header_correct(&hook->tmp_header) == FALSE || hook->hdr_key == NULL || hook->hdr_key->encrypt == NULL)
	{
		KeBugCheckEx(STATUS_DISK_CORRUPT_ERROR, __LINE__, 0, 0, 0);
	}

	if (finish != 0)
	{
		hook->tmp_header.flags &= ~(VF_TMP_MODE | VF_REENCRYPT);
		hook->tmp_header.tmp_size = 0;
		hook->tmp_header.tmp_wp_mode = 0;

		// reencryption finished, zero previous encryption key
		if (hook->tmp_header.flags & F_REENCRYPT) {
			RtlSecureZeroMemory(hook->tmp_header.key_2, sizeof(hook->tmp_header.key_2)); 
			hook->tmp_header.alg_2 = 0;
		}
	} else 
	{
		hook->tmp_header.flags   |= VF_TMP_MODE;
		hook->tmp_header.tmp_size = hook->tmp_size;
		hook->tmp_header.tmp_wp_mode = hook->crypt.wp_mode;

		if (hook->flags & F_REENCRYPT) {
			hook->tmp_header.flags |= VF_REENCRYPT;
		} 
	}
	// update header checksumm
	hook->tmp_header.hdr_crc = crc32((const unsigned char*)&hook->tmp_header.version, DC_CRC_AREA_SIZE);

	// write new header to disk (retry 10 times on error)
	for (i = 0; i < 10; i++) {
		if (io_write_header(hook, &hook->tmp_header, hook->hdr_key, NULL) == ST_OK) break;
		dc_delay(100);
	}

	// flush disk cache
	io_device_request(hook->orig_dev, IRP_MJ_FLUSH_BUFFERS, NULL, 0, 0);
}


static int dc_init_sync_mode(dev_hook *hook, sync_context *ctx)
{
	u8      *buff = hook->tmp_buff;
	int      resl;
	
	do
	{
		switch (lock_xchg(&hook->sync_init_type, 0))
		{
			case S_INIT_ENC:
				{
					/* initialize encryption process */
					
					/* save old sectors */
					resl = io_hook_rw(hook, buff, hook->head_len, 0, 1);
					if (resl != ST_OK) break;

					resl = io_hook_rw(hook, buff, hook->head_len, hook->stor_off, 0);
					if (resl != ST_OK) break;
										
					/* wipe old sectors */
					dc_wipe_process(&hook->wp_ctx, 0, hook->head_len);
					/* save initial state */
					dc_save_enc_state(hook, 0);
				}
			break;
			case S_INIT_DEC:
			case S_CONTINUE_ENC: 
				{
					resl = ST_OK;
				}
			break;
			case S_INIT_RE_ENC:
				{
					DbgMsg("S_INIT_RE_ENC\n");

					// swap keys
					{
						xts_key* tmp = hook->dsk_key;
						hook->dsk_key = hook->tmp_key;
						hook->tmp_key = tmp;
					}

					/* set re-encryption flag */
					hook->flags |= F_REENCRYPT;
					/* wipe old volume header */
					dc_wipe_process(&hook->wp_ctx, 0, hook->head_len);
					/* save initial state */
					dc_save_enc_state(hook, 0);

					resl = ST_OK;
				}
			break;
			case S_CONTINUE_RE_ENC:
				{
					DbgMsg("S_CONTINUE_RE_ENC\n");

					if ( (hook->tmp_key = (xts_key*)mm_secure_alloc(sizeof(xts_key))) == NULL )
					{
						resl = ST_NOMEM; break;
					}

					/* initialize secondary volume key */
					xts_set_key(hook->tmp_header.key_2, hook->tmp_header.alg_2, hook->tmp_key);

					/* set re-encryption flag */
					hook->flags |= F_REENCRYPT; resl = ST_OK;
				}
			break;
		}
	} while (0);

	return resl;
}

static int dc_process_sync_packet(dev_hook *hook, sync_packet *packet, sync_context *ctx)
{
	int new_wp = (int)(packet->param);
	int resl;

	switch (packet->type)
	{
		case S_OP_ENC_BLOCK:
			{
				if (ctx->finish == 0)
				{
					if ( (new_wp != hook->crypt.wp_mode) && (new_wp < WP_NUM) )
					{
						dc_wipe_free(&hook->wp_ctx);

						resl = dc_wipe_init(
							&hook->wp_ctx, hook, ENC_BLOCK_SIZE, new_wp, hook->crypt.cipher_id);

						if (resl == ST_OK) 
						{
							hook->crypt.wp_mode = d8(new_wp);
							dc_save_enc_state(hook, 0);
						} else {
							dc_wipe_init(&hook->wp_ctx, hook, ENC_BLOCK_SIZE, WP_NONE, 0);
						}
					}

					if (hook->flags & F_REENCRYPT) {
						resl = dc_re_enc_update(hook);
					} else {
						resl = dc_enc_update(hook);
					}

					if (resl == ST_FINISHED) {
						dc_save_enc_state(hook, 1); ctx->finish = 1;
					} else ctx->saved = 0;
				} else {
					resl = ST_FINISHED;
				}
			}
		break;
		case S_OP_DEC_BLOCK:
			{
				if (hook->flags & F_REENCRYPT) {
					resl = ST_ERROR; break;
				}

				if (ctx->finish == 0)
				{
					if ( (resl = dc_dec_update(hook)) == ST_FINISHED) {
						dc_process_unmount(hook, MF_NOFSCTL | MF_NOSYNC);
						ctx->finish = 1;
					} else ctx->saved = 0;
				} else {
					resl = ST_FINISHED;
				}
			}
		break;
		case S_OP_SYNC:
			{
				if ( (ctx->finish == 0) && (ctx->saved == 0) ) {
					dc_save_enc_state(hook, 0); ctx->saved = 1;
				}
				resl = ST_OK;
			}
		break;
		case S_OP_FINALIZE:
			{
				if ( (ctx->finish == 0) && (ctx->saved == 0) ) {
					dc_save_enc_state(hook, 0); ctx->finish = 1;
				}
				resl = ST_FINISHED;						
			}
		break;
	}

	return resl;
}

static void dc_sync_op_routine(dev_hook *hook)
{
	sync_packet *packet;
	PLIST_ENTRY  entry;
	u8          *buff;
	sync_context sctx;
	int          resl, init_t;
	int          del_storage;
	
	DbgMsg("sync thread started\n");

	dc_reference_hook(hook);

	/* initialize sync mode data */
	InitializeListHead(&hook->sync_req_queue);
	InitializeListHead(&hook->sync_irp_queue);
	KeInitializeSpinLock(&hook->sync_req_lock);

	KeInitializeEvent(
		&hook->sync_req_event, SynchronizationEvent, FALSE);

	/* enable synchronous irp processing */
	hook->flags |= (F_ENABLED | F_SYNC);
	
	memset(&sctx, 0, sizeof(sctx));
	init_t = hook->sync_init_type;
	del_storage = 0;

	/* allocate resources */
	if (buff = mm_pool_alloc(ENC_BLOCK_SIZE))
	{
		hook->tmp_buff = buff;

		resl = dc_wipe_init(
			&hook->wp_ctx, hook, ENC_BLOCK_SIZE, hook->crypt.wp_mode, hook->crypt.cipher_id);

		if (resl == ST_OK) 
		{
			sctx.winit = 1;
			/* init sync mode */
			resl = dc_init_sync_mode(hook, &sctx);
		}			 
	} else {
		resl = ST_NOMEM;
	}
	DbgMsg("sync mode initialized\n");
	/* save init status */
	hook->sync_init_status = resl;

	if (resl == ST_OK) 
	{
		/* signal of init finished */
		KeSetEvent(
			&hook->sync_enter_event, IO_NO_INCREMENT, FALSE);		
	} else 
	{
		if ( (init_t == S_INIT_ENC) || (init_t == S_CONTINUE_ENC) || (init_t == S_CONTINUE_RE_ENC) ) {
			hook->flags &= ~(F_ENABLED | F_SYNC | F_REENCRYPT | F_PROTECT_DCSYS);
		} else {
			hook->flags &= ~F_SYNC;
		}
		goto cleanup;
	}

	do
	{
		wait_object_infinity(&hook->sync_req_event);

		do
		{
			if (hook->flags & F_SYNC)
			{
				while (entry = ExInterlockedRemoveHeadList(&hook->sync_irp_queue, &hook->sync_req_lock))
				{
					io_encrypted_irp_io(hook, CONTAINING_RECORD(entry, IRP, Tail.Overlay.ListEntry), TRUE);
				}
			}
			if (entry = ExInterlockedRemoveHeadList(&hook->sync_req_queue, &hook->sync_req_lock))
			{
				packet = CONTAINING_RECORD(entry, sync_packet, entry_list);

				/* process packet */
				resl = dc_process_sync_packet(hook, packet, &sctx);

				/* prevent system power state changes */
				PoSetSystemState(ES_SYSTEM_REQUIRED);

				/* disable synchronous irp processing */
				if (resl == ST_FINISHED) 
				{
					del_storage  = !(hook->flags & F_ENABLED) && 
						            (hook->tmp_header.flags & VF_STORAGE_FILE);
					hook->flags &= ~(F_SYNC | F_REENCRYPT);		

					if ( (dc_conf_flags & CONF_DISABLE_TRIM) == 0 &&
						 (packet->type == S_OP_ENC_BLOCK || packet->type == S_OP_DEC_BLOCK) )
					{
						dc_trim_free_space(hook);
					}
				}

				/* signal of packet completion */
				packet->status = resl;
				
				KeSetEvent(&packet->sync_event, IO_NO_INCREMENT, FALSE);

				if ( (resl == ST_MEDIA_CHANGED) || (resl == ST_NO_MEDIA) ) {
					dc_process_unmount(hook, MF_NOFSCTL | MF_NOSYNC);
					resl = ST_FINISHED; sctx.finish = 1;
				}
			}
		} while (entry != NULL);
	} while (hook->flags & F_SYNC);
cleanup:;

	/* pass all IRPs to default routine */
	while (entry = ExInterlockedRemoveHeadList(&hook->sync_irp_queue, &hook->sync_req_lock)) {
		io_read_write_irp(hook, CONTAINING_RECORD(entry, IRP, Tail.Overlay.ListEntry));
	}

	// free resources and prevent leaks
	if (sctx.winit != 0) dc_wipe_free(&hook->wp_ctx);
	if (buff != NULL) mm_pool_free(buff);

	if (hook->hdr_key != NULL) {
		mm_secure_free(hook->hdr_key);
		hook->hdr_key = NULL;
	}
	if (hook->tmp_key != NULL) {
		mm_secure_free(hook->tmp_key);
		hook->tmp_key = NULL;
	}
	RtlSecureZeroMemory(&hook->tmp_header, sizeof(hook->tmp_header));

	/* report init finished if initialization fails */
	if (resl != ST_FINISHED) {
		KeSetEvent(&hook->sync_enter_event, IO_NO_INCREMENT, FALSE);	
	}

	if (del_storage != 0) {
		dc_delete_storage(hook);
	}

	dc_deref_hook(hook);

	DbgMsg("exit from sync thread\n");

	PsTerminateSystemThread(STATUS_SUCCESS);
}

int dc_enable_sync_mode(dev_hook *hook)
{
	int resl;

	do
	{
		if (hook->flags & F_SYNC) {
			resl = ST_ERROR; break;
		}

		KeInitializeEvent(
			&hook->sync_enter_event, NotificationEvent, FALSE);		

		resl = start_system_thread(dc_sync_op_routine, hook, NULL);

		if (resl == ST_OK) {
			wait_object_infinity(&hook->sync_enter_event);
			resl = hook->sync_init_status;						
		}
	} while (0);

	return resl;
}

int dc_send_sync_packet(wchar_t *dev_name, u32 type, void *param)
{
	dev_hook    *hook;
	sync_packet *packet;
	int          mutex = 0;
	int          resl;	

	do
	{
		if ( (hook = dc_find_hook(dev_name)) == NULL ) {
			resl = ST_NF_DEVICE; break;
		}

		wait_object_infinity(&hook->busy_lock);

		if ( !(hook->flags & F_SYNC) ) {			
			resl = ST_ERROR; break;
		}

		if ( (hook->flags & F_PREVENT_ENC) && 
			 ((type == S_OP_ENC_BLOCK) || (type == S_OP_DEC_BLOCK)) )
		{
			resl = ST_CANCEL; break;
		}

		if ( (packet = mm_pool_alloc(sizeof(sync_packet))) == NULL ) {
			resl = ST_NOMEM; break;
		}

		KeInitializeEvent(
			&packet->sync_event, NotificationEvent, FALSE);

		packet->type  = type;
		packet->param = param;		

		ExInterlockedInsertTailList(
			&hook->sync_req_queue, &packet->entry_list, &hook->sync_req_lock);

		KeSetEvent(
			&hook->sync_req_event, IO_NO_INCREMENT, FALSE);

		KeReleaseMutex(&hook->busy_lock, FALSE);

		wait_object_infinity(&packet->sync_event);

		resl = packet->status; mutex = 1;
		mm_pool_free(packet);
	} while (0);

	if (hook != NULL) 
	{		
		if (mutex == 0) {
			KeReleaseMutex(&hook->busy_lock, FALSE);
		}
		dc_deref_hook(hook);
	}
	return resl;
}

void dc_sync_all_encs()
{
	dev_hook *hook;

	if (hook = dc_first_hook())
	{
		do
		{
			dc_send_sync_packet(hook->dev_name, S_OP_SYNC, 0);
		} while (hook = dc_next_hook(hook));
	}
}

int dc_encrypt_start(wchar_t *dev_name, dc_pass *password, crypt_info *crypt, BOOLEAN confirmed)
{
	dc_header *header;
	dev_hook  *hook;
	xts_key   *hdr_key;
	int        resl;
	u64        storage;
				
	DbgMsg("dc_encrypt_start\n");

	header = NULL; hdr_key = NULL;
	do
	{
		if ( (hook = dc_find_hook(dev_name)) == NULL ) {
			resl = ST_NF_DEVICE; break;
		}

		wait_object_infinity(&hook->busy_lock);
		
		if (hook->flags & (F_ENABLED | F_UNSUPRT | F_DISABLE | F_CDROM)) {
			resl = ST_ERROR; break;
		}

		/* safety check */
		if (!confirmed && (hook->flags & F_SYSTEM) && (dc_load_flags & DST_UEFI_BOOT) && !(dc_load_flags & DST_BOOTLOADER)) {
			resl = ST_BL_NOT_PASSED; break;
		}

		/* verify encryption info */
		if ( (crypt->cipher_id >= CF_CIPHERS_NUM) || (crypt->wp_mode >= WP_NUM) ) {
			resl = ST_ERROR; break;
		}

		/* get device params */
		if ( !NT_SUCCESS(dc_fill_device_info(hook)) ) {
			resl = ST_IO_ERROR; break;
		}
		
		/* create redirection storage */
		if ( (resl = dc_create_storage(hook, &storage)) != ST_OK ) {
			break;
		}
		DbgMsg("storage created\n");

		if ( (header = (dc_header*)mm_secure_alloc(sizeof(dc_header))) == NULL ||
			 (hdr_key = (xts_key*)mm_secure_alloc(sizeof(xts_key))) == NULL ||
			 (hook->dsk_key = (xts_key*)mm_secure_alloc(sizeof(xts_key))) == NULL )
		{
			resl = ST_NOMEM; break;
		}

		/* create volume header */
		memset(header, 0, sizeof(dc_header));

		cp_rand_bytes(pv(header->salt),     PKCS5_SALT_SIZE);
		cp_rand_bytes(pv(&header->disk_id), sizeof(u32));
		cp_rand_bytes(pv(header->key_1),    DISKKEY_SIZE);

		header->sign     = DC_VOLUME_SIGN;
		header->version  = DC_HDR_VERSION;
		header->flags    = VF_TMP_MODE | VF_STORAGE_FILE;
		header->alg_1    = crypt->cipher_id;
		header->stor_off = storage;
		header->hdr_crc  = crc32((const unsigned char*)&header->version, DC_CRC_AREA_SIZE);

		// initialize volume key
		xts_set_key(header->key_1, crypt->cipher_id, hook->dsk_key);
		
		// initialize header key
		cp_set_header_key(hdr_key, header->salt, crypt->cipher_id, password);
		
		hook->crypt          = crypt[0];
		hook->use_size       = hook->dsk_size;
		hook->tmp_size       = hook->head_len;
		hook->stor_off       = storage;
		hook->vf_version     = DC_HDR_VERSION;
		hook->sync_init_type = S_INIT_ENC;
		hook->hdr_key        = hdr_key;
		hook->disk_id        = header->disk_id;
		hook->flags         |= F_PROTECT_DCSYS;

		/* copy header to temp buffer */
		memcpy(&hook->tmp_header, header, sizeof(dc_header));	
		
		if ( (resl = dc_enable_sync_mode(hook)) != ST_OK ) 
		{
			DbgMsg("sync init error\n");
			burn(&hook->tmp_header, sizeof(dc_header));	
			hdr_key = hook->hdr_key;
		} else {
			hdr_key = NULL;
		}
	} while (0);

	if (hdr_key != NULL) mm_secure_free(hdr_key);
	if (header != NULL)  mm_secure_free(header);

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

int dc_reencrypt_start(wchar_t *dev_name, dc_pass *password, crypt_info *crypt)
{
	dc_header *header = NULL;
	crypt_info o_crypt;
	dev_hook  *hook;
	xts_key   *hdr_key = NULL;
	xts_key   *dsk_key = NULL;
	int        resl;

	DbgMsg("dc_reencrypt_start\n");

	do
	{
		if ( (hook = dc_find_hook(dev_name)) == NULL ) {
			resl = ST_NF_DEVICE; break;
		}

		wait_object_infinity(&hook->busy_lock);

		if ( !(hook->flags & F_ENABLED) || 
			  (hook->flags & (F_SYNC | F_FORMATTING | F_CDROM)) ) 
		{
			resl = ST_ERROR; break;
		}

		/* verify encryption info */
		if ( (crypt->cipher_id >= CF_CIPHERS_NUM) || (crypt->wp_mode >= WP_NUM) ) {
			resl = ST_ERROR; break;
		}

		/* allocate new volume key */
		if ( (dsk_key = mm_secure_alloc(sizeof(xts_key))) == NULL ) {
			resl = ST_NOMEM; break;
		}
		/* allocate new header key */
		if ( (hdr_key = mm_secure_alloc(sizeof(xts_key))) == NULL ) {
			resl = ST_NOMEM; break;
		}
		/* read volume header */
		if ( (resl = io_read_header(hook, &header, NULL, password)) != ST_OK ) {
			break;
		}
		/* copy current volume key to secondary key */
		memcpy(header->key_2, header->key_1, DISKKEY_SIZE);

		/* generate new salt and volume key */
		cp_rand_bytes(header->salt,  PKCS5_SALT_SIZE);		
		cp_rand_bytes(header->key_1, DISKKEY_SIZE);

		/* change other fields */
		header->alg_2  = header->alg_1;
		header->alg_1  = crypt->cipher_id;
		header->flags |= VF_REENCRYPT;
		header->hdr_crc = crc32((const unsigned char*)&header->version, DC_CRC_AREA_SIZE);

		/* initialize new header key */
		cp_set_header_key(hdr_key, header->salt, header->alg_1, password);
		/* initialize new volume key */
		xts_set_key(header->key_1, header->alg_1, dsk_key);

		/* save old encryption info */
		o_crypt = hook->crypt;
		/* set new encryption info */		
		hook->crypt          = *crypt;
		hook->tmp_size       = 0;
		hook->sync_init_type = S_INIT_RE_ENC;
		hook->hdr_key        = hdr_key;
		hook->tmp_key        = dsk_key;
		
		/* copy header to temp buffer */
		memcpy(&hook->tmp_header, header, sizeof(dc_header));
		
		if ( (resl = dc_enable_sync_mode(hook)) != ST_OK ) 
		{
			burn(&hook->tmp_header, sizeof(dc_header));	
			hdr_key = hook->hdr_key;
			dsk_key = hook->tmp_key;
			/* restore encryption info */
			hook->crypt = o_crypt;
		} else {
			hdr_key = NULL;
			dsk_key = NULL;
		}
	} while (0);

	/* free resources */
	if (dsk_key != NULL) mm_secure_free(dsk_key);
	if (hdr_key != NULL) mm_secure_free(hdr_key);
	if (header != NULL)  mm_secure_free(header);

	if (hook != NULL) {
		KeReleaseMutex(&hook->busy_lock, FALSE);
		dc_deref_hook(hook);
	}
	return resl;
}

int dc_decrypt_start(wchar_t *dev_name, dc_pass *password)
{
	dc_header *header = NULL;
	dev_hook  *hook;
	xts_key   *hdr_key = NULL;
	int        resl;
				
	DbgMsg("dc_decrypt_start\n");

	do
	{
		if ( (hook = dc_find_hook(dev_name)) == NULL ) {
			resl = ST_NF_DEVICE; break;
		}

		wait_object_infinity(&hook->busy_lock);
		
		if ( !(hook->flags & F_ENABLED) || 
			  (hook->flags & (F_SYNC | F_FORMATTING | F_CDROM | F_NO_REDIRECT)) ) 
		{
			resl = ST_ERROR; break;
		}
		/* read volume header */
		if ( (resl = io_read_header(hook, &header, &hdr_key, password)) != ST_OK ) {
			break;
		}
		hook->crypt.cipher_id = d8(header->alg_1);
		hook->crypt.wp_mode   = WP_NONE;
		
		/* copy header to temp buffer */
		memcpy(&hook->tmp_header, header, sizeof(dc_header));

		hook->tmp_size       = hook->dsk_size;
		hook->sync_init_type = S_INIT_DEC;
		hook->hdr_key        = hdr_key;
		
		if ( (resl = dc_enable_sync_mode(hook)) != ST_OK ) 
		{
			burn(&hook->tmp_header, sizeof(dc_header));
			hdr_key = hook->hdr_key;
		} else {
			hdr_key = NULL;
		}
	} while (0);

	if (hdr_key != NULL) mm_secure_free(hdr_key);
	if (header != NULL)  mm_secure_free(header);

	if (hook != NULL) {
		KeReleaseMutex(&hook->busy_lock, FALSE);
		dc_deref_hook(hook);
	}
	return resl;
}
