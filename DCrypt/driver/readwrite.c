/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2007-2014
    * ntldr <ntldr@diskcryptor.net> PGP key ID - 0x1B6A24550F33E44A
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
#include "devhook.h"
#include "misc_irp.h"
#include "readwrite.h"
#include "mount.h"
#include "driver.h"
#include "fast_crypt.h"
#include "misc_mem.h"
#include "debug.h"

#define SSD_PAGE_SIZE				4096
#define SSD_ERASE_BLOCK_SIZE		(128 * 1024)

#define CHUNK_READ_THRESHOLD		(128 * 1024)
#define CHUNK_READ_CHUNK_SIZE		(512 * 1024)
#define CHUNK_MIN_READ_SIZE			(64 * 1024)
#define CHUNK_READ_ALIGN			SSD_PAGE_SIZE

#define CHUNK_WRITE_THRESHOLD		(128 * 1024)
#define CHUNK_WRITE_CHUNK_SIZE		SSD_ERASE_BLOCK_SIZE
#define CHUNK_WRITE_ALIGN			SSD_ERASE_BLOCK_SIZE

#define IS_CHUNKING_NEEDED(_length, _is_read) ( \
	(((_is_read) != 0) && ((_length) >= CHUNK_READ_THRESHOLD)) || \
	(((_is_read) == 0) && ((_length) >= CHUNK_WRITE_THRESHOLD)) )

typedef struct _io_context {
	dev_hook *hook;
	PIRP      orig_irp;
	PIRP      new_irp;
	//
	PUCHAR buff;
	PUCHAR new_buff;
	int    new_buff_index; // new_buff lookaside list index (-1, if allocated from pool)
	//
	ULONG     length;    // request length
	ULONGLONG offset;    // request disk offset
	ULONG     completed; // IO completed bytes
	ULONG     encrypted; // encrypted bytes
	//
	volatile long refs;  // context references counter
	

	ULONGLONG chunk_diskof;
	ULONG     chunk_length;
	ULONG     chunk_offset;
	xts_key  *chunk_key;
	
	BOOLEAN expected;      // this io operation is expected, enable optimization
	BOOLEAN discontinuous; // this is a discontinuous chunk
	BOOLEAN write_pending; // write operation currently pending

	BOOLEAN is_sync; // this is a synchronous IO operation,
	                 // io_encrypted_irp_io must not return before this IO completed
	
	ULONGLONG  write_offset;
	ULONG      write_length;
	
	KSPIN_LOCK write_lock;

	KEVENT   done_event;
	NTSTATUS status;

	WORK_QUEUE_ITEM work_item;

} io_context;

// function types declarations
WORKER_THREAD_ROUTINE io_async_read_chunk;
IO_COMPLETION_ROUTINE io_chunk_read_complete;
WORKER_THREAD_ROUTINE io_write_next_chunk;
IO_COMPLETION_ROUTINE io_chunk_write_complete;
WORKER_THREAD_ROUTINE io_async_encrypt_chunk;

#define io_context_addref(_ctx)      ( InterlockedIncrement(&(_ctx)->refs) )
#define io_set_status(_ctx, _status) ( (_ctx)->status = (_status) )

static NPAGED_LOOKASIDE_LIST g_io_contexts_list;    // Non-Paged lookaside list for io_context structures allocation
static NPAGED_LOOKASIDE_LIST g_temp_buff_lists[12]; // Lookaside lists for temporary buffers (512 - 2097152 bytes length)

static void io_context_deref(io_context *ctx)
{
	if (InterlockedDecrement(&ctx->refs) == 0)
	{
		// complete the original irp
		if (NT_SUCCESS(ctx->status)) {
			ctx->orig_irp->IoStatus.Status = STATUS_SUCCESS;
			ctx->orig_irp->IoStatus.Information = ctx->length;
		} else {
			ctx->orig_irp->IoStatus.Status = ctx->status;
			ctx->orig_irp->IoStatus.Information = ctx->length;
		}
		IoCompleteRequest(ctx->orig_irp, IO_DISK_INCREMENT);

		// free resources
		IoReleaseRemoveLock(&ctx->hook->remove_lock, ctx->orig_irp);
		InterlockedDecrement(&ctx->hook->io_depth);

		if (ctx->new_irp)
		{
			IoFreeIrp(ctx->new_irp);
		}

		if (ctx->new_buff)
		{
			if (ctx->new_buff_index >= 0) {
				ExFreeToNPagedLookasideList(&g_temp_buff_lists[ctx->new_buff_index], ctx->new_buff);
			} else {
				ExFreePoolWithTag(ctx->new_buff, '7_cd');
			}
		}

		// set the completion event if needed
		if (ctx->is_sync) {
			KeSetEvent(&ctx->done_event, IO_NO_INCREMENT, FALSE);
		} else {
			ExFreeToNPagedLookasideList(&g_io_contexts_list, ctx);
		}
	}
}

static ULONG io_read_chunk_length(io_context *ctx)
{
	ULONG remain = ctx->length - ctx->completed;
	ULONG length = min(remain / 2, CHUNK_READ_CHUNK_SIZE);

	// length must be SSD_PAGE_SIZE aligned
	if (length & (SSD_PAGE_SIZE-1))
	{
		length += SSD_PAGE_SIZE - (length & (SSD_PAGE_SIZE-1));
	}

	// don't create chunks that are too small
	if (remain - length < CHUNK_MIN_READ_SIZE)
	{
		length += remain - length;
	}	
	
	// increase the first chunk's size so subsequent chunks start aligned 
	if ( (ctx->chunk_offset == 0) && ((ctx->offset + length) & (CHUNK_READ_ALIGN-1)) )
	{
		length += CHUNK_READ_ALIGN - ((ctx->offset + length) & (CHUNK_READ_ALIGN-1));
	}
	return length;
}

static ULONG io_write_chunk_length(io_context *ctx)
{
	ULONG length = CHUNK_WRITE_CHUNK_SIZE;

	// increase the first chunk's size so subsequent chunks start aligned
	if ( (ctx->chunk_offset == 0) && ((ctx->offset + length) & (CHUNK_WRITE_ALIGN-1)) )
	{
		length += CHUNK_WRITE_ALIGN - ((ctx->offset + length) & (CHUNK_WRITE_ALIGN-1));
	}
	return length;
}

static void io_async_make_chunk(io_context *ctx, BOOLEAN is_read)
{
	dev_hook *hook = ctx->hook;
	ULONG     done = is_read != 0 ? ctx->completed : ctx->encrypted;
	
	ctx->chunk_diskof  = ctx->offset + done;
	ctx->chunk_offset  = done;
	ctx->chunk_key     = hook->dsk_key;
	ctx->discontinuous = FALSE;

	// handle redirected sectors
	if ( !(hook->flags & F_NO_REDIRECT) && (ctx->chunk_diskof < hook->head_len) )
	{
		ctx->chunk_diskof  = ctx->chunk_diskof + hook->stor_off;
		ctx->chunk_length  = hook->head_len;
		ctx->discontinuous = TRUE;
	} else 
	{
		if ( (dc_conf_flags & CONF_ENABLE_SSD_OPT) && (hook->flags & F_SSD) &&
			 (hook->io_depth == 1 && ctx->expected) && IS_CHUNKING_NEEDED(ctx->length, is_read) )
		{
			if (is_read) {
				ctx->chunk_length = io_read_chunk_length(ctx);
			} else {
				ctx->chunk_length = io_write_chunk_length(ctx);
			}
		} else {
			ctx->chunk_length = ctx->length;
		}
	}
	
	// handle partial encrypted state
	if (hook->flags & F_SYNC) 
	{
		if (ctx->chunk_diskof >= hook->tmp_size)
		{
			ctx->chunk_key = (hook->flags & F_REENCRYPT) ? hook->tmp_key : NULL;			
		} else
		{
			if (ctx->chunk_diskof + ctx->chunk_length > hook->tmp_size)
			{
				ctx->chunk_length = (ULONG)(hook->tmp_size - ctx->chunk_diskof);
			}
		}
	}
	if (ctx->chunk_length > ctx->length - done)
	{
		ctx->chunk_length = ctx->length - done;
	}
}

static NTSTATUS io_chunk_read_complete(PDEVICE_OBJECT dev_obj, PIRP irp, io_context *ctx)
{
	dev_hook* hook   = ctx->hook;
	PUCHAR    buff   = ctx->buff + ctx->chunk_offset;
	NTSTATUS  status = irp->IoStatus.Status;
	ULONGLONG offset = ctx->chunk_diskof;
	ULONG     length = (ULONG)irp->IoStatus.Information;
		
	// free mdl from the chunk irp
	IoFreeMdl(irp->MdlAddress);
	irp->MdlAddress	= NULL;

	// update completed length
	ctx->completed += ctx->chunk_length;

	if (NT_SUCCESS(status))
	{
		// if reading operation is not completed, start next chunk
		if (ctx->completed < ctx->length)
		{
			IoReuseIrp(irp, STATUS_SUCCESS);
			io_context_addref(ctx);
			io_async_read_chunk(ctx);
		}

		// decrypt chunk if needed
		if (ctx->chunk_key != NULL) 
		{
			if (hook->flags & F_NO_REDIRECT)
			{
				offset -= hook->head_len; // XTS offset is calculated from the beginning of the volume data
				                          // if redirection not used, subtract the header length
			}
			io_context_addref(ctx);
			cp_parallelized_crypt(0, ctx->chunk_key, io_context_deref, ctx, buff, buff, length, offset);
		}
	}

	// set the completion status if read operation completed or failed.
	if (NT_SUCCESS(status) == FALSE || ctx->completed == ctx->length)
	{
		io_set_status(ctx, status);
	}
	io_context_deref(ctx);
	return STATUS_MORE_PROCESSING_REQUIRED;
}

static void io_async_read_chunk(io_context *ctx)
{
	PIO_STACK_LOCATION new_sp;
	PMDL               new_mdl;
	PUCHAR             pbuf_va;

	if (KeGetCurrentIrql() >= DISPATCH_LEVEL) {
		ExInitializeWorkItem(&ctx->work_item, io_async_read_chunk, ctx);
		ExQueueWorkItem(&ctx->work_item, CriticalWorkQueue);
		return;
	}
	io_async_make_chunk(ctx, TRUE);

	new_sp = IoGetNextIrpStackLocation(ctx->new_irp);
	new_sp->MajorFunction = IRP_MJ_READ;
	new_sp->Flags         = IoGetCurrentIrpStackLocation(ctx->orig_irp)->Flags;
	new_sp->Parameters.Read.Length              = ctx->chunk_length;
	new_sp->Parameters.Read.ByteOffset.QuadPart = ctx->chunk_diskof;
	
	pbuf_va = ((PUCHAR)MmGetMdlVirtualAddress(ctx->orig_irp->MdlAddress)) + ctx->chunk_offset;
	new_mdl = mm_allocate_mdl_success(pbuf_va, ctx->chunk_length);

	if (new_mdl == NULL) {
		io_set_status(ctx, STATUS_INSUFFICIENT_RESOURCES);
		io_context_deref(ctx); 
		return;
	}
	IoBuildPartialMdl(ctx->orig_irp->MdlAddress, new_mdl, pbuf_va, ctx->chunk_length);
	ctx->new_irp->MdlAddress = new_mdl;

	IoSetCompletionRoutine(ctx->new_irp, io_chunk_read_complete, ctx, TRUE, TRUE, TRUE);
	IoCallDriver(ctx->hook->orig_dev, ctx->new_irp);
}

static NTSTATUS io_chunk_write_complete(PDEVICE_OBJECT dev_obj, PIRP irp, io_context *ctx)
{
	KLOCK_QUEUE_HANDLE lock_queue;
	BOOLEAN            need_write;

	// free mdl from the chunk irp
	IoFreeMdl(irp->MdlAddress);
	irp->MdlAddress	= NULL;

	if (NT_SUCCESS(irp->IoStatus.Status))
	{
		KeAcquireInStackQueuedSpinLock(&ctx->write_lock, &lock_queue);

		// update pointers
		ctx->write_offset += ctx->write_length;
		ctx->completed    += ctx->write_length;
		ctx->write_length  = ctx->encrypted - ctx->completed;
		need_write = ctx->write_pending = (ctx->write_length != 0);

		KeReleaseInStackQueuedSpinLock(&lock_queue);

		// if discontinuous chunk completed, start encryption of next chunk if needed
		if (ctx->discontinuous && ctx->completed < ctx->length)
		{
			ctx->discontinuous = FALSE;
			ctx->write_offset  = ctx->offset + ctx->completed;
			io_context_addref(ctx);
			io_async_encrypt_chunk(ctx);
		}

		// if next encrypted part available, start writing it now
		if (need_write) 
		{
			IoReuseIrp(irp, STATUS_SUCCESS);
			io_context_addref(ctx);
			io_write_next_chunk(ctx);
		}
	}
	io_context_deref(ctx);
	return STATUS_MORE_PROCESSING_REQUIRED;
}

static void io_write_next_chunk(io_context *ctx)
{
	PIO_STACK_LOCATION new_sp;
	PIRP               new_irp;

	if (KeGetCurrentIrql() >= DISPATCH_LEVEL)	{
		ExInitializeWorkItem(&ctx->work_item, io_write_next_chunk, ctx);
		ExQueueWorkItem(&ctx->work_item, CriticalWorkQueue);
		return;
	}
	new_irp = ctx->new_irp;
	new_sp  = IoGetNextIrpStackLocation(new_irp);

	new_sp->MajorFunction = IRP_MJ_WRITE;
	new_sp->Flags         = IoGetCurrentIrpStackLocation(ctx->orig_irp)->Flags;
	new_sp->Parameters.Write.Length              = ctx->write_length;
	new_sp->Parameters.Write.ByteOffset.QuadPart = ctx->write_offset;
	
	if ( (new_irp->MdlAddress = mm_allocate_mdl_success(ctx->new_buff + ctx->completed, ctx->write_length)) == NULL )
	{
		io_set_status(ctx, STATUS_INSUFFICIENT_RESOURCES);
		io_context_deref(ctx);
		return;
	}
	MmBuildMdlForNonPagedPool(new_irp->MdlAddress);
	IoSetCompletionRoutine(new_irp, io_chunk_write_complete, ctx, TRUE, TRUE, TRUE);
	IoCallDriver(ctx->hook->orig_dev, new_irp);
}

static void io_chunk_encrypt_complete(io_context *ctx)
{
	KLOCK_QUEUE_HANDLE lock_queue;
	BOOLEAN            need_write;
	
	if (ctx->chunk_offset == 0) {
		ctx->write_offset = ctx->chunk_diskof;
	}
	KeAcquireInStackQueuedSpinLock(&ctx->write_lock, &lock_queue);

	// update encrypted length
	ctx->encrypted += ctx->chunk_length;

	if (need_write = (ctx->write_pending == FALSE)) {
		ctx->write_pending = TRUE;
		ctx->write_length = ctx->encrypted - ctx->completed;
	}
	KeReleaseInStackQueuedSpinLock(&lock_queue);

	// write encrypted part if previous write operation completed
	if (need_write)
	{
		io_context_addref(ctx);
		io_write_next_chunk(ctx);
	}

	// encrypt next chunk if needed
	if (ctx->discontinuous == FALSE && ctx->encrypted < ctx->length)
	{
		io_context_addref(ctx);
		io_async_encrypt_chunk(ctx);
	}

	io_context_deref(ctx);
}

static void io_async_encrypt_chunk(io_context *ctx)
{
	PUCHAR    in_buf, out_buf;
	ULONGLONG offset;
			
	io_async_make_chunk(ctx, FALSE);
	
	out_buf = ctx->new_buff + ctx->encrypted;
	in_buf = ctx->buff + ctx->encrypted;
	offset = ctx->chunk_diskof;
		
	if (ctx->chunk_key != NULL)
	{
		if (ctx->hook->flags & F_NO_REDIRECT)
		{
			offset -= ctx->hook->head_len; // XTS offset is calculated from the beginning of the volume data
				                           // if redirection not used, subtract the header length
		}
		cp_parallelized_crypt(1, ctx->chunk_key, io_chunk_encrypt_complete, ctx, in_buf, out_buf, ctx->chunk_length, offset);
	} else {
		memcpy(out_buf, in_buf, ctx->chunk_length);
		io_chunk_encrypt_complete(ctx);
	}
}

NTSTATUS io_encrypted_irp_io(dev_hook *hook, PIRP irp, BOOLEAN is_sync)
{
	PIO_STACK_LOCATION irp_sp = IoGetCurrentIrpStackLocation(irp);
	NTSTATUS           status = STATUS_PENDING;
	io_context*        ctx;
	int                i;

	// allocate the IO context
	if ( (ctx = (io_context*)ExAllocateFromNPagedLookasideList(&g_io_contexts_list)) == NULL )
	{
		return dc_release_irp(hook, irp, STATUS_INSUFFICIENT_RESOURCES);
	}

	// initialize new IO context
	memset(ctx, 0, sizeof(io_context));

	ctx->orig_irp = irp;
	ctx->hook = hook;
	ctx->refs = 1;

	// increment hook IO queue depth
	InterlockedIncrement(&hook->io_depth);

	if (ctx->is_sync = is_sync)
	{
		KeInitializeEvent(&ctx->done_event, NotificationEvent, FALSE);
	}

	if (irp_sp->MajorFunction == IRP_MJ_READ) {
		ctx->offset = irp_sp->Parameters.Read.ByteOffset.QuadPart;
		ctx->length = irp_sp->Parameters.Read.Length;
	} else 
	{
		ctx->offset = irp_sp->Parameters.Write.ByteOffset.QuadPart;
		ctx->length = irp_sp->Parameters.Write.Length;

		// writing to redirection area must be blocked for preventing file system corruption
		if ( !(hook->flags & F_NO_REDIRECT) && 
			  (is_intersect(ctx->offset, ctx->length, hook->stor_off, hook->head_len) != 0) )
		{
			DbgMsg("writing to redirection area blocked, dev=%ws\n", hook->dev_name);
			status = STATUS_ACCESS_DENIED;
			goto on_fail;
		}
	}
	
	// IO operations must be within the volume data range and be SECTOR_SIZE aligned
	if ( (ctx->length == 0) || 
		 (ctx->length & (SECTOR_SIZE - 1)) || (ctx->offset + ctx->length > hook->use_size) )
	{
		DbgMsg("unaligned IO operation, dev=%ws\n", hook->dev_name);
		status = STATUS_INVALID_PARAMETER;
		goto on_fail;
	}

	// detect expected sequential IO operations
	if (InterlockedExchange64(&hook->expect_off, ctx->offset + ctx->length) == ctx->offset)
	{
		ctx->expected = TRUE;
	}

	// if redirection not used, volume data shifted by volume header length
	if (hook->flags & F_NO_REDIRECT)
	{
		ctx->offset += hook->head_len; // add the volume header length
		                               // to get the offset of the data on the storage device
	}

	// allocate resources for processing request
	if ( (ctx->new_irp = mm_allocate_irp_success(hook->orig_dev->StackSize)) == NULL ||
		 (ctx->buff = (PUCHAR)mm_map_mdl_success(irp->MdlAddress)) == NULL )
	{
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto on_fail;
	}
	
	// copy original IRP source to new IRP
	ctx->new_irp->Tail.Overlay.Thread = irp->Tail.Overlay.Thread;
	ctx->new_irp->Tail.Overlay.OriginalFileObject = irp->Tail.Overlay.OriginalFileObject;

	// marg original IRP as pending
	IoMarkIrpPending(irp);

	if (irp_sp->MajorFunction == IRP_MJ_WRITE)
	{
		// allocate memory from temporary buffer lookaside list
		for (i = 0; i < sizeof(g_temp_buff_lists) / sizeof(g_temp_buff_lists[0]); i++)
		{
			if ( (ctx->length <= (512u << i)) &&
				 (ctx->new_buff = (PUCHAR)ExAllocateFromNPagedLookasideList(&g_temp_buff_lists[i])) != NULL )
			{
				ctx->new_buff_index = i;
				break;
			}
		}

		// if memory not allocated from lookaside, allocate from pool
		if (ctx->new_buff == NULL)
		{
			if ( (ctx->new_buff = (PUCHAR)mm_alloc_success(NonPagedPool, ctx->length, '7_cd')) == NULL )
			{
				status = STATUS_INSUFFICIENT_RESOURCES;
				goto on_fail;
			}
			ctx->new_buff_index = -1;
		}

		KeInitializeSpinLock(&ctx->write_lock);
		io_async_encrypt_chunk(ctx);
	} else {
		// IRP_MJ_READ does not require memory allocation, start reading now
		io_async_read_chunk(ctx);
	}

cleanup:
	if (is_sync)
	{
		KeWaitForSingleObject(&ctx->done_event, Executive, KernelMode, FALSE, NULL);
		status = ctx->status;
		ExFreeToNPagedLookasideList(&g_io_contexts_list, ctx);
	}
	return status;

on_fail:
	io_set_status(ctx, status);
	io_context_deref(ctx);
	goto cleanup;
}


NTSTATUS io_read_write_irp(dev_hook *hook, PIRP irp)
{
	// reseed RNG on first 1000 I/O operations for collect initial entropy
	if (InterlockedIncrement(&dc_io_count) < 1000) {
		cp_rand_reseed();
	}

	if (hook->flags & (F_DISABLE | F_FORMATTING)) {
		return dc_release_irp(hook, irp, STATUS_INVALID_DEVICE_STATE);
	}

	if (hook->flags & F_SYNC)
	{
		IoMarkIrpPending(irp);
		ExInterlockedInsertTailList(&hook->sync_irp_queue, &irp->Tail.Overlay.ListEntry, &hook->sync_req_lock);
		KeSetEvent(&hook->sync_req_event, IO_DISK_INCREMENT, FALSE);
		return STATUS_PENDING;
	}	
	
	if ((hook->flags & F_ENABLED) == 0)
	{
		// probe for mount new volume
		if ( (hook->flags & (F_UNSUPRT | F_NO_AUTO_MOUNT)) || (hook->mnt_probed != 0) ) {
			if (IS_DEVICE_BLOCKED(hook) != 0) return dc_release_irp(hook, irp, STATUS_ACCESS_DENIED);
			return dc_forward_irp(hook, irp);
		}
		return dc_probe_mount(hook, irp);
	}	

	// start normal encrypted IO
	return io_encrypted_irp_io(hook, irp, 0);
}

void io_init()
{
	int i;

	for (i = 0; i < sizeof(g_temp_buff_lists) / sizeof(g_temp_buff_lists[0]); i++)
	{
		ExInitializeNPagedLookasideList(&g_temp_buff_lists[i], NULL, NULL, 0, (512u << i), '2_cd', 0);
	}
	ExInitializeNPagedLookasideList(&g_io_contexts_list, mm_alloc_success, NULL, 0, sizeof(io_context), '5_cd', 0);	
}

void io_free()
{
	int i;

	for (i = 0; i < sizeof(g_temp_buff_lists) / sizeof(g_temp_buff_lists[0]); i++)
	{
		ExDeleteNPagedLookasideList(&g_temp_buff_lists[i]);
	}
	ExDeleteNPagedLookasideList(&g_io_contexts_list);
}
