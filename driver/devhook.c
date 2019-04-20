/*
    *
    * DiskCryptor - open source partition encryption tool
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
#include "misc.h"
#include "prng.h"

static LIST_ENTRY hooks_list_head;
static ERESOURCE  hooks_sync_resource;

void dc_reference_hook(dev_hook *hook)
{
	ObReferenceObject(hook->hook_dev);
	ObReferenceObject(hook->orig_dev);
	ObReferenceObject(hook->pdo_dev);
}

void dc_deref_hook(dev_hook *hook)
{
	ObDereferenceObject(hook->pdo_dev);
	ObDereferenceObject(hook->orig_dev);
	ObDereferenceObject(hook->hook_dev);
}

dev_hook *dc_find_hook(wchar_t *dev_name)
{
	PLIST_ENTRY entry;
	dev_hook   *hook;
	dev_hook   *found = NULL;

	KeEnterCriticalRegion();
	ExAcquireResourceSharedLite(&hooks_sync_resource, TRUE);

	entry = hooks_list_head.Flink;

	while (entry != &hooks_list_head)
	{
		hook  = CONTAINING_RECORD(entry, dev_hook, hooks_list);
		entry = entry->Flink;

		if (_wcsicmp(hook->dev_name, dev_name) == 0) {
			dc_reference_hook(hook);
			found = hook; break;
		}
	}
	
	ExReleaseResourceLite(&hooks_sync_resource);
	KeLeaveCriticalRegion();

	return found;
}

void dc_insert_hook(dev_hook *hook)
{
	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(&hooks_sync_resource, TRUE);

	InsertTailList(&hooks_list_head, &hook->hooks_list);

	ExReleaseResourceLite(&hooks_sync_resource);
	KeLeaveCriticalRegion();
}

void dc_remove_hook(dev_hook *hook)
{
	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(&hooks_sync_resource, TRUE);

	RemoveEntryList(&hook->hooks_list);

	ExReleaseResourceLite(&hooks_sync_resource);
	KeLeaveCriticalRegion();
}

dev_hook *dc_first_hook()
{
	dev_hook *hook;
	int       sync;

	if (sync = (KeGetCurrentIrql() == PASSIVE_LEVEL)) {
		KeEnterCriticalRegion();
		ExAcquireResourceSharedLite(&hooks_sync_resource, TRUE);
	} 

	if (IsListEmpty(&hooks_list_head) == FALSE) {
		hook = CONTAINING_RECORD(hooks_list_head.Flink, dev_hook, hooks_list);
	} else 
	{
		if (sync != 0) {
			ExReleaseResourceLite(&hooks_sync_resource);
			KeLeaveCriticalRegion();
		}

		hook = NULL;
	}

	return hook;
}

dev_hook *dc_next_hook(dev_hook *hook)
{
	if (hook->hooks_list.Flink != &hooks_list_head) {
		hook = CONTAINING_RECORD(hook->hooks_list.Flink, dev_hook, hooks_list);
	} else 
	{
		if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
			ExReleaseResourceLite(&hooks_sync_resource);
			KeLeaveCriticalRegion();
		}

		hook = NULL;
	}
	
	return hook;
}

void dc_init_devhook()
{
	InitializeListHead(&hooks_list_head);

	ExInitializeResourceLite(&hooks_sync_resource);
}