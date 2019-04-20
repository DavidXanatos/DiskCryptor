/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2008-2009 
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
#include "boot.h"
#include "bios.h"
#include "misc.h"
#include "e820.h"
#include "boot_vtab.h"
#include "bios_misc.h"
#include "boot_load.h"

static void naked bios_jump_rm()
{
	/* zero configuration area to prevent leaks */
	zeromem(&conf, sizeof(conf));

	__asm
	{
		mov eax, [bdat]
		mov ecx, [eax].bd_base
	    add ecx, [eax].bd_size
		sub ecx, 384      /* reserve 384 bytes for backup data block */
		mov esp, ecx      /* setup new stack */
		jmp [eax].jump_rm /* jump to real-mode code */
	}
}

void bios_jump_boot(int hdd_n, int n_mount)
{
	if (n_mount != 0) 
	{
		/* setup backup data block */
		autocpy(
			addof(bdat->bd_base, bdat->bd_size - 384), bdat, offsetof(bd_data, ret_32));
	} else {
		/* clear boot data block signature */
		bdat->sign1 = 0; bdat->sign2 = 0;
	}
	bdat->boot_dsk = hdd2dos(hdd_n);
	bdat->rmc.dx   = 0x80;
	bdat->rmc.efl  = FL_IF; /* enable interrupts */
	bdat->segoff   = 0x7C00;
	bios_jump_rm();
}

void bios_reboot()
{
	bdat->rmc.ax  = 0x0472;
	bdat->rmc.di  = bdat->rmc.ax;
	bdat->rmc.efl = 0; /* disable interrupts */
	bdat->segoff  = 0x0FFFF0000;
	bios_jump_rm();
}

static void add_smap(e820entry *map) 
{
	if ( (bdat->mem_map.n_map < E820MAX) && (map->size != 0) ) {
		autocpy(&bdat->mem_map.map[bdat->mem_map.n_map++], map, sizeof(e820entry));
	}
}

void bios_create_smap()
{
	rm_ctx     ctx;
	e820map    map;
	e820entry *ent, tmp;
	u32        base, size;
	int        i;

	/* setup initial context */
	btab->p_set_ctx(0, &ctx);
	/* get system memory map */
	map.n_map = 0; base = bdat->bd_base; size = bdat->bd_size;
	do
	{
		ctx.eax = 0x0000E820;
		ctx.edx = 0x534D4150;
		ctx.ecx = sizeof(e820entry);
		ctx.es  = rm_seg(&map.map[map.n_map]);
		ctx.di  = rm_off(&map.map[map.n_map]);

		if ( (btab->p_bios_call(0x15, &ctx) == 0) || (ctx.eax != 0x534D4150) ) {
			break;
		}
	} while ( (++map.n_map < E820MAX) && (ctx.ebx != 0) );

	/* append my real mode block to second region */
	if ( (map.n_map >= 2) && (map.map[0].type == E820_RAM) && 
		 (map.map[1].type == E820_RESERVED) && (map.map[0].base == 0) &&
		 (map.map[1].base == map.map[0].size) &&
		 (base + size == map.map[0].size) )
	{
		map.map[0].size  = base;
		map.map[1].base  = map.map[0].size;
		map.map[1].size += size;		
	}
	
	/* build new memory map without my regions */
	for (i = 0; i < map.n_map; i++)
	{
		ent = &map.map[i];

		if ( (ent->type == E820_RAM) && 
			 (in_reg(base, ent->base, ent->size) != 0) )
		{
			tmp.base = ent->base;
			tmp.size = base - ent->base;
			tmp.type = ent->type;
			add_smap(&tmp);

			tmp.base = base;
			tmp.size = size;
			tmp.type = E820_RESERVED;
			add_smap(&tmp);

			if (ent->base + ent->size > base + size) 
			{
				tmp.base = base + size;
				tmp.size = ent->base + ent->size - tmp.base;
				tmp.type = ent->type;
				add_smap(&tmp);
			}
		} else {
			add_smap(ent);
		}
	}
}

void bios_hook_ints()
{
	/* setup new base memory size */
	p16(0x0413)[0] -= d16(bdat->bd_size / 1024);
	/* hook bios interrupts */
	bdat->hook_ints();
}