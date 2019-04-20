;
;   *
;   * DiskCryptor - open source partition encryption tool
;   * Copyright (c) 2008-2009
;   * ntldr <ntldr@diskcryptor.net> PGP key ID - 0xC48251EB4F8E4E6E
;   *
;   This program is free software: you can redistribute it and/or modify
;   it under the terms of the GNU General Public License version 3 as
;   published by the Free Software Foundation.
;
;   This program is distributed in the hope that it will be useful,
;   but WITHOUT ANY WARRANTY; without even the implied warranty of
;   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;   GNU General Public License for more details.
;
;   You should have received a copy of the GNU General Public License
;   along with this program.  If not, see <http://www.gnu.org/licenses/>.
;
org 0

include 'win32a.inc'
include 'macro.inc'
include 'struct.inc'

use16
 nop
 nop
 nop
 nop
 ; all bootloader data are loaded to memory
 ; setup real mode segment registers
 cli
 mov	ax, cs
 mov	ds, ax
 mov	gs, ax
 xor	bx, bx
 mov	es, bx
 mov	fs, bx
 mov	ss, bx
 ; setup initial realmode stack
 mov	sp, 4000h
 sti
 ; save boot disk
 push	dx
 ; get code base
 call	next
next:
 pop	bp
 add	bp, 0 - $ + 1
 ; bp - code base
 ; get embedded boot_hook image address
 lea	bx, [bp+bd_block+boot_data]
 ; get virtual size of boot_hook image
 mov	ebx, [bx+boot_mod.virt_size]
 ; align virtual size to 1k
 add	ebx, (1024-1)
 and	ebx, not (1024-1)
 ; add boot data size and 2kb for stack
 add	ebx, (bd_kbs * 1024) + 2048
 mov	[ds:bp+bd_block+bd_data.bd_size], ebx
 ; calc needed memory size
 shr	bx, 10
 ; get base memory size
 mov	dx, [fs:0413h]
 sub	dx, bx
 ; copy boot data block to top of base memory
 shl	dx, 6
 mov	es, dx
 xor	di, di
 lea	si, [bp+bd_block]
 mov	cx, bd_size
 cld
 rep movsb
 ; restore boot disk
 pop	dx
 ; push return address
 lea	ax, [bp+pm_loader]
 push	ax
 ; jump to resident block
 push	es
 push	pm_enable
 retf

pm_loader: ; protected mode loader
use32
 lea	ebx, [ecx + (bd_kbs * 1024)]
 ; get embedded PE image address
 call	next2
next2:
 pop	ebp
 add	ebp, bd_block + boot_data - next2
 mov	edx, ebp
 add	edx, [ebp+boot_mod.raw_size]
 ; ecx - boot data block
 ; ebp - boot_hook image
 ; edx - boot_load image
 ; ebx - new boot_hook image base
 call	load_module
 ; load boot_load module
 mov	ebp, edx
 mov	ebx, 8000h
 call	load_module
 jmp	$

load_module: ; ebp - module, ebx - address, ecx - bd_data
 pushad
 ; push EP parameters to stack
 push	5000h
 push	ecx
 ; zero memory
 mov	ecx, [ebp+boot_mod.virt_size]
 mov	edi, ebx
 xor	eax, eax
 rep stosb
 ; copy module code
 mov	esi, ebp
 mov	edi, ebx
 mov	ecx, [ebp+boot_mod.raw_size]
 rep movsb
 ; process relocs
 mov	ecx, [ebx+boot_mod.n_rels]
 lea	esi, [ebx+boot_mod.relocs]
do_relocs:
 test	ecx, ecx
 jz	relocs_done
 lodsd
 add	[ebx+eax], ebx
 dec	ecx
 jmp	do_relocs
relocs_done:
 ; zero original image
 mov	edi, ebp
 mov	ecx, [ebp+boot_mod.raw_size]
 rep stosb
 ; call EP
 mov	eax, [ebx+boot_mod.entry_rva]
 add	eax, ebx
 call	eax
 add	esp, 8
 popad
 ret

bd_block: ; boot data block

use16
org 0
 bdb	bd_data

NSEG  = 0
DSEG  = 1 shl 3 ; 32-bit data selector
CSEG  = 2 shl 3 ; 32-bit code selector
ESEG  = 3 shl 3 ; 32-bit extended data selector
RCSEG = 4 shl 3 ; 16-bit code selector
RDSEG = 5 shl 3 ; 16-bit data selector

gdtr:					; Global Descriptors Table Register
  dw 6*8-1				; limit of GDT (size minus one)
  dd gdt				; linear address of GDT

gdt rw 4				; null desciptor
    dw 0FFFFh, 0, 9200h, 0CFh		; 32-bit data desciptor
    dw 0FFFFh, 0, 9A00h, 0CFh		; 32-bit code desciptor
pm32_edes:
    dw 0FFFFh, 0, 9200h, 0CFh		; 32-bit extended data desciptor
pm16_cdes:
    dw 0FFFFh, 0, 9E00h, 0		; 16 bit code desciptor
pm16_ddes:
    dw 0FFFFh, 0, 9200h, 0		; 16 bit data desciptor

pm_enable:
use16
 ; save boot disk
 mov	[cs:bdb.boot_dsk], dl
 ; get return address
 xor	edx, edx
 pop	dx
 ; setup segment registers
 xor	ecx, ecx
 mov	cx, cs
 mov	ds, cx
 ; get bd_block offset
 shl	ecx, 4
 mov	[bdb.bd_base], ecx
 ; setup temporary PM stack
 mov	[bdb.esp_32], 20000h
 ; inverse real mode block signature in runtime
 ; to prevent finding it in false location
 not	[bdb.sign1]
 not	[bdb.sign2]
 ; correct GDT address
 add	[gdtr+2], ecx
 ; correct descriptors
 or	[pm16_cdes+2], ecx
 or	[pm16_ddes+2], ecx
 or	[pm32_edes+2], ecx
 ; correct PM/RM jumps
 add	[pm_jump], ecx
 mov	word [rm_jump], cs
 ; setup callback pointers
 lea	eax, [ecx+call_rm]
 mov	[bdb.call_rm], eax
 lea	eax, [ecx+jump_rm]
 mov	[bdb.jump_rm], eax
 lea	eax, [ecx+hook_ints]
 mov	[bdb.hook_ints], eax
 ; calculate pmode return address
 xor	eax, eax
 mov	ax, gs
 shl	eax, 4
 add	eax, edx
 mov	[bdb.segoff], eax
 ; jump to pmode
 call	jump_to_pm
use32
 ; return to caller
 jmp	[fs:bdb.segoff]


regs_load:
use16
 mov	eax, [cs:bdb.rmc.eax]
 mov	ecx, [cs:bdb.rmc.ecx]
 mov	edx, [cs:bdb.rmc.edx]
 mov	ebx, [cs:bdb.rmc.ebx]
 mov	ebp, [cs:bdb.rmc.ebp]
 mov	esi, [cs:bdb.rmc.esi]
 mov	edi, [cs:bdb.rmc.edi]
 push	[cs:bdb.rmc.efl]
 push	[cs:bdb.rmc.ds]
 push	[cs:bdb.rmc.es]
 pop	es
 pop	ds
 popfd
 ret

regs_save:
use16
 mov	[cs:bdb.rmc.eax], eax
 mov	[cs:bdb.rmc.ecx], ecx
 mov	[cs:bdb.rmc.edx], edx
 mov	[cs:bdb.rmc.ebx], ebx
 mov	[cs:bdb.rmc.ebp], ebp
 mov	[cs:bdb.rmc.esi], esi
 mov	[cs:bdb.rmc.edi], edi
 push	es
 push	ds
 pushfd
 pop	[cs:bdb.rmc.efl]
 pop	[cs:bdb.rmc.ds]
 pop	[cs:bdb.rmc.es]
 ret

call_rm:
use32
 pushad
 ; switch to RM
 call	jump_to_rm
use16
 ; load registers
 call	regs_load
 pushf
 cli
 call	far [cs:bdb.segoff]
 ; save changed registers
 call	regs_save
 ; return to pmode
 call	jump_to_pm
use32
 popad
 ret

jump_rm:
use32
 ; switch to RM
 call	jump_to_rm
use16
 ; load registers
 call	regs_load
 ; jump to RM code
 jmp	far [cs:bdb.segoff]


hook_ints:
use32
 ; switch to RM
 call	jump_to_rm
use16
 ; nook int15
 xor	ax, ax
 mov	fs, ax
 ; hook int13
 mov	eax, [fs:4Ch]
 mov	[bdb.old_int13], eax
 mov	word [fs:4Ch], new_int13
 mov	word [fs:4Eh], cs
 ; hook int15
 mov	eax, [fs:54h]
 mov	[bdb.old_int15], eax
 mov	word [fs:54h], new_int15
 mov	word [fs:56h], cs
 ; return to pmode
 call	jump_to_pm
use32
 ret

new_int15:
use16
 cmp	ax, 0E820h
 jnz	i15_pass
 cmp	edx, 0534D4150h
 jnz	i15_pass
 sti
 stc
 cld
 cmp	ebx, [cs:bdb.mem_map.n_map]
 jnc	i15_exit
 push	ds
 pusha
 push	cs
 pop	ds
 imul	bx, (8+8+4)
 lea	si, [bx+bdb.mem_map.map]
 mov	cx, (8+8+4)
 rep movsb
 popa
 pop	ds
 inc	ebx
 cmp	ebx, [cs:bdb.mem_map.n_map]
 jnz	@F
 xor	ebx, ebx
@@:
 mov	eax, 0534D4150h
 mov	ecx, (8+8+4)
 clc
 jmp	i15_exit
i15_pass:
 jmp	far [cs:bdb.old_int15]
i15_exit:
 retf	2

new_int13:
use16
 jmp	@F
 dd	6D4701BBh
@@:
 ; save segment registers
 push	fs
 push	gs
 ; save registers
 call	regs_save
 ; save flags
 mov	bp, sp
 push	word [ss:bp+8]
 pop	word [cs:bdb.push_fl]
 call	jump_to_pm
use32
 ; call to PM callback
 call	[fs:bdb.int_cbk]
 ; return to RM
 call	jump_to_rm
use16
 ; load registers
 call	regs_load
 ; load segment registers
 pop	gs
 pop	fs
 retf	2

jump_to_pm:
use16
 ; disable interrupts
 cli
 ; get return address
 pop	ax
 movzx	eax, ax
 mov	[cs:bdb.ret_32], eax
 ; save real mode stack
 mov	[cs:bdb.esp_16], esp
 mov	[cs:bdb.ss_16], ss
 ; setup ds
 mov	ax, cs
 mov	ds, ax
 ; load GDTR
 lgdt	[gdtr]
 ; switch to protected mode
 mov	eax, cr0
 or	eax, 1
 mov	cr0, eax
 ; jump to PM code
pm_jump = $+2
 jmp32	CSEG:pm_start
pm_start:
use32
 ; load 4 GB data descriptor
 mov	ax, ESEG
 mov	fs, ax
 mov	ax, DSEG      
 mov	ds, ax
 mov	es, ax
 mov	gs, ax
 mov	ss, ax
 ; enable SSE
 mov	eax, cr4
 or	eax, 200h ; OSFXSR bit
 mov	cr4, eax
 ; load PM stack
 mov	esp, [fs:bdb.esp_32]
 ; return to caller
 mov	eax, [fs:bdb.ret_32]
 add	eax, [fs:bdb.bd_base]
 push	eax
 ret

jump_to_rm:
use32
 ; get return address
 pop	[fs:bdb.ret_32]
 ; save PM stack
 mov	[fs:bdb.esp_32], esp
 ; load PM16 selector
 mov	ax, RDSEG
 mov	ds, ax
 mov	es, ax
 mov	ss, ax
 mov	fs, ax
 mov	gs, ax
 ; jump to PM16
 jmp	RCSEG:pm16_start
pm16_start:
use16
 ; clear PM bit in cr0
 mov	eax, cr0
 and	eax, 0FFFFFFFEh 
 mov	cr0, eax
 ; jump to real mode
rm_jump = $+3
 jmp	0:rm_start
rm_start:
 ; load RM segments
 mov	ax, cs
 mov	ds, ax
 mov	es, ax
 mov	fs, ax
 mov	gs, ax
 ; load RM stack
 mov	ss,  [bdb.ss_16]
 mov	esp, [bdb.esp_16]
 ; return to caller
 mov	eax, [bdb.ret_32]
 sub	eax, [bdb.bd_base]
 push	ax
 ret

bd_size = $
bd_kbs	= (bd_size / 1024) + 1

boot_data:



