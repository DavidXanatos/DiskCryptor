;
;   *
;   * DiskCryptor - open source partition encryption tool
;   * Copyright (c) 2008
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
org 7C00h

use16
 dw 0C033h  ; hack for compatibility with fucking Acer Travelmate BIOS
 nop	    ;
 nop	    ; 10EB9090h
 jmp   j_1  ;
lba_packet:
 size	  db 10h
 reserved db 0
 sectors  dw 64
 buff_lo  dw 0
 buff_hi  dw 2000h
 start_lo dd 1
 start_hi dd 0
j_1:
 jmp   0:start

start:
 cli
 xor   ax, ax
 mov   ds, ax
 mov   ss, ax
 mov   sp, 4000h
 sti
 ; check int13 hook installed by another bootloader copy
 mov   bx, [4Ch]
 mov   es, [4Eh]
 cmp   dword [es:bx+2], 6D4701BBh
 jz    boot_active
 ; read stage1 code to 2000:0
 call  read_sectors
 jc    boot_active
 ; jump to loaded image
 xor   bx, bx
 push  es
 push  bx
 retf

boot_active:
 mov   bp, 7C00h
 ; copy self to 1FE0:7C00
 mov   ax, 1FE0h
 mov   es, ax
 mov   si, bp
 mov   di, bp
 mov   cx, 0200h
 cld
 rep movsb
 ; jump to copy
 push  es
 push  in_seg
 retf
in_seg:
 ; setup new data segment
 mov   ax, cs
 mov   ds, ax
 ; find active partition
 mov   di, 7C00h+1BEh ; start of partition table
find:
 test  byte [di], 0x80
 jnz   active_found
 add   di, 0x10       ; next table
 cmp   di, 7C00h+1FEh ; scanned beyond end of table ??
 jb    find
 ; atcive partition not found
 call  error_msg
 db 'no active partition found',0
active_found:
 mov   eax, [di+8] ; get partition start
 ; setup LBA block
 mov   [start_lo], eax
 xor   ebx, ebx
 mov   [start_hi], ebx
 mov   [buff_hi], bx
 mov   [buff_lo], bp
 inc   bx
 mov   [sectors], bx
 ; reat boot sector
 call  read_sectors
 jnc   do_boot_1
 call  error_msg
 db 'disk read error',0
do_boot_1:
 ; check boot signature
 cmp   word [es:7C00h+1FEh], 0AA55h
 jz    do_boot_2
 call  error_msg
 db 'invalid boot sector',0
do_boot_2:
 ; jump to boot sector
 push  es
 push  bp
 retf

read_sectors:
 pusha
 ; save drive number
 mov   bp, dx
 ; setup read segment
 push  word [buff_hi]
 pop   es
 ; if read area below that 504mb use CHS enforcement
 ; this needed for compatibility with some stupid BIOSes
 xor   eax, eax
 cmp   dword [start_hi], eax
 jnz   check_lba
 cmp   dword [start_lo], (504 * 1024 * 2)
 jc    chs_mode
check_lba:
 ; check for LBA support
 mov   ah, 41h
 mov   bx, 55AAh
 int   13h
 jc    chs_mode
 cmp   bx, 0AA55h
 jnz   chs_mode
 test  cl, 1
 jz    chs_mode
 ; setup LBA parameters
lba_mode:
 mov   si, lba_packet
 mov   ah, 42h
 mov   dx, bp
 jmp   read
chs_mode: 
 ; get drive geometry
 mov   ah, 08h
 mov   dx, bp
 push  es
 int   13h
 pop   es
 ; if get geometry failed, then try to use LBA mode
 jc    lba_mode
 ; translate LBA to CHS
 and   cl, 3Fh
 inc   dh
 movzx ecx, cl ; ecx - max_sect
 movzx esi, dh ; esi - max_head
 mov   eax, [start_lo]
 xor   edx, edx
 div   ecx
 inc   dx
 mov   cl, dl
 xor   dx, dx
 div   esi
 mov   dh, dl
 mov   ch, al
 shr   ax, 002h
 and   al, 0C0h
 or    cl, al
 mov   ax, [sectors]
 mov   ah, 2
 ; set up drive number
 mov   bx, bp
 mov   dl, bl
 mov   bx, [buff_lo]
read:
 push  es
 int   13h
 pop   es
 popa
 ret

error_msg:
 pop   si
e_loop:
 lodsb
 test  al, al
 jz    $
 mov   ah, 0Eh
 xor   bx, bx
 int   10h
 jmp   e_loop


times  510-($-$$) db 0
db     0x55,0xaa








