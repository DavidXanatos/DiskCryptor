
struct rm_ctx
  union
    eax  dd ?
    ax	 dw ?
    union
      al db ?
      ah db ?
    ends
  ends
  union
    ecx  dd ?
    cx	 dw ?
    union
      cl db ?
      ch db ?
    ends
  ends
  union
    edx  dd ?
    dx	 dw ?
    union
      dl db ?
      dh db ?
    ends
  ends
  union
    ebx  dd ?
    bx	 dw ?
    union
      bl db ?
      bh db ?
    ends
  ends
  union
    ebp  dd ?
    bp	 dw ?
  ends
  union
    esi  dd ?
    si	 dw ?
  ends
  union
    edi  dd ?
    di	 dw ?
  ends
  efl	 dd ?
  ds	 dw ?
  es	 dw ?
ends

struct dc_pass
 size dd ?
 pass rw 128 
ends

struct e820_entry
  base dq ?
  size dq ?
  type dd ?
ends

struct e820_map
  n_map dd ?
  map	rb (64 * sizeof.e820_entry)
ends

struct bd_data
  sign1     dd 0FE0AC0AAh ; 01F53F55h
  sign2     dd 061BC9E1Bh ; 9E4361E4h
  bd_base   dd ?     ; boot data block base
  bd_size   dd ?     ; boot data block size (including 2kb for stack)
  password  dc_pass  ; bootauth password
  old_int15 dd ?     ; old int15 handler
  old_int13 dd ?     ; old int13 handler
  ; volatile data
  ret_32    dd ?     ; return address for RM <-> PM jump
  esp_16    dd ?     ; real mode stack
  ss_16     dw ?     ; real mode ss
  esp_32    dd ?     ; pmode stack
  segoff    dd ?     ; real mode call seg/off
  jump_rm   dd ?     ; real mode jump proc
  call_rm   dd ?     ; real mode call proc
  hook_ints dd ?     ; hook interrupts proc
  int_cbk   dd ?     ; protected mode callback
  boot_dsk  db ?     ; boot disk number
  rmc	    rm_ctx   ; real mode call context
  push_fl   dw ?     ; flags pushed to stack
  mem_map   e820_map ; new memory map
ends

struct boot_mod
  mod_sign  dd ? ; signature 'DCBM'
  raw_size  dd ? ; raw size
  virt_size dd ? ; virtual size
  entry_rva dd ? ; entry point RVA
  n_rels    dd ? ; relocations count
  relocs    dd ? ; relocations array
ends
