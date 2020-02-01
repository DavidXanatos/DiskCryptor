    .386
    .model  flat,C
    .code

;------------------------------------------------------------------------------
; VOID
; EFIAPI
; CpuHalt (
;   VOID
;   );
;------------------------------------------------------------------------------
EfiCpuHalt    PROC
    cli
l:  hlt
    jmp l
    ret
EfiCpuHalt    ENDP

    END
