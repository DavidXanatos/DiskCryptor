;------------------------------------------------------------------------------
; VOID
; EFIAPI
; EfiCpuHalt (
;   VOID
;   );
;------------------------------------------------------------------------------
    AREA    |.text|, CODE, READONLY

    EXPORT  EfiCpuHalt

EfiCpuHalt PROC
    ; Disable all interrupts (DAIF bits: Debug, SError, IRQ, FIQ)
    msr     daifset, #0xf

loop
    ; Halt processor until interrupt
    wfi
    ; Loop forever
    b       loop

    ; Unreachable, but keep for consistency with x64 version
    ret

    ENDP

    END
