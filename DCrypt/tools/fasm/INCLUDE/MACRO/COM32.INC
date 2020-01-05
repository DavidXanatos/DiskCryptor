
; Macroinstructions for interfacing the COM (Component Object Model) classes

macro cominvk object,proc,[arg]
 { common
    if ~ arg eq
   reverse
     pushd arg
   common
    end if
    assert defined com.object.#object ; must be a COM object
    mov eax,[object]
    push eax
    mov eax,[eax]
    call [eax+object#.#proc] }

macro comcall handle,interface,proc,[arg]
 { common
    if ~ arg eq
   reverse
     pushd arg
   common
    end if
    assert defined com.interface.#interface ; must be a COM interface
    if handle eqtype eax | handle eqtype 0
     push handle
     local ..handle
     label ..handle at handle
     mov eax,[..handle]
    else
     mov eax,handle
     push eax
     mov eax,[eax]
    end if
    call [eax+interface#.#proc] }

macro interface name,[proc]
 { common
    struc name \{
    match any, fields@struct \\{ fields@struct equ fields@struct,.,name, \\}
    match , fields@struct \\{ . dd ?
    virtual at 0
   forward
    .#proc dd ?
   common
    com.object.\#. = com.interface.#name
    end virtual \\} \}
    virtual at 0
   forward
     name#.#proc dd ?
   common
     com.interface.#name = $ shr 2
    end virtual }

