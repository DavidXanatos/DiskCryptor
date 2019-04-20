
macro op32 code
{
   use32
   db 66h
   #code 
   use16
}

macro call32 fn { op32 call fn }
macro jmp32  fn { op32 jmp  fn }
macro jz32   fn { op32 jz   fn }
macro jnz32  fn { op32 jnz  fn } 
macro jcxz32 fn { op32 jcxz fn }
macro jc32   fn { op32 jc   fn }
macro jnc32  fn { op32 jnc  fn }

