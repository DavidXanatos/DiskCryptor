@echo off
pushd %~dp0

call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\Tools\VsDevCmd.bat"

set NASM_PREFIX=%~dp0..\..\nasm\

rem call "..\edksetup.bat"
call "setenv.bat"

REM on a new edk2 don't forget to run edksetup.bat Rebuild

echo ***********************************************
echo *  
echo *  dcs_bld.bat X64
echo *  dcs_bld.bat X64Rel
echo *  
echo *  dcs_bld.bat IA32
echo *  dcs_bld.bat IA32Rel
echo *  
echo. 

cmd.exe
popd
