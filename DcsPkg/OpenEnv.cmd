@echo off
pushd %~dp0

call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\Common7\Tools\VsDevCmd.bat"

call "..\edksetup.bat"

set PATH=%PATH%;C:\nasm

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
