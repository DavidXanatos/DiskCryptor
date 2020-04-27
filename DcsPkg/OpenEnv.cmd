@echo off

call "C:\Program Files (x86)\Microsoft Visual Studio\2017\Enterprise\Common7\Tools\VsDevCmd.bat"

call "..\edksetup.bat"

set PATH=%PATH%;C:\nasm

echo ***********************************************
echo *  
echo *  dcs_bld.bat X64 VS2015
echo *  dcs_bld.bat X64Rel VS2015
echo *  
echo *  dcs_bld.bat IA32 VS2015
echo *  dcs_bld.bat IA32rel VS2015
echo *  
echo. 

cmd.exe