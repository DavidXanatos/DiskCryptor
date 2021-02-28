@echo off
pushd %~dp0

call setenv.bat

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
