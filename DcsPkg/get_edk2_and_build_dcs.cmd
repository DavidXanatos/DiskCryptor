cd %~dp0..\..
REM git clone --branch edk2-stable202511 --recurse-submodules https://github.com/tianocore/edk2.git
REM git clone --branch edk2-stable202511 --depth 1 --recurse-submodules --shallow-submodules https://github.com/tianocore/edk2.git

dir

cd edk2

call edksetup.bat Rebuild


mklink /J DcsPkg %~dp0
cd DcsPkg

dir

call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\Tools\VsDevCmd.bat"

set NASM_PREFIX=%~dp0..\DCrypt\tools\nasm\
dir %NASM_PREFIX%

call setenv.bat

call dcs_bld.bat X64Rel