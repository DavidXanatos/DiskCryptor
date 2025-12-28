cd ..\..
REM git clone --branch edk2-stable202511 --recurse-submodules https://github.com/tianocore/edk2.git
git clone --branch edk2-stable202511 --depth 1 --recurse-submodules --shallow-submodules https://github.com/tianocore/edk2.git
cd edk2

call edksetup.bat Rebuild

mklink /J DcsPkg ..\DiskCryptor\DcsPkg
cd DcsPkg

call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\Tools\VsDevCmd.bat"

set NASM_PREFIX=%~dp0..\..\DiskCryptor\DCrypt\tools\nasm\

call setenv.bat

call dcs_bld.bat X64Rel