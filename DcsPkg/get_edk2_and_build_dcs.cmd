cd %~dp0..\..
dir

REM git clone --branch edk2-stable202511 --recurse-submodules https://github.com/tianocore/edk2.git
REM git clone --branch edk2-stable202511 --depth 1 --recurse-submodules --shallow-submodules https://github.com/tianocore/edk2.git
cd edk2

call edksetup.bat Rebuild

mklink /J DcsPkg %~dp0
cd DcsPkg

dir

call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\Tools\VsDevCmd.bat"

set NASM_PREFIX=%~dp0..\DCrypt\tools\nasm\
dir %NASM_PREFIX%

call setenv.bat

REM fix
REM \edk2\CryptoPkg\Library\OpensslLib\openssl\crypto\bn\bn_gcd.c(659): error C2220: the following warning is treated as an error
REM \edk2\CryptoPkg\Library\OpensslLib\openssl\crypto\bn\bn_gcd.c(659): warning C4319: '~': zero extending 'unsigned int' to 'unsigned __int64' of greater size
REM \edk2\CryptoPkg\Library\OpensslLib\openssl\crypto\bn\bn_gcd.c(671): warning C4319: '~': zero extending 'unsigned int' to 'unsigned __int64' of greater size
set CL=/wd4319 %CL%

call dcs_bld.bat X64Rel


mkdir %~dp0.\Export
copy %~dp0..\..\edk2\Export\* %~dp0.\Export\
