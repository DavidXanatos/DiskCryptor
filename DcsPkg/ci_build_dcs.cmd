cd %~dp0..\..\edk2

mklink /J DcsPkg %~dp0
cd DcsPkg

call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\Tools\VsDevCmd.bat"

set NASM_PREFIX=%~dp0..\DCrypt\tools\nasm\
dir %NASM_PREFIX%

set DCS_EXPORT=%~dp0..\DCrypt\boot_efi\bin

call setenv.bat

REM fix
REM \edk2\CryptoPkg\Library\OpensslLib\openssl\crypto\bn\bn_gcd.c(659): error C2220: the following warning is treated as an error
REM \edk2\CryptoPkg\Library\OpensslLib\openssl\crypto\bn\bn_gcd.c(659): warning C4319: '~': zero extending 'unsigned int' to 'unsigned __int64' of greater size
REM \edk2\CryptoPkg\Library\OpensslLib\openssl\crypto\bn\bn_gcd.c(671): warning C4319: '~': zero extending 'unsigned int' to 'unsigned __int64' of greater size
set CL=/wd4319 %CL%

call dcs_bld.bat X64Rel
