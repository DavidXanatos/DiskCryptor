@echo off
pushd %~dp0

if "%veracrypt_src%"=="" if exist %CD:~0,-28%\VeraCrypt\src set veracrypt_src=%CD:~0,-28%\VeraCrypt\src

if not "%1" == "auto" goto :manual
if not "%2" == "" if exist %2 set veracrypt_src=%2
set create_links_del_ren=D
goto :create_links

:manual
call :select_path "%veracrypt_src%" "Select VeraCrypt directory:"
set veracrypt_src=%select_path_result%

set /P YesNo=Create links[Y/N]?
if /I ["%YesNo%"]==["Y"] goto :check_links
goto :end

:check_links
if NOT EXIST common goto :create_links
set /P create_links_del_ren=Old links detected [D]elete or [R]ename?

:create_links
if NOT EXIST common mkdir common
call :create_link common\Crc.c
call :create_link common\Crc.h
call :create_link common\Crypto.c
call :create_link common\Crypto.h
call :create_link common\Endian.c
call :create_link common\Endian.h
call :create_link common\GfMul.h
call :create_link common\Password.h
call :create_link common\Pkcs5.c
call :create_link common\Pkcs5.h
call :create_link common\Tcdefs.h
call :create_link common\Volumes.c
call :create_link common\Volumes.h
call :create_link common\Xml.c
call :create_link common\Xml.h
call :create_link common\Xts.c
call :create_link common\Xts.h

if NOT EXIST crypto mkdir crypto
call :create_link crypto\GostCipher.c
call :create_link crypto\GostCipher.h
call :create_link crypto\Gost89_x64.asm Gost89_x64.nasm
call :create_link crypto\Streebog.c
call :create_link crypto\Streebog.h
call :create_link crypto\kuznyechik.c
call :create_link crypto\kuznyechik.h
call :create_link crypto\Aes.h
call :create_link crypto\Aeskey.c
call :create_link crypto\Aesopt.h
call :create_link crypto\Aestab.c
call :create_link crypto\Aestab.h
call :create_link crypto\Aes_hw_cpu.h
call :create_link crypto\Aes_hw_cpu.asm Aes_hw_cpu.nasm
call :create_link crypto\Aes_x64.asm Aes_x64.nasm
call :create_link crypto\Aes_x86.asm Aes_x86.nasm
call :create_link crypto\cpu.h
call :create_link crypto\cpu.c
call :create_link crypto\config.h
call :create_link crypto\misc.h
call :create_link crypto\Rmd160.c
call :create_link crypto\Rmd160.h
call :create_link crypto\Serpent.c
call :create_link crypto\Serpent.h
call :create_link crypto\Sha2.c
call :create_link crypto\Sha2.h
call :create_link crypto\Twofish.c
call :create_link crypto\Twofish.h
call :create_link crypto\Whirlpool.c
call :create_link crypto\Whirlpool.h
call :create_link crypto\Camellia.c
call :create_link crypto\Camellia.h

set create_link_skip_pushd=Y
call :create_link Boot\Windows\BootCommon.h
call :create_link Boot\Windows\BootDefs.h
set create_link_skip_pushd=N

@echo on
copy /Y Twofish_x64.S.precompiled Twofish_x64.obj
copy /Y Camellia_aesni_x64.S.precompiled Camellia_aesni_x64.obj
copy /Y Camellia_x64.S.precompiled Camellia_x64.obj
@echo off

goto :end

:create_link
if /I NOT ["%create_link_skip_pushd%"]==["Y"] pushd %~dp1
set fn=%~n1%~x1
if NOT ["%2"]==[""] set fn=%2
call :get_bak_name %fn%
if /I ["%create_links_del_ren%"]==["R"] ren %fn% %name_bak%
if EXIST "%fn%" del %fn%
@echo on
mklink /H %fn% %veracrypt_src%\%1
@echo off
if /I NOT ["%create_link_skip_pushd%"]==["Y"] popd
goto :eof

:get_bak_name
set name_bak=%1
:get_bak_name_retry
if NOT EXIST %name_bak% goto :eof
set name_bak=%name_bak%.sv
goto :get_bak_name_retry

rem call select path
:select_path
set select_path_default=%1
if not exist "%select_path_default%" echo not found %select_path_default%
set select_path_msg=%2
set select_path_msg=%select_path_msg:~1,-1%

:select_path_retry
set select_path_result=
set /p select_path_result=[%select_path_default:~1,-1%] %select_path_msg%
if ["%select_path_result%"]==[""] set select_path_result=%select_path_default:~1,-1%
if exist %select_path_result% goto :eof
echo cannot find %select_path_result%
goto :select_path_retry

:end
popd