@echo off

set DCS_PKG_PATH="%~dp0DcsPkg.dsc"

if not defined DCS_ARCH      echo DCS_ARCH not set.      & goto :noenv
if not defined DCS_TYPE      echo DCS_TYPE not set.      & goto :noenv
if not defined DCS_TOOLCHAIN echo DCS_TOOLCHAIN not set. & goto :noenv
if not defined DCS_EXPORT    echo DCS_EXPORT not set.    & goto :noenv
if not defined WORKSPACE     echo WORKSPACE not set.     & goto :noenv
goto :X64

:noenv
echo Environment variable missing. Please run setenv.bat.
exit /b 1

:X64
if /I NOT ["%1"]==["X64"] goto :X64Rel
set DCS_ARCH=X64
set DCS_TYPE=DEBUG
goto :bld

:X64Rel
if /I NOT ["%1"]==["X64Rel"] goto :IA32
set DCS_ARCH=X64
set DCS_TYPE=RELEASE
goto :bld

:IA32
if /I NOT ["%1"]==["IA32"] goto :IA32Rel
set DCS_ARCH=IA32
set DCS_TYPE=DEBUG
goto :bld

:IA32Rel
if /I NOT ["%1"]==["IA32Rel"] goto :bld
set DCS_ARCH=IA32
set DCS_TYPE=RELEASE

:bld
if /I ["%2"]==["VS2010"] set DCS_TOOLCHAIN=VS2010x86
if /I ["%2"]==["VS2012"] set DCS_TOOLCHAIN=VS2012x86
if /I ["%2"]==["VS2013"] set DCS_TOOLCHAIN=VS2013x86
if /I ["%2"]==["VS2015"] set DCS_TOOLCHAIN=VS2015x86
if /I ["%2"]==["VS2017"] set DCS_TOOLCHAIN=VS2017
if /I ["%2"]==["VS2019"] set DCS_TOOLCHAIN=VS2019

set BIN_POSTFIX=
if "%DCS_ARCH%"=="IA32" set BIN_POSTFIX=32

call %~dp0bld.bat -t %DCS_TOOLCHAIN% -DSECURE_BOOT_ENABLE=1 -p %DCS_PKG_PATH% -b %DCS_TYPE% -a %DCS_ARCH%
if ERRORLEVEL 1 goto :exit

if exist SecureBoot\keys\DCS_sign.pfx (
  call SecureBoot\efi_sign.bat ..\Build\DcsPkg\%DCS_TYPE%_%DCS_TOOLCHAIN%\%DCS_ARCH%\DcsBml.efi        SecureBoot\keys\DCS_sign.pfx SecureBoot\certs\DCS_sign.crt 
  call SecureBoot\efi_sign.bat ..\Build\DcsPkg\%DCS_TYPE%_%DCS_TOOLCHAIN%\%DCS_ARCH%\DcsBoot.efi       SecureBoot\keys\DCS_sign.pfx SecureBoot\certs\DCS_sign.crt
  call SecureBoot\efi_sign.bat ..\Build\DcsPkg\%DCS_TYPE%_%DCS_TOOLCHAIN%\%DCS_ARCH%\DcsCfg.efi        SecureBoot\keys\DCS_sign.pfx SecureBoot\certs\DCS_sign.crt
  call SecureBoot\efi_sign.bat ..\Build\DcsPkg\%DCS_TYPE%_%DCS_TOOLCHAIN%\%DCS_ARCH%\DcsInfo.efi       SecureBoot\keys\DCS_sign.pfx SecureBoot\certs\DCS_sign.crt
  call SecureBoot\efi_sign.bat ..\Build\DcsPkg\%DCS_TYPE%_%DCS_TOOLCHAIN%\%DCS_ARCH%\DcsInt.efi        SecureBoot\keys\DCS_sign.pfx SecureBoot\certs\DCS_sign.crt
  call SecureBoot\efi_sign.bat ..\Build\DcsPkg\%DCS_TYPE%_%DCS_TOOLCHAIN%\%DCS_ARCH%\DcsRe.efi         SecureBoot\keys\DCS_sign.pfx SecureBoot\certs\DCS_sign.crt
  call SecureBoot\efi_sign.bat ..\Build\DcsPkg\%DCS_TYPE%_%DCS_TOOLCHAIN%\%DCS_ARCH%\LegacySpeaker.efi SecureBoot\keys\DCS_sign.pfx SecureBoot\certs\DCS_sign.crt
)

mkdir %DCS_EXPORT%
copy /y %WORKSPACE%\Build\DcsPkg\%DCS_TYPE%_%DCS_TOOLCHAIN%\%DCS_ARCH%\DcsBml.efi        %DCS_EXPORT%\DcsBml%BIN_POSTFIX%.efi
copy /y %WORKSPACE%\Build\DcsPkg\%DCS_TYPE%_%DCS_TOOLCHAIN%\%DCS_ARCH%\DcsBoot.efi       %DCS_EXPORT%\DcsBoot%BIN_POSTFIX%.efi
copy /y %WORKSPACE%\Build\DcsPkg\%DCS_TYPE%_%DCS_TOOLCHAIN%\%DCS_ARCH%\DcsCfg.efi        %DCS_EXPORT%\DcsCfg%BIN_POSTFIX%.dcs
copy /y %WORKSPACE%\Build\DcsPkg\%DCS_TYPE%_%DCS_TOOLCHAIN%\%DCS_ARCH%\DcsInfo.efi       %DCS_EXPORT%\DcsInfo%BIN_POSTFIX%.dcs
copy /y %WORKSPACE%\Build\DcsPkg\%DCS_TYPE%_%DCS_TOOLCHAIN%\%DCS_ARCH%\DcsInt.efi        %DCS_EXPORT%\DcsInt%BIN_POSTFIX%.dcs
copy /y %WORKSPACE%\Build\DcsPkg\%DCS_TYPE%_%DCS_TOOLCHAIN%\%DCS_ARCH%\DcsRe.efi         %DCS_EXPORT%\DcsRe%BIN_POSTFIX%.efi
copy /y %WORKSPACE%\Build\DcsPkg\%DCS_TYPE%_%DCS_TOOLCHAIN%\%DCS_ARCH%\LegacySpeaker.efi %DCS_EXPORT%\LegacySpeaker%BIN_POSTFIX%.dcs

:exit
