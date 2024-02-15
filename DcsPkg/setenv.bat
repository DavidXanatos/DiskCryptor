@echo off

if not defined WORKSPACE  set WORKSPACE=%cd%
if not defined DCS_EXPORT set DCS_EXPORT=%WORKSPACE%\Export
if not defined DCS_ARCH   set DCS_ARCH=X64
if not defined DCS_TYPE   set DCS_TYPE=DEBUG

if not defined DCS_TOOLCHAIN (
  if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019" (
    set DCS_TOOLCHAIN=VS2019
    goto done_dcs_toolchain
  )
  if exist "C:\Program Files (x86)\Microsoft Visual Studio\2017" (
    set DCS_TOOLCHAIN=VS2017
    goto done_dcs_toolchain
  )
  if exist "C:\Program Files (x86)\Microsoft Visual Studio\2015" (
    set DCS_TOOLCHAIN=VS2015x86
    goto done_dcs_toolchain
  )
  echo Error: DCS_TOOLCHAIN not set
  goto :end
)
:done_dcs_toolchain

if not defined NASM_PREFIX (
  if exist "C:\nasm" (
    set NASM_PREFIX=C:\nasm\
    goto :done_nasm_prefix
  )
  echo Error: NASM_PREFIX not set
  goto :end
)
:done_nasm_prefix

if not defined EDK_PREFIX (
  if exist "%cd%\edksetup.bat" (
    set EDK_PREFIX=%cd%
    goto :done_edk_prefix
  )
  if exist "%cd%\edk2\edksetup.bat" (
    set EDK_PREFIX=%cd%\edk2\..
    goto :done_edk_prefix
  )
  if exist "%cd%\..\edksetup.bat" (
    set EDK_PREFIX=%cd%\..
    goto :done_edk_prefix
  )
  if exist "%%~dp0..\edksetup.bat" (
    set EDK_PREFIX=%~dp0..
    goto :done_edk_prefix
  )
  if exist "%~dp0..\..\edk2\edksetup.bat" (
    set EDK_PREFIX=%~dp0..\..\edk2
    goto :done_edk_prefix
  )
  echo Error: EDK_PREFIX not set
  goto :end
)
:done_edk_prefix

set PACKAGES_PATH=%~dp0..;%EDK_PREFIX%
call %EDK_PREFIX%\edksetup.bat %DCS_TOOLCHAIN%

:end
