@echo off

rem ============================================================
rem  Add DiskCryptor to an OFFLINE WinPE
rem
rem  Usage:
rem    AddToPE.cmd  [drive letter, f:]  [wim index, 2]
rem
rem  Notes:
rem  - Requires admin.
rem ============================================================

if "%~1"=="" goto :usage
if "%~2"=="" goto :usage

set WIM_FILE=%1\sources\boot.wim
set WIM_INDEX=%2
set MOUNT=C:\Mount
set OFFLINE=HKLM\PE_SYSTEM
set HIVE=%MOUNT%\Windows\System32\Config\SYSTEM

if not exist "%WIM_FILE%" goto :usage

goto :args_ok

:usage
echo Usage: AddToPE.cmd [drive letter] [wim index]
echo Example: AddToPE.cmd f: 2
exit /b 2

:args_ok


echo Mounting wim file...
mkdir %MOUNT%
dism /Mount-Wim /WimFile:%WIM_FILE% /Index:%WIM_INDEX% /MountDir:%MOUNT%

REM simple add does not work
REM dism /Image:%MOUNT% /Add-Driver /Driver:%~dp0dcrypt.in


reg query "%OFFLINE%" >nul 2>nul
if not errorlevel 1 (
  echo INFO: Hive already loaded at %OFFLINE%, attempting unload...
  reg unload "%OFFLINE%" >nul 2>nul
)

echo Loading offline SYSTEM hive...
reg load "%OFFLINE%" "%HIVE%"
if errorlevel 1 (
  echo ERROR: Failed to load offline hive.
  goto end
)

echo Importing registry file...
reg import "%~dp0dcrypt_pe.reg"
if errorlevel 1 (
  echo ERROR: reg import failed.
  echo Attempting to unload hive...
  reg unload "%OFFLINE%" >nul 2>nul
  goto end
)

echo Unloading offline hive...
reg unload "%OFFLINE%"
if errorlevel 1 (
  echo ERROR: Failed to unload hive. It may still be mounted at %OFFLINE%.
)

echo Copying files...
copy %~dp0dcrypt.sys "%MOUNT%\Windows\System32\Drivers\"
mkdir "%MOUNT%\Program Files\dcrypt"
copy %~dp0* "%MOUNT%\Program Files\dcrypt\"

:end

echo Enabling Test Signing ...
bcdedit /store %MOUNT%\Windows\boot\DVD\EFI\bcd /set {default} testsigning on
REM bcdedit /store %MOUNT%\Windows\boot\DVD\EFI\bcd /set {default} nointegritychecks on

echo Unmounting wim file...
dism /Unmount-Wim /MountDir:%MOUNT% /Commit
REM dism /Unmount-Wim /MountDir:%MOUNT% /Discard
rmdir %MOUNT%


