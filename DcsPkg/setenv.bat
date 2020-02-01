@echo off
pushd "%~dp0"

if not defined PYTHONHOME (
   echo PYTHONHOME not found!
   goto :end
)

if defined VS100COMNTOOLS (
   call "%VS100COMNTOOLS%\vsvars32.bat"
   goto :initialize
) else (
   echo MSVS2010 not found!
   goto :end
)

:initialize

if not defined NASM_PREFIX set NASM_PREFIX=c:\Tools\nasm\
if not defined EDK_PREFIX set EDK_PREFIX=c:\Tools\edk2

call :updatepath "%PYTHONHOME%"
call :updatepath "%NASM_PREFIX%"

if not defined EDK_TOOLS_BIN (
   pushd "%EDK_PREFIX%"
   call edksetup.bat
   popd
)

goto :end

:updatepath
set appendpath=%~1
for %%A in ("%path:;=";"%") do (
   if /I "%~1"=="%%~A" (
      echo %1 in path found
      set appendpath=
   )
rem   echo %%~A
)
if defined appendpath set path=%path%;%appendpath%
goto :eof

:end
popd