@echo off
@if "%VS100COMNTOOLS%"=="" goto :error_no_vstools
@call "%VS100COMNTOOLS%\vsvars32.bat"

devenv dcrypt.sln /Build "Release|win32"
@if errorlevel 1 goto :error_build_fail
devenv dcrypt.sln /Build "Release|x64"
@if errorlevel 1 goto :error_build_fail


@goto end
:error_no_vstools
@set errorlevel=1
@echo ERROR: VS100COMNTOOLS variable is not set. 
@goto end
:error_build_fail
@echo ERROR: Can not build solution. 
@goto end

:end