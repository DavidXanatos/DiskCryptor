@echo off
@pushd %~dp0
@if "%INNOSETUP%"=="" goto :error_no_innosetup
@call make_dc.bat
@if errorlevel 1 goto :end

@pushd setup
"%INNOSETUP%\iscc.exe" /cc setup.iss
@popd

@goto end

:error_no_innosetup
@echo ERROR: INNOSETUP variable is not set. 
@goto end

:end
@popd
@pause