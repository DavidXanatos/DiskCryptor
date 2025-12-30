@echo off
call %~dp0setenv.bat
call %~dp0dcs_bld.bat X64rel  || goto :exit
REM call %~dp0dcs_bld.bat IA32rel || goto :exit
REM call %~dp0dcs_bld.bat A64rel || goto :exit

:exit
