@echo off
call %~dp0setenv.bat
call %~dp0dcs_bld.bat X64rel  || goto :exit
call %~dp0dcs_bld.bat IA32rel || goto :exit

:exit
