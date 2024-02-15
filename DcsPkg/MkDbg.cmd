@echo off
call "%~dp0setenv.bat"
call "%~dp0dcs_bld.bat" X64 || goto :exit
call "%~dp0dcs_bld.bat" IA32 || goto :exit

if ["%1"]==[""] goto :exit
set DCS=DCS
mkdir %1\EFI\%DCS%\
echo Copying Files to USB %1 ...
copy /y %DCS_EXPORT%\DcsBoot.efi       %1\EFI\%DCS%\DcsBoot.efi
copy /y %DCS_EXPORT%\DcsInt.dcs        %1\EFI\%DCS%\DcsInt.dcs
copy /y %DCS_EXPORT%\DcsInfo.dcs       %1\EFI\%DCS%\DcsInfo.dcs
copy /y %DCS_EXPORT%\DcsCfg.dcs        %1\EFI\%DCS%\DcsCfg.dcs
rem copy /y %DCS_OUTPUT%\DcsRe.efi         %1\EFI\Boot\bootx64.efi
rem copy /y %DCS_OUTPUT%\LegacySpeaker.dcs %1\EFI\%DCS%\LegacySpeaker.dcs

:exit
