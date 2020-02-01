@echo off
call dcs_bld.bat X64 VS2015

if ERRORLEVEL 1 goto :exit

set DCS=DCS
mkdir %1\EFI\%DCS%\

if ["%1"]==[""] goto :exit
echo Copying Files to USB %1 ...
copy %~dp0\..\Build\DcsPkg\DEBUG_VS2015x86\X64\DcsBoot.efi %1\EFI\%DCS%\DcsBoot.efi /y
copy %~dp0\..\Build\DcsPkg\DEBUG_VS2015x86\X64\DcsInt.efi %1\EFI\%DCS%\DcsInt.dcs /y
copy %~dp0\..\Build\DcsPkg\DEBUG_VS2015x86\X64\DcsInfo.efi %1\EFI\%DCS%\DcsInfo.dcs /y
copy %~dp0\..\Build\DcsPkg\DEBUG_VS2015x86\X64\DcsCfg.efi %1\EFI\%DCS%\DcsCfg.dcs /y
rem copy %~dp0\..\Build\DcsPkg\DEBUG_VS2015x86\X64\DcsRe.efi %1\EFI\Boot\bootx64.efi /y
rem copy %~dp0\..\Build\DcsPkg\RELEASE_VS2015x86\X64\LegacySpeaker.efi %1\EFI\%DCS%\LegacySpeaker.dcs /y

:exit