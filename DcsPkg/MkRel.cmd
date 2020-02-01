@echo off
call dcs_bld.bat X64rel VS2015
call dcs_bld.bat IA32rel VS2015

if ERRORLEVEL 1 goto :exit

mkdir %~dp0\build

copy %~dp0\..\Build\DcsPkg\RELEASE_VS2015x86\X64\DcsBoot.efi %~dp0\build\DcsBoot.efi /y
copy %~dp0\..\Build\DcsPkg\RELEASE_VS2015x86\X64\DcsInt.efi %~dp0\build\DcsInt.dcs /y
copy %~dp0\..\Build\DcsPkg\RELEASE_VS2015x86\X64\DcsInfo.efi %~dp0\build\DcsInfo.dcs /y
rem copy %~dp0\..\Build\DcsPkg\RELEASE_VS2015x86\X64\DcsCfg.efi %~dp0\build\DcsCfg.dcs /y
copy %~dp0\..\Build\DcsPkg\RELEASE_VS2015x86\X64\LegacySpeaker.efi %~dp0\build\LegacySpeaker.dcs /y
copy %~dp0\..\Build\DcsPkg\RELEASE_VS2015x86\X64\DcsRe.efi %~dp0\build\DcsRe.efi /y

copy %~dp0\..\Build\DcsPkg\RELEASE_VS2015x86\IA32\DcsBoot.efi %~dp0\build\DcsBoot32.efi /y
copy %~dp0\..\Build\DcsPkg\RELEASE_VS2015x86\IA32\DcsInt.efi %~dp0\build\DcsInt32.dcs /y
copy %~dp0\..\Build\DcsPkg\RELEASE_VS2015x86\IA32\DcsInfo.efi %~dp0\build\DcsInfo32.dcs /y
rem copy %~dp0\..\Build\DcsPkg\RELEASE_VS2015x86\IA32\DcsCfg.efi %~dp0\build\DcsCfg32.dcs /y
copy %~dp0\..\Build\DcsPkg\RELEASE_VS2015x86\IA32\LegacySpeaker.efi %~dp0\build\LegacySpeaker32.dcs /y
copy %~dp0\..\Build\DcsPkg\RELEASE_VS2015x86\IA32\DcsRe.efi %~dp0\build\DcsRe32.efi /y

:exit