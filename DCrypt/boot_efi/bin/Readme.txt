The source code for Disk Cryptography Services (DCS) EFI bootloader files is available at: https://github.com/DavidXanatos/DiskCryptor/DcsPkg

DCS uses EDK II as its UEFI development environment.

DCS is licensed under LGPL: https://opensource.org/licenses/LGPL-3.0

Here are the steps to build DCS (Visual Studio 2015, or 2017 with 2015 toolchain, should be installed)
  * Clone EDK: git clone https://github.com/tianocore/tianocore.github.io.git edk2
  * Switch to UDK2015 branch: git checkout UDK2015
  * Copy DCS as DcsPkg inside edk2 folder
  * Setup EDK by typing edksetup.bat at the root of folder edk2
  * change directory to DcsPkg and then type setenv.bat.
  * to build a x64 release type dcs_bld.bat X64Rel, for x86 release dcs_bld.bat IA32Rel, and for debug without "rel"
  * After the build is finished, EFI bootloader files will be present at edk2\Build\DcsPkg\...
  