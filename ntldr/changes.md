
# DiskCryptor v1.1

## [1.1.846.118] - 2014-07-09

### Improved:
- More accurate handling writing of the volume header. Reduced risk of data loss in the encryption process.

### Fixed:
- Small Windows 8 compatibility bugfixes.


## [1.1.836.118] - 2014-06-25

### Added: 
- Compatibility with Windows 8.0 and 8.1.

### Fixed: 
- BSOD when decrypting of formatted volume.

### Improved: 
- Internal improvements of code quality.


<br/><br/><br/> 
# DiskCryptor v1.0

## [1.0.802.118] - 2014-01-01

### Improved:
- Compatibility with perfmon (IO operation are showed in Disk Activity tab).
- Internal improvements of code quality.

### Fixed:
- Bug with a lost memory on some notebooks (e820 map enlarged to 64 items).


## [1.0.757.115] - 2013-01-03

### Added: 
- workaround for AES-NI support on Hyper-V.
- internal self-tests for PKDBF2 and XTS engines.

### Fixed:
- bug with data loss with some cases on VIA-PadLock.
- regression with SSD detection on Windows XP.
- bug with no FS creation when formatting from GUI.


## [1.0.757.115] - 2013-01-03

### Misc:
- Project moved to Visual Studio 2010.

### Improved:
- 3tb+ disks detection.


## [1.0.732.111] - Beta - 2011-05-23

### Added:
- Optimization for AVX instruction set.

### Improved:
- More stable benchmark results.
- Internal architecture.


## [1.0.716.109] - Beta - 2010-10-23

### Added: 
- Deny access to unencrypted devices option.
- New command-line options.

### Improved: 
- Compatibility of PXE booting.

### Fixed:
- Bugs.


## [1.0.711.107] - Beta - 2010-07-31

### Fixed: 
- Bugs.


## [1.0.709.107] - Beta - 2010-06-27

### Fixed:
- Bugs.


## [1.0.708.107] - Beta - 2010-06-27

### Added:
- Ability to change the size of the encrypted partitions.

### Removed: 
- Compatibility with Windows 2000. File dc_fsf.sys is not in use anymore.


## [1.0.667.107] - Beta - 2010-05-16

### Improved:
- Compatibility with third-party bootloaders.


## [1.0.666.106] - Beta - 2010-05-09

### Added:
- Optimized for SSE2 implementation of the Serpent.


## [1.0.664.106] - Beta - 2010-05-08

### Added:
- New optimizations special for SSD and fast RAID's.
- TRIM support for SSD and Disable TRIM option.


<br/><br/><br/> 
# DiskCryptor v0.9

## [0.9.593.106] - 2010-04-24

### Fixed:
- GUI freezes in Bootloader Configuration menu.


## [0.9.592.106] - 2010-04-05


## [0.9.583.106] - Beta - 2010-03-09

### Fixed:
- Unregistered Exception Handler bug.


## [0.9.573.105] - Beta - 2010-02-18

### Added: 
- Small bootloader only with AES. Required for compatibility with stupid and greedy BIOS'es in PXE boot mode.


## [0.9.569.103] - Beta - 2010-02-14

### Added:
- New optimization for AES and XTS mode, more performance now!
- Vista-PE plugin.

### Improved:
- Significantly performance of AES for VIA processors.
- Bootloader PXE compatibility.


## [0.9.562.101] - Beta - 2009-11-28

### Improved:
- Bootloader PXE compatibility.


## [0.9.561.98] - Beta - 2009-11-25

### Added:
- Support for Intel AES-NI instructions.

### Misc:
- Changed some small issues.


## [0.9.558.98] - Beta - 2009-09-12

### Added:
- Preventing system power state changes during the encryption process.

### Improved:
- Volume formatting speed.

### Fixed:
- Displaying program icon in the Add or Remove Programs.
- Incompatibility with Parallels Workstation BIOS.


<br/><br/><br/> 
# DiskCryptor v0.8

## [0.8] - 2009-07-28

### Added:
- Support for buggy XP configurations on Eee PC notebook.
- Support for Windows Embedded custom builds.

### Improved:
- Compatibility with AHCI mode in Intel chipsets.
- Compatibility with some server motherboards.
- Compatibility with Windows 7.
- Some minor issues.


<br/><br/><br/> 
# DiskCryptor v0.7

## [0.7] - 2009-05-31

### Added:
- Automatically delete mount points added when mounting.
- CD encryption feature.
- Compatibility with Windows 7.
- Correct signature of drivers and other executable files (special thanks to ReactOS Foundation).
- exFAT support.
- Installer.
- Load Boot Disk MBR option to invalid password actions in bootloader.
- New command-line keys.
- New implementation of AES optimized for CPUs with small instruction cache.
- Support for booting from software RAID1 volumes.
- Support for disks with large sector size.
- VIA PadLock AES acceleration support.

### Improved:
- More stable benchmark results.
- SCSI disks name detection.

## Fixed:
- Small bugs.


<br/><br/><br/> 
# DiskCryptor v0.6

## [0.6a] - 2009-01-19

### Added:
- Optional hiding $dcsys$ file.
- Resuming encryption after exit from hibernate mode.

### Improved:
- $dcsys$ file protection.

### Fixed:
- Bug with HDD name detection.
- Bug with Vista hang on shutdown.
- Small bugs in GUI.


## [0.6] - 2009-01-14

### Fixed:
- Bug with volume corruption when defragmenting.
- Incompatibility with PGP WDE 9.x.


<br/><br/><br/> 
# DiskCryptor v0.5

## [0.5] - 2008-12-26

### Added:
- Hibernation support in partial-encrypted state.
- Keyfiles support.

### Removed:
- Compatibility with TrueCrypt and previous DiskCryptor versions.
- LRW encryption mode.
- SHA1-HMAC PRF function.

### Fixed:
- Resolved many boot-encryption issues.
- Many hardware compatibility issues.

### Misc:
- Password length limit increased to 128 symbols.


<br/><br/><br/> 
# DiskCryptor v0.4

## [0.4] - 2008-09-27

### Added:
- Twofish, Serpent ciphers and cipher chains.
- XTS encryption mode.
- HMAC-SHA-512 Pkcs5.2 PRF function.
- Partition re-encrypt operation.
- Partition formatting with encryption.
- Backup/restore volume header operations.
- Mount point management when mounting/unmounting.
- Key '-p' to console version for entering password from command-line.

### Improved:
- Multi-cpu parallelized encryption.
- Embedded benchmark.
- Compatibility with buggy and stupid BIOSes.

### Removed:
- Floppy bootloaders support.

### Fixed:
- Many bugs.


<br/><br/><br/> 
# DiskCryptor v0.3

## [0.3] - 2008-07-17

### Added:
- Console version of DiskCryptor.
- Support for installing bootloader to CD or any bootable device.
- embedded password feature in bootloader.
- Multi boot and advanced booting options.
- Limited QWERTZ and AZERTY keyboard layouts support when pre-boot authentication.
- Power safe encryption, encryption stopping and reverting.
- Password prompt when decryption and changing password.
- Advanced IO queue options. This option enable multi CPU I/O requests splitting (increase perfomance to 50–400%).
- Optional authentication timeout to pre-boot authentication.
- Retry authentication option to pre-boot authentication.
- Disk speed testing tool.
- Embedded volume header backup. Backup header encrypted with different salt and needed for resiliency.
- Skipping bad sectors when encryption.
- Password strength meter.

### Security improvement:
- Added data wiping option in encryption process.
- Added clearing BIOS keyboard buffer to prevent password leakage ([details](http://www.ouah.org/Bios_Information_Leakage.txt)).

### Improved:
- Autorun on Windows Vista.
- Optimized internal driver routines, improved synchronization.
- Random number generator, more entropy sources and very strong security design.
- Removable devices encryption, more correct IRP handling.

### Fixed:
- Small bugs.


<br/><br/><br/> 
# DiskCryptor v0.2

## [0.2.6] - Beta - 2008-03-18

### Added:
- Dynamical (LDM) disks support.
- New bootloader architecture.
- Plugin for BartPE.
- Support for Windows Server 2008.

### Security improvement:
- Added automatically erasing keys in memory when shutdown, reboot or hibernate to prevent ["Cold Boot" Attacks](http://en.wikipedia.org/wiki/Cold_boot_attack).
- Added avoiding [LRW weakness](http://grouper.ieee.org/groups/1619/email/msg00923.html).
- When changing a password made erase volume header by Gutmann method to prevent restore previous password by magnetic microscopy.

### Improved:
- Auto mounting.
- Random number generator.
- Support for encryption devices with non-standard MaximumTransferLength.

### Fixed:
- Bug with encryption process may be stopped if other process has high CPU usage.
- Bug with impossible to use Shadow copy service in encrypted volume on win2003.
- Bug with possible encryption error on volumes bigger that 4Gb.


## [0.2.5] - Beta - 2008-01-11

### Added:
- Crash dumps and hiberfil encryption feature.
- Data leak control. This feature preventing data leaks through non-encrypted system files.

### Improved:
- Volume encryption/decryption speed.

### Fixed:
- GUI crash on Vista 64.
- Bug with extended partition corruption on boot disk.
- Bug with impossible to boot from FAT16 partition.
- Bug with decryption speed test.
- Small bugs in bootloader.

## [0.2] - Beta - 2007-12-19

### Added:
- Bootloader settings. Changing messages of entering password, and incorrect password.
- Command line bootloader fix tool.
- Encryption speed test.
- Full support for removable devices (external disks, USB-Sticks, card readers).
- Hot keys.
- Program settings.
- Some fool proof checks.
- Setting behavior loader when entering an incorrect password (system halt/reboot).
- Support for SCSI devices.
- About box.

### Improved:
- Random numbers generator used to generate keys. Added new sources of entropy.
- Extreme improved cryptographic functions for the x86 architecture. Increased speed in 1.5–1.7 times compared with TrueCrypt 4.3.
- Full support for Windows Vista.
- Removed license violations with TrueCrypt collective license. All TrueCrypt code rewritten.
- Rewritten most of the boot code, it becomes smaller.

### Fixed:
- BSOD when extraction removable device in the encryption/decryption progress.
- Bug with bootloader not installed, if you starting encryption process without admin privilege.
- Bug with decryption volume in SATA ACHI disk.
- Bug with it is impossible formatting encrypted volume.
- Many small issues with some flashes and card readers.

### Misc:
- Now you can change name of the driver during installation.
- The license is changed to GNU GPLv3.


<br/><br/><br/> 
# DiskCryptor v0.1

## [0.1] - Beta - 2007-11-19

- First public release.

