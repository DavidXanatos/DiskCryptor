VeraCrypt EFI Bootloader for EFI Windows system encryption (LGPL)

DcsProp - Configuration for the loader
SecureBoot - certificates for Secure boot configuration

Modules:
DcsBoot.efi - Starter
DcsRe.efi  - Recovery tool (decrypt etc)
DcsCfg.dcs - configuration from EFI shell
DcsBml.dcs - Boot menu lock runtime driver to prvent Windows modification of boot order
DcsInt.dcs - PreBoot authorization 
DcsInfo.dcs - PlatformInfo generation
LegacySpeaker.dcs - driver for ordinary speaker (beep)
