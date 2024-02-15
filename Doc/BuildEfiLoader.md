# Build EFI Bootloader

How to build the DiskCryptor EFI bootloader.

## Install Tools

Install the requirements for the EFI Software Development Kit (EDK II) as described in the [tutorial][1]:

- Install Python >= 3.7
- Install Visual Studio (2015-2019 recommended)
- Install NASM to `C:\nasm\`

## Checkout Code

Run the following commands in your source code directory (e.g. `D:\Git`):

    git clone https://github.com/DavidXanatos/DiskCryptor.git
    git clone --no-checkout https://github.com/tianocore/edk2
    cd edk2
    git checkout -b branch-201911 edk2-stable201911
    git submodule update --init --recursive

## Setup EDK

This step builds some internal build tools. It is only required once.

Run the following commands in the edk2 directory. Replace `VS2019` by the Visual Studio version of your choice.

    set NASM_PREFIX=C:\nasm\
    edksetup.bat Rebuild VS2019

## Build Bootloader

Run the following commands in your favored build directory (e.g. `D:\Build\DiskCryptor`). The binaries will be copied to the `Export` subdirectory (e.g. `D:\Build\DiskCryptor\Export`).

Build debug configuration (32 and 64 bit):

    D:\Git\DiskCryptor\DcsPkg\MkDbg.cmd

Build release configuration (32 and 64 bit):

    D:\Git\DiskCryptor\DcsPkg\MkRel.cmd

Alternatively you can open an interactive command prompt and build individual configurations by calling:

    D:\Git\DiskCryptor\DcsPkg\OpenEnv.cmd
    dcs_bld.bat X64
    dcs_bld.bat X64Rel
    dcs_bld.bat IA32
    dcs_bld.bat IA32Rel

The working directories and other parameters can be customized by setting environment variables. Have a look at `DcsPkg\setenv.bat`.


[1]: https://github.com/tianocore/tianocore.github.io/wiki/Getting-Started-with-EDK-II
