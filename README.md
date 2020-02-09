# DiskCryptor

DiskCryptor is an open encryption solution that offers encryption of all disk partitions, including the system partition. The fact of openess goes in sharp contrast with the current situation, where most of the software with comparable functionality is completely proprietary, which makes it unacceptable to use for protection of confidential data.

Originally DiskCryptor was developed as a replacement for DriveCrypt Plus Pack and PGP WDE by ntldr back at [diskcryptor.net](https://diskcryptor.net), however since there was no more development since 2014 we decided to continue the development on our own here. The new releases of  DiskCryptor are ment as a replacement for BitLocker from Microsoft as **[BitLocker can NOT be considered secure](https://www.diskcryptor.org/why-not-bitlocker/)**.

We have updated DiskCryptor for use with windows 10, adding a UEFI/GPT bootloader as well as other minor fixes to improve windows 10 compatybility. We aim at further improving and maintaining windows 10 compatybility.

This website, for now, mostly mirrors informations from the old wiki, as we develop new features new content will be added to reflect the changes in the new builds.


## Program Features

</h2></td>
</tr>
<tr class="odd">
<td><ul>
<li><strong>Support of <a href="https://en.wikipedia.org/wiki/Advanced_Encryption_Standard">AES</a>, <a href="https://en.wikipedia.org/wiki/Twofish">Twofish</a>, <a href="https://en.wikipedia.org/wiki/Serpent_(cipher)">Serpent</a> encryption algorithms</strong>, including their combinations.
<ul>
<li>Transparent encryption of disk partitions.</li>
<li>Full support for dynamic disks.</li>
<li>Support for disk devices with large sector size (important for <a href="https://en.wikipedia.org/wiki/RAID">hardware RAID</a> operation).</li>
</ul></li>
<li><strong>High performance</strong>, comparable to efficiency of a non-encrypted system.
<ul>
<li>Support for hardware AES acceleration:
<ul>
<li>AES New Instructions set on recent <a href="http://software.intel.com/en-us/articles/intel-advanced-encryption-standard-instructions-aes-ni">Intel</a> and AMD CPUs;</li>
<li><a href="http://www.via.com.tw/en/initiatives/padlock/hardware.jsp">PadLock extensions</a> on VIA processors.</li>
</ul></li>
<li>Support for the SSD <a href="https://en.wikipedia.org/wiki/Trim_(computing)">TRIM</a> extension.</li>
</ul></li>
<li><strong>Broad choice in configuration of booting</strong> an encrypted OS. Support for various multi-boot options.
<ul>
<li>Full compatibility with <a href="https://en.wikipedia.org/wiki/Unified_Extensible_Firmware_Interface">UEFI</a>/<a href="https://en.wikipedia.org/wiki/GUID_Partition_Table">GPT</a> boot</li>
<li>MBR bootloader Full compatibility with third party boot loaders (<a href="https://en.wikipedia.org/wiki/LILO_(boot_loader)">LILO</a>, <a href="https://en.wikipedia.org/wiki/GNU_GRUB">GRUB</a>, etc.).</li>
<li>Encryption of system partitions with pre-boot authentication.</li>
<li>Option to place boot loader on external media and to authenticate using the key media.</li>
<li>Support for key files.</li>
</ul></li>
<li><strong>Full support for external storage devices</strong>.
<ul>
<li>Option to create encrypted CD and DVD disks.</li>
<li>Full support for encryption of external USB storage devices.</li>
<li>Automatic mounting of disk partitions and external storage devices.</li>
</ul></li>
<li>Support for hotkeys and optional command-line interface (CLI).</li>
<li><strong>Open license</strong> <a href="https://en.wikipedia.org/wiki/GNU_General_Public_License">GNU GPLv3</a>.</li>
</ul></td>
</tr>
