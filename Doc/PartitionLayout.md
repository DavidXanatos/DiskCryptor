# DiskCryptor Partition Layout

There are two types of encrypted partitions which slightly differ in their layout.

The beginning of the physical partition (sector 0) always contains the DiskCryptor header (`dc_header`, 2048 byte). The type of partion is defined by the flag `VF_STORAGE_FILE` (0x04) in the `dc_header.flags` field.

| dc_header.flags   | dc_header.stor_off | Type                       |
|:----------------- |:------------------ |:-------------------------- |
| `VF_STORAGE_FILE` | > 0                | Encrypted after formatting |
| 0                 | 0                  | Formatted by DiskCryptor   |


## Partition Encrypted After Formatting

Partitions which were created via the DiskCryptor "Encrypt" command, including the Windows OS partition.

The size of the decrypted partion is exactly the same as the underlying physical partition. The first 2048 bytes of the physical partition are replaced by the `dc_header`. The original content of the first 2048 bytes is stored in a hidden file named `$dcsys$`.

The DC driver creates `$dcsys$` when the user encrypts the hard disk. It stores the physical address of the file in `dc_header.stor_off`. Whenever the file system driver accesses the first 2048 bytes, the DC driver redirects the I/O command to `stor_off`.

The DC driver prohibits access to `$dcsys$`. The file `$dcsys$` would contain `dc_header`, although encrypted differently than the rest of the data.

         Decrypted                Physical
    |------------------+        |-----------+---
    | Data 0           | o    > | dc_header |  ^
    | Data 1           |  \  /  | Data 1    |  |
    | Data 2           |   \/   | Data 2    |  | dc_header.stor_off
    | Data 3           |   /\   | Data 3    |  |
    | Data 4           |  /  \  | Data 4    |  v
    | Data 5 = $dcsys$ | o    > | Data 0    +---
    | Data 6           |        | Data 6    |
    | Data 7           |        | Data 7    |
    | Data 8           |        | Data 8    |
    | Data 9           |        | Data 9    |
    +------------------+        +-----------+


## Partition Formatted by DiskCryptor

Partitions which were created via the DiskCryptor "Format" command.

The `dc_header` is again stored at the beginning of the physical partition. The decrypted partition's size is reduced by `sizeof(dc_header)` = 2048 byte at the end. The partition does not contain special files. When the file system driver accesses the first 2048 byte, the I/O command gets redirected to the end of the partition.

      Decrypted                Physical
    |-----------+            |-----------+---
    | Data 0    | o          | dc_header |  ^
    | Data 1    |  \         | Data 1    |  |
    | Data 2    |   \        | Data 2    |  |
    | Data 3    |    \       | Data 3    |  |
    | Data 4    |     \      | Data 4    |  | partition_size - sizeof(dc_header)
    | Data 5    |      \     | Data 5    |  |
    | Data 6    |       \    | Data 6    |  |
    | Data 7    |        \   | Data 7    |  |
    | Data 8    |         \  | Data 8    |  v
    |-----------+          > | Data 0    +---
                             +-----------+
