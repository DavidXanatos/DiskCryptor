/*++

Copyright (c) 2003  Microsoft Corporation

Module Name:

    ntdddump.h

Abstract:

    Definitions required for filter drivers on the dump path.

Environment:

    Kernel mode

Revision History:


--*/

#include <ntddk.h>

#ifndef __NTDDDUMP_H__
#define __NTDDDUMP_H__

#define DUMP_FILTER_MAJOR_VERSION   1
#define DUMP_FILTER_MINOR_VERSION   0

#define DUMP_FILTER_CRITICAL 0x00000001

typedef enum _FILTER_DUMP_TYPE {
    DumpTypeUndefined,
    DumpTypeCrashdump,
    DumpTypeHibernation
} FILTER_DUMP_TYPE, *PFILTER_DUMP_TYPE;

typedef enum _FILTER_CALLBACK {
    CallbackDumpInit,
    CallbackDumpStart,
    CallbackDumpWrite,
    CallbackDumpFinish,
    CallbackMaxCallback
} FILTER_CALLBACK, *PFILTER_CALLBACK;

//
// Define the filter driver extension structure
//

typedef struct _FILTER_EXTENSION {

    //
    // Dump type
    //
    FILTER_DUMP_TYPE DumpType;

    //
    // Pointer to dump volume object
    //
    PDEVICE_OBJECT DeviceObject;

    //
    // Dump device geometry
    //
    DISK_GEOMETRY Geometry;

    //
    // Dump disk size
    //
    LARGE_INTEGER DiskSize;

    //
    // Dump partition Information
    // Contains dump partition offset
    //
    DISK_PARTITION_INFO PartitionInfo;

    //
    // Filter driver specific data
    //
    PVOID DumpData;

} FILTER_EXTENSION, *PFILTER_EXTENSION;


typedef
NTSTATUS
(*PDUMP_START) (
    __in PFILTER_EXTENSION FilterExtension
    );

typedef
NTSTATUS
(*PDUMP_WRITE) (
    __in PFILTER_EXTENSION FilterExtension,
    __in PLARGE_INTEGER DiskByteOffset,
    __in PMDL Mdl
    );

typedef
NTSTATUS
(*PDUMP_FINISH) (
    __in PFILTER_EXTENSION FilterExtension
    );

typedef
NTSTATUS
(*PDUMP_UNLOAD) (
    __in PFILTER_EXTENSION FilterExtension
    );


//
// Define the filter driver call table structure
//

typedef struct _FILTER_INITIALIZATION_DATA {

    //
    // Major version of the structure
    // Set to DUMP_FILTER_MAJOR_VERSION
    //
    ULONG MajorVersion;

    //
    // Major version of the structure
    // Set to DUMP_FILTER_MINOR_VERSION
    //
    ULONG MinorVersion;

    //
    // Pointer to the dump init routine
    // This will be called when the dump starts
    //
    PDUMP_START DumpStart;

    //
    // Pointer to the write routine
    // This will be called before every write
    //
    PDUMP_WRITE DumpWrite;

    //
    // Pointer to the dump finish routine
    // This will be called when the dump completes
    //
    PDUMP_FINISH DumpFinish;

    //
    // Pointer to the dump unload routine
    // This will be called before unloading the driver
    //
    PDUMP_UNLOAD DumpUnload;

    //
    // Filter driver specific data
    //
    PVOID DumpData;

    //
    // Maximum number of pages per dump write.
    //
    ULONG MaxPagesPerWrite;

    //
    // Flags.
    //
    ULONG Flags;

} FILTER_INITIALIZATION_DATA, *PFILTER_INITIALIZATION_DATA;


#endif // __NTDDDUMP_H__



