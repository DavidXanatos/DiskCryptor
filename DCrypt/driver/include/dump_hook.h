#ifndef _DUMP_HOOK_H_
#define _DUMP_HOOK_H_

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    PVOID ExceptionTable;
    ULONG ExceptionTableSize;
    // ULONG padding on IA64
    PVOID GpValue;
    struct _NON_PAGED_DEBUG_INFO *NonPagedDebugInfo;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT __Unused5;
    PVOID SectionPointer;
    ULONG CheckSum;
    // ULONG padding on IA64
    PVOID LoadedImports;
    PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

//
// Define stall routine type for the dump driver.
//
// begin_ntosp
typedef
VOID
(*PSTALL_ROUTINE) (
    IN ULONG Delay
    );

//
// Define the interfaces for the dump driver's routines.
//

typedef
BOOLEAN
(*PDUMP_DRIVER_OPEN) (
    IN LARGE_INTEGER PartitionOffset
    );

typedef
NTSTATUS
(*PDUMP_DRIVER_WRITE) (
    IN PLARGE_INTEGER DiskByteOffset,
    IN PMDL Mdl
    );

//
// Actions accepted by DRIVER_WRITE_PENDING
//
#define IO_DUMP_WRITE_FULFILL   0   // fulfill IO request as if DRIVER_WAIT
#define IO_DUMP_WRITE_START     1   // start new IO
#define IO_DUMP_WRITE_RESUME    2   // resume pending IO
#define IO_DUMP_WRITE_FINISH    3   // finish pending IO
#define IO_DUMP_WRITE_INIT      4   // initialize locals

// size of data used by WRITE_PENDING that should be preserved
// between the calls
#define IO_DUMP_WRITE_DATA_PAGES 2
#define IO_DUMP_WRITE_DATA_SIZE (IO_DUMP_WRITE_DATA_PAGES << PAGE_SHIFT)

typedef
NTSTATUS
(*PDUMP_DRIVER_WRITE_PENDING) (
    IN LONG Action,
    IN PLARGE_INTEGER DiskByteOffset,
    IN PMDL Mdl,
    IN PVOID LocalData
    );


typedef
VOID
(*PDUMP_DRIVER_FINISH) (
    VOID
    );

typedef struct _DUMP_INITIALIZATION_CONTEXT {
    ULONG Length;
    ULONG Reserved;             // Was MBR Checksum. Should be zero now.
    PVOID MemoryBlock;
    PVOID CommonBuffer[2];
    PHYSICAL_ADDRESS PhysicalAddress[2];
    PSTALL_ROUTINE StallRoutine;
    PDUMP_DRIVER_OPEN OpenRoutine;
    PDUMP_DRIVER_WRITE WriteRoutine;
    PDUMP_DRIVER_FINISH FinishRoutine;
    struct _ADAPTER_OBJECT *AdapterObject;
    PVOID MappedRegisterBase;
    PVOID PortConfiguration;
    BOOLEAN CrashDump;
    ULONG MaximumTransferSize;
    ULONG CommonBufferSize;
    PVOID TargetAddress; //Opaque pointer to target address structure
    PDUMP_DRIVER_WRITE_PENDING WritePendingRoutine;
    ULONG PartitionStyle;
    union {
        struct {
            ULONG Signature;
            ULONG CheckSum;
        } Mbr;
        struct {
            GUID DiskId;
        } Gpt;
    } DiskInfo;
} DUMP_INITIALIZATION_CONTEXT, *PDUMP_INITIALIZATION_CONTEXT;

typedef struct _DUMP_STACK_CONTEXT {
    DUMP_INITIALIZATION_CONTEXT Init;
    LARGE_INTEGER               PartitionOffset;
    PVOID                       DumpPointers;
    ULONG                       PointersLength;
    PWCHAR                      ModulePrefix;
    LIST_ENTRY                  DriverList;
    ANSI_STRING                 InitMsg;
    ANSI_STRING                 ProgMsg;
    ANSI_STRING                 DoneMsg;
    PVOID                       FileObject;
    enum _DEVICE_USAGE_NOTIFICATION_TYPE    UsageType;
} DUMP_STACK_CONTEXT, *PDUMP_STACK_CONTEXT;

NTSTATUS dump_hook_init(PDRIVER_OBJECT DriverObject);

#endif