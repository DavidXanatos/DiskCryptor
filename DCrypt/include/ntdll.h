#ifndef _NTDLL_
#define _NTDLL_

typedef LONG NTSTATUS;
typedef LONG KPRIORITY;

NTSTATUS WINAPI
  RtlDecompressBuffer (
    USHORT CompressionFormat,
    PUCHAR UncompressedBuffer,
    ULONG  UncompressedBufferSize,
    PUCHAR CompressedBuffer,
    ULONG  CompressedBufferSize,
    PULONG FinalUncompressedSize
    );

NTSTATUS WINAPI
  RtlCompressBuffer (
    USHORT CompressionFormatAndEngine,
    PUCHAR UncompressedBuffer,
    ULONG  UncompressedBufferSize,
    PUCHAR CompressedBuffer,
    ULONG  CompressedBufferSize,
    ULONG  UncompressedChunkSize,
    PULONG FinalCompressedSize,
    PVOID  WorkSpace
    );

NTSTATUS WINAPI
  RtlGetCompressionWorkSpaceSize (
    USHORT  CompressionFormatAndEngine,
    PULONG  CompressBufferWorkSpaceSize,
    PULONG  CompressFragmentWorkSpaceSize
    );

typedef enum _PROCESSINFOCLASS {
	ProcessBasicInformation, // 0 Y N
	ProcessQuotaLimits, // 1 Y Y
	ProcessIoCounters, // 2 Y N
	ProcessVmCounters, // 3 Y N
	ProcessTimes, // 4 Y N
	ProcessBasePriority, // 5 N Y
	ProcessRaisePriority, // 6 N Y
	ProcessDebugPort, // 7 Y Y
	ProcessExceptionPort, // 8 N Y
	ProcessAccessToken, // 9 N Y
	ProcessLdtInformation, // 10 Y Y
	ProcessLdtSize, // 11 N Y
	ProcessDefaultHardErrorMode, // 12 Y Y
	ProcessIoPortHandlers, // 13 N Y
	ProcessPooledUsageAndLimits, // 14 Y N
	ProcessWorkingSetWatch, // 15 Y Y
	ProcessUserModeIOPL, // 16 N Y
	ProcessEnableAlignmentFaultFixup, // 17 N Y
	ProcessPriorityClass, // 18 N Y
	ProcessWx86Information, // 19 Y N
	ProcessHandleCount, // 20 Y N
	ProcessAffinityMask, // 21 N Y
	ProcessPriorityBoost, // 22 Y Y
	ProcessDeviceMap, // 23 Y Y
	ProcessSessionInformation, // 24 Y Y
	ProcessForegroundInformation, // 25 N Y
	ProcessWow64Information // 26 Y N
} PROCESSINFOCLASS;

NTSTATUS WINAPI 
  NtQueryInformationProcess(
    HANDLE           ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID            ProcessInformation,
	ULONG            ProcessInformationLength,
	PULONG           ReturnLength
	);

typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS  ExitStatus;
    PVOID     PebBaseAddress;
    ULONG_PTR AffinityMask;
    KPRIORITY BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;

typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG  Length;
    HANDLE  RootDirectory;
    PUNICODE_STRING  ObjectName;
    ULONG  Attributes;
    PVOID  SecurityDescriptor;
    PVOID  SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }


NTSTATUS WINAPI
  NtOpenFile(
    PHANDLE            FileHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK   IoStatusBlock,
    ULONG              ShareAccess,
    ULONG              OpenOptions
    );

NTSTATUS WINAPI
  NtCreateFile(
    PHANDLE  FileHandle,
    ACCESS_MASK  DesiredAccess,
    POBJECT_ATTRIBUTES  ObjectAttributes,
    PIO_STATUS_BLOCK  IoStatusBlock,
    PLARGE_INTEGER  AllocationSize  OPTIONAL,
    ULONG  FileAttributes,
    ULONG  ShareAccess,
    ULONG  CreateDisposition,
    ULONG  CreateOptions,
    PVOID  EaBuffer  OPTIONAL,
    ULONG  EaLength
    );


VOID WINAPI 
  RtlInitUnicodeString(
    PUNICODE_STRING DestinationString,
    PCWSTR          SourceString
    );

#define OBJ_INHERIT             0x00000002L
#define OBJ_PERMANENT           0x00000010L
#define OBJ_EXCLUSIVE           0x00000020L
#define OBJ_CASE_INSENSITIVE    0x00000040L
#define OBJ_OPENIF              0x00000080L
#define OBJ_OPENLINK            0x00000100L
#define OBJ_KERNEL_HANDLE       0x00000200L
#define OBJ_FORCE_ACCESS_CHECK  0x00000400L
#define OBJ_VALID_ATTRIBUTES    0x000007F2L


//
// Define the create/open option flags
//

#define FILE_DIRECTORY_FILE                     0x00000001
#define FILE_WRITE_THROUGH                      0x00000002
#define FILE_SEQUENTIAL_ONLY                    0x00000004
#define FILE_NO_INTERMEDIATE_BUFFERING          0x00000008

#define FILE_SYNCHRONOUS_IO_ALERT               0x00000010
#define FILE_SYNCHRONOUS_IO_NONALERT            0x00000020
#define FILE_NON_DIRECTORY_FILE                 0x00000040
#define FILE_CREATE_TREE_CONNECTION             0x00000080

#define FILE_COMPLETE_IF_OPLOCKED               0x00000100
#define FILE_NO_EA_KNOWLEDGE                    0x00000200
#define FILE_OPEN_REMOTE_INSTANCE               0x00000400
#define FILE_RANDOM_ACCESS                      0x00000800

#define FILE_DELETE_ON_CLOSE                    0x00001000
#define FILE_OPEN_BY_FILE_ID                    0x00002000
#define FILE_OPEN_FOR_BACKUP_INTENT             0x00004000
#define FILE_NO_COMPRESSION                     0x00008000

#define FILE_RESERVE_OPFILTER                   0x00100000
#define FILE_OPEN_REPARSE_POINT                 0x00200000
#define FILE_OPEN_NO_RECALL                     0x00400000
#define FILE_OPEN_FOR_FREE_SPACE_QUERY          0x00800000


#define FILE_COPY_STRUCTURED_STORAGE            0x00000041
#define FILE_STRUCTURED_STORAGE                 0x00000441


#define FILE_VALID_OPTION_FLAGS                 0x00ffffff
#define FILE_VALID_PIPE_OPTION_FLAGS            0x00000032
#define FILE_VALID_MAILSLOT_OPTION_FLAGS        0x00000032
#define FILE_VALID_SET_FLAGS                    0x00000036

#define FILE_SUPERSEDE                  0x00000000
#define FILE_OPEN                       0x00000001
#define FILE_CREATE                     0x00000002
#define FILE_OPEN_IF                    0x00000003
#define FILE_OVERWRITE                  0x00000004
#define FILE_OVERWRITE_IF               0x00000005
#define FILE_MAXIMUM_DISPOSITION        0x00000005

#endif