/*++

Copyright (c) 1989-2002  Microsoft Corporation

Module Name:

    fltKernel.h

Abstract:

    This contains all of the global definitions for mini-filters.

Environment:

    Kernel mode

--*/

#ifndef __FLTKERNEL__
#define __FLTKERNEL__

#ifdef __cplusplus
extern "C" {
#endif

//
// IMPORTANT!!!!!
//
// This is how FltMgr was released (from oldest to newest)
// xpsp2, srv03 SP1, w2k sp4+URP, LH, Win7
//

//
//  The defines items that are part of the filter manager baseline
//

#define FLT_MGR_BASELINE (((OSVER(NTDDI_VERSION) == NTDDI_WIN2K) && (SPVER(NTDDI_VERSION) >= SPVER(NTDDI_WIN2KSP4))) || \
                          ((OSVER(NTDDI_VERSION) == NTDDI_WINXP) && (SPVER(NTDDI_VERSION) >= SPVER(NTDDI_WINXPSP2))) || \
                          ((OSVER(NTDDI_VERSION) == NTDDI_WS03)  && (SPVER(NTDDI_VERSION) >= SPVER(NTDDI_WS03SP1))) ||  \
                          (NTDDI_VERSION >= NTDDI_VISTA))

//
//  This defines items that were added after XPSP2 was released.  This means
//  they are in Srv03 SP1, W2K SP4+URP, and Longhorn and above.
//

#define FLT_MGR_AFTER_XPSP2 (((OSVER(NTDDI_VERSION) == NTDDI_WIN2K) && (SPVER(NTDDI_VERSION) >= SPVER(NTDDI_WIN2KSP4))) ||  \
                             ((OSVER(NTDDI_VERSION) == NTDDI_WINXP) && (SPVER(NTDDI_VERSION) >  SPVER(NTDDI_WINXPSP2))) ||  \
                             ((OSVER(NTDDI_VERSION) == NTDDI_WS03)  && (SPVER(NTDDI_VERSION) >= SPVER(NTDDI_WS03SP1))) ||   \
                             (NTDDI_VERSION >= NTDDI_VISTA))

//
//  This defines items that only exist in longhorn or later
//

#define FLT_MGR_LONGHORN (NTDDI_VERSION >= NTDDI_VISTA)

//
//  This defines items that only exist in Windows 7 or later
//

#define FLT_MGR_WIN7 (NTDDI_VERSION >= NTDDI_WIN7)


///////////////////////////////////////////////////////////////////////////////
//
//  Standard includes
//
///////////////////////////////////////////////////////////////////////////////

#include <ntifs.h>
#include <fltUserStructures.h>
#include <initguid.h>

#if FLT_MGR_BASELINE

///////////////////////////////////////////////////////////////////////////////
//
//  Miscellaneous macros useful for Filter Manager & mini-filters
//
///////////////////////////////////////////////////////////////////////////////

//
//  Handy macros for doing pointer arithmetic
//

#define Add2Ptr(P,I) ((PVOID)((PUCHAR)(P) + (I)))
#define PtrOffset(B,O) ((ULONG)((ULONG_PTR)(O) - (ULONG_PTR)(B)))

//
//  This macro takes a length & rounds it up to a multiple of the alignment
//  Alignment is given as a power of 2
//

#define ROUND_TO_SIZE(_length, _alignment)                      \
            ((((ULONG_PTR)(_length)) + ((_alignment)-1)) & ~(ULONG_PTR) ((_alignment) - 1))

//
//  Checks if 1st argument is aligned on given power of 2 boundary specified
//  by 2nd argument
//

#define IS_ALIGNED(_pointer, _alignment)                        \
        ((((ULONG_PTR) (_pointer)) & ((_alignment) - 1)) == 0)

///////////////////////////////////////////////////////////////////////////////
//
//                  FltMgr Operation Definitions
//
///////////////////////////////////////////////////////////////////////////////

//
//  Along with the existing IRP_MJ_xxxx definitions (0 - 0x1b) in NTIFS.H,
//  this defines all of the operation IDs that can be sent to a mini-filter.
//

#define IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION   ((UCHAR)-1)
#define IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION   ((UCHAR)-2)
#define IRP_MJ_ACQUIRE_FOR_MOD_WRITE                 ((UCHAR)-3)
#define IRP_MJ_RELEASE_FOR_MOD_WRITE                 ((UCHAR)-4)
#define IRP_MJ_ACQUIRE_FOR_CC_FLUSH                  ((UCHAR)-5)
#define IRP_MJ_RELEASE_FOR_CC_FLUSH                  ((UCHAR)-6)


//
//  Leave space for additional FS_FILTER codes here
//

#define IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE             ((UCHAR)-13)
#define IRP_MJ_NETWORK_QUERY_OPEN                    ((UCHAR)-14)
#define IRP_MJ_MDL_READ                              ((UCHAR)-15)
#define IRP_MJ_MDL_READ_COMPLETE                     ((UCHAR)-16)
#define IRP_MJ_PREPARE_MDL_WRITE                     ((UCHAR)-17)
#define IRP_MJ_MDL_WRITE_COMPLETE                    ((UCHAR)-18)
#define IRP_MJ_VOLUME_MOUNT                          ((UCHAR)-19)
#define IRP_MJ_VOLUME_DISMOUNT                       ((UCHAR)-20)


#define FLT_INTERNAL_OPERATION_COUNT                 22

//
//  Not currently implemented
//

/*
#define IRP_MJ_READ_COMPRESSED                      ((UCHAR)-xx)
#define IRP_MJ_WRITE_COMPRESSED                     ((UCHAR)-xx)
#define IRP_MJ_MDL_READ_COMPLETE_REQUEST            ((UCHAR)-xx)
#define IRP_MJ_MDL_WRITE_COMPLETE_COMPRESSED        ((UCHAR)-xx)
*/

//
//  Marks the end of the operation list for registration
//

#define IRP_MJ_OPERATION_END                        ((UCHAR)0x80)


///////////////////////////////////////////////////////////////////////////////
//
//  Basic Filter data types
//
///////////////////////////////////////////////////////////////////////////////

typedef struct _FLT_FILTER *PFLT_FILTER;
typedef struct _FLT_VOLUME *PFLT_VOLUME;
typedef struct _FLT_INSTANCE *PFLT_INSTANCE;
typedef struct _FLT_PORT *PFLT_PORT;

typedef PVOID PFLT_CONTEXT;
#define NULL_CONTEXT ((PFLT_CONTEXT)NULL)   //EMPTY context

#if !FLT_MGR_LONGHORN
//
//  For non-longhorn environments we need to define this structure since
//  it is used elsewhere.  In longhorn and later it is part of ntifs.h
//

typedef struct _KTRANSACTION *PKTRANSACTION;

#endif // !FLT_MGR_LONGHORN



///////////////////////////////////////////////////////////////////////////////
//
//  This defines the standard parameter block that is passed to every
//  callback.
//
///////////////////////////////////////////////////////////////////////////////

#if !defined(_AMD64_) && !defined(_IA64_)
#include "pshpack4.h"
#endif

#if _MSC_VER >= 1200
#pragma warning(push)
#pragma warning(disable:4201) // nonstandard extension used : nameless struct/union
#endif

typedef union _FLT_PARAMETERS {

    //
    //  IRP_MJ_CREATE
    //

    struct {
        PIO_SECURITY_CONTEXT SecurityContext;

        //
        //  The low 24 bits contains CreateOptions flag values.
        //  The high 8 bits contains the CreateDisposition values.
        //

        ULONG Options;

        USHORT POINTER_ALIGNMENT FileAttributes;
        USHORT ShareAccess;
        ULONG POINTER_ALIGNMENT EaLength;

        PVOID EaBuffer;                 //Not in IO_STACK_LOCATION parameters list
        LARGE_INTEGER AllocationSize;   //Not in IO_STACK_LOCATION parameters list
    } Create;

    //
    //  IRP_MJ_CREATE_NAMED_PIPE
    //
    //  Notice that the fields in the following parameter structure must
    //  match those for the create structure other than the last longword.
    //  This is so that no distinctions need be made by the I/O system's
    //  parse routine other than for the last longword.
    //

    struct {
        PIO_SECURITY_CONTEXT SecurityContext;
        ULONG Options;
        USHORT POINTER_ALIGNMENT Reserved;
        USHORT ShareAccess;
        PVOID Parameters; // PNAMED_PIPE_CREATE_PARAMETERS
    } CreatePipe;

    //
    //  IRP_MJ_CREATE_MAILSLOT
    //
    //  Notice that the fields in the following parameter structure must
    //  match those for the create structure other than the last longword.
    //  This is so that no distinctions need be made by the I/O system's
    //  parse routine other than for the last longword.
    //

    struct {
        PIO_SECURITY_CONTEXT SecurityContext;
        ULONG Options;
        USHORT POINTER_ALIGNMENT Reserved;
        USHORT ShareAccess;
        PVOID Parameters; // PMAILSLOT_CREATE_PARAMETERS
    } CreateMailslot;

    //
    //  IRP_MJ_READ
    //

    struct {
        ULONG Length;                   //Length of transfer
        ULONG POINTER_ALIGNMENT Key;
        LARGE_INTEGER ByteOffset;       //Offset to read from

        PVOID ReadBuffer;       //Not in IO_STACK_LOCATION parameters list
        PMDL MdlAddress;        //Mdl address for the buffer  (maybe NULL)
    } Read;

    //
    //  IRP_MJ_WRITE
    //

    struct {
        ULONG Length;                   //Length of transfer
        ULONG POINTER_ALIGNMENT Key;
        LARGE_INTEGER ByteOffset;       //Offset to write to

        PVOID WriteBuffer;      //Not in IO_STACK_LOCATION parameters list
        PMDL MdlAddress;        //Mdl address for the buffer  (maybe NULL)
    } Write;

    //
    //  IRP_MJ_QUERY_INFORMATION
    //

    struct {
        ULONG Length;           //Length of buffer
        FILE_INFORMATION_CLASS POINTER_ALIGNMENT FileInformationClass; //Class of information to query

        PVOID InfoBuffer;       //Not in IO_STACK_LOCATION parameters list
    } QueryFileInformation;

    //
    //  IRP_MJ_SET_INFORMATION
    //

    struct {
        ULONG Length;
        FILE_INFORMATION_CLASS POINTER_ALIGNMENT FileInformationClass;
        PFILE_OBJECT ParentOfTarget;
        union {
            struct {
                BOOLEAN ReplaceIfExists;
                BOOLEAN AdvanceOnly;
            };
            ULONG ClusterCount;
            HANDLE DeleteHandle;
        };

        PVOID InfoBuffer;       //Not in IO_STACK_LOCATION parameters list
    } SetFileInformation;

    //
    //  IRP_MJ_QUERY_EA
    //

    struct {
        ULONG Length;
        PVOID EaList;
        ULONG EaListLength;
        ULONG POINTER_ALIGNMENT EaIndex;

        PVOID EaBuffer;         //Not in IO_STACK_LOCATION parameters list
        PMDL MdlAddress;        //Mdl address for the buffer  (maybe NULL)
    } QueryEa;

    //
    //  IRP_MJ_SET_EA
    //

    struct {
        ULONG Length;

        PVOID EaBuffer;         //Not in IO_STACK_LOCATION parameters list
        PMDL MdlAddress;        //Mdl address for the buffer  (maybe NULL)
    } SetEa;

    //
    //  IRP_MJ_QUERY_VOLUME_INFORMATION
    //

    struct {
        ULONG Length;
        FS_INFORMATION_CLASS POINTER_ALIGNMENT FsInformationClass;

        PVOID VolumeBuffer;     //Not in IO_STACK_LOCATION parameters list
    } QueryVolumeInformation;

    //
    //  IRP_MJ_SET_VOLUME_INFORMATION
    //

    struct {
        ULONG Length;
        FS_INFORMATION_CLASS POINTER_ALIGNMENT FsInformationClass;

        PVOID VolumeBuffer;     //Not in IO_STACK_LOCATION parameters list
    } SetVolumeInformation;

    //
    //  IRP_MJ_DIRECTORY_CONTROL
    //

    union {

        //
        //  IRP_MN_QUERY_DIRECTORY or IRP_MN_QUERY_OLE_DIRECTORY
        //

        struct {
            ULONG Length;
            PUNICODE_STRING FileName;
            FILE_INFORMATION_CLASS FileInformationClass;
            ULONG POINTER_ALIGNMENT FileIndex;

            PVOID DirectoryBuffer;  //Not in IO_STACK_LOCATION parameters list
            PMDL MdlAddress;        //Mdl address for the buffer  (maybe NULL)
        } QueryDirectory;

        //
        //  IRP_MN_NOTIFY_CHANGE_DIRECTORY
        //

        struct {
            ULONG Length;
            ULONG POINTER_ALIGNMENT CompletionFilter;

            //
            // These spares ensure that the offset of DirectoryBuffer is
            // exactly the same as that for QueryDirectory minor code. This
            // needs to be the same because filter manager code makes the assumption
            // they are the same
            //

            ULONG POINTER_ALIGNMENT Spare1;
            ULONG POINTER_ALIGNMENT Spare2;

            PVOID DirectoryBuffer;  //Not in IO_STACK_LOCATION parameters list
            PMDL MdlAddress;        //Mdl address for the buffer  (maybe NULL)
        } NotifyDirectory;

    } DirectoryControl;

    //
    //  IRP_MJ_FILE_SYSTEM_CONTROL
    //
    //  Note that the user's output buffer is stored in the UserBuffer field
    //  and the user's input buffer is stored in the SystemBuffer field.
    //

    union {

        //
        //  IRP_MN_VERIFY_VOLUME
        //

        struct {
            PVPB Vpb;
            PDEVICE_OBJECT DeviceObject;
        } VerifyVolume;

        //
        //  IRP_MN_KERNEL_CALL and IRP_MN_USER_FS_REQUEST
        //  The parameters are broken out into 3 separate unions based on the
        //  method of the FSCTL Drivers should use the method-appropriate
        //  union for accessing parameters
        //

        struct {
            ULONG OutputBufferLength;
            ULONG POINTER_ALIGNMENT InputBufferLength;
            ULONG POINTER_ALIGNMENT FsControlCode;
        } Common;

        //
        //  METHOD_NEITHER Fsctl parameters
        //

        struct {
            ULONG OutputBufferLength;
            ULONG POINTER_ALIGNMENT InputBufferLength;
            ULONG POINTER_ALIGNMENT FsControlCode;

            //
            //  Type3InputBuffer: name changed from IO_STACK_LOCATION parameters
            //  Note for this mothod, both input & output buffers are 'raw',
            //  i.e. unbuffered, and should be treated with caution ( either
            //  probed & captured before access, or use try-except to enclose
            //  access to the buffer)
            //

            PVOID InputBuffer;
            PVOID OutputBuffer;

            //
            //  Mdl address for the output buffer  (maybe NULL)
            //

            PMDL OutputMdlAddress;
        } Neither;

        //
        //  METHOD_BUFFERED Fsctl parameters
        //

        struct {
            ULONG OutputBufferLength;
            ULONG POINTER_ALIGNMENT InputBufferLength;
            ULONG POINTER_ALIGNMENT FsControlCode;

            //
            //  For method buffered, this buffer is used both for input and
            //  output
            //

            PVOID SystemBuffer;

        } Buffered;

        //
        //  METHOD_IN_DIRECT/METHOD_OUT_DIRECT Fsctl parameters
        //

        struct {
            ULONG OutputBufferLength;
            ULONG POINTER_ALIGNMENT InputBufferLength;
            ULONG POINTER_ALIGNMENT FsControlCode;

            //
            //  Note the input buffer is already captured & buffered here - so
            //  can be safely accessed from kernel mode.  The output buffer is
            //  locked down - so also safe to access, however the OutputBuffer
            //  pointer is the user virtual address, so if the driver wishes to
            //  access the buffer in a different process context than that of
            //  the original i/o - it will have to obtain the system address
            //  from the MDL
            //

            PVOID InputSystemBuffer;

            //
            //  User virtual address of output buffer
            //

            PVOID OutputBuffer;

            //
            //  Mdl address for the locked down output buffer (should be
            //  non-NULL)
            //

            PMDL OutputMdlAddress;
        } Direct;

    } FileSystemControl;

    //
    //  IRP_MJ_DEVICE_CONTROL or IRP_MJ_INTERNAL_DEVICE_CONTROL
    //

    union {

        struct {
            ULONG OutputBufferLength;
            ULONG POINTER_ALIGNMENT InputBufferLength;
            ULONG POINTER_ALIGNMENT IoControlCode;
        } Common;

        //
        //  The parameters are broken out into 3 separate unions based on the
        //  method of the IOCTL.  Drivers should use the method-appropriate
        //  union for accessing parameters.
        //

        //
        //  METHOD_NEITHER Ioctl parameters for IRP path
        //

        struct {
            ULONG OutputBufferLength;
            ULONG POINTER_ALIGNMENT InputBufferLength;
            ULONG POINTER_ALIGNMENT IoControlCode;

            //
            //  Type3InputBuffer: name changed from IO_STACK_LOCATION parameters
            //  Note for this mothod, both input & output buffers are 'raw',
            //  i.e. unbuffered, and should be treated with caution ( either
            //  probed & captured before access, or use try-except to enclose
            //  access to the buffer)
            //

            PVOID InputBuffer;
            PVOID OutputBuffer;

            //
            //  Mdl address for the output buffer  (maybe NULL)
            //

            PMDL OutputMdlAddress;
        } Neither;

        //
        //  METHOD_BUFFERED Ioctl parameters for IRP path
        //

        struct {
            ULONG OutputBufferLength;
            ULONG POINTER_ALIGNMENT InputBufferLength;
            ULONG POINTER_ALIGNMENT IoControlCode;

            //
            //  For method buffered, this buffer is used both for input and
            //  output
            //

            PVOID SystemBuffer;

        } Buffered;

        //
        //  METHOD_IN_DIRECT/METHOD_OUT_DIRECT Ioctl parameters
        //

        struct {
            ULONG OutputBufferLength;
            ULONG POINTER_ALIGNMENT InputBufferLength;
            ULONG POINTER_ALIGNMENT IoControlCode;

            //
            //  Note the input buffer is already captured & buffered here - so
            //  can be safely accessed from kernel mode.  The output buffer is
            //  locked down - so also safe to access, however the OutputBuffer
            //  pointer is the user virtual address, so if the driver wishes to
            //  access the buffer in a different process context than that of
            //  the original i/o - it will have to obtain the system address
            //  from the MDL
            //

            PVOID InputSystemBuffer;

            //
            //  User virtual address of output buffer
            //

            PVOID OutputBuffer;

            //
            //  Mdl address for the locked down output buffer (should be non-NULL)
            //

            PMDL OutputMdlAddress;
        } Direct;

        //
        //  Regardless of method, if the CALLBACK_DATA represents a fast i/o
        //  device IOCTL, this structure must be used to access the parameters
        //

        struct {
            ULONG OutputBufferLength;
            ULONG POINTER_ALIGNMENT InputBufferLength;
            ULONG POINTER_ALIGNMENT IoControlCode;

            //
            //  Both buffers are 'raw', i.e. unbuffered
            //

            PVOID InputBuffer;
            PVOID OutputBuffer;

        } FastIo;

    } DeviceIoControl;

    //
    //  IRP_MJ_LOCK_CONTROL
    //

    struct {
        PLARGE_INTEGER Length;
        ULONG POINTER_ALIGNMENT Key;
        LARGE_INTEGER ByteOffset;

        PEPROCESS ProcessId;        //  Only meaningful for FastIo locking operations.
        BOOLEAN FailImmediately;    //  Only meaningful for FastIo locking operations.
        BOOLEAN ExclusiveLock;      //  Only meaningful for FastIo locking operations.
    } LockControl;

    //
    //  IRP_MJ_QUERY_SECURITY
    //

    struct {
        SECURITY_INFORMATION SecurityInformation;
        ULONG POINTER_ALIGNMENT Length;

        PVOID SecurityBuffer;   //Not in IO_STACK_LOCATION parameters list
        PMDL MdlAddress;        //Mdl address for the buffer  (maybe NULL)
    } QuerySecurity;

    //
    //  IRP_MJ_SET_SECURITY
    //

    struct {
        SECURITY_INFORMATION SecurityInformation;
        PSECURITY_DESCRIPTOR SecurityDescriptor;
    } SetSecurity;

    //
    //  IRP_MJ_SYSTEM_CONTROL
    //

    struct {
        ULONG_PTR ProviderId;
        PVOID DataPath;
        ULONG BufferSize;
        PVOID Buffer;
    } WMI;

    //
    //  IRP_MJ_QUERY_QUOTA
    //

    struct {
        ULONG Length;
        PSID StartSid;
        PFILE_GET_QUOTA_INFORMATION SidList;
        ULONG SidListLength;

        PVOID QuotaBuffer;      //Not in IO_STACK_LOCATION parameters list
        PMDL MdlAddress;        //Mdl address for the buffer  (maybe NULL)
    } QueryQuota;

    //
    //  IRP_MJ_SET_QUOTA
    //

    struct {
        ULONG Length;

        PVOID QuotaBuffer;      //Not in IO_STACK_LOCATION parameters list
        PMDL MdlAddress;        //Mdl address for the buffer  (maybe NULL)
    } SetQuota;

    //
    //  IRP_MJ_PNP
    //

    union {

        //
        //  IRP_MN_START_DEVICE
        //

        struct {
            PCM_RESOURCE_LIST AllocatedResources;
            PCM_RESOURCE_LIST AllocatedResourcesTranslated;
        } StartDevice;

        //
        //  IRP_MN_QUERY_DEVICE_RELATIONS
        //

        struct {
            DEVICE_RELATION_TYPE Type;
        } QueryDeviceRelations;

        //
        //  IRP_MN_QUERY_INTERFACE
        //

        struct {
            CONST GUID *InterfaceType;
            USHORT Size;
            USHORT Version;
            PINTERFACE Interface;
            PVOID InterfaceSpecificData;
        } QueryInterface;

        //
        //  IRP_MN_QUERY_CAPABILITIES
        //

        struct {
            PDEVICE_CAPABILITIES Capabilities;
        } DeviceCapabilities;

        //
        //  IRP_MN_FILTER_RESOURCE_REQUIREMENTS
        //

        struct {
            PIO_RESOURCE_REQUIREMENTS_LIST IoResourceRequirementList;
        } FilterResourceRequirements;

        //
        //  IRP_MN_READ_CONFIG and IRP_MN_WRITE_CONFIG
        //

        struct {
            ULONG WhichSpace;
            PVOID Buffer;
            ULONG Offset;
            ULONG POINTER_ALIGNMENT Length;
        } ReadWriteConfig;

        //
        //  IRP_MN_SET_LOCK
        //

        struct {
            BOOLEAN Lock;
        } SetLock;

        //
        //  IRP_MN_QUERY_ID
        //

        struct {
            BUS_QUERY_ID_TYPE IdType;
        } QueryId;

        //
        //  IRP_MN_QUERY_DEVICE_TEXT
        //

        struct {
            DEVICE_TEXT_TYPE DeviceTextType;
            LCID POINTER_ALIGNMENT LocaleId;
        } QueryDeviceText;

        //
        //  IRP_MN_DEVICE_USAGE_NOTIFICATION
        //

        struct {
            BOOLEAN InPath;
            BOOLEAN Reserved[3];
            DEVICE_USAGE_NOTIFICATION_TYPE POINTER_ALIGNMENT Type;
        } UsageNotification;

    } Pnp;

    //
    //  ***** Start of Emulated IRP definitions
    //

    //
    //  IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION
    //

    struct {
        FS_FILTER_SECTION_SYNC_TYPE SyncType;
        ULONG PageProtection;
    } AcquireForSectionSynchronization;

    //
    //  IRP_MJ_ACQUIRE_FOR_MOD_WRITE
    //

    struct {
        PLARGE_INTEGER EndingOffset;
        PERESOURCE *ResourceToRelease;
    } AcquireForModifiedPageWriter;

    //
    //  IRP_MJ_RELEASE_FOR_MOD_WRITE
    //

    struct {
        PERESOURCE ResourceToRelease;
    } ReleaseForModifiedPageWriter;


    //
    //  FAST_IO_CHECK_IF_POSSIBLE
    //

    struct {
        LARGE_INTEGER FileOffset;
        ULONG Length;
        ULONG POINTER_ALIGNMENT LockKey;
        BOOLEAN POINTER_ALIGNMENT CheckForReadOperation;
    } FastIoCheckIfPossible;

    //
    //  IRP_MJ_NETWORK_QUERY_OPEN
    //

    struct {
        PIRP Irp;
        PFILE_NETWORK_OPEN_INFORMATION NetworkInformation;
    } NetworkQueryOpen;

    //
    //  IRP_MJ_MDL_READ
    //

    struct {
        LARGE_INTEGER FileOffset;
        ULONG POINTER_ALIGNMENT Length;
        ULONG POINTER_ALIGNMENT Key;
        PMDL *MdlChain;
    } MdlRead;

    //
    //  IRP_MJ_MDL_READ_COMPLETE
    //

    struct {
        PMDL MdlChain;
    } MdlReadComplete;

    //
    //  IRP_MJ_PREPARE_MDL_WRITE
    //

    struct {
        LARGE_INTEGER FileOffset;
        ULONG POINTER_ALIGNMENT Length;
        ULONG POINTER_ALIGNMENT Key;
        PMDL *MdlChain;
    } PrepareMdlWrite;

    //
    //  IRP_MJ_MDL_WRITE_COMPLETE
    //

    struct {
        LARGE_INTEGER FileOffset;
        PMDL MdlChain;
    } MdlWriteComplete;

    //
    //  IRP_MJ_VOLUME_MOUNT
    //

    struct {
        ULONG DeviceType;
    } MountVolume;


    //
    // Others - driver-specific
    //

    struct {
        PVOID Argument1;
        PVOID Argument2;
        PVOID Argument3;
        PVOID Argument4;
        PVOID Argument5;
        LARGE_INTEGER Argument6;
    } Others;

} FLT_PARAMETERS, *PFLT_PARAMETERS;

#if !defined(_AMD64_) && !defined(_IA64_)
#include "poppack.h"
#endif


///////////////////////////////////////////////////////////////////////////////
//
//                      CALLBACK DATA definition
//
///////////////////////////////////////////////////////////////////////////////

//
//  Changeable portion of the callback data. Any of the parameters in this
//  structure that are passed in via CallbackData->Px,  can be changed by
//  a mini-filter.  However if filter changes ANY of the parameters in this
//  structure, it needs to issue FltSetCallbackDataDirty()  on the
//  callback-data or the changes will not be honored & unpredictable failures
//  may occur.
//

typedef struct _FLT_IO_PARAMETER_BLOCK {


    //
    //  Fields from IRP
    //  Flags

    ULONG IrpFlags;

    //
    //  Major/minor functions from IRP
    //

    UCHAR MajorFunction;
    UCHAR MinorFunction;

    //
    //  The flags associated with operations.
    //  The IO_STACK_LOCATION.Flags field in the old model (SL_* flags)
    //

    UCHAR OperationFlags;

    //
    //  For alignment
    //

    UCHAR Reserved;


    //
    //  The FileObject that is the target for this
    //  IO operation.
    //

    PFILE_OBJECT TargetFileObject;

    //
    //  Instance that i/o is directed to
    //

    PFLT_INSTANCE TargetInstance;

    //
    //  Normalized parameters for the operation
    //

    FLT_PARAMETERS Parameters;

} FLT_IO_PARAMETER_BLOCK, *PFLT_IO_PARAMETER_BLOCK;


//
//  Flag Bit definitions for the Flags variable of FLT_CALLBACK_DATA
//

typedef ULONG FLT_CALLBACK_DATA_FLAGS;

    //
    //  Flags passed to mini-filters
    //

    //
    //  This mask designates the flags that describe the the type of i/o
    //  and parameters
    //
    #define FLTFL_CALLBACK_DATA_REISSUE_MASK           0x0000FFFF

    //
    //  The below 3 flags are mutually exclusive.
    //  i.e. only ONE and exacly one hould be set for the callback data.
    //  Once set they should never change
    //
    #define FLTFL_CALLBACK_DATA_IRP_OPERATION           0x00000001    // Set for Irp operations
    #define FLTFL_CALLBACK_DATA_FAST_IO_OPERATION       0x00000002    // Set for Fast Io operations
    #define FLTFL_CALLBACK_DATA_FS_FILTER_OPERATION     0x00000004    // Set for Fs Filter operations
    //
    //  In principle this flag can be set for any operation. Once set it shouldn't change
    //
    #define FLTFL_CALLBACK_DATA_SYSTEM_BUFFER           0x00000008    // Set if the buffer passed in for the i/o was a system buffer



    //
    //  Below flags are relevant only for IRP-based i/o - i.e. only
    //  if FLTFL_CALLBACK_DATA_IRP_OPERATION was set. If the i/o was reissued
    //  both flags will necessarily be set
    //
    #define FLTFL_CALLBACK_DATA_GENERATED_IO            0x00010000    // Set if this is I/O generated by a mini-filter
    #define FLTFL_CALLBACK_DATA_REISSUED_IO             0x00020000    // Set if this I/O was reissued

    //
    //  Below 2 flags are set only for post-callbacks.
    //
    #define FLTFL_CALLBACK_DATA_DRAINING_IO             0x00040000    // set if this operation is being drained. If set,
    #define FLTFL_CALLBACK_DATA_POST_OPERATION          0x00080000    // Set if this is a POST operation

    //
    //  This flag can only be set by Filter Manager, only for an IRP based operation
    //  and only for a post callback. When set, it specifies that a lower level driver
    //  allocated a buffer for AssociatedIrp.SystemBuffer in which the data for 
    //  the operation will be returned to the IO manager. Filters need to know this 
    //  because when they were called in the PRE operation AssociatedIrp.SystemBuffer 
    //  was null and as such their buffer is set to UserBuffer and they have no way of 
    //  getting the real data from SystemBuffer. Check the IRP_DEALLOCATE_BUFFER flag for
    //  more details on how this is used by file systems.
    //

    #define FLTFL_CALLBACK_DATA_NEW_SYSTEM_BUFFER       0x00100000

    //
    //  Flags set by mini-filters: these are set by the minifilters and may be reset
    //  by filter manager.
    //
    #define FLTFL_CALLBACK_DATA_DIRTY                   0x80000000    // Set by caller if parameters were changed



#if FLT_MGR_WIN7 

//
//  CallbackData allocation flags.
//

typedef ULONG FLT_ALLOCATE_CALLBACK_DATA_FLAGS;

    //
    //  Normaly only the IrpCtrl is allocated and the other members
    //  that might be needed are allocated at the time when they are needed.
    //  This flag allows the user to preallocate all other structures that 
    //  are needed thus avoiding a potential allocation failure at a later
    //  time. Useful when a filter wants to save a callbackdata to use in 
    //  case it needs to perform IO under low memory conditions. 
    //

    #define FLT_ALLOCATE_CALLBACK_DATA_PREALLOCATE_ALL_MEMORY   0x00000001

#endif //FLT_MGR_WIN7

//
//  This defines the standard information passed to a mini-filter for
//  every operation callback.
//

typedef struct _FLT_CALLBACK_DATA {

    //
    //  Flags
    //

    FLT_CALLBACK_DATA_FLAGS Flags;

    //
    //  Thread that initiated this operation.
    //

    PETHREAD CONST Thread;

    //
    //  Pointer to the changeable i/o parameters
    //

    PFLT_IO_PARAMETER_BLOCK CONST Iopb;

    //
    //  For pre-op calls: if filter returns STATUS_IO_COMPLETE, then it should
    //  set the return i/o status here.  For post-operation calls, this is set
    //  by filter-manager indicating the completed i/o status.
    //

    IO_STATUS_BLOCK IoStatus;


    struct _FLT_TAG_DATA_BUFFER *TagData;

    union {
        struct {

            //
            //  Queue links if the FltMgr queue is used to
            //  pend the callback
            //

            LIST_ENTRY QueueLinks;

            //
            //  Additional context
            //

            PVOID QueueContext[2];
        };

        //
        //  The following are available to filters to use
        //  in whatever manner desired if not using the filter manager
        //  queues.
        //  NOTE:  These fields are only valid while the filter is
        //         processing this operation which is inside the operation
        //         callback or while the operation is pended.
        //

        PVOID FilterContext[4];
    };

    //
    //  Original requester mode of caller
    //

    KPROCESSOR_MODE RequestorMode;

} FLT_CALLBACK_DATA, *PFLT_CALLBACK_DATA;


//
//  Routines to manipulate callback data dirty state
//

VOID
FLTAPI
FltSetCallbackDataDirty(
    __inout PFLT_CALLBACK_DATA Data
    );

VOID
FLTAPI
FltClearCallbackDataDirty(
    __inout PFLT_CALLBACK_DATA Data
    );

BOOLEAN
FLTAPI
FltIsCallbackDataDirty(
    __in PFLT_CALLBACK_DATA Data
    );


//
//  These used to be macros and our now routines.  This was done for greater
//  flexibility in the future.  I have kept the macros around for compatibility
//  with existing filters.
//

#define FLT_SET_CALLBACK_DATA_DIRTY(Data)   FltSetCallbackDataDirty(Data)
#define FLT_CLEAR_CALLBACK_DATA_DIRTY(Data) FltClearCallbackDataDirty(Data)
#define FLT_IS_CALLBACK_DATA_DIRTY(Data)    FltIsCallbackDataDirty(Data)

//
//  These just check the kind of operation for the CallbackData
//  All of them take callback data as the parameter
//

#define FLT_IS_IRP_OPERATION(Data)          (FlagOn( (Data)->Flags, FLTFL_CALLBACK_DATA_IRP_OPERATION ))
#define FLT_IS_FASTIO_OPERATION(Data)       (FlagOn( (Data)->Flags, FLTFL_CALLBACK_DATA_FAST_IO_OPERATION ))
#define FLT_IS_FS_FILTER_OPERATION(Data)    (FlagOn( (Data)->Flags, FLTFL_CALLBACK_DATA_FS_FILTER_OPERATION ))

//
//  Bunch of other miscellaneous i/o characteristics
//

#define FLT_IS_REISSUED_IO(Data)            (FlagOn( (Data)->Flags, FLTFL_CALLBACK_DATA_REISSUED_IO ))

//
//  This test only is useful for IRP operations to check if the passed in buffer is a system buffer
//

#define FLT_IS_SYSTEM_BUFFER(Data)          (FlagOn( (Data)->Flags, FLTFL_CALLBACK_DATA_SYSTEM_BUFFER ))


///////////////////////////////////////////////////////////////////////////////
//
//                        Context Definitions
//
///////////////////////////////////////////////////////////////////////////////

//
//  Definitions for the types of contexts that are available.
//

typedef USHORT FLT_CONTEXT_TYPE;

    #define FLT_VOLUME_CONTEXT          0x0001
    #define FLT_INSTANCE_CONTEXT        0x0002
    #define FLT_FILE_CONTEXT            0x0004
    #define FLT_STREAM_CONTEXT          0x0008
    #define FLT_STREAMHANDLE_CONTEXT    0x0010
    #define FLT_TRANSACTION_CONTEXT     0x0020

    #define FLT_CONTEXT_END             0xffff

//
//  Definition for ALL contexts
//

#define FLT_ALL_CONTEXTS (FLT_VOLUME_CONTEXT |      \
                          FLT_INSTANCE_CONTEXT |    \
                          FLT_FILE_CONTEXT |        \
                          FLT_STREAM_CONTEXT |      \
                          FLT_STREAMHANDLE_CONTEXT |\
                          FLT_TRANSACTION_CONTEXT)

//
//  This structure is passed to a filter's pre/post operation callback
//  routines and defines all of the handles associated with the given
//  operation.
//

typedef struct _FLT_RELATED_OBJECTS {

    USHORT CONST Size;
    USHORT CONST TransactionContext;            //TxF mini-version
    PFLT_FILTER CONST Filter;
    PFLT_VOLUME CONST Volume;
    PFLT_INSTANCE CONST Instance;
    PFILE_OBJECT CONST FileObject;
    PKTRANSACTION CONST Transaction;

} FLT_RELATED_OBJECTS, *PFLT_RELATED_OBJECTS;

typedef CONST struct _FLT_RELATED_OBJECTS *PCFLT_RELATED_OBJECTS;

//
//  Structure used by a filter to get/release multiple contexts at once.
//

typedef struct _FLT_RELATED_CONTEXTS {

    PFLT_CONTEXT VolumeContext;
    PFLT_CONTEXT InstanceContext;
    PFLT_CONTEXT FileContext;
    PFLT_CONTEXT StreamContext;
    PFLT_CONTEXT StreamHandleContext;
    PFLT_CONTEXT TransactionContext;

} FLT_RELATED_CONTEXTS, *PFLT_RELATED_CONTEXTS;

//
//  Prototype for Context Cleanup routine.  This routine is called by the
//  filterManager when it has determined it is time to free a context.
//  The called filter should cleanup any allocated memory they have inside
//  this context structure.  FLTMGR will free the context upon return.
//

typedef VOID
(FLTAPI *PFLT_CONTEXT_CLEANUP_CALLBACK) (
    __in PFLT_CONTEXT Context,
    __in FLT_CONTEXT_TYPE ContextType
    );

//
//  Function prototypes for Allocation and Free callbacks that may be used by
//  advanced filters that want to manage context allocation directly.
//
//  NOTE:  Most filters do not need to use this feature since the default
//         mechanism built into FltMgr does this efficiently.
//

typedef PVOID
(FLTAPI *PFLT_CONTEXT_ALLOCATE_CALLBACK)(
    __in POOL_TYPE PoolType,
    __in SIZE_T Size,
    __in FLT_CONTEXT_TYPE ContextType
    );

typedef VOID
(FLTAPI *PFLT_CONTEXT_FREE_CALLBACK)(
    __in PVOID Pool,
    __in FLT_CONTEXT_TYPE ContextType
    );

//
//  Defines context registration flags
//

typedef USHORT FLT_CONTEXT_REGISTRATION_FLAGS;

    //
    //  By default, the FltMgr matches exactly a given context allocation
    //  request with a size specified at context registration time.  If
    //  this flag is specified, then the FltMgr will use a given registered
    //  size definition if the requested size is <= to it.  Note that the
    //  FltMgr sorts multiple size definions into ascending order.
    //
    //  This flag is ignored on entries with FLT_VARIABLE_SIZED_CONTEXTS
    //  specified or Alloc/Free routines specified
    //

    #define FLTFL_CONTEXT_REGISTRATION_NO_EXACT_SIZE_MATCH 0x0001


//
//  When this value is used in the "Size" field of the FLT_CONTEXT_REGISTRATION
//  structure, then this registered context entry has no explicit size.
//  When allocation requests are made, FltMgr directly allocates and frees
//  the memory from pool.
//
//  For a given context and pool type, only one entry may have this value.
//  This may be included with multiple explicitly sized entries.  This will
//  always be sorted to the end of the list.
//

#define FLT_VARIABLE_SIZED_CONTEXTS ((SIZE_T)-1)

//
//  An array of this structure is used for registering the different kinds of
//  contexts used by this mini-filter.
//
//  At least one of these records must be speicifed to allocate a context of a
//  given type.
//

typedef struct _FLT_CONTEXT_REGISTRATION {

    //
    //  Identifies the type of this context
    //

    FLT_CONTEXT_TYPE ContextType;

    //
    //  Local flags
    //

    FLT_CONTEXT_REGISTRATION_FLAGS Flags;

    //
    //  Routine to call to cleanup the context before it is deleted.
    //  This may be NULL if not cleanup is needed.
    //

    PFLT_CONTEXT_CLEANUP_CALLBACK ContextCleanupCallback;

    //
    //  Defines the size & pool tag the mini-filter wants for the given context.
    //  FLT_VARIABLE_SIZED_CONTEXTS may be specified for the size if variable
    //  sized contexts are used.  A size of zero is valid.  If an empty pooltag
    //  value is specified, the FLTMGR will use a context type specific tag.
    //
    //  If an explicit size is specified, the FLTMGR internally optimizes the
    //  allocation of that entry.
    //
    //  NOTE:  These fields are ignored if Allocate & Free routines are
    //         specifed.
    //

    SIZE_T Size;
    ULONG PoolTag;

    //
    //  Specifies the ALLOCATE and FREE routines that should be used
    //  when allocating a context for this mini-filter.
    //
    //  NOTE: The above size & PoolTag fields are ignored when these routines
    //        are defined.
    //

    PFLT_CONTEXT_ALLOCATE_CALLBACK ContextAllocateCallback;
    PFLT_CONTEXT_FREE_CALLBACK ContextFreeCallback;

    //
    //  Reserved for future expansion
    //

    PVOID Reserved1;

} FLT_CONTEXT_REGISTRATION, *PFLT_CONTEXT_REGISTRATION;

typedef const FLT_CONTEXT_REGISTRATION *PCFLT_CONTEXT_REGISTRATION;


///////////////////////////////////////////////////////////////////////////////
//
//                  Known File System Types
//
///////////////////////////////////////////////////////////////////////////////

//
//  The enum FLT_FILESYSTEM_TYPE has been moved to FltUserStructures.h
//  so it can be referenced by both user mode and kernel mode components
//


///////////////////////////////////////////////////////////////////////////////
//
//              Instance attach/detach callback definitions
//
///////////////////////////////////////////////////////////////////////////////

//
//                ******** Instance setup ********
//

//
//  Flags identifying why the given instance attach callback routine was
//  called.  More then one bit may be set.
//

typedef ULONG FLT_INSTANCE_SETUP_FLAGS;

    //
    //  If set, this is an automatic instance attachment notification.  These
    //  occur when the filter is first loaded for all existing volumes, and
    //  when a new volume is mounted.
    //

    #define FLTFL_INSTANCE_SETUP_AUTOMATIC_ATTACHMENT   0x00000001

    //
    //  If set, this is a manual instance attachment request via FilterAttach
    //  (user mode) or FltAttachVolume.
    //

    #define FLTFL_INSTANCE_SETUP_MANUAL_ATTACHMENT      0x00000002

    //
    //  If set, this is an automatic instance notification for a volume that
    //  has just been mounted in the system.
    //

    #define FLTFL_INSTANCE_SETUP_NEWLY_MOUNTED_VOLUME   0x00000004

#if FLT_MGR_LONGHORN
    //
    //  If set, this volume is not currently attached to a storage stack.
    //  This usually means the volume is dismounted but it does not always
    //  mean that.  There are scnearios with certain file systems (fat & cdfs
    //  being some) where a volume can become reattached after it has detached.
    //  This flag is only set in Longhorn or later.
    //

    #define FLTFL_INSTANCE_SETUP_DETACHED_VOLUME        0x00000008

#endif // FLT_MGR_LONGHORN


//
//  This is called whenever a new instance is being created.  This gives the
//  filter the opportunity to decide if they want to attach to the given
//  volume or not.
//
//  A SUCCESS return value will cause the instance to be attached to the given
//  volume.  A WARNING or ERROR return value will cause the instance to NOT be
//  attached to the given volume.  Following are reasonable sample return
//  values:
//      STATUS_SUCCESS
//      STATUS_FLT_DO_NOT_ATTACH
//
//  If no callback is defined the given instance will be attached.
//

typedef NTSTATUS
(FLTAPI *PFLT_INSTANCE_SETUP_CALLBACK) (
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in FLT_INSTANCE_SETUP_FLAGS Flags,
    __in DEVICE_TYPE VolumeDeviceType,
    __in FLT_FILESYSTEM_TYPE VolumeFilesystemType
    );


//
//          ******** Instance Query Detach ********
//

//
//  Flags identifying why the given instance query detach callback routine was
//  called.  More then one bit may be set.
//

typedef ULONG FLT_INSTANCE_QUERY_TEARDOWN_FLAGS;

  //
  //  No flags currently defined
  //

//
//  This is called whenever a manual detachment request is made for the given
//  instance.  This is not called for mandatory detachment requests (like
//  filter unload or volume dismount).  This gives the filter the opportunity
//  to decide if they want to detach from the given volume or not.
//
//  A SUCCESS return value will cause the instance to be detached from the
//  given volume.  A WARNING or ERROR return value will cause the instance to
//  NOT be detached from the given volume.  Following are reasonable sample
//  return values:
//      STATUS_SUCCESS
//      STATUS_FLT_DO_NOT_DETACH
//
//  If no callback is defined the given instance will NOT be detached.
//

typedef NTSTATUS
(FLTAPI *PFLT_INSTANCE_QUERY_TEARDOWN_CALLBACK) (
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    );


//
//          ******** Instance teardown ********
//

//
//  Flag identifying why the given instance detach callback routine was called.
//  More then one bit may be set.
//

typedef ULONG FLT_INSTANCE_TEARDOWN_FLAGS;

    //
    //  If set, this is a manual instance detach request via FilterDetach
    //  (user mode) or FltDetachVolume (kernel mode).
    //

    #define FLTFL_INSTANCE_TEARDOWN_MANUAL                  0x00000001

    //
    //  If set, the filter is being unloaded.
    //

    #define FLTFL_INSTANCE_TEARDOWN_FILTER_UNLOAD           0x00000002

    //
    //  If set, the filter is being unloaded.
    //

    #define FLTFL_INSTANCE_TEARDOWN_MANDATORY_FILTER_UNLOAD 0x00000004

    //
    //  If set, the volume is being dismounted.
    //

    #define FLTFL_INSTANCE_TEARDOWN_VOLUME_DISMOUNT         0x00000008

    //
    //  If set, an error occurred while doing instance setup (like running
    //  out of memory).
    //

    #define FLTFL_INSTANCE_TEARDOWN_INTERNAL_ERROR          0x00000010


//
//  This is the prototype for two different teardown callback routines.
//
//  The TEARDOWN_START routine is called at the beginning of teardown process.
//  There may still be operation callbacks in progress.  This is called to give
//  the filter the oppertunity to do the following things:
//  - Restart any pended operations
//  - Set state so that minimual processing will be performed on future
//    operation callbacks.
//  - Unregister from other OS callback APIs
//

//
//  The TEARDOWN_COMPLETE routine is called after teardown has been finished.
//  The system guarentees that all existing callbacks have been completed
//  before this routine is called.  This is called to give the filter the
//  oppertunity to:
//  - Close any open files.
//  - do other instance state cleanup.
//

typedef VOID
(FLTAPI *PFLT_INSTANCE_TEARDOWN_CALLBACK) (
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in FLT_INSTANCE_TEARDOWN_FLAGS Reason
    );

//////////////////////////////////////////////////////////////////////////////
//
//                  Pre/Post Operation Callback definitions
//
///////////////////////////////////////////////////////////////////////////////

//
//  Values returned from the pre-operation callback routine defining what
//  to do next.
//

typedef enum _FLT_PREOP_CALLBACK_STATUS {

    FLT_PREOP_SUCCESS_WITH_CALLBACK,
    FLT_PREOP_SUCCESS_NO_CALLBACK,
    FLT_PREOP_PENDING,
    FLT_PREOP_DISALLOW_FASTIO,
    FLT_PREOP_COMPLETE,
    FLT_PREOP_SYNCHRONIZE


} FLT_PREOP_CALLBACK_STATUS, *PFLT_PREOP_CALLBACK_STATUS;

//
//  Pre-operation callback prototype.
//

typedef FLT_PREOP_CALLBACK_STATUS
(FLTAPI *PFLT_PRE_OPERATION_CALLBACK) (
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    );


//
//  Values returned from the post-operation callback routine defining what
//  to od next.
//

typedef enum _FLT_POSTOP_CALLBACK_STATUS {

    FLT_POSTOP_FINISHED_PROCESSING,
    FLT_POSTOP_MORE_PROCESSING_REQUIRED

} FLT_POSTOP_CALLBACK_STATUS, *PFLT_POSTOP_CALLBACK_STATUS;

//
//  Flag BITS sent to the post-operation callback routine
//

typedef ULONG FLT_POST_OPERATION_FLAGS;

    //
    //  If set, this instance is being detached and this post-operation
    //  routine has been called for cleanup processing (drained).  Since this
    //  instance is going away, you should perform a minimum of operations
    //  while processing this completion.
    //

    #define FLTFL_POST_OPERATION_DRAINING               0x00000001

//
//  Post-operation callback prototype
//

typedef FLT_POSTOP_CALLBACK_STATUS
(FLTAPI *PFLT_POST_OPERATION_CALLBACK) (
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in_opt PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    );

//
//  Post operation callbacks may be called at DPC level.  This routine may be
//  used to transfer completion processing to a "safe" IRQL level.  This
//  routine will determine if it is safe to call the "SafePostCallback" now
//  or if it must post the request to a worker thread.  If posting to a worker
//  thread is needed it determines it is safe to do so (some operations can
//  not be posted like paging IO).
//

__checkReturn
BOOLEAN
FLTAPI
FltDoCompletionProcessingWhenSafe(
    __in PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in_opt PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags,
    __in PFLT_POST_OPERATION_CALLBACK SafePostCallback,
    __out PFLT_POSTOP_CALLBACK_STATUS RetPostOperationStatus
    );

//
//  Defines current operation callback flags.
//

typedef ULONG FLT_OPERATION_REGISTRATION_FLAGS;

    //
    //  If set, the filter's callbacks for this operation will not be called,
    //  if it's a paging i/o operation. This flag is relevant only for IRP-based
    //  operations & ignored for non-IRP operations
    //

    #define FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO     0x00000001

    //
    //  If set read/write operations that are not non-cached will be skipped:
    //  i.e. the mini-filters callback for this operation will be bypassed.
    //  This flag is relevant only for IRP_MJ_READ & IRP_MJ_WRITE
    //  This of course implies that fast i/o reads and writes will be skipped,
    //  since those imply cached i/o by default
    //

    #define FLTFL_OPERATION_REGISTRATION_SKIP_CACHED_IO     0x00000002

    //
    //  If set all operations that are not issued on a DASD (volume) handle will be skipped:
    //  i.e. the mini-filters callback for this operation will be bypassed.
    //  This flag is relevant for all operations
    //

    #define FLTFL_OPERATION_REGISTRATION_SKIP_NON_DASD_IO   0x00000004


//
//  Structure used for registering operation callback routines
//

typedef struct _FLT_OPERATION_REGISTRATION {

    UCHAR MajorFunction;
    FLT_OPERATION_REGISTRATION_FLAGS Flags;
    PFLT_PRE_OPERATION_CALLBACK PreOperation;
    PFLT_POST_OPERATION_CALLBACK PostOperation;

    PVOID Reserved1;

} FLT_OPERATION_REGISTRATION, *PFLT_OPERATION_REGISTRATION;


///////////////////////////////////////////////////////////////////////////////
//
//  This defines structures and flags for reparse point tag notifications
//  that a filter uses to register.
//
///////////////////////////////////////////////////////////////////////////////

typedef struct _FLT_TAG_DATA_BUFFER {
    ULONG FileTag;
    USHORT TagDataLength;
    USHORT UnparsedNameLength;
    union {
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            ULONG  Flags;
            WCHAR  PathBuffer[1];
        } SymbolicLinkReparseBuffer;

        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            WCHAR PathBuffer[1];
        } MountPointReparseBuffer;

        struct {
            UCHAR  DataBuffer[1];
        } GenericReparseBuffer;

        //
        //  Used for non-Microsoft reparse points
        //

        struct {
            GUID TagGuid;
            UCHAR DataBuffer[1];
        } GenericGUIDReparseBuffer;
    };
} FLT_TAG_DATA_BUFFER, *PFLT_TAG_DATA_BUFFER;

#if _MSC_VER >= 1200
#pragma warning(pop)
#endif

#define FLT_TAG_DATA_BUFFER_HEADER_SIZE   FIELD_OFFSET(FLT_TAG_DATA_BUFFER, GenericReparseBuffer)



///////////////////////////////////////////////////////////////////////////////
//
//                      Filter Unload Definitions
//
///////////////////////////////////////////////////////////////////////////////

typedef ULONG FLT_FILTER_UNLOAD_FLAGS;

    //
    //  If set, the OS has requested to unload this filter and the operation
    //  can not be failed.
    //

    #define FLTFL_FILTER_UNLOAD_MANDATORY               0x00000001


//
//  Callback to notify a filter it is being unloaded.  If the filter returns
//  a SUCCESS code, then the filter is unloaded.  If a WARNING or ERROR
//  code is returned then the filter is not unloaded.  If not callback is
//  defined the filter will not be unloaded.
//

typedef NTSTATUS
(FLTAPI *PFLT_FILTER_UNLOAD_CALLBACK) (
    FLT_FILTER_UNLOAD_FLAGS Flags
    );

/////////////////////////////////////////////////////////////////////////
//
//  Routines and structures for Name Providing Filter (filters that modify
//  names in the namespace).
//
////////////////////////////////////////////////////////////////////////

//
//  The FLT_NAME_CONTROL structure is used to efficiently manage a name buffer
//  as a name is generated by a filter that modifies the namespace.
//
//  The filter should never free or try to replace the buffer in the Name
//  UNICODE_STRING directly.  It should call FltNameControlCheckAndGrow to
//  varify that the buffer is large enough for more data to be added and grow
//  the buffer as needed.
//

typedef struct _FLT_NAME_CONTROL {

    //
    //  The unicode string where the name should be set.
    //

    UNICODE_STRING Name;

} FLT_NAME_CONTROL, *PFLT_NAME_CONTROL;

__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTSTATUS
FLTAPI
FltCheckAndGrowNameControl (
    __inout PFLT_NAME_CONTROL NameCtrl,
    __in USHORT NewSize
    );

//
//  Define this hear for the PFLT_GENERATE_FILE_NAME signature.  This is defined
//  again later at the point where the flags are defined.
//

typedef ULONG FLT_FILE_NAME_OPTIONS;

typedef NTSTATUS
(FLTAPI *PFLT_GENERATE_FILE_NAME) (
    __in PFLT_INSTANCE Instance,
    __in PFILE_OBJECT FileObject,
    __in_opt PFLT_CALLBACK_DATA CallbackData,
    __in FLT_FILE_NAME_OPTIONS NameOptions,
    __out PBOOLEAN CacheFileNameInformation,
    __out PFLT_NAME_CONTROL FileName
    );

typedef ULONG FLT_NORMALIZE_NAME_FLAGS;

//
//  Normalize name flags
//

    #define FLTFL_NORMALIZE_NAME_CASE_SENSITIVE         0x01
    #define FLTFL_NORMALIZE_NAME_DESTINATION_FILE_NAME  0x02

typedef NTSTATUS
(FLTAPI *PFLT_NORMALIZE_NAME_COMPONENT) (
    __in PFLT_INSTANCE Instance,
    __in PCUNICODE_STRING ParentDirectory,
    __in USHORT VolumeNameLength,
    __in PCUNICODE_STRING Component,
    __out_bcount(ExpandComponentNameLength) PFILE_NAMES_INFORMATION ExpandComponentName,
    __in ULONG ExpandComponentNameLength,
    __in FLT_NORMALIZE_NAME_FLAGS Flags,
    __deref_inout_opt PVOID *NormalizationContext
    );

typedef NTSTATUS
(FLTAPI *PFLT_NORMALIZE_NAME_COMPONENT_EX) (
    __in PFLT_INSTANCE Instance,
    __in PFILE_OBJECT FileObject,
    __in PCUNICODE_STRING ParentDirectory,
    __in USHORT VolumeNameLength,
    __in PCUNICODE_STRING Component,
    __out_bcount(ExpandComponentNameLength) PFILE_NAMES_INFORMATION ExpandComponentName,
    __in ULONG ExpandComponentNameLength,
    __in FLT_NORMALIZE_NAME_FLAGS Flags,
    __deref_inout_opt PVOID *NormalizationContext
    );

typedef VOID
(FLTAPI *PFLT_NORMALIZE_CONTEXT_CLEANUP) (
    __in_opt PVOID *NormalizationContext
    );

__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTSTATUS
FLTAPI
FltPurgeFileNameInformationCache (
    __in PFLT_INSTANCE Instance,
    __in_opt PFILE_OBJECT FileObject
    );

///////////////////////////////////////////////////////////////////////////////
//
//                 Transaction callback definitions
//
///////////////////////////////////////////////////////////////////////////////

#if FLT_MGR_LONGHORN

typedef NTSTATUS
(FLTAPI *PFLT_TRANSACTION_NOTIFICATION_CALLBACK) (
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PFLT_CONTEXT TransactionContext,
    __in ULONG NotificationMask
    );

#endif // FLT_MGR_LONGHORN


//////////////////////////////////////////////////////////////////////////////
//
//  This structure is used at registration time to define what callbacks
//  this driver wishes to receive.
//
///////////////////////////////////////////////////////////////////////////////

//
//  This defines the MAJOR/MINOR version number to be passed in at registration
//  time.  The filter manager uses this number to validate / process the
//  parameters passed in.  Note that the minor version number can change and
//  you will still be able to register.  If the major version number changes
//  then the filter will no longer load.
//

//
//  Registration version for XP SP2 and W2K3 SP1
//

#define FLT_REGISTRATION_VERSION_0200  0x0200

//
//  Registration version for Vista Beta 2
//  (adds PFLT_TRANSACTION_NOTIFICATION_CALLBACK)
//

#define FLT_REGISTRATION_VERSION_0201  0x0201

//
//  Registration version for Vista RTM
//  (adds PFLT_NORMALIZE_NAME_COMPONENT_EX)
//

#define FLT_REGISTRATION_VERSION_0202  0x0202

//
//  NOTE:  You should always pass in this defined value (do not explicitly
//         specify older values)

#if FLT_MGR_LONGHORN
    #define FLT_REGISTRATION_VERSION   FLT_REGISTRATION_VERSION_0202  // Current version is 2.02
#else
    #define FLT_REGISTRATION_VERSION   FLT_REGISTRATION_VERSION_0200  // Current version is 2.00
#endif

//
//  Defines current registration flags
//

typedef ULONG FLT_REGISTRATION_FLAGS;

    //
    //  If set, this filter does not support a service stop request. This is
    //  is how the OS unloads drivers.
    //

    #define FLTFL_REGISTRATION_DO_NOT_SUPPORT_SERVICE_STOP  0x00000001

//
//  Registration structure
//

typedef struct _FLT_REGISTRATION {

    //
    //  The size, in bytes, of this registration structure.
    //

    USHORT Size;
    USHORT Version;

    //
    //  Flag values
    //

    FLT_REGISTRATION_FLAGS Flags;

    //
    //  Variable length array of routines that are used to manage contexts in
    //  the system.
    //

    CONST FLT_CONTEXT_REGISTRATION *ContextRegistration;

    //
    //  Variable length array of routines used for processing pre- and post-
    //  file system operations.
    //

    CONST FLT_OPERATION_REGISTRATION *OperationRegistration;

    //
    //  This is called before a filter is unloaded.  If an ERROR or WARNING
    //  status is returned then the filter is NOT unloaded.  A mandatory unload
    //  can not be failed.
    //
    //  If a NULL is specified for this routine, then the filter can never be
    //  unloaded.
    //

    PFLT_FILTER_UNLOAD_CALLBACK FilterUnloadCallback;

    //
    //  This is called to see if a filter would like to attach an instance
    //  to the given volume.  If an ERROR or WARNING status is returned, an
    //  attachment is not made.
    //
    //  If a NULL is specified for this routine, the attachment is always made.
    //

    PFLT_INSTANCE_SETUP_CALLBACK InstanceSetupCallback;

    //
    //  This is called to see if the filter wants to detach from the given
    //  volume.  This is only called for manual detach requests.  If an
    //  ERROR or WARNING status is returned, the filter is not detached.
    //
    //  If a NULL is specified for this routine, then instances can never be
    //  manually detached.
    //

    PFLT_INSTANCE_QUERY_TEARDOWN_CALLBACK InstanceQueryTeardownCallback;

    //
    //  This is called at the start of a filter detaching from a volume.
    //
    //  It is OK for this field to be NULL.
    //

    PFLT_INSTANCE_TEARDOWN_CALLBACK InstanceTeardownStartCallback;

    //
    //  This is called at the end of a filter detaching from a volume.  All
    //  outstanding operations have been completed by the time this routine
    //  is called.
    //
    //  It is OK for this field to be NULL.
    //

    PFLT_INSTANCE_TEARDOWN_CALLBACK InstanceTeardownCompleteCallback;

    //
    //  The following callbacks are provided by a filter only if it is
    //  interested in modifying the name space.
    //
    //  If NULL is specified for these callbacks, it is assumed that the
    //  filter would not affect the name being requested.
    //

    PFLT_GENERATE_FILE_NAME GenerateFileNameCallback;

    PFLT_NORMALIZE_NAME_COMPONENT NormalizeNameComponentCallback;

    PFLT_NORMALIZE_CONTEXT_CLEANUP NormalizeContextCleanupCallback;

    //
    //  The PFLT_NORMALIZE_NAME_COMPONENT_EX callback is also a name
    //  provider callback. It is not included here along with the
    //  other name provider callbacks to take care of the registration
    //  structure versioning issues.
    //

#if FLT_MGR_LONGHORN

    //
    //  This is called for transaction notifications received from the KTM
    //  when a filter has enlisted on that transaction.
    //

    PFLT_TRANSACTION_NOTIFICATION_CALLBACK TransactionNotificationCallback;

    //
    //  This is the extended normalize name component callback
    //  If a mini-filter provides this callback, then  this callback
    //  will be used as opposed to using PFLT_NORMALIZE_NAME_COMPONENT
    //
    //  The PFLT_NORMALIZE_NAME_COMPONENT_EX provides an extra parameter
    //  (PFILE_OBJECT) in addition to the parameters provided to
    //  PFLT_NORMALIZE_NAME_COMPONENT. A mini-filter may use this parameter
    //  to get to additional information like the TXN_PARAMETER_BLOCK.
    //
    //  A mini-filter that has no use for the additional parameter may
    //  only provide a PFLT_NORMALIZE_NAME_COMPONENT callback.
    //
    //  A mini-filter may provide both a PFLT_NORMALIZE_NAME_COMPONENT
    //  callback and a PFLT_NORMALIZE_NAME_COMPONENT_EX callback. The
    //  PFLT_NORMALIZE_NAME_COMPONENT_EX callback will be used by fltmgr
    //  versions that understand this callback (Vista RTM and beyond)
    //  and PFLT_NORMALIZE_NAME_COMPONENT callback will be used by fltmgr
    //  versions that do not understand the PFLT_NORMALIZE_NAME_COMPONENT_EX
    //  callback (prior to Vista RTM). This allows the same mini-filter
    //  binary to run with all versions of fltmgr.
    //

    PFLT_NORMALIZE_NAME_COMPONENT_EX NormalizeNameComponentExCallback;

#endif // FLT_MGR_LONGHORN

} FLT_REGISTRATION, *PFLT_REGISTRATION;



///////////////////////////////////////////////////////////////////////////////
//
// Callback routine for async i/o operations
//
///////////////////////////////////////////////////////////////////////////////

typedef VOID
(FLTAPI *PFLT_COMPLETED_ASYNC_IO_CALLBACK)(
    __in PFLT_CALLBACK_DATA CallbackData,
    __in PFLT_CONTEXT Context
    );


///////////////////////////////////////////////////////////////////////////////
//
// Flags that can be specified in Flt* APIs to indicate the nature of the
// i/o operation
//
// FltReadFile/FltWriteFile will accept these flags for example
//
///////////////////////////////////////////////////////////////////////////////

typedef ULONG FLT_IO_OPERATION_FLAGS;

    //
    //  If set, the given read/write request will be non-cached.
    //

    #define FLTFL_IO_OPERATION_NON_CACHED                   0x00000001

    //
    //  If set, the given read/write request will have the
    //  IRP_PAGING_IO flag set
    //

    #define FLTFL_IO_OPERATION_PAGING                       0x00000002

    //
    //  If set, the given read/write request will not update the
    //  file object's current byte offset.
    //

    #define FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET    0x00000004

#if FLT_MGR_LONGHORN
    //
    //  If set, the given read/write request will have the
    //  IRP_SYNCHRONOUS_PAGING_IO flag set
    //

    #define FLTFL_IO_OPERATION_SYNCHRONOUS_PAGING           0x00000008

#endif // FLT_MGR_LONGHORN


///////////////////////////////////////////////////////////////////////////////
//
//  These routines are used to register/unregister all callback routines for a
//  give file system mini-filter driver.
//
///////////////////////////////////////////////////////////////////////////////

__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTSTATUS
FLTAPI
FltRegisterFilter (
    __in PDRIVER_OBJECT Driver,
    __in CONST FLT_REGISTRATION *Registration,
    __deref_out PFLT_FILTER *RetFilter
    );

__drv_maxIRQL(APC_LEVEL)
VOID
FLTAPI
FltUnregisterFilter (
    __in PFLT_FILTER Filter
    );

__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTSTATUS
FLTAPI
FltStartFiltering (
    __in PFLT_FILTER Filter
    );

__checkReturn
__drv_maxIRQL(APC_LEVEL)
PVOID
FLTAPI
FltGetRoutineAddress (
    __in PCSTR FltMgrRoutineName
    );

///////////////////////////////////////////////////////////////////////////////
//
//  Pending support routines
//
///////////////////////////////////////////////////////////////////////////////


__drv_when(CallbackStatus==FLT_PREOP_COMPLETE, __drv_maxIRQL(DISPATCH_LEVEL)) 
__drv_when(CallbackStatus!=FLT_PREOP_COMPLETE, __drv_maxIRQL(APC_LEVEL))
VOID
FLTAPI
FltCompletePendedPreOperation (
    __in PFLT_CALLBACK_DATA CallbackData,
    __in FLT_PREOP_CALLBACK_STATUS CallbackStatus,
    __in_opt PVOID Context
    );

__drv_maxIRQL(DISPATCH_LEVEL)
VOID
FLTAPI
FltCompletePendedPostOperation (
    __in PFLT_CALLBACK_DATA CallbackData
    );


///////////////////////////////////////////////////////////////////////////////
//
//  Routines for requesting operation status.  This is used to get the result
//  returned by IoCallDriver for operations where STATUS_PENDING is treated
//  as a success code.  This occurs with oplocks and directory change
//  notifications
//
///////////////////////////////////////////////////////////////////////////////

typedef VOID
(FLTAPI *PFLT_GET_OPERATION_STATUS_CALLBACK)(
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PFLT_IO_PARAMETER_BLOCK IopbSnapshot,
    __in NTSTATUS OperationStatus,
    __in_opt PVOID RequesterContext
    );


__checkReturn
__drv_maxIRQL(DISPATCH_LEVEL)
NTSTATUS
FLTAPI
FltRequestOperationStatusCallback(
    __in PFLT_CALLBACK_DATA Data,
    __in PFLT_GET_OPERATION_STATUS_CALLBACK CallbackRoutine,
    __in_opt PVOID RequesterContext
    );


///////////////////////////////////////////////////////////////////////////////
//
//  Memory support routines
//
///////////////////////////////////////////////////////////////////////////////


__drv_when((PoolType==NonPagedPool), __drv_maxIRQL(DISPATCH_LEVEL))
__drv_when((PoolType!=NonPagedPool), __drv_maxIRQL(APC_LEVEL))
PVOID
FLTAPI
FltAllocatePoolAlignedWithTag (
    __in PFLT_INSTANCE Instance,
    __in POOL_TYPE PoolType,
    __in SIZE_T NumberOfBytes,
    __in ULONG Tag
    );

__drv_maxIRQL(DISPATCH_LEVEL)
VOID
FLTAPI
FltFreePoolAlignedWithTag (
    __in PFLT_INSTANCE Instance,
    __in PVOID Buffer,
    __in ULONG Tag
    );

///////////////////////////////////////////////////////////////////////////////
//
//  Routines for getting file, directory and volume names.
//
///////////////////////////////////////////////////////////////////////////////

//
//  The FLT_FILE_NAME_OPTIONS is a ULONG that gets broken down into three
//  sections:
//   bits 0-7:  enumeration representing the file name formats available
//   bits 8-15: enumeration representing the querying methods available
//   bits 16-23:  Currently unused
//   bits 24-31:  Flags
//

typedef ULONG FLT_FILE_NAME_OPTIONS;

//
//  Name format options
//

#define FLT_VALID_FILE_NAME_FORMATS 0x000000ff

    #define FLT_FILE_NAME_NORMALIZED    0x01
    #define FLT_FILE_NAME_OPENED        0x02
    #define FLT_FILE_NAME_SHORT         0x03

#define FltGetFileNameFormat( _NameOptions ) \
    ((_NameOptions) & FLT_VALID_FILE_NAME_FORMATS)

//
//  Name query methods.
//

#define FLT_VALID_FILE_NAME_QUERY_METHODS 0x0000ff00

    //
    //  In the default mode, if it is safe to query the file system,
    //  the Filter Manager try to retrieve the name from the cache first, and,
    //  if a name is not found, the name will be generated by querying the file
    //  system.
    //
    #define FLT_FILE_NAME_QUERY_DEFAULT     0x0100

    //
    //  Query the Filter Manager's name cache for the name, but don't try
    //  to query the file system if the name is not in the cache.
    //
    #define FLT_FILE_NAME_QUERY_CACHE_ONLY  0x0200

    //
    //  Only query the file system for the name, bypassing the Filter Manager's
    //  name cache completely.  Any name retrieved will not be cached.
    //
    #define FLT_FILE_NAME_QUERY_FILESYSTEM_ONLY 0x0300

    //
    //  Query the Filter Manager's name cache, but if the name is not
    //  found try to query the file system if it is safe to do so.
    //
    #define FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP 0x0400

#define FltGetFileNameQueryMethod( _NameOptions ) \
    ((_NameOptions) & FLT_VALID_FILE_NAME_QUERY_METHODS)

//
//  File name option flags
//

#define FLT_VALID_FILE_NAME_FLAGS 0xff000000

    //
    //  This flag is to be used by name provider filters to specify that a name
    //  query request they are making should be redirected to their filter rather
    //  than being satified by the name providers lower in the stack.
    //
    #define FLT_FILE_NAME_REQUEST_FROM_CURRENT_PROVIDER 0x01000000

    //
    //  This flag denotes that the name retrieved from this query should not
    //  be cached.  This is used by name providers as they perform intermediate
    //  queries to generate a name.
    //
    #define FLT_FILE_NAME_DO_NOT_CACHE                  0x02000000

#if FLT_MGR_AFTER_XPSP2

    //
    //  This flag denotes that it is safe to query the name in post-CREATE if
    //  STATUS_REPARSE was returned.  To ensure the name returned is valid,
    //  the call must know that the FileObject->FileName was not changed before
    //  STATUS_REPARSE was returned.
    //
    #define FLT_FILE_NAME_ALLOW_QUERY_ON_REPARSE        0x04000000

#endif

//
//  The flags are used to tell the file name routines which types of names
//  you would like parsed from the full name.  They are also used to specify
//  which names have been filled in for a given FLT_FILE_NAME_INFORMATION
//  structure.
//

typedef USHORT FLT_FILE_NAME_PARSED_FLAGS;

    #define FLTFL_FILE_NAME_PARSED_FINAL_COMPONENT      0x0001
    #define FLTFL_FILE_NAME_PARSED_EXTENSION            0x0002
    #define FLTFL_FILE_NAME_PARSED_STREAM               0x0004
    #define FLTFL_FILE_NAME_PARSED_PARENT_DIR           0x0008

//
//  This structure holds the different types of name information that
//  can be given for a file.  The NamesParsed field will have the
//  appropriate flags set to denote which names are filled in inside
//  the structure.
//

typedef struct _FLT_FILE_NAME_INFORMATION {

    USHORT Size;

    //
    //  For each bit that is set in the NamesParsed flags field, the
    //  corresponding substring from Name has been appropriately
    //  parsed into one of the unicode strings below.
    //

    FLT_FILE_NAME_PARSED_FLAGS NamesParsed;

    //
    //  The name format that this FLT_FILE_NAME_INFORMATION structure
    //  represents.
    //

    FLT_FILE_NAME_OPTIONS Format;

    //
    //  For normalized and opened names, this name contains the version of
    //  name in the following format:
    //
    //    [Volume name][Full path to file][File name][Stream Name]
    //
    //    For example, the above components would map to this example name as
    //    follows:
    //
    //    \Device\HarddiskVolume1\Documents and Settings\MyUser\My Documents\Test Results.txt:stream1
    //
    //    [Volume name] = "\Device\HarddiskVolume1"
    //    [Full path to file] = "\Documents and Settings\MyUser\My Documents\"
    //    [File name] = "Test Results.txt"
    //    [Stream name] = ":stream1"
    //
    //  For short names, only the short name for the final name component is
    //  returned in the Name unicode string.  Therefore, if you requested
    //  the short name of the file object representing an open on the file:
    //
    //    \Device\HarddiskVolume1\Documents and Settings\MyUser\My Documents\Test Results.txt
    //
    //  The name returned in Name will be at most 8 characters followed by a '.'
    //  then at most 3 more characters, like:
    //
    //    testre~1.txt
    //

    UNICODE_STRING Name;

    //
    //  The Volume is only filled in for name requested in normalized and opened
    //  formats.
    //

    UNICODE_STRING Volume;

    //
    //  The share component of the file name requested.  This will only be
    //  set for normalized and opened name formats on files that opened across
    //  redirectors.  For local files, this string will always be 0 length.
    //

    UNICODE_STRING Share;

    //
    //  To exemplify what each of the following substrings refer to, let's
    //  look again at the first example string from above:
    //
    //    \Device\HarddiskVolume1\Documents and Settings\MyUser\My Documents\Test Results.txt:stream1
    //
    //  Extension = "txt"
    //  Stream = ":stream1"
    //  FinalComponent = "Test Results.txt:stream1"
    //  ParentDir = "\Documents and Settings\MyUser\My Documents\"
    //

    //
    //  This can be parsed from a normalized, opened, or short name.
    //

    UNICODE_STRING Extension;

    //
    //  The following parse formats are only available for normalized and
    //  opened name formats, but not short names.
    //

    UNICODE_STRING Stream;
    UNICODE_STRING FinalComponent;
    UNICODE_STRING ParentDir;

} FLT_FILE_NAME_INFORMATION, *PFLT_FILE_NAME_INFORMATION;

__checkReturn
__drv_maxIRQL(APC_LEVEL) 
NTSTATUS
FLTAPI
FltGetFileNameInformation (
    __in PFLT_CALLBACK_DATA CallbackData,
    __in FLT_FILE_NAME_OPTIONS NameOptions,
    __deref_out PFLT_FILE_NAME_INFORMATION *FileNameInformation
    );

__checkReturn
__drv_maxIRQL(APC_LEVEL) 
NTSTATUS
FLTAPI
FltGetFileNameInformationUnsafe (
    __in PFILE_OBJECT FileObject,
    __in_opt PFLT_INSTANCE Instance,
    __in FLT_FILE_NAME_OPTIONS NameOptions,
    __deref_out PFLT_FILE_NAME_INFORMATION *FileNameInformation
    );

__drv_maxIRQL(APC_LEVEL) 
VOID
FLTAPI
FltReleaseFileNameInformation (
    __in PFLT_FILE_NAME_INFORMATION FileNameInformation
    );

__drv_maxIRQL(APC_LEVEL) 
VOID
FLTAPI
FltReferenceFileNameInformation (
    __in PFLT_FILE_NAME_INFORMATION FileNameInformation
    );

__drv_maxIRQL(APC_LEVEL) 
NTSTATUS
FLTAPI
FltParseFileName (
    __in PCUNICODE_STRING FileName,
    __inout_opt PUNICODE_STRING Extension,
    __inout_opt PUNICODE_STRING Stream,
    __inout_opt PUNICODE_STRING FinalComponent
    );

__drv_maxIRQL(APC_LEVEL) 
NTSTATUS
FLTAPI
FltParseFileNameInformation (
    __inout PFLT_FILE_NAME_INFORMATION FileNameInformation
    );

__checkReturn
__drv_maxIRQL(APC_LEVEL) 
NTSTATUS
FLTAPI
FltGetTunneledName (
    __in PFLT_CALLBACK_DATA CallbackData,
    __in PFLT_FILE_NAME_INFORMATION FileNameInformation,
    __deref_out_opt PFLT_FILE_NAME_INFORMATION *RetTunneledFileNameInformation
    );

__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTSTATUS
FLTAPI
FltGetVolumeName (
    __in PFLT_VOLUME Volume,
    __inout_opt PUNICODE_STRING VolumeName,
    __out_opt PULONG BufferSizeNeeded
    );

__checkReturn
__drv_maxIRQL(APC_LEVEL) 
NTSTATUS
FLTAPI
FltGetDestinationFileNameInformation (
    __in PFLT_INSTANCE Instance,
    __in PFILE_OBJECT FileObject,
    __in_opt HANDLE RootDirectory,
    __in_bcount(FileNameLength) PWSTR FileName,
    __in ULONG FileNameLength,
    __in FLT_FILE_NAME_OPTIONS NameOptions,
    __deref_out PFLT_FILE_NAME_INFORMATION *RetFileNameInformation
    );

__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTSTATUS
FLTAPI
FltIsDirectory (
    __in PFILE_OBJECT FileObject,
    __in PFLT_INSTANCE Instance,
    __out PBOOLEAN IsDirectory
    );


///////////////////////////////////////////////////////////////////////////////
//
//  Routines for loading and unloading Filters
//
///////////////////////////////////////////////////////////////////////////////

__checkReturn
__drv_maxIRQL(PASSIVE_LEVEL)
NTSTATUS
FLTAPI
FltLoadFilter (
    __in PCUNICODE_STRING FilterName
    );

__checkReturn
__drv_maxIRQL(PASSIVE_LEVEL)
NTSTATUS
FLTAPI
FltUnloadFilter (
    __in PCUNICODE_STRING FilterName
    );

__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTSTATUS
FLTAPI
FltAttachVolume (
    __inout PFLT_FILTER Filter,
    __inout PFLT_VOLUME Volume,
    __in_opt PCUNICODE_STRING InstanceName,
    __deref_opt_out_opt PFLT_INSTANCE *RetInstance
    );

__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTSTATUS
FLTAPI
FltAttachVolumeAtAltitude (
    __inout PFLT_FILTER Filter,
    __inout PFLT_VOLUME Volume,
    __in PCUNICODE_STRING Altitude,
    __in_opt PCUNICODE_STRING InstanceName,
    __deref_opt_out_opt PFLT_INSTANCE *RetInstance
    );

__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTSTATUS
FLTAPI
FltDetachVolume (
    __inout PFLT_FILTER Filter,
    __inout PFLT_VOLUME Volume,
    __in_opt PCUNICODE_STRING InstanceName
    );


///////////////////////////////////////////////////////////////////////////////
//
//  Routines for initiating I/O from within a filter.
//
///////////////////////////////////////////////////////////////////////////////

__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTSTATUS
FLTAPI
FltAllocateCallbackData (
    __in PFLT_INSTANCE Instance,
    __in_opt PFILE_OBJECT FileObject,
    __deref_out PFLT_CALLBACK_DATA *RetNewCallbackData
    );

#if FLT_MGR_WIN7

__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTSTATUS
FLTAPI
FltAllocateCallbackDataEx (
    __in PFLT_INSTANCE Instance,
    __in_opt PFILE_OBJECT FileObject,
    __in FLT_ALLOCATE_CALLBACK_DATA_FLAGS Flags,
    __deref_out PFLT_CALLBACK_DATA *RetNewCallbackData
    );

#endif //FLT_MGR_WIN7


__drv_maxIRQL(DISPATCH_LEVEL)
VOID
FLTAPI
FltFreeCallbackData(
    __in PFLT_CALLBACK_DATA CallbackData
    );

__drv_maxIRQL(APC_LEVEL)
VOID
FLTAPI
FltReuseCallbackData (
    __inout PFLT_CALLBACK_DATA CallbackData
    );

__drv_when(FlagOn(CallbackData->Iopb.IrpFlags, IRP_PAGING_IO), __drv_maxIRQL(APC_LEVEL))
__drv_when(!FlagOn(CallbackData->Iopb.IrpFlags, IRP_PAGING_IO), __drv_maxIRQL(PASSIVE_LEVEL))
VOID
FLTAPI
FltPerformSynchronousIo (
    __inout PFLT_CALLBACK_DATA CallbackData
    );


__checkReturn
__drv_when( FlagOn(CallbackData->Iopb.IrpFlags, IRP_PAGING_IO), __drv_maxIRQL(APC_LEVEL))
__drv_when( !FlagOn(CallbackData->Iopb.IrpFlags, IRP_PAGING_IO), __drv_maxIRQL(PASSIVE_LEVEL))
NTSTATUS
FLTAPI
FltPerformAsynchronousIo (
    __inout PFLT_CALLBACK_DATA CallbackData,
    __in PFLT_COMPLETED_ASYNC_IO_CALLBACK CallbackRoutine,
    __in PVOID CallbackContext
    );


#if FLT_MGR_LONGHORN

__checkReturn
__drv_maxIRQL(PASSIVE_LEVEL)
NTSTATUS
FLTAPI
FltCreateFileEx2 (
    __in PFLT_FILTER Filter,
    __in_opt PFLT_INSTANCE Instance,
    __out PHANDLE FileHandle,
    __deref_opt_out PFILE_OBJECT *FileObject,
    __in ACCESS_MASK DesiredAccess,
    __in POBJECT_ATTRIBUTES ObjectAttributes,
    __out PIO_STATUS_BLOCK IoStatusBlock,
    __in_opt PLARGE_INTEGER AllocationSize,
    __in ULONG FileAttributes,
    __in ULONG ShareAccess,
    __in ULONG CreateDisposition,
    __in ULONG CreateOptions,
    __in_bcount_opt(EaLength) PVOID EaBuffer,
    __in ULONG EaLength,
    __in ULONG Flags,
    __in_opt PIO_DRIVER_CREATE_CONTEXT DriverContext
    );

#endif

#if FLT_MGR_AFTER_XPSP2

//
//  Old version, please use the Ex2 version of this API when possible
//

__checkReturn
__drv_maxIRQL(PASSIVE_LEVEL)
NTSTATUS
FLTAPI
FltCreateFileEx (
    __in PFLT_FILTER Filter,
    __in_opt PFLT_INSTANCE Instance,
    __out PHANDLE FileHandle,
    __deref_opt_out PFILE_OBJECT *FileObject,
    __in ACCESS_MASK DesiredAccess,
    __in POBJECT_ATTRIBUTES ObjectAttributes,
    __out PIO_STATUS_BLOCK IoStatusBlock,
    __in_opt PLARGE_INTEGER AllocationSize,
    __in ULONG FileAttributes,
    __in ULONG ShareAccess,
    __in ULONG CreateDisposition,
    __in ULONG CreateOptions,
    __in_bcount_opt(EaLength) PVOID EaBuffer,
    __in ULONG EaLength,
    __in ULONG Flags
    );

#endif

//
//  Old version, please use the Ex2 version of this API when possible
//

__checkReturn
__drv_maxIRQL(PASSIVE_LEVEL)
NTSTATUS
FLTAPI
FltCreateFile (
    __in PFLT_FILTER Filter,
    __in_opt PFLT_INSTANCE Instance,
    __out PHANDLE   FileHandle,
    __in ACCESS_MASK DesiredAccess,
    __in POBJECT_ATTRIBUTES ObjectAttributes,
    __out PIO_STATUS_BLOCK IoStatusBlock,
    __in_opt PLARGE_INTEGER AllocationSize,
    __in ULONG FileAttributes,
    __in ULONG ShareAccess,
    __in ULONG CreateDisposition,
    __in ULONG CreateOptions,
    __in_bcount_opt(EaLength)PVOID EaBuffer,
    __in ULONG EaLength,
    __in ULONG Flags
    );

#if FLT_MGR_AFTER_XPSP2

__checkReturn
__drv_maxIRQL(PASSIVE_LEVEL)
NTSTATUS
FLTAPI
FltOpenVolume (
    __in PFLT_INSTANCE Instance,
    __out PHANDLE VolumeHandle,
    __deref_opt_out PFILE_OBJECT *VolumeFileObject
    );

#endif

__checkReturn
__drv_maxIRQL(PASSIVE_LEVEL)
__drv_when((Flags|FLTFL_IO_OPERATION_PAGING|FLTFL_IO_OPERATION_SYNCHRONOUS_PAGING),__drv_maxIRQL(APC_LEVEL))
NTSTATUS
FLTAPI
FltReadFile (
    __in PFLT_INSTANCE InitiatingInstance,
    __in PFILE_OBJECT FileObject,
    __in_opt PLARGE_INTEGER ByteOffset,
    __in ULONG Length,
    __out_bcount_part(Length,*BytesRead) PVOID Buffer,
    __in FLT_IO_OPERATION_FLAGS Flags,
    __out_opt PULONG BytesRead,
    __in_opt PFLT_COMPLETED_ASYNC_IO_CALLBACK CallbackRoutine,
    __in_opt PVOID CallbackContext
    );

__checkReturn
__drv_maxIRQL(PASSIVE_LEVEL)
NTSTATUS
FLTAPI
FltTagFile (
    __in PFLT_INSTANCE InitiatingInstance,
    __in PFILE_OBJECT FileObject,
    __in ULONG FileTag,
    __in_opt GUID *Guid,
    __in_bcount(DataBufferLength) PVOID DataBuffer,
    __in USHORT DataBufferLength
    );

__checkReturn
__drv_maxIRQL(PASSIVE_LEVEL)
NTSTATUS
FLTAPI
FltUntagFile(
    __in PFLT_INSTANCE InitiatingInstance,
    __in PFILE_OBJECT FileObject,
    __in ULONG FileTag,
    __in_opt GUID *Guid
    );

__checkReturn
__drv_maxIRQL(PASSIVE_LEVEL)
__drv_when((Flags|FLTFL_IO_OPERATION_PAGING|FLTFL_IO_OPERATION_SYNCHRONOUS_PAGING),__drv_maxIRQL(APC_LEVEL))
NTSTATUS
FLTAPI
FltWriteFile (
    __in PFLT_INSTANCE InitiatingInstance,
    __in PFILE_OBJECT FileObject,
    __in_opt PLARGE_INTEGER ByteOffset,
    __in ULONG Length,
    __in_bcount(Length) PVOID Buffer,
    __in FLT_IO_OPERATION_FLAGS Flags,
    __out_opt PULONG BytesWritten,
    __in_opt PFLT_COMPLETED_ASYNC_IO_CALLBACK CallbackRoutine,
    __in_opt PVOID CallbackContext
    );

__checkReturn
__drv_maxIRQL(PASSIVE_LEVEL)
NTSTATUS
FLTAPI
FltQueryInformationFile (
    __in PFLT_INSTANCE Instance,
    __in PFILE_OBJECT FileObject,
    __out_bcount_part(Length,*LengthReturned) PVOID FileInformation,
    __in ULONG Length,
    __in FILE_INFORMATION_CLASS FileInformationClass,
    __out_opt PULONG LengthReturned
    );

__checkReturn
__drv_maxIRQL(PASSIVE_LEVEL)
NTSTATUS
FLTAPI
FltSetInformationFile (
    __in PFLT_INSTANCE Instance,
    __in PFILE_OBJECT FileObject,
    __in_bcount(Length) PVOID FileInformation,
    __in ULONG Length,
    __in FILE_INFORMATION_CLASS FileInformationClass
    );

#if FLT_MGR_LONGHORN

__checkReturn
__drv_maxIRQL(PASSIVE_LEVEL)
NTSTATUS
FLTAPI
FltQueryDirectoryFile (
    __in PFLT_INSTANCE Instance,
    __in PFILE_OBJECT FileObject,
    __out_bcount(Length) PVOID FileInformation,
    __in ULONG Length,
    __in FILE_INFORMATION_CLASS FileInformationClass,
    __in BOOLEAN ReturnSingleEntry,
    __in_opt PUNICODE_STRING FileName,
    __in BOOLEAN RestartScan,
    __out_opt PULONG LengthReturned
    );

#endif

#if FLT_MGR_AFTER_XPSP2

__checkReturn
__drv_maxIRQL(PASSIVE_LEVEL)
NTSTATUS
FLTAPI
FltQueryEaFile(
    __in PFLT_INSTANCE Instance,
    __in PFILE_OBJECT FileObject,
    __out_bcount_part(Length,*LengthReturned) PVOID ReturnedEaData,
    __in ULONG Length,
    __in BOOLEAN ReturnSingleEntry,
    __in_bcount_opt(EaListLength) PVOID EaList,
    __in ULONG EaListLength,
    __in_opt PULONG EaIndex,
    __in BOOLEAN RestartScan,
    __out_opt PULONG LengthReturned
    );

__checkReturn
__drv_maxIRQL(PASSIVE_LEVEL)
NTSTATUS
FLTAPI
FltSetEaFile(
    __in PFLT_INSTANCE Instance,
    __in PFILE_OBJECT FileObject,
    __in_bcount(Length) PVOID EaBuffer,
    __in ULONG Length
    );

#endif

__checkReturn
__drv_maxIRQL(PASSIVE_LEVEL)
NTSTATUS
FLTAPI
FltQueryVolumeInformationFile (
    __in PFLT_INSTANCE Instance,
    __in PFILE_OBJECT FileObject,
    __out_bcount_part(Length,*LengthReturned) PVOID FsInformation,
    __in ULONG Length,
    __in FS_INFORMATION_CLASS FsInformationClass,
    __out_opt PULONG LengthReturned
    );

__checkReturn
__drv_maxIRQL(PASSIVE_LEVEL)
NTSTATUS
FLTAPI
FltQuerySecurityObject (
    __in PFLT_INSTANCE Instance,
    __in PFILE_OBJECT FileObject,
    __in SECURITY_INFORMATION SecurityInformation,
    __inout_bcount_opt(Length) PSECURITY_DESCRIPTOR SecurityDescriptor,
    __in ULONG Length,
    __out_opt PULONG LengthNeeded
    );

__checkReturn
__drv_maxIRQL(PASSIVE_LEVEL)
NTSTATUS
FLTAPI
FltSetSecurityObject (
    __in PFLT_INSTANCE Instance,
    __in PFILE_OBJECT FileObject,
    __in SECURITY_INFORMATION SecurityInformation,
    __in PSECURITY_DESCRIPTOR SecurityDescriptor
    );

__checkReturn
__drv_maxIRQL(PASSIVE_LEVEL)
NTSTATUS
FLTAPI
FltFlushBuffers (
    __in PFLT_INSTANCE Instance,
    __in PFILE_OBJECT FileObject
    );

__checkReturn
__drv_maxIRQL(PASSIVE_LEVEL)
NTSTATUS
FLTAPI
FltFsControlFile (
    __in PFLT_INSTANCE Instance,
    __in  PFILE_OBJECT FileObject,
    __in ULONG FsControlCode,
    __in_bcount_opt(InputBufferLength) PVOID InputBuffer,
    __in ULONG InputBufferLength,
    __out_bcount_part_opt(OutputBufferLength,*LengthReturned) PVOID OutputBuffer,
    __in ULONG OutputBufferLength,
    __out_opt PULONG LengthReturned
    );

__checkReturn
__drv_maxIRQL(PASSIVE_LEVEL)
NTSTATUS
FLTAPI
FltDeviceIoControlFile (
    __in PFLT_INSTANCE Instance,
    __in PFILE_OBJECT FileObject,
    __in ULONG IoControlCode,
    __in_bcount_opt(InputBufferLength) PVOID InputBuffer,
    __in ULONG InputBufferLength,
    __out_bcount_part_opt(OutputBufferLength,*LengthReturned) PVOID OutputBuffer,
    __in ULONG OutputBufferLength,
    __out_opt PULONG LengthReturned
    );

__checkReturn
__drv_maxIRQL(PASSIVE_LEVEL)
__drv_when((Flags|FLTFL_IO_OPERATION_PAGING|FLTFL_IO_OPERATION_SYNCHRONOUS_PAGING),__drv_maxIRQL(APC_LEVEL))
VOID
FLTAPI
FltReissueSynchronousIo (
   __in PFLT_INSTANCE InitiatingInstance,
   __in PFLT_CALLBACK_DATA CallbackData
   );

__drv_maxIRQL(PASSIVE_LEVEL)
NTSTATUS
FLTAPI
FltClose(
   __in HANDLE FileHandle
   );

__drv_maxIRQL(PASSIVE_LEVEL)
VOID
FLTAPI
FltCancelFileOpen (
    __in PFLT_INSTANCE Instance,
    __in PFILE_OBJECT FileObject
    );

__checkReturn
__drv_maxIRQL(PASSIVE_LEVEL)
NTSTATUS
FLTAPI
FltCreateSystemVolumeInformationFolder (
    __in PFLT_INSTANCE Instance
    );

///////////////////////////////////////////////////////////////////////////////
//
//                  CONTEXT routines
//
///////////////////////////////////////////////////////////////////////////////

//
//  Returns TRUE if the given file object supports the given type of context.
//  FALSE otherwise.
//

#if FLT_MGR_LONGHORN

__drv_maxIRQL(APC_LEVEL) 
BOOLEAN
FLTAPI
FltSupportsFileContextsEx (
    __in PFILE_OBJECT FileObject,
    __in_opt PFLT_INSTANCE Instance
    );

#endif

__drv_maxIRQL(APC_LEVEL) 
BOOLEAN
FLTAPI
FltSupportsFileContexts (
    __in PFILE_OBJECT FileObject
    );

__drv_maxIRQL(APC_LEVEL) 
BOOLEAN
FLTAPI
FltSupportsStreamContexts (
    __in PFILE_OBJECT FileObject
    );

__drv_maxIRQL(APC_LEVEL) 
BOOLEAN
FLTAPI
FltSupportsStreamHandleContexts (
    __in PFILE_OBJECT FileObject
    );


//
//  Called to allocate a context.  All context must be allocated via
//  this routine.
//

__checkReturn
__drv_maxIRQL(APC_LEVEL) 
NTSTATUS
FLTAPI
FltAllocateContext (
    __in PFLT_FILTER Filter,
    __in FLT_CONTEXT_TYPE ContextType,
    __in SIZE_T ContextSize,
    __in POOL_TYPE PoolType,
    __deref_out_bcount(ContextSize) PFLT_CONTEXT *ReturnedContext
    );

//
//  Get and release multiple contexts
//

__drv_maxIRQL(APC_LEVEL) 
VOID
FLTAPI
FltGetContexts (
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in FLT_CONTEXT_TYPE DesiredContexts,
    __out PFLT_RELATED_CONTEXTS Contexts
    );

__drv_maxIRQL(APC_LEVEL) 
VOID
FLTAPI
FltReleaseContexts (
    __in PFLT_RELATED_CONTEXTS Contexts
    );


//
//  State values for the SetContext routines
//

typedef enum _FLT_SET_CONTEXT_OPERATION {

    //
    //  If a context already exists, replace with the given context.
    //  Return the old context.
    //

    FLT_SET_CONTEXT_REPLACE_IF_EXISTS,

    //
    //  If a context already exists, keep the old context and return an
    //  error status.  Return the old context (yes, we really do want to
    //  return the old context, the caller already has the new context).
    //  The context returned must later be released.
    //

    FLT_SET_CONTEXT_KEEP_IF_EXISTS

} FLT_SET_CONTEXT_OPERATION, *PFLT_SET_CONTEXT_OPERATION;

//
//  Routines for setting a context on a given object.  Once a context has
//  been set, it can not be freed except in the free context callback
//  routine.
//

__drv_maxIRQL(APC_LEVEL) 
NTSTATUS
FLTAPI
FltSetVolumeContext (
    __in PFLT_VOLUME Volume,
    __in FLT_SET_CONTEXT_OPERATION Operation,
    __in PFLT_CONTEXT NewContext,
    __deref_opt_out_opt PFLT_CONTEXT *OldContext
    );

__drv_maxIRQL(APC_LEVEL) 
NTSTATUS
FLTAPI
FltSetInstanceContext (
    __in PFLT_INSTANCE Instance,
    __in FLT_SET_CONTEXT_OPERATION Operation,
    __in PFLT_CONTEXT NewContext,
    __deref_opt_out_opt PFLT_CONTEXT *OldContext
    );

__drv_maxIRQL(APC_LEVEL) 
NTSTATUS
FLTAPI
FltSetFileContext (
    __in PFLT_INSTANCE Instance,
    __in PFILE_OBJECT FileObject,
    __in FLT_SET_CONTEXT_OPERATION Operation,
    __in PFLT_CONTEXT NewContext,
    __deref_opt_out_opt PFLT_CONTEXT *OldContext
    );

__drv_maxIRQL(APC_LEVEL) 
NTSTATUS
FLTAPI
FltSetStreamContext (
    __in PFLT_INSTANCE Instance,
    __in PFILE_OBJECT FileObject,
    __in FLT_SET_CONTEXT_OPERATION Operation,
    __in PFLT_CONTEXT NewContext,
    __deref_opt_out_opt PFLT_CONTEXT *OldContext
    );

__drv_maxIRQL(APC_LEVEL) 
NTSTATUS
FLTAPI
FltSetStreamHandleContext (
    __in PFLT_INSTANCE Instance,
    __in PFILE_OBJECT FileObject,
    __in FLT_SET_CONTEXT_OPERATION Operation,
    __in PFLT_CONTEXT NewContext,
    __deref_opt_out_opt PFLT_CONTEXT *OldContext
    );

#if FLT_MGR_LONGHORN

__drv_maxIRQL(APC_LEVEL) 
NTSTATUS
FLTAPI
FltSetTransactionContext (
    __in PFLT_INSTANCE Instance,
    __in PKTRANSACTION Transaction,
    __in FLT_SET_CONTEXT_OPERATION Operation,
    __in PFLT_CONTEXT NewContext,
    __deref_opt_out PFLT_CONTEXT *OldContext
    );

#endif // FLT_MGR_LONGHORN

//
//  Routines for deleting a context on a given object.
//

__drv_maxIRQL(APC_LEVEL) 
VOID
FLTAPI
FltDeleteContext (
    __in PFLT_CONTEXT Context
    );

__drv_maxIRQL(APC_LEVEL) 
NTSTATUS
FLTAPI
FltDeleteVolumeContext (
    __in PFLT_FILTER Filter,
    __in PFLT_VOLUME Volume,
    __deref_opt_out_opt PFLT_CONTEXT *OldContext
    );

__drv_maxIRQL(APC_LEVEL) 
NTSTATUS
FLTAPI
FltDeleteInstanceContext (
    __in PFLT_INSTANCE Instance,
    __deref_opt_out_opt PFLT_CONTEXT *OldContext
    );

__drv_maxIRQL(APC_LEVEL) 
NTSTATUS
FLTAPI
FltDeleteFileContext (
    __in PFLT_INSTANCE Instance,
    __in PFILE_OBJECT FileObject,
    __deref_opt_out_opt PFLT_CONTEXT *OldContext
    );

__drv_maxIRQL(APC_LEVEL) 
NTSTATUS
FLTAPI
FltDeleteStreamContext (
    __in PFLT_INSTANCE Instance,
    __in PFILE_OBJECT FileObject,
    __deref_opt_out_opt PFLT_CONTEXT *OldContext
    );

__drv_maxIRQL(APC_LEVEL) 
NTSTATUS
FLTAPI
FltDeleteStreamHandleContext (
    __in PFLT_INSTANCE Instance,
    __in PFILE_OBJECT FileObject,
    __deref_opt_out_opt PFLT_CONTEXT *OldContext
    );


#if FLT_MGR_LONGHORN

__drv_maxIRQL(APC_LEVEL) 
NTSTATUS
FLTAPI
FltDeleteTransactionContext (
    __in PFLT_INSTANCE Instance,
    __in PKTRANSACTION Transaction,
    __deref_opt_out PFLT_CONTEXT *OldContext
    );

#endif // FLT_MGR_LONGHORN

//
//  Routines for getting/releasing contexts.  Any time a filter gets a context,
//  a corresponding release must be called.
//

__drv_maxIRQL(APC_LEVEL) 
NTSTATUS
FLTAPI
FltGetVolumeContext (
    __in PFLT_FILTER Filter,
    __in PFLT_VOLUME Volume,
    __deref_out PFLT_CONTEXT *Context
    );

__drv_maxIRQL(APC_LEVEL) 
NTSTATUS
FLTAPI
FltGetInstanceContext (
    __in PFLT_INSTANCE Instance,
    __deref_out PFLT_CONTEXT *Context
    );

__drv_maxIRQL(APC_LEVEL) 
NTSTATUS
FLTAPI
FltGetFileContext (
    __in PFLT_INSTANCE Instance,
    __in PFILE_OBJECT FileObject,
    __deref_out PFLT_CONTEXT *Context
    );

__drv_maxIRQL(APC_LEVEL) 
NTSTATUS
FLTAPI
FltGetStreamContext (
    __in PFLT_INSTANCE Instance,
    __in PFILE_OBJECT FileObject,
    __deref_out PFLT_CONTEXT *Context
    );

__drv_maxIRQL(APC_LEVEL) 
NTSTATUS
FLTAPI
FltGetStreamHandleContext (
    __in PFLT_INSTANCE Instance,
    __in PFILE_OBJECT FileObject,
    __deref_out PFLT_CONTEXT *Context
    );

#if FLT_MGR_LONGHORN

__drv_maxIRQL(APC_LEVEL) 
NTSTATUS
FLTAPI
FltGetTransactionContext (
    __in PFLT_INSTANCE Instance,
    __in PKTRANSACTION Transaction,
    __deref_out PFLT_CONTEXT *Context
    );

#endif // FLT_MGR_LONGHORN

//
//  This adds a reference to the given context structure.  The added reference
//  must be explicitly removed by a call to FltReleaseContext.
//

__drv_maxIRQL(DISPATCH_LEVEL)
VOID
FLTAPI
FltReferenceContext (
    __in PFLT_CONTEXT Context
    );

//
//  Routine to release contexts
//

__drv_maxIRQL(DISPATCH_LEVEL)
VOID
FLTAPI
FltReleaseContext (
    __in PFLT_CONTEXT Context
    );


///////////////////////////////////////////////////////////////////////////////
//
//  Routines for getting handles to Filters, Instances,
//  and Volumes.
//
///////////////////////////////////////////////////////////////////////////////

__drv_maxIRQL(APC_LEVEL) 
NTSTATUS
FLTAPI
FltGetFilterFromName (
    __in PCUNICODE_STRING FilterName,
    __deref_out PFLT_FILTER *RetFilter
    );

__drv_maxIRQL(PASSIVE_LEVEL)
NTSTATUS
FLTAPI
FltGetVolumeFromName (
    __in PFLT_FILTER Filter,
    __in PCUNICODE_STRING VolumeName,
    __deref_out PFLT_VOLUME *RetVolume
    );

__drv_maxIRQL(APC_LEVEL) 
NTSTATUS
FLTAPI
FltGetVolumeInstanceFromName (
    __in_opt PFLT_FILTER Filter,
    __in PFLT_VOLUME Volume,
    __in_opt PCUNICODE_STRING InstanceName,
    __deref_out PFLT_INSTANCE *RetInstance
    );

__drv_maxIRQL(APC_LEVEL) 
NTSTATUS
FLTAPI
FltGetVolumeFromInstance (
    __in PFLT_INSTANCE Instance,
    __deref_out PFLT_VOLUME *RetVolume
    );

__drv_maxIRQL(APC_LEVEL) 
NTSTATUS
FLTAPI
FltGetFilterFromInstance (
    __in PFLT_INSTANCE Instance,
    __deref_out PFLT_FILTER *RetFilter
    );

__drv_maxIRQL(APC_LEVEL) 
NTSTATUS
FLTAPI
FltGetVolumeFromFileObject (
    __in PFLT_FILTER Filter,
    __in PFILE_OBJECT FileObject,
    __deref_out PFLT_VOLUME *RetVolume
    );

__drv_maxIRQL(APC_LEVEL) 
NTSTATUS
FLTAPI
FltGetVolumeFromDeviceObject (
    __in PFLT_FILTER Filter,
    __in PDEVICE_OBJECT DeviceObject,
    __deref_out PFLT_VOLUME *RetVolume
    );

#if FLT_MGR_LONGHORN

__drv_maxIRQL(APC_LEVEL)
BOOLEAN
FLTAPI
FltIsFltMgrVolumeDeviceObject(
    __in PDEVICE_OBJECT DeviceObject
    );

#endif

__drv_maxIRQL(DISPATCH_LEVEL)
NTSTATUS
FLTAPI
FltGetDeviceObject (
    __in PFLT_VOLUME Volume,
    __deref_out PDEVICE_OBJECT *DeviceObject
    );

__drv_maxIRQL(DISPATCH_LEVEL)
NTSTATUS
FLTAPI
FltGetDiskDeviceObject(
    __in PFLT_VOLUME Volume,
    __deref_out PDEVICE_OBJECT *DiskDeviceObject
    );

__drv_maxIRQL(APC_LEVEL) 
NTSTATUS
FLTAPI
FltGetLowerInstance (
    __in PFLT_INSTANCE CurrentInstance,
    __deref_out PFLT_INSTANCE *LowerInstance
    );

__drv_maxIRQL(APC_LEVEL) 
NTSTATUS
FLTAPI
FltGetUpperInstance (
    __in PFLT_INSTANCE CurrentInstance,
    __deref_out PFLT_INSTANCE *UpperInstance
    );

__drv_maxIRQL(APC_LEVEL) 
NTSTATUS
FLTAPI
FltGetTopInstance (
    __in PFLT_VOLUME Volume,
    __deref_out PFLT_INSTANCE *Instance
    );

__drv_maxIRQL(APC_LEVEL) 
NTSTATUS
FLTAPI
FltGetBottomInstance (
    __in PFLT_VOLUME Volume,
    __deref_out PFLT_INSTANCE *Instance
    );

LONG
FLTAPI
FltCompareInstanceAltitudes (
    __in PFLT_INSTANCE Instance1,
    __in PFLT_INSTANCE Instance2
    );


///////////////////////////////////////////////////////////////////////////////
//
//  Routines for getting information on Filters and Filter Instances.
//
///////////////////////////////////////////////////////////////////////////////

__drv_maxIRQL(APC_LEVEL)
NTSTATUS
FLTAPI
FltGetFilterInformation (
    __in PFLT_FILTER Filter,
    __in FILTER_INFORMATION_CLASS InformationClass,
    __out_bcount_part_opt(BufferSize, *BytesReturned) PVOID Buffer,
    __in ULONG BufferSize,
    __out PULONG BytesReturned
    );

__drv_maxIRQL(APC_LEVEL)
NTSTATUS
FLTAPI
FltGetInstanceInformation (
    __in PFLT_INSTANCE Instance,
    __in INSTANCE_INFORMATION_CLASS InformationClass,
    __out_bcount_part_opt(BufferSize,*BytesReturned) PVOID Buffer,
    __in ULONG BufferSize,
    __out PULONG BytesReturned
    );

#if FLT_MGR_LONGHORN

__drv_maxIRQL(APC_LEVEL)
NTSTATUS
FLTAPI
FltGetVolumeInformation (
    __in PFLT_VOLUME Volume,
    __in FILTER_VOLUME_INFORMATION_CLASS InformationClass,
    __out_bcount_part_opt(BufferSize,*BytesReturned) PVOID Buffer,
    __in ULONG BufferSize,
    __out PULONG BytesReturned
    );

#endif // FLT_MGR_LONGHORN

///////////////////////////////////////////////////////////////////////////////
//
//  Routines for getting information about Volumes.
//
///////////////////////////////////////////////////////////////////////////////

typedef struct _FLT_VOLUME_PROPERTIES {

    //
    //  The possible DeviceTypes are defined in NTIFS.H and begin with
    //  FILE_DEVICE_
    //

    DEVICE_TYPE DeviceType;

    //
    //  The possible DeviceCharacteristics flags are defined in NTIFS.H.
    //  Potential values are:
    //      FILE_REMOVABLE_MEDIA
    //      FILE_READ_ONLY_DEVICE
    //      FILE_FLOPPY_DISKETTE
    //      FILE_WRITE_ONCE_MEDIA
    //      FILE_REMOTE_DEVICE
    //      FILE_DEVICE_IS_MOUNTED
    //      FILE_VIRTUAL_VOLUME
    //      FILE_AUTOGENERATED_DEVICE_NAME
    //      FILE_DEVICE_SECURE_OPEN
    //

    ULONG DeviceCharacteristics;

    //
    //  The possible DeviceObjectFlags are define in NTIFS.H.  All potential
    //  values begin with DO_.
    //

    ULONG DeviceObjectFlags;

    ULONG AlignmentRequirement;

    USHORT SectorSize;

    USHORT Reserved0;

    //
    //  The name of the file system driver associated with this device.
    //
    //  The buffer for this unicode string is contiguous with this structure and
    //  does not need to be initialized before calling FltGetVolumeProperties.
    //

    UNICODE_STRING FileSystemDriverName;

    //
    //  The name of the file system device associated with this device.
    //
    //  The buffer for this unicode string is contiguous with this structure and
    //  does not need to be initialized before calling FltGetVolumeProperties.
    //

    UNICODE_STRING FileSystemDeviceName;

    //
    //  The name of the real device object associated with this device.  This
    //  is empty for network file systems.
    //
    //  The buffer for this unicode string is contiguous with this structure and
    //  does not need to be initialized before calling FltGetVolumeProperties.
    //

    UNICODE_STRING RealDeviceName;

} FLT_VOLUME_PROPERTIES, *PFLT_VOLUME_PROPERTIES;

__drv_maxIRQL(APC_LEVEL)
NTSTATUS
FLTAPI
FltGetVolumeProperties (
    __in PFLT_VOLUME Volume,
    __out_bcount_part_opt(VolumePropertiesLength,*LengthReturned) PFLT_VOLUME_PROPERTIES VolumeProperties,
    __in ULONG VolumePropertiesLength,
    __out PULONG LengthReturned
    );

__checkReturn
__drv_maxIRQL(PASSIVE_LEVEL)
NTSTATUS
FLTAPI
FltIsVolumeWritable (
    __in PVOID FltObject,
    __out PBOOLEAN IsWritable
    );

#if FLT_MGR_LONGHORN

__drv_maxIRQL(APC_LEVEL)
NTSTATUS
FLTAPI
FltGetFileSystemType (
    __in PVOID FltObject,
    __out PFLT_FILESYSTEM_TYPE FileSystemType
    );

__checkReturn
__drv_maxIRQL(PASSIVE_LEVEL)
NTSTATUS
FLTAPI
FltIsVolumeSnapshot (
    __in PVOID FltObject,
    __out PBOOLEAN IsSnapshotVolume
    );

#endif // FLT_MGR_LONGHORN

__checkReturn
__drv_maxIRQL(PASSIVE_LEVEL)
NTSTATUS
FLTAPI
FltGetVolumeGuidName (
    __in PFLT_VOLUME Volume,
    __out PUNICODE_STRING VolumeGuidName,
    __out_opt PULONG BufferSizeNeeded
    );

__checkReturn
__drv_maxIRQL(PASSIVE_LEVEL)
NTSTATUS
FLTAPI
FltQueryVolumeInformation(
    __in PFLT_INSTANCE Instance,
    __out PIO_STATUS_BLOCK Iosb,
    __out_bcount(Length) PVOID FsInformation,
    __in ULONG Length,
    __in FS_INFORMATION_CLASS FsInformationClass
    );

__checkReturn
__drv_maxIRQL(PASSIVE_LEVEL)
NTSTATUS
FLTAPI
FltSetVolumeInformation(
    __in PFLT_INSTANCE Instance,
    __out PIO_STATUS_BLOCK Iosb,
    __out_bcount(Length) PVOID FsInformation,
    __in ULONG Length,
    __in FS_INFORMATION_CLASS FsInformationClass
    );


///////////////////////////////////////////////////////////////////////////////
//
//  Routines for enumerating Filter information, Instance informations and
//  Filter Instances in the system.
//
///////////////////////////////////////////////////////////////////////////////

__checkReturn
__drv_maxIRQL(APC_LEVEL) 
NTSTATUS
FLTAPI
FltEnumerateFilters (
    __out_ecount_part_opt(FilterListSize,*NumberFiltersReturned) PFLT_FILTER *FilterList,
    __in ULONG FilterListSize,
    __out PULONG NumberFiltersReturned
    );

__checkReturn
__drv_maxIRQL(APC_LEVEL) 
NTSTATUS
FLTAPI
FltEnumerateVolumes (
    __in PFLT_FILTER Filter,
    __out_ecount_part_opt(VolumeListSize,*NumberVolumesReturned) PFLT_VOLUME *VolumeList,
    __in ULONG VolumeListSize,
    __out PULONG NumberVolumesReturned
    );

__checkReturn
__drv_maxIRQL(APC_LEVEL) 
NTSTATUS
FLTAPI
FltEnumerateInstances (
    __in_opt PFLT_VOLUME Volume,
    __in_opt PFLT_FILTER Filter,
    __out_ecount_part_opt(InstanceListSize,*NumberInstancesReturned) PFLT_INSTANCE *InstanceList,
    __in ULONG InstanceListSize,
    __out PULONG NumberInstancesReturned
    );

__checkReturn
__drv_maxIRQL(APC_LEVEL) 
NTSTATUS
FLTAPI
FltEnumerateFilterInformation (
    __in ULONG Index,
    __in FILTER_INFORMATION_CLASS InformationClass,
    __out_bcount_part_opt(BufferSize,*BytesReturned) PVOID Buffer,
    __in ULONG BufferSize,
    __out PULONG BytesReturned
    );

__checkReturn
__drv_maxIRQL(APC_LEVEL) 
NTSTATUS
FLTAPI
FltEnumerateInstanceInformationByFilter (
    __in PFLT_FILTER Filter,
    __in ULONG Index,
    __in INSTANCE_INFORMATION_CLASS InformationClass,
    __out_bcount_part_opt(BufferSize,*BytesReturned) PVOID Buffer,
    __in ULONG BufferSize,
    __out PULONG BytesReturned
    );

__checkReturn
__drv_maxIRQL(APC_LEVEL) 
NTSTATUS
FLTAPI
FltEnumerateInstanceInformationByVolume (
    __in PFLT_VOLUME Volume,
    __in ULONG Index,
    __in INSTANCE_INFORMATION_CLASS InformationClass,
    __out_bcount_part_opt(BufferSize,*BytesReturned) PVOID Buffer,
    __in ULONG BufferSize,
    __out PULONG BytesReturned
    );

__checkReturn
__drv_maxIRQL(APC_LEVEL) 
NTSTATUS
FLTAPI
FltEnumerateVolumeInformation (
    __in PFLT_FILTER Filter,
    __in ULONG Index,
    __in FILTER_VOLUME_INFORMATION_CLASS InformationClass,
    __out_bcount_part_opt(BufferSize,*BytesReturned) PVOID Buffer,
    __in ULONG BufferSize,
    __out PULONG BytesReturned
    );


///////////////////////////////////////////////////////////////////////////////
//
//  Routines for referencing and closing FLT_VOLUMEs, FLT_INSTANCEs, and
//  FLT_FILTERs.
//
///////////////////////////////////////////////////////////////////////////////

__checkReturn
__drv_maxIRQL(DISPATCH_LEVEL)
NTSTATUS
FLTAPI
FltObjectReference (
    __inout PVOID FltObject
    );

__drv_maxIRQL(DISPATCH_LEVEL)
VOID
FLTAPI
FltObjectDereference (
    __inout PVOID FltObject
    );


///////////////////////////////////////////////////////////////////////////////
//
//  Routines & defs for sending messages from a filter to a user-mode component.
//
///////////////////////////////////////////////////////////////////////////////

//
//  Access masks for filter communication ports
//

#define FLT_PORT_CONNECT        0x0001
#define FLT_PORT_ALL_ACCESS     (FLT_PORT_CONNECT | STANDARD_RIGHTS_ALL)

//
//  Callback to notify a filter it has received a message from a user App
//

typedef NTSTATUS
(FLTAPI *PFLT_MESSAGE_NOTIFY) (
    __in_opt PVOID PortCookie,
    __in_bcount_opt(InputBufferLength) PVOID InputBuffer,
    __in ULONG InputBufferLength,
    __out_bcount_part_opt(OutputBufferLength,*ReturnOutputBufferLength) PVOID OutputBuffer,
    __in ULONG OutputBufferLength,
    __out PULONG ReturnOutputBufferLength
    );

//
//  Callback to notify a filter when a new connection to a port is established
//

typedef NTSTATUS
(FLTAPI *PFLT_CONNECT_NOTIFY) (
      __in PFLT_PORT ClientPort,
      __in_opt PVOID ServerPortCookie,
      __in_bcount_opt(SizeOfContext) PVOID ConnectionContext,
      __in ULONG SizeOfContext,
      __deref_out_opt PVOID *ConnectionPortCookie
      );

//
//  Callback to notify a filter when a connection to a port is being torn down
//

typedef VOID
(FLTAPI *PFLT_DISCONNECT_NOTIFY) (
      __in_opt PVOID ConnectionCookie
      );

__checkReturn
__drv_maxIRQL(PASSIVE_LEVEL)
NTSTATUS
FLTAPI
FltCreateCommunicationPort (
    __in PFLT_FILTER Filter,
    __deref_out PFLT_PORT *ServerPort,
    __in POBJECT_ATTRIBUTES ObjectAttributes,
    __in_opt PVOID ServerPortCookie,
    __in PFLT_CONNECT_NOTIFY ConnectNotifyCallback,
    __in PFLT_DISCONNECT_NOTIFY DisconnectNotifyCallback,
    __in_opt PFLT_MESSAGE_NOTIFY MessageNotifyCallback,
    __in LONG MaxConnections
    );

__drv_maxIRQL(PASSIVE_LEVEL)
VOID
FLTAPI
FltCloseCommunicationPort (
    __in PFLT_PORT ServerPort
    );

__drv_maxIRQL(PASSIVE_LEVEL)
VOID
FLTAPI
FltCloseClientPort (
    __in PFLT_FILTER Filter,
    __deref_out PFLT_PORT *ClientPort
    );

__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTSTATUS
FLTAPI
FltSendMessage (
    __in PFLT_FILTER Filter,
    __deref_in PFLT_PORT *ClientPort,
    __in_bcount(SenderBufferLength) PVOID SenderBuffer,
    __in ULONG SenderBufferLength,
    __out_bcount_opt(*ReplyLength) PVOID ReplyBuffer,
    __inout_opt PULONG ReplyLength,
    __in_opt PLARGE_INTEGER Timeout
    );

__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTSTATUS
FLTAPI
FltBuildDefaultSecurityDescriptor(
     __deref_out PSECURITY_DESCRIPTOR *SecurityDescriptor,
     __in ACCESS_MASK DesiredAccess
     );

__drv_maxIRQL(APC_LEVEL)
VOID
FLTAPI
FltFreeSecurityDescriptor(
    __in PSECURITY_DESCRIPTOR SecurityDescriptor
    );

///////////////////////////////////////////////////////////////////////////////
//
//  Plain cancel support. Note that using callback data queues and
//  setting the cancel routine manually is not supported
//
///////////////////////////////////////////////////////////////////////////////

typedef VOID
(FLTAPI *PFLT_COMPLETE_CANCELED_CALLBACK) (
    __in PFLT_CALLBACK_DATA CallbackData
);

__checkReturn
__drv_maxIRQL(DISPATCH_LEVEL)
BOOLEAN
FLTAPI
FltCancelIo(
    __in PFLT_CALLBACK_DATA CallbackData
    );

__drv_maxIRQL(DISPATCH_LEVEL)
NTSTATUS
FLTAPI
FltSetCancelCompletion (
    __in PFLT_CALLBACK_DATA CallbackData,
    __in PFLT_COMPLETE_CANCELED_CALLBACK CanceledCallback
    );

__checkReturn
__drv_maxIRQL(DISPATCH_LEVEL)
NTSTATUS
FLTAPI
FltClearCancelCompletion(
    __in PFLT_CALLBACK_DATA CallbackData
    );

BOOLEAN
FLTAPI
FltIsIoCanceled(
    __in PFLT_CALLBACK_DATA CallbackData
    );


///////////////////////////////////////////////////////////////////////////////
//
//  Workqueue wrappers
//
///////////////////////////////////////////////////////////////////////////////

typedef struct _FLT_DEFERRED_IO_WORKITEM *PFLT_DEFERRED_IO_WORKITEM;
typedef struct _FLT_GENERIC_WORKITEM *PFLT_GENERIC_WORKITEM;

typedef VOID
(FLTAPI *PFLT_DEFERRED_IO_WORKITEM_ROUTINE) (
    __in PFLT_DEFERRED_IO_WORKITEM FltWorkItem,
    __in PFLT_CALLBACK_DATA CallbackData,
    __in_opt PVOID Context
    );

typedef VOID
(FLTAPI *PFLT_GENERIC_WORKITEM_ROUTINE) (
    __in PFLT_GENERIC_WORKITEM FltWorkItem,
    __in PVOID FltObject,
    __in_opt PVOID Context
    );

__checkReturn
__drv_maxIRQL(DISPATCH_LEVEL)
PFLT_DEFERRED_IO_WORKITEM
FLTAPI
FltAllocateDeferredIoWorkItem(
    VOID
    );

__drv_maxIRQL(DISPATCH_LEVEL)
VOID
FLTAPI
FltFreeDeferredIoWorkItem (
    __in PFLT_DEFERRED_IO_WORKITEM FltWorkItem
    );

__checkReturn
__drv_maxIRQL(DISPATCH_LEVEL)
PFLT_GENERIC_WORKITEM
FLTAPI
FltAllocateGenericWorkItem(
    VOID
    );

__drv_maxIRQL(DISPATCH_LEVEL)
VOID
FLTAPI
FltFreeGenericWorkItem (
    __in PFLT_GENERIC_WORKITEM FltWorkItem
    );

__checkReturn
__drv_maxIRQL(DISPATCH_LEVEL)
NTSTATUS
FLTAPI
FltQueueDeferredIoWorkItem (
    __in PFLT_DEFERRED_IO_WORKITEM FltWorkItem,
    __in PFLT_CALLBACK_DATA Data,
    __in PFLT_DEFERRED_IO_WORKITEM_ROUTINE WorkerRoutine,
    __in WORK_QUEUE_TYPE QueueType,
    __in PVOID Context
    );

__checkReturn
__drv_maxIRQL(DISPATCH_LEVEL)
NTSTATUS
FLTAPI
FltQueueGenericWorkItem (
    __in PFLT_GENERIC_WORKITEM FltWorkItem,
    __in PVOID FltObject,
    __in PFLT_GENERIC_WORKITEM_ROUTINE WorkerRoutine,
    __in WORK_QUEUE_TYPE QueueType,
    __in_opt PVOID Context
    );



///////////////////////////////////////////////////////////////////////////////
//
//  Routines for decoding params, locking data buffers etc.
//
///////////////////////////////////////////////////////////////////////////////


__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTSTATUS
FLTAPI
FltLockUserBuffer(
    __in PFLT_CALLBACK_DATA CallbackData
    );

NTSTATUS
FLTAPI
FltDecodeParameters(
    __in PFLT_CALLBACK_DATA CallbackData,
    __deref_opt_out PMDL **MdlAddressPointer,
    __deref_opt_out_bcount(**Length) PVOID  **Buffer,
    __deref_opt_out PULONG *Length,
    __out_opt LOCK_OPERATION *DesiredAccess
    );

PMDL
FASTCALL
FltGetSwappedBufferMdlAddress(
    __in PFLT_CALLBACK_DATA CallbackData
    );

VOID
FASTCALL
FltRetainSwappedBufferMdlAddress(
    __in PFLT_CALLBACK_DATA CallbackData
    );

#if FLT_MGR_WIN7

__checkReturn
__drv_maxIRQL(DPC_LEVEL)
PVOID
FLTAPI
FltGetNewSystemBufferAddress(
    __in PFLT_CALLBACK_DATA CallbackData
    );

#endif // FLT_MGR_WIN7

///////////////////////////////////////////////////////////////////////////////
//
//  Routines for accessing cancel-safe queue abstraction provided by
//  filter manager
//
///////////////////////////////////////////////////////////////////////////////

//
// The cancel safe queue is not exposed in the w2k DDK headers, so we
// define what is neccesary here.
//

typedef IO_CSQ_IRP_CONTEXT FLT_CALLBACK_DATA_QUEUE_IO_CONTEXT, *PFLT_CALLBACK_DATA_QUEUE_IO_CONTEXT;

//
// Forward define callback data queue
//

typedef struct _FLT_CALLBACK_DATA_QUEUE FLT_CALLBACK_DATA_QUEUE, *PFLT_CALLBACK_DATA_QUEUE;

//
// Routines that insert/remove callback data's
//

typedef NTSTATUS
(FLTAPI *PFLT_CALLBACK_DATA_QUEUE_INSERT_IO)(
    __inout PFLT_CALLBACK_DATA_QUEUE Cbdq,
    __in PFLT_CALLBACK_DATA Cbd,
    __in_opt PVOID InsertContext
    );

typedef VOID
(FLTAPI *PFLT_CALLBACK_DATA_QUEUE_REMOVE_IO)(
    __inout PFLT_CALLBACK_DATA_QUEUE Cbdq,
    __in PFLT_CALLBACK_DATA Cbd
    );

//
// Retrieves the next callback data from the queue. NULL if none are left.
// If Cbd is NULL, returns the entry at the head of the queue. Does not remove
// Cbd from queue.
//

typedef PFLT_CALLBACK_DATA
(FLTAPI *PFLT_CALLBACK_DATA_QUEUE_PEEK_NEXT_IO)(
    __in PFLT_CALLBACK_DATA_QUEUE Cbdq,
    __in_opt PFLT_CALLBACK_DATA Cbd,
    __in_opt PVOID PeekContext
    );

//
//  Lock routine that protects the cancel safe queue
//

typedef VOID
(FLTAPI *PFLT_CALLBACK_DATA_QUEUE_ACQUIRE)(
    __inout PFLT_CALLBACK_DATA_QUEUE Cbdq,
    __out PKIRQL Irql
    );

typedef VOID
(FLTAPI *PFLT_CALLBACK_DATA_QUEUE_RELEASE)(
    __inout PFLT_CALLBACK_DATA_QUEUE Cbdq,
    __in KIRQL Irql
    );

//
//  Cancel routine callback for queued callback data's
//

typedef VOID
(FLTAPI *PFLT_CALLBACK_DATA_QUEUE_COMPLETE_CANCELED_IO)(
    __inout PFLT_CALLBACK_DATA_QUEUE Cbdq,
    __inout PFLT_CALLBACK_DATA Cbd
    );


typedef enum _FLT_CALLBACK_DATA_QUEUE_FLAGS FLT_CALLBACK_DATA_QUEUE_FLAGS;
//
// Following structure is opaque to filters, but allocated by them.
//

typedef struct _FLT_CALLBACK_DATA_QUEUE {

    //
    //  Embedded IRP cancel queue: this is opaque to minifilters
    //

    IO_CSQ Csq;

    //
    //  Flags .. These are private to filter manager
    //

    FLT_CALLBACK_DATA_QUEUE_FLAGS Flags;

    //
    //  Instance that is using this queue
    //

    PFLT_INSTANCE Instance;

    //
    //  Cancel-safe queue callbacks
    //

    PFLT_CALLBACK_DATA_QUEUE_INSERT_IO                   InsertIo;
    PFLT_CALLBACK_DATA_QUEUE_REMOVE_IO                   RemoveIo;
    PFLT_CALLBACK_DATA_QUEUE_PEEK_NEXT_IO                PeekNextIo;
    PFLT_CALLBACK_DATA_QUEUE_ACQUIRE                     Acquire;
    PFLT_CALLBACK_DATA_QUEUE_RELEASE                     Release;
    PFLT_CALLBACK_DATA_QUEUE_COMPLETE_CANCELED_IO        CompleteCanceledIo;


} FLT_CALLBACK_DATA_QUEUE, *PFLT_CALLBACK_DATA_QUEUE;


NTSTATUS
FLTAPI
FltCbdqInitialize(
    __in PFLT_INSTANCE                                       Instance,
    __inout PFLT_CALLBACK_DATA_QUEUE                         Cbdq,
    __in PFLT_CALLBACK_DATA_QUEUE_INSERT_IO                  CbdqInsertIo,
    __in PFLT_CALLBACK_DATA_QUEUE_REMOVE_IO                  CbdqRemoveIo,
    __in PFLT_CALLBACK_DATA_QUEUE_PEEK_NEXT_IO               CbdqPeekNextIo,
    __in PFLT_CALLBACK_DATA_QUEUE_ACQUIRE                    CbdqAcquire,
    __in PFLT_CALLBACK_DATA_QUEUE_RELEASE                    CbdqRelease,
    __in PFLT_CALLBACK_DATA_QUEUE_COMPLETE_CANCELED_IO       CbdqCompleteCanceledIo
    );

VOID
FLTAPI
FltCbdqEnable(
    __inout PFLT_CALLBACK_DATA_QUEUE Cbdq
    );

VOID
FLTAPI
FltCbdqDisable(
    __inout PFLT_CALLBACK_DATA_QUEUE Cbdq
    );

__checkReturn
NTSTATUS
FLTAPI
FltCbdqInsertIo(
    __inout PFLT_CALLBACK_DATA_QUEUE Cbdq,
    __in PFLT_CALLBACK_DATA Cbd,
    __in_opt PFLT_CALLBACK_DATA_QUEUE_IO_CONTEXT Context,
    __in_opt PVOID InsertContext
    );

__checkReturn
PFLT_CALLBACK_DATA
FLTAPI
FltCbdqRemoveIo(
    __inout PFLT_CALLBACK_DATA_QUEUE Cbdq,
    __in PFLT_CALLBACK_DATA_QUEUE_IO_CONTEXT Context
    );

__checkReturn
PFLT_CALLBACK_DATA
FLTAPI
FltCbdqRemoveNextIo(
    __inout  PFLT_CALLBACK_DATA_QUEUE Cbdq,
    __in_opt  PVOID     PeekContext
    );


///////////////////////////////////////////////////////////////////////////////
//
//  Routines and callbacks for handling oplocks provided by filter manager
//
///////////////////////////////////////////////////////////////////////////////

typedef
VOID
(FLTAPI *PFLTOPLOCK_WAIT_COMPLETE_ROUTINE) (
    __in PFLT_CALLBACK_DATA CallbackData,
    __in_opt PVOID Context
    );

typedef
VOID
(FLTAPI *PFLTOPLOCK_PREPOST_CALLBACKDATA_ROUTINE) (
    __in PFLT_CALLBACK_DATA CallbackData,
    __in_opt PVOID Context
    );

//
// Oplock support routines.
//

__drv_maxIRQL(APC_LEVEL) 
VOID
FLTAPI
FltInitializeOplock (
    __out POPLOCK Oplock
    );

__drv_maxIRQL(APC_LEVEL) 
VOID
FLTAPI
FltUninitializeOplock (
    __in POPLOCK Oplock
    );

__checkReturn
__drv_maxIRQL(APC_LEVEL) 
FLT_PREOP_CALLBACK_STATUS
FLTAPI
FltOplockFsctrl (
    __in POPLOCK Oplock,
    __in PFLT_CALLBACK_DATA CallbackData,
    __in ULONG OpenCount
    );

__checkReturn
__drv_maxIRQL(APC_LEVEL) 
FLT_PREOP_CALLBACK_STATUS
FLTAPI
FltCheckOplock (
    __in POPLOCK Oplock,
    __in PFLT_CALLBACK_DATA CallbackData,
    __in_opt PVOID Context,
    __in_opt PFLTOPLOCK_WAIT_COMPLETE_ROUTINE WaitCompletionRoutine,
    __in_opt PFLTOPLOCK_PREPOST_CALLBACKDATA_ROUTINE PrePostCallbackDataRoutine
    );

__drv_maxIRQL(APC_LEVEL) 
BOOLEAN
FLTAPI
FltOplockIsFastIoPossible (
    __in POPLOCK Oplock
    );

__drv_maxIRQL(APC_LEVEL) 
BOOLEAN
FLTAPI
FltCurrentBatchOplock (
    __in POPLOCK Oplock
    );

#if FLT_MGR_WIN7

__checkReturn
__drv_maxIRQL(APC_LEVEL) 
FLT_PREOP_CALLBACK_STATUS
FLTAPI
FltCheckOplockEx (
    __in POPLOCK Oplock,
    __in PFLT_CALLBACK_DATA CallbackData,
    __in ULONG Flags,
    __in_opt PVOID Context,
    __in_opt PFLTOPLOCK_WAIT_COMPLETE_ROUTINE WaitCompletionRoutine,
    __in_opt PFLTOPLOCK_PREPOST_CALLBACKDATA_ROUTINE PrePostCallbackDataRoutine
    );

__drv_maxIRQL(APC_LEVEL) 
BOOLEAN
FLTAPI
FltCurrentOplock (
    __in POPLOCK Oplock
    );

__drv_maxIRQL(APC_LEVEL) 
BOOLEAN
FLTAPI
FltCurrentOplockH (
    __in POPLOCK Oplock
    );

__drv_maxIRQL(APC_LEVEL) 
FLT_PREOP_CALLBACK_STATUS
FLTAPI
FltOplockBreakH (
    __in POPLOCK Oplock,
    __in PFLT_CALLBACK_DATA CallbackData,
    __in ULONG Flags,
    __in_opt PVOID Context,
    __in_opt PFLTOPLOCK_WAIT_COMPLETE_ROUTINE WaitCompletionRoutine,
    __in_opt PFLTOPLOCK_PREPOST_CALLBACKDATA_ROUTINE PrePostCallbackDataRoutine
    );

__drv_maxIRQL(APC_LEVEL) 
FLT_PREOP_CALLBACK_STATUS
FLTAPI
FltOplockBreakToNone (
    __in POPLOCK Oplock,
    __in PFLT_CALLBACK_DATA CallbackData,
    __in_opt PVOID Context,
    __in_opt PFLTOPLOCK_WAIT_COMPLETE_ROUTINE WaitCompletionRoutine,
    __in_opt PFLTOPLOCK_PREPOST_CALLBACKDATA_ROUTINE PrePostCallbackDataRoutine
    );

__drv_maxIRQL(APC_LEVEL) 
FLT_PREOP_CALLBACK_STATUS
FLTAPI
FltOplockBreakToNoneEx (
    __in POPLOCK Oplock,
    __in PFLT_CALLBACK_DATA CallbackData,
    __in ULONG Flags,
    __in_opt PVOID Context,
    __in_opt PFLTOPLOCK_WAIT_COMPLETE_ROUTINE WaitCompletionRoutine,
    __in_opt PFLTOPLOCK_PREPOST_CALLBACKDATA_ROUTINE PrePostCallbackDataRoutine
    );

__drv_maxIRQL(APC_LEVEL) 
BOOLEAN
FLTAPI
FltOplockIsSharedRequest (
    __in PFLT_CALLBACK_DATA CallbackData
    );

__checkReturn
__drv_maxIRQL(APC_LEVEL) 
FLT_PREOP_CALLBACK_STATUS
FLTAPI
FltOplockFsctrlEx (
    __in POPLOCK Oplock,
    __in PFLT_CALLBACK_DATA CallbackData,
    __in ULONG OpenCount,
    __in ULONG Flags
    );

BOOLEAN
FLTAPI
FltOplockKeysEqual (
    __in_opt PFILE_OBJECT Fo1,
    __in_opt PFILE_OBJECT Fo2
    );

#endif  //  FLT_MGR_WIN7

///////////////////////////////////////////////////////////////////////////////
//
//  Routines and callbacks for handling file lock support provided by filter manager
//
///////////////////////////////////////////////////////////////////////////////

typedef
NTSTATUS
(*PFLT_COMPLETE_LOCK_CALLBACK_DATA_ROUTINE) (
    __in_opt PVOID Context,
    __in PFLT_CALLBACK_DATA CallbackData
    );

VOID
FLTAPI
FltInitializeFileLock (
    __out PFILE_LOCK FileLock
    );

VOID
FLTAPI
FltUninitializeFileLock (
    __in PFILE_LOCK FileLock
    );

__checkReturn
__drv_maxIRQL(APC_LEVEL) 
PFILE_LOCK
FLTAPI
FltAllocateFileLock (
    __in_opt PFLT_COMPLETE_LOCK_CALLBACK_DATA_ROUTINE CompleteLockCallbackDataRoutine,
    __in_opt PUNLOCK_ROUTINE UnlockRoutine
    );

__drv_maxIRQL(APC_LEVEL) 
VOID
FLTAPI
FltFreeFileLock (
    __in PFILE_LOCK FileLock
    );

__checkReturn
__drv_maxIRQL(APC_LEVEL) 
FLT_PREOP_CALLBACK_STATUS
FLTAPI
FltProcessFileLock (
    __in PFILE_LOCK FileLock,
    __in PFLT_CALLBACK_DATA CallbackData,
    __in_opt PVOID Context
    );

__checkReturn
__drv_maxIRQL(APC_LEVEL) 
BOOLEAN
FLTAPI
FltCheckLockForReadAccess (
    __in PFILE_LOCK FileLock,
    __in PFLT_CALLBACK_DATA CallbackData
    );

__checkReturn
__drv_maxIRQL(APC_LEVEL) 
BOOLEAN
FLTAPI
FltCheckLockForWriteAccess (
    __in PFILE_LOCK FileLock,
    __in PFLT_CALLBACK_DATA CallbackData
    );


///////////////////////////////////////////////////////////////////////////////
//
//                          Locking Primitives
//
///////////////////////////////////////////////////////////////////////////////

//
//  EResource APIs which do proper wrapping of KeEnterCriticalRegion and
//  KeExitCriticalRegion to disable APCs (except Special Kernel APCs) while
//  the lock is held
//
//  Use ExInitializeResourceLite() to init the resource
//  Use ExDeleteResourceLite() to delete the resource
//

__drv_acquiresCriticalRegion
__drv_maxIRQL(APC_LEVEL)
VOID
FLTAPI
FltAcquireResourceExclusive(
    __inout __deref __drv_neverHold(ResourceLite) 
    __deref __drv_acquiresResource(ResourceLite) 
    PERESOURCE Resource
    );

__drv_acquiresCriticalRegion
__drv_maxIRQL(APC_LEVEL)
VOID
FLTAPI
FltAcquireResourceShared(
    __inout __deref __drv_neverHold(ResourceLite) 
    __deref __drv_acquiresResource(ResourceLite) 
    PERESOURCE Resource
    );

__drv_mustHoldCriticalRegion
__drv_releasesCriticalRegion
__drv_maxIRQL(DISPATCH_LEVEL)
VOID
FLTAPI
FltReleaseResource(
    __inout __deref __drv_releasesExclusiveResource(ResourceLite) PERESOURCE Resource
    );


//
//  PUSHLOCK APIs which do proper wrapping of KeEnterCriticalRegion and
//  KeExitCriticalRegion to disable APCs (except Special Kernel APCs) while
//  the lock is held
//

__drv_maxIRQL(APC_LEVEL) 
VOID
FLTAPI
FltInitializePushLock(
    __out PEX_PUSH_LOCK PushLock
    );

__drv_maxIRQL(APC_LEVEL) 
VOID
FLTAPI
FltDeletePushLock(
    __in PEX_PUSH_LOCK PushLock
    );

__drv_acquiresCriticalRegion
__drv_maxIRQL(APC_LEVEL) 
VOID
FLTAPI
FltAcquirePushLockExclusive(
    __inout __deref __drv_acquiresExclusiveResource(ExPushLockType)
    PEX_PUSH_LOCK PushLock
    );

__drv_acquiresCriticalRegion
__drv_maxIRQL(APC_LEVEL) 
VOID
FLTAPI
FltAcquirePushLockShared(
    __inout __deref __drv_acquiresExclusiveResource(ExPushLockType)        
    PEX_PUSH_LOCK PushLock
    );

__drv_mustHoldCriticalRegion
__drv_releasesCriticalRegion
__drv_maxIRQL(APC_LEVEL)
VOID
FLTAPI
FltReleasePushLock(
    __inout __deref __drv_releasesExclusiveResource(ExPushLockType)        
    PEX_PUSH_LOCK PushLock
    );


///////////////////////////////////////////////////////////////////////////////
//
//  Synchronization support routines
//
///////////////////////////////////////////////////////////////////////////////

#if FLT_MGR_LONGHORN

__checkReturn
__drv_when(((CallbackData!=NULL) && FLT_IS_IRP_OPERATION(CallbackData)), __drv_maxIRQL(PASSIVE_LEVEL))
__drv_when((!((CallbackData!=NULL) && FLT_IS_IRP_OPERATION(CallbackData))), __drv_maxIRQL(APC_LEVEL))
NTSTATUS
FLTAPI
FltCancellableWaitForSingleObject(
    __in PVOID Object,
    __in_opt PLARGE_INTEGER Timeout,
    __in_opt PFLT_CALLBACK_DATA CallbackData
    );

__checkReturn
__drv_when(((CallbackData!=NULL) && FLT_IS_IRP_OPERATION(CallbackData)), __drv_maxIRQL(PASSIVE_LEVEL))
__drv_when((!((CallbackData!=NULL) && FLT_IS_IRP_OPERATION(CallbackData))), __drv_maxIRQL(APC_LEVEL))
NTSTATUS
FLTAPI
FltCancellableWaitForMultipleObjects(
    __in ULONG Count,
    __in_ecount(Count) PVOID ObjectArray[],
    __in WAIT_TYPE WaitType,
    __in_opt PLARGE_INTEGER Timeout,
    __in_opt PKWAIT_BLOCK WaitBlockArray,
    __in PFLT_CALLBACK_DATA CallbackData
    );

#endif // FLT_MGR_LONGHORN


///////////////////////////////////////////////////////////////////////////////
//
//  General support routines
//
///////////////////////////////////////////////////////////////////////////////


BOOLEAN
FLTAPI
FltIsOperationSynchronous (
    __in PFLT_CALLBACK_DATA CallbackData
    );

__drv_maxIRQL(DISPATCH_LEVEL)
BOOLEAN
FLTAPI
FltIs32bitProcess (
    __in_opt PFLT_CALLBACK_DATA CallbackData
    );

__drv_maxIRQL(DISPATCH_LEVEL)
PEPROCESS
FLTAPI
FltGetRequestorProcess (
    __in PFLT_CALLBACK_DATA CallbackData
    );

__drv_maxIRQL(DISPATCH_LEVEL)
ULONG
FLTAPI
FltGetRequestorProcessId (
    __in PFLT_CALLBACK_DATA CallbackData
    );

#if FLT_MGR_LONGHORN

__drv_maxIRQL(DISPATCH_LEVEL)
HANDLE
FLTAPI
FltGetRequestorProcessIdEx (
    __in PFLT_CALLBACK_DATA CallbackData
    );

#endif // FLT_MGR_LONGHORN

__drv_maxIRQL(APC_LEVEL) 
VOID
FLTAPI
FltNotifyFilterChangeDirectory (
    __inout PNOTIFY_SYNC NotifySync,
    __inout PLIST_ENTRY NotifyList,
    __in PVOID FsContext,
    __in PSTRING FullDirectoryName,
    __in BOOLEAN WatchTree,
    __in BOOLEAN IgnoreBuffer,
    __in ULONG CompletionFilter,
    __in PFLT_CALLBACK_DATA NotifyCallbackData,
    __in_opt PCHECK_FOR_TRAVERSE_ACCESS TraverseCallback,
    __in_opt PSECURITY_SUBJECT_CONTEXT SubjectContext,
    __in_opt PFILTER_REPORT_CHANGE FilterCallback
    );

#if FLT_MGR_WIN7

__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTSTATUS
FLTAPI
FltGetRequestorSessionId(
    __in PFLT_CALLBACK_DATA CallbackData,
    __out PULONG SessionId 
    );


__drv_maxIRQL(DISPATCH_LEVEL)
NTSTATUS
FLTAPI
FltAdjustDeviceStackSizeForIoRedirection(
    __in PFLT_INSTANCE SourceInstance,
    __in PFLT_INSTANCE TargetInstance,
    __out_opt PBOOLEAN SourceDeviceStackSizeModified
    );

__drv_maxIRQL(DISPATCH_LEVEL)
NTSTATUS
FLTAPI
FltIsIoRedirectionAllowed(
    __in PFLT_INSTANCE SourceInstance,   
    __in PFLT_INSTANCE TargetInstance,
    __out PBOOLEAN RedirectionAllowed 
    );

__drv_maxIRQL(DISPATCH_LEVEL)
NTSTATUS
FLTAPI
FltIsIoRedirectionAllowedForOperation(
    __in PFLT_CALLBACK_DATA Data,
    __in PFLT_INSTANCE TargetInstance,
    __out PBOOLEAN RedirectionAllowedThisIo,    
    __out_opt PBOOLEAN RedirectionAllowedAllIo 
    );


#endif // FLT_MGR_WIN7 


///////////////////////////////////////////////////////////////////////////////
//
//  Transaction (TxF) support routines
//
///////////////////////////////////////////////////////////////////////////////

#if FLT_MGR_LONGHORN

//
//  Select ALL transaction notification values
//

#define FLT_MAX_TRANSACTION_NOTIFICATIONS \
                (TRANSACTION_NOTIFY_PREPREPARE | \
                 TRANSACTION_NOTIFY_PREPARE | \
                 TRANSACTION_NOTIFY_COMMIT | \
                 TRANSACTION_NOTIFY_ROLLBACK | \
                 TRANSACTION_NOTIFY_COMMIT_FINALIZE)

__checkReturn
__drv_maxIRQL(APC_LEVEL) 
NTSTATUS
FLTAPI
FltEnlistInTransaction (
    __in PFLT_INSTANCE Instance,
    __in PKTRANSACTION Transaction,
    __in PFLT_CONTEXT TransactionContext,
    __in NOTIFICATION_MASK NotificationMask
    );

__drv_maxIRQL(APC_LEVEL) 
NTSTATUS
FLTAPI
FltRollbackEnlistment (
    __in PFLT_INSTANCE Instance,
    __in PKTRANSACTION Transaction,
    __in_opt PFLT_CONTEXT TransactionContext
    );

__drv_maxIRQL(APC_LEVEL) 
NTSTATUS
FLTAPI
FltPrePrepareComplete (
    __in PFLT_INSTANCE Instance,
    __in PKTRANSACTION Transaction,
    __in_opt PFLT_CONTEXT TransactionContext
    );

__drv_maxIRQL(APC_LEVEL) 
NTSTATUS
FLTAPI
FltPrepareComplete (
    __in PFLT_INSTANCE Instance,
    __in PKTRANSACTION Transaction,
    __in_opt PFLT_CONTEXT TransactionContext
    );

__drv_maxIRQL(PASSIVE_LEVEL)
NTSTATUS
FLTAPI
FltCommitComplete (
    __in PFLT_INSTANCE Instance,
    __in PKTRANSACTION Transaction,
    __in_opt PFLT_CONTEXT TransactionContext
    );

__drv_maxIRQL(APC_LEVEL) 
NTSTATUS
FLTAPI
FltCommitFinalizeComplete (
    __in PFLT_INSTANCE Instance,
    __in PKTRANSACTION Transaction,
    __in_opt PFLT_CONTEXT TransactionContext
    );

__drv_maxIRQL(PASSIVE_LEVEL)
NTSTATUS
FLTAPI
FltRollbackComplete (
    __in PFLT_INSTANCE Instance,
    __in PKTRANSACTION Transaction,
    __in_opt PFLT_CONTEXT TransactionContext
    );

//
//  Some Kernel routines related to ECP manipulation
//      ZwCreateTransactionManager
//      ZwCreateResourceManager
//      TmEnableCallbacks
//      IoGetTransactionParameterBlock
//      TmCreateEnlistment
//      TmPrePrepareComplete
//      TmPrepareComplete
//      TmCommitComplete
//      TmRollbackComplete
//      TmRollbackEnlistment
//

#endif // FLT_MGR_LONGHORN



///////////////////////////////////////////////////////////////////////////////
//
//  Extra Create Parameter (ECP) support routines
//
///////////////////////////////////////////////////////////////////////////////

#if FLT_MGR_LONGHORN

__checkReturn
__drv_maxIRQL(APC_LEVEL) 
NTSTATUS
FLTAPI
FltAllocateExtraCreateParameterList (
    __in PFLT_FILTER Filter,
    __in FSRTL_ALLOCATE_ECPLIST_FLAGS Flags,
    __deref_out PECP_LIST *EcpList
    );

__checkReturn
__drv_maxIRQL(APC_LEVEL) 
NTSTATUS
FLTAPI
FltAllocateExtraCreateParameter (
    __in PFLT_FILTER Filter,
    __in LPCGUID EcpType,
    __in_bound ULONG SizeOfContext,
    __in FSRTL_ALLOCATE_ECP_FLAGS Flags,
    __in_opt PFSRTL_EXTRA_CREATE_PARAMETER_CLEANUP_CALLBACK CleanupCallback,
    __in ULONG PoolTag,
    __deref_out PVOID *EcpContext
    );

__drv_maxIRQL(APC_LEVEL)
VOID
FLTAPI
FltInitExtraCreateParameterLookasideList (
    __in PFLT_FILTER Filter,
    __inout PVOID Lookaside,
    __in FSRTL_ECP_LOOKASIDE_FLAGS Flags,
    __in SIZE_T Size,
    __in ULONG Tag
    );

__drv_maxIRQL(APC_LEVEL) 
VOID
FLTAPI
FltDeleteExtraCreateParameterLookasideList (
    __in PFLT_FILTER Filter,
    __inout PVOID Lookaside,
    __in FSRTL_ECP_LOOKASIDE_FLAGS Flags
    );

__checkReturn
__drv_maxIRQL(APC_LEVEL) 
NTSTATUS
FLTAPI
FltAllocateExtraCreateParameterFromLookasideList (
    __in PFLT_FILTER Filter,
    __in LPCGUID EcpType,
    __in ULONG SizeOfContext,
    __in FSRTL_ALLOCATE_ECP_FLAGS Flags,
    __in_opt PFSRTL_EXTRA_CREATE_PARAMETER_CLEANUP_CALLBACK CleanupCallback,
    __inout PVOID LookasideList,
    __deref_out PVOID *EcpContext
    );

__drv_maxIRQL(APC_LEVEL) 
NTSTATUS
FLTAPI
FltInsertExtraCreateParameter (
    __in PFLT_FILTER Filter,
    __inout PECP_LIST EcpList,
    __inout PVOID EcpContext
    );

__drv_maxIRQL(APC_LEVEL) 
NTSTATUS
FLTAPI
FltFindExtraCreateParameter (
    __in PFLT_FILTER Filter,
    __in PECP_LIST EcpList,
    __in LPCGUID EcpType,
    __deref_opt_out PVOID *EcpContext,
    __out_opt ULONG *EcpContextSize
    );

__drv_maxIRQL(APC_LEVEL) 
NTSTATUS
FLTAPI
FltRemoveExtraCreateParameter (
    __in PFLT_FILTER Filter,
    __inout PECP_LIST EcpList,
    __in LPCGUID EcpType,
    __deref_out PVOID *EcpContext,
    __out_opt ULONG *EcpContextSize
    );

__drv_maxIRQL(APC_LEVEL) 
VOID
FLTAPI
FltFreeExtraCreateParameterList (
    __in PFLT_FILTER Filter,
    __in PECP_LIST EcpList
    );

__drv_maxIRQL(APC_LEVEL) 
VOID
FLTAPI
FltFreeExtraCreateParameter (
    __in PFLT_FILTER Filter,
    __in PVOID EcpContext
    );

__drv_maxIRQL(APC_LEVEL)
NTSTATUS
FLTAPI
FltGetEcpListFromCallbackData (
    __in PFLT_FILTER Filter,
    __in PFLT_CALLBACK_DATA CallbackData,
    __deref_out_opt PECP_LIST *EcpList
    );

__drv_maxIRQL(APC_LEVEL)
NTSTATUS
FLTAPI
FltSetEcpListIntoCallbackData (
    __in PFLT_FILTER Filter,
    __in PFLT_CALLBACK_DATA CallbackData,
    __in PECP_LIST EcpList
    );

__drv_maxIRQL(APC_LEVEL)
NTSTATUS
FLTAPI
FltGetNextExtraCreateParameter (
    __in PFLT_FILTER Filter,
    __in PECP_LIST EcpList,
    __in_opt PVOID CurrentEcpContext,
    __out_opt LPGUID NextEcpType,
    __deref_opt_out PVOID *NextEcpContext,
    __out_opt ULONG *NextEcpContextSize
    );

__drv_maxIRQL(APC_LEVEL)
VOID
FLTAPI
FltAcknowledgeEcp (
    __in PFLT_FILTER Filter,
    __in PVOID EcpContext
    );

__drv_maxIRQL(APC_LEVEL)
BOOLEAN
FLTAPI
FltIsEcpAcknowledged (
    __in PFLT_FILTER Filter,
    __in PVOID EcpContext
    );

__drv_maxIRQL(APC_LEVEL)
BOOLEAN
FLTAPI
FltIsEcpFromUserMode (
    __in PFLT_FILTER Filter,
    __in PVOID EcpContext
    );

//
//  Some Kernel routines related to ECP manipulation
//
//      FsRtlAllocateExtraCreateParameterList
//      FsRtlFreeExtraCreateParameterList
//      FsRtlAllocateExtraCreateParameter
//      FsRtlFreeExtraCreateParameter
//      FsRtlInitExtraCreateParameterLookasideList
//      FsRtlDeleteExtraCreateParameterLookasideList
//      FsRtlAllocateExtraCreateParameterFromLookasideList
//      FsRtlInsertExtraCreateParameter
//      FsRtlRemoveExtraCreateParameter
//      FsRtlGetEcpListFromIrp
//      FsRtlSetEcpListIntoIrp
//      FsRtlGetNextExtraCreateParameter
//      FsRtlAcknowledgeEcp
//      FsRtlIsEcpAcknowledged
//      FsRtlIsEcpFromUserMode
//

#endif // FLT_MGR_LONGHORN


///////////////////////////////////////////////////////////////////////////////
//
//  IoPriorityHint support routines
//
///////////////////////////////////////////////////////////////////////////////

#if FLT_MGR_LONGHORN

__drv_maxIRQL(DISPATCH_LEVEL)
NTSTATUS
FLTAPI
FltRetrieveIoPriorityInfo (
    __in_opt PFLT_CALLBACK_DATA Data,
    __in_opt PFILE_OBJECT FileObject,
    __in_opt PETHREAD Thread,
    __inout PIO_PRIORITY_INFO PriorityInfo
    );

__drv_maxIRQL(DISPATCH_LEVEL)
NTSTATUS
FLTAPI
FltApplyPriorityInfoThread(
    __in PIO_PRIORITY_INFO InputPriorityInfo,
    __out_opt PIO_PRIORITY_INFO OutputPriorityInfo,
    __in PETHREAD Thread
    );

__drv_maxIRQL(DISPATCH_LEVEL)
IO_PRIORITY_HINT
FLTAPI
FltGetIoPriorityHint (
    __in PFLT_CALLBACK_DATA Data
    );

__drv_maxIRQL(DISPATCH_LEVEL)
IO_PRIORITY_HINT
FLTAPI
FltGetIoPriorityHintFromCallbackData (
    __in PFLT_CALLBACK_DATA Data
    );

__drv_maxIRQL(DISPATCH_LEVEL)
NTSTATUS
FLTAPI
FltSetIoPriorityHintIntoCallbackData (
    __in PFLT_CALLBACK_DATA Data,
    __in IO_PRIORITY_HINT PriorityHint
    );

__drv_maxIRQL(DISPATCH_LEVEL)
IO_PRIORITY_HINT
FLTAPI
FltGetIoPriorityHintFromFileObject (
    __in PFILE_OBJECT FileObject
    );

__checkReturn
__drv_maxIRQL(DISPATCH_LEVEL)
NTSTATUS
FLTAPI
FltSetIoPriorityHintIntoFileObject (
    __in PFILE_OBJECT FileObject,
    __in IO_PRIORITY_HINT PriorityHint
    );

__drv_maxIRQL(DISPATCH_LEVEL)
IO_PRIORITY_HINT
FLTAPI
FltGetIoPriorityHintFromThread (
    __in PETHREAD Thread
    );

__drv_maxIRQL(DISPATCH_LEVEL)
NTSTATUS
FLTAPI
FltSetIoPriorityHintIntoThread (
    __in PETHREAD Thread,
    __in IO_PRIORITY_HINT PriorityHint
    );

//
//  Some Kernel routines related to IoPriorityHint manipulation
//
//      IoInitializePriorityInfo
//      IoSetIoPriorityHint
//      IoGetIoPriorityHint
//      ZwSetInformationFile (FileIoPriorityHintInformation class)
//      ZwQueryInformationFile (FileIoPriorityHintInformation class)
//

#endif // FLT_MGR_LONGHORN


///////////////////////////////////////////////////////////////////////////////
//
//                      Debug support routines
//
///////////////////////////////////////////////////////////////////////////////

PCHAR
FLTAPI
FltGetIrpName (
    __in UCHAR IrpMajorCode
    );


///////////////////////////////////////////////////////////////////////////////
//
//  End of MAIN conditional compilation variables
//
///////////////////////////////////////////////////////////////////////////////

#else
#   pragma message("You are building for a target that does not have FilterManager Support!")
#endif // FLT_MGR_BASELINE

#ifdef __cplusplus
}       //  Balance extern "C" above
#endif

#endif  //__FLTKERNEL__

