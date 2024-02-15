/*++ BUILD Version: 0162    // Increment this if a change has global effects

Copyright (c) Microsoft Corporation. All rights reserved.

Module Name:

    wdm.h

Abstract:

    This module defines the WDM types, constants, and functions that are
    exposed to device drivers.

Revision History:

--*/

#ifndef _WDMDDK_
#define _WDMDDK_

#ifndef _NTDDK_
#define _WDM_INCLUDED_
#define _DDK_DRIVER_

//
// Use 9x compat Interlocked functions by default when including wdm.h
//

#define NO_INTERLOCKED_INTRINSICS

#endif

#define _NTDDK_
#define _STRSAFE_USE_SECURE_CRT 0

#ifndef RC_INVOKED
#if _MSC_VER < 1300
#error Compiler version not supported by Windows DDK
#endif
#endif // RC_INVOKED

#define NT_INCLUDED
#define _CTYPE_DISABLE_MACROS

#if _MSC_VER >= 1200
#pragma warning(push)
#endif

#pragma warning(disable:4115) // named type definition in parentheses
#pragma warning(disable:4201) // nameless struct/union
#pragma warning(disable:4214) // bit field types other than int

#include <excpt.h>
#include <ntdef.h>
#include <ntstatus.h>
#include <bugcodes.h>
#include <ntiologc.h>

__internal_kernel_driver
__drv_Mode_impl(WDM_INCLUDED)

#ifdef __cplusplus
extern "C" {
#endif

//
// Define types that are not exported.
//

typedef struct _ACCESS_STATE *PACCESS_STATE;
typedef struct _CALLBACK_OBJECT *PCALLBACK_OBJECT;
#if defined(_NTHAL_INCLUDED_)
typedef struct _KPROCESS *PEPROCESS;
typedef struct _ETHREAD *PETHREAD;
#elif defined(_NTIFS_INCLUDED_)
typedef struct _KPROCESS *PEPROCESS;
typedef struct _KTHREAD *PETHREAD;
#else
typedef struct _EPROCESS *PEPROCESS;
typedef struct _ETHREAD *PETHREAD;
#endif
typedef struct _IO_TIMER *PIO_TIMER;
typedef struct _KINTERRUPT *PKINTERRUPT;
typedef struct _KTHREAD *PKTHREAD, *PRKTHREAD;
typedef struct _KPROCESS *PKPROCESS, *PRKPROCESS;
typedef struct _OBJECT_TYPE *POBJECT_TYPE;
typedef struct _SECURITY_QUALITY_OF_SERVICE *PSECURITY_QUALITY_OF_SERVICE;


//
// Declare empty structure definitions so that they may be referenced by
// routines before they are defined
//
typedef struct _CONTEXT *PCONTEXT;
typedef struct _IO_STACK_LOCATION *PIO_STACK_LOCATION;
typedef struct _VPB *PVPB;
typedef struct _FILE_GET_QUOTA_INFORMATION *PFILE_GET_QUOTA_INFORMATION;


#if defined(_M_AMD64)

ULONG64
__readgsqword (
    IN ULONG Offset
    );

#pragma intrinsic(__readgsqword)

__forceinline
PKTHREAD
KeGetCurrentThread (
    VOID
    )

{
    return (struct _KTHREAD *)__readgsqword(0x188);
}

#endif // defined(_M_AMD64)

#if defined(_M_IX86) || defined(_M_IA64)

NTSYSAPI
PKTHREAD
NTAPI
KeGetCurrentThread(
    VOID
    );

#endif // defined(_M_IX86) || defined(_M_IA64)

//
// Define base address for kernel and user space
//

#ifndef _WIN64

#define KADDRESS_BASE 0

#define UADDRESS_BASE 0

#endif // !_WIN64


#if defined(_M_IA64) && !defined(_NTHAL_)

//
// Define Address of Processor Control Registers.
//

#define KIPCR ((ULONG_PTR)(KADDRESS_BASE + 0xFFFF0000))            // kernel address of first PCR

//
// Define Pointer to Processor Control Registers.
//

#define PCR ((volatile KPCR * const)KIPCR)

#endif // defined(_M_IA64) && !defined(_NTHAL_)

#include <mce.h>

#ifndef FAR
#define FAR
#endif

#define PsGetCurrentProcess IoGetCurrentProcess

#if (NTDDI_VERSION >= NTDDI_VISTA)
extern NTSYSAPI volatile CCHAR KeNumberProcessors;
#elif (NTDDI_VERSION >= NTDDI_WINXP)
extern NTSYSAPI CCHAR KeNumberProcessors;
#else
extern PCCHAR KeNumberProcessors;
#endif
#if defined(_X86_) 
//
// Interrupt Request Level definitions
//

#define PASSIVE_LEVEL 0             // Passive release level
#define LOW_LEVEL 0                 // Lowest interrupt level
#define APC_LEVEL 1                 // APC interrupt level
#define DISPATCH_LEVEL 2            // Dispatcher level
#define CMCI_LEVEL 5                // CMCI handler level

#define PROFILE_LEVEL 27            // timer used for profiling.
#define CLOCK1_LEVEL 28             // Interval clock 1 level - Not used on x86
#define CLOCK2_LEVEL 28             // Interval clock 2 level
#define IPI_LEVEL 29                // Interprocessor interrupt level
#define POWER_LEVEL 30              // Power failure level
#define HIGH_LEVEL 31               // Highest interrupt level

#define CLOCK_LEVEL                 (CLOCK2_LEVEL)

#endif 
#if defined(_AMD64_) 
//
// Interrupt Request Level definitions
//

#define PASSIVE_LEVEL 0                 // Passive release level
#define LOW_LEVEL 0                     // Lowest interrupt level
#define APC_LEVEL 1                     // APC interrupt level
#define DISPATCH_LEVEL 2                // Dispatcher level
#define CMCI_LEVEL 5                    // CMCI handler level

#define CLOCK_LEVEL 13                  // Interval clock level
#define IPI_LEVEL 14                    // Interprocessor interrupt level
#define DRS_LEVEL 14                    // Deferred Recovery Service level
#define POWER_LEVEL 14                  // Power failure level
#define PROFILE_LEVEL 15                // timer used for profiling.
#define HIGH_LEVEL 15                   // Highest interrupt level

#endif  
#if defined(_IA64_) 
//
// Define Interrupt Request Levels.
//

#define PASSIVE_LEVEL            0      // Passive release level
#define LOW_LEVEL                0      // Lowest interrupt level
#define APC_LEVEL                1      // APC interrupt level
#define DISPATCH_LEVEL           2      // Dispatcher level
#define CMC_LEVEL                3      // Correctable machine check level
#define DEVICE_LEVEL_BASE        4      // 4 - 11 - Device IRQLs
#define PC_LEVEL                12      // Performance Counter IRQL
#define IPI_LEVEL               14      // IPI IRQL
#define DRS_LEVEL               14      // Deferred Recovery Service level
#define CLOCK_LEVEL             13      // Clock Timer IRQL
#define POWER_LEVEL             15      // Power failure level
#define PROFILE_LEVEL           15      // Profiling level
#define HIGH_LEVEL              15      // Highest interrupt level

#endif 

#define LOW_PRIORITY 0              // Lowest thread priority level
#define LOW_REALTIME_PRIORITY 16    // Lowest realtime priority level
#define HIGH_PRIORITY 31            // Highest thread priority level
#define MAXIMUM_PRIORITY 32         // Number of thread priority levels

#define MAXIMUM_WAIT_OBJECTS 64     // Maximum number of wait objects

#define MAXIMUM_SUSPEND_COUNT MAXCHAR // Maximum times thread can be suspended


//
// Define system time structure.
//

typedef struct _KSYSTEM_TIME {
    ULONG LowPart;
    LONG High1Time;
    LONG High2Time;
} KSYSTEM_TIME, *PKSYSTEM_TIME;

//
// Thread priority
//

typedef LONG KPRIORITY;

//
// Spin Lock
//



typedef ULONG_PTR KSPIN_LOCK;
typedef KSPIN_LOCK *PKSPIN_LOCK;


//
// Define per processor lock queue structure.
//
// N.B. The lock field of the spin lock queue structure contains the address
//      of the associated kernel spin lock, an owner bit, and a lock bit. Bit
//      0 of the spin lock address is the wait bit and bit 1 is the owner bit.
//      The use of this field is such that the bits can be set and cleared
//      noninterlocked, however, the back pointer must be preserved.
//
//      The lock wait bit is set when a processor enqueues itself on the lock
//      queue and it is not the only entry in the queue. The processor will
//      spin on this bit waiting for the lock to be granted.
//
//      The owner bit is set when the processor owns the respective lock.
//
//      The next field of the spin lock queue structure is used to line the
//      queued lock structures together in fifo order. It also can set set and
//      cleared noninterlocked.
//

#define LOCK_QUEUE_WAIT 1
#define LOCK_QUEUE_WAIT_BIT 0

#define LOCK_QUEUE_OWNER 2
#define LOCK_QUEUE_OWNER_BIT 1

#if defined(_AMD64_)

typedef ULONG64 KSPIN_LOCK_QUEUE_NUMBER;

#define LockQueueUnusedSpare0 0
#define LockQueueExpansionLock 1
#define LockQueueUnusedSpare2 2
#define LockQueueSystemSpaceLock 3
#define LockQueueVacbLock 4
#define LockQueueMasterLock 5
#define LockQueueNonPagedPoolLock 6
#define LockQueueIoCancelLock 7
#define LockQueueWorkQueueLock 8
#define LockQueueIoVpbLock 9
#define LockQueueIoDatabaseLock 10
#define LockQueueIoCompletionLock 11
#define LockQueueNtfsStructLock 12
#define LockQueueAfdWorkQueueLock 13
#define LockQueueBcbLock 14
#define LockQueueMmNonPagedPoolLock 15
#define LockQueueUnusedSpare16 16
#define LockQueueMaximumLock (LockQueueUnusedSpare16 + 1)

#else

typedef enum _KSPIN_LOCK_QUEUE_NUMBER {
    LockQueueUnusedSpare0,
    LockQueueExpansionLock,
    LockQueueUnusedSpare2,
    LockQueueSystemSpaceLock,
    LockQueueVacbLock,
    LockQueueMasterLock,
    LockQueueNonPagedPoolLock,
    LockQueueIoCancelLock,
    LockQueueWorkQueueLock,
    LockQueueIoVpbLock,
    LockQueueIoDatabaseLock,
    LockQueueIoCompletionLock,
    LockQueueNtfsStructLock,
    LockQueueAfdWorkQueueLock,
    LockQueueBcbLock,
    LockQueueMmNonPagedPoolLock,
    LockQueueUnusedSpare16,
    LockQueueMaximumLock = LockQueueUnusedSpare16 + 1
} KSPIN_LOCK_QUEUE_NUMBER, *PKSPIN_LOCK_QUEUE_NUMBER;

#endif

typedef struct _KSPIN_LOCK_QUEUE {
    struct _KSPIN_LOCK_QUEUE * volatile Next;
    PKSPIN_LOCK volatile Lock;
} KSPIN_LOCK_QUEUE, *PKSPIN_LOCK_QUEUE;

typedef struct _KLOCK_QUEUE_HANDLE {
    KSPIN_LOCK_QUEUE LockQueue;
    KIRQL OldIrql;
} KLOCK_QUEUE_HANDLE, *PKLOCK_QUEUE_HANDLE;


//
// Interrupt routine (first level dispatch)
//

typedef
__drv_functionClass(KINTERRUPT_ROUTINE)
__drv_sameIRQL
VOID
KINTERRUPT_ROUTINE (
    VOID
    );

typedef KINTERRUPT_ROUTINE *PKINTERRUPT_ROUTINE;

//
// Profile source types
//
typedef enum _KPROFILE_SOURCE {
    ProfileTime,
    ProfileAlignmentFixup,
    ProfileTotalIssues,
    ProfilePipelineDry,
    ProfileLoadInstructions,
    ProfilePipelineFrozen,
    ProfileBranchInstructions,
    ProfileTotalNonissues,
    ProfileDcacheMisses,
    ProfileIcacheMisses,
    ProfileCacheMisses,
    ProfileBranchMispredictions,
    ProfileStoreInstructions,
    ProfileFpInstructions,
    ProfileIntegerInstructions,
    Profile2Issue,
    Profile3Issue,
    Profile4Issue,
    ProfileSpecialInstructions,
    ProfileTotalCycles,
    ProfileIcacheIssues,
    ProfileDcacheAccesses,
    ProfileMemoryBarrierCycles,
    ProfileLoadLinkedIssues,
    ProfileMaximum
} KPROFILE_SOURCE;


//
// Define 128-bit 16-byte aligned xmm register type.
//

typedef struct DECLSPEC_ALIGN(16) _M128A {
    ULONGLONG Low;
    LONGLONG High;
} M128A, *PM128A;

//
// Format of data for (F)XSAVE/(F)XRSTOR instruction
//

typedef struct DECLSPEC_ALIGN(16) _XSAVE_FORMAT {
    USHORT ControlWord;
    USHORT StatusWord;
    UCHAR TagWord;
    UCHAR Reserved1;
    USHORT ErrorOpcode;
    ULONG ErrorOffset;
    USHORT ErrorSelector;
    USHORT Reserved2;
    ULONG DataOffset;
    USHORT DataSelector;
    USHORT Reserved3;
    ULONG MxCsr;
    ULONG MxCsr_Mask;
    M128A FloatRegisters[8];

#if defined(_WIN64)

    M128A XmmRegisters[16];
    UCHAR Reserved4[96];

#else

    M128A XmmRegisters[8];
    UCHAR Reserved4[192];

    //
    // The fields below are not part of XSAVE/XRSTOR format.
    // They are written by the OS which is relying on a fact that
    // neither (FX)SAVE nor (F)XSTOR used this area.
    //

    ULONG   StackControl[7];    // KERNEL_STACK_CONTROL structure actualy
    ULONG   Cr0NpxState;

#endif

} XSAVE_FORMAT, *PXSAVE_FORMAT;

typedef struct DECLSPEC_ALIGN(8) _XSAVE_AREA_HEADER {
    ULONG64 Mask;
    ULONG64 Reserved[7];
} XSAVE_AREA_HEADER, *PXSAVE_AREA_HEADER;

typedef struct DECLSPEC_ALIGN(16) _XSAVE_AREA {
    XSAVE_FORMAT LegacyState;
    XSAVE_AREA_HEADER Header;
} XSAVE_AREA, *PXSAVE_AREA;

typedef struct _XSTATE_CONTEXT {
    ULONG64 Mask;
    ULONG Length;
    ULONG Reserved1;
    __field_bcount_opt(Length) PXSAVE_AREA Area;

#if defined(_X86_)
    ULONG Reserved2;
#endif

    PVOID Buffer;

#if defined(_X86_)
    ULONG Reserved3;
#endif

} XSTATE_CONTEXT, *PXSTATE_CONTEXT;


#define XSAVE_ALIGN                 64
#define MINIMAL_XSTATE_AREA_LENGTH  sizeof(XSAVE_AREA)


//
// This structure specifies an offset (from the beginning of CONTEXT_EX
// structure) and size of a single chunk of an extended context structure.
//
// N.B. Offset may be negative.
//

typedef struct _CONTEXT_CHUNK {
    LONG Offset;
    ULONG Length;
} CONTEXT_CHUNK, *PCONTEXT_CHUNK;

//
// CONTEXT_EX structure is an extension to CONTEXT structure. It defines
// a context record as a set of disjoint variable-sized buffers (chunks)
// each containing a portion of processor state. Currently there are only
// two buffers (chunks) are defined:
//
//   - Legacy, that stores traditional CONTEXT structure;
//   - XState, that stores XSAVE save area buffer starting from
//     XSAVE_AREA_HEADER, i.e. without the first 512 bytes.
//
// There a few assumptions exists that simplify conversion of PCONTEXT
// pointer to PCONTEXT_EX pointer.
//
// 1. APIs that work with PCONTEXT pointers assume that CONTEXT_EX is
//    stored right after the CONTEXT structure. It is also assumed that
//    CONTEXT_EX is present if and only if corresponding CONTEXT_XXX
//    flags are set in CONTEXT.ContextFlags.
//
// 2. CONTEXT_EX.Legacy is always present if CONTEXT_EX structure is
//    present. All other chunks are optional.
//
// 3. CONTEXT.ContextFlags unambigiously define which chunks are
//    present. I.e. if CONTEXT_XSTATE is set CONTEXT_EX.XState is valid.
//

typedef struct _CONTEXT_EX {

    //
    // The total length of the structure starting from the chunk with
    // the smallest offset. N.B. that the offset may be negative.
    //

    CONTEXT_CHUNK All;

    //
    // Wrapper for the traditional CONTEXT structure. N.B. the size of
    // the chunk may be less than sizeof(CONTEXT) is some cases (when
    // CONTEXT_EXTENDED_REGISTERS is not set on x86 for instance).
    //

    CONTEXT_CHUNK Legacy;

    //
    // CONTEXT_XSTATE: Extended processor state chunk. The state is
    // stored in the same format XSAVE operation strores it with
    // exception of the first 512 bytes, i.e. staring from
    // XSAVE_AREA_HEADER. The lower two bits corresponding FP and
    // SSE state must be zero.
    //

    CONTEXT_CHUNK XState;

} CONTEXT_EX, *PCONTEXT_EX;

#define CONTEXT_EX_LENGTH   ALIGN_UP_BY(sizeof(CONTEXT_EX), STACK_ALIGN)

//
// These macros make context chunks manupulations easier.
//

#define RTL_CONTEXT_EX_OFFSET(ContextEx, Chunk)         \
    ((ContextEx)->Chunk.Offset)

#define RTL_CONTEXT_EX_LENGTH(ContextEx, Chunk)         \
    ((ContextEx)->Chunk.Length)

#define RTL_CONTEXT_EX_CHUNK(Base, Layout, Chunk)       \
    ((PVOID)((PCHAR)(Base) + RTL_CONTEXT_EX_OFFSET(Layout, Chunk)))

#define RTL_CONTEXT_OFFSET(Context, Chunk)              \
    RTL_CONTEXT_EX_OFFSET((PCONTEXT_EX)(Context + 1), Chunk)

#define RTL_CONTEXT_LENGTH(Context, Chunk)              \
    RTL_CONTEXT_EX_LENGTH((PCONTEXT_EX)(Context + 1), Chunk)

#define RTL_CONTEXT_CHUNK(Context, Chunk)               \
    RTL_CONTEXT_EX_CHUNK((PCONTEXT_EX)(Context + 1),    \
                         (PCONTEXT_EX)(Context + 1),    \
                         Chunk)


#if !defined(__midl) && !defined(MIDL_PASS)

//
// XSAVE/XRSTOR save area should be aligned on 64 byte boundary
//

C_ASSERT((sizeof(XSAVE_FORMAT) & (XSAVE_ALIGN - 1)) == 0);
C_ASSERT((FIELD_OFFSET(XSAVE_AREA, Header) & (XSAVE_ALIGN - 1)) == 0);

// XSAVE_AREA structure must be sized uniformly on all architectures
C_ASSERT(MINIMAL_XSTATE_AREA_LENGTH == 512 + 64);

#endif


#ifdef _X86_

//
// Disable these two pragmas that evaluate to "sti" "cli" on x86 so that driver
// writers to not leave them inadvertantly in their code.
//

#if !defined(MIDL_PASS)
#if !defined(RC_INVOKED)

#if _MSC_VER >= 1200
#pragma warning(push)
#endif
#pragma warning(disable:4164)   // disable C4164 warning so that apps that
                                // build with /Od don't get weird errors !
#ifdef _M_IX86
#pragma function(_enable)
#pragma function(_disable)
#endif

#if _MSC_VER >= 1200
#pragma warning(pop)
#else
#pragma warning(default:4164)   // reenable C4164 warning
#endif

#endif
#endif


#if defined(_M_IX86) && !defined(RC_INVOKED) && !defined(MIDL_PASS)

#ifdef __cplusplus
extern "C" {
#endif



#if (_MSC_FULL_VER >= 14000101)


//
// Define bit test intrinsics.
//

#define BitTest _bittest
#define BitTestAndComplement _bittestandcomplement
#define BitTestAndSet _bittestandset
#define BitTestAndReset _bittestandreset
#define InterlockedBitTestAndSet _interlockedbittestandset
#define InterlockedBitTestAndReset _interlockedbittestandreset

__checkReturn
BOOLEAN
_bittest (
    __in_bcount((Offset+7)/8) LONG const *Base,
    __in LONG Offset
    );

BOOLEAN
_bittestandcomplement (
    __inout_bcount((Offset+7)/8) LONG *Base,
    __in LONG Offset
    );

BOOLEAN
_bittestandset (
    __inout_bcount((Offset+7)/8) LONG *Base,
    __in LONG Offset
    );

BOOLEAN
_bittestandreset (
    __inout_bcount((Offset+7)/8) LONG *Base,
    __in LONG Offset
    );

BOOLEAN
_interlockedbittestandset (
    __inout_bcount((Offset+7)/8) __drv_interlocked LONG volatile *Base,
    __in LONG Offset
    );

BOOLEAN
_interlockedbittestandreset (
    __inout_bcount((Offset+7)/8) __drv_interlocked LONG volatile *Base,
    __in LONG Offset
    );

#pragma intrinsic(_bittest)
#pragma intrinsic(_bittestandcomplement)
#pragma intrinsic(_bittestandset)
#pragma intrinsic(_bittestandreset)
#pragma intrinsic(_interlockedbittestandset)
#pragma intrinsic(_interlockedbittestandreset)

//
// Define bit scan intrinsics.
//

#define BitScanForward _BitScanForward
#define BitScanReverse _BitScanReverse

__success(return != 0)
BOOLEAN
_BitScanForward (
    __out ULONG *Index,
    __in ULONG Mask
    );

__success(return != 0)
BOOLEAN
_BitScanReverse (
    __out ULONG *Index,
    __in ULONG Mask
    );

#pragma intrinsic(_BitScanForward)
#pragma intrinsic(_BitScanReverse)

#else

#pragma warning(push)
#pragma warning(disable:4035 4793)

FORCEINLINE
BOOLEAN
InterlockedBitTestAndSet (
    __inout_bcount((Bit+7)/8) __drv_interlocked LONG volatile *Base,
    __in LONG Bit
    )
{
    __asm {
           mov eax, Bit
           mov ecx, Base
           lock bts [ecx], eax
           setc al
    };
}

FORCEINLINE
BOOLEAN
InterlockedBitTestAndReset (
    __inout_bcount((Bit+7)/8) __drv_interlocked LONG volatile *Base,
    __in LONG Bit
    )
{
    __asm {
           mov eax, Bit
           mov ecx, Base
           lock btr [ecx], eax
           setc al
    };
}
#pragma warning(pop)

#endif	/* _MSC_FULL_VER >= 14000101 */

//
// [pfx_parse] - guard against PREfix intrinsic error
//
#if (_MSC_FULL_VER >= 140040816) || (defined(_PREFAST_) && (_MSC_VER >= 1400))

#define InterlockedAnd16 _InterlockedAnd16
#define InterlockedCompareExchange16 _InterlockedCompareExchange16
#define InterlockedOr16 _InterlockedOr16

SHORT
_InterlockedAnd16 (
    __inout __drv_interlocked SHORT volatile *Destination,
    __in SHORT Value
    );

SHORT
_InterlockedCompareExchange16 (
    __inout __drv_interlocked SHORT volatile *Destination,
    __in SHORT ExChange,
    __in SHORT Comperand
    );

SHORT
_InterlockedOr16 (
    __inout __drv_interlocked SHORT volatile *Destination,
    __in SHORT Value
    );

#pragma intrinsic(_InterlockedAnd16)
#pragma intrinsic(_InterlockedCompareExchange16)
#pragma intrinsic(_InterlockedOr16)

#endif  /* _MSC_FULL_VER >= 140040816 */

#if !defined(_M_CEE_PURE)
#pragma warning(push)
#pragma warning(disable:4035 4793)

FORCEINLINE
BOOLEAN
InterlockedBitTestAndComplement (
    __inout_bcount((Bit+7)/8) __drv_interlocked LONG volatile *Base,
    __in LONG Bit
    )
{
    __asm {
           mov eax, Bit
           mov ecx, Base
           lock btc [ecx], eax
           setc al
    };
}
#pragma warning(pop)
#endif	/* _M_CEE_PURE */

//
// [pfx_parse]
// guard against __readfsbyte parsing error
//
#if (_MSC_FULL_VER >= 13012035) || defined(_PREFIX_) || defined(_PREFAST_)

//
// Define FS referencing intrinsics
//

UCHAR
__readfsbyte (
    __in ULONG Offset
    );

USHORT
__readfsword (
    __in ULONG Offset
    );

ULONG
__readfsdword (
    __in ULONG Offset
    );

VOID
__writefsbyte (
    __in ULONG Offset,
    __in UCHAR Data
    );

VOID
__writefsword (
    __in ULONG Offset,
    __in USHORT Data
    );

VOID
__writefsdword (
    __in ULONG Offset,
    __in ULONG Data
    );

#pragma intrinsic(__readfsbyte)
#pragma intrinsic(__readfsword)
#pragma intrinsic(__readfsdword)
#pragma intrinsic(__writefsbyte)
#pragma intrinsic(__writefsword)
#pragma intrinsic(__writefsdword)

#endif	/* _MSC_FULL_VER >= 13012035 */

#if (_MSC_FULL_VER >= 140050727) || defined(_PREFIX_) || defined(_PREFAST_)

#if !defined(_MANAGED)

VOID
__incfsbyte (
    __in ULONG Offset
    );

VOID
__addfsbyte (
    __in ULONG Offset,
    __in UCHAR Value
    );

VOID
__incfsword (
    __in ULONG Offset
    );

VOID
__addfsword (
    __in ULONG Offset,
    __in USHORT Value
    );

VOID
__incfsdword (
    __in ULONG Offset
    );

VOID
__addfsdword (
    __in ULONG Offset,
    __in ULONG Value
    );

#pragma intrinsic(__incfsbyte)
#pragma intrinsic(__addfsbyte)
#pragma intrinsic(__incfsword)
#pragma intrinsic(__addfsword)
#pragma intrinsic(__incfsdword)
#pragma intrinsic(__addfsdword)

#endif

#endif	/* _MSC_FULL_VER >= 140050727 */

#if (_MSC_FULL_VER >= 140041204) || defined(_PREFIX_) || defined(_PREFAST_)

VOID
_mm_pause (
    VOID
    );

#pragma intrinsic(_mm_pause)

#define YieldProcessor _mm_pause

#else

#if !defined(_M_CEE_PURE)
#define YieldProcessor() __asm { rep nop }
#endif  // !defined(_M_CEE_PURE)

#endif  // (_MSC_FULL_VER >= 140041204)

#ifdef __cplusplus
}
#endif

#endif  /* !defined(MIDL_PASS) || defined(_M_IX86) */


#if defined(_X86_) && defined(_M_IX86) && !defined(RC_INVOKED) && !defined(MIDL_PASS)

#if _MSC_FULL_VER >= 140030222

VOID
__int2c (
    VOID
    );

#pragma intrinsic(__int2c)

__analysis_noreturn
FORCEINLINE
VOID
DbgRaiseAssertionFailure (
    VOID
    )

{
    __int2c();
}

#else
#pragma warning( push )
#pragma warning( disable : 4793 )

__analysis_noreturn
FORCEINLINE
VOID
DbgRaiseAssertionFailure (
    VOID
    )

{
    __asm int 0x2c
}

#pragma warning( pop )

#endif

#endif


#define MAXIMUM_SUPPORTED_EXTENSION     512

#if !defined(__midl) && !defined(MIDL_PASS)

C_ASSERT(sizeof(XSAVE_FORMAT) == MAXIMUM_SUPPORTED_EXTENSION);

#endif

#endif // _X86_

#ifdef _AMD64_


#if defined(_M_AMD64) && !defined(RC_INVOKED) && !defined(MIDL_PASS)

//
// Define bit test intrinsics.
//

#ifdef __cplusplus
extern "C" {
#endif

#define BitTest _bittest
#define BitTestAndComplement _bittestandcomplement
#define BitTestAndSet _bittestandset
#define BitTestAndReset _bittestandreset
#define InterlockedBitTestAndSet _interlockedbittestandset
#define InterlockedBitTestAndReset _interlockedbittestandreset

#define BitTest64 _bittest64
#define BitTestAndComplement64 _bittestandcomplement64
#define BitTestAndSet64 _bittestandset64
#define BitTestAndReset64 _bittestandreset64
#define InterlockedBitTestAndSet64 _interlockedbittestandset64
#define InterlockedBitTestAndReset64 _interlockedbittestandreset64

__checkReturn
BOOLEAN
_bittest (
    __in_bcount((Offset+7)/8) LONG const *Base,
    __in LONG Offset
    );

BOOLEAN
_bittestandcomplement (
    __inout_bcount((Offset+7)/8) LONG *Base,
    __in LONG Offset
    );

BOOLEAN
_bittestandset (
    __inout_bcount((Offset+7)/8) LONG *Base,
    __in LONG Offset
    );

BOOLEAN
_bittestandreset (
    __inout_bcount((Offset+7)/8) LONG *Base,
    __in LONG Offset
    );

BOOLEAN
_interlockedbittestandset (
    __inout_bcount((Offset+7)/8) __drv_interlocked LONG volatile *Base,
    __in LONG Offset
    );

BOOLEAN
_interlockedbittestandreset (
    __inout_bcount((Offset+7)/8) __drv_interlocked LONG volatile *Base,
    __in LONG Offset
    );

BOOLEAN
_bittest64 (
    __in_bcount((Offset+7)/8) LONG64 const *Base,
    __in LONG64 Offset
    );

BOOLEAN
_bittestandcomplement64 (
    __inout_bcount((Offset+7)/8) LONG64 *Base,
    __in LONG64 Offset
    );

BOOLEAN
_bittestandset64 (
    __inout_bcount((Offset+7)/8) LONG64 *Base,
    __in LONG64 Offset
    );

BOOLEAN
_bittestandreset64 (
    __inout_bcount((Offset+7)/8) LONG64 *Base,
    __in LONG64 Offset
    );

BOOLEAN
_interlockedbittestandset64 (
    __inout_bcount((Offset+7)/8) __drv_interlocked LONG64 volatile *Base,
    __in LONG64 Offset
    );

BOOLEAN
_interlockedbittestandreset64 (
    __inout_bcount((Offset+7)/8) __drv_interlocked LONG64 volatile *Base,
    __in LONG64 Offset
    );

#pragma intrinsic(_bittest)
#pragma intrinsic(_bittestandcomplement)
#pragma intrinsic(_bittestandset)
#pragma intrinsic(_bittestandreset)
#pragma intrinsic(_interlockedbittestandset)
#pragma intrinsic(_interlockedbittestandreset)

#pragma intrinsic(_bittest64)
#pragma intrinsic(_bittestandcomplement64)
#pragma intrinsic(_bittestandset64)
#pragma intrinsic(_bittestandreset64)
#pragma intrinsic(_interlockedbittestandset64)
#pragma intrinsic(_interlockedbittestandreset64)

//
// Define bit scan intrinsics.
//

#define BitScanForward _BitScanForward
#define BitScanReverse _BitScanReverse
#define BitScanForward64 _BitScanForward64
#define BitScanReverse64 _BitScanReverse64

__success(return!=0)
BOOLEAN
_BitScanForward (
    __out ULONG *Index,
    __in ULONG Mask
    );

__success(return!=0)
BOOLEAN
_BitScanReverse (
    __out ULONG *Index,
    __in ULONG Mask
    );

__success(return!=0)
BOOLEAN
_BitScanForward64 (
    __out ULONG *Index,
    __in ULONG64 Mask
    );

__success(return!=0)
BOOLEAN
_BitScanReverse64 (
    __out ULONG *Index,
    __in ULONG64 Mask
    );

#pragma intrinsic(_BitScanForward)
#pragma intrinsic(_BitScanReverse)
#pragma intrinsic(_BitScanForward64)
#pragma intrinsic(_BitScanReverse64)

//
// Interlocked intrinsic functions.
//

#define InterlockedIncrement16 _InterlockedIncrement16
#define InterlockedDecrement16 _InterlockedDecrement16
#define InterlockedCompareExchange16 _InterlockedCompareExchange16

#define InterlockedAnd _InterlockedAnd
#define InterlockedAndAcquire _InterlockedAnd
#define InterlockedAndRelease _InterlockedAnd
#define InterlockedOr _InterlockedOr
#define InterlockedOrAcquire _InterlockedOr
#define InterlockedOrRelease _InterlockedOr
#define InterlockedXor _InterlockedXor
#define InterlockedIncrement _InterlockedIncrement
#define InterlockedIncrementAcquire InterlockedIncrement
#define InterlockedIncrementRelease InterlockedIncrement
#define InterlockedDecrement _InterlockedDecrement
#define InterlockedDecrementAcquire InterlockedDecrement
#define InterlockedDecrementRelease InterlockedDecrement
#define InterlockedAdd _InterlockedAdd
#define InterlockedExchange _InterlockedExchange
#define InterlockedExchangeAdd _InterlockedExchangeAdd
#define InterlockedCompareExchange _InterlockedCompareExchange
#define InterlockedCompareExchangeAcquire InterlockedCompareExchange
#define InterlockedCompareExchangeRelease InterlockedCompareExchange

#define InterlockedAnd64 _InterlockedAnd64
#define InterlockedAnd64Acquire _InterlockedAnd64
#define InterlockedAnd64Release _InterlockedAnd64
#define InterlockedAndAffinity InterlockedAnd64
#define InterlockedOr64 _InterlockedOr64
#define InterlockedOr64Acquire _InterlockedOr64
#define InterlockedOr64Release _InterlockedOr64
#define InterlockedOrAffinity InterlockedOr64
#define InterlockedXor64 _InterlockedXor64
#define InterlockedIncrement64 _InterlockedIncrement64
#define InterlockedDecrement64 _InterlockedDecrement64
#define InterlockedAdd64 _InterlockedAdd64
#define InterlockedExchange64 _InterlockedExchange64
#define InterlockedExchangeAcquire64 InterlockedExchange64
#define InterlockedExchangeAdd64 _InterlockedExchangeAdd64
#define InterlockedCompareExchange64 _InterlockedCompareExchange64
#define InterlockedCompareExchangeAcquire64 InterlockedCompareExchange64
#define InterlockedCompareExchangeRelease64 InterlockedCompareExchange64

#define InterlockedExchangePointer _InterlockedExchangePointer
#define InterlockedCompareExchangePointer _InterlockedCompareExchangePointer
#define InterlockedCompareExchangePointerAcquire _InterlockedCompareExchangePointer
#define InterlockedCompareExchangePointerRelease _InterlockedCompareExchangePointer

#define InterlockedExchangeAddSizeT(a, b) InterlockedExchangeAdd64((LONG64 *)a, b)
#define InterlockedIncrementSizeT(a) InterlockedIncrement64((LONG64 *)a)
#define InterlockedDecrementSizeT(a) InterlockedDecrement64((LONG64 *)a)

SHORT
InterlockedIncrement16 (
    __inout __drv_interlocked SHORT volatile *Addend
    );

SHORT
InterlockedDecrement16 (
    __inout __drv_interlocked SHORT volatile *Addend
    );

SHORT
InterlockedCompareExchange16 (
    __inout __drv_interlocked SHORT volatile *Destination,
    __in SHORT ExChange,
    __in SHORT Comperand
    );

LONG
InterlockedAnd (
    __inout __drv_interlocked LONG volatile *Destination,
    __in LONG Value
    );

LONG
InterlockedOr (
    __inout __drv_interlocked LONG volatile *Destination,
    __in LONG Value
    );

LONG
InterlockedXor (
    __inout __drv_interlocked LONG volatile *Destination,
    __in LONG Value
    );

LONG64
InterlockedAnd64 (
    __inout __drv_interlocked LONG64 volatile *Destination,
    __in LONG64 Value
    );

LONG64
InterlockedOr64 (
    __inout __drv_interlocked LONG64 volatile *Destination,
    __in LONG64 Value
    );

LONG64
InterlockedXor64 (
    __inout __drv_interlocked LONG64 volatile *Destination,
    __in LONG64 Value
    );

LONG
InterlockedIncrement(
    __inout __drv_interlocked LONG volatile *Addend
    );

LONG
InterlockedDecrement(
    __inout __drv_interlocked LONG volatile *Addend
    );

LONG
InterlockedExchange(
    __inout __drv_interlocked LONG volatile *Target,
    __in LONG Value
    );

LONG
InterlockedExchangeAdd(
    __inout __drv_interlocked LONG volatile *Addend,
    __in LONG Value
    );

#if !defined(_X86AMD64_)

__forceinline
LONG
InterlockedAdd(
    __inout __drv_interlocked LONG volatile *Addend,
    __in LONG Value
    )

{
    return InterlockedExchangeAdd(Addend, Value) + Value;
}

#endif

LONG
InterlockedCompareExchange (
    __inout __drv_interlocked LONG volatile *Destination,
    __in LONG ExChange,
    __in LONG Comperand
    );

LONG64
InterlockedIncrement64(
    __inout __drv_interlocked LONG64 volatile *Addend
    );

LONG64
InterlockedDecrement64(
    __inout __drv_interlocked LONG64 volatile *Addend
    );

LONG64
InterlockedExchange64(
    __inout __drv_interlocked LONG64 volatile *Target,
    __in LONG64 Value
    );

LONG64
InterlockedExchangeAdd64(
    __inout __drv_interlocked LONG64 volatile *Addend,
    __in LONG64 Value
    );

#if !defined(_X86AMD64_)

__forceinline
LONG64
InterlockedAdd64(
    __inout __drv_interlocked LONG64 volatile *Addend,
    __in LONG64 Value
    )

{
    return InterlockedExchangeAdd64(Addend, Value) + Value;
}

#endif

LONG64
InterlockedCompareExchange64 (
    __inout __drv_interlocked LONG64 volatile *Destination,
    __in LONG64 ExChange,
    __in LONG64 Comperand
    );

PVOID
InterlockedCompareExchangePointer (
    __inout __drv_interlocked PVOID volatile *Destination,
    __in_opt PVOID Exchange,
    __in_opt PVOID Comperand
    );

PVOID
InterlockedExchangePointer(
    __inout __drv_interlocked PVOID volatile *Target,
    __in_opt PVOID Value
    );

#pragma intrinsic(_InterlockedIncrement16)
#pragma intrinsic(_InterlockedDecrement16)
#pragma intrinsic(_InterlockedCompareExchange16)
#pragma intrinsic(_InterlockedAnd)
#pragma intrinsic(_InterlockedOr)
#pragma intrinsic(_InterlockedXor)
#pragma intrinsic(_InterlockedIncrement)
#pragma intrinsic(_InterlockedDecrement)
#pragma intrinsic(_InterlockedExchange)
#pragma intrinsic(_InterlockedExchangeAdd)
#pragma intrinsic(_InterlockedCompareExchange)
#pragma intrinsic(_InterlockedAnd64)
#pragma intrinsic(_InterlockedOr64)
#pragma intrinsic(_InterlockedXor64)
#pragma intrinsic(_InterlockedIncrement64)
#pragma intrinsic(_InterlockedDecrement64)
#pragma intrinsic(_InterlockedExchange64)
#pragma intrinsic(_InterlockedExchangeAdd64)
#pragma intrinsic(_InterlockedCompareExchange64)
#pragma intrinsic(_InterlockedExchangePointer)
#pragma intrinsic(_InterlockedCompareExchangePointer)

#if _MSC_FULL_VER >= 140041204

#define InterlockedAnd8 _InterlockedAnd8
#define InterlockedOr8 _InterlockedOr8
#define InterlockedXor8 _InterlockedXor8
#define InterlockedAnd16 _InterlockedAnd16
#define InterlockedOr16 _InterlockedOr16
#define InterlockedXor16 _InterlockedXor16

char
InterlockedAnd8 (
    __inout __drv_interlocked char volatile *Destination,
    __in char Value
    );

char
InterlockedOr8 (
    __inout __drv_interlocked char volatile *Destination,
    __in char Value
    );

char
InterlockedXor8 (
    __inout __drv_interlocked char volatile *Destination,
    __in char Value
    );

SHORT
InterlockedAnd16(
    __inout __drv_interlocked SHORT volatile *Destination,
    __in SHORT Value
    );

SHORT
InterlockedOr16(
    __inout __drv_interlocked SHORT volatile *Destination,
    __in SHORT Value
    );

SHORT
InterlockedXor16(
    __inout __drv_interlocked SHORT volatile *Destination,
    __in SHORT Value
    );

#pragma intrinsic (_InterlockedAnd8)
#pragma intrinsic (_InterlockedOr8)
#pragma intrinsic (_InterlockedXor8)
#pragma intrinsic (_InterlockedAnd16)
#pragma intrinsic (_InterlockedOr16)
#pragma intrinsic (_InterlockedXor16)

#endif

//
// Define function to flush a cache line.
//

#define CacheLineFlush(Address) _mm_clflush(Address)

VOID
_mm_clflush (
    __in VOID const *Address
    );

#pragma intrinsic(_mm_clflush)

VOID
_ReadWriteBarrier (
    VOID
    );

#pragma intrinsic(_ReadWriteBarrier)

//
// Define memory fence intrinsics
//

#define FastFence __faststorefence
#define LoadFence _mm_lfence
#define MemoryFence _mm_mfence
#define StoreFence _mm_sfence

VOID
__faststorefence (
    VOID
    );

VOID
_mm_lfence (
    VOID
    );

VOID
_mm_mfence (
    VOID
    );

VOID
_mm_sfence (
    VOID
    );

VOID
_mm_pause (
    VOID
    );

VOID
_mm_prefetch (
    __in CHAR CONST *a,
    __in int sel
    );

VOID
_m_prefetchw (
    __in volatile CONST VOID *Source
    );

//
// Define constants for use with _mm_prefetch.
//

#define _MM_HINT_T0     1
#define _MM_HINT_T1     2
#define _MM_HINT_T2     3
#define _MM_HINT_NTA    0

#pragma intrinsic(__faststorefence)
#pragma intrinsic(_mm_pause)
#pragma intrinsic(_mm_prefetch)
#pragma intrinsic(_mm_lfence)
#pragma intrinsic(_mm_mfence)
#pragma intrinsic(_mm_sfence)
#pragma intrinsic(_m_prefetchw)

#define YieldProcessor _mm_pause
#define MemoryBarrier __faststorefence
#define PreFetchCacheLine(l, a)  _mm_prefetch((CHAR CONST *) a, l)
#define PrefetchForWrite(p) _m_prefetchw(p)
#define ReadForWriteAccess(p) (_m_prefetchw(p), *(p))

//
// PreFetchCacheLine level defines.
//

#define PF_TEMPORAL_LEVEL_1 _MM_HINT_T0
#define PF_TEMPORAL_LEVEL_2 _MM_HINT_T1
#define PF_TEMPORAL_LEVEL_3 _MM_HINT_T2
#define PF_NON_TEMPORAL_LEVEL_ALL _MM_HINT_NTA

//
// Define get/set MXCSR intrinsics.
//

#define ReadMxCsr _mm_getcsr
#define WriteMxCsr _mm_setcsr

unsigned int
_mm_getcsr (
    VOID
    );

VOID
_mm_setcsr (
    __in unsigned int MxCsr
    );

#pragma intrinsic(_mm_getcsr)
#pragma intrinsic(_mm_setcsr)

//
// Assert exception.
//

VOID
__int2c (
    VOID
    );

#pragma intrinsic(__int2c)

__analysis_noreturn
FORCEINLINE
VOID
DbgRaiseAssertionFailure (
    VOID
    )

{
    __int2c();
}

//
// Define function to get the caller's EFLAGs value.
//

#define GetCallersEflags() __getcallerseflags()

unsigned __int32
__getcallerseflags (
    VOID
    );

#pragma intrinsic(__getcallerseflags)

//
// Define function to get segment limit.
//

#define GetSegmentLimit __segmentlimit

ULONG
__segmentlimit (
    __in ULONG Selector
    );

#pragma intrinsic(__segmentlimit)

//
// Define function to read the value of a performance counter.
//

#define ReadPMC __readpmc

ULONG64
__readpmc (
    __in ULONG Counter
    );

#pragma intrinsic(__readpmc)

//
// Define function to read the value of the time stamp counter
//

#define ReadTimeStampCounter() __rdtsc()

ULONG64
__rdtsc (
    VOID
    );

#pragma intrinsic(__rdtsc)

//
// Define functions to move strings as bytes, words, dwords, and qwords.
//

VOID
__movsb (
    __out_ecount_full(Count) PUCHAR Destination,
    __in_ecount(Count) UCHAR const *Source,
    __in SIZE_T Count
    );

VOID
__movsw (
    __out_ecount_full(Count) PUSHORT Destination,
    __in_ecount(Count) USHORT const *Source,
    __in SIZE_T Count
    );

VOID
__movsd (
    __out_ecount_full(Count) PULONG Destination,
    __in_ecount(Count) ULONG const *Source,
    __in SIZE_T Count
    );

VOID
__movsq (
    __out_ecount_full(Count) PULONG64 Destination,
    __in_ecount(Count) ULONG64 const *Source,
    __in SIZE_T Count
    );

#pragma intrinsic(__movsb)
#pragma intrinsic(__movsw)
#pragma intrinsic(__movsd)
#pragma intrinsic(__movsq)

//
// Define functions to store strings as bytes, words, dwords, and qwords.
//

VOID
__stosb (
    __out_ecount_full(Count) PUCHAR Destination,
    __in UCHAR Value,
    __in SIZE_T Count
    );

VOID
__stosw (
    __out_ecount_full(Count) PUSHORT Destination,
    __in USHORT Value,
    __in SIZE_T Count
    );

VOID
__stosd (
    __out_ecount_full(Count) PULONG Destination,
    __in ULONG Value,
    __in SIZE_T Count
    );

VOID
__stosq (
    __out_ecount_full(Count) PULONG64 Destination,
    __in ULONG64 Value,
    __in SIZE_T Count
    );

#pragma intrinsic(__stosb)
#pragma intrinsic(__stosw)
#pragma intrinsic(__stosd)
#pragma intrinsic(__stosq)

//
// Define functions to capture the high 64-bits of a 128-bit multiply.
//

#define MultiplyHigh __mulh
#define UnsignedMultiplyHigh __umulh

LONGLONG
MultiplyHigh (
    __in LONG64 Multiplier,
    __in LONG64 Multiplicand
    );

ULONGLONG
UnsignedMultiplyHigh (
    __in ULONG64 Multiplier,
    __in ULONG64 Multiplicand
    );

#pragma intrinsic(__mulh)
#pragma intrinsic(__umulh)

//
// Define functions to perform 128-bit shifts
//

#define ShiftLeft128 __shiftleft128
#define ShiftRight128 __shiftright128

ULONG64
ShiftLeft128 (
    __in ULONG64 LowPart,
    __in ULONG64 HighPart,
    __in UCHAR Shift
    );

ULONG64
ShiftRight128 (
    __in ULONG64 LowPart,
    __in ULONG64 HighPart,
    __in UCHAR Shift
    );

#pragma intrinsic(__shiftleft128)
#pragma intrinsic(__shiftright128)

//
// Define functions to perform 128-bit multiplies.
//

#define Multiply128 _mul128

LONG64
Multiply128 (
    __in LONG64 Multiplier,
    __in LONG64 Multiplicand,
    __out LONG64 *HighProduct
    );

#pragma intrinsic(_mul128)

#ifndef UnsignedMultiply128

#define UnsignedMultiply128 _umul128

ULONG64
UnsignedMultiply128 (
    __in ULONG64 Multiplier,
    __in ULONG64 Multiplicand,
    __out ULONG64 *HighProduct
    );

#pragma intrinsic(_umul128)

#endif

__forceinline
LONG64
MultiplyExtract128 (
    __in LONG64 Multiplier,
    __in LONG64 Multiplicand,
    __in UCHAR Shift
    )

{

    LONG64 extractedProduct;
    LONG64 highProduct;
    LONG64 lowProduct;
    BOOLEAN negate;
    ULONG64 uhighProduct;
    ULONG64 ulowProduct;

    lowProduct = Multiply128(Multiplier, Multiplicand, &highProduct);
    negate = FALSE;
    uhighProduct = (ULONG64)highProduct;
    ulowProduct = (ULONG64)lowProduct;
    if (highProduct < 0) {
        negate = TRUE;
        uhighProduct = (ULONG64)(-highProduct);
        ulowProduct = (ULONG64)(-lowProduct);
        if (ulowProduct != 0) {
            uhighProduct -= 1;
        }
    }

    extractedProduct = (LONG64)ShiftRight128(ulowProduct, uhighProduct, Shift);
    if (negate != FALSE) {
        extractedProduct = -extractedProduct;
    }

    return extractedProduct;
}

__forceinline
ULONG64
UnsignedMultiplyExtract128 (
    __in ULONG64 Multiplier,
    __in ULONG64 Multiplicand,
    __in UCHAR Shift
    )

{

    ULONG64 extractedProduct;
    ULONG64 highProduct;
    ULONG64 lowProduct;

    lowProduct = UnsignedMultiply128(Multiplier, Multiplicand, &highProduct);
    extractedProduct = ShiftRight128(lowProduct, highProduct, Shift);
    return extractedProduct;
}

//
// Define functions to read and write the uer TEB and the system PCR/PRCB.
//

UCHAR
__readgsbyte (
    __in ULONG Offset
    );

USHORT
__readgsword (
    __in ULONG Offset
    );

ULONG
__readgsdword (
    __in ULONG Offset
    );

ULONG64
__readgsqword (
    __in ULONG Offset
    );

VOID
__writegsbyte (
    __in ULONG Offset,
    __in UCHAR Data
    );

VOID
__writegsword (
    __in ULONG Offset,
    __in USHORT Data
    );

VOID
__writegsdword (
    __in ULONG Offset,
    __in ULONG Data
    );

VOID
__writegsqword (
    __in ULONG Offset,
    __in ULONG64 Data
    );

#pragma intrinsic(__readgsbyte)
#pragma intrinsic(__readgsword)
#pragma intrinsic(__readgsdword)
#pragma intrinsic(__readgsqword)
#pragma intrinsic(__writegsbyte)
#pragma intrinsic(__writegsword)
#pragma intrinsic(__writegsdword)
#pragma intrinsic(__writegsqword)

#if !defined(_MANAGED)

VOID
__incgsbyte (
    __in ULONG Offset
    );

VOID
__addgsbyte (
    __in ULONG Offset,
    __in UCHAR Value
    );

VOID
__incgsword (
    __in ULONG Offset
    );

VOID
__addgsword (
    __in ULONG Offset,
    __in USHORT Value
    );

VOID
__incgsdword (
    __in ULONG Offset
    );

VOID
__addgsdword (
    __in ULONG Offset,
    __in ULONG Value
    );

VOID
__incgsqword (
    __in ULONG Offset
    );

VOID
__addgsqword (
    __in ULONG Offset,
    __in ULONG64 Value
    );

#if 0
#pragma intrinsic(__incgsbyte)
#pragma intrinsic(__addgsbyte)
#pragma intrinsic(__incgsword)
#pragma intrinsic(__addgsword)
#pragma intrinsic(__incgsdword)
#pragma intrinsic(__addgsdword)
#pragma intrinsic(__incgsqword)
#pragma intrinsic(__addgsqword)
#endif

#endif

#ifdef __cplusplus
}
#endif

#endif // defined(_M_AMD64) && !defined(RC_INVOKED) && !defined(MIDL_PASS)


typedef XSAVE_FORMAT XMM_SAVE_AREA32, *PXMM_SAVE_AREA32;


#endif // _AMD64_


#ifdef _IA64_


#if defined(_M_IA64) && !defined(RC_INVOKED) && !defined(MIDL_PASS)

#ifdef __cplusplus
extern "C" {
#endif

//
// Define bit test intrinsics.
//

#define BitTest _bittest
#define BitTestAndComplement _bittestandcomplement
#define BitTestAndSet _bittestandset
#define BitTestAndReset _bittestandreset

#define BitTest64 _bittest64
#define BitTestAndComplement64 _bittestandcomplement64
#define BitTestAndSet64 _bittestandset64
#define BitTestAndReset64 _bittestandreset64

__checkReturn
BOOLEAN
_bittest (
    __in_bcount((Offset+7)/8) LONG const *Base,
    __in LONG Offset
    );

BOOLEAN
_bittestandcomplement (
    __inout_bcount((Offset+7)/8) LONG *Base,
    __in LONG Offset
    );

BOOLEAN
_bittestandset (
    __inout_bcount((Offset+7)/8) LONG *Base,
    __in LONG Offset
    );

BOOLEAN
_bittestandreset (
    __inout_bcount((Offset+7)/8) LONG *Base,
    __in LONG Offset
    );

__checkReturn
BOOLEAN
_bittest64 (
    __in_bcount((Offset+7)/8) LONG64 const *Base,
    __in LONG64 Offset
    );

BOOLEAN
_bittestandcomplement64 (
    __inout_bcount((Offset+7)/8) LONG64 *Base,
    __in LONG64 Offset
    );

BOOLEAN
_bittestandset64 (
    __inout_bcount((Offset+7)/8) LONG64 *Base,
    __in LONG64 Offset
    );

BOOLEAN
_bittestandreset64 (
    __inout_bcount((Offset+7)/8) LONG64 *Base,
    __in LONG64 Offset
    );

#pragma intrinsic(_bittest)
#pragma intrinsic(_bittestandcomplement)
#pragma intrinsic(_bittestandset)
#pragma intrinsic(_bittestandreset)

#pragma intrinsic(_bittest64)
#pragma intrinsic(_bittestandcomplement64)
#pragma intrinsic(_bittestandset64)
#pragma intrinsic(_bittestandreset64)

//
// Define bit scan intrinsics.
//

#define BitScanForward _BitScanForward
#define BitScanReverse _BitScanReverse
#define BitScanForward64 _BitScanForward64
#define BitScanReverse64 _BitScanReverse64

__success(return!=0)
BOOLEAN
_BitScanForward (
    __out ULONG *Index,
    __in ULONG Mask
    );

__success(return!=0)
BOOLEAN
_BitScanReverse (
    __out ULONG *Index,
    __in ULONG Mask
    );

__success(return!=0)
BOOLEAN
_BitScanForward64 (
    __out ULONG *Index,
    __in ULONG64 Mask
    );

__success(return!=0)
BOOLEAN
_BitScanReverse64 (
    __out ULONG *Index,
    __in ULONG64 Mask
    );

#pragma intrinsic(_BitScanForward)
#pragma intrinsic(_BitScanReverse)
#pragma intrinsic(_BitScanForward64)
#pragma intrinsic(_BitScanReverse64)

#define InterlockedCompareExchange16 _InterlockedCompareExchange16

SHORT
_InterlockedCompareExchange16 (
    __inout __drv_interlocked SHORT volatile *Destination,
    __in SHORT ExChange,
    __in SHORT Comperand
    );

#pragma intrinsic(_InterlockedCompareExchange16)

#ifdef __cplusplus
}
#endif

#define InterlockedAdd                  _InterlockedAdd
#define InterlockedAddAcquire           _InterlockedAdd_acq
#define InterlockedAddRelease           _InterlockedAdd_rel

#define InterlockedIncrement            _InterlockedIncrement
#define InterlockedIncrementAcquire     _InterlockedIncrement_acq
#define InterlockedIncrementRelease     _InterlockedIncrement_rel

#define InterlockedDecrement            _InterlockedDecrement
#define InterlockedDecrementAcquire     _InterlockedDecrement_acq
#define InterlockedDecrementRelease     _InterlockedDecrement_rel

#define InterlockedExchange             _InterlockedExchange
#define InterlockedExchangeAcquire      _InterlockedExchange_acq

#define InterlockedExchangeAdd          _InterlockedExchangeAdd
#define InterlockedExchangeAddAcquire   _InterlockedExchangeAdd_acq
#define InterlockedExchangeAddRelease   _InterlockedExchangeAdd_rel

#define InterlockedAdd64                _InterlockedAdd64
#define InterlockedAddAcquire64         _InterlockedAdd64_acq
#define InterlockedAddRelease64         _InterlockedAdd64_rel

#define InterlockedIncrement64          _InterlockedIncrement64
#define InterlockedIncrementAcquire64   _InterlockedIncrement64_acq
#define InterlockedIncrementRelease64   _InterlockedIncrement64_rel

#define InterlockedDecrement64          _InterlockedDecrement64
#define InterlockedDecrementAcquire64   _InterlockedDecrement64_acq
#define InterlockedDecrementRelease64   _InterlockedDecrement64_rel

#define InterlockedExchange64           _InterlockedExchange64
#define InterlockedExchangeAcquire64    _InterlockedExchange64_acq

#define InterlockedExchangeAdd64        _InterlockedExchangeAdd64
#define InterlockedExchangeAddAcquire64 _InterlockedExchangeAdd64_acq
#define InterlockedExchangeAddRelease64 _InterlockedExchangeAdd64_rel

#define InterlockedCompareExchange64        _InterlockedCompareExchange64
#define InterlockedCompareExchangeAcquire64 _InterlockedCompareExchange64_acq
#define InterlockedCompareExchangeRelease64 _InterlockedCompareExchange64_rel

#define InterlockedCompare64Exchange128         _InterlockedCompare64Exchange128
#define InterlockedCompare64ExchangeAcquire128  _InterlockedCompare64Exchange128_acq
#define InterlockedCompare64ExchangeRelease128  _InterlockedCompare64Exchange128_rel

#define InterlockedCompareExchange          _InterlockedCompareExchange
#define InterlockedCompareExchangeAcquire   _InterlockedCompareExchange_acq
#define InterlockedCompareExchangeRelease   _InterlockedCompareExchange_rel

#define InterlockedExchangePointer          _InterlockedExchangePointer
#define InterlockedExchangePointerAcquire   _InterlockedExchangePointer_acq

#define InterlockedCompareExchangePointer           _InterlockedCompareExchangePointer
#define InterlockedCompareExchangePointerRelease    _InterlockedCompareExchangePointer_rel
#define InterlockedCompareExchangePointerAcquire    _InterlockedCompareExchangePointer_acq


#define InterlockedExchangeAddSizeT(a, b) InterlockedExchangeAdd64((LONG64 *)a, b)
#define InterlockedIncrementSizeT(a) InterlockedIncrement64((LONG64 *)a)
#define InterlockedDecrementSizeT(a) InterlockedDecrement64((LONG64 *)a)

#define InterlockedOr       _InterlockedOr
#define InterlockedOrAcquire   _InterlockedOr_acq
#define InterlockedOrRelease   _InterlockedOr_rel
#define InterlockedOr8      _InterlockedOr8
#define InterlockedOr8Acquire  _InterlockedOr8_acq
#define InterlockedOr8Release  _InterlockedOr8_rel
#define InterlockedOr16     _InterlockedOr16
#define InterlockedOr16Acquire _InterlockedOr16_acq
#define InterlockedOr16Release _InterlockedOr16_rel
#define InterlockedOr64     _InterlockedOr64
#define InterlockedOr64Acquire _InterlockedOr64_acq
#define InterlockedOr64Release _InterlockedOr64_rel
#define InterlockedXor      _InterlockedXor
#define InterlockedXorAcquire  _InterlockedXor_acq
#define InterlockedXorRelease  _InterlockedXor_rel
#define InterlockedXor8     _InterlockedXor8
#define InterlockedXor8Acquire _InterlockedXor8_acq
#define InterlockedXor8Release _InterlockedXor8_rel
#define InterlockedXor16    _InterlockedXor16
#define InterlockedXor16Acquire _InterlockedXor16_acq
#define InterlockedXor16Release _InterlockedXor16_rel
#define InterlockedXor64     _InterlockedXor64
#define InterlockedXor64Acquire _InterlockedXor64_acq
#define InterlockedXor64Release _InterlockedXor64_rel
#define InterlockedAnd       _InterlockedAnd
#define InterlockedAndAcquire   _InterlockedAnd_acq
#define InterlockedAndRelease   _InterlockedAnd_rel
#define InterlockedAnd8      _InterlockedAnd8
#define InterlockedAnd8Acquire  _InterlockedAnd8_acq
#define InterlockedAnd8Release  _InterlockedAnd8_rel
#define InterlockedAnd16     _InterlockedAnd16
#define InterlockedAnd16Acquire _InterlockedAnd16_acq
#define InterlockedAnd16Release _InterlockedAnd16_rel
#define InterlockedAnd64     _InterlockedAnd64
#define InterlockedAnd64Acquire _InterlockedAnd64_acq
#define InterlockedAnd64Release _InterlockedAnd64_rel

#ifdef __cplusplus
extern "C" {
#endif

LONG
__cdecl
InterlockedAdd (
    __inout __drv_interlocked LONG volatile *Addend,
    __in LONG Value
    );

LONG
__cdecl
InterlockedAddAcquire (
    __inout __drv_interlocked LONG volatile *Addend,
    __in LONG Value
    );

LONG
__cdecl
InterlockedAddRelease (
    __inout __drv_interlocked LONG volatile *Addend,
    __in LONG Value
    );

LONGLONG
__cdecl
InterlockedAdd64 (
    __inout __drv_interlocked LONGLONG volatile *Addend,
    __in LONGLONG Value
    );

LONGLONG
__cdecl
InterlockedAddAcquire64 (
    __inout __drv_interlocked LONGLONG volatile *Addend,
    __in LONGLONG Value
    );


LONGLONG
__cdecl
InterlockedAddRelease64 (
    __inout __drv_interlocked LONGLONG volatile *Addend,
    __in LONGLONG Value
    );

LONG
__cdecl
InterlockedIncrement(
    __inout __drv_interlocked LONG volatile *Addend
    );

LONG
__cdecl
InterlockedDecrement(
    __inout __drv_interlocked LONG volatile *Addend
    );

LONG
__cdecl
InterlockedIncrementAcquire(
    __inout __drv_interlocked LONG volatile *Addend
    );

LONG
__cdecl
InterlockedDecrementAcquire(
    __inout __drv_interlocked LONG volatile *Addend
    );

LONG
__cdecl
InterlockedIncrementRelease(
    __inout __drv_interlocked LONG volatile *Addend
    );

LONG
__cdecl
InterlockedDecrementRelease(
    __inout __drv_interlocked LONG volatile *Addend
    );

LONG
__cdecl
InterlockedExchange(
    __inout __drv_interlocked LONG volatile *Target,
    __in LONG Value
    );

LONG
__cdecl
InterlockedExchangeAcquire(
    __inout __drv_interlocked LONG volatile *Target,
    __in LONG Value
    );

LONG
__cdecl
InterlockedExchangeAdd(
    __inout __drv_interlocked LONG volatile *Addend,
    __in LONG Value
    );

LONG
__cdecl
InterlockedExchangeAddAcquire(
    __inout __drv_interlocked LONG volatile *Addend,
    __in LONG Value
    );

LONG
__cdecl
InterlockedExchangeAddRelease(
    __inout __drv_interlocked LONG volatile *Addend,
    __in LONG Value
    );

LONG
__cdecl
InterlockedCompareExchange (
    __inout __drv_interlocked LONG volatile *Destination,
    __in LONG ExChange,
    __in LONG Comperand
    );


LONG
__cdecl
InterlockedCompareExchangeRelease (
    __inout __drv_interlocked LONG volatile *Destination,
    __in LONG ExChange,
    __in LONG Comperand
    );


LONG
__cdecl
InterlockedCompareExchangeAcquire (
    __inout __drv_interlocked LONG volatile *Destination,
    __in LONG ExChange,
    __in LONG Comperand
    );


LONGLONG
__cdecl
InterlockedIncrement64(
    __inout __drv_interlocked LONGLONG volatile *Addend
    );

LONGLONG
__cdecl
InterlockedIncrementAcquire64(
    __inout __drv_interlocked LONGLONG volatile *Addend
    );

LONGLONG
__cdecl
InterlockedIncrementRelease64(
    __inout __drv_interlocked LONGLONG volatile *Addend
    );

LONGLONG
__cdecl
InterlockedDecrement64(
    __inout __drv_interlocked LONGLONG volatile *Addend
    );

LONGLONG
__cdecl
InterlockedDecrementAcquire64(
    __inout __drv_interlocked LONGLONG volatile *Addend
    );

LONGLONG
__cdecl
InterlockedDecrementRelease64(
    __inout __drv_interlocked LONGLONG volatile *Addend
    );

LONGLONG
__cdecl
InterlockedExchange64(
    __inout __drv_interlocked LONGLONG volatile *Target,
    __in LONGLONG Value
    );

LONGLONG
__cdecl
InterlockedExchangeAcquire64(
    __inout __drv_interlocked LONGLONG volatile *Target,
    __in LONGLONG Value
    );

LONGLONG
__cdecl
InterlockedExchangeAdd64(
    __inout __drv_interlocked LONGLONG volatile *Addend,
    __in LONGLONG Value
    );

LONGLONG
__cdecl
InterlockedExchangeAddAcquire64(
    __inout __drv_interlocked LONGLONG volatile *Addend,
    __in LONGLONG Value
    );

LONGLONG
__cdecl
InterlockedExchangeAddRelease64(
    __inout __drv_interlocked LONGLONG volatile *Addend,
    __in LONGLONG Value
    );

LONGLONG
__cdecl
InterlockedCompareExchange64 (
    __inout __drv_interlocked LONGLONG volatile *Destination,
    __in LONGLONG ExChange,
    __in LONGLONG Comperand
    );

LONGLONG
__cdecl
InterlockedCompareExchangeAcquire64 (
    __inout __drv_interlocked LONGLONG volatile *Destination,
    __in LONGLONG ExChange,
    __in LONGLONG Comperand
    );

LONGLONG
__cdecl
InterlockedCompareExchangeRelease64 (
    __inout __drv_interlocked LONGLONG volatile *Destination,
    __in LONGLONG ExChange,
    __in LONGLONG Comperand
    );

LONG64
__cdecl
InterlockedCompare64Exchange128(
    __inout_bcount(16) __drv_interlocked LONG64 volatile *Destination,
    __in LONG64 ExchangeHigh,
    __in LONG64 ExchangeLow,
    __in LONG64 Comperand
    );

LONG64
__cdecl
InterlockedCompare64ExchangeAcquire128(
    __inout_bcount(16) __drv_interlocked LONG64 volatile *Destination,
    __in LONG64 ExchangeHigh,
    __in LONG64 ExchangeLow,
    __in LONG64 Comperand
    );

LONG64
__cdecl
InterlockedCompare64ExchangeRelease128(
    __inout_bcount(16) __drv_interlocked LONG64 volatile *Destination,
    __in LONG64 ExchangeHigh,
    __in LONG64 ExchangeLow,
    __in LONG64 Comperand
    );

PVOID
__cdecl
InterlockedCompareExchangePointer (
    __inout __drv_interlocked PVOID volatile *Destination,
    __in PVOID Exchange,
    __in PVOID Comperand
    );

PVOID
__cdecl
InterlockedCompareExchangePointerAcquire (
    __inout __drv_interlocked PVOID volatile *Destination,
    __in PVOID Exchange,
    __in PVOID Comperand
    );

PVOID
__cdecl
InterlockedCompareExchangePointerRelease (
    __inout __drv_interlocked PVOID volatile *Destination,
    __in PVOID Exchange,
    __in PVOID Comperand
    );

PVOID
__cdecl
InterlockedExchangePointer(
    __inout __drv_interlocked PVOID volatile *Target,
    __in PVOID Value
    );

PVOID
__cdecl
InterlockedExchangePointerAcquire(
    __inout __drv_interlocked PVOID volatile *Target,
    __in PVOID Value
    );

LONG
__cdecl
InterlockedOr (
    __inout __drv_interlocked LONG volatile *Destination,
    __in LONG Value
    );

LONG
__cdecl
InterlockedOrAcquire (
    __inout __drv_interlocked LONG volatile *Destination,
    __in LONG Value
    );

LONG
__cdecl
InterlockedOrRelease (
    __inout __drv_interlocked LONG volatile *Destination,
    __in LONG Value
    );

CHAR
__cdecl
InterlockedOr8 (
    __inout __drv_interlocked CHAR volatile *Destination,
    __in CHAR Value
    );

CHAR
__cdecl
InterlockedOr8Acquire (
    __inout __drv_interlocked CHAR volatile *Destination,
    __in CHAR Value
    );

CHAR
__cdecl
InterlockedOr8Release (
    __inout __drv_interlocked CHAR volatile *Destination,
    __in CHAR Value
    );

SHORT
__cdecl
InterlockedOr16(
    __inout __drv_interlocked SHORT volatile *Destination,
    __in SHORT Value
    );

SHORT
__cdecl
InterlockedOr16Acquire (
    __inout __drv_interlocked SHORT volatile *Destination,
    __in SHORT Value
    );

SHORT
__cdecl
InterlockedOr16Release (
    __inout __drv_interlocked SHORT volatile *Destination,
    __in SHORT Value
    );

LONGLONG
__cdecl
InterlockedOr64 (
    __inout __drv_interlocked LONGLONG volatile *Destination,
    __in LONGLONG Value
    );

LONGLONG
__cdecl
InterlockedOr64Acquire (
    __inout __drv_interlocked LONGLONG volatile *Destination,
    __in LONGLONG Value
    );

LONGLONG
__cdecl
InterlockedOr64Release (
    __inout __drv_interlocked LONGLONG volatile *Destination,
    __in LONGLONG Value
    );

LONG
__cdecl
InterlockedXor (
    __inout __drv_interlocked LONG volatile *Destination,
    __in LONG Value
    );

LONG
__cdecl
InterlockedXorAcquire (
    __inout __drv_interlocked LONG volatile *Destination,
    __in LONG Value
    );

LONG
__cdecl
InterlockedXorRelease (
    __inout __drv_interlocked LONG volatile *Destination,
    __in LONG Value
    );

CHAR
__cdecl
InterlockedXor8 (
    __inout __drv_interlocked CHAR volatile *Destination,
    __in CHAR Value
    );

CHAR
__cdecl
InterlockedXor8Acquire (
    __inout __drv_interlocked CHAR volatile *Destination,
    __in CHAR Value
    );

CHAR
__cdecl
InterlockedXor8Release (
    __inout __drv_interlocked CHAR volatile *Destination,
    __in CHAR Value
    );

SHORT
__cdecl
InterlockedXor16(
    __inout __drv_interlocked SHORT volatile *Destination,
    __in SHORT Value
    );

SHORT
__cdecl
InterlockedXor16Acquire (
    __inout __drv_interlocked SHORT volatile *Destination,
    __in SHORT Value
    );

SHORT
__cdecl
InterlockedXor16Release (
    __inout __drv_interlocked SHORT volatile *Destination,
    __in SHORT Value
    );

LONGLONG
__cdecl
InterlockedXor64 (
    __inout __drv_interlocked LONGLONG volatile *Destination,
    __in LONGLONG Value
    );

LONGLONG
__cdecl
InterlockedXor64Acquire (
    __inout __drv_interlocked LONGLONG volatile *Destination,
    __in LONGLONG Value
    );

LONGLONG
__cdecl
InterlockedXor64Release (
    __inout __drv_interlocked LONGLONG volatile *Destination,
    __in LONGLONG Value
    );

LONG
__cdecl
InterlockedAnd (
    __inout __drv_interlocked LONG volatile *Destination,
    __in LONG Value
    );

LONG
__cdecl
InterlockedAndAcquire (
    __inout __drv_interlocked LONG volatile *Destination,
    __in LONG Value
    );

LONG
__cdecl
InterlockedAndRelease (
    __inout __drv_interlocked LONG volatile *Destination,
    __in LONG Value
    );

CHAR
__cdecl
InterlockedAnd8 (
    __inout __drv_interlocked CHAR volatile *Destination,
    __in CHAR Value
    );

CHAR
__cdecl
InterlockedAnd8Acquire (
    __inout __drv_interlocked CHAR volatile *Destination,
    __in CHAR Value
    );

CHAR
__cdecl
InterlockedAnd8Release (
    __inout __drv_interlocked CHAR volatile *Destination,
    __in CHAR Value
    );

SHORT
__cdecl
InterlockedAnd16(
    __inout __drv_interlocked SHORT volatile *Destination,
    __in SHORT Value
    );

SHORT
__cdecl
InterlockedAnd16Acquire (
    __inout __drv_interlocked SHORT volatile *Destination,
    __in SHORT Value
    );

SHORT
__cdecl
InterlockedAnd16Release (
    __inout __drv_interlocked SHORT volatile *Destination,
    __in SHORT Value
    );

LONGLONG
__cdecl
InterlockedAnd64 (
    __inout __drv_interlocked LONGLONG volatile *Destination,
    __in LONGLONG Value
    );

LONGLONG
__cdecl
InterlockedAnd64Acquire (
    __inout __drv_interlocked LONGLONG volatile *Destination,
    __in LONGLONG Value
    );

LONGLONG
__cdecl
InterlockedAnd64Release (
    __inout __drv_interlocked LONGLONG volatile *Destination,
    __in LONGLONG Value
    );

#pragma intrinsic(_InterlockedAdd)
#pragma intrinsic(_InterlockedIncrement)
#pragma intrinsic(_InterlockedIncrement_acq)
#pragma intrinsic(_InterlockedIncrement_rel)
#pragma intrinsic(_InterlockedDecrement)
#pragma intrinsic(_InterlockedDecrement_acq)
#pragma intrinsic(_InterlockedDecrement_rel)
#pragma intrinsic(_InterlockedExchange)
#pragma intrinsic(_InterlockedCompareExchange)
#pragma intrinsic(_InterlockedCompareExchange_acq)
#pragma intrinsic(_InterlockedCompareExchange_rel)
#pragma intrinsic(_InterlockedExchangeAdd)
#pragma intrinsic(_InterlockedAdd64)
#pragma intrinsic(_InterlockedIncrement64)
#pragma intrinsic(_InterlockedDecrement64)
#pragma intrinsic(_InterlockedExchange64)
#pragma intrinsic(_InterlockedExchange64_acq)
#pragma intrinsic(_InterlockedCompareExchange64)
#pragma intrinsic(_InterlockedCompareExchange64_acq)
#pragma intrinsic(_InterlockedCompareExchange64_rel)
#pragma intrinsic(_InterlockedCompare64Exchange128)
#pragma intrinsic(_InterlockedCompare64Exchange128_acq)
#pragma intrinsic(_InterlockedCompare64Exchange128_rel)
#pragma intrinsic(_InterlockedExchangeAdd64)
#pragma intrinsic(_InterlockedExchangePointer)
#pragma intrinsic(_InterlockedCompareExchangePointer)
#pragma intrinsic(_InterlockedCompareExchangePointer_acq)
#pragma intrinsic(_InterlockedCompareExchangePointer_rel)
#pragma intrinsic(_InterlockedAdd_acq)
#pragma intrinsic(_InterlockedAdd_rel)
#pragma intrinsic(_InterlockedExchange_acq)
#pragma intrinsic(_InterlockedExchangeAdd_acq)
#pragma intrinsic(_InterlockedExchangeAdd_rel)
#pragma intrinsic(_InterlockedAdd64_acq)
#pragma intrinsic(_InterlockedAdd64_rel)
#pragma intrinsic(_InterlockedIncrement64_acq)
#pragma intrinsic(_InterlockedIncrement64_rel)
#pragma intrinsic(_InterlockedDecrement64_acq)
#pragma intrinsic(_InterlockedDecrement64_rel)
#pragma intrinsic(_InterlockedExchangeAdd64_acq)
#pragma intrinsic(_InterlockedExchangeAdd64_rel)
#pragma intrinsic(_InterlockedExchangePointer_acq)
#pragma intrinsic (_InterlockedOr)
#pragma intrinsic (_InterlockedOr_acq)
#pragma intrinsic (_InterlockedOr_rel)
#pragma intrinsic (_InterlockedOr8)
#pragma intrinsic (_InterlockedOr8_acq)
#pragma intrinsic (_InterlockedOr8_rel)
#pragma intrinsic (_InterlockedOr16)
#pragma intrinsic (_InterlockedOr16_acq)
#pragma intrinsic (_InterlockedOr16_rel)
#pragma intrinsic (_InterlockedOr64)
#pragma intrinsic (_InterlockedOr64_acq)
#pragma intrinsic (_InterlockedOr64_rel)
#pragma intrinsic (_InterlockedXor)
#pragma intrinsic (_InterlockedXor_acq)
#pragma intrinsic (_InterlockedXor_rel)
#pragma intrinsic (_InterlockedXor8)
#pragma intrinsic (_InterlockedXor8_acq)
#pragma intrinsic (_InterlockedXor8_rel)
#pragma intrinsic (_InterlockedXor16)
#pragma intrinsic (_InterlockedXor16_acq)
#pragma intrinsic (_InterlockedXor16_rel)
#pragma intrinsic (_InterlockedXor64)
#pragma intrinsic (_InterlockedXor64_acq)
#pragma intrinsic (_InterlockedXor64_rel)
#pragma intrinsic (_InterlockedAnd)
#pragma intrinsic (_InterlockedAnd_acq)
#pragma intrinsic (_InterlockedAnd_rel)
#pragma intrinsic (_InterlockedAnd8)
#pragma intrinsic (_InterlockedAnd8_acq)
#pragma intrinsic (_InterlockedAnd8_rel)
#pragma intrinsic (_InterlockedAnd16)
#pragma intrinsic (_InterlockedAnd16_acq)
#pragma intrinsic (_InterlockedAnd16_rel)
#pragma intrinsic (_InterlockedAnd64)
#pragma intrinsic (_InterlockedAnd64_acq)
#pragma intrinsic (_InterlockedAnd64_rel)

#if !defined (InterlockedAnd64)

#define InterlockedAnd64 InterlockedAnd64_Inline

LONGLONG
FORCEINLINE
InterlockedAnd64_Inline (
    __inout __drv_interlocked LONGLONG volatile *Destination,
    __in LONGLONG Value
    )
{
    LONGLONG Old;

    do {
        Old = *Destination;
    } while (InterlockedCompareExchange64(Destination,
                                          Old & Value,
                                          Old) != Old);

    return Old;
}

#endif

#define InterlockedAndAffinity InterlockedAnd64

#if !defined (InterlockedOr64)

#define InterlockedOr64 InterlockedOr64_Inline

LONGLONG
FORCEINLINE
InterlockedOr64_Inline (
    __inout __drv_interlocked LONGLONG volatile *Destination,
    __in LONGLONG Value
    )
{
    LONGLONG Old;

    do {
        Old = *Destination;
    } while (InterlockedCompareExchange64(Destination,
                                          Old | Value,
                                          Old) != Old);

    return Old;
}

#endif

#define InterlockedOrAffinity InterlockedOr64

#if !defined (InterlockedXor64)

#define InterlockedXor64 InterlockedXor64_Inline

LONGLONG
FORCEINLINE
InterlockedXor64_Inline (
    __inout __drv_interlocked LONGLONG volatile *Destination,
    __in LONGLONG Value
    )
{
    LONGLONG Old;

    do {
        Old = *Destination;
    } while (InterlockedCompareExchange64(Destination,
                                          Old ^ Value,
                                          Old) != Old);

    return Old;
}

#endif

#if !defined (InterlockedBitTestAndSet)

#define InterlockedBitTestAndSet InterlockedBitTestAndSet_Inline

BOOLEAN
FORCEINLINE
InterlockedBitTestAndSet_Inline (
    __inout __drv_interlocked LONG volatile *Base,
    __in LONG Bit
    )
{
    LONG tBit;

    tBit = 1<<(Bit & (sizeof (*Base)*8-1));
    return (BOOLEAN) ((InterlockedOr (&Base[Bit/(sizeof (*Base)*8)], tBit)&tBit) != 0);
}

#endif

#if !defined (InterlockedBitTestAndReset)

#define InterlockedBitTestAndReset InterlockedBitTestAndReset_Inline

BOOLEAN
FORCEINLINE
InterlockedBitTestAndReset_Inline (
    __inout __drv_interlocked LONG volatile *Base,
    __in LONG Bit
    )
{
    LONG tBit;

    tBit = 1<<(Bit & (sizeof (*Base)*8-1));
    return (BOOLEAN) ((InterlockedAnd (&Base[Bit/(sizeof (*Base)*8)], ~tBit)&tBit) != 0);
}

#endif

#if !defined (InterlockedBitTestAndSet64)

#define InterlockedBitTestAndSet64 InterlockedBitTestAndSet64_Inline

BOOLEAN
FORCEINLINE
InterlockedBitTestAndSet64_Inline (
    __inout __drv_interlocked LONG64 volatile *Base,
    __in LONG64 Bit
    )
{
    LONG64 tBit;

    tBit = 1i64<<(Bit & (sizeof (*Base)*8-1));
    return (BOOLEAN) ((InterlockedOr64 (&Base[Bit/(sizeof (*Base)*8)], tBit)&tBit) != 0);
}

#endif

#if !defined (InterlockedBitTestAndReset64)

#define InterlockedBitTestAndReset64 InterlockedBitTestAndReset64_Inline

BOOLEAN
FORCEINLINE
InterlockedBitTestAndReset64_Inline (
    __inout __drv_interlocked LONG64 volatile *Base,
    __in LONG64 Bit
    )
{
    LONG64 tBit;

    tBit = 1i64<<(Bit & (sizeof (*Base)*8-1));
    return (BOOLEAN) ((InterlockedAnd64 (&Base[Bit/(sizeof (*Base)*8)], ~tBit)&tBit) != 0);
}

#endif

#if !defined (InterlockedBitTestAndComplement)

#define InterlockedBitTestAndComplement InterlockedBitTestAndComplement_Inline

BOOLEAN
FORCEINLINE
InterlockedBitTestAndComplement_Inline (
    __inout __drv_interlocked LONG volatile *Base,
    __in LONG Bit
    )
{
    LONG tBit;

    tBit = 1<<(Bit & (sizeof (*Base)*8-1));
    return (BOOLEAN) ((InterlockedXor (&Base[Bit/(sizeof (*Base)*8)], tBit)&tBit) != 0);
}

#endif

#if !defined (InterlockedBitTestAndComplement64)

#define InterlockedBitTestAndComplement64 InterlockedBitTestAndComplement64_Inline

BOOLEAN
FORCEINLINE
InterlockedBitTestAndComplement64_Inline (
    __inout __drv_interlocked LONG64 volatile *Base,
    __in LONG64 Bit
    )
{
    LONG64 tBit;

    tBit = 1i64<<(Bit & (sizeof (*Base)*8-1));
    return (BOOLEAN) ((InterlockedXor64 (&Base[Bit/(sizeof (*Base)*8)], tBit)&tBit) != 0);
}

#endif

#ifdef __cplusplus
}
#endif

#endif /* defined(_M_IA64) && !defined(RC_INVOKED) && !defined(MIDL_PASS) */


#if defined(_IA64_) && defined(_M_IA64) && !defined(RC_INVOKED) && !defined(MIDL_PASS)

void
__break(
    __in int StIIM
    );

#pragma intrinsic (__break)

#define BREAK_DEBUG_BASE    0x080000
#define ASSERT_BREAKPOINT         (BREAK_DEBUG_BASE+3)  // Cause a STATUS_ASSERTION_FAILURE exception to be raised.

__analysis_noreturn
FORCEINLINE
VOID
DbgRaiseAssertionFailure (
    VOID
    )

{
    __break(ASSERT_BREAKPOINT);
}

#endif

#endif // _IA64_
//
//  Define an access token from a programmer's viewpoint.  The structure is
//  completely opaque and the programer is only allowed to have pointers
//  to tokens.
//

typedef PVOID PACCESS_TOKEN;            

//
// Pointer to a SECURITY_DESCRIPTOR  opaque data type.
//

typedef PVOID PSECURITY_DESCRIPTOR;     

//
// Define a pointer to the Security ID data type (an opaque data type)
//

typedef PVOID PSID;     

typedef ULONG ACCESS_MASK;
typedef ACCESS_MASK *PACCESS_MASK;


//
//  The following are masks for the predefined standard access types
//

#define DELETE                           (0x00010000L)
#define READ_CONTROL                     (0x00020000L)
#define WRITE_DAC                        (0x00040000L)
#define WRITE_OWNER                      (0x00080000L)
#define SYNCHRONIZE                      (0x00100000L)

#define STANDARD_RIGHTS_REQUIRED         (0x000F0000L)

#define STANDARD_RIGHTS_READ             (READ_CONTROL)
#define STANDARD_RIGHTS_WRITE            (READ_CONTROL)
#define STANDARD_RIGHTS_EXECUTE          (READ_CONTROL)

#define STANDARD_RIGHTS_ALL              (0x001F0000L)

#define SPECIFIC_RIGHTS_ALL              (0x0000FFFFL)

//
// AccessSystemAcl access type
//

#define ACCESS_SYSTEM_SECURITY           (0x01000000L)

//
// MaximumAllowed access type
//

#define MAXIMUM_ALLOWED                  (0x02000000L)

//
//  These are the generic rights.
//

#define GENERIC_READ                     (0x80000000L)
#define GENERIC_WRITE                    (0x40000000L)
#define GENERIC_EXECUTE                  (0x20000000L)
#define GENERIC_ALL                      (0x10000000L)


//
//  Define the generic mapping array.  This is used to denote the
//  mapping of each generic access right to a specific access mask.
//

typedef struct _GENERIC_MAPPING {
    ACCESS_MASK GenericRead;
    ACCESS_MASK GenericWrite;
    ACCESS_MASK GenericExecute;
    ACCESS_MASK GenericAll;
} GENERIC_MAPPING;
typedef GENERIC_MAPPING *PGENERIC_MAPPING;



////////////////////////////////////////////////////////////////////////
//                                                                    //
//                        LUID_AND_ATTRIBUTES                         //
//                                                                    //
////////////////////////////////////////////////////////////////////////
//
//


#include <pshpack4.h>

typedef struct _LUID_AND_ATTRIBUTES {
    LUID Luid;
    ULONG Attributes;
    } LUID_AND_ATTRIBUTES, * PLUID_AND_ATTRIBUTES;
typedef LUID_AND_ATTRIBUTES LUID_AND_ATTRIBUTES_ARRAY[ANYSIZE_ARRAY];
typedef LUID_AND_ATTRIBUTES_ARRAY *PLUID_AND_ATTRIBUTES_ARRAY;

#include <poppack.h>

// This is the *current* ACL revision

#define ACL_REVISION     (2)
#define ACL_REVISION_DS  (4)

// This is the history of ACL revisions.  Add a new one whenever
// ACL_REVISION is updated

#define ACL_REVISION1   (1)
#define MIN_ACL_REVISION ACL_REVISION2
#define ACL_REVISION2   (2)
#define ACL_REVISION3   (3)
#define ACL_REVISION4   (4)
#define MAX_ACL_REVISION ACL_REVISION4

typedef struct _ACL {
    UCHAR AclRevision;
    UCHAR Sbz1;
    USHORT AclSize;
    USHORT AceCount;
    USHORT Sbz2;
} ACL;
typedef ACL *PACL;

//
// Current security descriptor revision value
//

#define SECURITY_DESCRIPTOR_REVISION     (1)
#define SECURITY_DESCRIPTOR_REVISION1    (1)

//
// Privilege attributes
//

#define SE_PRIVILEGE_ENABLED_BY_DEFAULT (0x00000001L)
#define SE_PRIVILEGE_ENABLED            (0x00000002L)
#define SE_PRIVILEGE_REMOVED            (0X00000004L)
#define SE_PRIVILEGE_USED_FOR_ACCESS    (0x80000000L)

#define SE_PRIVILEGE_VALID_ATTRIBUTES   (SE_PRIVILEGE_ENABLED_BY_DEFAULT | \
                                         SE_PRIVILEGE_ENABLED            | \
                                         SE_PRIVILEGE_REMOVED            | \
                                         SE_PRIVILEGE_USED_FOR_ACCESS)


//
// Privilege Set Control flags
//

#define PRIVILEGE_SET_ALL_NECESSARY    (1)

//
//  Privilege Set - This is defined for a privilege set of one.
//                  If more than one privilege is needed, then this structure
//                  will need to be allocated with more space.
//
//  Note: don't change this structure without fixing the INITIAL_PRIVILEGE_SET
//  structure (defined in se.h)
//

typedef struct _PRIVILEGE_SET {
    ULONG PrivilegeCount;
    ULONG Control;
    LUID_AND_ATTRIBUTES Privilege[ANYSIZE_ARRAY];
    } PRIVILEGE_SET, * PPRIVILEGE_SET;


//
// These must be converted to LUIDs before use.
//

#define SE_MIN_WELL_KNOWN_PRIVILEGE         (2L)
#define SE_CREATE_TOKEN_PRIVILEGE           (2L)
#define SE_ASSIGNPRIMARYTOKEN_PRIVILEGE     (3L)
#define SE_LOCK_MEMORY_PRIVILEGE            (4L)
#define SE_INCREASE_QUOTA_PRIVILEGE         (5L)

#define SE_MACHINE_ACCOUNT_PRIVILEGE        (6L)
#define SE_TCB_PRIVILEGE                    (7L)
#define SE_SECURITY_PRIVILEGE               (8L)
#define SE_TAKE_OWNERSHIP_PRIVILEGE         (9L)
#define SE_LOAD_DRIVER_PRIVILEGE            (10L)
#define SE_SYSTEM_PROFILE_PRIVILEGE         (11L)
#define SE_SYSTEMTIME_PRIVILEGE             (12L)
#define SE_PROF_SINGLE_PROCESS_PRIVILEGE    (13L)
#define SE_INC_BASE_PRIORITY_PRIVILEGE      (14L)
#define SE_CREATE_PAGEFILE_PRIVILEGE        (15L)
#define SE_CREATE_PERMANENT_PRIVILEGE       (16L)
#define SE_BACKUP_PRIVILEGE                 (17L)
#define SE_RESTORE_PRIVILEGE                (18L)
#define SE_SHUTDOWN_PRIVILEGE               (19L)
#define SE_DEBUG_PRIVILEGE                  (20L)
#define SE_AUDIT_PRIVILEGE                  (21L)
#define SE_SYSTEM_ENVIRONMENT_PRIVILEGE     (22L)
#define SE_CHANGE_NOTIFY_PRIVILEGE          (23L)
#define SE_REMOTE_SHUTDOWN_PRIVILEGE        (24L)
#define SE_UNDOCK_PRIVILEGE                 (25L)
#define SE_SYNC_AGENT_PRIVILEGE             (26L)
#define SE_ENABLE_DELEGATION_PRIVILEGE      (27L)
#define SE_MANAGE_VOLUME_PRIVILEGE          (28L)
#define SE_IMPERSONATE_PRIVILEGE            (29L)
#define SE_CREATE_GLOBAL_PRIVILEGE          (30L)
#define SE_TRUSTED_CREDMAN_ACCESS_PRIVILEGE (31L)
#define SE_RELABEL_PRIVILEGE                (32L)
#define SE_INC_WORKING_SET_PRIVILEGE        (33L)
#define SE_TIME_ZONE_PRIVILEGE              (34L)
#define SE_CREATE_SYMBOLIC_LINK_PRIVILEGE   (35L)
#define SE_MAX_WELL_KNOWN_PRIVILEGE         (SE_CREATE_SYMBOLIC_LINK_PRIVILEGE)

//
// Impersonation Level
//
// Impersonation level is represented by a pair of bits in Windows.
// If a new impersonation level is added or lowest value is changed from
// 0 to something else, fix the Windows CreateFile call.
//

typedef enum _SECURITY_IMPERSONATION_LEVEL {
    SecurityAnonymous,
    SecurityIdentification,
    SecurityImpersonation,
    SecurityDelegation
    } SECURITY_IMPERSONATION_LEVEL, * PSECURITY_IMPERSONATION_LEVEL;

#define SECURITY_MAX_IMPERSONATION_LEVEL SecurityDelegation
#define SECURITY_MIN_IMPERSONATION_LEVEL SecurityAnonymous
#define DEFAULT_IMPERSONATION_LEVEL SecurityImpersonation
#define VALID_IMPERSONATION_LEVEL(L) (((L) >= SECURITY_MIN_IMPERSONATION_LEVEL) && ((L) <= SECURITY_MAX_IMPERSONATION_LEVEL))
//
// Security Tracking Mode
//

#define SECURITY_DYNAMIC_TRACKING      (TRUE)
#define SECURITY_STATIC_TRACKING       (FALSE)

typedef BOOLEAN SECURITY_CONTEXT_TRACKING_MODE,
                    * PSECURITY_CONTEXT_TRACKING_MODE;



//
// Quality Of Service
//

typedef struct _SECURITY_QUALITY_OF_SERVICE {
    ULONG Length;
    SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
    SECURITY_CONTEXT_TRACKING_MODE ContextTrackingMode;
    BOOLEAN EffectiveOnly;
    } SECURITY_QUALITY_OF_SERVICE, * PSECURITY_QUALITY_OF_SERVICE;


//
// Used to represent information related to a thread impersonation
//

typedef struct _SE_IMPERSONATION_STATE {
    PACCESS_TOKEN Token;
    BOOLEAN CopyOnOpen;
    BOOLEAN EffectiveOnly;
    SECURITY_IMPERSONATION_LEVEL Level;
} SE_IMPERSONATION_STATE, *PSE_IMPERSONATION_STATE;


typedef ULONG SECURITY_INFORMATION, *PSECURITY_INFORMATION;

#define OWNER_SECURITY_INFORMATION       (0x00000001L)
#define GROUP_SECURITY_INFORMATION       (0x00000002L)
#define DACL_SECURITY_INFORMATION        (0x00000004L)
#define SACL_SECURITY_INFORMATION        (0x00000008L)
#define LABEL_SECURITY_INFORMATION       (0x00000010L)

#define PROTECTED_DACL_SECURITY_INFORMATION     (0x80000000L)
#define PROTECTED_SACL_SECURITY_INFORMATION     (0x40000000L)
#define UNPROTECTED_DACL_SECURITY_INFORMATION   (0x20000000L)
#define UNPROTECTED_SACL_SECURITY_INFORMATION   (0x10000000L)


#ifndef _NTLSA_IFS_


//
// All of this stuff (between the Ifndef _NTLSA_AUDIT_ and its endif) were not
// present in NTIFS prior to Windows Server 2003 SP1. All of the definitions however
// exist down to windows 2000 (except for the few exceptions noted in the code).
//

#ifndef _NTLSA_AUDIT_
#define _NTLSA_AUDIT_

/////////////////////////////////////////////////////////////////////////
//                                                                     //
// Data types related to Auditing                                      //
//                                                                     //
/////////////////////////////////////////////////////////////////////////


//
// The following enumerated type is used between the reference monitor and
// LSA in the generation of audit messages.  It is used to indicate the
// type of data being passed as a parameter from the reference monitor
// to LSA.  LSA is responsible for transforming the specified data type
// into a set of unicode strings that are added to the event record in
// the audit log.
//

typedef enum _SE_ADT_PARAMETER_TYPE {

    SeAdtParmTypeNone = 0,          //Produces 1 parameter
                                    //Received value:
                                    //
                                    //  None.
                                    //
                                    //Results in:
                                    //
                                    //  a unicode string containing "-".
                                    //
                                    //Note:  This is typically used to
                                    //       indicate that a parameter value
                                    //       was not available.
                                    //

    SeAdtParmTypeString,            //Produces 1 parameter.
                                    //Received Value:
                                    //
                                    //  Unicode String (variable length)
                                    //
                                    //Results in:
                                    //
                                    //  No transformation.  The string
                                    //  entered into the event record as
                                    //  received.
                                    //
                                    // The Address value of the audit info
                                    // should be a pointer to a UNICODE_STRING
                                    // structure.



    SeAdtParmTypeFileSpec,          //Produces 1 parameter.
                                    //Received value:
                                    //
                                    //  Unicode string containing a file or
                                    //  directory name.
                                    //
                                    //Results in:
                                    //
                                    //  Unicode string with the prefix of the
                                    //  file's path replaced by a drive letter
                                    //  if possible.
                                    //




    SeAdtParmTypeUlong,             //Produces 1 parameter
                                    //Received value:
                                    //
                                    //  Ulong
                                    //
                                    //Results in:
                                    //
                                    //  Unicode string representation of
                                    //  unsigned integer value.


    SeAdtParmTypeSid,               //Produces 1 parameter.
                                    //Received value:
                                    //
                                    //  SID (variable length)
                                    //
                                    //Results in:
                                    //
                                    //  String representation of SID
                                    //




    SeAdtParmTypeLogonId,           //Produces 4 parameters.
                                    //Received Value:
                                    //
                                    //  LUID (fixed length)
                                    //
                                    //Results in:
                                    //
                                    //  param 1: Sid string
                                    //  param 2: Username string
                                    //  param 3: domain name string
                                    //  param 4: Logon ID (Luid) string


    SeAdtParmTypeNoLogonId,         //Produces 3 parameters.
                                    //Received value:
                                    //
                                    //  None.
                                    //
                                    //Results in:
                                    //
                                    //  param 1: "-"
                                    //  param 2: "-"
                                    //  param 3: "-"
                                    //  param 4: "-"
                                    //
                                    //Note:
                                    //
                                    //  This type is used when a logon ID
                                    //  is needed, but one is not available
                                    //  to pass.  For example, if an
                                    //  impersonation logon ID is expected
                                    //  but the subject is not impersonating
                                    //  anyone.
                                    //

    SeAdtParmTypeAccessMask,        //Produces 1 parameter with formatting.
                                    //Received value:
                                    //
                                    //  ACCESS_MASK followed by
                                    //  a Unicode string.  The unicode
                                    //  string contains the name of the
                                    //  type of object the access mask
                                    //  applies to.  The event's source
                                    //  further qualifies the object type.
                                    //
                                    //Results in:
                                    //
                                    //  formatted unicode string built to
                                    //  take advantage of the specified
                                    //  source's parameter message file.
                                    //
                                    //Note:
                                    //
                                    //  An access mask containing three
                                    //  access types for a Widget object
                                    //  type (defined by the Foozle source)
                                    //  might end up looking like:
                                    //
                                    //      %%1062\n\t\t%1066\n\t\t%%601
                                    //
                                    //  The %%numbers are signals to the
                                    //  event viewer to perform parameter
                                    //  substitution before display.
                                    //



    SeAdtParmTypePrivs,             //Produces 1 parameter with formatting.
                                    //Received value:
                                    //
                                    //Results in:
                                    //
                                    //  formatted unicode string similar to
                                    //  that for access types.  Each priv
                                    //  will be formatted to be displayed
                                    //  on its own line.  E.g.,
                                    //
                                    //      %%642\n\t\t%%651\n\t\t%%655
                                    //

    SeAdtParmTypeObjectTypes,       //Produces 10 parameters with formatting.
                                    //Received value:
                                    //
                                    // Produces a list a stringized GUIDS along
                                    // with information similar to that for
                                    // an access mask.

    SeAdtParmTypeHexUlong,          //Produces 1 parameter
                                    //Received value:
                                    //
                                    //  Ulong
                                    //
                                    //Results in:
                                    //
                                    //  Unicode string representation of
                                    //  unsigned integer value in hexadecimal.

// In W2k this value did not exist, it was ParmTypeLUID

    SeAdtParmTypePtr,               //Produces 1 parameter
                                    //Received value:
                                    //
                                    //  pointer
                                    //
                                    //Results in:
                                    //
                                    //  Unicode string representation of
                                    //  unsigned integer value in hexadecimal.

//
// Everything below exists only in Windows XP and greater
//

    SeAdtParmTypeTime,              //Produces 2 parameters
                                    //Received value:
                                    //
                                    //  LARGE_INTEGER
                                    //
                                    //Results in:
                                    //
                                    // Unicode string representation of
                                    // date and time.

                                    //
    SeAdtParmTypeGuid,              //Produces 1 parameter
                                    //Received value:
                                    //
                                    //  GUID pointer
                                    //
                                    //Results in:
                                    //
                                    // Unicode string representation of GUID
                                    // {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
                                    //

//
// Everything below exists only in Windows Server 2003 and Greater
//

    SeAdtParmTypeLuid,              //
                                    //Produces 1 parameter
                                    //Received value:
                                    //
                                    // LUID
                                    //
                                    //Results in:
                                    //
                                    // Hex LUID
                                    //

    SeAdtParmTypeHexInt64,          //Produces 1 parameter
                                    //Received value:
                                    //
                                    //  64 bit integer
                                    //
                                    //Results in:
                                    //
                                    //  Unicode string representation of
                                    //  unsigned integer value in hexadecimal.

    SeAdtParmTypeStringList,        //Produces 1 parameter
                                    //Received value:
                                    //
                                    // ptr to LSAP_ADT_STRING_LIST
                                    //
                                    //Results in:
                                    //
                                    // Unicode string representation of
                                    // concatenation of the strings in the list

    SeAdtParmTypeSidList,           //Produces 1 parameter
                                    //Received value:
                                    //
                                    // ptr to LSAP_ADT_SID_LIST
                                    //
                                    //Results in:
                                    //
                                    // Unicode string representation of
                                    // concatenation of the SIDs in the list

    SeAdtParmTypeDuration,          //Produces 1 parameters
                                    //Received value:
                                    //
                                    //  LARGE_INTEGER
                                    //
                                    //Results in:
                                    //
                                    // Unicode string representation of
                                    // a duration.

    SeAdtParmTypeUserAccountControl,//Produces 3 parameters
                                    //Received value:
                                    //
                                    // old and new UserAccountControl values
                                    //
                                    //Results in:
                                    //
                                    // Unicode string representations of
                                    // the flags in UserAccountControl.
                                    // 1 - old value in hex
                                    // 2 - new value in hex
                                    // 3 - difference as strings

    SeAdtParmTypeNoUac,             //Produces 3 parameters
                                    //Received value:
                                    //
                                    // none
                                    //
                                    //Results in:
                                    //
                                    // Three dashes ('-') as unicode strings.

    SeAdtParmTypeMessage,           //Produces 1 Parameter
                                    //Received value:
                                    //
                                    //  ULONG (MessageNo from msobjs.mc)
                                    //
                                    //Results in:
                                    //
                                    // Unicode string representation of
                                    // %%MessageNo which the event viewer
                                    // will replace with the message string
                                    // from msobjs.mc

    SeAdtParmTypeDateTime,          //Produces 1 Parameter
                                    //Received value:
                                    //
                                    //  LARGE_INTEGER
                                    //
                                    //Results in:
                                    //
                                    // Unicode string representation of
                                    // date and time (in _one_ string).

    SeAdtParmTypeSockAddr,          // Produces 2 parameters
                                    //
                                    // Received value:
                                    //
                                    // pointer to SOCKADDR_IN/SOCKADDR_IN6
                                    // structure
                                    //
                                    // Results in:
                                    //
                                    // param 1: IP address string
                                    // param 2: Port number string
                                    //

//
// Everything below this exists only in Windows Server 2008 and greater
//

    SeAdtParmTypeSD,                // Produces 1 parameters
                                    //
                                    // Received value:
                                    //
                                    // pointer to SECURITY_DESCRIPTOR
                                    // structure
                                    //
                                    // Results in:
                                    //
                                    // SDDL string representation of SD
                                    //

    SeAdtParmTypeLogonHours,        // Produces 1 parameters
                                    //
                                    // Received value:
                                    //
                                    // pointer to LOGON_HOURS
                                    // structure
                                    //
                                    // Results in:
                                    //
                                    // String representation of allowed logon hours
                                    //

    SeAdtParmTypeLogonIdNoSid,      //Produces 3 parameters.
                                    //Received Value:
                                    //
                                    //  LUID (fixed length)
                                    //
                                    //Results in:
                                    //
                                    //  param 1: Username string
                                    //  param 2: domain name string
                                    //  param 3: Logon ID (Luid) string

    SeAdtParmTypeUlongNoConv,       // Produces 1 parameter.
                                    // Received Value:
                                    // Ulong
                                    //
                                    //Results in:
                                    // Not converted to string
                                    //

    SeAdtParmTypeSockAddrNoPort,     // Produces 1 parameter
                                    //
                                    // Received value:
                                    //
                                    // pointer to SOCKADDR_IN/SOCKADDR_IN6
                                    // structure
                                    //
                                    // Results in:
                                    //
                                    // param 1: IPv4/IPv6 address string
                                    //
//
// Everything below this exists only in Windows Server 2008 and greater
//

    SeAdtParmTypeAccessReason                // Produces 1 parameters
                                    //
                                    // Received value:
                                    //
                                    // pointer to SECURITY_DESCRIPTOR
                                    // structure followed by the reason code.
                                    // The reason code could be the index
                                    // of the ACE in the SD or privilege ID or
                                    // other reason codes.
                                    //
                                    // Results in:
                                    //
                                    // String representation of the access reason.
                                    //

} SE_ADT_PARAMETER_TYPE, *PSE_ADT_PARAMETER_TYPE;

#ifndef GUID_DEFINED
#include <guiddef.h>
#endif /* GUID_DEFINED */

typedef struct _SE_ADT_OBJECT_TYPE {
    GUID ObjectType;
    USHORT Flags;
#define SE_ADT_OBJECT_ONLY 0x1
    USHORT Level;
    ACCESS_MASK AccessMask;
} SE_ADT_OBJECT_TYPE, *PSE_ADT_OBJECT_TYPE;

typedef struct _SE_ADT_PARAMETER_ARRAY_ENTRY {

    SE_ADT_PARAMETER_TYPE Type;
    ULONG Length;
    ULONG_PTR Data[2];
    PVOID Address;

} SE_ADT_PARAMETER_ARRAY_ENTRY, *PSE_ADT_PARAMETER_ARRAY_ENTRY;


typedef struct _SE_ADT_ACCESS_REASON{
    ACCESS_MASK AccessMask;
    ULONG  AccessReasons[32];
    ULONG  ObjectTypeIndex;
    ULONG AccessGranted;
    PSECURITY_DESCRIPTOR SecurityDescriptor;    // multple SDs may be stored here in self-relative way.
} SE_ADT_ACCESS_REASON, *PSE_ADT_ACCESS_REASON;



//
// Structure that will be passed between the Reference Monitor and LSA
// to transmit auditing information.
//

#define SE_MAX_AUDIT_PARAMETERS 32
#define SE_MAX_GENERIC_AUDIT_PARAMETERS 28

typedef struct _SE_ADT_PARAMETER_ARRAY {

    ULONG CategoryId;
    ULONG AuditId;
    ULONG ParameterCount;
    ULONG Length;
    USHORT FlatSubCategoryId;
    USHORT Type;
    ULONG Flags;
    SE_ADT_PARAMETER_ARRAY_ENTRY Parameters[ SE_MAX_AUDIT_PARAMETERS ];

} SE_ADT_PARAMETER_ARRAY, *PSE_ADT_PARAMETER_ARRAY;


#define SE_ADT_PARAMETERS_SELF_RELATIVE     0x00000001
#define SE_ADT_PARAMETERS_SEND_TO_LSA       0x00000002
#define SE_ADT_PARAMETER_EXTENSIBLE_AUDIT   0x00000004
#define SE_ADT_PARAMETER_GENERIC_AUDIT      0x00000008
#define SE_ADT_PARAMETER_WRITE_SYNCHRONOUS  0x00000010


//
// This macro only existed in Windows Server 2008 and after
//

#define LSAP_SE_ADT_PARAMETER_ARRAY_TRUE_SIZE(AuditParameters)    \
     ( sizeof(SE_ADT_PARAMETER_ARRAY) -                           \
       sizeof(SE_ADT_PARAMETER_ARRAY_ENTRY) *                     \
       (SE_MAX_AUDIT_PARAMETERS - AuditParameters->ParameterCount) )

#endif // _NTLSA_AUDIT_


#endif // _NTLSA_IFS_

//
// Define the various device type values.  Note that values used by Microsoft
// Corporation are in the range 0-32767, and 32768-65535 are reserved for use
// by customers.
//

#define DEVICE_TYPE ULONG

#define FILE_DEVICE_BEEP                0x00000001
#define FILE_DEVICE_CD_ROM              0x00000002
#define FILE_DEVICE_CD_ROM_FILE_SYSTEM  0x00000003
#define FILE_DEVICE_CONTROLLER          0x00000004
#define FILE_DEVICE_DATALINK            0x00000005
#define FILE_DEVICE_DFS                 0x00000006
#define FILE_DEVICE_DISK                0x00000007
#define FILE_DEVICE_DISK_FILE_SYSTEM    0x00000008
#define FILE_DEVICE_FILE_SYSTEM         0x00000009
#define FILE_DEVICE_INPORT_PORT         0x0000000a
#define FILE_DEVICE_KEYBOARD            0x0000000b
#define FILE_DEVICE_MAILSLOT            0x0000000c
#define FILE_DEVICE_MIDI_IN             0x0000000d
#define FILE_DEVICE_MIDI_OUT            0x0000000e
#define FILE_DEVICE_MOUSE               0x0000000f
#define FILE_DEVICE_MULTI_UNC_PROVIDER  0x00000010
#define FILE_DEVICE_NAMED_PIPE          0x00000011
#define FILE_DEVICE_NETWORK             0x00000012
#define FILE_DEVICE_NETWORK_BROWSER     0x00000013
#define FILE_DEVICE_NETWORK_FILE_SYSTEM 0x00000014
#define FILE_DEVICE_NULL                0x00000015
#define FILE_DEVICE_PARALLEL_PORT       0x00000016
#define FILE_DEVICE_PHYSICAL_NETCARD    0x00000017
#define FILE_DEVICE_PRINTER             0x00000018
#define FILE_DEVICE_SCANNER             0x00000019
#define FILE_DEVICE_SERIAL_MOUSE_PORT   0x0000001a
#define FILE_DEVICE_SERIAL_PORT         0x0000001b
#define FILE_DEVICE_SCREEN              0x0000001c
#define FILE_DEVICE_SOUND               0x0000001d
#define FILE_DEVICE_STREAMS             0x0000001e
#define FILE_DEVICE_TAPE                0x0000001f
#define FILE_DEVICE_TAPE_FILE_SYSTEM    0x00000020
#define FILE_DEVICE_TRANSPORT           0x00000021
#define FILE_DEVICE_UNKNOWN             0x00000022
#define FILE_DEVICE_VIDEO               0x00000023
#define FILE_DEVICE_VIRTUAL_DISK        0x00000024
#define FILE_DEVICE_WAVE_IN             0x00000025
#define FILE_DEVICE_WAVE_OUT            0x00000026
#define FILE_DEVICE_8042_PORT           0x00000027
#define FILE_DEVICE_NETWORK_REDIRECTOR  0x00000028
#define FILE_DEVICE_BATTERY             0x00000029
#define FILE_DEVICE_BUS_EXTENDER        0x0000002a
#define FILE_DEVICE_MODEM               0x0000002b
#define FILE_DEVICE_VDM                 0x0000002c
#define FILE_DEVICE_MASS_STORAGE        0x0000002d
#define FILE_DEVICE_SMB                 0x0000002e
#define FILE_DEVICE_KS                  0x0000002f
#define FILE_DEVICE_CHANGER             0x00000030
#define FILE_DEVICE_SMARTCARD           0x00000031
#define FILE_DEVICE_ACPI                0x00000032
#define FILE_DEVICE_DVD                 0x00000033
#define FILE_DEVICE_FULLSCREEN_VIDEO    0x00000034
#define FILE_DEVICE_DFS_FILE_SYSTEM     0x00000035
#define FILE_DEVICE_DFS_VOLUME          0x00000036
#define FILE_DEVICE_SERENUM             0x00000037
#define FILE_DEVICE_TERMSRV             0x00000038
#define FILE_DEVICE_KSEC                0x00000039
#define FILE_DEVICE_FIPS                0x0000003A
#define FILE_DEVICE_INFINIBAND          0x0000003B
#define FILE_DEVICE_VMBUS               0x0000003E
#define FILE_DEVICE_CRYPT_PROVIDER      0x0000003F
#define FILE_DEVICE_WPD                 0x00000040
#define FILE_DEVICE_BLUETOOTH           0x00000041
#define FILE_DEVICE_MT_COMPOSITE        0x00000042
#define FILE_DEVICE_MT_TRANSPORT        0x00000043
#define FILE_DEVICE_BIOMETRIC		0x00000044
#define FILE_DEVICE_PMI                 0x00000045

//
// Macro definition for defining IOCTL and FSCTL function control codes.  Note
// that function codes 0-2047 are reserved for Microsoft Corporation, and
// 2048-4095 are reserved for customers.
//

#define CTL_CODE( DeviceType, Function, Method, Access ) (                 \
    ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
)

//
// Macro to extract device type out of the device io control code
//
#define DEVICE_TYPE_FROM_CTL_CODE(ctrlCode)     (((ULONG)(ctrlCode & 0xffff0000)) >> 16)

//
// Macro to extract buffering method out of the device io control code
//
#define METHOD_FROM_CTL_CODE(ctrlCode)          ((ULONG)(ctrlCode & 3))

//
// Define the method codes for how buffers are passed for I/O and FS controls
//

#define METHOD_BUFFERED                 0
#define METHOD_IN_DIRECT                1
#define METHOD_OUT_DIRECT               2
#define METHOD_NEITHER                  3

//
// Define some easier to comprehend aliases:
//   METHOD_DIRECT_TO_HARDWARE (writes, aka METHOD_IN_DIRECT)
//   METHOD_DIRECT_FROM_HARDWARE (reads, aka METHOD_OUT_DIRECT)
//

#define METHOD_DIRECT_TO_HARDWARE       METHOD_IN_DIRECT
#define METHOD_DIRECT_FROM_HARDWARE     METHOD_OUT_DIRECT

//
// Define the access check value for any access
//
//
// The FILE_READ_ACCESS and FILE_WRITE_ACCESS constants are also defined in
// ntioapi.h as FILE_READ_DATA and FILE_WRITE_DATA. The values for these
// constants *MUST* always be in sync.
//
//
// FILE_SPECIAL_ACCESS is checked by the NT I/O system the same as FILE_ANY_ACCESS.
// The file systems, however, may add additional access checks for I/O and FS controls
// that use this value.
//


#define FILE_ANY_ACCESS                 0
#define FILE_SPECIAL_ACCESS    (FILE_ANY_ACCESS)
#define FILE_READ_ACCESS          ( 0x0001 )    // file & pipe
#define FILE_WRITE_ACCESS         ( 0x0002 )    // file & pipe



//
// Define access rights to files and directories
//

//
// The FILE_READ_DATA and FILE_WRITE_DATA constants are also defined in
// devioctl.h as FILE_READ_ACCESS and FILE_WRITE_ACCESS. The values for these
// constants *MUST* always be in sync.
// The values are redefined in devioctl.h because they must be available to
// both DOS and NT.
//

#define FILE_READ_DATA            ( 0x0001 )    // file & pipe
#define FILE_LIST_DIRECTORY       ( 0x0001 )    // directory

#define FILE_WRITE_DATA           ( 0x0002 )    // file & pipe
#define FILE_ADD_FILE             ( 0x0002 )    // directory

#define FILE_APPEND_DATA          ( 0x0004 )    // file
#define FILE_ADD_SUBDIRECTORY     ( 0x0004 )    // directory
#define FILE_CREATE_PIPE_INSTANCE ( 0x0004 )    // named pipe


#define FILE_READ_EA              ( 0x0008 )    // file & directory

#define FILE_WRITE_EA             ( 0x0010 )    // file & directory

#define FILE_EXECUTE              ( 0x0020 )    // file
#define FILE_TRAVERSE             ( 0x0020 )    // directory

#define FILE_DELETE_CHILD         ( 0x0040 )    // directory

#define FILE_READ_ATTRIBUTES      ( 0x0080 )    // all

#define FILE_WRITE_ATTRIBUTES     ( 0x0100 )    // all

#define FILE_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1FF)

#define FILE_GENERIC_READ         (STANDARD_RIGHTS_READ     |\
                                   FILE_READ_DATA           |\
                                   FILE_READ_ATTRIBUTES     |\
                                   FILE_READ_EA             |\
                                   SYNCHRONIZE)


#define FILE_GENERIC_WRITE        (STANDARD_RIGHTS_WRITE    |\
                                   FILE_WRITE_DATA          |\
                                   FILE_WRITE_ATTRIBUTES    |\
                                   FILE_WRITE_EA            |\
                                   FILE_APPEND_DATA         |\
                                   SYNCHRONIZE)


#define FILE_GENERIC_EXECUTE      (STANDARD_RIGHTS_EXECUTE  |\
                                   FILE_READ_ATTRIBUTES     |\
                                   FILE_EXECUTE             |\
                                   SYNCHRONIZE)




//
// Define share access rights to files and directories
//

#define FILE_SHARE_READ                 0x00000001  
#define FILE_SHARE_WRITE                0x00000002  
#define FILE_SHARE_DELETE               0x00000004  
#define FILE_SHARE_VALID_FLAGS          0x00000007

//
// Define the file attributes values
//
// Note:  0x00000008 is reserved for use for the old DOS VOLID (volume ID)
//        and is therefore not considered valid in NT.
//
// Note:  Note also that the order of these flags is set to allow both the
//        FAT and the Pinball File Systems to directly set the attributes
//        flags in attributes words without having to pick each flag out
//        individually.  The order of these flags should not be changed!
//

#define FILE_ATTRIBUTE_READONLY             0x00000001  
#define FILE_ATTRIBUTE_HIDDEN               0x00000002  
#define FILE_ATTRIBUTE_SYSTEM               0x00000004  
//OLD DOS VOLID                             0x00000008

#define FILE_ATTRIBUTE_DIRECTORY            0x00000010  
#define FILE_ATTRIBUTE_ARCHIVE              0x00000020  
#define FILE_ATTRIBUTE_DEVICE               0x00000040  
#define FILE_ATTRIBUTE_NORMAL               0x00000080  

#define FILE_ATTRIBUTE_TEMPORARY            0x00000100  
#define FILE_ATTRIBUTE_SPARSE_FILE          0x00000200  
#define FILE_ATTRIBUTE_REPARSE_POINT        0x00000400  
#define FILE_ATTRIBUTE_COMPRESSED           0x00000800  

#define FILE_ATTRIBUTE_OFFLINE              0x00001000  
#define FILE_ATTRIBUTE_NOT_CONTENT_INDEXED  0x00002000  
#define FILE_ATTRIBUTE_ENCRYPTED            0x00004000  

#define FILE_ATTRIBUTE_VIRTUAL              0x00010000  

#define FILE_ATTRIBUTE_VALID_FLAGS          0x00007fb7
#define FILE_ATTRIBUTE_VALID_SET_FLAGS      0x000031a7

//
// Define the create disposition values
//

#define FILE_SUPERSEDE                  0x00000000
#define FILE_OPEN                       0x00000001
#define FILE_CREATE                     0x00000002
#define FILE_OPEN_IF                    0x00000003
#define FILE_OVERWRITE                  0x00000004
#define FILE_OVERWRITE_IF               0x00000005
#define FILE_MAXIMUM_DISPOSITION        0x00000005

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

#if (NTDDI_VERSION >= NTDDI_WIN7)
#define FILE_OPEN_REQUIRING_OPLOCK              0x00010000
#define FILE_DISALLOW_EXCLUSIVE                 0x00020000
#endif /* NTDDI_VERSION >= NTDDI_WIN7 */

#define FILE_RESERVE_OPFILTER                   0x00100000
#define FILE_OPEN_REPARSE_POINT                 0x00200000
#define FILE_OPEN_NO_RECALL                     0x00400000
#define FILE_OPEN_FOR_FREE_SPACE_QUERY          0x00800000


#define FILE_VALID_OPTION_FLAGS                 0x00ffffff
#define FILE_VALID_PIPE_OPTION_FLAGS            0x00000032
#define FILE_VALID_MAILSLOT_OPTION_FLAGS        0x00000032
#define FILE_VALID_SET_FLAGS                    0x00000036

//
// Define the I/O status information return values for NtCreateFile/NtOpenFile
//

#define FILE_SUPERSEDED                 0x00000000
#define FILE_OPENED                     0x00000001
#define FILE_CREATED                    0x00000002
#define FILE_OVERWRITTEN                0x00000003
#define FILE_EXISTS                     0x00000004
#define FILE_DOES_NOT_EXIST             0x00000005

//
// Define special ByteOffset parameters for read and write operations
//

#define FILE_WRITE_TO_END_OF_FILE       0xffffffff
#define FILE_USE_FILE_POINTER_POSITION  0xfffffffe

//
// Define alignment requirement values
//

#define FILE_BYTE_ALIGNMENT             0x00000000
#define FILE_WORD_ALIGNMENT             0x00000001
#define FILE_LONG_ALIGNMENT             0x00000003
#define FILE_QUAD_ALIGNMENT             0x00000007
#define FILE_OCTA_ALIGNMENT             0x0000000f
#define FILE_32_BYTE_ALIGNMENT          0x0000001f
#define FILE_64_BYTE_ALIGNMENT          0x0000003f
#define FILE_128_BYTE_ALIGNMENT         0x0000007f
#define FILE_256_BYTE_ALIGNMENT         0x000000ff
#define FILE_512_BYTE_ALIGNMENT         0x000001ff

//
// Define the maximum length of a filename string
//

#define MAXIMUM_FILENAME_LENGTH         256

//
// Define the various device characteristics flags
//

#define FILE_REMOVABLE_MEDIA                    0x00000001
#define FILE_READ_ONLY_DEVICE                   0x00000002
#define FILE_FLOPPY_DISKETTE                    0x00000004
#define FILE_WRITE_ONCE_MEDIA                   0x00000008
#define FILE_REMOTE_DEVICE                      0x00000010
#define FILE_DEVICE_IS_MOUNTED                  0x00000020
#define FILE_VIRTUAL_VOLUME                     0x00000040
#define FILE_AUTOGENERATED_DEVICE_NAME          0x00000080
#define FILE_DEVICE_SECURE_OPEN                 0x00000100
#define FILE_CHARACTERISTIC_PNP_DEVICE          0x00000800
#define FILE_CHARACTERISTIC_TS_DEVICE           0x00001000
#define FILE_CHARACTERISTIC_WEBDAV_DEVICE       0x00002000

//
// Define the base asynchronous I/O argument types
//

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    } DUMMYUNIONNAME;

    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

#if defined(_WIN64)

typedef struct _IO_STATUS_BLOCK32 {
    NTSTATUS Status;
    ULONG Information;
} IO_STATUS_BLOCK32, *PIO_STATUS_BLOCK32;

#endif

//
// Define an Asynchronous Procedure Call from I/O viewpoint
//

typedef
VOID
(NTAPI *PIO_APC_ROUTINE) (
    __in PVOID ApcContext,
    __in PIO_STATUS_BLOCK IoStatusBlock,
    __in ULONG Reserved
    );

#define PIO_APC_ROUTINE_DEFINED

//
// Define the session states and events
//
typedef enum _IO_SESSION_EVENT {
    IoSessionEventIgnore         = 0,
    IoSessionEventCreated,      // 1
    IoSessionEventTerminated,   // 2
    IoSessionEventConnected,    // 3
    IoSessionEventDisconnected, // 4
    IoSessionEventLogon,        // 5
    IoSessionEventLogoff,       // 6
    IoSessionEventMax
} IO_SESSION_EVENT, *PIO_SESSION_EVENT;

typedef enum _IO_SESSION_STATE {
    IoSessionStateCreated                = 1,
    IoSessionStateInitialized,          // 2
    IoSessionStateConnected,            // 3
    IoSessionStateDisconnected,         // 4
    IoSessionStateDisconnectedLoggedOn, // 5
    IoSessionStateLoggedOn,             // 6
    IoSessionStateLoggedOff,            // 7
    IoSessionStateTerminated,           // 8
    IoSessionStateMax
} IO_SESSION_STATE, *PIO_SESSION_STATE;

//
// Define masks that determine which events a driver that registers for
// callbacks care about
//

#define IO_SESSION_STATE_ALL_EVENTS             0xffffffff
#define IO_SESSION_STATE_CREATION_EVENT         0x00000001
#define IO_SESSION_STATE_TERMINATION_EVENT      0x00000002
#define IO_SESSION_STATE_CONNECT_EVENT          0x00000004
#define IO_SESSION_STATE_DISCONNECT_EVENT       0x00000008
#define IO_SESSION_STATE_LOGON_EVENT            0x00000010
#define IO_SESSION_STATE_LOGOFF_EVENT           0x00000020

#define IO_SESSION_STATE_VALID_EVENT_MASK       0x0000003f

#define IO_SESSION_MAX_PAYLOAD_SIZE             256L

//
// Payload structures
//

// IoSessionEventConnected
typedef struct _IO_SESSION_CONNECT_INFO {
    ULONG SessionId;
    BOOLEAN LocalSession;
} IO_SESSION_CONNECT_INFO, *PIO_SESSION_CONNECT_INFO;


//
// Define the file information class values
//
// WARNING:  The order of the following values are assumed by the I/O system.
//           Any changes made here should be reflected there as well.
//

typedef enum _FILE_INFORMATION_CLASS {
    FileDirectoryInformation         = 1,
    FileFullDirectoryInformation,   // 2
    FileBothDirectoryInformation,   // 3
    FileBasicInformation,           // 4
    FileStandardInformation,        // 5
    FileInternalInformation,        // 6
    FileEaInformation,              // 7
    FileAccessInformation,          // 8
    FileNameInformation,            // 9
    FileRenameInformation,          // 10
    FileLinkInformation,            // 11
    FileNamesInformation,           // 12
    FileDispositionInformation,     // 13
    FilePositionInformation,        // 14
    FileFullEaInformation,          // 15
    FileModeInformation,            // 16
    FileAlignmentInformation,       // 17
    FileAllInformation,             // 18
    FileAllocationInformation,      // 19
    FileEndOfFileInformation,       // 20
    FileAlternateNameInformation,   // 21
    FileStreamInformation,          // 22
    FilePipeInformation,            // 23
    FilePipeLocalInformation,       // 24
    FilePipeRemoteInformation,      // 25
    FileMailslotQueryInformation,   // 26
    FileMailslotSetInformation,     // 27
    FileCompressionInformation,     // 28
    FileObjectIdInformation,        // 29
    FileCompletionInformation,      // 30
    FileMoveClusterInformation,     // 31
    FileQuotaInformation,           // 32
    FileReparsePointInformation,    // 33
    FileNetworkOpenInformation,     // 34
    FileAttributeTagInformation,    // 35
    FileTrackingInformation,        // 36
    FileIdBothDirectoryInformation, // 37
    FileIdFullDirectoryInformation, // 38
    FileValidDataLengthInformation, // 39
    FileShortNameInformation,       // 40
    FileIoCompletionNotificationInformation, // 41
    FileIoStatusBlockRangeInformation,       // 42
    FileIoPriorityHintInformation,           // 43
    FileSfioReserveInformation,              // 44
    FileSfioVolumeInformation,               // 45
    FileHardLinkInformation,                 // 46
    FileProcessIdsUsingFileInformation,      // 47
    FileNormalizedNameInformation,           // 48
    FileNetworkPhysicalNameInformation,      // 49
    FileIdGlobalTxDirectoryInformation,      // 50
    FileIsRemoteDeviceInformation,           // 51
    FileAttributeCacheInformation,           // 52
    FileNumaNodeInformation,                 // 53
    FileStandardLinkInformation,             // 54
    FileRemoteProtocolInformation,           // 55
    FileMaximumInformation
} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;

//
// Define the various structures which are returned on query operations
//

typedef struct _FILE_BASIC_INFORMATION {
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    ULONG FileAttributes;
} FILE_BASIC_INFORMATION, *PFILE_BASIC_INFORMATION;

typedef struct _FILE_STANDARD_INFORMATION {
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG NumberOfLinks;
    BOOLEAN DeletePending;
    BOOLEAN Directory;
} FILE_STANDARD_INFORMATION, *PFILE_STANDARD_INFORMATION;


typedef struct _FILE_POSITION_INFORMATION {
    LARGE_INTEGER CurrentByteOffset;
} FILE_POSITION_INFORMATION, *PFILE_POSITION_INFORMATION;


typedef struct _FILE_NETWORK_OPEN_INFORMATION {
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG FileAttributes;
} FILE_NETWORK_OPEN_INFORMATION, *PFILE_NETWORK_OPEN_INFORMATION;





typedef struct _FILE_FULL_EA_INFORMATION {
    ULONG NextEntryOffset;
    UCHAR Flags;
    UCHAR EaNameLength;
    USHORT EaValueLength;
    CHAR EaName[1];
} FILE_FULL_EA_INFORMATION, *PFILE_FULL_EA_INFORMATION;


//
// Support to reserve bandwidth for a file handle.
//

typedef struct _FILE_SFIO_RESERVE_INFORMATION {
    ULONG RequestsPerPeriod;
    ULONG Period;
    BOOLEAN RetryFailures;
    BOOLEAN Discardable;
    ULONG RequestSize;
    ULONG NumOutstandingRequests;
} FILE_SFIO_RESERVE_INFORMATION, *PFILE_SFIO_RESERVE_INFORMATION;

//
// Support to query bandwidth properties of a volume.
//

typedef struct _FILE_SFIO_VOLUME_INFORMATION {
    ULONG MaximumRequestsPerPeriod;
    ULONG MinimumPeriod;
    ULONG MinimumTransferSize;
} FILE_SFIO_VOLUME_INFORMATION, *PFILE_SFIO_VOLUME_INFORMATION;

//
// Support to set priority hints on a filehandle.
//

typedef enum _IO_PRIORITY_HINT {
    IoPriorityVeryLow = 0,          // Defragging, content indexing and other background I/Os
    IoPriorityLow,                  // Prefetching for applications.
    IoPriorityNormal,               // Normal I/Os
    IoPriorityHigh,                 // Used by filesystems for checkpoint I/O
    IoPriorityCritical,             // Used by memory manager. Not available for applications.
    MaxIoPriorityTypes
} IO_PRIORITY_HINT;

typedef struct _FILE_IO_PRIORITY_HINT_INFORMATION {
    IO_PRIORITY_HINT   PriorityHint;
} FILE_IO_PRIORITY_HINT_INFORMATION, *PFILE_IO_PRIORITY_HINT_INFORMATION;

//
// Don't queue an entry to an associated completion port if returning success
// synchronously.
//
#define FILE_SKIP_COMPLETION_PORT_ON_SUCCESS    0x1

//
// Don't set the file handle event on IO completion.
//
#define FILE_SKIP_SET_EVENT_ON_HANDLE           0x2

//
// Don't set user supplied event on successful fast-path IO completion.
//
#define FILE_SKIP_SET_USER_EVENT_ON_FAST_IO     0x4

typedef  struct _FILE_IO_COMPLETION_NOTIFICATION_INFORMATION {
    ULONG Flags;
} FILE_IO_COMPLETION_NOTIFICATION_INFORMATION, *PFILE_IO_COMPLETION_NOTIFICATION_INFORMATION;

typedef  struct _FILE_PROCESS_IDS_USING_FILE_INFORMATION {
    ULONG NumberOfProcessIdsInList;
    ULONG_PTR ProcessIdList[1];
} FILE_PROCESS_IDS_USING_FILE_INFORMATION, *PFILE_PROCESS_IDS_USING_FILE_INFORMATION;

typedef struct _FILE_IS_REMOTE_DEVICE_INFORMATION {
    BOOLEAN IsRemote;
} FILE_IS_REMOTE_DEVICE_INFORMATION, *PFILE_IS_REMOTE_DEVICE_INFORMATION;

typedef struct _FILE_NUMA_NODE_INFORMATION {
    USHORT NodeNumber;
} FILE_NUMA_NODE_INFORMATION, *PFILE_NUMA_NODE_INFORMATION;

//
// Set an range of IOSBs on a file handle.
//

typedef struct _FILE_IOSTATUSBLOCK_RANGE_INFORMATION {
    PUCHAR       IoStatusBlockRange;
    ULONG        Length;
} FILE_IOSTATUSBLOCK_RANGE_INFORMATION, *PFILE_IOSTATUSBLOCK_RANGE_INFORMATION;

//
// Define the file system information class values
//
// WARNING:  The order of the following values are assumed by the I/O system.
//           Any changes made here should be reflected there as well.

typedef enum _FSINFOCLASS {
    FileFsVolumeInformation       = 1,
    FileFsLabelInformation,      // 2
    FileFsSizeInformation,       // 3
    FileFsDeviceInformation,     // 4
    FileFsAttributeInformation,  // 5
    FileFsControlInformation,    // 6
    FileFsFullSizeInformation,   // 7
    FileFsObjectIdInformation,   // 8
    FileFsDriverPathInformation, // 9
    FileFsVolumeFlagsInformation,// 10
    FileFsMaximumInformation
} FS_INFORMATION_CLASS, *PFS_INFORMATION_CLASS;


typedef struct _FILE_FS_DEVICE_INFORMATION {
    DEVICE_TYPE DeviceType;
    ULONG Characteristics;
} FILE_FS_DEVICE_INFORMATION, *PFILE_FS_DEVICE_INFORMATION;

//
// Define the I/O bus interface types.
//

typedef enum _INTERFACE_TYPE {
    InterfaceTypeUndefined = -1,
    Internal,
    Isa,
    Eisa,
    MicroChannel,
    TurboChannel,
    PCIBus,
    VMEBus,
    NuBus,
    PCMCIABus,
    CBus,
    MPIBus,
    MPSABus,
    ProcessorInternal,
    InternalPowerBus,
    PNPISABus,
    PNPBus,
    Vmcs,
    MaximumInterfaceType
}INTERFACE_TYPE, *PINTERFACE_TYPE;

//
// Define the DMA transfer widths.
//

typedef enum _DMA_WIDTH {
    Width8Bits,
    Width16Bits,
    Width32Bits,
    MaximumDmaWidth
}DMA_WIDTH, *PDMA_WIDTH;

//
// Define DMA transfer speeds.
//

typedef enum _DMA_SPEED {
    Compatible,
    TypeA,
    TypeB,
    TypeC,
    TypeF,
    MaximumDmaSpeed
}DMA_SPEED, *PDMA_SPEED;

//
// Define Interface reference/dereference routines for
//  Interfaces exported by IRP_MN_QUERY_INTERFACE
//

typedef VOID (*PINTERFACE_REFERENCE)(PVOID Context);
typedef VOID (*PINTERFACE_DEREFERENCE)(PVOID Context);

//
// Define I/O Driver error log packet structure.  This structure is filled in
// by the driver.
//

typedef struct _IO_ERROR_LOG_PACKET {
    UCHAR MajorFunctionCode;
    UCHAR RetryCount;
    USHORT DumpDataSize;
    USHORT NumberOfStrings;
    USHORT StringOffset;
    USHORT EventCategory;
    NTSTATUS ErrorCode;
    ULONG UniqueErrorValue;
    NTSTATUS FinalStatus;
    ULONG SequenceNumber;
    ULONG IoControlCode;
    LARGE_INTEGER DeviceOffset;
    ULONG DumpData[1];
}IO_ERROR_LOG_PACKET, *PIO_ERROR_LOG_PACKET;

//
// Define the I/O error log message.  This message is sent by the error log
// thread over the lpc port.
//

typedef struct _IO_ERROR_LOG_MESSAGE {
    USHORT Type;
    USHORT Size;
    USHORT DriverNameLength;
    LARGE_INTEGER TimeStamp;
    ULONG DriverNameOffset;
    IO_ERROR_LOG_PACKET EntryData;
}IO_ERROR_LOG_MESSAGE, *PIO_ERROR_LOG_MESSAGE;

//
// Define the maximum message size that will be sent over the LPC to the
// application reading the error log entries.
//

//
// Regardless of LPC size restrictions, ERROR_LOG_MAXIMUM_SIZE must remain
// a value that can fit in a UCHAR.
//

#define ERROR_LOG_LIMIT_SIZE (256-16)

//
// This limit, exclusive of IO_ERROR_LOG_MESSAGE_HEADER_LENGTH, also applies
// to IO_ERROR_LOG_MESSAGE_LENGTH
//

#define IO_ERROR_LOG_MESSAGE_HEADER_LENGTH (sizeof(IO_ERROR_LOG_MESSAGE) -    \
                                            sizeof(IO_ERROR_LOG_PACKET) +     \
                                            (sizeof(WCHAR) * 40))

#define ERROR_LOG_MESSAGE_LIMIT_SIZE                                          \
    (ERROR_LOG_LIMIT_SIZE + IO_ERROR_LOG_MESSAGE_HEADER_LENGTH)

//
// IO_ERROR_LOG_MESSAGE_LENGTH is
// min(PORT_MAXIMUM_MESSAGE_LENGTH, ERROR_LOG_MESSAGE_LIMIT_SIZE)
//

#define IO_ERROR_LOG_MESSAGE_LENGTH                                           \
    ((PORT_MAXIMUM_MESSAGE_LENGTH > ERROR_LOG_MESSAGE_LIMIT_SIZE) ?           \
        ERROR_LOG_MESSAGE_LIMIT_SIZE :                                        \
        PORT_MAXIMUM_MESSAGE_LENGTH)

//
// Define the maximum packet size a driver can allocate.
//

#define ERROR_LOG_MAXIMUM_SIZE (IO_ERROR_LOG_MESSAGE_LENGTH -                 \
                                IO_ERROR_LOG_MESSAGE_HEADER_LENGTH)


#ifdef _WIN64
#define PORT_MAXIMUM_MESSAGE_LENGTH 512
#else
#define PORT_MAXIMUM_MESSAGE_LENGTH 256
#endif

//
// Registry Specific Access Rights.
//

#define KEY_QUERY_VALUE         (0x0001)
#define KEY_SET_VALUE           (0x0002)
#define KEY_CREATE_SUB_KEY      (0x0004)
#define KEY_ENUMERATE_SUB_KEYS  (0x0008)
#define KEY_NOTIFY              (0x0010)
#define KEY_CREATE_LINK         (0x0020)
#define KEY_WOW64_32KEY         (0x0200)
#define KEY_WOW64_64KEY         (0x0100)
#define KEY_WOW64_RES           (0x0300)

#define KEY_READ                ((STANDARD_RIGHTS_READ       |\
                                  KEY_QUERY_VALUE            |\
                                  KEY_ENUMERATE_SUB_KEYS     |\
                                  KEY_NOTIFY)                 \
                                  &                           \
                                 (~SYNCHRONIZE))


#define KEY_WRITE               ((STANDARD_RIGHTS_WRITE      |\
                                  KEY_SET_VALUE              |\
                                  KEY_CREATE_SUB_KEY)         \
                                  &                           \
                                 (~SYNCHRONIZE))

#define KEY_EXECUTE             ((KEY_READ)                   \
                                  &                           \
                                 (~SYNCHRONIZE))

#define KEY_ALL_ACCESS          ((STANDARD_RIGHTS_ALL        |\
                                  KEY_QUERY_VALUE            |\
                                  KEY_SET_VALUE              |\
                                  KEY_CREATE_SUB_KEY         |\
                                  KEY_ENUMERATE_SUB_KEYS     |\
                                  KEY_NOTIFY                 |\
                                  KEY_CREATE_LINK)            \
                                  &                           \
                                 (~SYNCHRONIZE))

//
// Open/Create Options
//

#define REG_OPTION_RESERVED         (0x00000000L)   // Parameter is reserved

#define REG_OPTION_NON_VOLATILE     (0x00000000L)   // Key is preserved
                                                    // when system is rebooted

#define REG_OPTION_VOLATILE         (0x00000001L)   // Key is not preserved
                                                    // when system is rebooted

#define REG_OPTION_CREATE_LINK      (0x00000002L)   // Created key is a
                                                    // symbolic link

#define REG_OPTION_BACKUP_RESTORE   (0x00000004L)   // open for backup or restore
                                                    // special access rules
                                                    // privilege required

#define REG_OPTION_OPEN_LINK        (0x00000008L)   // Open symbolic link

#define REG_LEGAL_OPTION            \
                (REG_OPTION_RESERVED            |\
                 REG_OPTION_NON_VOLATILE        |\
                 REG_OPTION_VOLATILE            |\
                 REG_OPTION_CREATE_LINK         |\
                 REG_OPTION_BACKUP_RESTORE      |\
                 REG_OPTION_OPEN_LINK)

#define REG_OPEN_LEGAL_OPTION       \
                (REG_OPTION_RESERVED            |\
                 REG_OPTION_BACKUP_RESTORE      |\
                 REG_OPTION_OPEN_LINK)

//
// Key creation/open disposition
//

#define REG_CREATED_NEW_KEY         (0x00000001L)   // New Registry Key created
#define REG_OPENED_EXISTING_KEY     (0x00000002L)   // Existing Key opened

//
// hive format to be used by Reg(Nt)SaveKeyEx
//
#define REG_STANDARD_FORMAT     1
#define REG_LATEST_FORMAT       2
#define REG_NO_COMPRESSION      4

//
// Key restore & hive load flags
//

#define REG_WHOLE_HIVE_VOLATILE         (0x00000001L)   // Restore whole hive volatile
#define REG_REFRESH_HIVE                (0x00000002L)   // Unwind changes to last flush
#define REG_NO_LAZY_FLUSH               (0x00000004L)   // Never lazy flush this hive
#define REG_FORCE_RESTORE               (0x00000008L)   // Force the restore process even when we have open handles on subkeys
#define REG_APP_HIVE                    (0x00000010L)   // Loads the hive visible to the calling process
#define REG_PROCESS_PRIVATE             (0x00000020L)   // Hive cannot be mounted by any other process while in use
#define REG_START_JOURNAL               (0x00000040L)   // Starts Hive Journal
#define REG_HIVE_EXACT_FILE_GROWTH      (0x00000080L)   // Grow hive file in exact 4k increments
#define REG_HIVE_NO_RM                  (0x00000100L)   // No RM is started for this hive (no transactions)
#define REG_HIVE_SINGLE_LOG             (0x00000200L)   // Legacy single logging is used for this hive
#define REG_BOOT_HIVE                   (0x00000400L)   // This hive might be used by the OS loader

//
// Unload Flags
//
#define REG_FORCE_UNLOAD            1

//
// Notify filter values
//

#define REG_NOTIFY_CHANGE_NAME          (0x00000001L) // Create or delete (child)
#define REG_NOTIFY_CHANGE_ATTRIBUTES    (0x00000002L)
#define REG_NOTIFY_CHANGE_LAST_SET      (0x00000004L) // time stamp
#define REG_NOTIFY_CHANGE_SECURITY      (0x00000008L)

#define REG_LEGAL_CHANGE_FILTER                 \
                (REG_NOTIFY_CHANGE_NAME          |\
                 REG_NOTIFY_CHANGE_ATTRIBUTES    |\
                 REG_NOTIFY_CHANGE_LAST_SET      |\
                 REG_NOTIFY_CHANGE_SECURITY)
 
//
// Key query structures
//

typedef struct _KEY_BASIC_INFORMATION {
    LARGE_INTEGER LastWriteTime;
    ULONG   TitleIndex;
    ULONG   NameLength;
    WCHAR   Name[1];            // Variable length string
} KEY_BASIC_INFORMATION, *PKEY_BASIC_INFORMATION;

typedef struct _KEY_NODE_INFORMATION {
    LARGE_INTEGER LastWriteTime;
    ULONG   TitleIndex;
    ULONG   ClassOffset;
    ULONG   ClassLength;
    ULONG   NameLength;
    WCHAR   Name[1];            // Variable length string
//          Class[1];           // Variable length string not declared
} KEY_NODE_INFORMATION, *PKEY_NODE_INFORMATION;

typedef struct _KEY_FULL_INFORMATION {
    LARGE_INTEGER LastWriteTime;
    ULONG   TitleIndex;
    ULONG   ClassOffset;
    ULONG   ClassLength;
    ULONG   SubKeys;
    ULONG   MaxNameLen;
    ULONG   MaxClassLen;
    ULONG   Values;
    ULONG   MaxValueNameLen;
    ULONG   MaxValueDataLen;
    WCHAR   Class[1];           // Variable length
} KEY_FULL_INFORMATION, *PKEY_FULL_INFORMATION;

typedef enum _KEY_INFORMATION_CLASS {
    KeyBasicInformation,
    KeyNodeInformation,
    KeyFullInformation,
    KeyNameInformation,
    KeyCachedInformation,
    KeyFlagsInformation,
    KeyVirtualizationInformation,
    KeyHandleTagsInformation,
    MaxKeyInfoClass  // MaxKeyInfoClass should always be the last enum
} KEY_INFORMATION_CLASS;

typedef struct _KEY_WRITE_TIME_INFORMATION {
    LARGE_INTEGER LastWriteTime;
} KEY_WRITE_TIME_INFORMATION, *PKEY_WRITE_TIME_INFORMATION;

typedef struct _KEY_WOW64_FLAGS_INFORMATION {
    ULONG   UserFlags;
} KEY_WOW64_FLAGS_INFORMATION, *PKEY_WOW64_FLAGS_INFORMATION;

typedef struct _KEY_HANDLE_TAGS_INFORMATION {
    ULONG   HandleTags;
} KEY_HANDLE_TAGS_INFORMATION, *PKEY_HANDLE_TAGS_INFORMATION;

typedef struct _KEY_CONTROL_FLAGS_INFORMATION {
    ULONG   ControlFlags;
} KEY_CONTROL_FLAGS_INFORMATION, *PKEY_CONTROL_FLAGS_INFORMATION;

typedef struct _KEY_SET_VIRTUALIZATION_INFORMATION {
    ULONG   VirtualTarget           : 1; // Tells if the key is a virtual target key. 
    ULONG   VirtualStore	        : 1; // Tells if the key is a virtual store key.
    ULONG   VirtualSource           : 1; // Tells if the key has been virtualized at least one (virtual hint)
    ULONG   Reserved                : 29;   
} KEY_SET_VIRTUALIZATION_INFORMATION, *PKEY_SET_VIRTUALIZATION_INFORMATION;

typedef enum _KEY_SET_INFORMATION_CLASS {
    KeyWriteTimeInformation,
    KeyWow64FlagsInformation,
    KeyControlFlagsInformation,
    KeySetVirtualizationInformation,
    KeySetDebugInformation,
    KeySetHandleTagsInformation,
    MaxKeySetInfoClass  // MaxKeySetInfoClass should always be the last enum
} KEY_SET_INFORMATION_CLASS;

//
// Value entry query structures
//

typedef struct _KEY_VALUE_BASIC_INFORMATION {
    ULONG   TitleIndex;
    ULONG   Type;
    ULONG   NameLength;
    WCHAR   Name[1];            // Variable size
} KEY_VALUE_BASIC_INFORMATION, *PKEY_VALUE_BASIC_INFORMATION;

typedef struct _KEY_VALUE_FULL_INFORMATION {
    ULONG   TitleIndex;
    ULONG   Type;
    ULONG   DataOffset;
    ULONG   DataLength;
    ULONG   NameLength;
    WCHAR   Name[1];            // Variable size
//          Data[1];            // Variable size data not declared
} KEY_VALUE_FULL_INFORMATION, *PKEY_VALUE_FULL_INFORMATION;

typedef struct _KEY_VALUE_PARTIAL_INFORMATION {
    ULONG   TitleIndex;
    ULONG   Type;
    ULONG   DataLength;
    UCHAR   Data[1];            // Variable size
} KEY_VALUE_PARTIAL_INFORMATION, *PKEY_VALUE_PARTIAL_INFORMATION;

typedef struct _KEY_VALUE_PARTIAL_INFORMATION_ALIGN64 {
    ULONG   Type;
    ULONG   DataLength;
    UCHAR   Data[1];            // Variable size
} KEY_VALUE_PARTIAL_INFORMATION_ALIGN64, *PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64;

typedef struct _KEY_VALUE_ENTRY {
    PUNICODE_STRING ValueName;
    ULONG           DataLength;
    ULONG           DataOffset;
    ULONG           Type;
} KEY_VALUE_ENTRY, *PKEY_VALUE_ENTRY;

typedef enum _KEY_VALUE_INFORMATION_CLASS {
    KeyValueBasicInformation,
    KeyValueFullInformation,
    KeyValuePartialInformation,
    KeyValueFullInformationAlign64,
    KeyValuePartialInformationAlign64,
    MaxKeyValueInfoClass  // MaxKeyValueInfoClass should always be the last enum
} KEY_VALUE_INFORMATION_CLASS;



#define OBJ_NAME_PATH_SEPARATOR ((WCHAR)L'\\')


//
// Object Manager Object Type Specific Access Rights.
//

#define OBJECT_TYPE_CREATE (0x0001)

#define OBJECT_TYPE_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0x1)

//
// Object Manager Directory Specific Access Rights.
//

#define DIRECTORY_QUERY                 (0x0001)
#define DIRECTORY_TRAVERSE              (0x0002)
#define DIRECTORY_CREATE_OBJECT         (0x0004)
#define DIRECTORY_CREATE_SUBDIRECTORY   (0x0008)

#define DIRECTORY_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0xF)

//begin_winnt

//
// Object Manager Symbolic Link Specific Access Rights.
//

//end_winnt

#define SYMBOLIC_LINK_QUERY (0x0001)

#define SYMBOLIC_LINK_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0x1)

typedef struct _OBJECT_NAME_INFORMATION {
    UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION;

#define DUPLICATE_CLOSE_SOURCE      0x00000001  
#define DUPLICATE_SAME_ACCESS       0x00000002  
#define DUPLICATE_SAME_ATTRIBUTES   0x00000004

//
// Section Information Structures.
//

typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;

//
// Section Access Rights.
//


#define SECTION_QUERY                0x0001
#define SECTION_MAP_WRITE            0x0002
#define SECTION_MAP_READ             0x0004
#define SECTION_MAP_EXECUTE          0x0008
#define SECTION_EXTEND_SIZE          0x0010
#define SECTION_MAP_EXECUTE_EXPLICIT 0x0020 // not included in SECTION_ALL_ACCESS

#define SECTION_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED|SECTION_QUERY|\
                            SECTION_MAP_WRITE |      \
                            SECTION_MAP_READ |       \
                            SECTION_MAP_EXECUTE |    \
                            SECTION_EXTEND_SIZE)

#define SESSION_QUERY_ACCESS  0x0001
#define SESSION_MODIFY_ACCESS 0x0002

#define SESSION_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED |  \
                            SESSION_QUERY_ACCESS |             \
                            SESSION_MODIFY_ACCESS)



#define SEGMENT_ALL_ACCESS SECTION_ALL_ACCESS

#define PAGE_NOACCESS          0x01     
#define PAGE_READONLY          0x02     
#define PAGE_READWRITE         0x04     
#define PAGE_WRITECOPY         0x08     
#define PAGE_EXECUTE           0x10     
#define PAGE_EXECUTE_READ      0x20     
#define PAGE_EXECUTE_READWRITE 0x40     
#define PAGE_EXECUTE_WRITECOPY 0x80     
#define PAGE_GUARD            0x100     
#define PAGE_NOCACHE          0x200     
#define PAGE_WRITECOMBINE     0x400     

#define MEM_COMMIT           0x1000     
#define MEM_RESERVE          0x2000     
#define MEM_DECOMMIT         0x4000     
#define MEM_RELEASE          0x8000     
#define MEM_FREE            0x10000     
#define MEM_PRIVATE         0x20000     
#define MEM_MAPPED          0x40000     
#define MEM_RESET           0x80000     
#define MEM_TOP_DOWN       0x100000     
#define MEM_LARGE_PAGES  0x20000000     
#define MEM_4MB_PAGES    0x80000000     
#define SEC_RESERVE       0x4000000     
#define SEC_COMMIT        0x8000000     
#define SEC_LARGE_PAGES  0x80000000     
#define PROCESS_DUP_HANDLE                 (0x0040)  
#if (NTDDI_VERSION >= NTDDI_VISTA)
#define PROCESS_ALL_ACCESS        (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | \
                                   0xFFFF)
#else
#define PROCESS_ALL_ACCESS        (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | \
                                   0xFFF)
#endif

#if defined(_WIN64)

#define MAXIMUM_PROC_PER_GROUP 64

#else

#define MAXIMUM_PROC_PER_GROUP 32

#endif

#define MAXIMUM_PROCESSORS          MAXIMUM_PROC_PER_GROUP


//
// Thread Specific Access Rights
//

#define THREAD_TERMINATE                 (0x0001)  
#define THREAD_SUSPEND_RESUME            (0x0002)  
#define THREAD_ALERT                     (0x0004)
#define THREAD_GET_CONTEXT               (0x0008)  
#define THREAD_SET_CONTEXT               (0x0010)  
#define THREAD_SET_INFORMATION           (0x0020)  
#define THREAD_SET_LIMITED_INFORMATION   (0x0400)  
#define THREAD_QUERY_LIMITED_INFORMATION (0x0800)  
#if (NTDDI_VERSION >= NTDDI_VISTA)
#define THREAD_ALL_ACCESS         (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | \
                                   0xFFFF)
#else
#define THREAD_ALL_ACCESS         (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | \
                                   0x3FF)
#endif
//
// ClientId
//

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;
typedef CLIENT_ID *PCLIENT_ID;

#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )  
#define ZwCurrentProcess() NtCurrentProcess()         
#define NtCurrentThread() ( (HANDLE)(LONG_PTR) -2 )   
#define ZwCurrentThread() NtCurrentThread()           

//
// =========================================
// Define GUIDs which represent well-known power schemes
// =========================================
//

//
// Maximum Power Savings - indicates that very aggressive power savings measures will be used to help
//                         stretch battery life.
//
// {a1841308-3541-4fab-bc81-f71556f20b4a}
//
DEFINE_GUID( GUID_MAX_POWER_SAVINGS, 0xA1841308, 0x3541, 0x4FAB, 0xBC, 0x81, 0xF7, 0x15, 0x56, 0xF2, 0x0B, 0x4A );

//
// No Power Savings - indicates that almost no power savings measures will be used.
//
// {8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c}
//
DEFINE_GUID( GUID_MIN_POWER_SAVINGS, 0x8C5E7FDA, 0xE8BF, 0x4A96, 0x9A, 0x85, 0xA6, 0xE2, 0x3A, 0x8C, 0x63, 0x5C );

//
// Typical Power Savings - indicates that fairly aggressive power savings measures will be used.
//
// {381b4222-f694-41f0-9685-ff5bb260df2e}
//
DEFINE_GUID( GUID_TYPICAL_POWER_SAVINGS, 0x381B4222, 0xF694, 0x41F0, 0x96, 0x85, 0xFF, 0x5B, 0xB2, 0x60, 0xDF, 0x2E );

//
// This is a special GUID that represents "no subgroup" of settings.  That is, it indicates
// that settings that are in the root of the power policy hierarchy as opposed to settings
// that are buried under a subgroup of settings.  This should be used when querying for
// power settings that may not fall into a subgroup.
//
DEFINE_GUID( NO_SUBGROUP_GUID, 0xFEA3413E, 0x7E05, 0x4911, 0x9A, 0x71, 0x70, 0x03, 0x31, 0xF1, 0xC2, 0x94 );

//
// This is a special GUID that represents "every power scheme".  That is, it indicates
// that any write to this power scheme should be reflected to every scheme present.
// This allows users to write a single setting once and have it apply to all schemes.  They
// can then apply custom settings to specific power schemes that they care about.
//
DEFINE_GUID( ALL_POWERSCHEMES_GUID, 0x68A1E95E, 0x13EA, 0x41E1, 0x80, 0x11, 0x0C, 0x49, 0x6C, 0xA4, 0x90, 0xB0 );

//
// This is a special GUID that represents a 'personality' that each power scheme will have.
// In other words, each power scheme will have this key indicating "I'm most like *this* base
// power scheme."  This individual setting will have one of three settings:
// GUID_MAX_POWER_SAVINGS
// GUID_MIN_POWER_SAVINGS
// GUID_TYPICAL_POWER_SAVINGS
//
// This allows several features:
// 1. Drivers and applications can register for notification of this GUID.  So when this power
//    scheme is activiated, this GUID's setting will be sent across the system and drivers/applications
//    can see "GUID_MAX_POWER_SAVINGS" which will tell them in a generic fashion "get real aggressive
//    about conserving power".
// 2. UserB may install a driver or application which creates power settings, and UserB may modify
//    those power settings.  Now UserA logs in.  How does he see those settings?  They simply don't
//    exist in his private power key.  Well they do exist over in the system power key.  When we
//    enumerate all the power settings in this system power key and don't find a corresponding entry
//    in the user's private power key, then we can go look at this "personality" key in the users
//    power scheme.  We can then go get a default value for the power setting, depending on which
//    "personality" power scheme is being operated on.  Here's an example:
//    A. UserB installs an application that creates a power setting Seetting1
//    B. UserB changes Setting1 to have a value of 50 because that's one of the possible settings
//       available for setting1.
//    C. UserB logs out
//    D. UserA logs in and his active power scheme is some custom scheme that was derived from
//       the GUID_TYPICAL_POWER_SAVINGS.  But remember that UserA has no setting1 in his
//       private power key.
//    E. When activating UserA's selected power scheme, all power settings in the system power key will
//       be enumerated (including Setting1).
//    F. The power manager will see that UserA has no Setting1 power setting in his private power scheme.
//    G. The power manager will query UserA's power scheme for its personality and retrieve
//       GUID_TYPICAL_POWER_SAVINGS.
//    H. The power manager then looks in Setting1 in the system power key and looks in its set of default
//       values for the corresponding value for GUID_TYPICAL_POWER_SAVINGS power schemes.
//    I. This derived power setting is applied.
DEFINE_GUID( GUID_POWERSCHEME_PERSONALITY, 0x245D8541, 0x3943, 0x4422, 0xB0, 0x25, 0x13, 0xA7, 0x84, 0xF6, 0x79, 0xB7 );

//
// Define a special GUID which will be used to define the active power scheme.
// User will register for this power setting GUID, and when the active power
// scheme changes, they'll get a callback where the payload is the GUID
// representing the active powerscheme.
// ( 31F9F286-5084-42FE-B720-2B0264993763 }
//
DEFINE_GUID( GUID_ACTIVE_POWERSCHEME, 0x31F9F286, 0x5084, 0x42FE, 0xB7, 0x20, 0x2B, 0x02, 0x64, 0x99, 0x37, 0x63 );

//
// =========================================
// Define GUIDs which represent well-known power settings
// =========================================
//

// Video settings
// --------------
//
// Specifies the subgroup which will contain all of the video
// settings for a single policy.
//
DEFINE_GUID( GUID_VIDEO_SUBGROUP, 0x7516B95F, 0xF776, 0x4464, 0x8C, 0x53, 0x06, 0x16, 0x7F, 0x40, 0xCC, 0x99 );

//
// Specifies (in seconds) how long we wait after the last user input has been
// recieved before we power off the video.
//
DEFINE_GUID( GUID_VIDEO_POWERDOWN_TIMEOUT, 0x3C0BC021, 0xC8A8, 0x4E07, 0xA9, 0x73, 0x6B, 0x14, 0xCB, 0xCB, 0x2B, 0x7E );

//
// Specifies whether adaptive display dimming is turned on or off.
// 82DBCF2D-CD67-40C5-BFDC-9F1A5CCD4663
//
DEFINE_GUID( GUID_VIDEO_ANNOYANCE_TIMEOUT, 0x82DBCF2D, 0xCD67, 0x40C5, 0xBF, 0xDC, 0x9F, 0x1A, 0x5C, 0xCD, 0x46, 0x63 );

//
// Specifies how much adaptive dim time out will be increased by.
// EED904DF-B142-4183-B10B-5A1197A37864
//
DEFINE_GUID( GUID_VIDEO_ADAPTIVE_PERCENT_INCREASE, 0xEED904DF, 0xB142, 0x4183, 0xB1, 0x0B, 0x5A, 0x11, 0x97, 0xA3, 0x78, 0x64 );

//
// Specifies (in seconds) how long we wait after the last user input has been
// recieved before we dim the video.
//
DEFINE_GUID( GUID_VIDEO_DIM_TIMEOUT, 0x17aaa29b, 0x8b43, 0x4b94, 0xaa, 0xfe, 0x35, 0xf6, 0x4d, 0xaa, 0xf1, 0xee);

//
// Specifies if the operating system should use adaptive timers (based on
// previous behavior) to power down the video,
//
DEFINE_GUID( GUID_VIDEO_ADAPTIVE_POWERDOWN, 0x90959D22, 0xD6A1, 0x49B9, 0xAF, 0x93, 0xBC, 0xE8, 0x85, 0xAD, 0x33, 0x5B );

//
// Specifies if the monitor is currently being powered or not.
// 02731015-4510-4526-99E6-E5A17EBD1AEA
//
DEFINE_GUID( GUID_MONITOR_POWER_ON, 0x02731015, 0x4510, 0x4526, 0x99, 0xE6, 0xE5, 0xA1, 0x7E, 0xBD, 0x1A, 0xEA );

//
// Monitor brightness policy when in normal state
// {aded5e82-b909-4619-9949-f5d71dac0bcb}
DEFINE_GUID(GUID_DEVICE_POWER_POLICY_VIDEO_BRIGHTNESS, 0xaded5e82L, 0xb909, 0x4619, 0x99, 0x49, 0xf5, 0xd7, 0x1d, 0xac, 0x0b, 0xcb);

//
//
// Monitor brightness policy when in dim state
// {f1fbfde2-a960-4165-9f88-50667911ce96}
DEFINE_GUID(GUID_DEVICE_POWER_POLICY_VIDEO_DIM_BRIGHTNESS, 0xf1fbfde2, 0xa960, 0x4165, 0x9f, 0x88, 0x50, 0x66, 0x79, 0x11, 0xce, 0x96);

//
// Current Monitor brightness
// {8ffee2c6-2d01-46be-adb9-398addc5b4ff}
DEFINE_GUID(GUID_VIDEO_CURRENT_MONITOR_BRIGHTNESS, 0x8ffee2c6, 0x2d01, 0x46be, 0xad, 0xb9, 0x39, 0x8a, 0xdd, 0xc5, 0xb4, 0xff);


//
// Specifies if the operating system should use ambient light sensor to change
// disply brightness adatively.
// {FBD9AA66-9553-4097-BA44-ED6E9D65EAB8}
DEFINE_GUID(GUID_VIDEO_ADAPTIVE_DISPLAY_BRIGHTNESS, 0xFBD9AA66, 0x9553, 0x4097, 0xBA, 0x44, 0xED, 0x6E, 0x9D, 0x65, 0xEA, 0xB8);

//
// Specifies a change in the session's display state.
// 73A5E93A-5BB1-4F93-895B-DBD0DA855967
//
// N.B. This is a session-specific notification, sent only to interactive
//      session registrants. Session 0 and kernel mode consumers do not receive
//      this notification.
DEFINE_GUID( GUID_SESSION_DISPLAY_STATE, 0x73A5E93A, 0x5BB1, 0x4F93, 0x89, 0x5B, 0xDB, 0xD0, 0xDA, 0x85, 0x59, 0x67 );

//
// Specifies a change in the current monitor's display state.
// 6fe69556-704a-47a0-8f24-c28d936fda47
//
DEFINE_GUID(GUID_CONSOLE_DISPLAY_STATE, 0x6fe69556, 0x704a, 0x47a0, 0x8f, 0x24, 0xc2, 0x8d, 0x93, 0x6f, 0xda, 0x47);

//
// Defines a guid for enabling/disabling the ability to create display required 
// power requests.
//
// {A9CEB8DA-CD46-44FB-A98B-02AF69DE4623}
//
DEFINE_GUID( GUID_ALLOW_DISPLAY_REQUIRED, 0xA9CEB8DA, 0xCD46, 0x44FB, 0xA9, 0x8B, 0x02, 0xAF, 0x69, 0xDE, 0x46, 0x23 );

// Harddisk settings
// -----------------
//
// Specifies the subgroup which will contain all of the harddisk
// settings for a single policy.
//
DEFINE_GUID( GUID_DISK_SUBGROUP, 0x0012EE47, 0x9041, 0x4B5D, 0x9B, 0x77, 0x53, 0x5F, 0xBA, 0x8B, 0x14, 0x42 );

//
// Specifies (in seconds) how long we wait after the last disk access
// before we power off the disk.
//
DEFINE_GUID( GUID_DISK_POWERDOWN_TIMEOUT, 0x6738E2C4, 0xE8A5, 0x4A42, 0xB1, 0x6A, 0xE0, 0x40, 0xE7, 0x69, 0x75, 0x6E );

//
// Specifies the amount of contiguous disk activity time to ignore when
// calculating disk idleness.
//
// 80e3c60e-bb94-4ad8-bbe0-0d3195efc663
//

DEFINE_GUID( GUID_DISK_BURST_IGNORE_THRESHOLD, 0x80e3c60e, 0xbb94, 0x4ad8, 0xbb, 0xe0, 0x0d, 0x31, 0x95, 0xef, 0xc6, 0x63 );

//
// Specifies if the operating system should use adaptive timers (based on
// previous behavior) to power down the disk,
//
DEFINE_GUID( GUID_DISK_ADAPTIVE_POWERDOWN, 0x396A32E1, 0x499A, 0x40B2, 0x91, 0x24, 0xA9, 0x6A, 0xFE, 0x70, 0x76, 0x67 );

// System sleep settings
// ---------------------
//
// Specifies the subgroup which will contain all of the sleep
// settings for a single policy.
// { 238C9FA8-0AAD-41ED-83F4-97BE242C8F20 }
//
DEFINE_GUID( GUID_SLEEP_SUBGROUP, 0x238C9FA8, 0x0AAD, 0x41ED, 0x83, 0xF4, 0x97, 0xBE, 0x24, 0x2C, 0x8F, 0x20 );

//
// Specifies an idle treshold percentage (0-100). The system must be this idle
// over a period of time in order to idle to sleep.
//
// N.B. DEPRECATED IN WINDOWS 6.1
//
DEFINE_GUID( GUID_SLEEP_IDLE_THRESHOLD, 0x81cd32e0, 0x7833, 0x44f3, 0x87, 0x37, 0x70, 0x81, 0xf3, 0x8d, 0x1f, 0x70 );

//
// Specifies (in seconds) how long we wait after the system is deemed
// "idle" before moving to standby (S1, S2 or S3).
//
DEFINE_GUID( GUID_STANDBY_TIMEOUT, 0x29F6C1DB, 0x86DA, 0x48C5, 0x9F, 0xDB, 0xF2, 0xB6, 0x7B, 0x1F, 0x44, 0xDA );

//
// Specifies (in seconds) how long the system should go back to sleep after
// waking unattended. 0 indicates that the standard standby/hibernate idle
// policy should be used instead.
//
// {7bc4a2f9-d8fc-4469-b07b-33eb785aaca0}
//
DEFINE_GUID( GUID_UNATTEND_SLEEP_TIMEOUT, 0x7bc4a2f9, 0xd8fc, 0x4469, 0xb0, 0x7b, 0x33, 0xeb, 0x78, 0x5a, 0xac, 0xa0 );

//
// Specifies (in seconds) how long we wait after the system is deemed
// "idle" before moving to hibernate (S4).
//
DEFINE_GUID( GUID_HIBERNATE_TIMEOUT, 0x9D7815A6, 0x7EE4, 0x497E, 0x88, 0x88, 0x51, 0x5A, 0x05, 0xF0, 0x23, 0x64 );

//
// Specifies whether or not Fast S4 should be enabled if the system supports it
// 94AC6D29-73CE-41A6-809F-6363BA21B47E
//
DEFINE_GUID( GUID_HIBERNATE_FASTS4_POLICY, 0x94AC6D29, 0x73CE, 0x41A6, 0x80, 0x9F, 0x63, 0x63, 0xBA, 0x21, 0xB4, 0x7E );

//
// Define a GUID for controlling the criticality of sleep state transitions.
// Critical sleep transitions do not query applications, services or drivers
// before transitioning the platform to a sleep state.
//
// {B7A27025-E569-46c2-A504-2B96CAD225A1}
//
DEFINE_GUID( GUID_CRITICAL_POWER_TRANSITION,  0xB7A27025, 0xE569, 0x46c2, 0xA5, 0x04, 0x2B, 0x96, 0xCA, 0xD2, 0x25, 0xA1);

//
// Specifies if the system is entering or exiting 'away mode'.
// 98A7F580-01F7-48AA-9C0F-44352C29E5C0
//
DEFINE_GUID( GUID_SYSTEM_AWAYMODE, 0x98A7F580, 0x01F7, 0x48AA, 0x9C, 0x0F, 0x44, 0x35, 0x2C, 0x29, 0xE5, 0xC0 );

// Specify whether away mode is allowed
//
// {25DFA149-5DD1-4736-B5AB-E8A37B5B8187}
//
DEFINE_GUID( GUID_ALLOW_AWAYMODE, 0x25dfa149, 0x5dd1, 0x4736, 0xb5, 0xab, 0xe8, 0xa3, 0x7b, 0x5b, 0x81, 0x87 );

//
// Defines a guid for enabling/disabling standby (S1-S3) states. This does not
// affect hibernation (S4).
//
// {abfc2519-3608-4c2a-94ea-171b0ed546ab}
//
DEFINE_GUID( GUID_ALLOW_STANDBY_STATES, 0xabfc2519, 0x3608, 0x4c2a, 0x94, 0xea, 0x17, 0x1b, 0x0e, 0xd5, 0x46, 0xab );

//
// Defines a guid for enabling/disabling the ability to wake via RTC.
//
// {BD3B718A-0680-4D9D-8AB2-E1D2B4AC806D}
//
DEFINE_GUID( GUID_ALLOW_RTC_WAKE, 0xBD3B718A, 0x0680, 0x4D9D, 0x8A, 0xB2, 0xE1, 0xD2, 0xB4, 0xAC, 0x80, 0x6D );

//
// Defines a guid for enabling/disabling the ability to create system required 
// power requests.
//
// {A4B195F5-8225-47D8-8012-9D41369786E2}
//
DEFINE_GUID( GUID_ALLOW_SYSTEM_REQUIRED, 0xA4B195F5, 0x8225, 0x47D8, 0x80, 0x12, 0x9D, 0x41, 0x36, 0x97, 0x86, 0xE2 );
  
// System button actions
// ---------------------
//
//
// Specifies the subgroup which will contain all of the system button
// settings for a single policy.
//
DEFINE_GUID( GUID_SYSTEM_BUTTON_SUBGROUP, 0x4F971E89, 0xEEBD, 0x4455, 0xA8, 0xDE, 0x9E, 0x59, 0x04, 0x0E, 0x73, 0x47 );

// Specifies (in a POWER_ACTION_POLICY structure) the appropriate action to
// take when the system power button is pressed.
//
DEFINE_GUID( GUID_POWERBUTTON_ACTION, 0x7648EFA3, 0xDD9C, 0x4E3E, 0xB5, 0x66, 0x50, 0xF9, 0x29, 0x38, 0x62, 0x80 );
DEFINE_GUID( GUID_POWERBUTTON_ACTION_FLAGS, 0x857E7FAC, 0x034B, 0x4704, 0xAB, 0xB1, 0xBC, 0xA5, 0x4A, 0xA3, 0x14, 0x78 );

//
// Specifies (in a POWER_ACTION_POLICY structure) the appropriate action to
// take when the system sleep button is pressed.
//
DEFINE_GUID( GUID_SLEEPBUTTON_ACTION, 0x96996BC0, 0xAD50, 0x47EC, 0x92, 0x3B, 0x6F, 0x41, 0x87, 0x4D, 0xD9, 0xEB );
DEFINE_GUID( GUID_SLEEPBUTTON_ACTION_FLAGS, 0x2A160AB1, 0xB69D, 0x4743, 0xB7, 0x18, 0xBF, 0x14, 0x41, 0xD5, 0xE4, 0x93 );

//
// Specifies (in a POWER_ACTION_POLICY structure) the appropriate action to
// take when the system sleep button is pressed.
// { A7066653-8D6C-40A8-910E-A1F54B84C7E5 }
//
DEFINE_GUID( GUID_USERINTERFACEBUTTON_ACTION, 0xA7066653, 0x8D6C, 0x40A8, 0x91, 0x0E, 0xA1, 0xF5, 0x4B, 0x84, 0xC7, 0xE5 );

//
// Specifies (in a POWER_ACTION_POLICY structure) the appropriate action to
// take when the system lid is closed.
//
DEFINE_GUID( GUID_LIDCLOSE_ACTION, 0x5CA83367, 0x6E45, 0x459F, 0xA2, 0x7B, 0x47, 0x6B, 0x1D, 0x01, 0xC9, 0x36 );
DEFINE_GUID( GUID_LIDCLOSE_ACTION_FLAGS, 0x97E969AC, 0x0D6C, 0x4D08, 0x92, 0x7C, 0xD7, 0xBD, 0x7A, 0xD7, 0x85, 0x7B );
DEFINE_GUID( GUID_LIDOPEN_POWERSTATE, 0x99FF10E7, 0x23B1, 0x4C07, 0xA9, 0xD1, 0x5C, 0x32, 0x06, 0xD7, 0x41, 0xB4 );


// Battery Discharge Settings
// --------------------------
//
// Specifies the subgroup which will contain all of the battery discharge
// settings for a single policy.
//
DEFINE_GUID( GUID_BATTERY_SUBGROUP, 0xE73A048D, 0xBF27, 0x4F12, 0x97, 0x31, 0x8B, 0x20, 0x76, 0xE8, 0x89, 0x1F );

//
// 4 battery discharge alarm settings.
//
// GUID_BATTERY_DISCHARGE_ACTION_x - This is the action to take.  It is a value
//                                   of type POWER_ACTION
// GUID_BATTERY_DISCHARGE_LEVEL_x  - This is the battery level (%)
// GUID_BATTERY_DISCHARGE_FLAGS_x  - Flags defined below:
//                                   POWER_ACTION_POLICY->EventCode flags
//                                   BATTERY_DISCHARGE_FLAGS_EVENTCODE_MASK
//                                   BATTERY_DISCHARGE_FLAGS_ENABLE
DEFINE_GUID( GUID_BATTERY_DISCHARGE_ACTION_0, 0x637EA02F, 0xBBCB, 0x4015, 0x8E, 0x2C, 0xA1, 0xC7, 0xB9, 0xC0, 0xB5, 0x46 );
DEFINE_GUID( GUID_BATTERY_DISCHARGE_LEVEL_0, 0x9A66D8D7, 0x4FF7, 0x4EF9, 0xB5, 0xA2, 0x5A, 0x32, 0x6C, 0xA2, 0xA4, 0x69 );
DEFINE_GUID( GUID_BATTERY_DISCHARGE_FLAGS_0, 0x5dbb7c9f, 0x38e9, 0x40d2, 0x97, 0x49, 0x4f, 0x8a, 0x0e, 0x9f, 0x64, 0x0f );

DEFINE_GUID( GUID_BATTERY_DISCHARGE_ACTION_1, 0xD8742DCB, 0x3E6A, 0x4B3C, 0xB3, 0xFE, 0x37, 0x46, 0x23, 0xCD, 0xCF, 0x06 );
DEFINE_GUID( GUID_BATTERY_DISCHARGE_LEVEL_1, 0x8183BA9A, 0xE910, 0x48DA, 0x87, 0x69, 0x14, 0xAE, 0x6D, 0xC1, 0x17, 0x0A );
DEFINE_GUID( GUID_BATTERY_DISCHARGE_FLAGS_1, 0xbcded951, 0x187b, 0x4d05, 0xbc, 0xcc, 0xf7, 0xe5, 0x19, 0x60, 0xc2, 0x58 );

DEFINE_GUID( GUID_BATTERY_DISCHARGE_ACTION_2, 0x421CBA38, 0x1A8E, 0x4881, 0xAC, 0x89, 0xE3, 0x3A, 0x8B, 0x04, 0xEC, 0xE4 );
DEFINE_GUID( GUID_BATTERY_DISCHARGE_LEVEL_2, 0x07A07CA2, 0xADAF, 0x40D7, 0xB0, 0x77, 0x53, 0x3A, 0xAD, 0xED, 0x1B, 0xFA );
DEFINE_GUID( GUID_BATTERY_DISCHARGE_FLAGS_2, 0x7fd2f0c4, 0xfeb7, 0x4da3, 0x81, 0x17, 0xe3, 0xfb, 0xed, 0xc4, 0x65, 0x82 );

DEFINE_GUID( GUID_BATTERY_DISCHARGE_ACTION_3, 0x80472613, 0x9780, 0x455E, 0xB3, 0x08, 0x72, 0xD3, 0x00, 0x3C, 0xF2, 0xF8 );
DEFINE_GUID( GUID_BATTERY_DISCHARGE_LEVEL_3, 0x58AFD5A6, 0xC2DD, 0x47D2, 0x9F, 0xBF, 0xEF, 0x70, 0xCC, 0x5C, 0x59, 0x65 );
DEFINE_GUID( GUID_BATTERY_DISCHARGE_FLAGS_3, 0x73613ccf, 0xdbfa, 0x4279, 0x83, 0x56, 0x49, 0x35, 0xf6, 0xbf, 0x62, 0xf3 );

// Processor power settings
// ------------------------
//

// Specifies the subgroup which will contain all of the processor
// settings for a single policy.
//
DEFINE_GUID( GUID_PROCESSOR_SETTINGS_SUBGROUP, 0x54533251, 0x82BE, 0x4824, 0x96, 0xC1, 0x47, 0xB6, 0x0B, 0x74, 0x0D, 0x00 );

//
// Specifies various attributes that control processor performance/throttle
// states.
// 
DEFINE_GUID( GUID_PROCESSOR_THROTTLE_POLICY, 0x57027304, 0x4AF6, 0x4104, 0x92, 0x60, 0xE3, 0xD9, 0x52, 0x48, 0xFC, 0x36 );

#define PERFSTATE_POLICY_CHANGE_IDEAL  0
#define PERFSTATE_POLICY_CHANGE_SINGLE 1
#define PERFSTATE_POLICY_CHANGE_ROCKET 2
#define PERFSTATE_POLICY_CHANGE_MAX PERFSTATE_POLICY_CHANGE_ROCKET

//
// Specifies a percentage (between 0 and 100) that the processor frequency
// should never go above.  For example, if this value is set to 80, then
// the processor frequency will never be throttled above 80 percent of its
// maximum frequency by the system.
//
DEFINE_GUID( GUID_PROCESSOR_THROTTLE_MAXIMUM, 0xBC5038F7, 0x23E0, 0x4960, 0x96, 0xDA, 0x33, 0xAB, 0xAF, 0x59, 0x35, 0xEC );

//
// Specifies a percentage (between 0 and 100) that the processor frequency
// should not drop below.  For example, if this value is set to 50, then the
// processor frequency will never be throttled below 50 percent of its
// maximum frequency by the system.
//
DEFINE_GUID( GUID_PROCESSOR_THROTTLE_MINIMUM, 0x893DEE8E, 0x2BEF, 0x41E0, 0x89, 0xC6, 0xB5, 0x5D, 0x09, 0x29, 0x96, 0x4C );

//
// Specifies whether throttle states are allowed to be used even when
// performance states are available.
//
// {3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb}
//
DEFINE_GUID( GUID_PROCESSOR_ALLOW_THROTTLING, 0x3b04d4fd, 0x1cc7, 0x4f23, 0xab, 0x1c, 0xd1, 0x33, 0x78, 0x19, 0xc4, 0xbb );

//
// Specifies processor power settings for CState policy data
// {68F262A7-F621-4069-B9A5-4874169BE23C}
//
DEFINE_GUID( GUID_PROCESSOR_IDLESTATE_POLICY, 0x68f262a7, 0xf621, 0x4069, 0xb9, 0xa5, 0x48, 0x74, 0x16, 0x9b, 0xe2, 0x3c);

//
// Specifies processor power settings for PerfState policy data
// {BBDC3814-18E9-4463-8A55-D197327C45C0}
//
DEFINE_GUID( GUID_PROCESSOR_PERFSTATE_POLICY, 0xBBDC3814, 0x18E9, 0x4463, 0x8A, 0x55, 0xD1, 0x97, 0x32, 0x7C, 0x45, 0xC0);

//
// Specifies the increase busy percentage threshold that must be met before
// increasing the processor performance state.
//
// {06cadf0e-64ed-448a-8927-ce7bf90eb35d}
//
DEFINE_GUID( GUID_PROCESSOR_PERF_INCREASE_THRESHOLD, 0x06cadf0e, 0x64ed, 0x448a, 0x89, 0x27, 0xce, 0x7b, 0xf9, 0x0e, 0xb3, 0x5d );

//
// Specifies the decrease busy percentage threshold that must be met before
// decreasing the processor performance state.
//
// {12a0ab44-fe28-4fa9-b3bd-4b64f44960a6}
//
DEFINE_GUID( GUID_PROCESSOR_PERF_DECREASE_THRESHOLD, 0x12a0ab44, 0xfe28, 0x4fa9, 0xb3, 0xbd, 0x4b, 0x64, 0xf4, 0x49, 0x60, 0xa6 );

//
// Specifies, either as ideal, single or rocket, how aggressive performance
// states should be selected when increasing the processor performance state.
//
// {465E1F50-B610-473a-AB58-00D1077DC418}
//
DEFINE_GUID( GUID_PROCESSOR_PERF_INCREASE_POLICY, 0x465e1f50, 0xb610, 0x473a, 0xab, 0x58, 0x0, 0xd1, 0x7, 0x7d, 0xc4, 0x18);

//
// Specifies, either as ideal, single or rocket, how aggressive performance
// states should be selected when decreasing the processor performance state.
//
// {40FBEFC7-2E9D-4d25-A185-0CFD8574BAC6}
//
DEFINE_GUID( GUID_PROCESSOR_PERF_DECREASE_POLICY, 0x40fbefc7, 0x2e9d, 0x4d25, 0xa1, 0x85, 0xc, 0xfd, 0x85, 0x74, 0xba, 0xc6);

//
// Specifies, in milliseconds, the minimum amount of time that must elapse after
// the last processor performance state change before increasing the processor
// performance state.
//
// {984CF492-3BED-4488-A8F9-4286C97BF5AA}
//
DEFINE_GUID( GUID_PROCESSOR_PERF_INCREASE_TIME, 0x984cf492, 0x3bed, 0x4488, 0xa8, 0xf9, 0x42, 0x86, 0xc9, 0x7b, 0xf5, 0xaa);

//
// Specifies, in milliseconds, the minimum amount of time that must elapse after
// the last processor performance state change before increasing the processor
// performance state.
//
// {D8EDEB9B-95CF-4f95-A73C-B061973693C8}
//
DEFINE_GUID( GUID_PROCESSOR_PERF_DECREASE_TIME, 0xd8edeb9b, 0x95cf, 0x4f95, 0xa7, 0x3c, 0xb0, 0x61, 0x97, 0x36, 0x93, 0xc8);

//
// Specifies the time, in milliseconds, that must expire before considering
// a change in the processor performance states or parked core set.
//
// {4D2B0152-7D5C-498b-88E2-34345392A2C5}
//
DEFINE_GUID( GUID_PROCESSOR_PERF_TIME_CHECK, 0x4d2b0152, 0x7d5c, 0x498b, 0x88, 0xe2, 0x34, 0x34, 0x53, 0x92, 0xa2, 0xc5);

//
// Specifies whether a processor may opportunistically increase frequency above
// the maximum when operating contitions allow it to do so safely.
//
// {45BCC044-D885-43e2-8605-EE0EC6E96B59}
//
DEFINE_GUID(GUID_PROCESSOR_PERF_BOOST_POLICY, 
0x45bcc044, 0xd885, 0x43e2, 0x86, 0x5, 0xee, 0xe, 0xc6, 0xe9, 0x6b, 0x59);

#define PROCESSOR_PERF_BOOST_POLICY_DISABLED 0
#define PROCESSOR_PERF_BOOST_POLICY_MAX 100

//
// Specifies if idle state promotion and demotion values should be scaled based
// on the current peformance state.
//
// {6C2993B0-8F48-481f-BCC6-00DD2742AA06}
//
DEFINE_GUID( GUID_PROCESSOR_IDLE_ALLOW_SCALING, 0x6c2993b0, 0x8f48, 0x481f, 0xbc, 0xc6, 0x0, 0xdd, 0x27, 0x42, 0xaa, 0x6);

//
// Specifies if idle states should be disabled.
//
// {5D76A2CA-E8C0-402f-A133-2158492D58AD}
//
DEFINE_GUID( GUID_PROCESSOR_IDLE_DISABLE, 0x5d76a2ca, 0xe8c0, 0x402f, 0xa1, 0x33, 0x21, 0x58, 0x49, 0x2d, 0x58, 0xad);

//
// Specifies the time that elapsed since the last idle state promotion or
// demotion before idle states may be promoted or demoted again (in 
// microseconds).
//
// {C4581C31-89AB-4597-8E2B-9C9CAB440E6B}
//
DEFINE_GUID( GUID_PROCESSOR_IDLE_TIME_CHECK, 0xc4581c31, 0x89ab, 0x4597, 0x8e, 0x2b, 0x9c, 0x9c, 0xab, 0x44, 0xe, 0x6b);


//
// Specifies the upper busy threshold that must be met before demoting the
// processor to a lighter idle state (in percentage).
//
// {4B92D758-5A24-4851-A470-815D78AEE119}
//
DEFINE_GUID( GUID_PROCESSOR_IDLE_DEMOTE_THRESHOLD, 0x4b92d758, 0x5a24, 0x4851, 0xa4, 0x70, 0x81, 0x5d, 0x78, 0xae, 0xe1, 0x19);

//
// Specifies the lower busy threshold that must be met before promoting the 
// processor to a deeper idle state (in percentage).
//
// {7B224883-B3CC-4d79-819F-8374152CBE7C}
//
DEFINE_GUID( GUID_PROCESSOR_IDLE_PROMOTE_THRESHOLD, 0x7b224883, 0xb3cc, 0x4d79, 0x81, 0x9f, 0x83, 0x74, 0x15, 0x2c, 0xbe, 0x7c);

//
// Specifies the utilization threshold in percent that must be crossed in order to un-park cores.
// 
// {df142941-20f3-4edf-9a4a-9c83d3d717d1}
// 
DEFINE_GUID( GUID_PROCESSOR_CORE_PARKING_INCREASE_THRESHOLD, 0xdf142941, 0x20f3, 0x4edf, 0x9a, 0x4a, 0x9c, 0x83, 0xd3, 0xd7, 0x17, 0xd1 );

//
// Specifies the utilization threshold in percent that must be crossed in order to park cores.
// 
// {68dd2f27-a4ce-4e11-8487-3794e4135dfa}
// 
DEFINE_GUID( GUID_PROCESSOR_CORE_PARKING_DECREASE_THRESHOLD, 0x68dd2f27, 0xa4ce, 0x4e11, 0x84, 0x87, 0x37, 0x94, 0xe4, 0x13, 0x5d, 0xfa);

//
// Specifies, either as ideal, single or rocket, how aggressive core parking is when cores must be unparked.
// 
// {c7be0679-2817-4d69-9d02-519a537ed0c6}
// 
DEFINE_GUID( GUID_PROCESSOR_CORE_PARKING_INCREASE_POLICY, 0xc7be0679, 0x2817, 0x4d69, 0x9d, 0x02, 0x51, 0x9a, 0x53, 0x7e, 0xd0, 0xc6);

#define CORE_PARKING_POLICY_CHANGE_IDEAL  0
#define CORE_PARKING_POLICY_CHANGE_SINGLE 1
#define CORE_PARKING_POLICY_CHANGE_ROCKET 2
#define CORE_PARKING_POLICY_CHANGE_MAX CORE_PARKING_POLICY_CHANGE_ROCKET

// 
// Specifies, either as ideal, single or rocket, how aggressive core parking is when cores must be parked.
// 
// {71021b41-c749-4d21-be74-a00f335d582b}
// 
DEFINE_GUID( GUID_PROCESSOR_CORE_PARKING_DECREASE_POLICY, 0x71021b41, 0xc749, 0x4d21, 0xbe, 0x74, 0xa0, 0x0f, 0x33, 0x5d, 0x58, 0x2b);

//
// Specifies, on a per processor group basis, the maximum number of cores that can be kept unparked. 
// 
// {ea062031-0e34-4ff1-9b6d-eb1059334028}
// 
DEFINE_GUID( GUID_PROCESSOR_CORE_PARKING_MAX_CORES, 0xea062031, 0x0e34, 0x4ff1, 0x9b, 0x6d, 0xeb, 0x10, 0x59, 0x33, 0x40, 0x28);

//
// Specifies, on a per processor group basis, the minimum number of cores that must be kept unparked.
// 
// {0cc5b647-c1df-4637-891a-dec35c318583}
// 
DEFINE_GUID( GUID_PROCESSOR_CORE_PARKING_MIN_CORES, 0x0cc5b647, 0xc1df, 0x4637, 0x89, 0x1a, 0xde, 0xc3, 0x5c, 0x31, 0x85, 0x83);

//
// Specifies, in milliseconds, the minimum amount of time a core must be parked before it can be unparked.
// 
// {2ddd5a84-5a71-437e-912a-db0b8c788732}
//
DEFINE_GUID( GUID_PROCESSOR_CORE_PARKING_INCREASE_TIME, 0x2ddd5a84, 0x5a71, 0x437e, 0x91, 0x2a, 0xdb, 0x0b, 0x8c, 0x78, 0x87, 0x32);

//
// Specifies, in milliseconds, the minimum amount of time a core must be unparked before it can be parked.
// 
// {dfd10d17-d5eb-45dd-877a-9a34ddd15c82}
// 
DEFINE_GUID( GUID_PROCESSOR_CORE_PARKING_DECREASE_TIME, 0xdfd10d17, 0xd5eb, 0x45dd, 0x87, 0x7a, 0x9a, 0x34, 0xdd, 0xd1, 0x5c, 0x82);

//
// Specifies the factor by which to decrease affinity history on each core after each check.
// 
// {8f7b45e3-c393-480a-878c-f67ac3d07082}
// 
DEFINE_GUID( GUID_PROCESSOR_CORE_PARKING_AFFINITY_HISTORY_DECREASE_FACTOR, 0x8f7b45e3, 0xc393, 0x480a, 0x87, 0x8c, 0xf6, 0x7a, 0xc3, 0xd0, 0x70, 0x82);

//
// Specifies the threshold above which a core is considered to have had significant affinitized work scheduled to it while parked.
// 
// {5b33697b-e89d-4d38-aa46-9e7dfb7cd2f9}
// 
DEFINE_GUID( GUID_PROCESSOR_CORE_PARKING_AFFINITY_HISTORY_THRESHOLD, 0x5b33697b, 0xe89d, 0x4d38, 0xaa, 0x46, 0x9e, 0x7d, 0xfb, 0x7c, 0xd2, 0xf9);

//
// Specifies the weighting given to each occurence where affinitized work was scheduled to a parked core.
// 
// {e70867f1-fa2f-4f4e-aea1-4d8a0ba23b20}
// 
DEFINE_GUID( GUID_PROCESSOR_CORE_PARKING_AFFINITY_WEIGHTING, 0xe70867f1, 0xfa2f, 0x4f4e, 0xae, 0xa1, 0x4d, 0x8a, 0x0b, 0xa2, 0x3b, 0x20);

//
// Specifies the factor by which to decrease the over utilization history on each core after the current performance check.
// 
// {1299023c-bc28-4f0a-81ec-d3295a8d815d}
// 
DEFINE_GUID( GUID_PROCESSOR_CORE_PARKING_OVER_UTILIZATION_HISTORY_DECREASE_FACTOR, 0x1299023c, 0xbc28, 0x4f0a, 0x81, 0xec, 0xd3, 0x29, 0x5a, 0x8d, 0x81, 0x5d);

//
// Specifies the threshold above which a core is considered to have been recently over utilized while parked.
// 
// {9ac18e92-aa3c-4e27-b307-01ae37307129}
// 
DEFINE_GUID( GUID_PROCESSOR_CORE_PARKING_OVER_UTILIZATION_HISTORY_THRESHOLD, 0x9ac18e92, 0xaa3c, 0x4e27, 0xb3, 0x07, 0x01, 0xae, 0x37, 0x30, 0x71, 0x29);

//
// Specifies the weighting given to each occurence where a parked core is found to be over utilized.
// 
// {8809c2d8-b155-42d4-bcda-0d345651b1db}
// 
DEFINE_GUID( GUID_PROCESSOR_CORE_PARKING_OVER_UTILIZATION_WEIGHTING, 0x8809c2d8, 0xb155, 0x42d4, 0xbc, 0xda, 0x0d, 0x34, 0x56, 0x51, 0xb1, 0xdb);

//
// Specifies, in percentage, the busy threshold that must be met before a parked core is considered over utilized.
// 
// {943c8cb6-6f93-4227-ad87-e9a3feec08d1}
// 
DEFINE_GUID( GUID_PROCESSOR_CORE_PARKING_OVER_UTILIZATION_THRESHOLD, 0x943c8cb6, 0x6f93, 0x4227, 0xad, 0x87, 0xe9, 0xa3, 0xfe, 0xec, 0x08, 0xd1);

//
// Specifies if at least one processor per core should always remain unparked.
// 
// {a55612aa-f624-42c6-a443-7397d064c04f}
// 

DEFINE_GUID( GUID_PROCESSOR_PARKING_CORE_OVERRIDE, 0xa55612aa, 0xf624, 0x42c6, 0xa4, 0x43, 0x73, 0x97, 0xd0, 0x64, 0xc0, 0x4f);

//
// Specifies what performance state a processor should enter when first parked.
// 
// {447235c7-6a8d-4cc0-8e24-9eaf70b96e2b}
// 

DEFINE_GUID( GUID_PROCESSOR_PARKING_PERF_STATE, 0x447235c7, 0x6a8d, 0x4cc0, 0x8e, 0x24, 0x9e, 0xaf, 0x70, 0xb9, 0x6e, 0x2b);

//
// Specifies the number of perf time check intervals to average utility over.
//
// {7d24baa7-0b84-480f-840c-1b0743c00f5f}
//
DEFINE_GUID( GUID_PROCESSOR_PERF_HISTORY, 0x7d24baa7, 0x0b84, 0x480f, 0x84, 0x0c, 0x1b, 0x07, 0x43, 0xc0, 0x0f, 0x5f);

//
// Specifies active vs passive cooling.  Although not directly related to
// processor settings, it is the processor that gets throttled if we're doing
// passive cooling, so it is fairly strongly related.
// {94D3A615-A899-4AC5-AE2B-E4D8F634367F}
//
DEFINE_GUID( GUID_SYSTEM_COOLING_POLICY, 0x94D3A615, 0xA899, 0x4AC5, 0xAE, 0x2B, 0xE4, 0xD8, 0xF6, 0x34, 0x36, 0x7F);

// Lock Console on Wake
// --------------------
//

// Specifies the behavior of the system when we wake from standby or
// hibernate.  If this is set, then we will cause the console to lock
// after we resume.
//
DEFINE_GUID( GUID_LOCK_CONSOLE_ON_WAKE, 0x0E796BDB, 0x100D, 0x47D6, 0xA2, 0xD5, 0xF7, 0xD2, 0xDA, 0xA5, 0x1F, 0x51 );

// Device idle characteristics
// ---------------------------
//
// Specifies whether to use the "performance" or "conservative" timeouts for
// device idle management.
//
// 4faab71a-92e5-4726-b531-224559672d19
//
DEFINE_GUID( GUID_DEVICE_IDLE_POLICY, 0x4faab71a, 0x92e5, 0x4726, 0xb5, 0x31, 0x22, 0x45, 0x59, 0x67, 0x2d, 0x19 );

#define POWER_DEVICE_IDLE_POLICY_PERFORMANCE  0
#define POWER_DEVICE_IDLE_POLICY_CONSERVATIVE 1

// AC/DC power source
// ------------------
//

// Specifies the power source for the system.  consumers may register for
// notification when the power source changes and will be notified with
// one of 3 values:
// 0 - Indicates the system is being powered by an AC power source.
// 1 - Indicates the system is being powered by a DC power source.
// 2 - Indicates the system is being powered by a short-term DC power
//     source.  For example, this would be the case if the system is
//     being powed by a short-term battery supply in a backing UPS
//     system.  When this value is recieved, the consumer should make
//     preparations for either a system hibernate or system shutdown.
//
// { 5D3E9A59-E9D5-4B00-A6BD-FF34FF516548 }
DEFINE_GUID( GUID_ACDC_POWER_SOURCE, 0x5D3E9A59, 0xE9D5, 0x4B00, 0xA6, 0xBD, 0xFF, 0x34, 0xFF, 0x51, 0x65, 0x48 );

// Lid state changes
// -----------------
//
// Specifies the current state of the lid (open or closed). The callback won't
// be called at all until a lid device is found and its current state is known.
//
// Values:
//
// 0 - closed
// 1 - opened
//
// { BA3E0F4D-B817-4094-A2D1-D56379E6A0F3 }
//

DEFINE_GUID( GUID_LIDSWITCH_STATE_CHANGE,  0xBA3E0F4D, 0xB817, 0x4094, 0xA2, 0xD1, 0xD5, 0x63, 0x79, 0xE6, 0xA0, 0xF3 );

// Battery life remaining
// ----------------------
//

// Specifies the percentage of battery life remaining.  The consumer
// may register for notification in order to track battery life in
// a fine-grained manner.
//
// Once registered, the consumer can expect to be notified as the battery
// life percentage changes.
//
// The consumer will recieve a value between 0 and 100 (inclusive) which
// indicates percent battery life remaining.
//
// { A7AD8041-B45A-4CAE-87A3-EECBB468A9E1 }
DEFINE_GUID( GUID_BATTERY_PERCENTAGE_REMAINING, 0xA7AD8041, 0xB45A, 0x4CAE, 0x87, 0xA3, 0xEE, 0xCB, 0xB4, 0x68, 0xA9, 0xE1 );


// Notification to listeners that the system is fairly busy and won't be moving
// into an idle state any time soon.  This can be used as a hint to listeners
// that now might be a good time to do background tasks.
//
DEFINE_GUID( GUID_IDLE_BACKGROUND_TASK, 0x515C31D8, 0xF734, 0x163D, 0xA0, 0xFD, 0x11, 0xA0, 0x8C, 0x91, 0xE8, 0xF1 );

// Notification to listeners that the system is fairly busy and won't be moving
// into an idle state any time soon.  This can be used as a hint to listeners
// that now might be a good time to do background tasks.
//
// { CF23F240-2A54-48D8-B114-DE1518FF052E }
DEFINE_GUID( GUID_BACKGROUND_TASK_NOTIFICATION, 0xCF23F240, 0x2A54, 0x48D8, 0xB1, 0x14, 0xDE, 0x15, 0x18, 0xFF, 0x05, 0x2E );

// Define a GUID that will represent the action of a direct experience button
// on the platform.  Users will register for this DPPE setting and recieve
// notification when the h/w button is pressed.
//
// { 1A689231-7399-4E9A-8F99-B71F999DB3FA }
//
DEFINE_GUID( GUID_APPLAUNCH_BUTTON, 0x1A689231, 0x7399, 0x4E9A, 0x8F, 0x99, 0xB7, 0x1F, 0x99, 0x9D, 0xB3, 0xFA );

// PCI Express power settings
// ------------------------
//

// Specifies the subgroup which will contain all of the PCI Express
// settings for a single policy.
//
// {501a4d13-42af-4429-9fd1-a8218c268e20}
//
DEFINE_GUID( GUID_PCIEXPRESS_SETTINGS_SUBGROUP, 0x501a4d13, 0x42af,0x4429, 0x9f, 0xd1, 0xa8, 0x21, 0x8c, 0x26, 0x8e, 0x20 );

// Specifies the PCI Express ASPM power policy.
//
// {ee12f906-d277-404b-b6da-e5fa1a576df5}
//
DEFINE_GUID( GUID_PCIEXPRESS_ASPM_POLICY, 0xee12f906, 0xd277, 0x404b, 0xb6, 0xda, 0xe5, 0xfa, 0x1a, 0x57, 0x6d, 0xf5 );

// POWER Shutdown settings
// ------------------------
//

// Specifies if forced shutdown should be used for all button and lid initiated
// shutdown actions.
//
// {833a6b62-dfa4-46d1-82f8-e09e34d029d6}
//

DEFINE_GUID( GUID_ENABLE_SWITCH_FORCED_SHUTDOWN, 0x833a6b62, 0xdfa4, 0x46d1, 0x82, 0xf8, 0xe0, 0x9e, 0x34, 0xd0, 0x29, 0xd6 );


#ifndef _PO_DDK_
#define _PO_DDK_



typedef enum _SYSTEM_POWER_STATE {
    PowerSystemUnspecified = 0,
    PowerSystemWorking     = 1,
    PowerSystemSleeping1   = 2,
    PowerSystemSleeping2   = 3,
    PowerSystemSleeping3   = 4,
    PowerSystemHibernate   = 5,
    PowerSystemShutdown    = 6,
    PowerSystemMaximum     = 7
} SYSTEM_POWER_STATE, *PSYSTEM_POWER_STATE;

#define POWER_SYSTEM_MAXIMUM 7

typedef enum {
    PowerActionNone = 0,
    PowerActionReserved,
    PowerActionSleep,
    PowerActionHibernate,
    PowerActionShutdown,
    PowerActionShutdownReset,
    PowerActionShutdownOff,
    PowerActionWarmEject
} POWER_ACTION, *PPOWER_ACTION;

typedef enum _DEVICE_POWER_STATE {
    PowerDeviceUnspecified = 0,
    PowerDeviceD0,
    PowerDeviceD1,
    PowerDeviceD2,
    PowerDeviceD3,
    PowerDeviceMaximum
} DEVICE_POWER_STATE, *PDEVICE_POWER_STATE;

typedef enum _MONITOR_DISPLAY_STATE {
    PowerMonitorOff = 0,
    PowerMonitorOn,
    PowerMonitorDim
} MONITOR_DISPLAY_STATE, *PMONITOR_DISPLAY_STATE;



typedef union _POWER_STATE {
    SYSTEM_POWER_STATE SystemState;
    DEVICE_POWER_STATE DeviceState;
} POWER_STATE, *PPOWER_STATE;

typedef enum _POWER_STATE_TYPE {
    SystemPowerState = 0,
    DevicePowerState
} POWER_STATE_TYPE, *PPOWER_STATE_TYPE;

#if (NTDDI_VERSION >= NTDDI_VISTA)
typedef struct _SYSTEM_POWER_STATE_CONTEXT {
    union {
        struct {
            ULONG   Reserved1             : 8;
            ULONG   TargetSystemState     : 4;
            ULONG   EffectiveSystemState  : 4;
            ULONG   CurrentSystemState    : 4;
            ULONG   IgnoreHibernationPath : 1;
            ULONG   PseudoTransition      : 1;
            ULONG   Reserved2             : 10;
        } DUMMYSTRUCTNAME;

        ULONG ContextAsUlong;
    } DUMMYUNIONNAME;
} SYSTEM_POWER_STATE_CONTEXT, *PSYSTEM_POWER_STATE_CONTEXT;
#endif // (NTDDI_VERSION >= NTDDI_VISTA)

#if (NTDDI_VERSION >= NTDDI_WIN7)

typedef struct _COUNTED_REASON_CONTEXT {
    ULONG Version;
    ULONG Flags;
    union {
        struct {
            UNICODE_STRING ResourceFileName;
            USHORT ResourceReasonId;
            ULONG StringCount;
            PUNICODE_STRING __field_ecount(StringCount) ReasonStrings;
        } DUMMYSTRUCTNAME;

        UNICODE_STRING SimpleString;
    } DUMMYUNIONNAME;
} COUNTED_REASON_CONTEXT, *PCOUNTED_REASON_CONTEXT;

#endif // (NTDDI_VERSION >= NTDDI_WIN7)

//
// Generic power related IOCTLs
//

#define IOCTL_QUERY_DEVICE_POWER_STATE  \
        CTL_CODE(FILE_DEVICE_BATTERY, 0x0, METHOD_BUFFERED, FILE_READ_ACCESS)

#define IOCTL_SET_DEVICE_WAKE           \
        CTL_CODE(FILE_DEVICE_BATTERY, 0x1, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_CANCEL_DEVICE_WAKE        \
        CTL_CODE(FILE_DEVICE_BATTERY, 0x2, METHOD_BUFFERED, FILE_WRITE_ACCESS)


//
// Defines for W32 interfaces
//



#define ES_SYSTEM_REQUIRED   ((ULONG)0x00000001)
#define ES_DISPLAY_REQUIRED  ((ULONG)0x00000002)
#define ES_USER_PRESENT      ((ULONG)0x00000004)
#define ES_AWAYMODE_REQUIRED ((ULONG)0x00000040)
#define ES_CONTINUOUS        ((ULONG)0x80000000)

typedef ULONG EXECUTION_STATE, *PEXECUTION_STATE;

typedef enum {
    LT_DONT_CARE,
    LT_LOWEST_LATENCY
} LATENCY_TIME;

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN7)

#define DIAGNOSTIC_REASON_VERSION              0

#define DIAGNOSTIC_REASON_SIMPLE_STRING        0x00000001
#define DIAGNOSTIC_REASON_DETAILED_STRING      0x00000002
#define DIAGNOSTIC_REASON_NOT_SPECIFIED        0x80000000
#define DIAGNOSTIC_REASON_INVALID_FLAGS        (~0x80000003)

#endif // (_WIN32_WINNT >= _WIN32_WINNT_WIN7)

//
// Defines for power request APIs
//

#define POWER_REQUEST_CONTEXT_VERSION          0

#define POWER_REQUEST_CONTEXT_SIMPLE_STRING    0x00000001
#define POWER_REQUEST_CONTEXT_DETAILED_STRING  0x00000002

//
// N.B. The maximum is a macro (rather than part of enum) for cgen to be able
// to parse power.h correctly. When a new power request type is added, the
// PowerRequestMaximum should be manually incremented.
//

typedef enum _POWER_REQUEST_TYPE {
    PowerRequestDisplayRequired,
    PowerRequestSystemRequired,
    PowerRequestAwayModeRequired
} POWER_REQUEST_TYPE, *PPOWER_REQUEST_TYPE;

#define PowerRequestMaximum 3



#if (NTDDI_VERSION >= NTDDI_WINXP)

//-----------------------------------------------------------------------------
// Device Power Information
// Accessable via CM_Get_DevInst_Registry_Property_Ex(CM_DRP_DEVICE_POWER_DATA)
//-----------------------------------------------------------------------------

#define PDCAP_D0_SUPPORTED              0x00000001
#define PDCAP_D1_SUPPORTED              0x00000002
#define PDCAP_D2_SUPPORTED              0x00000004
#define PDCAP_D3_SUPPORTED              0x00000008
#define PDCAP_WAKE_FROM_D0_SUPPORTED    0x00000010
#define PDCAP_WAKE_FROM_D1_SUPPORTED    0x00000020
#define PDCAP_WAKE_FROM_D2_SUPPORTED    0x00000040
#define PDCAP_WAKE_FROM_D3_SUPPORTED    0x00000080
#define PDCAP_WARM_EJECT_SUPPORTED      0x00000100

typedef struct CM_Power_Data_s {
    ULONG               PD_Size;
    DEVICE_POWER_STATE  PD_MostRecentPowerState;
    ULONG               PD_Capabilities;
    ULONG               PD_D1Latency;
    ULONG               PD_D2Latency;
    ULONG               PD_D3Latency;
    DEVICE_POWER_STATE  PD_PowerStateMapping[POWER_SYSTEM_MAXIMUM];
    SYSTEM_POWER_STATE  PD_DeepestSystemWake;
} CM_POWER_DATA, *PCM_POWER_DATA;

#endif // (NTDDI_VERSION >= NTDDI_WINXP)



typedef enum {
    SystemPowerPolicyAc,
    SystemPowerPolicyDc,
    VerifySystemPolicyAc,
    VerifySystemPolicyDc,
    SystemPowerCapabilities,
    SystemBatteryState,
    SystemPowerStateHandler,
    ProcessorStateHandler,
    SystemPowerPolicyCurrent,
    AdministratorPowerPolicy,
    SystemReserveHiberFile,
    ProcessorInformation,
    SystemPowerInformation,
    ProcessorStateHandler2,
    LastWakeTime,                                   // Compare with KeQueryInterruptTime()
    LastSleepTime,                                  // Compare with KeQueryInterruptTime()
    SystemExecutionState,
    SystemPowerStateNotifyHandler,
    ProcessorPowerPolicyAc,
    ProcessorPowerPolicyDc,
    VerifyProcessorPowerPolicyAc,
    VerifyProcessorPowerPolicyDc,
    ProcessorPowerPolicyCurrent,
    SystemPowerStateLogging,
    SystemPowerLoggingEntry,
    SetPowerSettingValue,
    NotifyUserPowerSetting,
    PowerInformationLevelUnused0,
    PowerInformationLevelUnused1,
    SystemVideoState,
    TraceApplicationPowerMessage,
    TraceApplicationPowerMessageEnd,
    ProcessorPerfStates,
    ProcessorIdleStates,
    ProcessorCap,
    SystemWakeSource,
    SystemHiberFileInformation,
    TraceServicePowerMessage,
    ProcessorLoad,
    PowerShutdownNotification,
    MonitorCapabilities,
    SessionPowerInit,
    SessionDisplayState,
    PowerRequestCreate,
    PowerRequestAction,
    GetPowerRequestList,
    ProcessorInformationEx,
    NotifyUserModeLegacyPowerEvent,
    GroupPark,
    ProcessorIdleDomains,
    WakeTimerList,
    SystemHiberFileSize,
    PowerInformationLevelMaximum
} POWER_INFORMATION_LEVEL;

//
// Power Setting definitions
//

typedef enum {
    PoAc,
    PoDc,
    PoHot,
    PoConditionMaximum
} SYSTEM_POWER_CONDITION;

typedef struct {

    //
    // Version of this structure.  Currently should be set to
    // POWER_SETTING_VALUE_VERSION.
    //
    ULONG       Version;


    //
    // GUID representing the power setting being applied.
    //
    GUID        Guid;


    //
    // What power state should this setting be applied to?  E.g.
    // AC, DC, thermal, ...
    //
    SYSTEM_POWER_CONDITION PowerCondition;

    //
    // Length (in bytes) of the 'Data' member.
    //
    ULONG       DataLength;

    //
    // Data which contains the actual setting value.
    //
    UCHAR   Data[ANYSIZE_ARRAY];
} SET_POWER_SETTING_VALUE, *PSET_POWER_SETTING_VALUE;

#define POWER_SETTING_VALUE_VERSION (0x1)

typedef struct {
    GUID Guid;
} NOTIFY_USER_POWER_SETTING, *PNOTIFY_USER_POWER_SETTING;

//
// Package definition for an experience button device notification.  When
// someone registers for GUID_EXPERIENCE_BUTTON, this is the definition of
// the setting data they'll get.
//
typedef struct _APPLICATIONLAUNCH_SETTING_VALUE {

    //
    // System time when the most recent button press ocurred.  Note that this is
    // specified in 100ns internvals since January 1, 1601.
    //
    LARGE_INTEGER       ActivationTime;

    //
    // Reserved for internal use.
    //
    ULONG               Flags;

    //
    // which instance of this device was pressed?
    //
    ULONG               ButtonInstanceID;


} APPLICATIONLAUNCH_SETTING_VALUE, *PAPPLICATIONLAUNCH_SETTING_VALUE;

//
// define platform roles
//

typedef enum {
    PlatformRoleUnspecified = 0,
    PlatformRoleDesktop,
    PlatformRoleMobile,
    PlatformRoleWorkstation,
    PlatformRoleEnterpriseServer,
    PlatformRoleSOHOServer,
    PlatformRoleAppliancePC,
    PlatformRolePerformanceServer,
    PlatformRoleMaximum
} POWER_PLATFORM_ROLE;

//
// System power manager capabilities
//

#if (NTDDI_VERSION >= NTDDI_WINXP) || !defined(_BATCLASS_)
typedef struct {
    ULONG       Granularity;
    ULONG       Capacity;
} BATTERY_REPORTING_SCALE, *PBATTERY_REPORTING_SCALE;
#endif // (NTDDI_VERSION >= NTDDI_WINXP) || !defined(_BATCLASS_)


#endif // !_PO_DDK_

//
// Predefined Value Types.
//

#define REG_NONE                    ( 0 )   // No value type
#define REG_SZ                      ( 1 )   // Unicode nul terminated string
#define REG_EXPAND_SZ               ( 2 )   // Unicode nul terminated string
                                            // (with environment variable references)
#define REG_BINARY                  ( 3 )   // Free form binary
#define REG_DWORD                   ( 4 )   // 32-bit number
#define REG_DWORD_LITTLE_ENDIAN     ( 4 )   // 32-bit number (same as REG_DWORD)
#define REG_DWORD_BIG_ENDIAN        ( 5 )   // 32-bit number
#define REG_LINK                    ( 6 )   // Symbolic Link (unicode)
#define REG_MULTI_SZ                ( 7 )   // Multiple Unicode strings
#define REG_RESOURCE_LIST           ( 8 )   // Resource list in the resource map
#define REG_FULL_RESOURCE_DESCRIPTOR ( 9 )  // Resource list in the hardware description
#define REG_RESOURCE_REQUIREMENTS_LIST ( 10 )
#define REG_QWORD                   ( 11 )  // 64-bit number
#define REG_QWORD_LITTLE_ENDIAN     ( 11 )  // 64-bit number (same as REG_QWORD)

//
// Service Types (Bit Mask)
//
#define SERVICE_KERNEL_DRIVER          0x00000001
#define SERVICE_FILE_SYSTEM_DRIVER     0x00000002
#define SERVICE_ADAPTER                0x00000004
#define SERVICE_RECOGNIZER_DRIVER      0x00000008

#define SERVICE_DRIVER                 (SERVICE_KERNEL_DRIVER | \
                                        SERVICE_FILE_SYSTEM_DRIVER | \
                                        SERVICE_RECOGNIZER_DRIVER)

#define SERVICE_WIN32_OWN_PROCESS      0x00000010
#define SERVICE_WIN32_SHARE_PROCESS    0x00000020
#define SERVICE_WIN32                  (SERVICE_WIN32_OWN_PROCESS | \
                                        SERVICE_WIN32_SHARE_PROCESS)

#define SERVICE_INTERACTIVE_PROCESS    0x00000100

#define SERVICE_TYPE_ALL               (SERVICE_WIN32  | \
                                        SERVICE_ADAPTER | \
                                        SERVICE_DRIVER  | \
                                        SERVICE_INTERACTIVE_PROCESS)

//
// Start Type
//

#define SERVICE_BOOT_START             0x00000000
#define SERVICE_SYSTEM_START           0x00000001
#define SERVICE_AUTO_START             0x00000002
#define SERVICE_DEMAND_START           0x00000003
#define SERVICE_DISABLED               0x00000004

//
// Error control type
//
#define SERVICE_ERROR_IGNORE           0x00000000
#define SERVICE_ERROR_NORMAL           0x00000001
#define SERVICE_ERROR_SEVERE           0x00000002
#define SERVICE_ERROR_CRITICAL         0x00000003

//
//
// Define the registry driver node enumerations
//

typedef enum _CM_SERVICE_NODE_TYPE {
    DriverType               = SERVICE_KERNEL_DRIVER,
    FileSystemType           = SERVICE_FILE_SYSTEM_DRIVER,
    Win32ServiceOwnProcess   = SERVICE_WIN32_OWN_PROCESS,
    Win32ServiceShareProcess = SERVICE_WIN32_SHARE_PROCESS,
    AdapterType              = SERVICE_ADAPTER,
    RecognizerType           = SERVICE_RECOGNIZER_DRIVER
} SERVICE_NODE_TYPE;

typedef enum _CM_SERVICE_LOAD_TYPE {
    BootLoad    = SERVICE_BOOT_START,
    SystemLoad  = SERVICE_SYSTEM_START,
    AutoLoad    = SERVICE_AUTO_START,
    DemandLoad  = SERVICE_DEMAND_START,
    DisableLoad = SERVICE_DISABLED
} SERVICE_LOAD_TYPE;

typedef enum _CM_ERROR_CONTROL_TYPE {
    IgnoreError   = SERVICE_ERROR_IGNORE,
    NormalError   = SERVICE_ERROR_NORMAL,
    SevereError   = SERVICE_ERROR_SEVERE,
    CriticalError = SERVICE_ERROR_CRITICAL
} SERVICE_ERROR_TYPE;

//
// Service node Flags. These flags are used by the OS loader to promote
// a driver's start type to boot start if the system is booting using
// the specified mechanism. The flags should be set in the driver's
// registry configuration.
//
// CM_SERVICE_NETWORK_BOOT_LOAD - Specified if a driver should be
// promoted on network boot.
//
// CM_SERVICE_VIRTUAL_DISK_BOOT_LOAD - Specified if a driver should be
// promoted on booting from a VHD.
//
// CM_SERVICE_USB_DISK_BOOT_LOAD - Specified if a driver should be promoted
// while booting from a USB disk.
//

#define CM_SERVICE_NETWORK_BOOT_LOAD      0x00000001
#define CM_SERVICE_VIRTUAL_DISK_BOOT_LOAD 0x00000002
#define CM_SERVICE_USB_DISK_BOOT_LOAD     0x00000004

//
// Mask defining the legal promotion flag values.
//

#define CM_SERVICE_VALID_PROMOTION_MASK (CM_SERVICE_NETWORK_BOOT_LOAD |       \
                                         CM_SERVICE_VIRTUAL_DISK_BOOT_LOAD |  \
                                         CM_SERVICE_USB_DISK_BOOT_LOAD)



//
// Resource List definitions
//



//
// Defines the Type in the RESOURCE_DESCRIPTOR
//
// NOTE:  For all CM_RESOURCE_TYPE values, there must be a
// corresponding ResType value in the 32-bit ConfigMgr headerfile
// (cfgmgr32.h).  Values in the range [0x6,0x80) use the same values
// as their ConfigMgr counterparts.  CM_RESOURCE_TYPE values with
// the high bit set (i.e., in the range [0x80,0xFF]), are
// non-arbitrated resources.  These correspond to the same values
// in cfgmgr32.h that have their high bit set (however, since
// cfgmgr32.h uses 16 bits for ResType values, these values are in
// the range [0x8000,0x807F).  Note that ConfigMgr ResType values
// cannot be in the range [0x8080,0xFFFF), because they would not
// be able to map into CM_RESOURCE_TYPE values.  (0xFFFF itself is
// a special value, because it maps to CmResourceTypeDeviceSpecific.)
//

typedef int CM_RESOURCE_TYPE;

// CmResourceTypeNull is reserved

#define CmResourceTypeNull                0   // ResType_All or ResType_None (0x0000)
#define CmResourceTypePort                1   // ResType_IO (0x0002)
#define CmResourceTypeInterrupt           2   // ResType_IRQ (0x0004)
#define CmResourceTypeMemory              3   // ResType_Mem (0x0001)
#define CmResourceTypeDma                 4   // ResType_DMA (0x0003)
#define CmResourceTypeDeviceSpecific      5   // ResType_ClassSpecific (0xFFFF)
#define CmResourceTypeBusNumber           6   // ResType_BusNumber (0x0006)
#define CmResourceTypeMemoryLarge         7   // ResType_MemLarge (0x0007)
#define CmResourceTypeNonArbitrated     128   // Not arbitrated if 0x80 bit set
#define CmResourceTypeConfigData        128   // ResType_Reserved (0x8000)
#define CmResourceTypeDevicePrivate     129   // ResType_DevicePrivate (0x8001)
#define CmResourceTypePcCardConfig      130   // ResType_PcCardConfig (0x8002)
#define CmResourceTypeMfCardConfig      131   // ResType_MfCardConfig (0x8003)

//
// Defines the ShareDisposition in the RESOURCE_DESCRIPTOR
//

typedef enum _CM_SHARE_DISPOSITION {
    CmResourceShareUndetermined = 0,    // Reserved
    CmResourceShareDeviceExclusive,
    CmResourceShareDriverExclusive,
    CmResourceShareShared
} CM_SHARE_DISPOSITION;

//
// Define the bit masks for Flags when type is CmResourceTypeInterrupt
//

#define CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE           0
#define CM_RESOURCE_INTERRUPT_LATCHED                   1
#define CM_RESOURCE_INTERRUPT_MESSAGE                   2
#define CM_RESOURCE_INTERRUPT_POLICY_INCLUDED           4

//
// A bitmask defining the bits in a resource or requirements descriptor
// flags field that corresponds to the latch mode or a level triggered
// interrupt.
//

#define CM_RESOURCE_INTERRUPT_LEVEL_LATCHED_BITS 0x0001

//
// Define the token value used for an interrupt vector to mean that the vector
// is message signaled.  This value is used in the MaximumVector field.
//

#define CM_RESOURCE_INTERRUPT_MESSAGE_TOKEN   ((ULONG)-2)

//
// Define the bit masks for Flags when type is CmResourceTypeMemory
// or CmResourceTypeMemoryLarge
//

#define CM_RESOURCE_MEMORY_READ_WRITE                       0x0000
#define CM_RESOURCE_MEMORY_READ_ONLY                        0x0001
#define CM_RESOURCE_MEMORY_WRITE_ONLY                       0x0002
#define CM_RESOURCE_MEMORY_WRITEABILITY_MASK                0x0003
#define CM_RESOURCE_MEMORY_PREFETCHABLE                     0x0004

#define CM_RESOURCE_MEMORY_COMBINEDWRITE                    0x0008
#define CM_RESOURCE_MEMORY_24                               0x0010
#define CM_RESOURCE_MEMORY_CACHEABLE                        0x0020
#define CM_RESOURCE_MEMORY_WINDOW_DECODE                    0x0040
#define CM_RESOURCE_MEMORY_BAR                              0x0080

#define CM_RESOURCE_MEMORY_COMPAT_FOR_INACCESSIBLE_RANGE    0x0100

//
// Define the bit masks exclusive to type CmResourceTypeMemoryLarge.
//

#define CM_RESOURCE_MEMORY_LARGE                            0x0E00
#define CM_RESOURCE_MEMORY_LARGE_40                         0x0200
#define CM_RESOURCE_MEMORY_LARGE_48                         0x0400
#define CM_RESOURCE_MEMORY_LARGE_64                         0x0800

//
// Define limits for large memory resources
//

#define CM_RESOURCE_MEMORY_LARGE_40_MAXLEN          0x000000FFFFFFFF00
#define CM_RESOURCE_MEMORY_LARGE_48_MAXLEN          0x0000FFFFFFFF0000
#define CM_RESOURCE_MEMORY_LARGE_64_MAXLEN          0xFFFFFFFF00000000

//
// Define the bit masks for Flags when type is CmResourceTypePort
//

#define CM_RESOURCE_PORT_MEMORY                             0x0000
#define CM_RESOURCE_PORT_IO                                 0x0001
#define CM_RESOURCE_PORT_10_BIT_DECODE                      0x0004
#define CM_RESOURCE_PORT_12_BIT_DECODE                      0x0008
#define CM_RESOURCE_PORT_16_BIT_DECODE                      0x0010
#define CM_RESOURCE_PORT_POSITIVE_DECODE                    0x0020
#define CM_RESOURCE_PORT_PASSIVE_DECODE                     0x0040
#define CM_RESOURCE_PORT_WINDOW_DECODE                      0x0080
#define CM_RESOURCE_PORT_BAR                                0x0100

//
// Define the bit masks for Flags when type is CmResourceTypeDma
//

#define CM_RESOURCE_DMA_8                   0x0000
#define CM_RESOURCE_DMA_16                  0x0001
#define CM_RESOURCE_DMA_32                  0x0002
#define CM_RESOURCE_DMA_8_AND_16            0x0004
#define CM_RESOURCE_DMA_BUS_MASTER          0x0008
#define CM_RESOURCE_DMA_TYPE_A              0x0010
#define CM_RESOURCE_DMA_TYPE_B              0x0020
#define CM_RESOURCE_DMA_TYPE_F              0x0040



//
// This structure defines one type of resource used by a driver.
//
// There can only be *1* DeviceSpecificData block. It must be located at
// the end of all resource descriptors in a full descriptor block.
//

//
// Make sure alignment is made properly by compiler; otherwise move
// flags back to the top of the structure (common to all members of the
// union).
//


#include "pshpack4.h"
typedef struct _CM_PARTIAL_RESOURCE_DESCRIPTOR {
    UCHAR Type;
    UCHAR ShareDisposition;
    USHORT Flags;
    union {

        //
        // Range of resources, inclusive.  These are physical, bus relative.
        // It is known that Port and Memory below have the exact same layout
        // as Generic.
        //

        struct {
            PHYSICAL_ADDRESS Start;
            ULONG Length;
        } Generic;

        //
        //

        struct {
            PHYSICAL_ADDRESS Start;
            ULONG Length;
        } Port;

        //
        //

        struct {
#if defined(NT_PROCESSOR_GROUPS)
            USHORT Level;
            USHORT Group;
#else
            ULONG Level;
#endif
            ULONG Vector;
            KAFFINITY Affinity;
        } Interrupt;

        //
        // Values for message signaled interrupts are distinct in the
        // raw and translated cases.
        //

        struct {
            union {
               struct {
#if defined(NT_PROCESSOR_GROUPS)
                   USHORT Group;
#else
                   USHORT Reserved;
#endif
                   USHORT MessageCount;
                   ULONG Vector;
                   KAFFINITY Affinity;
               } Raw;

               struct {
#if defined(NT_PROCESSOR_GROUPS)
                   USHORT Level;
                   USHORT Group;
#else
                   ULONG Level;
#endif
                   ULONG Vector;
                   KAFFINITY Affinity;
               } Translated;
            } DUMMYUNIONNAME;
        } MessageInterrupt;

        //
        // Range of memory addresses, inclusive. These are physical, bus
        // relative. The value should be the same as the one passed to
        // HalTranslateBusAddress().
        //

        struct {
            PHYSICAL_ADDRESS Start;    // 64 bit physical addresses.
            ULONG Length;
        } Memory;

        //
        // Physical DMA channel.
        //

        struct {
            ULONG Channel;
            ULONG Port;
            ULONG Reserved1;
        } Dma;

        //
        // Device driver private data, usually used to help it figure
        // what the resource assignments decisions that were made.
        //

        struct {
            ULONG Data[3];
        } DevicePrivate;

        //
        // Bus Number information.
        //

        struct {
            ULONG Start;
            ULONG Length;
            ULONG Reserved;
        } BusNumber;

        //
        // Device Specific information defined by the driver.
        // The DataSize field indicates the size of the data in bytes. The
        // data is located immediately after the DeviceSpecificData field in
        // the structure.
        //

        struct {
            ULONG DataSize;
            ULONG Reserved1;
            ULONG Reserved2;
        } DeviceSpecificData;

        // The following structures provide support for memory-mapped
        // IO resources greater than MAXULONG
        struct {
            PHYSICAL_ADDRESS Start;
            ULONG Length40;
        } Memory40;

        struct {
            PHYSICAL_ADDRESS Start;
            ULONG Length48;
        } Memory48;

        struct {
            PHYSICAL_ADDRESS Start;
            ULONG Length64;
        } Memory64;


    } u;
} CM_PARTIAL_RESOURCE_DESCRIPTOR, *PCM_PARTIAL_RESOURCE_DESCRIPTOR;
#include "poppack.h"

//
// A Partial Resource List is what can be found in the ARC firmware
// or will be generated by ntdetect.com.
// The configuration manager will transform this structure into a Full
// resource descriptor when it is about to store it in the regsitry.
//
// Note: There must a be a convention to the order of fields of same type,
// (defined on a device by device basis) so that the fields can make sense
// to a driver (i.e. when multiple memory ranges are necessary).
//

typedef struct _CM_PARTIAL_RESOURCE_LIST {
    USHORT Version;
    USHORT Revision;
    ULONG Count;
    CM_PARTIAL_RESOURCE_DESCRIPTOR PartialDescriptors[1];
} CM_PARTIAL_RESOURCE_LIST, *PCM_PARTIAL_RESOURCE_LIST;

//
// A Full Resource Descriptor is what can be found in the registry.
// This is what will be returned to a driver when it queries the registry
// to get device information; it will be stored under a key in the hardware
// description tree.
//
// Note: There must a be a convention to the order of fields of same type,
// (defined on a device by device basis) so that the fields can make sense
// to a driver (i.e. when multiple memory ranges are necessary).
//

typedef struct _CM_FULL_RESOURCE_DESCRIPTOR {
    INTERFACE_TYPE InterfaceType; // unused for WDM
    ULONG BusNumber; // unused for WDM
    CM_PARTIAL_RESOURCE_LIST PartialResourceList;
} CM_FULL_RESOURCE_DESCRIPTOR, *PCM_FULL_RESOURCE_DESCRIPTOR;

//
// The Resource list is what will be stored by the drivers into the
// resource map via the IO API.
//

typedef struct _CM_RESOURCE_LIST {
    ULONG Count;
    CM_FULL_RESOURCE_DESCRIPTOR List[1];
} CM_RESOURCE_LIST, *PCM_RESOURCE_LIST;


//
// Define the structures used to interpret configuration data of
// \\Registry\machine\hardware\description tree.
// Basically, these structures are used to interpret component
// sepcific data.
//

//
// Define DEVICE_FLAGS
//

typedef struct _DEVICE_FLAGS {
    ULONG Failed : 1;
    ULONG ReadOnly : 1;
    ULONG Removable : 1;
    ULONG ConsoleIn : 1;
    ULONG ConsoleOut : 1;
    ULONG Input : 1;
    ULONG Output : 1;
} DEVICE_FLAGS, *PDEVICE_FLAGS;

//
// Define Component Information structure
//

typedef struct _CM_COMPONENT_INFORMATION {
    DEVICE_FLAGS Flags;
    ULONG Version;
    ULONG Key;
    KAFFINITY AffinityMask;
} CM_COMPONENT_INFORMATION, *PCM_COMPONENT_INFORMATION;

//
// The following structures are used to interpret x86
// DeviceSpecificData of CM_PARTIAL_RESOURCE_DESCRIPTOR.
// (Most of the structures are defined by BIOS.  They are
// not aligned on word (or dword) boundary.
//

//
// Define the Rom Block structure
//

typedef struct _CM_ROM_BLOCK {
    ULONG Address;
    ULONG Size;
} CM_ROM_BLOCK, *PCM_ROM_BLOCK;



#include "pshpack1.h"



//
// Define INT13 driver parameter block
//

typedef struct _CM_INT13_DRIVE_PARAMETER {
    USHORT DriveSelect;
    ULONG MaxCylinders;
    USHORT SectorsPerTrack;
    USHORT MaxHeads;
    USHORT NumberDrives;
} CM_INT13_DRIVE_PARAMETER, *PCM_INT13_DRIVE_PARAMETER;



//
// Define Mca POS data block for slot
//

typedef struct _CM_MCA_POS_DATA {
    USHORT AdapterId;
    UCHAR PosData1;
    UCHAR PosData2;
    UCHAR PosData3;
    UCHAR PosData4;
} CM_MCA_POS_DATA, *PCM_MCA_POS_DATA;

//
// Memory configuration of eisa data block structure
//

typedef struct _EISA_MEMORY_TYPE {
    UCHAR ReadWrite: 1;
    UCHAR Cached : 1;
    UCHAR Reserved0 :1;
    UCHAR Type:2;
    UCHAR Shared:1;
    UCHAR Reserved1 :1;
    UCHAR MoreEntries : 1;
} EISA_MEMORY_TYPE, *PEISA_MEMORY_TYPE;

typedef struct _EISA_MEMORY_CONFIGURATION {
    EISA_MEMORY_TYPE ConfigurationByte;
    UCHAR DataSize;
    USHORT AddressLowWord;
    UCHAR AddressHighByte;
    USHORT MemorySize;
} EISA_MEMORY_CONFIGURATION, *PEISA_MEMORY_CONFIGURATION;


//
// Interrupt configurationn of eisa data block structure
//

typedef struct _EISA_IRQ_DESCRIPTOR {
    UCHAR Interrupt : 4;
    UCHAR Reserved :1;
    UCHAR LevelTriggered :1;
    UCHAR Shared : 1;
    UCHAR MoreEntries : 1;
} EISA_IRQ_DESCRIPTOR, *PEISA_IRQ_DESCRIPTOR;

typedef struct _EISA_IRQ_CONFIGURATION {
    EISA_IRQ_DESCRIPTOR ConfigurationByte;
    UCHAR Reserved;
} EISA_IRQ_CONFIGURATION, *PEISA_IRQ_CONFIGURATION;


//
// DMA description of eisa data block structure
//

typedef struct _DMA_CONFIGURATION_BYTE0 {
    UCHAR Channel : 3;
    UCHAR Reserved : 3;
    UCHAR Shared :1;
    UCHAR MoreEntries :1;
} DMA_CONFIGURATION_BYTE0;

typedef struct _DMA_CONFIGURATION_BYTE1 {
    UCHAR Reserved0 : 2;
    UCHAR TransferSize : 2;
    UCHAR Timing : 2;
    UCHAR Reserved1 : 2;
} DMA_CONFIGURATION_BYTE1;

typedef struct _EISA_DMA_CONFIGURATION {
    DMA_CONFIGURATION_BYTE0 ConfigurationByte0;
    DMA_CONFIGURATION_BYTE1 ConfigurationByte1;
} EISA_DMA_CONFIGURATION, *PEISA_DMA_CONFIGURATION;


//
// Port description of eisa data block structure
//

typedef struct _EISA_PORT_DESCRIPTOR {
    UCHAR NumberPorts : 5;
    UCHAR Reserved :1;
    UCHAR Shared :1;
    UCHAR MoreEntries : 1;
} EISA_PORT_DESCRIPTOR, *PEISA_PORT_DESCRIPTOR;

typedef struct _EISA_PORT_CONFIGURATION {
    EISA_PORT_DESCRIPTOR Configuration;
    USHORT PortAddress;
} EISA_PORT_CONFIGURATION, *PEISA_PORT_CONFIGURATION;


//
// Eisa slot information definition
// N.B. This structure is different from the one defined
//      in ARC eisa addendum.
//

typedef struct _CM_EISA_SLOT_INFORMATION {
    UCHAR ReturnCode;
    UCHAR ReturnFlags;
    UCHAR MajorRevision;
    UCHAR MinorRevision;
    USHORT Checksum;
    UCHAR NumberFunctions;
    UCHAR FunctionInformation;
    ULONG CompressedId;
} CM_EISA_SLOT_INFORMATION, *PCM_EISA_SLOT_INFORMATION;


//
// Eisa function information definition
//

typedef struct _CM_EISA_FUNCTION_INFORMATION {
    ULONG CompressedId;
    UCHAR IdSlotFlags1;
    UCHAR IdSlotFlags2;
    UCHAR MinorRevision;
    UCHAR MajorRevision;
    UCHAR Selections[26];
    UCHAR FunctionFlags;
    UCHAR TypeString[80];
    EISA_MEMORY_CONFIGURATION EisaMemory[9];
    EISA_IRQ_CONFIGURATION EisaIrq[7];
    EISA_DMA_CONFIGURATION EisaDma[4];
    EISA_PORT_CONFIGURATION EisaPort[20];
    UCHAR InitializationData[60];
} CM_EISA_FUNCTION_INFORMATION, *PCM_EISA_FUNCTION_INFORMATION;

//
// The following defines the way pnp bios information is stored in
// the registry \\HKEY_LOCAL_MACHINE\HARDWARE\Description\System\MultifunctionAdapter\x
// key, where x is an integer number indicating adapter instance. The
// "Identifier" of the key must equal to "PNP BIOS" and the
// "ConfigurationData" is organized as follow:
//
//      CM_PNP_BIOS_INSTALLATION_CHECK        +
//      CM_PNP_BIOS_DEVICE_NODE for device 1  +
//      CM_PNP_BIOS_DEVICE_NODE for device 2  +
//                ...
//      CM_PNP_BIOS_DEVICE_NODE for device n
//

//
// Pnp BIOS device node structure
//

typedef struct _CM_PNP_BIOS_DEVICE_NODE {
    USHORT Size;
    UCHAR Node;
    ULONG ProductId;
    UCHAR DeviceType[3];
    USHORT DeviceAttributes;
    // followed by AllocatedResourceBlock, PossibleResourceBlock
    // and CompatibleDeviceId
} CM_PNP_BIOS_DEVICE_NODE,*PCM_PNP_BIOS_DEVICE_NODE;

//
// Pnp BIOS Installation check
//

typedef struct _CM_PNP_BIOS_INSTALLATION_CHECK {
    UCHAR Signature[4];             // $PnP (ascii)
    UCHAR Revision;
    UCHAR Length;
    USHORT ControlField;
    UCHAR Checksum;
    ULONG EventFlagAddress;         // Physical address
    USHORT RealModeEntryOffset;
    USHORT RealModeEntrySegment;
    USHORT ProtectedModeEntryOffset;
    ULONG ProtectedModeCodeBaseAddress;
    ULONG OemDeviceId;
    USHORT RealModeDataBaseAddress;
    ULONG ProtectedModeDataBaseAddress;
} CM_PNP_BIOS_INSTALLATION_CHECK, *PCM_PNP_BIOS_INSTALLATION_CHECK;

#include "poppack.h"

//
// Masks for EISA function information
//

#define EISA_FUNCTION_ENABLED                   0x80
#define EISA_FREE_FORM_DATA                     0x40
#define EISA_HAS_PORT_INIT_ENTRY                0x20
#define EISA_HAS_PORT_RANGE                     0x10
#define EISA_HAS_DMA_ENTRY                      0x08
#define EISA_HAS_IRQ_ENTRY                      0x04
#define EISA_HAS_MEMORY_ENTRY                   0x02
#define EISA_HAS_TYPE_ENTRY                     0x01
#define EISA_HAS_INFORMATION                    EISA_HAS_PORT_RANGE + \
                                                EISA_HAS_DMA_ENTRY + \
                                                EISA_HAS_IRQ_ENTRY + \
                                                EISA_HAS_MEMORY_ENTRY + \
                                                EISA_HAS_TYPE_ENTRY

//
// Masks for EISA memory configuration
//

#define EISA_MORE_ENTRIES                       0x80
#define EISA_SYSTEM_MEMORY                      0x00
#define EISA_MEMORY_TYPE_RAM                    0x01

//
// Returned error code for EISA bios call
//

#define EISA_INVALID_SLOT                       0x80
#define EISA_INVALID_FUNCTION                   0x81
#define EISA_INVALID_CONFIGURATION              0x82
#define EISA_EMPTY_SLOT                         0x83
#define EISA_INVALID_BIOS_CALL                  0x86



//
// The following structures are used to interpret mips
// DeviceSpecificData of CM_PARTIAL_RESOURCE_DESCRIPTOR.
//

//
// Device data records for adapters.
//

//
// The device data record for the Emulex SCSI controller.
//

typedef struct _CM_SCSI_DEVICE_DATA {
    USHORT Version;
    USHORT Revision;
    UCHAR HostIdentifier;
} CM_SCSI_DEVICE_DATA, *PCM_SCSI_DEVICE_DATA;

//
// Device data records for controllers.
//

//
// The device data record for the Video controller.
//

typedef struct _CM_VIDEO_DEVICE_DATA {
    USHORT Version;
    USHORT Revision;
    ULONG VideoClock;
} CM_VIDEO_DEVICE_DATA, *PCM_VIDEO_DEVICE_DATA;

//
// The device data record for the SONIC network controller.
//

typedef struct _CM_SONIC_DEVICE_DATA {
    USHORT Version;
    USHORT Revision;
    USHORT DataConfigurationRegister;
    UCHAR EthernetAddress[8];
} CM_SONIC_DEVICE_DATA, *PCM_SONIC_DEVICE_DATA;

//
// The device data record for the serial controller.
//

typedef struct _CM_SERIAL_DEVICE_DATA {
    USHORT Version;
    USHORT Revision;
    ULONG BaudClock;
} CM_SERIAL_DEVICE_DATA, *PCM_SERIAL_DEVICE_DATA;

//
// Device data records for peripherals.
//

//
// The device data record for the Monitor peripheral.
//

typedef struct _CM_MONITOR_DEVICE_DATA {
    USHORT Version;
    USHORT Revision;
    USHORT HorizontalScreenSize;
    USHORT VerticalScreenSize;
    USHORT HorizontalResolution;
    USHORT VerticalResolution;
    USHORT HorizontalDisplayTimeLow;
    USHORT HorizontalDisplayTime;
    USHORT HorizontalDisplayTimeHigh;
    USHORT HorizontalBackPorchLow;
    USHORT HorizontalBackPorch;
    USHORT HorizontalBackPorchHigh;
    USHORT HorizontalFrontPorchLow;
    USHORT HorizontalFrontPorch;
    USHORT HorizontalFrontPorchHigh;
    USHORT HorizontalSyncLow;
    USHORT HorizontalSync;
    USHORT HorizontalSyncHigh;
    USHORT VerticalBackPorchLow;
    USHORT VerticalBackPorch;
    USHORT VerticalBackPorchHigh;
    USHORT VerticalFrontPorchLow;
    USHORT VerticalFrontPorch;
    USHORT VerticalFrontPorchHigh;
    USHORT VerticalSyncLow;
    USHORT VerticalSync;
    USHORT VerticalSyncHigh;
} CM_MONITOR_DEVICE_DATA, *PCM_MONITOR_DEVICE_DATA;

//
// The device data record for the Floppy peripheral.
//

typedef struct _CM_FLOPPY_DEVICE_DATA {
    USHORT Version;
    USHORT Revision;
    CHAR Size[8];
    ULONG MaxDensity;
    ULONG MountDensity;
    //
    // New data fields for version >= 2.0
    //
    UCHAR StepRateHeadUnloadTime;
    UCHAR HeadLoadTime;
    UCHAR MotorOffTime;
    UCHAR SectorLengthCode;
    UCHAR SectorPerTrack;
    UCHAR ReadWriteGapLength;
    UCHAR DataTransferLength;
    UCHAR FormatGapLength;
    UCHAR FormatFillCharacter;
    UCHAR HeadSettleTime;
    UCHAR MotorSettleTime;
    UCHAR MaximumTrackValue;
    UCHAR DataTransferRate;
} CM_FLOPPY_DEVICE_DATA, *PCM_FLOPPY_DEVICE_DATA;

//
// The device data record for the Keyboard peripheral.
// The KeyboardFlags is defined (by x86 BIOS INT 16h, function 02) as:
//      bit 7 : Insert on
//      bit 6 : Caps Lock on
//      bit 5 : Num Lock on
//      bit 4 : Scroll Lock on
//      bit 3 : Alt Key is down
//      bit 2 : Ctrl Key is down
//      bit 1 : Left shift key is down
//      bit 0 : Right shift key is down
//

typedef struct _CM_KEYBOARD_DEVICE_DATA {
    USHORT Version;
    USHORT Revision;
    UCHAR Type;
    UCHAR Subtype;
    USHORT KeyboardFlags;
} CM_KEYBOARD_DEVICE_DATA, *PCM_KEYBOARD_DEVICE_DATA;

//
// Declaration of the structure for disk geometries
//

typedef struct _CM_DISK_GEOMETRY_DEVICE_DATA {
    ULONG BytesPerSector;
    ULONG NumberOfCylinders;
    ULONG SectorsPerTrack;
    ULONG NumberOfHeads;
} CM_DISK_GEOMETRY_DEVICE_DATA, *PCM_DISK_GEOMETRY_DEVICE_DATA;



//
// Define the bitmasks for resource options
//

#define IO_RESOURCE_PREFERRED       0x01
#define IO_RESOURCE_DEFAULT         0x02
#define IO_RESOURCE_ALTERNATIVE     0x08

//
// Define interrupt affinity policy values
//

#if defined(NT_PROCESSOR_GROUPS)

typedef USHORT IRQ_DEVICE_POLICY, *PIRQ_DEVICE_POLICY;
typedef enum _IRQ_DEVICE_POLICY_USHORT {
    IrqPolicyMachineDefault = 0,
    IrqPolicyAllCloseProcessors = 1,
    IrqPolicyOneCloseProcessor = 2,
    IrqPolicyAllProcessorsInMachine = 3,
    IrqPolicyAllProcessorsInGroup = 3,
    IrqPolicySpecifiedProcessors = 4,
    IrqPolicySpreadMessagesAcrossAllProcessors = 5
};

#else

typedef enum _IRQ_DEVICE_POLICY {
    IrqPolicyMachineDefault = 0,
    IrqPolicyAllCloseProcessors,
    IrqPolicyOneCloseProcessor,
    IrqPolicyAllProcessorsInMachine,
    IrqPolicySpecifiedProcessors,
    IrqPolicySpreadMessagesAcrossAllProcessors
} IRQ_DEVICE_POLICY, *PIRQ_DEVICE_POLICY;

#endif

//
// Define interrupt priority policy values
//

typedef enum _IRQ_PRIORITY {
    IrqPriorityUndefined = 0,
    IrqPriorityLow,
    IrqPriorityNormal,
    IrqPriorityHigh
} IRQ_PRIORITY, *PIRQ_PRIORITY;

//
// Define interrupt group affinity policy
//

typedef enum _IRQ_GROUP_POLICY {
    GroupAffinityAllGroupZero = 0,
    GroupAffinityDontCare
} IRQ_GROUP_POLICY, *PIRQ_GROUP_POLICY;

//
// This structure defines one type of resource requested by the driver
//

typedef struct _IO_RESOURCE_DESCRIPTOR {
    UCHAR Option;
    UCHAR Type;                         // use CM_RESOURCE_TYPE
    UCHAR ShareDisposition;             // use CM_SHARE_DISPOSITION
    UCHAR Spare1;
    USHORT Flags;                       // use CM resource flag defines
    USHORT Spare2;                      // align

    union {
        struct {
            ULONG Length;
            ULONG Alignment;
            PHYSICAL_ADDRESS MinimumAddress;
            PHYSICAL_ADDRESS MaximumAddress;
        } Port;

        struct {
            ULONG Length;
            ULONG Alignment;
            PHYSICAL_ADDRESS MinimumAddress;
            PHYSICAL_ADDRESS MaximumAddress;
        } Memory;

        struct {
            ULONG MinimumVector;
            ULONG MaximumVector;
#if defined(NT_PROCESSOR_GROUPS)
            IRQ_DEVICE_POLICY AffinityPolicy;
            USHORT Group;
#else
            IRQ_DEVICE_POLICY AffinityPolicy;
#endif
            IRQ_PRIORITY PriorityPolicy;
            KAFFINITY TargetedProcessors;
        } Interrupt;

        struct {
            ULONG MinimumChannel;
            ULONG MaximumChannel;
        } Dma;

        struct {
            ULONG Length;
            ULONG Alignment;
            PHYSICAL_ADDRESS MinimumAddress;
            PHYSICAL_ADDRESS MaximumAddress;
        } Generic;

        struct {
            ULONG Data[3];
        } DevicePrivate;

        //
        // Bus Number information.
        //

        struct {
            ULONG Length;
            ULONG MinBusNumber;
            ULONG MaxBusNumber;
            ULONG Reserved;
        } BusNumber;

        struct {
            ULONG Priority;   // use LCPRI_Xxx values in cfg.h
            ULONG Reserved1;
            ULONG Reserved2;
        } ConfigData;

        //
        // The following structures provide descriptions
        // for memory resource requirement greater than MAXULONG
        //

        struct {
            ULONG Length40;
            ULONG Alignment40;
            PHYSICAL_ADDRESS MinimumAddress;
            PHYSICAL_ADDRESS MaximumAddress;
        } Memory40;

        struct {
            ULONG Length48;
            ULONG Alignment48;
            PHYSICAL_ADDRESS MinimumAddress;
            PHYSICAL_ADDRESS MaximumAddress;
        } Memory48;

        struct {
            ULONG Length64;
            ULONG Alignment64;
            PHYSICAL_ADDRESS MinimumAddress;
            PHYSICAL_ADDRESS MaximumAddress;
        } Memory64;


    } u;

} IO_RESOURCE_DESCRIPTOR, *PIO_RESOURCE_DESCRIPTOR;




typedef struct _IO_RESOURCE_LIST {
    USHORT Version;
    USHORT Revision;

    ULONG Count;
    IO_RESOURCE_DESCRIPTOR Descriptors[1];
} IO_RESOURCE_LIST, *PIO_RESOURCE_LIST;


typedef struct _IO_RESOURCE_REQUIREMENTS_LIST {
    ULONG ListSize;
    INTERFACE_TYPE InterfaceType; // unused for WDM
    ULONG BusNumber; // unused for WDM
    ULONG SlotNumber;
    ULONG Reserved[3];
    ULONG AlternativeLists;
    IO_RESOURCE_LIST  List[1];
} IO_RESOURCE_REQUIREMENTS_LIST, *PIO_RESOURCE_REQUIREMENTS_LIST;

//
// for move macros
//
#ifdef _MAC
#ifndef _INC_STRING
#include <string.h>
#endif /* _INC_STRING */
#else
#include <string.h>
#endif // _MAC


#ifndef _SLIST_HEADER_
#define _SLIST_HEADER_

#if defined(_WIN64)

//
// The type SINGLE_LIST_ENTRY is not suitable for use with SLISTs.  For
// WIN64, an entry on an SLIST is required to be 16-byte aligned, while a
// SINGLE_LIST_ENTRY structure has only 8 byte alignment.
//
// Therefore, all SLIST code should use the SLIST_ENTRY type instead of the
// SINGLE_LIST_ENTRY type.
//

#pragma warning(push)
#pragma warning(disable:4324)   // structure padded due to align()
typedef struct DECLSPEC_ALIGN(16) _SLIST_ENTRY *PSLIST_ENTRY;
typedef struct DECLSPEC_ALIGN(16) _SLIST_ENTRY {
    PSLIST_ENTRY Next;
} SLIST_ENTRY;
#pragma warning(pop)

typedef struct _SLIST_ENTRY32 {
    ULONG Next;
} SLIST_ENTRY32, *PSLIST_ENTRY32;

#else

#define SLIST_ENTRY SINGLE_LIST_ENTRY
#define _SLIST_ENTRY _SINGLE_LIST_ENTRY
#define PSLIST_ENTRY PSINGLE_LIST_ENTRY

typedef SLIST_ENTRY SLIST_ENTRY32, *PSLIST_ENTRY32;

#endif // _WIN64

#if defined(_WIN64)

typedef union DECLSPEC_ALIGN(16) _SLIST_HEADER {
    struct {  // original struct
        ULONGLONG Alignment;
        ULONGLONG Region;
    } DUMMYSTRUCTNAME;
    struct {  // 8-byte header
        ULONGLONG Depth:16;
        ULONGLONG Sequence:9;
        ULONGLONG NextEntry:39;
        ULONGLONG HeaderType:1; // 0: 8-byte; 1: 16-byte
        ULONGLONG Init:1;       // 0: uninitialized; 1: initialized
        ULONGLONG Reserved:59;
        ULONGLONG Region:3;
    } Header8;
    struct {  // ia64 16-byte header
        ULONGLONG Depth:16;
        ULONGLONG Sequence:48;
        ULONGLONG HeaderType:1; // 0: 8-byte; 1: 16-byte
        ULONGLONG Init:1;       // 0: uninitialized; 1: initialized
        ULONGLONG Reserved:2;
        ULONGLONG NextEntry:60; // last 4 bits are always 0's
    } Header16;
    struct {  // x64 16-byte header
        ULONGLONG Depth:16;
        ULONGLONG Sequence:48;
        ULONGLONG HeaderType:1; // 0: 8-byte; 1: 16-byte
        ULONGLONG Reserved:3;
        ULONGLONG NextEntry:60; // last 4 bits are always 0's
    } HeaderX64;
} SLIST_HEADER, *PSLIST_HEADER;

typedef union _SLIST_HEADER32{
    ULONGLONG Alignment;
    struct {
        SLIST_ENTRY32 Next;
        USHORT Depth;
        USHORT Sequence;
    } DUMMYSTRUCTNAME;
} SLIST_HEADER32, *PSLIST_HEADER32;

#else

typedef union _SLIST_HEADER {
    ULONGLONG Alignment;
    struct {
        SLIST_ENTRY Next;
        USHORT Depth;
        USHORT Sequence;
    } DUMMYSTRUCTNAME;
} SLIST_HEADER, *PSLIST_HEADER;

typedef SLIST_HEADER SLIST_HEADER32, *PSLIST_HEADER32;

#endif // _WIN64

#endif // _SLIST_HEADER_

//
// If debugging support enabled, define an ASSERT macro that works.  Otherwise
// define the ASSERT macro to expand to an empty expression.
//
// The ASSERT macro has been updated to be an expression instead of a statement.
//

NTSYSAPI
VOID
NTAPI
RtlAssert(
    __in PVOID VoidFailedAssertion,
    __in PVOID VoidFileName,
    __in ULONG LineNumber,
    __in_opt PSTR MutableMessage
    );

#if DBG

#define ASSERT( exp ) \
    ((!(exp)) ? \
        (RtlAssert( #exp, __FILE__, __LINE__, NULL ),FALSE) : \
        TRUE)

#define ASSERTMSG( msg, exp ) \
    ((!(exp)) ? \
        (RtlAssert( #exp, __FILE__, __LINE__, msg ),FALSE) : \
        TRUE)

#define RTL_SOFT_ASSERT(_exp) \
    ((!(_exp)) ? \
        (DbgPrint("%s(%d): Soft assertion failed\n   Expression: %s\n", __FILE__, __LINE__, #_exp),FALSE) : \
        TRUE)

#define RTL_SOFT_ASSERTMSG(_msg, _exp) \
    ((!(_exp)) ? \
        (DbgPrint("%s(%d): Soft assertion failed\n   Expression: %s\n   Message: %s\n", __FILE__, __LINE__, #_exp, (_msg)),FALSE) : \
        TRUE)

#if _MSC_VER >= 1300

#define NT_ASSERT(_exp) \
    ((!(_exp)) ? \
        (__annotation(L"Debug", L"AssertFail", L#_exp), \
         DbgRaiseAssertionFailure(), FALSE) : \
        TRUE)

#define NT_ASSERTMSG(_msg, _exp) \
    ((!(_exp)) ? \
        (__annotation(L"Debug", L"AssertFail", L##_msg), \
         DbgRaiseAssertionFailure(), FALSE) : \
        TRUE)

#define NT_ASSERTMSGW(_msg, _exp) \
    ((!(_exp)) ? \
        (__annotation(L"Debug", L"AssertFail", _msg), \
         DbgRaiseAssertionFailure(), FALSE) : \
        TRUE)

#define NT_VERIFY     NT_ASSERT
#define NT_VERIFYMSG  NT_ASSERTMSG
#define NT_VERIFYMSGW NT_ASSERTMSGW

#endif // #if _MSC_VER >= 1300

#define RTL_VERIFY         ASSERT
#define RTL_VERIFYMSG      ASSERTMSG

#define RTL_SOFT_VERIFY    RTL_SOFT_ASSERT
#define RTL_SOFT_VERIFYMSG RTL_SOFT_ASSERTMSG

#else
#define ASSERT( exp )         ((void) 0)
#define ASSERTMSG( msg, exp ) ((void) 0)

#if _MSC_VER >= 1300

#define NT_ASSERT(_exp)           ((void) 0)
#define NT_ASSERTMSG(_msg, _exp)  ((void) 0)
#define NT_ASSERTMSGW(_msg, _exp) ((void) 0)

#define NT_VERIFY(_exp)           ((_exp) ? TRUE : FALSE)
#define NT_VERIFYMSG(_msg, _exp ) ((_exp) ? TRUE : FALSE)
#define NT_VERIFYMSGW(_msg, _exp) ((_exp) ? TRUE : FALSE)

#endif // #if _MSC_VER >= 1300

#define RTL_SOFT_ASSERT(_exp)          ((void) 0)
#define RTL_SOFT_ASSERTMSG(_msg, _exp) ((void) 0)

#define RTL_VERIFY( exp )         ((exp) ? TRUE : FALSE)
#define RTL_VERIFYMSG( msg, exp ) ((exp) ? TRUE : FALSE)

#define RTL_SOFT_VERIFY(_exp)         ((_exp) ? TRUE : FALSE)
#define RTL_SOFT_VERIFYMSG(msg, _exp) ((_exp) ? TRUE : FALSE)

#endif // DBG

//
//  Doubly-linked list manipulation routines.
//


//
//  VOID
//  InitializeListHead32(
//      PLIST_ENTRY32 ListHead
//      );
//

#define InitializeListHead32(ListHead) (\
    (ListHead)->Flink = (ListHead)->Blink = PtrToUlong((ListHead)))

#if !defined(MIDL_PASS) && !defined(SORTPP_PASS)

#define RTL_STATIC_LIST_HEAD(x) LIST_ENTRY x = { &x, &x }

FORCEINLINE
VOID
InitializeListHead(
    __out PLIST_ENTRY ListHead
    )
{
    ListHead->Flink = ListHead->Blink = ListHead;
}

__checkReturn
BOOLEAN
FORCEINLINE
IsListEmpty(
    __in const LIST_ENTRY * ListHead
    )
{
    return (BOOLEAN)(ListHead->Flink == ListHead);
}

FORCEINLINE
BOOLEAN
RemoveEntryList(
    __in PLIST_ENTRY Entry
    )
{
    PLIST_ENTRY Blink;
    PLIST_ENTRY Flink;

    Flink = Entry->Flink;
    Blink = Entry->Blink;
    Blink->Flink = Flink;
    Flink->Blink = Blink;
    return (BOOLEAN)(Flink == Blink);
}

FORCEINLINE
PLIST_ENTRY
RemoveHeadList(
    __inout PLIST_ENTRY ListHead
    )
{
    PLIST_ENTRY Flink;
    PLIST_ENTRY Entry;

    Entry = ListHead->Flink;
    Flink = Entry->Flink;
    ListHead->Flink = Flink;
    Flink->Blink = ListHead;
    return Entry;
}



FORCEINLINE
PLIST_ENTRY
RemoveTailList(
    __inout PLIST_ENTRY ListHead
    )
{
    PLIST_ENTRY Blink;
    PLIST_ENTRY Entry;

    Entry = ListHead->Blink;
    Blink = Entry->Blink;
    ListHead->Blink = Blink;
    Blink->Flink = ListHead;
    return Entry;
}


FORCEINLINE
VOID
InsertTailList(
    __inout PLIST_ENTRY ListHead,
    __inout __drv_aliasesMem PLIST_ENTRY Entry
    )
{
    PLIST_ENTRY Blink;

    Blink = ListHead->Blink;
    Entry->Flink = ListHead;
    Entry->Blink = Blink;
    Blink->Flink = Entry;
    ListHead->Blink = Entry;
}


FORCEINLINE
VOID
InsertHeadList(
    __inout PLIST_ENTRY ListHead,
    __inout __drv_aliasesMem PLIST_ENTRY Entry
    )
{
    PLIST_ENTRY Flink;

    Flink = ListHead->Flink;
    Entry->Flink = Flink;
    Entry->Blink = ListHead;
    Flink->Blink = Entry;
    ListHead->Flink = Entry;
}

FORCEINLINE
VOID
AppendTailList(
    __inout PLIST_ENTRY ListHead,
    __inout PLIST_ENTRY ListToAppend
    )
{
    PLIST_ENTRY ListEnd = ListHead->Blink;

    ListHead->Blink->Flink = ListToAppend;
    ListHead->Blink = ListToAppend->Blink;
    ListToAppend->Blink->Flink = ListHead;
    ListToAppend->Blink = ListEnd;
}

FORCEINLINE
PSINGLE_LIST_ENTRY
PopEntryList(
    __inout PSINGLE_LIST_ENTRY ListHead
    )
{
    PSINGLE_LIST_ENTRY FirstEntry;
    FirstEntry = ListHead->Next;
    if (FirstEntry != NULL) {
        ListHead->Next = FirstEntry->Next;
    }

    return FirstEntry;
}


FORCEINLINE
VOID
PushEntryList(
    __inout PSINGLE_LIST_ENTRY ListHead,
    __inout __drv_aliasesMem PSINGLE_LIST_ENTRY Entry
    )
{
    Entry->Next = ListHead->Next;
    ListHead->Next = Entry;
}

#endif // !MIDL_PASS

//
// Subroutines for dealing with the Registry
//

typedef
__drv_functionClass(RTL_QUERY_REGISTRY_ROUTINE)
__drv_maxIRQL(PASSIVE_LEVEL)
__drv_sameIRQL
NTSTATUS
NTAPI
RTL_QUERY_REGISTRY_ROUTINE(
    __in_z PWSTR ValueName,
    __in ULONG ValueType,
    __in_bcount_opt(ValueLength) PVOID ValueData,
    __in ULONG ValueLength,
    __in_opt PVOID Context,
    __in_opt PVOID EntryContext
    );
typedef RTL_QUERY_REGISTRY_ROUTINE *PRTL_QUERY_REGISTRY_ROUTINE;

typedef struct _RTL_QUERY_REGISTRY_TABLE {
    PRTL_QUERY_REGISTRY_ROUTINE QueryRoutine;
    ULONG Flags;
    PWSTR Name;
    PVOID EntryContext;
    ULONG DefaultType;
    PVOID DefaultData;
    ULONG DefaultLength;

} RTL_QUERY_REGISTRY_TABLE, *PRTL_QUERY_REGISTRY_TABLE;


//
// The following flags specify how the Name field of a RTL_QUERY_REGISTRY_TABLE
// entry is interpreted.  A NULL name indicates the end of the table.
//

#define RTL_QUERY_REGISTRY_SUBKEY   0x00000001  // Name is a subkey and remainder of
                                                // table or until next subkey are value
                                                // names for that subkey to look at.

#define RTL_QUERY_REGISTRY_TOPKEY   0x00000002  // Reset current key to original key for
                                                // this and all following table entries.

#define RTL_QUERY_REGISTRY_REQUIRED 0x00000004  // Fail if no match found for this table
                                                // entry.

#define RTL_QUERY_REGISTRY_NOVALUE  0x00000008  // Used to mark a table entry that has no
                                                // value name, just wants a call out, not
                                                // an enumeration of all values.

#define RTL_QUERY_REGISTRY_NOEXPAND 0x00000010  // Used to suppress the expansion of
                                                // REG_MULTI_SZ into multiple callouts or
                                                // to prevent the expansion of environment
                                                // variable values in REG_EXPAND_SZ

#define RTL_QUERY_REGISTRY_DIRECT   0x00000020  // QueryRoutine field ignored.  EntryContext
                                                // field points to location to store value.
                                                // For null terminated strings, EntryContext
                                                // points to UNICODE_STRING structure that
                                                // that describes maximum size of buffer.
                                                // If .Buffer field is NULL then a buffer is
                                                // allocated.
                                                //

#define RTL_QUERY_REGISTRY_DELETE   0x00000040  // Used to delete value keys after they
                                                // are queried.

#define RTL_QUERY_REGISTRY_NOSTRING 0x00000080  // Used with RTL_QUERY_REGISTRY_DIRECT in
                                                // cases where the caller expects a
                                                // non-string value.  Otherwise, the
                                                // assumption that EntryContext points to
                                                // a UNICODE_STRING structure can overrun
                                                // the caller's buffer.
                                                //

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
RtlQueryRegistryValues(
    __in     ULONG RelativeTo,
    __in     PCWSTR Path,
    __inout __drv_at(*(*QueryTable).EntryContext, __out)
        PRTL_QUERY_REGISTRY_TABLE QueryTable,
    __in_opt PVOID Context,
    __in_opt PVOID Environment
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
RtlWriteRegistryValue(
    __in ULONG RelativeTo,
    __in PCWSTR Path,
    __in_z PCWSTR ValueName,
    __in ULONG ValueType,
    __in_bcount_opt(ValueLength) PVOID ValueData,
    __in ULONG ValueLength
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
RtlDeleteRegistryValue(
    __in ULONG RelativeTo,
    __in PCWSTR Path,
    __in_z PCWSTR ValueName
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
RtlCreateRegistryKey(
    __in ULONG RelativeTo,
    __in PWSTR Path
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
__checkReturn
NTSYSAPI
NTSTATUS
NTAPI
RtlCheckRegistryKey(
    __in ULONG RelativeTo,
    __in PWSTR Path
    );
#endif

//
// The following values for the RelativeTo parameter determine what the
// Path parameter to RtlQueryRegistryValues is relative to.
//

#define RTL_REGISTRY_ABSOLUTE     0   // Path is a full path
#define RTL_REGISTRY_SERVICES     1   // \Registry\Machine\System\CurrentControlSet\Services
#define RTL_REGISTRY_CONTROL      2   // \Registry\Machine\System\CurrentControlSet\Control
#define RTL_REGISTRY_WINDOWS_NT   3   // \Registry\Machine\Software\Microsoft\Windows NT\CurrentVersion
#define RTL_REGISTRY_DEVICEMAP    4   // \Registry\Machine\Hardware\DeviceMap
#define RTL_REGISTRY_USER         5   // \Registry\User\CurrentUser
#define RTL_REGISTRY_MAXIMUM      6
#define RTL_REGISTRY_HANDLE       0x40000000    // Low order bits are registry handle
#define RTL_REGISTRY_OPTIONAL     0x80000000    // Indicates the key node is optional


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
RtlIntegerToUnicodeString (
    __in ULONG Value,
    __in_opt ULONG Base,
    __inout PUNICODE_STRING String
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
RtlInt64ToUnicodeString (
    __in ULONGLONG Value,
    __in_opt ULONG Base,
    __inout PUNICODE_STRING String
    );
#endif

#ifdef _WIN64
#define RtlIntPtrToUnicodeString(Value, Base, String) RtlInt64ToUnicodeString(Value, Base, String)
#else
#define RtlIntPtrToUnicodeString(Value, Base, String) RtlIntegerToUnicodeString(Value, Base, String)
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
RtlUnicodeStringToInteger (
    __in PCUNICODE_STRING String,
    __in_opt ULONG Base,
    __out PULONG Value
    );
#endif

//
//  String manipulation routines
//

#ifdef _NTSYSTEM_

#define NLS_MB_CODE_PAGE_TAG NlsMbCodePageTag
#define NLS_MB_OEM_CODE_PAGE_TAG NlsMbOemCodePageTag

#else

#define NLS_MB_CODE_PAGE_TAG (*NlsMbCodePageTag)
#define NLS_MB_OEM_CODE_PAGE_TAG (*NlsMbOemCodePageTag)

#endif // _NTSYSTEM_

extern BOOLEAN NLS_MB_CODE_PAGE_TAG;     // TRUE -> Multibyte CP, FALSE -> Singlebyte
extern BOOLEAN NLS_MB_OEM_CODE_PAGE_TAG; // TRUE -> Multibyte CP, FALSE -> Singlebyte

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
NTSYSAPI
VOID
NTAPI
RtlInitString(
    __out PSTRING DestinationString,
    __in_z_opt __drv_aliasesMem PCSZ SourceString
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
NTSYSAPI
VOID
NTAPI
RtlInitAnsiString(
    __out PANSI_STRING DestinationString,
    __in_z_opt __drv_aliasesMem PCSZ SourceString
    );
#endif

__drv_maxIRQL(DISPATCH_LEVEL)
NTSYSAPI
VOID
NTAPI
RtlInitUnicodeString(
    __out PUNICODE_STRING DestinationString,
    __in_z_opt __drv_aliasesMem PCWSTR SourceString
    );

#if !defined(MIDL_PASS)
FORCEINLINE
VOID
RtlInitEmptyUnicodeString(
    __out PUNICODE_STRING UnicodeString,
    __bcount_opt(BufferSize) __drv_aliasesMem PWCHAR Buffer,
    __in USHORT BufferSize
    )
{
    UnicodeString->Length = 0;
    UnicodeString->MaximumLength = BufferSize;
    UnicodeString->Buffer = Buffer;
}

FORCEINLINE
VOID
RtlInitEmptyAnsiString(
    __out PANSI_STRING AnsiString,
    __bcount_opt(BufferSize) __drv_aliasesMem PCHAR Buffer,
    __in USHORT BufferSize
    )
{
    AnsiString->Length = 0;
    AnsiString->MaximumLength = BufferSize;
    AnsiString->Buffer = Buffer;
}
#endif // !defined(MIDL_PASS)

//
// NLS String functions
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
__checkReturn
NTSYSAPI
NTSTATUS
NTAPI
RtlAnsiStringToUnicodeString(
    __drv_when(AllocateDestinationString, __out __drv_at(DestinationString->Buffer, __drv_allocatesMem(Mem)))
    __drv_when(!AllocateDestinationString, __inout)
        PUNICODE_STRING DestinationString,
    __in PCANSI_STRING SourceString,
    __in BOOLEAN AllocateDestinationString
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
__drv_when(AllocateDestinationString, __checkReturn)
NTSYSAPI
NTSTATUS
NTAPI
RtlUnicodeStringToAnsiString(
    __drv_when(AllocateDestinationString, __out __drv_at(DestinationString->Buffer, __drv_allocatesMem(Mem)))
    __drv_when(!AllocateDestinationString, __inout)
        PANSI_STRING DestinationString,
    __in PCUNICODE_STRING SourceString,
    __in BOOLEAN AllocateDestinationString
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
__checkReturn
NTSYSAPI
LONG
NTAPI
RtlCompareUnicodeStrings(
    __in_ecount(String1Length) PCWCH String1,
    __in SIZE_T String1Length,
    __in_ecount(String2Length) PCWCH String2,
    __in SIZE_T String2Length,
    __in BOOLEAN CaseInSensitive
    );

__drv_maxIRQL(PASSIVE_LEVEL)
__checkReturn
NTSYSAPI
LONG
NTAPI
RtlCompareUnicodeString(
    __in PCUNICODE_STRING String1,
    __in PCUNICODE_STRING String2,
    __in BOOLEAN CaseInSensitive
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
__checkReturn
NTSYSAPI
BOOLEAN
NTAPI
RtlEqualUnicodeString(
    __in PCUNICODE_STRING String1,
    __in PCUNICODE_STRING String2,
    __in BOOLEAN CaseInSensitive
    );
#endif

#define HASH_STRING_ALGORITHM_DEFAULT   (0)
#define HASH_STRING_ALGORITHM_X65599    (1)
#define HASH_STRING_ALGORITHM_INVALID   (0xffffffff)

#if (NTDDI_VERSION >= NTDDI_WINXP)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
RtlHashUnicodeString(
    __in PCUNICODE_STRING String,
    __in BOOLEAN CaseInSensitive,
    __in ULONG HashAlgorithm,
    __out PULONG HashValue
    );

#endif // NTDDI_VERSION >= NTDDI_WINXP


#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTSYSAPI
VOID
NTAPI
RtlCopyUnicodeString(
    __inout PUNICODE_STRING DestinationString,
    __in_opt PCUNICODE_STRING SourceString
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTSYSAPI
NTSTATUS
NTAPI
RtlAppendUnicodeStringToString (
    __inout PUNICODE_STRING Destination,
    __in PCUNICODE_STRING Source
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTSYSAPI
NTSTATUS
NTAPI
RtlAppendUnicodeToString (
    __inout PUNICODE_STRING Destination,
    __in_z_opt PCWSTR Source
    );
#endif



#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
WCHAR
NTAPI
RtlUpcaseUnicodeChar(
    __in WCHAR SourceCharacter
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
WCHAR
NTAPI
RtlDowncaseUnicodeChar(
    __in WCHAR SourceCharacter
    );
#endif

__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
VOID
NTAPI
RtlFreeUnicodeString(
    __inout __drv_at(UnicodeString->Buffer, __drv_freesMem(Mem))
        PUNICODE_STRING UnicodeString
    );

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
VOID
NTAPI
RtlFreeAnsiString(
    __inout __drv_at(AnsiString->Buffer, __drv_freesMem(Mem))
        PANSI_STRING AnsiString
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
ULONG
NTAPI
RtlxUnicodeStringToAnsiSize(
    __in PCUNICODE_STRING UnicodeString
    );
#endif

//
//  NTSYSAPI
//  ULONG
//  NTAPI
//  RtlUnicodeStringToAnsiSize(
//      PUNICODE_STRING UnicodeString
//      );
//

#define RtlUnicodeStringToAnsiSize(STRING) (                  \
    NLS_MB_CODE_PAGE_TAG ?                                    \
    RtlxUnicodeStringToAnsiSize(STRING) :                     \
    ((STRING)->Length + sizeof(UNICODE_NULL)) / sizeof(WCHAR) \
)


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
ULONG
NTAPI
RtlxAnsiStringToUnicodeSize(
    __in PCANSI_STRING AnsiString
    );
#endif

//
//  NTSYSAPI
//  ULONG
//  NTAPI
//  RtlAnsiStringToUnicodeSize(
//      PANSI_STRING AnsiString
//      );
//

#define RtlAnsiStringToUnicodeSize(STRING) (                 \
    NLS_MB_CODE_PAGE_TAG ?                                   \
    RtlxAnsiStringToUnicodeSize(STRING) :                    \
    ((STRING)->Length + sizeof(ANSI_NULL)) * sizeof(WCHAR) \
)

#if (NTDDI_VERSION >= NTDDI_WIN7)
__drv_maxIRQL(PASSIVE_LEVEL)
__checkReturn
NTSYSAPI
NTSTATUS
NTAPI
RtlUnicodeToUTF8N(
    __out_bcount_part(UTF8StringMaxByteCount, *UTF8StringActualByteCount) PCHAR  UTF8StringDestination,
    __in                                ULONG  UTF8StringMaxByteCount,
    __out                               PULONG UTF8StringActualByteCount,
    __in_bcount(UnicodeStringByteCount) PCWCH UnicodeStringSource,
    __in                                ULONG  UnicodeStringByteCount
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
__drv_maxIRQL(PASSIVE_LEVEL)
__checkReturn
NTSYSAPI
NTSTATUS
NTAPI
RtlUTF8ToUnicodeN(
    __out_bcount_part(UnicodeStringMaxByteCount, *UnicodeStringActualByteCount) PWSTR  UnicodeStringDestination,
    __in                             ULONG  UnicodeStringMaxByteCount,
    __out                            PULONG UnicodeStringActualByteCount,
    __in_bcount(UTF8StringByteCount) PCCH   UTF8StringSource,
    __in                             ULONG  UTF8StringByteCount
    );
#endif



#include <guiddef.h>



#ifndef DEFINE_GUIDEX
    #define DEFINE_GUIDEX(name) EXTERN_C const CDECL GUID name
#endif // !defined(DEFINE_GUIDEX)

#ifndef STATICGUIDOF
    #define STATICGUIDOF(guid) STATIC_##guid
#endif // !defined(STATICGUIDOF)

#ifndef __IID_ALIGNED__
    #define __IID_ALIGNED__
    #ifdef __cplusplus
        inline int IsEqualGUIDAligned(REFGUID guid1, REFGUID guid2)
        {
            return ((*(PLONGLONG)(&guid1) == *(PLONGLONG)(&guid2)) && (*((PLONGLONG)(&guid1) + 1) == *((PLONGLONG)(&guid2) + 1)));
        }
    #else // !__cplusplus
        #define IsEqualGUIDAligned(guid1, guid2) \
            ((*(PLONGLONG)(guid1) == *(PLONGLONG)(guid2)) && (*((PLONGLONG)(guid1) + 1) == *((PLONGLONG)(guid2) + 1)))
    #endif // !__cplusplus
#endif // !__IID_ALIGNED__

__drv_maxIRQL(PASSIVE_LEVEL)
__checkReturn
NTSYSAPI
NTSTATUS
NTAPI
RtlStringFromGUID(
    __in REFGUID Guid,
    __out __drv_at(GuidString->Buffer, __drv_allocatesMem(Mem))
        PUNICODE_STRING GuidString
    );

__drv_maxIRQL(PASSIVE_LEVEL)
__checkReturn
NTSYSAPI
NTSTATUS
NTAPI
RtlGUIDFromString(
    __in PCUNICODE_STRING GuidString,
    __out GUID* Guid
    );

//
// Fast primitives to compare, move, and zero memory
//



#if _DBG_MEMCPY_INLINE_ && !defined(MIDL_PASS) && !defined(_MEMCPY_INLINE_) && !defined(_CRTBLD)
#define _MEMCPY_INLINE_
FORCEINLINE
PVOID
__cdecl
memcpy_inline (
    __out_bcount_full(size) void *dst,
    __in_bcount(size) const void *src,
    __in size_t size
    )
{
    //
    // Make sure the source and destination do not overlap such that the
    // move destroys the destination.
    //
    if (((char *)dst > (char *)src) &&
        ((char *)dst < ((char *)src + size))) {
        __debugbreak();
    }
    return memcpy(dst, src, size);
}
#define memcpy memcpy_inline
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn
NTSYSAPI
SIZE_T
NTAPI
RtlCompareMemory (
    __in const VOID *Source1,
    __in const VOID *Source2,
    __in SIZE_T Length
    );

#endif

#define RtlEqualMemory(Destination,Source,Length) (!memcmp((Destination),(Source),(Length)))
#define RtlMoveMemory(Destination,Source,Length) memmove((Destination),(Source),(Length))
#define RtlCopyMemory(Destination,Source,Length) memcpy((Destination),(Source),(Length))
#define RtlFillMemory(Destination,Length,Fill) memset((Destination),(Fill),(Length))
#define RtlZeroMemory(Destination,Length) memset((Destination),0,(Length))


#if !defined(MIDL_PASS)

FORCEINLINE
PVOID
RtlSecureZeroMemory(
    __out_bcount_full(cnt) PVOID ptr,
    __in SIZE_T cnt
    )
{
    volatile char *vptr = (volatile char *)ptr;

#if defined(_M_AMD64)

        __stosb((PUCHAR)((ULONG64)vptr), 0, cnt);

#else

    while (cnt) {
        *vptr = 0;
        vptr++;
        cnt--;
    }

#endif

    return ptr;
}

#endif



#define RtlCopyBytes RtlCopyMemory
#define RtlZeroBytes RtlZeroMemory
#define RtlFillBytes RtlFillMemory

#if defined(_M_AMD64)

NTSYSAPI
VOID
NTAPI
RtlCopyMemoryNonTemporal (
   __out_bcount_full(Length) VOID UNALIGNED *Destination,
   __in_bcount(Length) CONST VOID UNALIGNED *Source,
   __in SIZE_T Length
   );

#else

#define RtlCopyMemoryNonTemporal RtlCopyMemory

#endif

#if (NTDDI_VERSION >= NTDDI_WIN2KSP3)
NTSYSAPI
VOID
FASTCALL
RtlPrefetchMemoryNonTemporal(
    __in PVOID Source,
    __in SIZE_T Length
    );

#endif

//
// Define kernel debugger print prototypes and macros.
//
// N.B. The following function cannot be directly imported because there are
//      a few places in the source tree where this function is redefined.
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)

#if (_MSC_FULL_VER >= 150030729) && !defined(IMPORT_NATIVE_DBG_BREAK)

#define DbgBreakPoint __debugbreak

#else

__analysis_noreturn
VOID
NTAPI
DbgBreakPoint(
    VOID
    );

#endif

#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__analysis_noreturn
NTSYSAPI
VOID
NTAPI
DbgBreakPointWithStatus(
    __in ULONG Status
    );
#endif

#define DBG_STATUS_CONTROL_C        1
#define DBG_STATUS_SYSRQ            2
#define DBG_STATUS_BUGCHECK_FIRST   3
#define DBG_STATUS_BUGCHECK_SECOND  4
#define DBG_STATUS_FATAL            5
#define DBG_STATUS_DEBUG_CONTROL    6
#define DBG_STATUS_WORKER           7

#if DBG

#define KdPrint(_x_) DbgPrint _x_
#define KdPrintEx(_x_) DbgPrintEx _x_
#define vKdPrintEx(_x_) vDbgPrintEx _x_
#define vKdPrintExWithPrefix(_x_) vDbgPrintExWithPrefix _x_
#define KdBreakPoint() DbgBreakPoint()

#define KdBreakPointWithStatus(s) DbgBreakPointWithStatus(s)

#else

#define KdPrint(_x_)
#define KdPrintEx(_x_)
#define vKdPrintEx(_x_)
#define vKdPrintExWithPrefix(_x_)
#define KdBreakPoint()

#define KdBreakPointWithStatus(s)

#endif // DBG

#ifndef _DBGNT_

ULONG
__cdecl
DbgPrint (
    __in_z __drv_formatString(printf) PCSTR Format,
    ...
    );

#if (NTDDI_VERSION >= NTDDI_WINXP)
NTSYSAPI
ULONG
__cdecl
DbgPrintEx (
    __in ULONG ComponentId,
    __in ULONG Level,
    __in_z __drv_formatString(printf) PCSTR Format,
    ...
    );
#endif

#ifdef _VA_LIST_DEFINED

#if (NTDDI_VERSION >= NTDDI_WINXP)
NTSYSAPI
ULONG
NTAPI
vDbgPrintEx(
    __in ULONG ComponentId,
    __in ULONG Level,
    __in_z PCCH Format,
    __in va_list arglist
    );

NTSYSAPI
ULONG
NTAPI
vDbgPrintExWithPrefix (
    __in_z PCCH Prefix,
    __in ULONG ComponentId,
    __in ULONG Level,
    __in_z PCCH Format,
    __in va_list arglist
    );

#endif

#endif // _VA_LIST_DEFINED

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTSYSAPI
ULONG
__cdecl
DbgPrintReturnControlC (
    __in_z __drv_formatString(printf) PCCH Format,
    ...
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
NTSYSAPI
NTSTATUS
NTAPI
DbgQueryDebugFilterState (
    __in ULONG ComponentId,
    __in ULONG Level
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
NTSYSAPI
NTSTATUS
NTAPI
DbgSetDebugFilterState (
    __in ULONG ComponentId,
    __in ULONG Level,
    __in BOOLEAN State
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
typedef
VOID
(*PDEBUG_PRINT_CALLBACK) (
    __in PSTRING Output,
    __in ULONG ComponentId,
    __in ULONG Level
    );

NTSYSAPI
NTSTATUS
NTAPI
DbgSetDebugPrintCallback (
    __in PDEBUG_PRINT_CALLBACK DebugPrintCallback,
    __in BOOLEAN Enable
    );
#endif

#endif // _DBGNT_

//
// Large integer arithmetic routines.
//

//
// Large integer add - 64-bits + 64-bits -> 64-bits
//


#if !defined(MIDL_PASS)


DECLSPEC_DEPRECATED_DDK         // Use native __int64 math
__drv_preferredFunction("compiler support for 64 bit", "Obsolete")
__inline
LARGE_INTEGER
NTAPI_INLINE
RtlLargeIntegerAdd (
    __in LARGE_INTEGER Addend1,
    __in LARGE_INTEGER Addend2
    )
{
    LARGE_INTEGER Sum;

    Sum.QuadPart = Addend1.QuadPart + Addend2.QuadPart;
    return Sum;
}

//
// Enlarged integer multiply - 32-bits * 32-bits -> 64-bits
//

DECLSPEC_DEPRECATED_DDK         // Use native __int64 math
__drv_preferredFunction("compiler support for 64 bit", "Obsolete")
__inline
LARGE_INTEGER
NTAPI_INLINE
RtlEnlargedIntegerMultiply (
    __in LONG Multiplicand,
    __in LONG Multiplier
    )
{
    LARGE_INTEGER Product;

    Product.QuadPart = (LONGLONG)Multiplicand * (ULONGLONG)Multiplier;
    return Product;
}

//
// Unsigned enlarged integer multiply - 32-bits * 32-bits -> 64-bits
//

DECLSPEC_DEPRECATED_DDK         // Use native __int64 math
__drv_preferredFunction("compiler support for 64 bit", "Obsolete")
__inline
LARGE_INTEGER
NTAPI_INLINE
RtlEnlargedUnsignedMultiply (
    __in ULONG Multiplicand,
    __in ULONG Multiplier
    )
{
    LARGE_INTEGER Product;

    Product.QuadPart = (ULONGLONG)Multiplicand * (ULONGLONG)Multiplier;
    return Product;
}

//
// Enlarged integer divide - 64-bits / 32-bits > 32-bits
//

DECLSPEC_DEPRECATED_DDK         // Use native __int64 math
__drv_preferredFunction("compiler support for 64 bit", "Obsolete")
__inline
ULONG
NTAPI_INLINE
RtlEnlargedUnsignedDivide (
    __in ULARGE_INTEGER Dividend,
    __in ULONG Divisor,
    __out_opt PULONG Remainder
    )
{
    ULONG Quotient;

    Quotient = (ULONG)(Dividend.QuadPart / Divisor);
    if (ARGUMENT_PRESENT(Remainder)) {
        *Remainder = (ULONG)(Dividend.QuadPart % Divisor);
    }

    return Quotient;
}

//
// Large integer negation - -(64-bits)
//

DECLSPEC_DEPRECATED_DDK         // Use native __int64 math
__drv_preferredFunction("compiler support for 64 bit", "Obsolete")
__inline
LARGE_INTEGER
NTAPI_INLINE
RtlLargeIntegerNegate (
    __in LARGE_INTEGER Subtrahend
    )
{
    LARGE_INTEGER Difference;

    Difference.QuadPart = -Subtrahend.QuadPart;
    return Difference;
}

//
// Large integer subtract - 64-bits - 64-bits -> 64-bits.
//

DECLSPEC_DEPRECATED_DDK         // Use native __int64 math
__drv_preferredFunction("compiler support for 64 bit", "Obsolete")
__inline
LARGE_INTEGER
NTAPI_INLINE
RtlLargeIntegerSubtract (
    __in LARGE_INTEGER Minuend,
    __in LARGE_INTEGER Subtrahend
    )
{
    LARGE_INTEGER Difference;

    Difference.QuadPart = Minuend.QuadPart - Subtrahend.QuadPart;
    return Difference;
}

//
// Extended large integer magic divide - 64-bits / 32-bits -> 64-bits
//

#if defined(_AMD64_)

DECLSPEC_DEPRECATED_DDK         // Use native __int64 math
__drv_preferredFunction("compiler support for 64 bit", "Obsolete")
__inline
LARGE_INTEGER
NTAPI_INLINE
RtlExtendedMagicDivide (
    __in LARGE_INTEGER Dividend,
    __in LARGE_INTEGER MagicDivisor,
    __in CCHAR ShiftCount
    )

{

    LARGE_INTEGER Quotient;

    if (Dividend.QuadPart >= 0) {
        Quotient.QuadPart = UnsignedMultiplyHigh(Dividend.QuadPart,
                                                 (ULONG64)MagicDivisor.QuadPart);

    } else {
        Quotient.QuadPart = UnsignedMultiplyHigh(-Dividend.QuadPart,
                                                 (ULONG64)MagicDivisor.QuadPart);
    }

    Quotient.QuadPart = (ULONG64)Quotient.QuadPart >> ShiftCount;
    if (Dividend.QuadPart < 0) {
        Quotient.QuadPart = - Quotient.QuadPart;
    }

    return Quotient;
}

#endif // defined(_AMD64_)

#if defined(_X86_) || defined(_IA64_)

#if (NTDDI_VERSION >= NTDDI_WIN2K)
DECLSPEC_DEPRECATED_DDK         // Use native __int64 math
__drv_preferredFunction("compiler support for 64 bit", "Obsolete")
NTSYSAPI
LARGE_INTEGER
NTAPI
RtlExtendedMagicDivide (
    __in LARGE_INTEGER Dividend,
    __in LARGE_INTEGER MagicDivisor,
    __in CCHAR ShiftCount
    );
#endif

#endif // defined(_X86_) || defined(_IA64_)


#if defined(_AMD64_) || defined(_IA64_)


//
// Large Integer divide - 64-bits / 32-bits -> 64-bits
//

DECLSPEC_DEPRECATED_DDK         // Use native __int64 math
__drv_preferredFunction("compiler support for 64 bit", "Obsolete")
__inline
LARGE_INTEGER
NTAPI_INLINE
RtlExtendedLargeIntegerDivide (
    __in LARGE_INTEGER Dividend,
    __in ULONG Divisor,
    __out_opt PULONG Remainder
    )
{
    LARGE_INTEGER Quotient;

    Quotient.QuadPart = (ULONG64)Dividend.QuadPart / Divisor;
    if (ARGUMENT_PRESENT(Remainder)) {
        *Remainder = (ULONG)(Dividend.QuadPart % Divisor);
    }

    return Quotient;
}

//
// Extended integer multiply - 32-bits * 64-bits -> 64-bits
//

DECLSPEC_DEPRECATED_DDK         // Use native __int64 math
__drv_preferredFunction("compiler support for 64 bit", "Obsolete")
__inline
LARGE_INTEGER
NTAPI_INLINE
RtlExtendedIntegerMultiply (
    __in LARGE_INTEGER Multiplicand,
    __in LONG Multiplier
    )
{
    LARGE_INTEGER Product;

    Product.QuadPart = Multiplicand.QuadPart * Multiplier;
    return Product;
}


#else


//
// Large Integer divide - 64-bits / 32-bits -> 64-bits
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)
DECLSPEC_DEPRECATED_DDK         // Use native __int64 math
__drv_preferredFunction("compiler support for 64 bit", "Obsolete")
NTSYSAPI
LARGE_INTEGER
NTAPI
RtlExtendedLargeIntegerDivide (
    __in LARGE_INTEGER Dividend,
    __in ULONG Divisor,
    __out_opt PULONG Remainder
    );
#endif

//
// Extended integer multiply - 32-bits * 64-bits -> 64-bits
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)
DECLSPEC_DEPRECATED_DDK         // Use native __int64 math
__drv_preferredFunction("compiler support for 64 bit", "Obsolete")
NTSYSAPI
LARGE_INTEGER
NTAPI
RtlExtendedIntegerMultiply (
    __in LARGE_INTEGER Multiplicand,
    __in LONG Multiplier
    );
#endif


#endif // defined(_AMD64_) || defined(_IA64_)


//
// Large integer and - 64-bite & 64-bits -> 64-bits.
//

#if PRAGMA_DEPRECATED_DDK
#pragma deprecated(RtlLargeIntegerAnd)      // Use native __int64 math
#endif
#define RtlLargeIntegerAnd(Result, Source, Mask) \
    Result.QuadPart = Source.QuadPart & Mask.QuadPart

//
// Convert signed integer to large integer.
//

DECLSPEC_DEPRECATED_DDK_WINXP         // Use native __int64 math
__inline
LARGE_INTEGER
NTAPI_INLINE
RtlConvertLongToLargeInteger (
    __in LONG SignedInteger
    )
{
    LARGE_INTEGER Result;

    Result.QuadPart = SignedInteger;
    return Result;
}

//
// Convert unsigned integer to large integer.
//

DECLSPEC_DEPRECATED_DDK_WINXP         // Use native __int64 math
__inline
LARGE_INTEGER
NTAPI_INLINE
RtlConvertUlongToLargeInteger (
    __in ULONG UnsignedInteger
    )
{
    LARGE_INTEGER Result;

    Result.QuadPart = UnsignedInteger;
    return Result;
}

//
// Large integer shift routines.
//

DECLSPEC_DEPRECATED_DDK_WINXP         // Use native __int64 math
__drv_preferredFunction("compiler support for 64 bit", "Obsolete")
__inline
LARGE_INTEGER
NTAPI_INLINE
RtlLargeIntegerShiftLeft (
    __in LARGE_INTEGER LargeInteger,
    __in CCHAR ShiftCount
    )
{
    LARGE_INTEGER Result;

    Result.QuadPart = LargeInteger.QuadPart << ShiftCount;
    return Result;
}

DECLSPEC_DEPRECATED_DDK_WINXP         // Use native __int64 math
__drv_preferredFunction("compiler support for 64 bit", "Obsolete")
__inline
LARGE_INTEGER
NTAPI_INLINE
RtlLargeIntegerShiftRight (
    __in LARGE_INTEGER LargeInteger,
    __in CCHAR ShiftCount
    )
{
    LARGE_INTEGER Result;

    Result.QuadPart = (ULONG64)LargeInteger.QuadPart >> ShiftCount;
    return Result;
}

DECLSPEC_DEPRECATED_DDK_WINXP         // Use native __int64 math
__drv_preferredFunction("compiler support for 64 bit", "Obsolete")
__inline
LARGE_INTEGER
NTAPI_INLINE
RtlLargeIntegerArithmeticShift (
    __in LARGE_INTEGER LargeInteger,
    __in CCHAR ShiftCount
    )
{
    LARGE_INTEGER Result;

    Result.QuadPart = LargeInteger.QuadPart >> ShiftCount;
    return Result;
}


//
// Large integer comparison routines.
//

#if PRAGMA_DEPRECATED_DDK
#pragma deprecated(RtlLargeIntegerGreaterThan)      // Use native __int64 math
#pragma deprecated(RtlLargeIntegerGreaterThanOrEqualTo)      // Use native __int64 math
#pragma deprecated(RtlLargeIntegerEqualTo)      // Use native __int64 math
#pragma deprecated(RtlLargeIntegerNotEqualTo)      // Use native __int64 math
#pragma deprecated(RtlLargeIntegerLessThan)      // Use native __int64 math
#pragma deprecated(RtlLargeIntegerLessThanOrEqualTo)      // Use native __int64 math
#pragma deprecated(RtlLargeIntegerGreaterThanZero)      // Use native __int64 math
#pragma deprecated(RtlLargeIntegerGreaterOrEqualToZero)      // Use native __int64 math
#pragma deprecated(RtlLargeIntegerEqualToZero)      // Use native __int64 math
#pragma deprecated(RtlLargeIntegerNotEqualToZero)      // Use native __int64 math
#pragma deprecated(RtlLargeIntegerLessThanZero)      // Use native __int64 math
#pragma deprecated(RtlLargeIntegerLessOrEqualToZero)      // Use native __int64 math
#endif

#define RtlLargeIntegerGreaterThan(X,Y) (                              \
    (((X).HighPart == (Y).HighPart) && ((X).LowPart > (Y).LowPart)) || \
    ((X).HighPart > (Y).HighPart)                                      \
)

#define RtlLargeIntegerGreaterThanOrEqualTo(X,Y) (                      \
    (((X).HighPart == (Y).HighPart) && ((X).LowPart >= (Y).LowPart)) || \
    ((X).HighPart > (Y).HighPart)                                       \
)

#define RtlLargeIntegerEqualTo(X,Y) (                              \
    !(((X).LowPart ^ (Y).LowPart) | ((X).HighPart ^ (Y).HighPart)) \
)

#define RtlLargeIntegerNotEqualTo(X,Y) (                          \
    (((X).LowPart ^ (Y).LowPart) | ((X).HighPart ^ (Y).HighPart)) \
)

#define RtlLargeIntegerLessThan(X,Y) (                                 \
    (((X).HighPart == (Y).HighPart) && ((X).LowPart < (Y).LowPart)) || \
    ((X).HighPart < (Y).HighPart)                                      \
)

#define RtlLargeIntegerLessThanOrEqualTo(X,Y) (                         \
    (((X).HighPart == (Y).HighPart) && ((X).LowPart <= (Y).LowPart)) || \
    ((X).HighPart < (Y).HighPart)                                       \
)

#define RtlLargeIntegerGreaterThanZero(X) (       \
    (((X).HighPart == 0) && ((X).LowPart > 0)) || \
    ((X).HighPart > 0 )                           \
)

#define RtlLargeIntegerGreaterOrEqualToZero(X) ( \
    (X).HighPart >= 0                            \
)

#define RtlLargeIntegerEqualToZero(X) ( \
    !((X).LowPart | (X).HighPart)       \
)

#define RtlLargeIntegerNotEqualToZero(X) ( \
    ((X).LowPart | (X).HighPart)           \
)

#define RtlLargeIntegerLessThanZero(X) ( \
    ((X).HighPart < 0)                   \
)

#define RtlLargeIntegerLessOrEqualToZero(X) (           \
    ((X).HighPart < 0) || !((X).LowPart | (X).HighPart) \
)


#endif // !defined(MIDL_PASS)


//
//  Time conversion routines
//

typedef struct _TIME_FIELDS {
    CSHORT Year;        // range [1601...]
    CSHORT Month;       // range [1..12]
    CSHORT Day;         // range [1..31]
    CSHORT Hour;        // range [0..23]
    CSHORT Minute;      // range [0..59]
    CSHORT Second;      // range [0..59]
    CSHORT Milliseconds;// range [0..999]
    CSHORT Weekday;     // range [0..6] == [Sunday..Saturday]
} TIME_FIELDS;
typedef TIME_FIELDS *PTIME_FIELDS;


#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTSYSAPI
VOID
NTAPI
RtlTimeToTimeFields (
    __in PLARGE_INTEGER Time,
    __out PTIME_FIELDS TimeFields
    );
#endif

//
//  A time field record (Weekday ignored) -> 64 bit Time value
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__success(return != 0)
NTSYSAPI
BOOLEAN
NTAPI
RtlTimeFieldsToTime (
    __in PTIME_FIELDS TimeFields,
    __out PLARGE_INTEGER Time
    );
#endif

//
// The following macros store and retrieve USHORTS and ULONGS from potentially
// unaligned addresses, avoiding alignment faults.  they should probably be
// rewritten in assembler
//

#define SHORT_SIZE  (sizeof(USHORT))
#define SHORT_MASK  (SHORT_SIZE - 1)
#define LONG_SIZE       (sizeof(LONG))
#define LONGLONG_SIZE   (sizeof(LONGLONG))
#define LONG_MASK       (LONG_SIZE - 1)
#define LONGLONG_MASK   (LONGLONG_SIZE - 1)
#define LOWBYTE_MASK 0x00FF

#define FIRSTBYTE(VALUE)  ((VALUE) & LOWBYTE_MASK)
#define SECONDBYTE(VALUE) (((VALUE) >> 8) & LOWBYTE_MASK)
#define THIRDBYTE(VALUE)  (((VALUE) >> 16) & LOWBYTE_MASK)
#define FOURTHBYTE(VALUE) (((VALUE) >> 24) & LOWBYTE_MASK)

//
// if MIPS Big Endian, order of bytes is reversed.
//

#define SHORT_LEAST_SIGNIFICANT_BIT  0
#define SHORT_MOST_SIGNIFICANT_BIT   1

#define LONG_LEAST_SIGNIFICANT_BIT       0
#define LONG_3RD_MOST_SIGNIFICANT_BIT    1
#define LONG_2ND_MOST_SIGNIFICANT_BIT    2
#define LONG_MOST_SIGNIFICANT_BIT        3

//++
//
// VOID
// RtlStoreUshort (
//     PUSHORT ADDRESS
//     USHORT VALUE
//     )
//
// Routine Description:
//
// This macro stores a USHORT value in at a particular address, avoiding
// alignment faults.
//
// Arguments:
//
//     ADDRESS - where to store USHORT value
//     VALUE - USHORT to store
//
// Return Value:
//
//     none.
//
//--

#if defined(_AMD64_)

#define RtlStoreUshort(ADDRESS,VALUE)                           \
        *(USHORT UNALIGNED *)(ADDRESS) = (VALUE)

#else

#define RtlStoreUshort(ADDRESS,VALUE)                     \
         if ((ULONG_PTR)(ADDRESS) & SHORT_MASK) {         \
             ((PUCHAR) (ADDRESS))[SHORT_LEAST_SIGNIFICANT_BIT] = (UCHAR)(FIRSTBYTE(VALUE));    \
             ((PUCHAR) (ADDRESS))[SHORT_MOST_SIGNIFICANT_BIT ] = (UCHAR)(SECONDBYTE(VALUE));   \
         }                                                \
         else {                                           \
             *((PUSHORT) (ADDRESS)) = (USHORT) VALUE;     \
         }

#endif

//++
//
// VOID
// RtlStoreUlong (
//     PULONG ADDRESS
//     ULONG VALUE
//     )
//
// Routine Description:
//
// This macro stores a ULONG value in at a particular address, avoiding
// alignment faults.
//
// Arguments:
//
//     ADDRESS - where to store ULONG value
//     VALUE - ULONG to store
//
// Return Value:
//
//     none.
//
// Note:
//     Depending on the machine, we might want to call storeushort in the
//     unaligned case.
//
//--


#if defined(_AMD64_)

#define RtlStoreUlong(ADDRESS,VALUE)                        \
        *(ULONG UNALIGNED *)(ADDRESS) = (VALUE)

#else

#define RtlStoreUlong(ADDRESS,VALUE)                      \
         if ((ULONG_PTR)(ADDRESS) & LONG_MASK) {          \
             ((PUCHAR) (ADDRESS))[LONG_LEAST_SIGNIFICANT_BIT      ] = (UCHAR)(FIRSTBYTE(VALUE));    \
             ((PUCHAR) (ADDRESS))[LONG_3RD_MOST_SIGNIFICANT_BIT   ] = (UCHAR)(SECONDBYTE(VALUE));   \
             ((PUCHAR) (ADDRESS))[LONG_2ND_MOST_SIGNIFICANT_BIT   ] = (UCHAR)(THIRDBYTE(VALUE));    \
             ((PUCHAR) (ADDRESS))[LONG_MOST_SIGNIFICANT_BIT       ] = (UCHAR)(FOURTHBYTE(VALUE));   \
         }                                                \
         else {                                           \
             *((PULONG) (ADDRESS)) = (ULONG) (VALUE);     \
         }

#endif

//++
//
// VOID
// RtlStoreUlonglong (
//     PULONGLONG ADDRESS
//     ULONG VALUE
//     )
//
// Routine Description:
//
// This macro stores a ULONGLONG value in at a particular address, avoiding
// alignment faults.
//
// Arguments:
//
//     ADDRESS - where to store ULONGLONG value
//     VALUE - ULONGLONG to store
//
// Return Value:
//
//     none.
//
//--

#if defined(_AMD64_)

#define RtlStoreUlonglong(ADDRESS,VALUE)                        \
        *(ULONGLONG UNALIGNED *)(ADDRESS) = (VALUE)

#else

#define RtlStoreUlonglong(ADDRESS,VALUE)                        \
         if ((ULONG_PTR)(ADDRESS) & LONGLONG_MASK) {            \
             RtlStoreUlong((ULONG_PTR)(ADDRESS),                \
                           (ULONGLONG)(VALUE) & 0xFFFFFFFF);    \
             RtlStoreUlong((ULONG_PTR)(ADDRESS)+sizeof(ULONG),  \
                           (ULONGLONG)(VALUE) >> 32);           \
         } else {                                               \
             *((PULONGLONG)(ADDRESS)) = (ULONGLONG)(VALUE);     \
         }

#endif

//++
//
// VOID
// RtlStoreUlongPtr (
//     PULONG_PTR ADDRESS
//     ULONG_PTR VALUE
//     )
//
// Routine Description:
//
// This macro stores a ULONG_PTR value in at a particular address, avoiding
// alignment faults.
//
// Arguments:
//
//     ADDRESS - where to store ULONG_PTR value
//     VALUE - ULONG_PTR to store
//
// Return Value:
//
//     none.
//
//--

#ifdef _WIN64

#define RtlStoreUlongPtr(ADDRESS,VALUE)                         \
         RtlStoreUlonglong(ADDRESS,VALUE)

#else

#define RtlStoreUlongPtr(ADDRESS,VALUE)                         \
         RtlStoreUlong(ADDRESS,VALUE)

#endif

//++
//
// VOID
// RtlRetrieveUshort (
//     PUSHORT DESTINATION_ADDRESS
//     PUSHORT SOURCE_ADDRESS
//     )
//
// Routine Description:
//
// This macro retrieves a USHORT value from the SOURCE address, avoiding
// alignment faults.  The DESTINATION address is assumed to be aligned.
//
// Arguments:
//
//     DESTINATION_ADDRESS - where to store USHORT value
//     SOURCE_ADDRESS - where to retrieve USHORT value from
//
// Return Value:
//
//     none.
//
//--

#if defined(_AMD64_)

#define RtlRetrieveUshort(DEST_ADDRESS,SRC_ADDRESS)                     \
         *(USHORT UNALIGNED *)(DEST_ADDRESS) = *(PUSHORT)(SRC_ADDRESS)

#else

#define RtlRetrieveUshort(DEST_ADDRESS,SRC_ADDRESS)                   \
         if ((ULONG_PTR)SRC_ADDRESS & SHORT_MASK) {                       \
             ((PUCHAR) (DEST_ADDRESS))[0] = ((PUCHAR) (SRC_ADDRESS))[0];  \
             ((PUCHAR) (DEST_ADDRESS))[1] = ((PUCHAR) (SRC_ADDRESS))[1];  \
         }                                                            \
         else {                                                       \
             *((PUSHORT) DEST_ADDRESS) = *((PUSHORT) SRC_ADDRESS);    \
         }                                                            \

#endif

//++
//
// VOID
// RtlRetrieveUlong (
//     PULONG DESTINATION_ADDRESS
//     PULONG SOURCE_ADDRESS
//     )
//
// Routine Description:
//
// This macro retrieves a ULONG value from the SOURCE address, avoiding
// alignment faults.  The DESTINATION address is assumed to be aligned.
//
// Arguments:
//
//     DESTINATION_ADDRESS - where to store ULONG value
//     SOURCE_ADDRESS - where to retrieve ULONG value from
//
// Return Value:
//
//     none.
//
// Note:
//     Depending on the machine, we might want to call retrieveushort in the
//     unaligned case.
//
//--

#if defined(_AMD64_)

#define RtlRetrieveUlong(DEST_ADDRESS,SRC_ADDRESS)                     \
         *(ULONG UNALIGNED *)(DEST_ADDRESS) = *(PULONG)(SRC_ADDRESS)

#else

#define RtlRetrieveUlong(DEST_ADDRESS,SRC_ADDRESS)                    \
         if ((ULONG_PTR)SRC_ADDRESS & LONG_MASK) {                        \
             ((PUCHAR) (DEST_ADDRESS))[0] = ((PUCHAR) (SRC_ADDRESS))[0];  \
             ((PUCHAR) (DEST_ADDRESS))[1] = ((PUCHAR) (SRC_ADDRESS))[1];  \
             ((PUCHAR) (DEST_ADDRESS))[2] = ((PUCHAR) (SRC_ADDRESS))[2];  \
             ((PUCHAR) (DEST_ADDRESS))[3] = ((PUCHAR) (SRC_ADDRESS))[3];  \
         }                                                            \
         else {                                                       \
             *((PULONG) DEST_ADDRESS) = *((PULONG) SRC_ADDRESS);      \
         }

#endif

//
//  BitMap routines.  The following structure, routines, and macros are
//  for manipulating bitmaps.  The user is responsible for allocating a bitmap
//  structure (which is really a header) and a buffer (which must be longword
//  aligned and multiple longwords in size).
//

typedef struct _RTL_BITMAP {
    ULONG SizeOfBitMap;                     // Number of bits in bit map
    PULONG Buffer;                          // Pointer to the bit map itself
} RTL_BITMAP;
typedef RTL_BITMAP *PRTL_BITMAP;

//
//  The following routine initializes a new bitmap.  It does not alter the
//  data currently in the bitmap.  This routine must be called before
//  any other bitmap routine/macro.
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTSYSAPI
VOID
NTAPI
RtlInitializeBitMap (
    __out PRTL_BITMAP BitMapHeader,
    __in __drv_aliasesMem PULONG BitMapBuffer,
    __in ULONG SizeOfBitMap
    );
#endif

//
//  The following three routines clear, set, and test the state of a
//  single bit in a bitmap.
//

#if (NTDDI_VERSION >= NTDDI_WINXP)
NTSYSAPI
VOID
NTAPI
RtlClearBit (
    __in PRTL_BITMAP BitMapHeader,
    __in_range(<, BitMapHeader->SizeOfBitMap) ULONG BitNumber
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
NTSYSAPI
VOID
NTAPI
RtlSetBit (
    __in PRTL_BITMAP BitMapHeader,
    __in_range(<, BitMapHeader->SizeOfBitMap) ULONG BitNumber
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
__checkReturn
NTSYSAPI
BOOLEAN
NTAPI
RtlTestBit (
    __in PRTL_BITMAP BitMapHeader,
    __in_range(<, BitMapHeader->SizeOfBitMap) ULONG BitNumber
    );
#endif

//
//  The following two routines either clear or set all of the bits
//  in a bitmap.
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTSYSAPI
VOID
NTAPI
RtlClearAllBits (
    __in PRTL_BITMAP BitMapHeader
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTSYSAPI
VOID
NTAPI
RtlSetAllBits (
    __in PRTL_BITMAP BitMapHeader
    );
#endif

//
//  The following two routines locate a contiguous region of either
//  clear or set bits within the bitmap.  The region will be at least
//  as large as the number specified, and the search of the bitmap will
//  begin at the specified hint index (which is a bit index within the
//  bitmap, zero based).  The return value is the bit index of the located
//  region (zero based) or -1 (i.e., 0xffffffff) if such a region cannot
//  be located
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__success(return != -1)
__checkReturn
NTSYSAPI
ULONG
NTAPI
RtlFindClearBits (
    __in PRTL_BITMAP BitMapHeader,
    __in ULONG NumberToFind,
    __in ULONG HintIndex
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__success(return != -1)
__checkReturn
NTSYSAPI
ULONG
NTAPI
RtlFindSetBits (
    __in PRTL_BITMAP BitMapHeader,
    __in ULONG NumberToFind,
    __in ULONG HintIndex
    );
#endif

//
//  The following two routines locate a contiguous region of either
//  clear or set bits within the bitmap and either set or clear the bits
//  within the located region.  The region will be as large as the number
//  specified, and the search for the region will begin at the specified
//  hint index (which is a bit index within the bitmap, zero based).  The
//  return value is the bit index of the located region (zero based) or
//  -1 (i.e., 0xffffffff) if such a region cannot be located.  If a region
//  cannot be located then the setting/clearing of the bitmap is not performed.
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__success(return != -1)
NTSYSAPI
ULONG
NTAPI
RtlFindClearBitsAndSet (
    __in PRTL_BITMAP BitMapHeader,
    __in ULONG NumberToFind,
    __in ULONG HintIndex
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__success(return != -1)
NTSYSAPI
ULONG
NTAPI
RtlFindSetBitsAndClear (
    __in PRTL_BITMAP BitMapHeader,
    __in ULONG NumberToFind,
    __in ULONG HintIndex
    );
#endif

//
//  The following two routines clear or set bits within a specified region
//  of the bitmap.  The starting index is zero based.
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTSYSAPI
VOID
NTAPI
RtlClearBits (
    __in PRTL_BITMAP BitMapHeader,
    __in_range(0, BitMapHeader->SizeOfBitMap - NumberToClear) ULONG StartingIndex,
    __in_range(0, BitMapHeader->SizeOfBitMap - StartingIndex) ULONG NumberToClear
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTSYSAPI
VOID
NTAPI
RtlSetBits (
    __in PRTL_BITMAP BitMapHeader,
    __in_range(0, BitMapHeader->SizeOfBitMap - NumberToSet) ULONG StartingIndex,
    __in_range(0, BitMapHeader->SizeOfBitMap - StartingIndex) ULONG NumberToSet
    );
#endif

//
//  The following routine locates a set of contiguous regions of clear
//  bits within the bitmap.  The caller specifies whether to return the
//  longest runs or just the first found lcoated.  The following structure is
//  used to denote a contiguous run of bits.  The two routines return an array
//  of this structure, one for each run located.
//

typedef struct _RTL_BITMAP_RUN {

    ULONG StartingIndex;
    ULONG NumberOfBits;

} RTL_BITMAP_RUN;
typedef RTL_BITMAP_RUN *PRTL_BITMAP_RUN;

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTSYSAPI
ULONG
NTAPI
RtlFindClearRuns (
    __in PRTL_BITMAP BitMapHeader,
    __out_ecount_part(SizeOfRunArray, return) PRTL_BITMAP_RUN RunArray,
    __in_range(>, 0) ULONG SizeOfRunArray,
    __in BOOLEAN LocateLongestRuns
    );
#endif

//
//  The following routine locates the longest contiguous region of
//  clear bits within the bitmap.  The returned starting index value
//  denotes the first contiguous region located satisfying our requirements
//  The return value is the length (in bits) of the longest region found.
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTSYSAPI
ULONG
NTAPI
RtlFindLongestRunClear (
    __in PRTL_BITMAP BitMapHeader,
    __out PULONG StartingIndex
    );
#endif

//
//  The following routine locates the first contiguous region of
//  clear bits within the bitmap.  The returned starting index value
//  denotes the first contiguous region located satisfying our requirements
//  The return value is the length (in bits) of the region found.
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTSYSAPI
ULONG
NTAPI
RtlFindFirstRunClear (
    __in PRTL_BITMAP BitMapHeader,
    __out PULONG StartingIndex
    );
#endif

//
//  The following macro returns the value of the bit stored within the
//  bitmap at the specified location.  If the bit is set a value of 1 is
//  returned otherwise a value of 0 is returned.
//
//      ULONG
//      RtlCheckBit (
//          PRTL_BITMAP BitMapHeader,
//          ULONG BitPosition
//          );
//
//
//  To implement CheckBit the macro retrieves the longword containing the
//  bit in question, shifts the longword to get the bit in question into the
//  low order bit position and masks out all other bits.
//

#if defined(_M_AMD64) && !defined(MIDL_PASS)

__checkReturn
FORCEINLINE
BOOLEAN
RtlCheckBit (
    __in PRTL_BITMAP BitMapHeader,
    __in_range(<, BitMapHeader->SizeOfBitMap) ULONG BitPosition
    )

{
    return BitTest64((LONG64 const *)BitMapHeader->Buffer, (LONG64)BitPosition);
}

#else

#define RtlCheckBit(BMH,BP) (((((PLONG)(BMH)->Buffer)[(BP) / 32]) >> ((BP) % 32)) & 0x1)

#endif

//
//  The following two procedures return to the caller the total number of
//  clear or set bits within the specified bitmap.
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTSYSAPI
ULONG
NTAPI
RtlNumberOfClearBits (
    __in PRTL_BITMAP BitMapHeader
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTSYSAPI
ULONG
NTAPI
RtlNumberOfSetBits (
    __in PRTL_BITMAP BitMapHeader
    );
#endif

//
//  The following two procedures return to the caller a boolean value
//  indicating if the specified range of bits are all clear or set.
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn
NTSYSAPI
BOOLEAN
NTAPI
RtlAreBitsClear (
    __in PRTL_BITMAP BitMapHeader,
    __in ULONG StartingIndex,
    __in ULONG Length
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn
NTSYSAPI
BOOLEAN
NTAPI
RtlAreBitsSet (
    __in PRTL_BITMAP BitMapHeader,
    __in ULONG StartingIndex,
    __in ULONG Length
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTSYSAPI
ULONG
NTAPI
RtlFindNextForwardRunClear (
    __in PRTL_BITMAP BitMapHeader,
    __in ULONG FromIndex,
    __out PULONG StartingRunIndex
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTSYSAPI
ULONG
NTAPI
RtlFindLastBackwardRunClear (
    __in PRTL_BITMAP BitMapHeader,
    __in ULONG FromIndex,
    __out PULONG StartingRunIndex
    );
#endif

//
//  The following two procedures return to the caller a value indicating
//  the position within a ULONGLONG of the most or least significant non-zero
//  bit.  A value of zero results in a return value of -1.
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__success(return != -1)
__checkReturn
NTSYSAPI
CCHAR
NTAPI
RtlFindLeastSignificantBit (
    __in ULONGLONG Set
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__success(return != -1)
__checkReturn
NTSYSAPI
CCHAR
NTAPI
RtlFindMostSignificantBit (
    __in ULONGLONG Set
    );
#endif

//
// The following procedure finds the number of set bits within a ULONG_PTR
// value.
//

#if (NTDDI_VERSION >= NTDDI_VISTA)
NTSYSAPI
ULONG
NTAPI
RtlNumberOfSetBitsUlongPtr (
    __in ULONG_PTR Target
    );
#endif


//
// BOOLEAN
// RtlEqualLuid(
//      PLUID L1,
//      PLUID L2
//      );

#define RtlEqualLuid(L1, L2) (((L1)->LowPart == (L2)->LowPart) && \
                              ((L1)->HighPart  == (L2)->HighPart))

//
// BOOLEAN
// RtlIsZeroLuid(
//      PLUID L1
//      );
//
#define RtlIsZeroLuid(L1) ((BOOLEAN) (((L1)->LowPart | (L1)->HighPart) == 0))

//
//  SecurityDescriptor RTL routine definitions
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
RtlCreateSecurityDescriptor (
    __out PSECURITY_DESCRIPTOR SecurityDescriptor,
    __in ULONG Revision
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
__checkReturn
NTSYSAPI
BOOLEAN
NTAPI
RtlValidSecurityDescriptor (
    __in PSECURITY_DESCRIPTOR SecurityDescriptor
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTSYSAPI
ULONG
NTAPI
RtlLengthSecurityDescriptor (
    __in PSECURITY_DESCRIPTOR SecurityDescriptor
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
__checkReturn
NTSYSAPI
BOOLEAN
NTAPI
RtlValidRelativeSecurityDescriptor (
    __in_bcount(SecurityDescriptorLength) PSECURITY_DESCRIPTOR SecurityDescriptorInput,
    __in ULONG SecurityDescriptorLength,
    __in SECURITY_INFORMATION RequiredInformation
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
RtlSetDaclSecurityDescriptor (
    __inout PSECURITY_DESCRIPTOR SecurityDescriptor,
    __in BOOLEAN DaclPresent,
    __in_opt PACL Dacl,
    __in_opt BOOLEAN DaclDefaulted
    );
#endif


//
// Byte swap routines.  These are used to convert from little-endian to
// big-endian and vice-versa.
//

#if (defined(_M_IX86) && (_MSC_FULL_VER > 13009037)) || ((defined(_M_AMD64) || defined(_M_IA64)) && (_MSC_FULL_VER > 13009175))
#ifdef __cplusplus
extern "C" {
#endif
unsigned short __cdecl _byteswap_ushort(unsigned short);
unsigned long  __cdecl _byteswap_ulong (unsigned long);
unsigned __int64 __cdecl _byteswap_uint64(unsigned __int64);
#ifdef __cplusplus
}
#endif
#pragma intrinsic(_byteswap_ushort)
#pragma intrinsic(_byteswap_ulong)
#pragma intrinsic(_byteswap_uint64)

#define RtlUshortByteSwap(_x)    _byteswap_ushort((USHORT)(_x))
#define RtlUlongByteSwap(_x)     _byteswap_ulong((_x))
#define RtlUlonglongByteSwap(_x) _byteswap_uint64((_x))
#else

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTSYSAPI
USHORT
FASTCALL
RtlUshortByteSwap(
    __in USHORT Source
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTSYSAPI
ULONG
FASTCALL
RtlUlongByteSwap(
    __in ULONG Source
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTSYSAPI
ULONGLONG
FASTCALL
RtlUlonglongByteSwap(
    __in ULONGLONG Source
    );
#endif

#endif


#define RTLVERLIB_DDI(x) Wdmlib##x

typedef BOOLEAN (*PFN_RTL_IS_NTDDI_VERSION_AVAILABLE)(
    __in ULONG Version
    );

typedef BOOLEAN (*PFN_RTL_IS_SERVICE_PACK_VERSION_INSTALLED)(
    __in ULONG Version
    );

BOOLEAN
RTLVERLIB_DDI(RtlIsNtDdiVersionAvailable)(
    __in ULONG Version
    );

BOOLEAN
RTLVERLIB_DDI(RtlIsServicePackVersionInstalled)(
    __in ULONG Version
    );

#ifndef RtlIsNtDdiVersionAvailable
#define RtlIsNtDdiVersionAvailable WdmlibRtlIsNtDdiVersionAvailable
#endif

#ifndef RtlIsServicePackVersionInstalled
#define RtlIsServicePackVersionInstalled WdmlibRtlIsServicePackVersionInstalled
#endif

//
// Interlocked bit manipulation interfaces
//

#define RtlInterlockedSetBits(Flags, Flag) \
    InterlockedOr((PLONG)(Flags), Flag)

#define RtlInterlockedAndBits(Flags, Flag) \
    InterlockedAnd((PLONG)(Flags), Flag)

#define RtlInterlockedClearBits(Flags, Flag) \
    RtlInterlockedAndBits(Flags, ~(Flag))

#define RtlInterlockedXorBits(Flags, Flag) \
    InterlockedXor(Flags, Flag)

#define RtlInterlockedSetBitsDiscardReturn(Flags, Flag) \
    (VOID) RtlInterlockedSetBits(Flags, Flag)

#define RtlInterlockedAndBitsDiscardReturn(Flags, Flag) \
    (VOID) RtlInterlockedAndBits(Flags, Flag)

#define RtlInterlockedClearBitsDiscardReturn(Flags, Flag) \
    RtlInterlockedAndBitsDiscardReturn(Flags, ~(Flag))

#if (NTDDI_VERSION >= NTDDI_WINXP)
#include <dpfilter.h>
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
NTSYSAPI
NTSTATUS
NTAPI
RtlIoEncodeMemIoResource (
    __in PIO_RESOURCE_DESCRIPTOR Descriptor,
    __in UCHAR Type,
    __in ULONGLONG Length,
    __in ULONGLONG Alignment,
    __in ULONGLONG MinimumAddress,
    __in ULONGLONG MaximumAddress
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
NTSYSAPI
NTSTATUS
NTAPI
RtlCmEncodeMemIoResource (
    __in PCM_PARTIAL_RESOURCE_DESCRIPTOR Descriptor,
    __in UCHAR Type,
    __in ULONGLONG Length,
    __in ULONGLONG Start
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
NTSYSAPI
ULONGLONG
NTAPI
RtlIoDecodeMemIoResource (
    __in PIO_RESOURCE_DESCRIPTOR Descriptor,
    __out_opt PULONGLONG Alignment,
    __out_opt PULONGLONG MinimumAddress,
    __out_opt PULONGLONG MaximumAddress
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
NTSYSAPI
ULONGLONG
NTAPI
RtlCmDecodeMemIoResource (
    __in PCM_PARTIAL_RESOURCE_DESCRIPTOR Descriptor,
    __out_opt PULONGLONG Start
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
NTSYSAPI
NTSTATUS
NTAPI
RtlFindClosestEncodableLength (
    __in ULONGLONG SourceLength,
    __out PULONGLONG TargetLength
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN7)

NTSYSAPI
ULONG64
NTAPI
RtlGetEnabledExtendedFeatures (
    __in ULONG64 FeatureMask
    );

#endif

#ifndef _NTTMAPI_
#define _NTTMAPI_


#ifdef __cplusplus
extern "C" {
#endif


#include <ktmtypes.h>

//
// Types for Nt level TM calls
//

//
// KTM Tm object rights
//
#define TRANSACTIONMANAGER_QUERY_INFORMATION     ( 0x0001 )
#define TRANSACTIONMANAGER_SET_INFORMATION       ( 0x0002 )
#define TRANSACTIONMANAGER_RECOVER               ( 0x0004 )
#define TRANSACTIONMANAGER_RENAME                ( 0x0008 )
#define TRANSACTIONMANAGER_CREATE_RM             ( 0x0010 )

// The following right is intended for DTC's use only; it will be
// deprecated, and no one else should take a dependency on it.
#define TRANSACTIONMANAGER_BIND_TRANSACTION      ( 0x0020 )

//
// Generic mappings for transaction manager rights.
//

#define TRANSACTIONMANAGER_GENERIC_READ            (STANDARD_RIGHTS_READ            |\
                                                    TRANSACTIONMANAGER_QUERY_INFORMATION)

#define TRANSACTIONMANAGER_GENERIC_WRITE           (STANDARD_RIGHTS_WRITE           |\
                                                    TRANSACTIONMANAGER_SET_INFORMATION     |\
                                                    TRANSACTIONMANAGER_RECOVER             |\
                                                    TRANSACTIONMANAGER_RENAME              |\
                                                    TRANSACTIONMANAGER_CREATE_RM)

#define TRANSACTIONMANAGER_GENERIC_EXECUTE         (STANDARD_RIGHTS_EXECUTE)

#define TRANSACTIONMANAGER_ALL_ACCESS              (STANDARD_RIGHTS_REQUIRED        |\
                                                    TRANSACTIONMANAGER_GENERIC_READ        |\
                                                    TRANSACTIONMANAGER_GENERIC_WRITE       |\
                                                    TRANSACTIONMANAGER_GENERIC_EXECUTE     |\
                                                    TRANSACTIONMANAGER_BIND_TRANSACTION)


//
// KTM transaction object rights.
//
#define TRANSACTION_QUERY_INFORMATION     ( 0x0001 )
#define TRANSACTION_SET_INFORMATION       ( 0x0002 )
#define TRANSACTION_ENLIST                ( 0x0004 )
#define TRANSACTION_COMMIT                ( 0x0008 )
#define TRANSACTION_ROLLBACK              ( 0x0010 )
#define TRANSACTION_PROPAGATE             ( 0x0020 )
#define TRANSACTION_RIGHT_RESERVED1       ( 0x0040 )

//
// Generic mappings for transaction rights.
// Resource managers, when enlisting, should generally use the macro
// TRANSACTION_RESOURCE_MANAGER_RIGHTS when opening a transaction.
// It's the same as generic read and write except that it does not allow
// a commit decision to be made.
//

#define TRANSACTION_GENERIC_READ            (STANDARD_RIGHTS_READ            |\
                                             TRANSACTION_QUERY_INFORMATION   |\
                                             SYNCHRONIZE)

#define TRANSACTION_GENERIC_WRITE           (STANDARD_RIGHTS_WRITE           |\
                                             TRANSACTION_SET_INFORMATION     |\
                                             TRANSACTION_COMMIT              |\
                                             TRANSACTION_ENLIST              |\
                                             TRANSACTION_ROLLBACK            |\
                                             TRANSACTION_PROPAGATE           |\
                                             SYNCHRONIZE)

#define TRANSACTION_GENERIC_EXECUTE         (STANDARD_RIGHTS_EXECUTE         |\
                                             TRANSACTION_COMMIT              |\
                                             TRANSACTION_ROLLBACK            |\
                                             SYNCHRONIZE)

#define TRANSACTION_ALL_ACCESS              (STANDARD_RIGHTS_REQUIRED        |\
                                             TRANSACTION_GENERIC_READ        |\
                                             TRANSACTION_GENERIC_WRITE       |\
                                             TRANSACTION_GENERIC_EXECUTE)

#define TRANSACTION_RESOURCE_MANAGER_RIGHTS (TRANSACTION_GENERIC_READ        |\
                                             STANDARD_RIGHTS_WRITE           |\
                                             TRANSACTION_SET_INFORMATION     |\
                                             TRANSACTION_ENLIST              |\
                                             TRANSACTION_ROLLBACK            |\
                                             TRANSACTION_PROPAGATE           |\
                                             SYNCHRONIZE)

//
// KTM resource manager object rights.
//
#define RESOURCEMANAGER_QUERY_INFORMATION     ( 0x0001 )
#define RESOURCEMANAGER_SET_INFORMATION       ( 0x0002 )
#define RESOURCEMANAGER_RECOVER               ( 0x0004 )
#define RESOURCEMANAGER_ENLIST                ( 0x0008 )
#define RESOURCEMANAGER_GET_NOTIFICATION      ( 0x0010 )
#define RESOURCEMANAGER_REGISTER_PROTOCOL     ( 0x0020 )
#define RESOURCEMANAGER_COMPLETE_PROPAGATION  ( 0x0040 )

//
// Generic mappings for resource manager rights.
//
#define RESOURCEMANAGER_GENERIC_READ        (STANDARD_RIGHTS_READ                 |\
                                             RESOURCEMANAGER_QUERY_INFORMATION    |\
                                             SYNCHRONIZE)

#define RESOURCEMANAGER_GENERIC_WRITE       (STANDARD_RIGHTS_WRITE                |\
                                             RESOURCEMANAGER_SET_INFORMATION      |\
                                             RESOURCEMANAGER_RECOVER              |\
                                             RESOURCEMANAGER_ENLIST               |\
                                             RESOURCEMANAGER_GET_NOTIFICATION     |\
                                             RESOURCEMANAGER_REGISTER_PROTOCOL    |\
                                             RESOURCEMANAGER_COMPLETE_PROPAGATION |\
                                             SYNCHRONIZE)

#define RESOURCEMANAGER_GENERIC_EXECUTE     (STANDARD_RIGHTS_EXECUTE              |\
                                             RESOURCEMANAGER_RECOVER              |\
                                             RESOURCEMANAGER_ENLIST               |\
                                             RESOURCEMANAGER_GET_NOTIFICATION     |\
                                             RESOURCEMANAGER_COMPLETE_PROPAGATION |\
                                             SYNCHRONIZE)

#define RESOURCEMANAGER_ALL_ACCESS          (STANDARD_RIGHTS_REQUIRED             |\
                                             RESOURCEMANAGER_GENERIC_READ         |\
                                             RESOURCEMANAGER_GENERIC_WRITE        |\
                                             RESOURCEMANAGER_GENERIC_EXECUTE)


//
// KTM enlistment object rights.
//
#define ENLISTMENT_QUERY_INFORMATION     ( 0x0001 )
#define ENLISTMENT_SET_INFORMATION       ( 0x0002 )
#define ENLISTMENT_RECOVER               ( 0x0004 )
#define ENLISTMENT_SUBORDINATE_RIGHTS    ( 0x0008 )
#define ENLISTMENT_SUPERIOR_RIGHTS       ( 0x0010 )

//
// Generic mappings for enlistment rights.
//
#define ENLISTMENT_GENERIC_READ        (STANDARD_RIGHTS_READ           |\
                                        ENLISTMENT_QUERY_INFORMATION)

#define ENLISTMENT_GENERIC_WRITE       (STANDARD_RIGHTS_WRITE          |\
                                        ENLISTMENT_SET_INFORMATION     |\
                                        ENLISTMENT_RECOVER             |\
                                        ENLISTMENT_SUBORDINATE_RIGHTS  |\
                                        ENLISTMENT_SUPERIOR_RIGHTS)

#define ENLISTMENT_GENERIC_EXECUTE     (STANDARD_RIGHTS_EXECUTE        |\
                                        ENLISTMENT_RECOVER             |\
                                        ENLISTMENT_SUBORDINATE_RIGHTS  |\
                                        ENLISTMENT_SUPERIOR_RIGHTS)

#define ENLISTMENT_ALL_ACCESS          (STANDARD_RIGHTS_REQUIRED       |\
                                        ENLISTMENT_GENERIC_READ        |\
                                        ENLISTMENT_GENERIC_WRITE       |\
                                        ENLISTMENT_GENERIC_EXECUTE)


//
// Transaction outcomes.
//
// TODO: warning, must match values in KTRANSACTION_OUTCOME duplicated def 
// in tm.h.
//

typedef enum _TRANSACTION_OUTCOME {
    TransactionOutcomeUndetermined = 1,
    TransactionOutcomeCommitted,
    TransactionOutcomeAborted,
} TRANSACTION_OUTCOME;


typedef enum _TRANSACTION_STATE {
    TransactionStateNormal = 1,
    TransactionStateIndoubt,
    TransactionStateCommittedNotify,
} TRANSACTION_STATE;


typedef struct _TRANSACTION_BASIC_INFORMATION {
    GUID    TransactionId;
    ULONG   State;
    ULONG   Outcome;
} TRANSACTION_BASIC_INFORMATION, *PTRANSACTION_BASIC_INFORMATION;

typedef struct _TRANSACTIONMANAGER_BASIC_INFORMATION {
    GUID    TmIdentity;
    LARGE_INTEGER VirtualClock;
} TRANSACTIONMANAGER_BASIC_INFORMATION, *PTRANSACTIONMANAGER_BASIC_INFORMATION;

typedef struct _TRANSACTIONMANAGER_LOG_INFORMATION {
    GUID  LogIdentity;
} TRANSACTIONMANAGER_LOG_INFORMATION, *PTRANSACTIONMANAGER_LOG_INFORMATION;

typedef struct _TRANSACTIONMANAGER_LOGPATH_INFORMATION {
    ULONG LogPathLength;
    __field_ecount(LogPathLength) WCHAR LogPath[1]; // Variable size
//  Data[1];                                        // Variable size data not declared
} TRANSACTIONMANAGER_LOGPATH_INFORMATION, *PTRANSACTIONMANAGER_LOGPATH_INFORMATION;

typedef struct _TRANSACTIONMANAGER_RECOVERY_INFORMATION {
    ULONGLONG  LastRecoveredLsn;
} TRANSACTIONMANAGER_RECOVERY_INFORMATION, *PTRANSACTIONMANAGER_RECOVERY_INFORMATION;




typedef struct _TRANSACTION_PROPERTIES_INFORMATION {
    ULONG              IsolationLevel;
    ULONG              IsolationFlags;
    LARGE_INTEGER      Timeout;
    ULONG              Outcome;
    ULONG              DescriptionLength;
    WCHAR              Description[1];            // Variable size
//          Data[1];            // Variable size data not declared
} TRANSACTION_PROPERTIES_INFORMATION, *PTRANSACTION_PROPERTIES_INFORMATION;

// The following info-class is intended for DTC's use only; it will be
// deprecated, and no one else should take a dependency on it.
typedef struct _TRANSACTION_BIND_INFORMATION {
    HANDLE TmHandle;
} TRANSACTION_BIND_INFORMATION, *PTRANSACTION_BIND_INFORMATION;

typedef struct _TRANSACTION_ENLISTMENT_PAIR {
    GUID   EnlistmentId;
    GUID   ResourceManagerId;
} TRANSACTION_ENLISTMENT_PAIR, *PTRANSACTION_ENLISTMENT_PAIR;

typedef struct _TRANSACTION_ENLISTMENTS_INFORMATION {
    ULONG                       NumberOfEnlistments;
    TRANSACTION_ENLISTMENT_PAIR EnlistmentPair[1]; // Variable size
} TRANSACTION_ENLISTMENTS_INFORMATION, *PTRANSACTION_ENLISTMENTS_INFORMATION;

typedef struct _TRANSACTION_SUPERIOR_ENLISTMENT_INFORMATION {
    TRANSACTION_ENLISTMENT_PAIR SuperiorEnlistmentPair;
} TRANSACTION_SUPERIOR_ENLISTMENT_INFORMATION, *PTRANSACTION_SUPERIOR_ENLISTMENT_INFORMATION;


typedef struct _RESOURCEMANAGER_BASIC_INFORMATION {
    GUID    ResourceManagerId;
    ULONG   DescriptionLength;
    WCHAR   Description[1];            // Variable size
} RESOURCEMANAGER_BASIC_INFORMATION, *PRESOURCEMANAGER_BASIC_INFORMATION;

typedef struct _RESOURCEMANAGER_COMPLETION_INFORMATION {
    HANDLE    IoCompletionPortHandle;
    ULONG_PTR CompletionKey;
} RESOURCEMANAGER_COMPLETION_INFORMATION, *PRESOURCEMANAGER_COMPLETION_INFORMATION;

typedef enum _TRANSACTION_INFORMATION_CLASS {
    TransactionBasicInformation,
    TransactionPropertiesInformation,
    TransactionEnlistmentInformation,
    TransactionSuperiorEnlistmentInformation
} TRANSACTION_INFORMATION_CLASS;


typedef enum _TRANSACTIONMANAGER_INFORMATION_CLASS {
    TransactionManagerBasicInformation,
    TransactionManagerLogInformation,
    TransactionManagerLogPathInformation,
    TransactionManagerRecoveryInformation = 4

} TRANSACTIONMANAGER_INFORMATION_CLASS;



typedef enum _RESOURCEMANAGER_INFORMATION_CLASS {
    ResourceManagerBasicInformation,
    ResourceManagerCompletionInformation,
} RESOURCEMANAGER_INFORMATION_CLASS;


typedef struct _ENLISTMENT_BASIC_INFORMATION {
    GUID    EnlistmentId;
    GUID    TransactionId;
    GUID    ResourceManagerId;
} ENLISTMENT_BASIC_INFORMATION, *PENLISTMENT_BASIC_INFORMATION;

typedef struct _ENLISTMENT_CRM_INFORMATION {
    GUID   CrmTransactionManagerId;
    GUID   CrmResourceManagerId;
    GUID   CrmEnlistmentId;
} ENLISTMENT_CRM_INFORMATION, *PENLISTMENT_CRM_INFORMATION;



typedef enum _ENLISTMENT_INFORMATION_CLASS {
    EnlistmentBasicInformation,
    EnlistmentRecoveryInformation,
    EnlistmentCrmInformation
} ENLISTMENT_INFORMATION_CLASS;

typedef struct _TRANSACTION_LIST_ENTRY {
    UOW    UOW;
} TRANSACTION_LIST_ENTRY, *PTRANSACTION_LIST_ENTRY;

typedef struct _TRANSACTION_LIST_INFORMATION {
    ULONG   NumberOfTransactions;
    TRANSACTION_LIST_ENTRY TransactionInformation[1]; // Var size
} TRANSACTION_LIST_INFORMATION, *PTRANSACTION_LIST_INFORMATION;


//
// Types of objects known to the kernel transaction manager.
//

typedef enum _KTMOBJECT_TYPE {

    KTMOBJECT_TRANSACTION,
    KTMOBJECT_TRANSACTION_MANAGER,
    KTMOBJECT_RESOURCE_MANAGER,
    KTMOBJECT_ENLISTMENT,
    KTMOBJECT_INVALID

} KTMOBJECT_TYPE, *PKTMOBJECT_TYPE;


//
// KTMOBJECT_CURSOR
//
// Used by NtEnumerateTransactionObject to enumerate a transaction
// object namespace (e.g. enlistments in a resource manager).
//

typedef struct _KTMOBJECT_CURSOR {

    //
    // The last GUID enumerated; zero if beginning enumeration.
    // 

    GUID    LastQuery;

    //
    // A count of GUIDs filled in by this last enumeration.
    // 

    ULONG   ObjectIdCount;

    //
    // ObjectIdCount GUIDs from the namespace specified.
    // 

    GUID    ObjectIds[1];

} KTMOBJECT_CURSOR, *PKTMOBJECT_CURSOR;



//
// Nt level transaction manager API calls
//

#if (NTDDI_VERSION >= NTDDI_VISTA)
__checkReturn 
__drv_maxIRQL (APC_LEVEL) 
NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreateTransactionManager (
    __out PHANDLE TmHandle,
    __in ACCESS_MASK DesiredAccess,
    __in_opt POBJECT_ATTRIBUTES ObjectAttributes,
    __in_opt PUNICODE_STRING LogFileName,
    __in_opt ULONG CreateOptions,
    __in_opt ULONG CommitStrength
    );
#endif // NTDDI_VERSION >= NTDDI_VISTA


#if (NTDDI_VERSION >= NTDDI_VISTA)
__checkReturn 
__drv_maxIRQL (APC_LEVEL) 
NTSYSCALLAPI
NTSTATUS
NTAPI
NtOpenTransactionManager (
    __out PHANDLE TmHandle,
    __in ACCESS_MASK DesiredAccess,
    __in_opt POBJECT_ATTRIBUTES ObjectAttributes,
    __in_opt PUNICODE_STRING LogFileName,
    __in_opt LPGUID TmIdentity,
    __in_opt ULONG OpenOptions
    );
#endif // NTDDI_VERSION >= NTDDI_VISTA


#if (NTDDI_VERSION >= NTDDI_VISTA)
__checkReturn 
__drv_maxIRQL (APC_LEVEL) 
NTSYSCALLAPI
NTSTATUS
NTAPI
NtRenameTransactionManager (
    __in PUNICODE_STRING LogFileName,
    __in LPGUID ExistingTransactionManagerGuid
    );
#endif // NTDDI_VERSION >= NTDDI_VISTA


#if (NTDDI_VERSION >= NTDDI_VISTA)
__checkReturn 
__drv_maxIRQL (APC_LEVEL) 
NTSYSCALLAPI
NTSTATUS
NTAPI
NtRollforwardTransactionManager (
    __in HANDLE TransactionManagerHandle,
    __in_opt PLARGE_INTEGER TmVirtualClock
    );
#endif // NTDDI_VERSION >= NTDDI_VISTA


#if (NTDDI_VERSION >= NTDDI_VISTA)
__checkReturn 
__drv_maxIRQL (APC_LEVEL) 
NTSYSCALLAPI
NTSTATUS
NTAPI
NtRecoverTransactionManager (
    __in HANDLE TransactionManagerHandle
    );
#endif // NTDDI_VERSION >= NTDDI_VISTA


#if (NTDDI_VERSION >= NTDDI_VISTA)
__checkReturn 
__drv_maxIRQL (APC_LEVEL) 
NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryInformationTransactionManager (
    __in HANDLE TransactionManagerHandle,
    __in TRANSACTIONMANAGER_INFORMATION_CLASS TransactionManagerInformationClass,
    __out_bcount(TransactionManagerInformationLength) PVOID TransactionManagerInformation,
    __in ULONG TransactionManagerInformationLength,
    __out PULONG ReturnLength
    );
#endif // NTDDI_VERSION >= NTDDI_VISTA


#if (NTDDI_VERSION >= NTDDI_VISTA)
__checkReturn 
__drv_maxIRQL (APC_LEVEL) 
NTSYSCALLAPI
NTSTATUS
NTAPI
NtSetInformationTransactionManager (
    __in_opt HANDLE TmHandle,
    __in TRANSACTIONMANAGER_INFORMATION_CLASS TransactionManagerInformationClass,
    __in_bcount(TransactionManagerInformationLength) PVOID TransactionManagerInformation,
    __in ULONG TransactionManagerInformationLength
    );
#endif // NTDDI_VERSION >= NTDDI_VISTA


#if (NTDDI_VERSION >= NTDDI_VISTA)
__checkReturn 
__drv_maxIRQL (APC_LEVEL) 
NTSYSCALLAPI
NTSTATUS 
NTAPI
NtEnumerateTransactionObject (
    __in_opt HANDLE RootObjectHandle,
    __in KTMOBJECT_TYPE QueryType,
    __inout_bcount(ObjectCursorLength) PKTMOBJECT_CURSOR ObjectCursor,
    __in ULONG ObjectCursorLength,
    __out PULONG ReturnLength
    );
#endif // NTDDI_VERSION >= NTDDI_VISTA


typedef NTSTATUS (NTAPI * PFN_NT_CREATE_TRANSACTION)(
    __out PHANDLE TransactionHandle,
    __in ACCESS_MASK DesiredAccess,
    __in_opt POBJECT_ATTRIBUTES ObjectAttributes,
    __in_opt LPGUID Uow,
    __in_opt HANDLE TmHandle,
    __in_opt ULONG CreateOptions,
    __in_opt ULONG IsolationLevel,
    __in_opt ULONG IsolationFlags,
    __in_opt PLARGE_INTEGER Timeout,
    __in_opt PUNICODE_STRING Description
    );    


#if (NTDDI_VERSION >= NTDDI_VISTA)
__checkReturn 
__drv_maxIRQL (APC_LEVEL) 
NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreateTransaction (
    __out PHANDLE TransactionHandle,
    __in ACCESS_MASK DesiredAccess,
    __in_opt POBJECT_ATTRIBUTES ObjectAttributes,
    __in_opt LPGUID Uow,
    __in_opt HANDLE TmHandle,
    __in_opt ULONG CreateOptions,
    __in_opt ULONG IsolationLevel,
    __in_opt ULONG IsolationFlags,
    __in_opt PLARGE_INTEGER Timeout,
    __in_opt PUNICODE_STRING Description
    );
#endif // NTDDI_VERSION >= NTDDI_VISTA


typedef NTSTATUS (NTAPI *PFN_NT_OPEN_TRANSACTION)(
    __out PHANDLE TransactionHandle,
    __in ACCESS_MASK DesiredAccess,
    __in POBJECT_ATTRIBUTES ObjectAttributes,
    __in_opt LPGUID Uow,
    __in_opt HANDLE TmHandle
    );


#if (NTDDI_VERSION >= NTDDI_VISTA)
__checkReturn 
__drv_maxIRQL (APC_LEVEL) 
NTSYSCALLAPI
NTSTATUS
NTAPI
NtOpenTransaction (
    __out PHANDLE TransactionHandle,
    __in ACCESS_MASK DesiredAccess,
    __in POBJECT_ATTRIBUTES ObjectAttributes,
    __in LPGUID Uow,
    __in_opt HANDLE TmHandle
    );
#endif // NTDDI_VERSION >= NTDDI_VISTA


typedef NTSTATUS (NTAPI * PFN_NT_QUERY_INFORMATION_TRANSACTION)(
    __in HANDLE TransactionHandle,
    __in TRANSACTION_INFORMATION_CLASS TransactionInformationClass,
    __out_bcount(TransactionInformationLength) PVOID TransactionInformation,
    __in ULONG TransactionInformationLength,
    __out_opt PULONG ReturnLength
    );


#if (NTDDI_VERSION >= NTDDI_VISTA)
__checkReturn 
__drv_maxIRQL (APC_LEVEL) 
NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryInformationTransaction (
    __in HANDLE TransactionHandle,
    __in TRANSACTION_INFORMATION_CLASS TransactionInformationClass,
    __out_bcount(TransactionInformationLength) PVOID TransactionInformation,
    __in ULONG TransactionInformationLength,
    __out_opt PULONG ReturnLength
    );
#endif // NTDDI_VERSION >= NTDDI_VISTA


typedef NTSTATUS (NTAPI * PFN_NT_SET_INFORMATION_TRANSACTION)(
    __in HANDLE TransactionHandle,
    __in TRANSACTION_INFORMATION_CLASS TransactionInformationClass,
    __in PVOID TransactionInformation,
    __in ULONG TransactionInformationLength
    );


#if (NTDDI_VERSION >= NTDDI_VISTA)
__checkReturn 
__drv_maxIRQL (APC_LEVEL) 
NTSYSCALLAPI
NTSTATUS
NTAPI
NtSetInformationTransaction (
    __in HANDLE TransactionHandle,
    __in TRANSACTION_INFORMATION_CLASS TransactionInformationClass,
    __in_bcount(TransactionInformationLength) PVOID TransactionInformation,
    __in ULONG TransactionInformationLength
    );
#endif // NTDDI_VERSION >= NTDDI_VISTA


typedef NTSTATUS (NTAPI * PFN_NT_COMMIT_TRANSACTION)(
    __in HANDLE  TransactionHandle,
    __in BOOLEAN Wait
    );


#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL (APC_LEVEL) 
NTSYSCALLAPI
NTSTATUS
NTAPI
NtCommitTransaction (
    __in HANDLE TransactionHandle,
    __in BOOLEAN Wait
    );
#endif // NTDDI_VERSION >= NTDDI_VISTA


typedef NTSTATUS (NTAPI * PFN_NT_ROLLBACK_TRANSACTION)(
    __in HANDLE TransactionHandle,
    __in BOOLEAN Wait
    );


#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL (APC_LEVEL) 
NTSYSCALLAPI
NTSTATUS
NTAPI
NtRollbackTransaction (
    __in HANDLE TransactionHandle,
    __in BOOLEAN Wait
    );
#endif // NTDDI_VERSION >= NTDDI_VISTA


#if (NTDDI_VERSION >= NTDDI_VISTA)
__checkReturn 
__drv_maxIRQL (APC_LEVEL) 
NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreateEnlistment (
    __out PHANDLE EnlistmentHandle,
    __in ACCESS_MASK DesiredAccess,
    __in HANDLE ResourceManagerHandle,
    __in HANDLE TransactionHandle,
    __in_opt POBJECT_ATTRIBUTES ObjectAttributes,
    __in_opt ULONG CreateOptions,
    __in NOTIFICATION_MASK NotificationMask,
    __in_opt PVOID EnlistmentKey
    );
#endif // NTDDI_VERSION >= NTDDI_VISTA


#if (NTDDI_VERSION >= NTDDI_VISTA)
__checkReturn 
__drv_maxIRQL (APC_LEVEL) 
NTSYSCALLAPI
NTSTATUS
NTAPI
NtOpenEnlistment (
    __out PHANDLE EnlistmentHandle,
    __in ACCESS_MASK DesiredAccess,
    __in HANDLE ResourceManagerHandle,
    __in LPGUID EnlistmentGuid,
    __in_opt POBJECT_ATTRIBUTES ObjectAttributes
    );
#endif // NTDDI_VERSION >= NTDDI_VISTA


#if (NTDDI_VERSION >= NTDDI_VISTA)
__checkReturn 
__drv_maxIRQL (APC_LEVEL) 
NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryInformationEnlistment (
    __in HANDLE EnlistmentHandle,
    __in ENLISTMENT_INFORMATION_CLASS EnlistmentInformationClass,
    __out_bcount(EnlistmentInformationLength) PVOID EnlistmentInformation,
    __in ULONG EnlistmentInformationLength,
    __out PULONG ReturnLength
    );
#endif // NTDDI_VERSION >= NTDDI_VISTA


#if (NTDDI_VERSION >= NTDDI_VISTA)
__checkReturn 
__drv_maxIRQL (APC_LEVEL) 
NTSYSCALLAPI
NTSTATUS
NTAPI
NtSetInformationEnlistment (
    __in_opt HANDLE EnlistmentHandle,
    __in ENLISTMENT_INFORMATION_CLASS EnlistmentInformationClass,
    __in_bcount(EnlistmentInformationLength) PVOID EnlistmentInformation,
    __in ULONG EnlistmentInformationLength
    );
#endif // NTDDI_VERSION >= NTDDI_VISTA


#if (NTDDI_VERSION >= NTDDI_VISTA)
__checkReturn 
__drv_maxIRQL (APC_LEVEL) 
NTSYSCALLAPI
NTSTATUS
NTAPI
NtRecoverEnlistment (
    __in HANDLE EnlistmentHandle,
    __in_opt PVOID EnlistmentKey
    );
#endif // NTDDI_VERSION >= NTDDI_VISTA


#if (NTDDI_VERSION >= NTDDI_VISTA)
__checkReturn 
__drv_maxIRQL (APC_LEVEL) 
NTSYSCALLAPI
NTSTATUS
NTAPI
NtPrePrepareEnlistment (
    __in HANDLE EnlistmentHandle,
    __in_opt PLARGE_INTEGER TmVirtualClock
    );
#endif // NTDDI_VERSION >= NTDDI_VISTA


#if (NTDDI_VERSION >= NTDDI_VISTA)
__checkReturn 
__drv_maxIRQL (APC_LEVEL) 
NTSYSCALLAPI
NTSTATUS
NTAPI
NtPrepareEnlistment (
    __in HANDLE EnlistmentHandle,
    __in_opt PLARGE_INTEGER TmVirtualClock
    );
#endif // NTDDI_VERSION >= NTDDI_VISTA


#if (NTDDI_VERSION >= NTDDI_VISTA)
__checkReturn 
__drv_maxIRQL (APC_LEVEL) 
NTSYSCALLAPI
NTSTATUS
NTAPI
NtCommitEnlistment (
    __in HANDLE EnlistmentHandle,
    __in_opt PLARGE_INTEGER TmVirtualClock
    );
#endif // NTDDI_VERSION >= NTDDI_VISTA


#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL (APC_LEVEL) 
NTSYSCALLAPI
NTSTATUS
NTAPI
NtRollbackEnlistment (
    __in HANDLE EnlistmentHandle,
    __in_opt PLARGE_INTEGER TmVirtualClock
    );
#endif // NTDDI_VERSION >= NTDDI_VISTA


#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL (APC_LEVEL) 
NTSYSCALLAPI
NTSTATUS
NTAPI 
NtPrePrepareComplete (
    __in HANDLE EnlistmentHandle,
    __in_opt PLARGE_INTEGER TmVirtualClock
    );
#endif // NTDDI_VERSION >= NTDDI_VISTA


#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL (APC_LEVEL) 
NTSYSCALLAPI
NTSTATUS
NTAPI 
NtPrepareComplete (
    __in HANDLE EnlistmentHandle,
    __in_opt PLARGE_INTEGER TmVirtualClock
    );
#endif // NTDDI_VERSION >= NTDDI_VISTA


#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL (APC_LEVEL) 
NTSYSCALLAPI
NTSTATUS
NTAPI 
NtCommitComplete (
    __in HANDLE EnlistmentHandle,
    __in_opt PLARGE_INTEGER TmVirtualClock
    );
#endif // NTDDI_VERSION >= NTDDI_VISTA


#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL (APC_LEVEL) 
NTSYSCALLAPI
NTSTATUS
NTAPI 
NtReadOnlyEnlistment (
    __in HANDLE EnlistmentHandle,
    __in_opt PLARGE_INTEGER TmVirtualClock
    );
#endif // NTDDI_VERSION >= NTDDI_VISTA


#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL (APC_LEVEL) 
NTSYSCALLAPI
NTSTATUS
NTAPI 
NtRollbackComplete (
    __in HANDLE EnlistmentHandle,
    __in_opt PLARGE_INTEGER TmVirtualClock
    );
#endif // NTDDI_VERSION >= NTDDI_VISTA


#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL (APC_LEVEL) 
NTSYSCALLAPI
NTSTATUS
NTAPI 
NtSinglePhaseReject (
    __in HANDLE EnlistmentHandle,
    __in_opt PLARGE_INTEGER TmVirtualClock
    );
#endif // NTDDI_VERSION >= NTDDI_VISTA


#if (NTDDI_VERSION >= NTDDI_VISTA)
__checkReturn 
__drv_maxIRQL (APC_LEVEL) 
NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreateResourceManager (
    __out PHANDLE ResourceManagerHandle,
    __in ACCESS_MASK DesiredAccess,
    __in HANDLE TmHandle,
    __in LPGUID RmGuid,
    __in_opt POBJECT_ATTRIBUTES ObjectAttributes,
    __in_opt ULONG CreateOptions,
    __in_opt PUNICODE_STRING Description
    );
#endif // NTDDI_VERSION >= NTDDI_VISTA


#if (NTDDI_VERSION >= NTDDI_VISTA)
__checkReturn 
__drv_maxIRQL (APC_LEVEL) 
NTSYSCALLAPI
NTSTATUS
NTAPI
NtOpenResourceManager (
    __out PHANDLE ResourceManagerHandle,
    __in ACCESS_MASK DesiredAccess,
    __in HANDLE TmHandle,
    __in_opt LPGUID ResourceManagerGuid,
    __in_opt POBJECT_ATTRIBUTES ObjectAttributes
    );
#endif // NTDDI_VERSION >= NTDDI_VISTA


#if (NTDDI_VERSION >= NTDDI_VISTA)
__checkReturn 
__drv_maxIRQL (APC_LEVEL) 
NTSYSCALLAPI
NTSTATUS
NTAPI
NtRecoverResourceManager (
    __in HANDLE ResourceManagerHandle
    );
#endif // NTDDI_VERSION >= NTDDI_VISTA


#if (NTDDI_VERSION >= NTDDI_VISTA)
__checkReturn 
__drv_maxIRQL (APC_LEVEL) 
NTSYSCALLAPI
NTSTATUS
NTAPI
NtGetNotificationResourceManager (
    __in HANDLE ResourceManagerHandle,
    __out PTRANSACTION_NOTIFICATION TransactionNotification,
    __in ULONG NotificationLength,
    __in_opt PLARGE_INTEGER Timeout,
    __out_opt PULONG ReturnLength,
    __in ULONG Asynchronous,
    __in_opt ULONG_PTR AsynchronousContext
    );
#endif // NTDDI_VERSION >= NTDDI_VISTA


#if (NTDDI_VERSION >= NTDDI_VISTA)
__checkReturn 
__drv_maxIRQL (APC_LEVEL) 
NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryInformationResourceManager (
    __in HANDLE ResourceManagerHandle,
    __in RESOURCEMANAGER_INFORMATION_CLASS ResourceManagerInformationClass,
    __out_bcount(ResourceManagerInformationLength) PVOID ResourceManagerInformation,
    __in ULONG ResourceManagerInformationLength,
    __out_opt PULONG ReturnLength
    );
#endif // NTDDI_VERSION >= NTDDI_VISTA


#if (NTDDI_VERSION >= NTDDI_VISTA)
__checkReturn 
__drv_maxIRQL (APC_LEVEL) 
NTSYSCALLAPI
NTSTATUS
NTAPI
NtSetInformationResourceManager (
    __in HANDLE ResourceManagerHandle,
    __in RESOURCEMANAGER_INFORMATION_CLASS ResourceManagerInformationClass,
    __in_bcount(ResourceManagerInformationLength) PVOID ResourceManagerInformation,
    __in ULONG ResourceManagerInformationLength
    );
#endif // NTDDI_VERSION >= NTDDI_VISTA


#if (NTDDI_VERSION >= NTDDI_VISTA)
__checkReturn 
__drv_maxIRQL (APC_LEVEL) 
NTSYSCALLAPI
NTSTATUS
NTAPI
NtRegisterProtocolAddressInformation(
    __in HANDLE ResourceManager,
    __in PCRM_PROTOCOL_ID ProtocolId,
    __in ULONG ProtocolInformationSize,
    __in PVOID ProtocolInformation,
    __in_opt ULONG CreateOptions
    );
#endif // NTDDI_VERSION >= NTDDI_VISTA


#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL (APC_LEVEL) 
NTSYSCALLAPI
NTSTATUS
NTAPI
NtPropagationComplete(
    __in HANDLE ResourceManagerHandle,
    __in ULONG RequestCookie,
    __in ULONG BufferLength,
    __in PVOID Buffer
    );
#endif // NTDDI_VERSION >= NTDDI_VISTA


#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL (APC_LEVEL) 
NTSYSCALLAPI
NTSTATUS
NTAPI
NtPropagationFailed(
    __in HANDLE ResourceManagerHandle,
    __in ULONG RequestCookie,
    __in NTSTATUS PropStatus
    );
#endif // NTDDI_VERSION >= NTDDI_VISTA



#ifdef __cplusplus
}
#endif

#endif // _NTTMAPI_


//
// Define alignment macros to align structure sizes and pointers up and down.
//

#undef ALIGN_DOWN_BY
#undef ALIGN_UP_BY
#undef ALIGN_DOWN_POINTER_BY
#undef ALIGN_UP_POINTER_BY
#undef ALIGN_DOWN
#undef ALIGN_UP
#undef ALIGN_DOWN_POINTER
#undef ALIGN_UP_POINTER

#define ALIGN_DOWN_BY(length, alignment) \
    ((ULONG_PTR)(length) & ~(alignment - 1))

#define ALIGN_UP_BY(length, alignment) \
    (ALIGN_DOWN_BY(((ULONG_PTR)(length) + alignment - 1), alignment))

#define ALIGN_DOWN_POINTER_BY(address, alignment) \
    ((PVOID)((ULONG_PTR)(address) & ~((ULONG_PTR)alignment - 1)))

#define ALIGN_UP_POINTER_BY(address, alignment) \
    (ALIGN_DOWN_POINTER_BY(((ULONG_PTR)(address) + alignment - 1), alignment))

#define ALIGN_DOWN(length, type) \
    ALIGN_DOWN_BY(length, sizeof(type))

#define ALIGN_UP(length, type) \
    ALIGN_UP_BY(length, sizeof(type))

#define ALIGN_DOWN_POINTER(address, type) \
    ALIGN_DOWN_POINTER_BY(address, sizeof(type))

#define ALIGN_UP_POINTER(address, type) \
    ALIGN_UP_POINTER_BY(address, sizeof(type))

//
// Calculate the byte offset of a field in a structure of type type.
//

#ifndef FIELD_OFFSET
#define FIELD_OFFSET(type, field) ((ULONG)&(((type *)0)->field))
#endif

#ifndef FIELD_SIZE
#define FIELD_SIZE(type, field) (sizeof(((type *)0)->field))
#endif

#define POOL_TAGGING 1

#if DBG

#define IF_DEBUG if (TRUE)

#else

#define IF_DEBUG if (FALSE)

#endif

#if DEVL


extern ULONG NtGlobalFlag;

#define IF_NTOS_DEBUG(FlagName) \
    if (NtGlobalFlag & (FLG_ ## FlagName))

#else

#define IF_NTOS_DEBUG(FlagName) if(FALSE)

#endif



//
// Define General Lookaside and supporting types here
//

typedef enum _POOL_TYPE POOL_TYPE;

typedef
__drv_sameIRQL
__drv_functionClass(ALLOCATE_FUNCTION)
PVOID
ALLOCATE_FUNCTION (
    __in POOL_TYPE PoolType,
    __in SIZE_T NumberOfBytes,
    __in ULONG Tag
    );
typedef ALLOCATE_FUNCTION *PALLOCATE_FUNCTION;

typedef
__drv_sameIRQL
__drv_functionClass(FREE_FUNCTION)
VOID
FREE_FUNCTION (
    __in PVOID Buffer
    );
typedef FREE_FUNCTION *PFREE_FUNCTION;

typedef struct _LOOKASIDE_LIST_EX *PLOOKASIDE_LIST_EX;

typedef
__drv_sameIRQL
__drv_functionClass(ALLOCATE_FUNCTION_EX)
PVOID
ALLOCATE_FUNCTION_EX (
    __in POOL_TYPE PoolType,
    __in SIZE_T NumberOfBytes,
    __in ULONG Tag,
    __inout PLOOKASIDE_LIST_EX Lookaside
    );
typedef ALLOCATE_FUNCTION_EX *PALLOCATE_FUNCTION_EX;

typedef
__drv_sameIRQL
__drv_functionClass(FREE_FUNCTION_EX)
VOID
FREE_FUNCTION_EX (
    __in PVOID Buffer,
    __inout PLOOKASIDE_LIST_EX Lookaside
    );
typedef FREE_FUNCTION_EX *PFREE_FUNCTION_EX;

#if !defined(_WIN64) && (defined(_NTDDK_) || defined(_NTIFS_) || defined(_NDIS_))

#define LOOKASIDE_ALIGN

#else

#define LOOKASIDE_ALIGN DECLSPEC_CACHEALIGN

#endif


//
// The goal here is to end up with two structure types that are identical except
// for the fact that one (GENERAL_LOOKASIDE) is cache aligned, and the other
// (GENERAL_LOOKASIDE_POOL) is merely naturally aligned.
//
// An anonymous structure element would do the trick except that C++ can't handle
// such complex syntax, so we're stuck with this macro technique.
//

#define GENERAL_LOOKASIDE_LAYOUT                \
    union {                                     \
        SLIST_HEADER ListHead;                  \
        SINGLE_LIST_ENTRY SingleListHead;       \
    } DUMMYUNIONNAME;                           \
    USHORT Depth;                               \
    USHORT MaximumDepth;                        \
    ULONG TotalAllocates;                       \
    union {                                     \
        ULONG AllocateMisses;                   \
        ULONG AllocateHits;                     \
    } DUMMYUNIONNAME2;                          \
                                                \
    ULONG TotalFrees;                           \
    union {                                     \
        ULONG FreeMisses;                       \
        ULONG FreeHits;                         \
    } DUMMYUNIONNAME3;                          \
                                                \
    POOL_TYPE Type;                             \
    ULONG Tag;                                  \
    ULONG Size;                                 \
    union {                                     \
        PALLOCATE_FUNCTION_EX AllocateEx;       \
        PALLOCATE_FUNCTION Allocate;            \
    } DUMMYUNIONNAME4;                          \
                                                \
    union {                                     \
        PFREE_FUNCTION_EX FreeEx;               \
        PFREE_FUNCTION Free;                    \
    } DUMMYUNIONNAME5;                          \
                                                \
    LIST_ENTRY ListEntry;                       \
    ULONG LastTotalAllocates;                   \
    union {                                     \
        ULONG LastAllocateMisses;               \
        ULONG LastAllocateHits;                 \
    } DUMMYUNIONNAME6;                          \
    ULONG Future[2];

//
// GENERAL_LOOKASIDE is a cache aligned type, typically shared between
// multiple processors
//

#if _MSC_VER >= 1200
#pragma warning(push)
#pragma warning(disable:4324) // structure was padded due to __declspec(align())
#endif

typedef struct LOOKASIDE_ALIGN _GENERAL_LOOKASIDE {
    GENERAL_LOOKASIDE_LAYOUT
} GENERAL_LOOKASIDE;

typedef GENERAL_LOOKASIDE *PGENERAL_LOOKASIDE;

#if _MSC_VER >= 1200
#pragma warning(pop)
#endif



//
// GENERAL_LOOKASIDE_POOL is the same layout as GENERAL_LOOKASIDE but is
// not cacheblock aligned, for use in cases where access is limited to a
// single processor
//

typedef struct _GENERAL_LOOKASIDE_POOL {
    GENERAL_LOOKASIDE_LAYOUT
} GENERAL_LOOKASIDE_POOL, *PGENERAL_LOOKASIDE_POOL;

//
// The above two structures should have identical layouts.  A few spot-checks
// just to make sure.
//

#define LOOKASIDE_CHECK(f)  \
    C_ASSERT(FIELD_OFFSET(GENERAL_LOOKASIDE,f)==FIELD_OFFSET(GENERAL_LOOKASIDE_POOL,f))

LOOKASIDE_CHECK(TotalFrees);
LOOKASIDE_CHECK(Tag);
LOOKASIDE_CHECK(Future);

//
// Kernel definitions that need to be here for forward reference purposes
//


//
// Processor modes.
//

typedef CCHAR KPROCESSOR_MODE;

typedef enum _MODE {
    KernelMode,
    UserMode,
    MaximumMode
} MODE;


//
// APC function types
//

//
// Put in an empty definition for the KAPC so that the
// routines can reference it before it is declared.
//

struct _KAPC;

typedef
__drv_functionClass(KNORMAL_ROUTINE)
__drv_maxIRQL(PASSIVE_LEVEL)
__drv_minIRQL(PASSIVE_LEVEL)
__drv_requiresIRQL(PASSIVE_LEVEL)
__drv_sameIRQL
VOID
KNORMAL_ROUTINE (
    __in_opt PVOID NormalContext,
    __in_opt PVOID SystemArgument1,
    __in_opt PVOID SystemArgument2
    );
typedef KNORMAL_ROUTINE *PKNORMAL_ROUTINE;

typedef
__drv_functionClass(KKERNEL_ROUTINE)
__drv_maxIRQL(APC_LEVEL)
__drv_minIRQL(APC_LEVEL)
__drv_requiresIRQL(APC_LEVEL)
__drv_sameIRQL
VOID
KKERNEL_ROUTINE (
    __in struct _KAPC *Apc,
    __deref_inout_opt PKNORMAL_ROUTINE *NormalRoutine,
    __deref_inout_opt PVOID *NormalContext,
    __deref_inout_opt PVOID *SystemArgument1,
    __deref_inout_opt PVOID *SystemArgument2
    );
typedef KKERNEL_ROUTINE *PKKERNEL_ROUTINE;

typedef
__drv_functionClass(KRUNDOWN_ROUTINE)
__drv_maxIRQL(PASSIVE_LEVEL)
__drv_minIRQL(PASSIVE_LEVEL)
__drv_requiresIRQL(PASSIVE_LEVEL)
__drv_sameIRQL
VOID
KRUNDOWN_ROUTINE (
    __in struct _KAPC *Apc
    );
typedef KRUNDOWN_ROUTINE *PKRUNDOWN_ROUTINE;

typedef
__drv_functionClass(KSYNCHRONIZE_ROUTINE)
__drv_sameIRQL
BOOLEAN
KSYNCHRONIZE_ROUTINE (
    __in PVOID SynchronizeContext
    );
typedef KSYNCHRONIZE_ROUTINE *PKSYNCHRONIZE_ROUTINE;

//
// Asynchronous Procedure Call (APC) object
//
// N.B. The size of this structure cannot change since it has been exported.
//

#define ASSERT_APC(E) NT_ASSERT((E)->Type == ApcObject)

typedef struct _KAPC {
    UCHAR Type;
    UCHAR SpareByte0;
    UCHAR Size;
    UCHAR SpareByte1;
    ULONG SpareLong0;
    struct _KTHREAD *Thread;
    LIST_ENTRY ApcListEntry;
    PKKERNEL_ROUTINE KernelRoutine;
    PKRUNDOWN_ROUTINE RundownRoutine;
    PKNORMAL_ROUTINE NormalRoutine;
    PVOID NormalContext;

    //
    // N.B. The following two members MUST be together.
    //

    PVOID SystemArgument1;
    PVOID SystemArgument2;
    CCHAR ApcStateIndex;
    KPROCESSOR_MODE ApcMode;
    BOOLEAN Inserted;
} KAPC, *PKAPC, *PRKAPC;

#define KAPC_OFFSET_TO_SPARE_BYTE0 FIELD_OFFSET(KAPC, SpareByte0)
#define KAPC_OFFSET_TO_SPARE_BYTE1 FIELD_OFFSET(KAPC, SpareByte1)
#define KAPC_OFFSET_TO_SPARE_LONG FIELD_OFFSET(KAPC, SpareLong0)
#define KAPC_OFFSET_TO_SYSTEMARGUMENT1 FIELD_OFFSET(KAPC, SystemArgument1)
#define KAPC_OFFSET_TO_SYSTEMARGUMENT2 FIELD_OFFSET(KAPC, SystemArgument2)
#define KAPC_OFFSET_TO_APCSTATEINDEX FIELD_OFFSET(KAPC, ApcStateIndex)
#define KAPC_ACTUAL_LENGTH (FIELD_OFFSET(KAPC, Inserted) + sizeof(BOOLEAN))


//
// DPC routine
//

struct _KDPC;

__drv_functionClass(KDEFERRED_ROUTINE)
__drv_maxIRQL(DISPATCH_LEVEL)
__drv_minIRQL(DISPATCH_LEVEL)
__drv_requiresIRQL(DISPATCH_LEVEL)
__drv_sameIRQL
typedef
VOID
KDEFERRED_ROUTINE (
    __in struct _KDPC *Dpc,
    __in_opt PVOID DeferredContext,
    __in_opt PVOID SystemArgument1,
    __in_opt PVOID SystemArgument2
    );

typedef KDEFERRED_ROUTINE *PKDEFERRED_ROUTINE;

//
// Define DPC importance.
//
// LowImportance - Queue DPC at end of target DPC queue.
// MediumImportance - Queue DPC at end of target DPC queue.
// MediumHighImportance - Queue DPC at end of target DPC queue.
// HighImportance - Queue DPC at front of target DPC DPC queue.
//
// If there is currently a DPC active on the target processor, or a DPC
// interrupt has already been requested on the target processor when a
// DPC is queued, then no further action is necessary. The DPC will be
// executed on the target processor when its queue entry is processed.
//
// If there is not a DPC active on the target processor and a DPC interrupt
// has not been requested on the target processor, then the exact treatment
// of the DPC is dependent on whether the host system is a UP system or an
// MP system.
//
// UP system.
//
// If the DPC is not of low importance, the current DPC queue depth
// is greater than the maximum target depth, or current DPC request rate is
// less the minimum target rate, then a DPC interrupt is requested on the
// host processor and the DPC will be processed when the interrupt occurs.
// Otherwise, no DPC interupt is requested and the DPC execution will be
// delayed until the DPC queue depth is greater that the target depth or the
// minimum DPC rate is less than the target rate.
//
// MP system.
//
// If the DPC is being queued to another processor and the depth of the DPC
// queue on the target processor is greater than the maximum target depth or
// the DPC is of medium high or high importance, then a DPC interrupt is
// requested on the target processor and the DPC will be processed when the
// Interrupt occurs.  Otherwise, the DPC execution will be delayed on the target
// processor until the DPC queue depth on the target processor is greater that
// the maximum target depth or the minimum DPC rate on the target processor is
// less than the target mimimum rate.
//
// If the DPC is being queued to the current processor and the DPC is not of
// low importance, the current DPC queue depth is greater than the maximum
// target depth, or the minimum DPC rate is less than the minimum target rate,
// then a DPC interrupt is request on the current processor and the DPV will
// be processed when the interrupt occurs. Otherwise, no DPC interupt is
// requested and the DPC execution will be delayed until the DPC queue depth
// is greater that the target depth or the minimum DPC rate is less than the
// target rate.
//

typedef enum _KDPC_IMPORTANCE {
    LowImportance,
    MediumImportance,
    HighImportance,
    MediumHighImportance
} KDPC_IMPORTANCE;

//
// Define DPC type indicies.
//

#define DPC_NORMAL 0
#define DPC_THREADED 1

//
// Deferred Procedure Call (DPC) object
//

#define ASSERT_DPC(Object)                                                   \
    ASSERT(((Object)->Type == 0) ||                                          \
           ((Object)->Type == DpcObject) ||                                  \
           ((Object)->Type == ThreadedDpcObject))

typedef struct _KDPC {
    UCHAR Type;
    UCHAR Importance;
    volatile USHORT Number;
    LIST_ENTRY DpcListEntry;
    PKDEFERRED_ROUTINE DeferredRoutine;
    PVOID DeferredContext;
    PVOID SystemArgument1;
    PVOID SystemArgument2;
    __volatile PVOID DpcData;
} KDPC, *PKDPC, *PRKDPC;

//
// Interprocessor interrupt worker routine function prototype.
//

typedef PVOID PKIPI_CONTEXT;

typedef
__drv_functionClass(KIPI_WORKER)
__drv_sameIRQL
VOID
KIPI_WORKER (
    __inout PKIPI_CONTEXT PacketContext,
    __in_opt PVOID Parameter1,
    __in_opt PVOID Parameter2,
    __in_opt PVOID Parameter3
    );

typedef KIPI_WORKER *PKIPI_WORKER;

//
// Define interprocessor interrupt performance counters.
//

typedef struct _KIPI_COUNTS {
    ULONG Freeze;
    ULONG Packet;
    ULONG DPC;
    ULONG APC;
    ULONG FlushSingleTb;
    ULONG FlushMultipleTb;
    ULONG FlushEntireTb;
    ULONG GenericCall;
    ULONG ChangeColor;
    ULONG SweepDcache;
    ULONG SweepIcache;
    ULONG SweepIcacheRange;
    ULONG FlushIoBuffers;
    ULONG GratuitousDPC;
} KIPI_COUNTS, *PKIPI_COUNTS;


//
// I/O system definitions.
//
// Define a Memory Descriptor List (MDL)
//
// An MDL describes pages in a virtual buffer in terms of physical pages.  The
// pages associated with the buffer are described in an array that is allocated
// just after the MDL header structure itself.
//
// One simply calculates the base of the array by adding one to the base
// MDL pointer:
//
//      Pages = (PPFN_NUMBER) (Mdl + 1);
//
// Notice that while in the context of the subject thread, the base virtual
// address of a buffer mapped by an MDL may be referenced using the following:
//
//      Mdl->StartVa | Mdl->ByteOffset
//

typedef __struct_bcount(Size) struct _MDL {
    struct _MDL *Next;
    CSHORT Size;
    CSHORT MdlFlags;
    struct _EPROCESS *Process;
    PVOID MappedSystemVa;
    PVOID StartVa;
    ULONG ByteCount;
    ULONG ByteOffset;
} MDL, *PMDL;

typedef __inexpressible_readableTo(polymorphism) MDL *PMDLX;

#define MDL_MAPPED_TO_SYSTEM_VA     0x0001
#define MDL_PAGES_LOCKED            0x0002
#define MDL_SOURCE_IS_NONPAGED_POOL 0x0004
#define MDL_ALLOCATED_FIXED_SIZE    0x0008
#define MDL_PARTIAL                 0x0010
#define MDL_PARTIAL_HAS_BEEN_MAPPED 0x0020
#define MDL_IO_PAGE_READ            0x0040
#define MDL_WRITE_OPERATION         0x0080
#define MDL_PARENT_MAPPED_SYSTEM_VA 0x0100
#define MDL_FREE_EXTRA_PTES         0x0200
#define MDL_DESCRIBES_AWE           0x0400
#define MDL_IO_SPACE                0x0800
#define MDL_NETWORK_HEADER          0x1000
#define MDL_MAPPING_CAN_FAIL        0x2000
#define MDL_ALLOCATED_MUST_SUCCEED  0x4000
#define MDL_INTERNAL                0x8000

#define MDL_MAPPING_FLAGS (MDL_MAPPED_TO_SYSTEM_VA     | \
                           MDL_PAGES_LOCKED            | \
                           MDL_SOURCE_IS_NONPAGED_POOL | \
                           MDL_PARTIAL_HAS_BEEN_MAPPED | \
                           MDL_PARENT_MAPPED_SYSTEM_VA | \
                           MDL_SYSTEM_VA               | \
                           MDL_IO_SPACE )


//
// switch to PREFast or DBG when appropriate
//

#if defined(_PREFAST_)

void __PREfastPagedCode(void);
void __PREfastPagedCodeLocked(void);
#define PAGED_CODE()        __PREfastPagedCode();
#define PAGED_CODE_LOCKED() __PREfastPagedCodeLocked();

#elif DBG

#if (NTDDI_VERSION >= NTDDI_VISTA)
#define PAGED_ASSERT( exp ) NT_ASSERT( exp )
#else
#define PAGED_ASSERT( exp ) ASSERT( exp )
#endif

#define PAGED_CODE() {                                                       \
    if (KeGetCurrentIrql() > APC_LEVEL) {                                    \
        KdPrint(("EX: Pageable code called at IRQL %d\n", KeGetCurrentIrql())); \
        PAGED_ASSERT(FALSE);                                                    \
    }                                                                        \
}

#define PAGED_CODE_LOCKED() NOP_FUNCTION;

#else

#define PAGED_CODE()        NOP_FUNCTION;
#define PAGED_CODE_LOCKED() NOP_FUNCTION;

#endif

#define NTKERNELAPI DECLSPEC_IMPORT     

#if defined(_X86_) && !defined(_NTHAL_)

#define _DECL_HAL_KE_IMPORT  DECLSPEC_IMPORT

#elif defined(_X86_)

#define _DECL_HAL_KE_IMPORT

#else

#define _DECL_HAL_KE_IMPORT NTKERNELAPI

#endif


#if !defined(_NTHALDLL_) && !defined(_BLDR_)

#define NTHALAPI DECLSPEC_IMPORT            

#else

#define NTHALAPI

#endif

//
// Common dispatcher object header
//
// N.B. The size field contains the number of dwords in the structure.
//

#define TIMER_EXPIRED_INDEX_BITS        6
#define TIMER_PROCESSOR_INDEX_BITS      5

typedef struct _DISPATCHER_HEADER {
    union {
        struct {
            UCHAR Type;                 // All (accessible via KOBJECT_TYPE)

            union {
                union {                 // Timer
                    UCHAR TimerControlFlags;
                    struct {
                        UCHAR Absolute              : 1;
                        UCHAR Coalescable           : 1;
                        UCHAR KeepShifting          : 1;    // Periodic timer
                        UCHAR EncodedTolerableDelay : 5;    // Periodic timer
                    } DUMMYSTRUCTNAME;
                } DUMMYUNIONNAME;

                UCHAR Abandoned;        // Queue
                BOOLEAN Signalling;     // Gate/Events
            } DUMMYUNIONNAME;

            union {
                union {
                    UCHAR ThreadControlFlags;  // Thread
                    struct {
                        UCHAR CpuThrottled      : 1;
                        UCHAR CycleProfiling    : 1;
                        UCHAR CounterProfiling  : 1;
                        UCHAR Reserved          : 5;
                    } DUMMYSTRUCTNAME;
                } DUMMYUNIONNAME;
                UCHAR Hand;             // Timer
                UCHAR Size;             // All other objects
            } DUMMYUNIONNAME2;

            union {
                union {                 // Timer
                    UCHAR TimerMiscFlags;
                    struct {

#if !defined(_X86_)

                        UCHAR Index             : TIMER_EXPIRED_INDEX_BITS;

#else

                        UCHAR Index             : 1;
                        UCHAR Processor         : TIMER_PROCESSOR_INDEX_BITS;

#endif

                        UCHAR Inserted          : 1;
                        volatile UCHAR Expired  : 1;
                    } DUMMYSTRUCTNAME;
                } DUMMYUNIONNAME;
                union {                 // Thread
                    BOOLEAN DebugActive;
                    struct {
                        BOOLEAN ActiveDR7       : 1;
                        BOOLEAN Instrumented    : 1;
                        BOOLEAN Reserved2       : 4;
                        BOOLEAN UmsScheduled    : 1;
                        BOOLEAN UmsPrimary      : 1;
                    } DUMMYSTRUCTNAME;
                } DUMMYUNIONNAME;
                BOOLEAN DpcActive;      // Mutant
            } DUMMYUNIONNAME3;
        } DUMMYSTRUCTNAME;

        volatile LONG Lock;             // Interlocked
    } DUMMYUNIONNAME;

    LONG SignalState;                   // Object lock
    LIST_ENTRY WaitListHead;            // Object lock
} DISPATCHER_HEADER;



//
// Event object
//

#define ASSERT_EVENT(E)                                                      \
    NT_ASSERT((KOBJECT_TYPE(E) == NotificationEvent) ||                     \
              (KOBJECT_TYPE(E) == SynchronizationEvent))

typedef struct _KEVENT {
    DISPATCHER_HEADER Header;
} KEVENT, *PKEVENT, *PRKEVENT;

//
// Gate object
//
// N.B. Gate object services allow the specification of synchronization
//      events. This allows fast mutex to be transparently replaced with
//      gates.
//

#define ASSERT_GATE(object)                                                  \
    NT_ASSERT((KOBJECT_TYPE(object) == GateObject) || \
              (KOBJECT_TYPE(object) == EventSynchronizationObject))

typedef struct _KGATE {
    DISPATCHER_HEADER Header;
} KGATE, *PKGATE;

//
// Timer object
//
// N.B. The period field must be the last member of this structure.
//

#define ASSERT_TIMER(E)                                                      \
    NT_ASSERT((KOBJECT_TYPE(E) == TimerNotificationObject) ||                \
              (KOBJECT_TYPE(E) == TimerSynchronizationObject))

typedef struct _KTIMER {
    DISPATCHER_HEADER Header;
    ULARGE_INTEGER DueTime;
    LIST_ENTRY TimerListEntry;
    struct _KDPC *Dpc;

#if !defined(_X86_)

    ULONG Processor;

#endif

    ULONG Period;
} KTIMER, *PKTIMER, *PRKTIMER;

#define KTIMER_ACTUAL_LENGTH                                                \
    (FIELD_OFFSET(KTIMER, Period) + sizeof(LONG))

typedef enum _LOCK_OPERATION {
    IoReadAccess,
    IoWriteAccess,
    IoModifyAccess
} LOCK_OPERATION;


#if defined(_X86_) 


//
// Types to use to contain PFNs and their counts.
//

typedef ULONG PFN_COUNT;

typedef LONG SPFN_NUMBER, *PSPFN_NUMBER;
typedef ULONG PFN_NUMBER, *PPFN_NUMBER;

//
// Define maximum size of flush multiple TB request.
//

#define FLUSH_MULTIPLE_MAXIMUM 32

//
// Indicate that the i386 compiler supports the pragma textout construct.
//

#define ALLOC_PRAGMA 1
//
// Indicate that the i386 compiler supports the DATA_SEG("INIT") and
// DATA_SEG("PAGE") pragmas
//

#define ALLOC_DATA_PRAGMA 1


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(HIGH_LEVEL)
_DECL_HAL_KE_IMPORT
VOID
FASTCALL
KfLowerIrql (
    __in __drv_restoresIRQL __drv_nonConstant KIRQL NewIrql
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(HIGH_LEVEL)
__drv_raisesIRQL(NewIrql)
__drv_savesIRQL
_DECL_HAL_KE_IMPORT
KIRQL
FASTCALL
KfRaiseIrql (
    __in KIRQL NewIrql
    );
#endif

#define KeLowerIrql(a) KfLowerIrql(a)
#define KeRaiseIrql(a,b) *(b) = KfRaiseIrql(a)


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
__drv_savesIRQL
__drv_setsIRQL(DISPATCH_LEVEL)
_DECL_HAL_KE_IMPORT
KIRQL
KeRaiseIrqlToDpcLevel (
    VOID
    );
#endif


//
// I/O space read and write macros.
//
//  These have to be actual functions on the 386, because we need
//  to use assembler, but cannot return a value if we inline it.
//
//  The READ/WRITE_REGISTER_* calls manipulate I/O registers in MEMORY space.
//  (Use x86 move instructions, with LOCK prefix to force correct behavior
//   w.r.t. caches and write buffers.)
//
//  The READ/WRITE_PORT_* calls manipulate I/O registers in PORT space.
//  (Use x86 in/out instructions.)
//

NTKERNELAPI
UCHAR
NTAPI
READ_REGISTER_UCHAR(
    __in __drv_nonConstant PUCHAR  Register
    );

NTKERNELAPI
USHORT
NTAPI
READ_REGISTER_USHORT(
    __in __drv_nonConstant PUSHORT Register
    );

NTKERNELAPI
ULONG
NTAPI
READ_REGISTER_ULONG(
    __in __drv_nonConstant PULONG  Register
    );

NTKERNELAPI
VOID
NTAPI
READ_REGISTER_BUFFER_UCHAR(
    __in __drv_nonConstant PUCHAR  Register,
    __out_ecount_full(Count) PUCHAR  Buffer,
    __in ULONG   Count
    );

NTKERNELAPI
VOID
NTAPI
READ_REGISTER_BUFFER_USHORT(
    __in __drv_nonConstant PUSHORT Register,
    __out_ecount_full(Count) PUSHORT Buffer,
    __in ULONG   Count
    );

NTKERNELAPI
VOID
NTAPI
READ_REGISTER_BUFFER_ULONG(
    __in __drv_nonConstant PULONG  Register,
    __out_ecount_full(Count) PULONG  Buffer,
    __in ULONG   Count
    );


NTKERNELAPI
VOID
NTAPI
WRITE_REGISTER_UCHAR(
    __in __drv_nonConstant PUCHAR  Register,
    __in UCHAR   Value
    );

NTKERNELAPI
VOID
NTAPI
WRITE_REGISTER_USHORT(
    __in __drv_nonConstant PUSHORT Register,
    __in USHORT  Value
    );

NTKERNELAPI
VOID
NTAPI
WRITE_REGISTER_ULONG(
    __in __drv_nonConstant PULONG  Register,
    __in ULONG   Value
    );

NTKERNELAPI
VOID
NTAPI
WRITE_REGISTER_BUFFER_UCHAR(
    __in __drv_nonConstant PUCHAR  Register,
    __in_ecount(Count) PUCHAR  Buffer,
    __in ULONG   Count
    );

NTKERNELAPI
VOID
NTAPI
WRITE_REGISTER_BUFFER_USHORT(
    __in __drv_nonConstant PUSHORT Register,
    __in_ecount(Count) PUSHORT Buffer,
    __in ULONG   Count
    );

NTKERNELAPI
VOID
NTAPI
WRITE_REGISTER_BUFFER_ULONG(
    __in __drv_nonConstant PULONG  Register,
    __in_ecount(Count) PULONG  Buffer,
    __in ULONG   Count
    );

NTHALAPI
UCHAR
NTAPI
READ_PORT_UCHAR(
    __in __drv_nonConstant PUCHAR  Port
    );

NTHALAPI
USHORT
NTAPI
READ_PORT_USHORT(
    __in __drv_nonConstant PUSHORT Port
    );

NTHALAPI
ULONG
NTAPI
READ_PORT_ULONG(
    __in __drv_nonConstant PULONG  Port
    );

NTHALAPI
VOID
NTAPI
READ_PORT_BUFFER_UCHAR(
    __in __drv_nonConstant PUCHAR  Port,
    __out_ecount_full(Count) PUCHAR  Buffer,
    __in ULONG   Count
    );

NTHALAPI
VOID
NTAPI
READ_PORT_BUFFER_USHORT(
    __in __drv_nonConstant PUSHORT Port,
    __out_ecount_full(Count) PUSHORT Buffer,
    __in ULONG   Count
    );

NTHALAPI
VOID
NTAPI
READ_PORT_BUFFER_ULONG(
    __in __drv_nonConstant PULONG  Port,
    __out_ecount_full(Count) PULONG  Buffer,
    __in ULONG   Count
    );

NTHALAPI
VOID
NTAPI
WRITE_PORT_UCHAR(
    __in __drv_nonConstant PUCHAR  Port,
    __in UCHAR   Value
    );

NTHALAPI
VOID
NTAPI
WRITE_PORT_USHORT(
    __in __drv_nonConstant PUSHORT Port,
    __in USHORT  Value
    );

NTHALAPI
VOID
NTAPI
WRITE_PORT_ULONG(
    __in __drv_nonConstant PULONG  Port,
    __in ULONG   Value
    );

NTHALAPI
VOID
NTAPI
WRITE_PORT_BUFFER_UCHAR(
    __in __drv_nonConstant PUCHAR  Port,
    __in_ecount(Count) PUCHAR  Buffer,
    __in ULONG   Count
    );

NTHALAPI
VOID
NTAPI
WRITE_PORT_BUFFER_USHORT(
    __in __drv_nonConstant PUSHORT Port,
    __in_ecount(Count) PUSHORT Buffer,
    __in ULONG   Count
    );

NTHALAPI
VOID
NTAPI
WRITE_PORT_BUFFER_ULONG(
    __in __drv_nonConstant PULONG  Port,
    __in_ecount(Count) PULONG  Buffer,
    __in ULONG   Count
    );


//
// Get data cache fill size.
//

#if PRAGMA_DEPRECATED_DDK
#pragma deprecated(KeGetDcacheFillSize)      // Use GetDmaAlignment
#endif

#define KeGetDcacheFillSize() 1L


#define KeFlushIoBuffers(Mdl, ReadOperation, DmaOperation)


#define ExAcquireSpinLock(Lock, OldIrql) KeAcquireSpinLock((Lock), (OldIrql))
#define ExReleaseSpinLock(Lock, OldIrql) KeReleaseSpinLock((Lock), (OldIrql))
#define ExAcquireSpinLockAtDpcLevel(Lock) KeAcquireSpinLockAtDpcLevel(Lock)
#define ExReleaseSpinLockFromDpcLevel(Lock) KeReleaseSpinLockFromDpcLevel(Lock)


#define KeQueryTickCount(CurrentCount) { \
    KSYSTEM_TIME volatile *_TickCount = *((PKSYSTEM_TIME *)(&KeTickCount)); \
    for (;;) {                                                              \
        (CurrentCount)->HighPart = _TickCount->High1Time;                   \
        (CurrentCount)->LowPart = _TickCount->LowPart;                      \
        if ((CurrentCount)->HighPart == _TickCount->High2Time) break;       \
        YieldProcessor();                                                   \
    }                                                                       \
}

//
// The non-volatile 387 state
//

typedef struct _KFLOATING_SAVE {
    ULONG   ControlWord;
    ULONG   StatusWord;
    ULONG   ErrorOffset;
    ULONG   ErrorSelector;
    ULONG   DataOffset;                 // Not used in wdm
    ULONG   DataSelector;
    ULONG   Cr0NpxState;
    ULONG   Spare1;                     // Not used in wdm
} KFLOATING_SAVE, *PKFLOATING_SAVE;

//
// Structure of AMD cache information returned by CPUID instruction
//

typedef union _AMD_L1_CACHE_INFO {
    ULONG Ulong;
    struct {
        UCHAR LineSize;
        UCHAR LinesPerTag;
        UCHAR Associativity;
        UCHAR Size;
    };
} AMD_L1_CACHE_INFO, *PAMD_L1_CACHE_INFO;

typedef union _AMD_L2_CACHE_INFO {
    ULONG Ulong;
    struct {
        UCHAR  LineSize;
        UCHAR  LinesPerTag   : 4;
        UCHAR  Associativity : 4;
        USHORT Size;
    };
} AMD_L2_CACHE_INFO, *PAMD_L2_CACHE_INFO;

typedef union _AMD_L3_CACHE_INFO {
    ULONG Ulong;
    struct {
        UCHAR  LineSize;
        UCHAR  LinesPerTag   : 4;
        UCHAR  Associativity : 4;
        USHORT Reserved : 2;
        USHORT Size : 14;
    };
} AMD_L3_CACHE_INFO, *PAMD_L3_CACHE_INFO;

//
// Structure of Intel deterministic cache information returned by
// CPUID instruction
//

typedef enum _INTEL_CACHE_TYPE {
    IntelCacheNull,
    IntelCacheData,
    IntelCacheInstruction,
    IntelCacheUnified,
    IntelCacheRam,
    IntelCacheTrace
} INTEL_CACHE_TYPE;

typedef union INTEL_CACHE_INFO_EAX {
    ULONG Ulong;
    struct {
        INTEL_CACHE_TYPE Type : 5;
        ULONG Level : 3;
        ULONG SelfInitializing : 1;
        ULONG FullyAssociative : 1;
        ULONG Reserved : 4;
        ULONG ThreadsSharing : 12;
        ULONG ProcessorCores : 6;
    };
} INTEL_CACHE_INFO_EAX, *PINTEL_CACHE_INFO_EAX;

typedef union INTEL_CACHE_INFO_EBX {
    ULONG Ulong;
    struct {
        ULONG LineSize      : 12;
        ULONG Partitions    : 10;
        ULONG Associativity : 10;
    };
} INTEL_CACHE_INFO_EBX, *PINTEL_CACHE_INFO_EBX;

//
// i386 Specific portions of mm component
//

//
// Define the page size for the Intel 386 as 4096 (0x1000).
//

#define PAGE_SIZE 0x1000

//
// Define the number of trailing zeroes in a page aligned virtual address.
// This is used as the shift count when shifting virtual addresses to
// virtual page numbers.
//

#define PAGE_SHIFT 12L


#define MmGetProcedureAddress(Address) (Address)
#define MmLockPagableCodeSection(Address) MmLockPagableDataSection(Address)

#define KIP0PCRADDRESS              0xffdff000  

#define KI_USER_SHARED_DATA         0xffdf0000
#define SharedUserData  ((KUSER_SHARED_DATA * const) KI_USER_SHARED_DATA)

//
// Result type definition for i386.  (Machine specific enumerate type
// which is return type for portable exinterlockedincrement/decrement
// procedures.)  In general, you should use the enumerated type defined
// in ex.h instead of directly referencing these constants.
//

// Flags loaded into AH by LAHF instruction

#define EFLAG_SIGN      0x8000
#define EFLAG_ZERO      0x4000
#define EFLAG_SELECT    (EFLAG_SIGN | EFLAG_ZERO)

#define RESULT_NEGATIVE ((EFLAG_SIGN & ~EFLAG_ZERO) & EFLAG_SELECT)
#define RESULT_ZERO     ((~EFLAG_SIGN & EFLAG_ZERO) & EFLAG_SELECT)
#define RESULT_POSITIVE ((~EFLAG_SIGN & ~EFLAG_ZERO) & EFLAG_SELECT)

//
// Convert various portable ExInterlock APIs into their architectural
// equivalents.
//

#if PRAGMA_DEPRECATED_DDK
#pragma deprecated(ExInterlockedIncrementLong)      // Use InterlockedIncrement
#pragma deprecated(ExInterlockedDecrementLong)      // Use InterlockedDecrement
#pragma deprecated(ExInterlockedExchangeUlong)      // Use InterlockedExchange
#endif

#define ExInterlockedIncrementLong(Addend,Lock) \
        Exfi386InterlockedIncrementLong(Addend)

#define ExInterlockedDecrementLong(Addend,Lock) \
        Exfi386InterlockedDecrementLong(Addend)

#define ExInterlockedExchangeUlong(Target,Value,Lock) \
        Exfi386InterlockedExchangeUlong(Target,Value)

#define ExInterlockedAddUlong           ExfInterlockedAddUlong
#define ExInterlockedInsertHeadList     ExfInterlockedInsertHeadList
#define ExInterlockedInsertTailList     ExfInterlockedInsertTailList
#define ExInterlockedRemoveHeadList     ExfInterlockedRemoveHeadList
#define ExInterlockedPopEntryList       ExfInterlockedPopEntryList
#define ExInterlockedPushEntryList      ExfInterlockedPushEntryList

#if !defined(MIDL_PASS)
#if defined(NO_INTERLOCKED_INTRINSICS) || defined(_CROSS_PLATFORM_)

NTKERNELAPI
LONG
FASTCALL
InterlockedIncrement(
    __inout __drv_interlocked LONG volatile *Addend
    );

NTKERNELAPI
LONG
FASTCALL
InterlockedDecrement(
    __inout __drv_interlocked LONG volatile *Addend
    );

NTKERNELAPI
LONG
FASTCALL
InterlockedExchange(
    __inout __drv_interlocked LONG volatile *Target,
    __in LONG Value
    );

LONG
FASTCALL
InterlockedExchangeAdd(
    __inout __drv_interlocked LONG volatile *Addend,
    __in LONG Increment
    );

NTKERNELAPI
LONG
FASTCALL
InterlockedCompareExchange (
    __inout __drv_interlocked LONG volatile *Destination,
    __in LONG ExChange,
    __in LONG Comperand
    );

#define InterlockedCompareExchangePointer(Destination, ExChange, Comperand) \
    (PVOID)InterlockedCompareExchange((PLONG)Destination, (LONG)ExChange, (LONG)Comperand)

NTKERNELAPI
LONGLONG
FASTCALL
ExfInterlockedCompareExchange64 (
    __inout __drv_interlocked LONGLONG volatile *Destination,
    __in PLONGLONG ExChange,
    __in PLONGLONG Comperand
    );

FORCEINLINE
LONGLONG
InterlockedCompareExchange64_inline (
    __inout __drv_interlocked LONGLONG volatile *Destination,
    __in LONGLONG ExChange,
    __in LONGLONG Comperand
    )
{
    return ExfInterlockedCompareExchange64(Destination, &ExChange, &Comperand);
}

#define InterlockedCompareExchange64 InterlockedCompareExchange64_inline

#else       // NO_INTERLOCKED_INTRINSICS || _CROSS_PLATFORM_

#if (_MSC_FULL_VER > 13009037)
LONG
__cdecl
_InterlockedExchange(
    __inout __drv_interlocked LONG volatile *Target,
    __in LONG Value
    );

#pragma intrinsic(_InterlockedExchange)
#define InterlockedExchange _InterlockedExchange
#else
FORCEINLINE
LONG
FASTCALL
InterlockedExchange(
    __inout __drv_interlocked LONG volatile *Target,
    __in LONG Value
    )
{
    __asm {
        mov     eax, Value
        mov     ecx, Target
        xchg    [ecx], eax
    }
}
#endif

#if (_MSC_FULL_VER > 13009037)
LONG
__cdecl
_InterlockedIncrement(
    __inout __drv_interlocked LONG volatile *Addend
    );

#pragma intrinsic(_InterlockedIncrement)
#define InterlockedIncrement _InterlockedIncrement
#else
#define InterlockedIncrement(Addend) (InterlockedExchangeAdd (Addend, 1)+1)
#endif

#if (_MSC_FULL_VER > 13009037)
LONG
__cdecl
_InterlockedDecrement(
    __inout __drv_interlocked LONG volatile *Addend
    );

#pragma intrinsic(_InterlockedDecrement)
#define InterlockedDecrement _InterlockedDecrement
#else
#define InterlockedDecrement(Addend) (InterlockedExchangeAdd (Addend, -1)-1)
#endif

#if (_MSC_FULL_VER > 13009037)
LONG
__cdecl
_InterlockedExchangeAdd(
    __inout __drv_interlocked LONG volatile *Addend,
    __in LONG Increment
    );

#pragma intrinsic(_InterlockedExchangeAdd)
#define InterlockedExchangeAdd _InterlockedExchangeAdd
#else

FORCEINLINE
LONG
FASTCALL
InterlockedExchangeAdd(
    __inout __drv_interlocked LONG volatile *Addend,
    __in LONG Increment
    )
{
    __asm {
         mov     eax, Increment
         mov     ecx, Addend
    lock xadd    [ecx], eax
    }
}

#endif

#if (_MSC_FULL_VER > 13009037)
LONG
__cdecl
_InterlockedCompareExchange (
    __inout __drv_interlocked LONG volatile *Destination,
    __in LONG ExChange,
    __in LONG Comperand
    );

#pragma intrinsic(_InterlockedCompareExchange)
#define InterlockedCompareExchange (LONG)_InterlockedCompareExchange
#else
FORCEINLINE
LONG
FASTCALL
InterlockedCompareExchange(
    __inout __drv_interlocked LONG volatile *Destination,
    __in LONG Exchange,
    __in LONG Comperand
    )
{
    __asm {
        mov     eax, Comperand
        mov     ecx, Destination
        mov     edx, Exchange
    lock cmpxchg [ecx], edx
    }
}
#endif

#define InterlockedCompareExchangePointer(Destination, ExChange, Comperand) \
    (PVOID)InterlockedCompareExchange((PLONG)Destination, (LONG)ExChange, (LONG)Comperand)

NTKERNELAPI
LONGLONG
FASTCALL
ExfInterlockedCompareExchange64 (
    __inout __drv_interlocked LONGLONG volatile *Destination,
    __in PLONGLONG ExChange,
    __in PLONGLONG Comperand
    );

LONGLONG
FORCEINLINE
InterlockedCompareExchange64_inline (
    __inout __drv_interlocked LONGLONG volatile *Destination,
    __in LONGLONG ExChange,
    __in LONGLONG Comperand
    )
{
    return ExfInterlockedCompareExchange64(Destination, &ExChange, &Comperand);
}

#if (_MSC_FULL_VER >= 140031008)

LONGLONG
__cdecl
_InterlockedCompareExchange64 (
    __inout __drv_interlocked LONGLONG volatile *Destination,
    __in LONGLONG ExChange,
    __in LONGLONG Comperand
    );

#pragma intrinsic(_InterlockedCompareExchange64)
#define InterlockedCompareExchange64 _InterlockedCompareExchange64

#else

#define InterlockedCompareExchange64 InterlockedCompareExchange64_inline

#endif // _MSC_FULL_VER > 140031008

#endif      // INTERLOCKED_INTRINSICS || _CROSS_PLATFORM_

#define InterlockedExchangePointer(Target, Value) \
    (PVOID)InterlockedExchange((PLONG)Target, (LONG)Value)

#endif      // MIDL_PASS

#define InterlockedIncrementAcquire InterlockedIncrement
#define InterlockedIncrementRelease InterlockedIncrement
#define InterlockedDecrementAcquire InterlockedDecrement
#define InterlockedDecrementRelease InterlockedDecrement
#define InterlockedExchangeAcquire64 InterlockedExchange64
#define InterlockedCompareExchangeAcquire InterlockedCompareExchange
#define InterlockedCompareExchangeRelease InterlockedCompareExchange
#define InterlockedCompareExchangeAcquire64 InterlockedCompareExchange64
#define InterlockedCompareExchangeRelease64 InterlockedCompareExchange64
#define InterlockedCompareExchangePointerAcquire InterlockedCompareExchangePointer
#define InterlockedCompareExchangePointerRelease InterlockedCompareExchangePointer

#define InterlockedExchangeAddSizeT(a, b) InterlockedExchangeAdd((LONG *)a, b)
#define InterlockedIncrementSizeT(a) InterlockedIncrement((LONG *)a)
#define InterlockedDecrementSizeT(a) InterlockedDecrement((LONG *)a)


#if !defined(MIDL_PASS) && defined(_M_IX86)

//
// i386 function definitions
//


//
// Get current IRQL.
//
// On x86 this function resides in the HAL
//

__drv_maxIRQL(HIGH_LEVEL)
__drv_savesIRQL
NTHALAPI
KIRQL
NTAPI
KeGetCurrentIrql(
    VOID
    );

#endif // !defined(MIDL_PASS) && defined(_M_IX86)


//++
//
// VOID
// KeMemoryBarrier (
//    VOID
//    )
//
// VOID
// KeMemoryBarrierWithoutFence (
//    VOID
//    )
//
//
// Routine Description:
//
//    These functions order memory accesses as seen by other processors.
//
// Arguments:
//
//    None.
//
// Return Value:
//
//    None.
//
//--

#ifdef __cplusplus
extern "C" {
#endif

//
// Define function to flush a cache line.
//

#define CacheLineFlush(Address) _mm_clflush(Address)

VOID
_mm_clflush (
    VOID const *Address
    );

#pragma intrinsic(_mm_clflush)

VOID
_ReadWriteBarrier(
    VOID
    );

#ifdef __cplusplus
}
#endif

#pragma intrinsic(_ReadWriteBarrier)

#pragma warning( push )
#pragma warning( disable : 4793 )

FORCEINLINE
VOID
KeMemoryBarrier (
    VOID
    )
{
    LONG Barrier;
    __asm {
        xchg Barrier, eax
    }
}

#pragma warning( pop )

#define KeMemoryBarrierWithoutFence() _ReadWriteBarrier()


__checkReturn
__drv_maxIRQL(DISPATCH_LEVEL)
__drv_valueIs(<0;==0)
__drv_when(return==0, __drv_floatSaved)
NTKERNELAPI
NTSTATUS
NTAPI
KeSaveFloatingPointState (
    __out __deref __drv_neverHold(FloatState)
    __drv_when(return==0, __deref __drv_acquiresResource(FloatState))
    PKFLOATING_SAVE   FloatSave
    );

__drv_valueIs(==0)
__drv_floatRestored
NTKERNELAPI
NTSTATUS
NTAPI
KeRestoreFloatingPointState (
    __in __deref __drv_releasesExclusiveResource(FloatState)
    PKFLOATING_SAVE FloatSave
    );


#endif // defined(_X86_)



#if defined(_M_AMD64) && !defined(RC_INVOKED) && !defined(MIDL_PASS)

//
// Define intrinsic function to do in's and out's.
//

#ifdef __cplusplus
extern "C" {
#endif

UCHAR
__inbyte (
    __in USHORT Port
    );

USHORT
__inword (
    __in USHORT Port
    );

ULONG
__indword (
    __in USHORT Port
    );

VOID
__outbyte (
    __in USHORT Port,
    __in UCHAR Data
    );

VOID
__outword (
    __in USHORT Port,
    __in USHORT Data
    );

VOID
__outdword (
    __in USHORT Port,
    __in ULONG Data
    );

VOID
__inbytestring (
    __in USHORT Port,
    __out_ecount_full(Count) PUCHAR Buffer,
    __in ULONG Count
    );

VOID
__inwordstring (
    __in USHORT Port,
    __out_ecount_full(Count) PUSHORT Buffer,
    __in ULONG Count
    );

VOID
__indwordstring (
    __in USHORT Port,
    __out_ecount_full(Count) PULONG Buffer,
    __in ULONG Count
    );

VOID
__outbytestring (
    __in USHORT Port,
    __in_ecount(Count) PUCHAR Buffer,
    __in ULONG Count
    );

VOID
__outwordstring (
    __in USHORT Port,
    __in_ecount(Count) PUSHORT Buffer,
    __in ULONG Count
    );

VOID
__outdwordstring (
    __in USHORT Port,
    __in_ecount(Count) PULONG Buffer,
    __in ULONG Count
    );

#pragma intrinsic(__inbyte)
#pragma intrinsic(__inword)
#pragma intrinsic(__indword)
#pragma intrinsic(__outbyte)
#pragma intrinsic(__outword)
#pragma intrinsic(__outdword)
#pragma intrinsic(__inbytestring)
#pragma intrinsic(__inwordstring)
#pragma intrinsic(__indwordstring)
#pragma intrinsic(__outbytestring)
#pragma intrinsic(__outwordstring)
#pragma intrinsic(__outdwordstring)

#ifdef __cplusplus
}
#endif

#endif // defined(_M_AMD64) && !defined(RC_INVOKED) && !defined(MIDL_PASS)


#if defined(_AMD64_) // ntddk nthal irqls
//
// Types to use to contain PFNs and their counts.
//

typedef ULONG PFN_COUNT;
typedef LONG64 SPFN_NUMBER, *PSPFN_NUMBER;
typedef ULONG64 PFN_NUMBER, *PPFN_NUMBER;

//
// Define maximum size of flush multiple TB request.
//

#define FLUSH_MULTIPLE_MAXIMUM 19

//
// Indicate that the AMD64 compiler supports the allocate pragmas.
//

#define ALLOC_PRAGMA 1
#define ALLOC_DATA_PRAGMA 1

//
// Define functions to read and write CR8.
//
// CR8 is the APIC TPR register.
//

#ifdef __cplusplus
extern "C" {
#endif

#define ReadCR8() __readcr8()

__drv_maxIRQL(HIGH_LEVEL)
__drv_savesIRQL
ULONG64
__readcr8 (
    VOID
    );

#define WriteCR8(Data) __writecr8(Data)

__drv_maxIRQL(HIGH_LEVEL)
__drv_setsIRQL(Data)
VOID
__writecr8 (
    __in ULONG64 Data
    );

#pragma intrinsic(__readcr8)
#pragma intrinsic(__writecr8)

#ifdef __cplusplus
}
#endif




#if defined(_AMD64_) && !defined(DSF_DRIVER)

//
// I/O space read and write macros.
//
//  The READ/WRITE_REGISTER_* calls manipulate I/O registers in MEMORY space.
//
//  The READ/WRITE_PORT_* calls manipulate I/O registers in PORT space.
//

#ifdef __cplusplus
extern "C" {
#endif

__forceinline
UCHAR
READ_REGISTER_UCHAR (
    __in __drv_nonConstant volatile UCHAR *Register
    )
{
    _ReadWriteBarrier();
    return *Register;
}

__forceinline
USHORT
READ_REGISTER_USHORT (
    __in __drv_nonConstant volatile USHORT *Register
    )
{
    _ReadWriteBarrier();
    return *Register;
}

__forceinline
ULONG
READ_REGISTER_ULONG (
    __in __drv_nonConstant volatile ULONG *Register
    )
{
    _ReadWriteBarrier();
    return *Register;
}

__forceinline
ULONG64
READ_REGISTER_ULONG64 (
    __in __drv_nonConstant volatile ULONG64 *Register
    )
{
    _ReadWriteBarrier();
    return *Register;
}

__forceinline
VOID
READ_REGISTER_BUFFER_UCHAR (
    __in __drv_nonConstant PUCHAR Register,
    __out_ecount_full(Count) PUCHAR Buffer,
    __in ULONG Count
    )
{
    _ReadWriteBarrier();
    __movsb(Buffer, Register, Count);
    return;
}

__forceinline
VOID
READ_REGISTER_BUFFER_USHORT (
    __in __drv_nonConstant PUSHORT Register,
    __out_ecount_full(Count) PUSHORT Buffer,
    __in ULONG Count
    )
{
    _ReadWriteBarrier();
    __movsw(Buffer, Register, Count);
    return;
}

__forceinline
VOID
READ_REGISTER_BUFFER_ULONG (
    __in __drv_nonConstant PULONG Register,
    __out_ecount_full(Count) PULONG Buffer,
    __in ULONG Count
    )
{
    _ReadWriteBarrier();
    __movsd(Buffer, Register, Count);
    return;
}

__forceinline
VOID
READ_REGISTER_BUFFER_ULONG64 (
    __in __drv_nonConstant PULONG64 Register,
    __out_ecount_full(Count) PULONG64 Buffer,
    __in ULONG Count
    )
{
    _ReadWriteBarrier();
    __movsq(Buffer, Register, Count);
    return;
}

__forceinline
VOID
WRITE_REGISTER_UCHAR (
    __in __drv_nonConstant volatile UCHAR *Register,
    __in UCHAR Value
    )
{

    *Register = Value;
    FastFence();
    return;
}

__forceinline
VOID
WRITE_REGISTER_USHORT (
    __in __drv_nonConstant volatile USHORT *Register,
    __in USHORT Value
    )
{

    *Register = Value;
    FastFence();
    return;
}

__forceinline
VOID
WRITE_REGISTER_ULONG (
    __in __drv_nonConstant volatile ULONG *Register,
    __in ULONG Value
    )
{

    *Register = Value;
    FastFence();
    return;
}

__forceinline
VOID
WRITE_REGISTER_ULONG64 (
    __in __drv_nonConstant volatile ULONG64 *Register,
    __in ULONG64 Value
    )
{

    *Register = Value;
    FastFence();
    return;
}

__forceinline
VOID
WRITE_REGISTER_BUFFER_UCHAR (
    __in __drv_nonConstant PUCHAR Register,
    __in_ecount(Count) PUCHAR Buffer,
    __in ULONG Count
    )
{

    __movsb(Register, Buffer, Count);
    FastFence();
    return;
}

__forceinline
VOID
WRITE_REGISTER_BUFFER_USHORT (
    __in __drv_nonConstant PUSHORT Register,
    __in_ecount(Count) PUSHORT Buffer,
    __in ULONG Count
    )
{

    __movsw(Register, Buffer, Count);
    FastFence();
    return;
}

__forceinline
VOID
WRITE_REGISTER_BUFFER_ULONG (
    __in __drv_nonConstant PULONG Register,
    __in_ecount(Count) PULONG Buffer,
    __in ULONG Count
    )
{

    __movsd(Register, Buffer, Count);
    FastFence();
    return;
}

__forceinline
VOID
WRITE_REGISTER_BUFFER_ULONG64 (
    __in __drv_nonConstant PULONG64 Register,
    __in_ecount(Count) PULONG64 Buffer,
    __in ULONG Count
    )
{

    __movsq(Register, Buffer, Count);
    FastFence();
    return;
}

__forceinline
UCHAR
READ_PORT_UCHAR (
    __in __drv_nonConstant PUCHAR Port
    )

{
    UCHAR Result;

    _ReadWriteBarrier();
    Result = __inbyte((USHORT)((ULONG_PTR)Port));
    _ReadWriteBarrier();
    return Result;
}

__forceinline
USHORT
READ_PORT_USHORT (
    __in __drv_nonConstant PUSHORT Port
    )

{
    USHORT Result;

    _ReadWriteBarrier();
    Result = __inword((USHORT)((ULONG_PTR)Port));
    _ReadWriteBarrier();
    return Result;
}

__forceinline
ULONG
READ_PORT_ULONG (
    __in __drv_nonConstant PULONG Port
    )

{
    ULONG Result;

    _ReadWriteBarrier();
    Result = __indword((USHORT)((ULONG_PTR)Port));
    _ReadWriteBarrier();
    return Result;
}


__forceinline
VOID
READ_PORT_BUFFER_UCHAR (
    __in __drv_nonConstant PUCHAR Port,
    __out_ecount_full(Count) PUCHAR Buffer,
    __in ULONG Count
    )

{
    _ReadWriteBarrier();
    __inbytestring((USHORT)((ULONG_PTR)Port), Buffer, Count);
    _ReadWriteBarrier();
    return;
}

__forceinline
VOID
READ_PORT_BUFFER_USHORT (
    __in __drv_nonConstant PUSHORT Port,
    __out_ecount_full(Count) PUSHORT Buffer,
    __in ULONG Count
    )

{
    _ReadWriteBarrier();
    __inwordstring((USHORT)((ULONG_PTR)Port), Buffer, Count);
    _ReadWriteBarrier();
    return;
}

__forceinline
VOID
READ_PORT_BUFFER_ULONG (
    __in __drv_nonConstant PULONG Port,
    __out_ecount_full(Count) PULONG Buffer,
    __in ULONG Count
    )

{
    _ReadWriteBarrier();
    __indwordstring((USHORT)((ULONG_PTR)Port), Buffer, Count);
    _ReadWriteBarrier();
    return;
}

__forceinline
VOID
WRITE_PORT_UCHAR (
    __in __drv_nonConstant PUCHAR Port,
    __in UCHAR Value
    )

{
    _ReadWriteBarrier();
    __outbyte((USHORT)((ULONG_PTR)Port), Value);
    _ReadWriteBarrier();
    return;
}

__forceinline
VOID
WRITE_PORT_USHORT (
    __in __drv_nonConstant PUSHORT Port,
    __in USHORT Value
    )

{
    _ReadWriteBarrier();
    __outword((USHORT)((ULONG_PTR)Port), Value);
    _ReadWriteBarrier();
    return;
}

__forceinline
VOID
WRITE_PORT_ULONG (
    __in __drv_nonConstant PULONG Port,
    __in ULONG Value
    )

{
    _ReadWriteBarrier();
    __outdword((USHORT)((ULONG_PTR)Port), Value);
    _ReadWriteBarrier();
    return;
}

__forceinline
VOID
WRITE_PORT_BUFFER_UCHAR (
    __in __drv_nonConstant PUCHAR Port,
    __in_ecount(Count) PUCHAR Buffer,
    __in ULONG Count
    )

{
    _ReadWriteBarrier();
    __outbytestring((USHORT)((ULONG_PTR)Port), Buffer, Count);
    _ReadWriteBarrier();
    return;
}

__forceinline
VOID
WRITE_PORT_BUFFER_USHORT (
    __in __drv_nonConstant PUSHORT Port,
    __in_ecount(Count) PUSHORT Buffer,
    __in ULONG Count
    )

{
    _ReadWriteBarrier();
    __outwordstring((USHORT)((ULONG_PTR)Port), Buffer, Count);
    _ReadWriteBarrier();
    return;
}

__forceinline
VOID
WRITE_PORT_BUFFER_ULONG (
    __in __drv_nonConstant PULONG Port,
    __in_ecount(Count) PULONG Buffer,
    __in ULONG Count
    )

{
    _ReadWriteBarrier();
    __outdwordstring((USHORT)((ULONG_PTR)Port), Buffer, Count);
    _ReadWriteBarrier();
    return;
}

#ifdef __cplusplus
}
#endif

#elif defined(_AMD64_) && defined(DSF_DRIVER)
#include <DsfHrmPorts.h>
#endif




//
// Get data cache fill size.
//

#if PRAGMA_DEPRECATED_DDK
#pragma deprecated(KeGetDcacheFillSize)      // Use GetDmaAlignment
#endif

#define KeGetDcacheFillSize() 1L


#define KeFlushIoBuffers(Mdl, ReadOperation, DmaOperation)


#define ExAcquireSpinLock(Lock, OldIrql) KeAcquireSpinLock((Lock), (OldIrql))
#define ExReleaseSpinLock(Lock, OldIrql) KeReleaseSpinLock((Lock), (OldIrql))
#define ExAcquireSpinLockAtDpcLevel(Lock) KeAcquireSpinLockAtDpcLevel(Lock)
#define ExReleaseSpinLockFromDpcLevel(Lock) KeReleaseSpinLockFromDpcLevel(Lock)


#define KI_USER_SHARED_DATA 0xFFFFF78000000000UI64

#define SharedUserData ((KUSER_SHARED_DATA * const)KI_USER_SHARED_DATA)

#define SharedInterruptTime (KI_USER_SHARED_DATA + 0x8)
#define SharedSystemTime (KI_USER_SHARED_DATA + 0x14)
#define SharedTickCount (KI_USER_SHARED_DATA + 0x320)

#define KeQueryInterruptTime() *((volatile ULONG64 *)(SharedInterruptTime))

#define KeQuerySystemTime(CurrentCount)                                     \
    *((PULONG64)(CurrentCount)) = *((volatile ULONG64 *)(SharedSystemTime))

#define KeQueryTickCount(CurrentCount)                                      \
    *((PULONG64)(CurrentCount)) = *((volatile ULONG64 *)(SharedTickCount))

//
// Dummy nonvolatile floating state structure.
//

typedef struct _KFLOATING_SAVE {
    ULONG Dummy;
} KFLOATING_SAVE, *PKFLOATING_SAVE;

//
// AMD64 Specific portions of mm component.
//
// Define the page size for the AMD64 as 4096 (0x1000).
//

#define PAGE_SIZE 0x1000

//
// Define the number of trailing zeroes in a page aligned virtual address.
// This is used as the shift count when shifting virtual addresses to
// virtual page numbers.
//

#define PAGE_SHIFT 12L


#define MmGetProcedureAddress(Address) (Address)
#define MmLockPagableCodeSection(Address) MmLockPagableDataSection(Address)


//
// Define macro to perform a load fence after a lock acquisition.
//

#define LFENCE_ACQUIRE() LoadFence()

#if !defined(_CROSS_PLATFORM_)

FORCEINLINE
VOID
KeMemoryBarrier (
    VOID
    )

/*++

Routine Description:

    This function orders memory accesses as seen by other processors.

Arguments:

    None.

Return Value:

    None.

--*/

{

    FastFence();
    LFENCE_ACQUIRE();
    return;
}

//++
//
// VOID
// KeMemoryBarrierWithoutFence (
//    VOID
//    )
//
//
// Routine Description:
//
//    This function instructs the compiler not to reorder loads and stores
//    across the function invocation.
//
// Arguments:
//
//    None.
//
// Return Value:
//
//    None.
//
//--

#define KeMemoryBarrierWithoutFence() _ReadWriteBarrier()

#else

#define KeMemoryBarrier()
#define KeMemoryBarrierWithoutFence()

#endif


__checkReturn
__drv_maxIRQL(DISPATCH_LEVEL)
__drv_valueIs(<0;==0)
__drv_when(return==0, __drv_floatSaved)
__forceinline
NTSTATUS
KeSaveFloatingPointState (
    __out __deref __drv_neverHold(FloatState)
    __drv_when(return==0, __deref __drv_acquiresResource(FloatState))
    PVOID FloatingState
    )

#pragma warning (suppress:28104 28161) // PFD can't recognize the implementation
{

    UNREFERENCED_PARAMETER(FloatingState);

    return STATUS_SUCCESS;
}

__drv_valueIs(==0)
__drv_floatRestored
__forceinline
NTSTATUS
KeRestoreFloatingPointState (
    __in __deref __drv_releasesExclusiveResource(FloatState) PVOID FloatingState
    )

#pragma warning (suppress:28103 28162) // PFD can't recognize the implementation
{

    UNREFERENCED_PARAMETER(FloatingState);

    return STATUS_SUCCESS;
}


#endif // defined(_AMD64_)


//
// Platform specific kernel fucntions to raise and lower IRQL.
//


#if defined(_AMD64_) && !defined(MIDL_PASS)


__drv_maxIRQL(HIGH_LEVEL)
__drv_savesIRQL
__forceinline
KIRQL
KeGetCurrentIrql (
    VOID
    )

/*++

Routine Description:

    This function return the current IRQL.

Arguments:

    None.

Return Value:

    The current IRQL is returned as the function value.

--*/

{

    return (KIRQL)ReadCR8();
}

__drv_maxIRQL(HIGH_LEVEL)
__forceinline
VOID
KeLowerIrql (
    __in __drv_nonConstant __drv_restoresIRQL KIRQL NewIrql
   )

/*++

Routine Description:

    This function lowers the IRQL to the specified value.

Arguments:

    NewIrql  - Supplies the new IRQL value.

Return Value:

    None.

--*/

{

    NT_ASSERT(KeGetCurrentIrql() >= NewIrql);

    WriteCR8(NewIrql);
    return;
}

#define KeRaiseIrql(a,b) *(b) = KfRaiseIrql(a)

__drv_maxIRQL(HIGH_LEVEL)
__drv_raisesIRQL(NewIrql)
__drv_savesIRQL
__forceinline
KIRQL
KfRaiseIrql (
    __in KIRQL NewIrql
    )

/*++

Routine Description:

    This function raises the current IRQL to the specified value and returns
    the previous IRQL.

Arguments:

    NewIrql (cl) - Supplies the new IRQL value.

Return Value:

    The previous IRQL is retured as the function value.

--*/

{

    KIRQL OldIrql;

    OldIrql = KeGetCurrentIrql();

    NT_ASSERT(OldIrql <= NewIrql);

    WriteCR8(NewIrql);
    return OldIrql;
}

#endif // defined(_AMD64_) && !defined(MIDL_PASS)


#if defined(_IA64_) 

//
// Types to use to contain PFNs and their counts.
//

typedef ULONG PFN_COUNT;

typedef LONG_PTR SPFN_NUMBER, *PSPFN_NUMBER;
typedef ULONG_PTR PFN_NUMBER, *PPFN_NUMBER;

//
// Indicate that the IA64 compiler supports the pragma textout construct.
//

#define ALLOC_PRAGMA 1

//
// Define intrinsic calls and their prototypes
//

#include "ia64reg.h"

#ifdef __cplusplus
extern "C" {
#endif

unsigned __int64 __getReg (int);
void __setReg (int, unsigned __int64);
void __isrlz (void);
void __dsrlz (void);
void __fwb (void);
void __mf (void);
void __mfa (void);
void __synci (void);
__int64 __thash (__int64);
__int64 __ttag (__int64);
void __ptcl (__int64, __int64);
void __ptcg (__int64, __int64);
void __ptcga (__int64, __int64);
void __ptri (__int64, __int64);
void __ptrd (__int64, __int64);
void __invalat (void);
void __break (int);
void __fc (__int64);
void __fci (__int64);
void __sum (int);
void __rsm (int);
void _ReleaseSpinLock( unsigned __int64 *);
void __yield();
void __lfetch(int, volatile void const *);
void __lfetchfault(int, volatile void const *);
void __lfetch_excl(int, volatile void const *);
void __lfetchfault_excl(int, volatile void const *);
#ifdef _M_IA64
#pragma intrinsic (__getReg)
#pragma intrinsic (__setReg)
#pragma intrinsic (__isrlz)
#pragma intrinsic (__dsrlz)
#pragma intrinsic (__fwb)
#pragma intrinsic (__mf)
#pragma intrinsic (__mfa)
#pragma intrinsic (__synci)
#pragma intrinsic (__thash)
#pragma intrinsic (__ttag)
#pragma intrinsic (__ptcl)
#pragma intrinsic (__ptcg)
#pragma intrinsic (__ptcga)
#pragma intrinsic (__ptri)
#pragma intrinsic (__ptrd)
#pragma intrinsic (__invalat)
#pragma intrinsic (__break)
#pragma intrinsic (__fc)
#pragma intrinsic (__fci)
#pragma intrinsic (__sum)
#pragma intrinsic (__rsm)
#pragma intrinsic (_ReleaseSpinLock)
#pragma intrinsic (__yield)
#pragma intrinsic (__lfetch)
#pragma intrinsic (__lfetchfault)
#pragma intrinsic (__lfetchfault_excl)
#pragma intrinsic (__lfetch_excl)
#endif // _M_IA64

#ifdef __cplusplus
}
#endif



//
// Define length of interrupt vector table.
//

#define MAXIMUM_VECTOR 256

//
// Begin of a block of definitions that must be synchronized with kxia64.h.

#define KI_USER_SHARED_DATA ((ULONG_PTR)(KADDRESS_BASE + 0xFFFE0000))
#define SharedUserData ((KUSER_SHARED_DATA * const)KI_USER_SHARED_DATA)


__checkReturn
__drv_maxIRQL(DISPATCH_LEVEL)
__drv_valueIs(<0;==0)
__drv_when(return==0, __drv_floatSaved)
__forceinline
NTSTATUS
KeSaveFloatingPointState (
    __out __deref __drv_neverHold(FloatState)
    __drv_when(return==0, __deref __drv_acquiresResource(FloatState))
    PVOID FloatingState
    )
#pragma warning (suppress:28104 28161) // PFD can't recognize the implementation
{

    UNREFERENCED_PARAMETER(FloatingState);

    return STATUS_SUCCESS;
}

__drv_valueIs(==0)
__drv_floatRestored
__forceinline
NTSTATUS
KeRestoreFloatingPointState (
    __in __deref __drv_releasesExclusiveResource(FloatState) PVOID FloatingState
    )

#pragma warning (suppress:28103 28162) // PFD can't recognize the implementation
{

    UNREFERENCED_PARAMETER(FloatingState);

    return STATUS_SUCCESS;
}



//
//
// VOID
// KeMemoryBarrierWithoutFence (
//    VOID
//    )
//
//
// Routine Description:
//
//    This function cases ordering of memory acceses generated by the compiler.
//
//
// Arguments:
//
//    None.
//
// Return Value:
//
//    None.
//--

#ifdef __cplusplus
extern "C" {
#endif

VOID
_ReadWriteBarrier (
    VOID
    );

#ifdef __cplusplus
}
#endif

#pragma intrinsic(_ReadWriteBarrier)

#define KeMemoryBarrierWithoutFence() _ReadWriteBarrier()

//++
//
//
// VOID
// KeMemoryBarrier (
//    VOID
//    )
//
//
// Routine Description:
//
//    This function cases ordering of memory acceses as generated by the compiler and
//    as seen by other processors.
//
//
// Arguments:
//
//    None.
//
// Return Value:
//
//    None.
//--

#define KE_MEMORY_BARRIER_REQUIRED

#define KeMemoryBarrier() __mf()

//
// Define the page size
//

#define PAGE_SIZE 0x2000

//
// Define the number of trailing zeroes in a page aligned virtual address.
// This is used as the shift count when shifting virtual addresses to
// virtual page numbers.
//

#define PAGE_SHIFT 13L

//
// Cache and write buffer flush functions.
//

__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
VOID
KeFlushIoBuffers (
    __in PMDL Mdl,
    __in BOOLEAN ReadOperation,
    __in BOOLEAN DmaOperation
    );


//
// Kernel breakin breakpoint
//

VOID
KeBreakinBreakpoint (
    VOID
    );


#define ExAcquireSpinLock(Lock, OldIrql) KeAcquireSpinLock((Lock), (OldIrql))
#define ExReleaseSpinLock(Lock, OldIrql) KeReleaseSpinLock((Lock), (OldIrql))
#define ExAcquireSpinLockAtDpcLevel(Lock) KeAcquireSpinLockAtDpcLevel(Lock)
#define ExReleaseSpinLockFromDpcLevel(Lock) KeReleaseSpinLockFromDpcLevel(Lock)


#if defined(_NTDRIVER_) || defined(_NTDDK_) || defined(_NTIFS_)

#define KeQueryTickCount(CurrentCount ) \
    *(PULONGLONG)(CurrentCount) = **((volatile ULONGLONG **)(&KeTickCount));

#else

NTKERNELAPI
VOID
KeQueryTickCount (
    __out PLARGE_INTEGER CurrentCount
    );

#endif // defined(_NTDRIVER_) || defined(_NTDDK_) || defined(_NTIFS_)

//
// I/O space read and write macros.
//

NTHALAPI
UCHAR
READ_PORT_UCHAR (
    __drv_nonConstant PUCHAR RegisterAddress
    );

NTHALAPI
USHORT
READ_PORT_USHORT (
    __drv_nonConstant PUSHORT RegisterAddress
    );

NTHALAPI
ULONG
READ_PORT_ULONG (
    __drv_nonConstant PULONG RegisterAddress
    );

NTHALAPI
VOID
READ_PORT_BUFFER_UCHAR (
    __drv_nonConstant PUCHAR portAddress,
    PUCHAR readBuffer,
    ULONG  readCount
    );

NTHALAPI
VOID
READ_PORT_BUFFER_USHORT (
    __drv_nonConstant PUSHORT portAddress,
    PUSHORT readBuffer,
    ULONG  readCount
    );

NTHALAPI
VOID
READ_PORT_BUFFER_ULONG (
    __drv_nonConstant PULONG portAddress,
    PULONG readBuffer,
    ULONG  readCount
    );

NTHALAPI
VOID
WRITE_PORT_UCHAR (
    __drv_nonConstant PUCHAR portAddress,
    UCHAR  Data
    );

NTHALAPI
VOID
WRITE_PORT_USHORT (
    __drv_nonConstant PUSHORT portAddress,
    USHORT  Data
    );

NTHALAPI
VOID
WRITE_PORT_ULONG (
    __drv_nonConstant PULONG portAddress,
    ULONG  Data
    );

NTHALAPI
VOID
WRITE_PORT_BUFFER_UCHAR (
    __drv_nonConstant PUCHAR portAddress,
    PUCHAR writeBuffer,
    ULONG  writeCount
    );

NTHALAPI
VOID
WRITE_PORT_BUFFER_USHORT (
    __drv_nonConstant PUSHORT portAddress,
    PUSHORT writeBuffer,
    ULONG  writeCount
    );

NTHALAPI
VOID
WRITE_PORT_BUFFER_ULONG (
    __drv_nonConstant PULONG portAddress,
    PULONG writeBuffer,
    ULONG  writeCount
    );


#define READ_REGISTER_UCHAR(x) \
    (__mf(), *(volatile UCHAR * const)(x))

#define READ_REGISTER_USHORT(x) \
    (__mf(), *(volatile USHORT * const)(x))

#define READ_REGISTER_ULONG(x) \
    (__mf(), *(volatile ULONG * const)(x))

#define READ_REGISTER_ULONG64(x) \
    (__mf(), *(volatile ULONG64 * const)(x))

#define READ_REGISTER_BUFFER_UCHAR(x, y, z) {                           \
    PUCHAR registerBuffer = x;                                          \
    PUCHAR readBuffer = y;                                              \
    ULONG readCount;                                                    \
    __mf();                                                             \
    for (readCount = z; readCount--; readBuffer++, registerBuffer++) {  \
        *readBuffer = *(volatile UCHAR * const)(registerBuffer);        \
    }                                                                   \
}

#define READ_REGISTER_BUFFER_USHORT(x, y, z) {                          \
    PUSHORT registerBuffer = x;                                         \
    PUSHORT readBuffer = y;                                             \
    ULONG readCount;                                                    \
    __mf();                                                             \
    for (readCount = z; readCount--; readBuffer++, registerBuffer++) {  \
        *readBuffer = *(volatile USHORT * const)(registerBuffer);       \
    }                                                                   \
}

#define READ_REGISTER_BUFFER_ULONG(x, y, z) {                           \
    PULONG registerBuffer = x;                                          \
    PULONG readBuffer = y;                                              \
    ULONG readCount;                                                    \
    __mf();                                                             \
    for (readCount = z; readCount--; readBuffer++, registerBuffer++) {  \
        *readBuffer = *(volatile ULONG * const)(registerBuffer);        \
    }                                                                   \
}

#define READ_REGISTER_BUFFER_ULONG64(x, y, z) {                         \
    PULONG64 registerBuffer = x;                                        \
    PULONG64 readBuffer = y;                                            \
    ULONG readCount;                                                    \
    __mf();                                                             \
    for (readCount = z; readCount--; readBuffer++, registerBuffer++) {  \
        *readBuffer = *(volatile ULONG64 * const)(registerBuffer);      \
    }                                                                   \
}

#define WRITE_REGISTER_UCHAR(x, y) {    \
    *(volatile UCHAR * const)(x) = y;   \
    KeFlushWriteBuffer();               \
}

#define WRITE_REGISTER_USHORT(x, y) {   \
    *(volatile USHORT * const)(x) = y;  \
    KeFlushWriteBuffer();               \
}

#define WRITE_REGISTER_ULONG(x, y) {    \
    *(volatile ULONG * const)(x) = y;   \
    KeFlushWriteBuffer();               \
}

#define WRITE_REGISTER_ULONG64(x, y) {  \
    *(volatile ULONG64 * const)(x) = y; \
    KeFlushWriteBuffer();               \
}

#define WRITE_REGISTER_BUFFER_UCHAR(x, y, z) {                            \
    PUCHAR registerBuffer = x;                                            \
    PUCHAR writeBuffer = y;                                               \
    ULONG writeCount;                                                     \
    for (writeCount = z; writeCount--; writeBuffer++, registerBuffer++) { \
        *(volatile UCHAR * const)(registerBuffer) = *writeBuffer;         \
    }                                                                     \
    KeFlushWriteBuffer();                                                 \
}

#define WRITE_REGISTER_BUFFER_USHORT(x, y, z) {                           \
    PUSHORT registerBuffer = x;                                           \
    PUSHORT writeBuffer = y;                                              \
    ULONG writeCount;                                                     \
    for (writeCount = z; writeCount--; writeBuffer++, registerBuffer++) { \
        *(volatile USHORT * const)(registerBuffer) = *writeBuffer;        \
    }                                                                     \
    KeFlushWriteBuffer();                                                 \
}

#define WRITE_REGISTER_BUFFER_ULONG(x, y, z) {                            \
    PULONG registerBuffer = x;                                            \
    PULONG writeBuffer = y;                                               \
    ULONG writeCount;                                                     \
    for (writeCount = z; writeCount--; writeBuffer++, registerBuffer++) { \
        *(volatile ULONG * const)(registerBuffer) = *writeBuffer;         \
    }                                                                     \
    KeFlushWriteBuffer();                                                 \
}

#define WRITE_REGISTER_BUFFER_ULONG64(x, y, z) {                          \
    PULONG64 registerBuffer = x;                                          \
    PULONG64 writeBuffer = y;                                             \
    ULONG writeCount;                                                     \
    for (writeCount = z; writeCount--; writeBuffer++, registerBuffer++) { \
        *(volatile ULONG64 * const)(registerBuffer) = *writeBuffer;       \
    }                                                                     \
    KeFlushWriteBuffer();                                                 \
}


//
// Non-volatile floating point state
//

typedef struct _KFLOATING_SAVE {
    ULONG   Reserved;
} KFLOATING_SAVE, *PKFLOATING_SAVE;


__drv_maxIRQL(HIGH_LEVEL)
__drv_savesIRQL
NTKERNELAPI
KIRQL
KeGetCurrentIrql(
    VOID
    );

__drv_maxIRQL(HIGH_LEVEL)
NTKERNELAPI
VOID
KeLowerIrql (
    __in __drv_nonConstant __drv_restoresIRQL KIRQL NewIrql
    );

__drv_maxIRQL(HIGH_LEVEL)
__drv_raisesIRQL(NewIrql)
NTKERNELAPI
VOID
KeRaiseIrql (
    __in KIRQL NewIrql,
    __out __deref __drv_savesIRQL PKIRQL OldIrql
    );


#define MmGetProcedureAddress(Address) (Address)
#define MmLockPagableCodeSection(PLabelAddress) \
    MmLockPagableDataSection((PVOID)(*((PULONGLONG)PLabelAddress)))

#define VRN_MASK   0xE000000000000000UI64    // Virtual Region Number mask

//
// The lowest address for system space.
//

#define MM_LOWEST_SYSTEM_ADDRESS ((PVOID)((ULONG_PTR)(KADDRESS_BASE + 0xC0C00000)))
#endif // defined(_IA64_)  

//
// Event Specific Access Rights.
//

#define EVENT_QUERY_STATE       0x0001
#define EVENT_MODIFY_STATE      0x0002  
#define EVENT_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|0x3) 


//
// Semaphore Specific Access Rights.
//

#define SEMAPHORE_QUERY_STATE       0x0001
#define SEMAPHORE_MODIFY_STATE      0x0002  

#define SEMAPHORE_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|0x3) 


typedef enum _LOGICAL_PROCESSOR_RELATIONSHIP {
    RelationProcessorCore,
    RelationNumaNode,
    RelationCache,
    RelationProcessorPackage,
    RelationGroup,
    RelationAll = 0xffff
} LOGICAL_PROCESSOR_RELATIONSHIP;

#define LTP_PC_SMT 0x1

typedef enum _PROCESSOR_CACHE_TYPE {
    CacheUnified,
    CacheInstruction,
    CacheData,
    CacheTrace
} PROCESSOR_CACHE_TYPE;

#define CACHE_FULLY_ASSOCIATIVE 0xFF

typedef struct _CACHE_DESCRIPTOR {
    UCHAR  Level;
    UCHAR  Associativity;
    USHORT LineSize;
    ULONG  Size;
    PROCESSOR_CACHE_TYPE Type;
} CACHE_DESCRIPTOR, *PCACHE_DESCRIPTOR;

typedef struct _SYSTEM_LOGICAL_PROCESSOR_INFORMATION {
    ULONG_PTR   ProcessorMask;
    LOGICAL_PROCESSOR_RELATIONSHIP Relationship;
    union {
        struct {
            UCHAR Flags;
        } ProcessorCore;
        struct {
            ULONG NodeNumber;
        } NumaNode;
        CACHE_DESCRIPTOR Cache;
        ULONGLONG  Reserved[2];
    } DUMMYUNIONNAME;
} SYSTEM_LOGICAL_PROCESSOR_INFORMATION, *PSYSTEM_LOGICAL_PROCESSOR_INFORMATION;

typedef struct _PROCESSOR_RELATIONSHIP {
    UCHAR Flags;
    UCHAR Reserved[21];
    USHORT GroupCount;
    __field_ecount(GroupCount) GROUP_AFFINITY GroupMask[ANYSIZE_ARRAY];
} PROCESSOR_RELATIONSHIP, *PPROCESSOR_RELATIONSHIP;

typedef struct _NUMA_NODE_RELATIONSHIP {
    ULONG NodeNumber;
    UCHAR Reserved[20];
    GROUP_AFFINITY GroupMask;
} NUMA_NODE_RELATIONSHIP, *PNUMA_NODE_RELATIONSHIP;

typedef struct _CACHE_RELATIONSHIP {
    UCHAR Level;
    UCHAR Associativity;
    USHORT LineSize;
    ULONG CacheSize;
    PROCESSOR_CACHE_TYPE Type;
    UCHAR Reserved[20];
    GROUP_AFFINITY GroupMask;
} CACHE_RELATIONSHIP, *PCACHE_RELATIONSHIP;

typedef struct _PROCESSOR_GROUP_INFO {
    UCHAR MaximumProcessorCount;
    UCHAR ActiveProcessorCount;
    UCHAR Reserved[38];
    KAFFINITY ActiveProcessorMask;
} PROCESSOR_GROUP_INFO, *PPROCESSOR_GROUP_INFO;

typedef struct _GROUP_RELATIONSHIP {
    USHORT MaximumGroupCount;
    USHORT ActiveGroupCount;
    UCHAR Reserved[20];
    PROCESSOR_GROUP_INFO GroupInfo[ANYSIZE_ARRAY];
} GROUP_RELATIONSHIP, *PGROUP_RELATIONSHIP;

__struct_bcount(Size) struct _SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX {
    LOGICAL_PROCESSOR_RELATIONSHIP Relationship;
    ULONG Size;
    union {
        PROCESSOR_RELATIONSHIP Processor;
        NUMA_NODE_RELATIONSHIP NumaNode;
        CACHE_RELATIONSHIP Cache;
        GROUP_RELATIONSHIP Group;
    } DUMMYUNIONNAME;
};

typedef struct _SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX, *PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX;


//
// Defined processor features
//

#define PF_FLOATING_POINT_PRECISION_ERRATA  0   
#define PF_FLOATING_POINT_EMULATED          1   
#define PF_COMPARE_EXCHANGE_DOUBLE          2   
#define PF_MMX_INSTRUCTIONS_AVAILABLE       3   
#define PF_PPC_MOVEMEM_64BIT_OK             4   
#define PF_ALPHA_BYTE_INSTRUCTIONS          5   
#define PF_XMMI_INSTRUCTIONS_AVAILABLE      6   
#define PF_3DNOW_INSTRUCTIONS_AVAILABLE     7   
#define PF_RDTSC_INSTRUCTION_AVAILABLE      8   
#define PF_PAE_ENABLED                      9   
#define PF_XMMI64_INSTRUCTIONS_AVAILABLE   10   
#define PF_SSE_DAZ_MODE_AVAILABLE          11   
#define PF_NX_ENABLED                      12   
#define PF_SSE3_INSTRUCTIONS_AVAILABLE     13   
#define PF_COMPARE_EXCHANGE128             14   
#define PF_COMPARE64_EXCHANGE128           15   
#define PF_CHANNELS_ENABLED                16   
#define PF_XSAVE_ENABLED                   17   

typedef enum _ALTERNATIVE_ARCHITECTURE_TYPE {
    StandardDesign,                 // None == 0 == standard design
    NEC98x86,                       // NEC PC98xx series on X86
    EndAlternatives                 // past end of known alternatives
} ALTERNATIVE_ARCHITECTURE_TYPE;

// correctly define these run-time definitions for non X86 machines

#ifndef _X86_

#ifndef IsNEC_98
#define IsNEC_98 (FALSE)
#endif

#ifndef IsNotNEC_98
#define IsNotNEC_98 (TRUE)
#endif

#ifndef SetNEC_98
#define SetNEC_98
#endif

#ifndef SetNotNEC_98
#define SetNotNEC_98
#endif

#endif // _X86_

#define PROCESSOR_FEATURE_MAX 64

//
// Exception flag definitions.
//


#define EXCEPTION_NONCONTINUABLE 0x1    // Noncontinuable exception


//
// Define maximum number of exception parameters.
//


#define EXCEPTION_MAXIMUM_PARAMETERS 15 // maximum number of exception parameters

//
// Exception record definition.
//

typedef struct _EXCEPTION_RECORD {
    NTSTATUS ExceptionCode;
    ULONG ExceptionFlags;
    struct _EXCEPTION_RECORD *ExceptionRecord;
    PVOID ExceptionAddress;
    ULONG NumberParameters;
    ULONG_PTR ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
    } EXCEPTION_RECORD;

typedef EXCEPTION_RECORD *PEXCEPTION_RECORD;

typedef struct _EXCEPTION_RECORD32 {
    NTSTATUS ExceptionCode;
    ULONG ExceptionFlags;
    ULONG ExceptionRecord;
    ULONG ExceptionAddress;
    ULONG NumberParameters;
    ULONG ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
} EXCEPTION_RECORD32, *PEXCEPTION_RECORD32;

typedef struct _EXCEPTION_RECORD64 {
    NTSTATUS ExceptionCode;
    ULONG ExceptionFlags;
    ULONG64 ExceptionRecord;
    ULONG64 ExceptionAddress;
    ULONG NumberParameters;
    ULONG __unusedAlignment;
    ULONG64 ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
} EXCEPTION_RECORD64, *PEXCEPTION_RECORD64;

//
// Typedef for pointer returned by exception_info()
//

typedef struct _EXCEPTION_POINTERS {
    PEXCEPTION_RECORD ExceptionRecord;
    PCONTEXT ContextRecord;
} EXCEPTION_POINTERS, *PEXCEPTION_POINTERS;


#define THREAD_WAIT_OBJECTS 3           // Builtin usable wait blocks



//
// Several routines have an architecture specific implementation. Generate
// an error if a supported target is not defined.
//

#if !(defined(_X86_) || defined(_AMD64_) || defined(_IA64_))

#error "No target architecture defined"

#endif

#if (NTDDI_VERSION < NTDDI_WIN7) || defined(_X86_) || !defined(NT_PROCESSOR_GROUPS)

#define SINGLE_GROUP_LEGACY_API 1

#endif




//
// Interrupt modes.
//

typedef enum _KINTERRUPT_MODE {
    LevelSensitive,
    Latched
} KINTERRUPT_MODE;

typedef enum _KINTERRUPT_POLARITY {
    InterruptPolarityUnknown,
    InterruptActiveHigh,
    InterruptActiveLow
} KINTERRUPT_POLARITY, *PKINTERRUPT_POLARITY;


//
// Wait reasons
//

typedef enum _KWAIT_REASON {
    Executive,
    FreePage,
    PageIn,
    PoolAllocation,
    DelayExecution,
    Suspended,
    UserRequest,
    WrExecutive,
    WrFreePage,
    WrPageIn,
    WrPoolAllocation,
    WrDelayExecution,
    WrSuspended,
    WrUserRequest,
    WrEventPair,
    WrQueue,
    WrLpcReceive,
    WrLpcReply,
    WrVirtualMemory,
    WrPageOut,
    WrRendezvous,
    WrKeyedEvent,
    WrTerminated,
    WrProcessInSwap,
    WrCpuRateControl,
    WrCalloutStack,
    WrKernel,
    WrResource,
    WrPushLock,
    WrMutex,
    WrQuantumEnd,
    WrDispatchInt,
    WrPreempted,
    WrYieldExecution,
    WrFastMutex,
    WrGuardedMutex,
    WrRundown,
    MaximumWaitReason
} KWAIT_REASON;


typedef struct _KWAIT_BLOCK {
    LIST_ENTRY WaitListEntry;
    struct _KTHREAD *Thread;
    PVOID Object;
    struct _KWAIT_BLOCK *NextWaitBlock;
    USHORT WaitKey;
    UCHAR WaitType;
    volatile UCHAR BlockState;

#if defined(_WIN64)

    LONG SpareLong;

#endif

} KWAIT_BLOCK, *PKWAIT_BLOCK, *PRKWAIT_BLOCK;

//
// Thread start function
//

typedef
__drv_sameIRQL
__drv_functionClass(KSTART_ROUTINE)
VOID
KSTART_ROUTINE (
    __in PVOID StartContext
    );
typedef KSTART_ROUTINE *PKSTART_ROUTINE;

//
// Kernel object structure definitions
//

//
// Device Queue object and entry
//

#define ASSERT_DEVICE_QUEUE(E) NT_ASSERT((E)->Type == DeviceQueueObject)

typedef struct _KDEVICE_QUEUE {
    CSHORT Type;
    CSHORT Size;
    LIST_ENTRY DeviceListHead;
    KSPIN_LOCK Lock;

#if defined(_AMD64_)

    union {
        BOOLEAN Busy;
        struct {
            LONG64 Reserved : 8;
            LONG64 Hint : 56;
        };
    };

#else

    BOOLEAN Busy;

#endif

} KDEVICE_QUEUE, *PKDEVICE_QUEUE, *PRKDEVICE_QUEUE;

typedef struct _KDEVICE_QUEUE_ENTRY {
    LIST_ENTRY DeviceListEntry;
    ULONG SortKey;
    BOOLEAN Inserted;
} KDEVICE_QUEUE_ENTRY, *PKDEVICE_QUEUE_ENTRY, *PRKDEVICE_QUEUE_ENTRY;

//
// Define the interrupt service function type and the empty struct
// type.
//

__drv_functionClass(KSERVICE_ROUTINE)
__drv_requiresIRQL(HIGH_LEVEL)
__drv_sameIRQL
typedef
BOOLEAN
KSERVICE_ROUTINE (
    __in struct _KINTERRUPT *Interrupt,
    __in PVOID ServiceContext
    );

typedef KSERVICE_ROUTINE *PKSERVICE_ROUTINE;

__drv_functionClass(KMESSAGE_SERVICE_ROUTINE)
__drv_sameIRQL
typedef
BOOLEAN
KMESSAGE_SERVICE_ROUTINE (
    __in struct _KINTERRUPT *Interrupt,
    __in PVOID ServiceContext,
    __in ULONG MessageID
    );

typedef KMESSAGE_SERVICE_ROUTINE *PKMESSAGE_SERVICE_ROUTINE;

//
// Mutant object
//

#define ASSERT_MUTANT(E) NT_ASSERT(KOBJECT_TYPE(E) == MutantObject)

typedef struct _KMUTANT {
    DISPATCHER_HEADER Header;
    LIST_ENTRY MutantListEntry;
    struct _KTHREAD *OwnerThread;
    BOOLEAN Abandoned;
    UCHAR ApcDisable;
} KMUTANT, *PKMUTANT, *PRKMUTANT, KMUTEX, *PKMUTEX, *PRKMUTEX;

//
//
// Semaphore object
//
// N.B. The limit field must be the last member of this structure.
//

#define ASSERT_SEMAPHORE(E) NT_ASSERT(KOBJECT_TYPE(E) == SemaphoreObject)

typedef struct _KSEMAPHORE {
    DISPATCHER_HEADER Header;
    LONG Limit;
} KSEMAPHORE, *PKSEMAPHORE, *PRKSEMAPHORE;

#define KSEMAPHORE_ACTUAL_LENGTH                                             \
    (FIELD_OFFSET(KSEMAPHORE, Limit) + sizeof(LONG))

//
// DPC object
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
KeInitializeDpc (
    __out __drv_aliasesMem PRKDPC Dpc,
    __in PKDEFERRED_ROUTINE DeferredRoutine,
    __in_opt __drv_aliasesMem PVOID DeferredContext
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WS03)
NTKERNELAPI
VOID
KeInitializeThreadedDpc (
    __out PRKDPC Dpc,
    __in PKDEFERRED_ROUTINE DeferredRoutine,
    __in_opt PVOID DeferredContext
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
BOOLEAN
KeInsertQueueDpc (
    __inout PRKDPC Dpc,
    __in_opt PVOID SystemArgument1,
    __in_opt PVOID SystemArgument2
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(HIGH_LEVEL)
NTKERNELAPI
BOOLEAN
KeRemoveQueueDpc (
    __inout PRKDPC Dpc
    );
#endif



#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
KeSetImportanceDpc (
    __inout PRKDPC Dpc,
    __in KDPC_IMPORTANCE Importance
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K) && defined(SINGLE_GROUP_LEGACY_API)
NTKERNELAPI
VOID
KeSetTargetProcessorDpc (
    __inout PRKDPC Dpc,
    __in CCHAR Number
    );
#endif



#if (NTDDI_VERSION >= NTDDI_WINXPSP2)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
KeFlushQueuedDpcs (
    VOID
    );
#endif

//
// Device queue object
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
VOID
KeInitializeDeviceQueue (
    __out PKDEVICE_QUEUE DeviceQueue
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_requiresIRQL(DISPATCH_LEVEL)
NTKERNELAPI
BOOLEAN
KeInsertDeviceQueue (
    __inout PKDEVICE_QUEUE DeviceQueue,
    __inout PKDEVICE_QUEUE_ENTRY DeviceQueueEntry
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_requiresIRQL(DISPATCH_LEVEL)
NTKERNELAPI
BOOLEAN
KeInsertByKeyDeviceQueue (
    __inout PKDEVICE_QUEUE DeviceQueue,
    __inout PKDEVICE_QUEUE_ENTRY DeviceQueueEntry,
    __in ULONG SortKey
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_requiresIRQL(DISPATCH_LEVEL)
NTKERNELAPI
PKDEVICE_QUEUE_ENTRY
KeRemoveDeviceQueue (
    __inout PKDEVICE_QUEUE DeviceQueue
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_requiresIRQL(DISPATCH_LEVEL)
NTKERNELAPI
PKDEVICE_QUEUE_ENTRY
KeRemoveByKeyDeviceQueue (
    __inout PKDEVICE_QUEUE DeviceQueue,
    __in ULONG SortKey
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
__drv_requiresIRQL(DISPATCH_LEVEL)
NTKERNELAPI
PKDEVICE_QUEUE_ENTRY
KeRemoveByKeyDeviceQueueIfBusy (
    __inout PKDEVICE_QUEUE DeviceQueue,
    __in ULONG SortKey
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
BOOLEAN
KeRemoveEntryDeviceQueue (
    __inout PKDEVICE_QUEUE DeviceQueue,
    __inout PKDEVICE_QUEUE_ENTRY DeviceQueueEntry
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(HIGH_LEVEL)
NTKERNELAPI
BOOLEAN
KeSynchronizeExecution (
    __inout PKINTERRUPT Interrupt,
    __in PKSYNCHRONIZE_ROUTINE SynchronizeRoutine,
    __in_opt __drv_aliasesMem PVOID SynchronizeContext
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
__drv_maxIRQL(HIGH_LEVEL)
__drv_savesIRQL
__drv_setsIRQL(HIGH_LEVEL)
NTKERNELAPI
KIRQL
KeAcquireInterruptSpinLock (
    __inout __deref __drv_acquiresExclusiveResource(InterruptSpinLock)
    PKINTERRUPT Interrupt
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
__drv_requiresIRQL(HIGH_LEVEL)
NTKERNELAPI
VOID
KeReleaseInterruptSpinLock (
    __inout __deref __drv_releasesExclusiveResource(InterruptSpinLock)
    PKINTERRUPT Interrupt,
    __in __drv_restoresIRQL KIRQL OldIrql
    );
#endif

//
// Kernel dispatcher object functions
//
// Event Object
//

NTKERNELAPI
VOID
KeInitializeEvent (
    __out PRKEVENT Event,
    __in EVENT_TYPE Type,
    __in BOOLEAN State
    );

__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
VOID
KeClearEvent (
    __inout PRKEVENT Event
    );


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
LONG
KeReadStateEvent (
    __in PRKEVENT Event
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
LONG
KeResetEvent (
    __inout PRKEVENT Event
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_when(Wait==0, __drv_maxIRQL(DISPATCH_LEVEL))
__drv_when(Wait==1, __drv_maxIRQL(APC_LEVEL))
__drv_when(Wait==1, __drv_reportError("Caution: 'Wait' argument does not provide"
                                      " any synchronization guarantees, only a hint"
                                      " to the system that the thread will immediately"
                                      " issue a wait operation"))
NTKERNELAPI
LONG
KeSetEvent (
    __inout PRKEVENT Event,
    __in KPRIORITY Increment,
    __in __drv_constant BOOLEAN Wait
    );
#endif

//
// Mutex object
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
KeInitializeMutex (
    __out PRKMUTEX Mutex,
    __in ULONG Level
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
LONG
KeReadStateMutex (
    __in PRKMUTEX Mutex
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_when(Wait==0, __drv_maxIRQL(DISPATCH_LEVEL))
__drv_when(Wait==1, __drv_maxIRQL(APC_LEVEL))
__drv_when(Wait==1, __drv_reportError("Caution: 'Wait' argument does not provide"
                                      " any synchronization guarantees, only a hint"
                                      " to the system that the thread will immediately"
                                      " issue a wait operation"))
NTKERNELAPI
LONG
KeReleaseMutex (
    __inout PRKMUTEX Mutex,
    __in BOOLEAN Wait
    );
#endif

//
// Semaphore object
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
VOID
KeInitializeSemaphore (
    __out PRKSEMAPHORE Semaphore,
    __in LONG Count,
    __in LONG Limit
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
LONG
KeReadStateSemaphore (
    __in PRKSEMAPHORE Semaphore
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_when(Wait==0, __drv_maxIRQL(DISPATCH_LEVEL))
__drv_when(Wait==1, __drv_maxIRQL(APC_LEVEL))
__drv_when(Wait==1, __drv_reportError("Caution: 'Wait' argument does not provide"
                                      " any synchronization guarantees, only a hint"
                                      " to the system that the thread will immediately"
                                      " issue a wait operation"))
NTKERNELAPI
LONG
KeReleaseSemaphore (
    __inout PRKSEMAPHORE Semaphore,
    __in KPRIORITY Increment,
    __in LONG Adjustment,
    __in __drv_constant BOOLEAN Wait
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN7)
__drv_maxIRQL(DISPATCH_LEVEL)
__drv_minIRQL(PASSIVE_LEVEL)
__drv_sameIRQL
ULONG64
KeQueryTotalCycleTimeProcess (
    __inout PKPROCESS Process,
    __out PULONG64 CycleTimeStamp
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_minIRQL(PASSIVE_LEVEL)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
NTSTATUS
KeDelayExecutionThread (
    __in KPROCESSOR_MODE WaitMode,
    __in BOOLEAN Alertable,
    __in PLARGE_INTEGER Interval
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
KPRIORITY
KeQueryPriorityThread (
    __in PKTHREAD Thread
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
ULONG
KeQueryRuntimeThread (
    __in PKTHREAD Thread,
    __out PULONG UserTime
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
__drv_maxIRQL(APC_LEVEL)
__drv_minIRQL(PASSIVE_LEVEL)
__drv_sameIRQL
ULONG64
KeQueryTotalCycleTimeThread (
    __inout PKTHREAD Thread,
    __out PULONG64 CycleTimeStamp
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN7)
__checkReturn
NTKERNELAPI
NTSTATUS
KeSetTargetProcessorDpcEx (
    __inout PKDPC Dpc,
    __in PPROCESSOR_NUMBER ProcNumber
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K) && defined(SINGLE_GROUP_LEGACY_API)
__drv_minIRQL(PASSIVE_LEVEL)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
KeRevertToUserAffinityThread (
    VOID
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K) && defined(SINGLE_GROUP_LEGACY_API)
__drv_minIRQL(PASSIVE_LEVEL)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
KeSetSystemAffinityThread (
    __in KAFFINITY Affinity
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA) && defined(SINGLE_GROUP_LEGACY_API)
__drv_minIRQL(PASSIVE_LEVEL)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
KeRevertToUserAffinityThreadEx (
    __in KAFFINITY Affinity
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
__drv_minIRQL(PASSIVE_LEVEL)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
KeSetSystemGroupAffinityThread (
    __in PGROUP_AFFINITY Affinity,
    __out_opt PGROUP_AFFINITY PreviousAffinity
    );

__drv_minIRQL(PASSIVE_LEVEL)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
KeRevertToUserGroupAffinityThread (
    __in PGROUP_AFFINITY PreviousAffinity
    );
#endif

#if (NTDDI_VERSION >= NTDDI_LONGHORN) && defined(SINGLE_GROUP_LEGACY_API)
__drv_minIRQL(PASSIVE_LEVEL)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
KAFFINITY
KeSetSystemAffinityThreadEx (
    __in KAFFINITY Affinity
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_minIRQL(PASSIVE_LEVEL)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
KPRIORITY
KeSetPriorityThread (
    __inout PKTHREAD Thread,
    __in KPRIORITY Priority
    );
#endif



#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_neverHoldCriticalRegion
__drv_acquiresCriticalRegion
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
KeEnterCriticalRegion (
    VOID
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_mustHoldCriticalRegion
__drv_releasesCriticalRegion
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
KeLeaveCriticalRegion (
    VOID
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
__drv_neverHoldCriticalRegion
__drv_acquiresCriticalRegion
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
KeEnterGuardedRegion (
    VOID
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
__drv_mustHoldCriticalRegion
__drv_releasesCriticalRegion
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
KeLeaveGuardedRegion (
    VOID
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
BOOLEAN
KeAreApcsDisabled (
    VOID
    );
#endif



//
// Timer object
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
VOID
KeInitializeTimer (
    __out PKTIMER Timer
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
VOID
KeInitializeTimerEx (
    __out PKTIMER Timer,
    __in TIMER_TYPE Type
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
BOOLEAN
KeCancelTimer (
    __inout PKTIMER
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
BOOLEAN
KeReadStateTimer (
    __in PKTIMER Timer
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
BOOLEAN
KeSetTimer (
    __inout PKTIMER Timer,
    __in LARGE_INTEGER DueTime,
    __in_opt PKDPC Dpc
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
BOOLEAN
KeSetTimerEx (
    __inout PKTIMER Timer,
    __in LARGE_INTEGER DueTime,
    __in LONG Period,
    __in_opt PKDPC Dpc
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
BOOLEAN
KeSetCoalescableTimer (
    __inout PKTIMER Timer,
    __in LARGE_INTEGER DueTime,
    __in ULONG Period,
    __in ULONG TolerableDelay,
    __in_opt PKDPC Dpc
    );
#endif


#define KeWaitForMutexObject KeWaitForSingleObject

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_minIRQL(PASSIVE_LEVEL)
__drv_when((Timeout==NULL || *Timeout!=0), __drv_maxIRQL(APC_LEVEL))
__drv_when((Timeout!=NULL && *Timeout==0), __drv_maxIRQL(DISPATCH_LEVEL))
NTKERNELAPI
NTSTATUS
KeWaitForMultipleObjects (
    __in ULONG Count,
    __in_ecount(Count) PVOID Object[],
    __in __drv_strictTypeMatch(__drv_typeConst) WAIT_TYPE WaitType,
    __in __drv_strictTypeMatch(__drv_typeCond) KWAIT_REASON WaitReason,
    __in __drv_strictType(KPROCESSOR_MODE/enum _MODE,__drv_typeConst)
    KPROCESSOR_MODE WaitMode,
    __in BOOLEAN Alertable,
    __in_opt PLARGE_INTEGER Timeout,
    __out_opt PKWAIT_BLOCK WaitBlockArray
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_minIRQL(PASSIVE_LEVEL)
__drv_when((Timeout==NULL || *Timeout!=0), __drv_maxIRQL(APC_LEVEL))
__drv_when((Timeout!=NULL && *Timeout==0), __drv_maxIRQL(DISPATCH_LEVEL))
NTKERNELAPI
NTSTATUS
KeWaitForSingleObject (
    __in __deref __drv_notPointer PVOID Object,
    __in __drv_strictTypeMatch(__drv_typeCond) KWAIT_REASON WaitReason,
    __in __drv_strictType(KPROCESSOR_MODE/enum _MODE,__drv_typeConst)
    KPROCESSOR_MODE WaitMode,
    __in BOOLEAN Alertable,
    __in_opt PLARGE_INTEGER Timeout
    );
#endif

//
// Define interprocess interrupt generic call types.
//

typedef
__drv_sameIRQL
__drv_functionClass(KIPI_BROADCAST_WORKER)
__drv_requiresIRQL(IPI_LEVEL)
ULONG_PTR
KIPI_BROADCAST_WORKER (
    __in ULONG_PTR Argument
    );

typedef KIPI_BROADCAST_WORKER *PKIPI_BROADCAST_WORKER;

#if (NTDDI_VERSION >= NTDDI_WS03)
__drv_minIRQL(PASSIVE_LEVEL)
__drv_maxIRQL(IPI_LEVEL-1)
NTKERNELAPI
ULONG_PTR
KeIpiGenericCall (
    __in PKIPI_BROADCAST_WORKER BroadcastFunction,
    __in ULONG_PTR Context
    );
#endif

//
// spin lock functions
//

#if defined(_X86_) && (defined(_WDM_INCLUDED_) || defined(WIN9X_COMPAT_SPINLOCK))

#if (NTDDI_VERSION >= NTDDI_WIN2K)

NTKERNELAPI
VOID
NTAPI
KeInitializeSpinLock (
    __out PKSPIN_LOCK SpinLock
    );

#endif

#else

FORCEINLINE
VOID
NTAPI
KeInitializeSpinLock (
    __out PKSPIN_LOCK SpinLock
    )

/*++

Routine Description:

    This function initializes a spinlock.

Arguments:

    SpinLock - Supplies a pointer to a spinlock.

Return Value:

    None.

--*/

{

    *SpinLock = 0;
    return;
}

#endif



#if (NTDDI_VERSION >= NTDDI_WS03)
__checkReturn
NTKERNELAPI
BOOLEAN
FASTCALL
KeTestSpinLock (
    __in PKSPIN_LOCK SpinLock
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
__checkReturn
__drv_minIRQL(DISPATCH_LEVEL)
__drv_valueIs(==1;==0)
NTKERNELAPI
BOOLEAN
FASTCALL
KeTryToAcquireSpinLockAtDpcLevel (
    __inout __deref __drv_neverHold(KeSpinLockType)
    __drv_when(return!=0, __deref __drv_acquiresResource(KeSpinLockType))
    PKSPIN_LOCK SpinLock
    );
#endif

#if defined(_X86_)   // ntifs

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_minIRQL(DISPATCH_LEVEL)
NTKERNELAPI
VOID
FASTCALL
KefAcquireSpinLockAtDpcLevel (
    __inout __deref __drv_acquiresExclusiveResource(KeSpinLockType)
    PKSPIN_LOCK SpinLock
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_minIRQL(DISPATCH_LEVEL)
NTKERNELAPI
VOID
FASTCALL
KefReleaseSpinLockFromDpcLevel (
    __inout __deref __drv_releasesExclusiveResource(KeSpinLockType)
    PKSPIN_LOCK SpinLock
    );
#endif

#define KeAcquireSpinLockAtDpcLevel(a) KefAcquireSpinLockAtDpcLevel(a)
#define KeReleaseSpinLockFromDpcLevel(a) KefReleaseSpinLockFromDpcLevel(a)

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
__drv_savesIRQL
__drv_setsIRQL(DISPATCH_LEVEL)
_DECL_HAL_KE_IMPORT
KIRQL
FASTCALL
KfAcquireSpinLock (
    __inout __deref __drv_acquiresExclusiveResource(KeSpinLockType)
    PKSPIN_LOCK SpinLock
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_requiresIRQL(DISPATCH_LEVEL)
_DECL_HAL_KE_IMPORT
VOID
FASTCALL
KfReleaseSpinLock (
    __inout __deref __drv_releasesExclusiveResource(KeSpinLockType)
    PKSPIN_LOCK SpinLock,
    __in __drv_restoresIRQL KIRQL NewIrql
    );
#endif


#define KeAcquireSpinLock(a,b) *(b) = KfAcquireSpinLock(a)
#define KeReleaseSpinLock(a,b) KfReleaseSpinLock(a,b)

#else // ntifs

//
// These functions are imported for IA64, ntddk, ntifs, nthal, ntosp, and wdm.
// They can be inlined for the system on AMD64.
//

#define KeAcquireSpinLock(SpinLock, OldIrql) \
    *(OldIrql) = KeAcquireSpinLockRaiseToDpc(SpinLock)


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_minIRQL(DISPATCH_LEVEL)
NTKERNELAPI
VOID
KeAcquireSpinLockAtDpcLevel (
    __inout __deref __drv_acquiresExclusiveResource(KeSpinLockType)
    PKSPIN_LOCK SpinLock
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
__drv_savesIRQL
__drv_setsIRQL(DISPATCH_LEVEL)
NTKERNELAPI
KIRQL
KeAcquireSpinLockRaiseToDpc (
    __inout __deref __drv_acquiresExclusiveResource(KeSpinLockType)
    PKSPIN_LOCK SpinLock
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_requiresIRQL(DISPATCH_LEVEL)
NTKERNELAPI
VOID
KeReleaseSpinLock (
    __inout __deref __drv_releasesExclusiveResource(KeSpinLockType)
    PKSPIN_LOCK SpinLock,
    __in __drv_restoresIRQL KIRQL NewIrql
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_minIRQL(DISPATCH_LEVEL)
NTKERNELAPI
VOID
KeReleaseSpinLockFromDpcLevel (
    __inout __deref __drv_releasesExclusiveResource(KeSpinLockType)
    PKSPIN_LOCK SpinLock
    );
#endif

#endif // ntifs



#if (NTDDI_VERSION >= NTDDI_WS03)
__drv_maxIRQL(DISPATCH_LEVEL)
__drv_savesIRQL
NTKERNELAPI
KIRQL
FASTCALL
KeAcquireSpinLockForDpc (
    __inout __deref __drv_acquiresExclusiveResource(KeSpinLockType)
    PKSPIN_LOCK SpinLock
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WS03)
__drv_requiresIRQL(DISPATCH_LEVEL)
NTKERNELAPI
VOID
FASTCALL
KeReleaseSpinLockForDpc (
    __inout __deref __drv_releasesExclusiveResource(KeSpinLockType)
    PKSPIN_LOCK SpinLock,
    __in __drv_restoresIRQL KIRQL OldIrql
    );
#endif



//
// Queued spin lock functions for "in stack" lock handles.
//
// The following three functions RAISE and LOWER IRQL when a queued
// in stack spin lock is acquired or released using these routines.
//

#if (NTDDI_VERSION >= NTDDI_WINXP)
__drv_maxIRQL(DISPATCH_LEVEL)
__drv_savesIRQLGlobal(QueuedSpinLock,LockHandle)
__drv_setsIRQL(DISPATCH_LEVEL)
_DECL_HAL_KE_IMPORT
VOID
FASTCALL
KeAcquireInStackQueuedSpinLock (
    __inout PKSPIN_LOCK SpinLock,
    __out __deref __drv_acquiresExclusiveResource(KeQueuedSpinLockType)
    PKLOCK_QUEUE_HANDLE LockHandle
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
__drv_requiresIRQL(DISPATCH_LEVEL)
__drv_restoresIRQLGlobal(QueuedSpinLock,LockHandle)
_DECL_HAL_KE_IMPORT
VOID
FASTCALL
KeReleaseInStackQueuedSpinLock (
    __in __deref __drv_releasesExclusiveResource(KeQueuedSpinLockType)
    PKLOCK_QUEUE_HANDLE LockHandle
    );
#endif

//
// The following two functions do NOT raise or lower IRQL when a queued
// in stack spin lock is acquired or released using these functions.
//

#if (NTDDI_VERSION >= NTDDI_WINXP)
__drv_minIRQL(DISPATCH_LEVEL)
NTKERNELAPI
VOID
FASTCALL
KeAcquireInStackQueuedSpinLockAtDpcLevel (
    __inout PKSPIN_LOCK SpinLock,
    __out __deref __drv_acquiresExclusiveResource(KeQueuedSpinLockType)
    PKLOCK_QUEUE_HANDLE LockHandle
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
__drv_requiresIRQL(DISPATCH_LEVEL)
NTKERNELAPI
VOID
FASTCALL
KeReleaseInStackQueuedSpinLockFromDpcLevel (
    __in __deref __drv_releasesExclusiveResource(KeQueuedSpinLockType)
    PKLOCK_QUEUE_HANDLE LockHandle
    );
#endif

//
// The following two functions conditionally raise or lower IRQL when a
// queued in-stack spin lock is acquired or released using these functions.
//

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(DISPATCH_LEVEL)
__drv_savesIRQLGlobal(QueuedSpinLock,LockHandle)
NTKERNELAPI
VOID
FASTCALL
KeAcquireInStackQueuedSpinLockForDpc (
    __inout PKSPIN_LOCK SpinLock,
    __out __deref __drv_acquiresExclusiveResource(KeQueuedSpinLockType)
    PKLOCK_QUEUE_HANDLE LockHandle
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_requiresIRQL(DISPATCH_LEVEL)
__drv_restoresIRQLGlobal(QueuedSpinLock,LockHandle)
NTKERNELAPI
VOID
FASTCALL
KeReleaseInStackQueuedSpinLockForDpc (
    __in __deref __drv_releasesExclusiveResource(KeQueuedSpinLockType)
    PKLOCK_QUEUE_HANDLE LockHandle
    );
#endif

//
// Miscellaneous kernel functions
//

typedef struct _KDPC_WATCHDOG_INFORMATION {
    ULONG DpcTimeLimit;
    ULONG DpcTimeCount;
    ULONG DpcWatchdogLimit;
    ULONG DpcWatchdogCount;
    ULONG Reserved;
} KDPC_WATCHDOG_INFORMATION, *PKDPC_WATCHDOG_INFORMATION;

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_requiresIRQL(DISPATCH_LEVEL)
NTKERNELAPI
NTSTATUS
KeQueryDpcWatchdogInformation (
    __out PKDPC_WATCHDOG_INFORMATION WatchdogInformation
    );
#endif

typedef enum _KBUGCHECK_BUFFER_DUMP_STATE {
    BufferEmpty,
    BufferInserted,
    BufferStarted,
    BufferFinished,
    BufferIncomplete
} KBUGCHECK_BUFFER_DUMP_STATE;

typedef
__drv_functionClass(KBUGCHECK_CALLBACK_ROUTINE)
__drv_sameIRQL
VOID
KBUGCHECK_CALLBACK_ROUTINE (
    IN PVOID Buffer,
    IN ULONG Length
    );
typedef KBUGCHECK_CALLBACK_ROUTINE *PKBUGCHECK_CALLBACK_ROUTINE;

typedef struct _KBUGCHECK_CALLBACK_RECORD {
    LIST_ENTRY Entry;
    PKBUGCHECK_CALLBACK_ROUTINE CallbackRoutine;
    __field_bcount_opt(Length) PVOID Buffer;
    ULONG Length;
    PUCHAR Component;
    ULONG_PTR Checksum;
    UCHAR State;
} KBUGCHECK_CALLBACK_RECORD, *PKBUGCHECK_CALLBACK_RECORD;

#define KeInitializeCallbackRecord(CallbackRecord) \
    (CallbackRecord)->State = BufferEmpty

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn
NTKERNELAPI
BOOLEAN
KeDeregisterBugCheckCallback (
    __inout PKBUGCHECK_CALLBACK_RECORD CallbackRecord
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn
NTKERNELAPI
BOOLEAN
KeRegisterBugCheckCallback (
    __out PKBUGCHECK_CALLBACK_RECORD CallbackRecord,
    __in PKBUGCHECK_CALLBACK_ROUTINE CallbackRoutine,
    __in_bcount_opt(Length) PVOID Buffer,
    __in ULONG Length,
    __in PUCHAR Component
    );
#endif

typedef enum _KBUGCHECK_CALLBACK_REASON {
    KbCallbackInvalid,
    KbCallbackReserved1,
    KbCallbackSecondaryDumpData,
    KbCallbackDumpIo,
    KbCallbackAddPages
} KBUGCHECK_CALLBACK_REASON;

typedef
__drv_functionClass(KBUGCHECK_REASON_CALLBACK_ROUTINE)
__drv_sameIRQL
VOID
KBUGCHECK_REASON_CALLBACK_ROUTINE (
    __in KBUGCHECK_CALLBACK_REASON Reason,
    __in struct _KBUGCHECK_REASON_CALLBACK_RECORD* Record,
    __inout PVOID ReasonSpecificData,
    __in ULONG ReasonSpecificDataLength
    );
typedef KBUGCHECK_REASON_CALLBACK_ROUTINE *PKBUGCHECK_REASON_CALLBACK_ROUTINE;

typedef struct _KBUGCHECK_REASON_CALLBACK_RECORD {
    LIST_ENTRY Entry;
    PKBUGCHECK_REASON_CALLBACK_ROUTINE CallbackRoutine;
    PUCHAR Component;
    ULONG_PTR Checksum;
    KBUGCHECK_CALLBACK_REASON Reason;
    UCHAR State;
} KBUGCHECK_REASON_CALLBACK_RECORD, *PKBUGCHECK_REASON_CALLBACK_RECORD;

typedef struct _KBUGCHECK_SECONDARY_DUMP_DATA {
    IN PVOID InBuffer;
    IN ULONG InBufferLength;
    IN ULONG MaximumAllowed;
    OUT GUID Guid;
    OUT PVOID OutBuffer;
    OUT ULONG OutBufferLength;
} KBUGCHECK_SECONDARY_DUMP_DATA, *PKBUGCHECK_SECONDARY_DUMP_DATA;

typedef enum _KBUGCHECK_DUMP_IO_TYPE {
    KbDumpIoInvalid,
    KbDumpIoHeader,
    KbDumpIoBody,
    KbDumpIoSecondaryData,
    KbDumpIoComplete
} KBUGCHECK_DUMP_IO_TYPE;

typedef struct _KBUGCHECK_DUMP_IO {
    IN ULONG64 Offset;
    IN PVOID Buffer;
    IN ULONG BufferLength;
    IN KBUGCHECK_DUMP_IO_TYPE Type;
} KBUGCHECK_DUMP_IO, *PKBUGCHECK_DUMP_IO;

#define KB_ADD_PAGES_FLAG_VIRTUAL_ADDRESS           0x00000001UL
#define KB_ADD_PAGES_FLAG_PHYSICAL_ADDRESS          0x00000002UL
#define KB_ADD_PAGES_FLAG_ADDITIONAL_RANGES_EXIST   0x80000000UL

typedef struct _KBUGCHECK_ADD_PAGES {
    __inout PVOID Context;      // Private context for callback use
    __inout ULONG Flags;        // Zero initialized on input
    __in ULONG BugCheckCode;
    __out ULONG_PTR Address;
    __out ULONG_PTR Count;
} KBUGCHECK_ADD_PAGES, *PKBUGCHECK_ADD_PAGES;

//
// Equates for exceptions which cause system fatal error
//

#define EXCEPTION_DIVIDED_BY_ZERO       0
#define EXCEPTION_DEBUG                 1
#define EXCEPTION_NMI                   2
#define EXCEPTION_INT3                  3
#define EXCEPTION_BOUND_CHECK           5
#define EXCEPTION_INVALID_OPCODE        6
#define EXCEPTION_NPX_NOT_AVAILABLE     7
#define EXCEPTION_DOUBLE_FAULT          8
#define EXCEPTION_NPX_OVERRUN           9
#define EXCEPTION_INVALID_TSS           0x0A
#define EXCEPTION_SEGMENT_NOT_PRESENT   0x0B
#define EXCEPTION_STACK_FAULT           0x0C
#define EXCEPTION_GP_FAULT              0x0D
#define EXCEPTION_RESERVED_TRAP         0x0F
#define EXCEPTION_NPX_ERROR             0x010
#define EXCEPTION_ALIGNMENT_CHECK       0x011

#if (NTDDI_VERSION >= NTDDI_WINXPSP1)
__checkReturn
NTKERNELAPI
BOOLEAN
KeDeregisterBugCheckReasonCallback (
    __inout PKBUGCHECK_REASON_CALLBACK_RECORD CallbackRecord
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXPSP1)
__checkReturn
NTKERNELAPI
BOOLEAN
KeRegisterBugCheckReasonCallback (
    __out PKBUGCHECK_REASON_CALLBACK_RECORD CallbackRecord,
    __in PKBUGCHECK_REASON_CALLBACK_ROUTINE CallbackRoutine,
    __in KBUGCHECK_CALLBACK_REASON Reason,
    __in PUCHAR Component
    );
#endif

typedef
__drv_functionClass(NMI_CALLBACK)
__drv_sameIRQL
BOOLEAN
NMI_CALLBACK(
    __in_opt PVOID Context,
    __in BOOLEAN Handled
    );
typedef NMI_CALLBACK *PNMI_CALLBACK;

#if (NTDDI_VERSION >= NTDDI_WS03)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
PVOID
KeRegisterNmiCallback (
    __in PNMI_CALLBACK CallbackRoutine,
    __in_opt PVOID Context
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WS03)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
NTSTATUS
KeDeregisterNmiCallback (
    __in PVOID Handle
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_preferredFunction("error logging or driver shutdown",
    "Whenever possible, all kernel-mode components should log an error and "
    "continue to run, rather than calling KeBugCheckEx")
NTKERNELAPI
DECLSPEC_NORETURN
VOID
NTAPI
KeBugCheckEx(
    __in ULONG BugCheckCode,
    __in ULONG_PTR BugCheckParameter1,
    __in ULONG_PTR BugCheckParameter2,
    __in ULONG_PTR BugCheckParameter3,
    __in ULONG_PTR BugCheckParameter4
    );
#endif

#if !defined(_AMD64_)

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
ULONGLONG
KeQueryInterruptTime (
    VOID
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
KeQuerySystemTime (
    __out PLARGE_INTEGER CurrentTime
    );
#endif

#endif // !_AMD64_

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
ULONG
KeQueryTimeIncrement (
    VOID
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
NTKERNELAPI
ULONGLONG
KeQueryUnbiasedInterruptTime (
    VOID
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
NTKERNELAPI
ULONG
KeGetRecommendedSharedDataAlignment (
    VOID
    );
#endif



#if (NTDDI_VERSION >= NTDDI_WIN2K) && defined(SINGLE_GROUP_LEGACY_API)
NTKERNELAPI
KAFFINITY
KeQueryActiveProcessors (
    VOID
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA) && defined(SINGLE_GROUP_LEGACY_API)
NTKERNELAPI
ULONG
KeQueryActiveProcessorCount (
    __out_opt PKAFFINITY ActiveProcessors
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
NTKERNELAPI
ULONG
KeQueryActiveProcessorCountEx (
    __in USHORT GroupNumber
    );
#endif

#if (NTDDI_VERSION >= NTDDI_LONGHORN) && defined(SINGLE_GROUP_LEGACY_API)
NTKERNELAPI
ULONG
KeQueryMaximumProcessorCount (
    VOID
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
NTKERNELAPI
ULONG
KeQueryMaximumProcessorCountEx (
    __in USHORT GroupNumber
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
NTKERNELAPI
USHORT
KeQueryActiveGroupCount (
    VOID
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
NTKERNELAPI
USHORT
KeQueryMaximumGroupCount (
    VOID
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
NTKERNELAPI
KAFFINITY
KeQueryGroupAffinity (
    __in USHORT GroupNumber
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
NTKERNELAPI
ULONG
KeGetCurrentProcessorNumberEx (
    __out_opt PPROCESSOR_NUMBER ProcNumber
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
NTKERNELAPI
VOID
KeQueryNodeActiveAffinity (
    __in USHORT NodeNumber,
    __out_opt PGROUP_AFFINITY Affinity,
    __out_opt PUSHORT Count
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
NTKERNELAPI
USHORT
KeQueryNodeMaximumProcessorCount (
    __in USHORT NodeNumber
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
NTKERNELAPI
USHORT
KeQueryHighestNodeNumber (
    VOID
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
NTKERNELAPI
USHORT
KeGetCurrentNodeNumber (
    VOID
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
NTSTATUS
KeQueryLogicalProcessorRelationship (
    __in_opt PPROCESSOR_NUMBER ProcessorNumber,
    __in LOGICAL_PROCESSOR_RELATIONSHIP RelationshipType,
    __out_bcount_opt(*Length) PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX Information,
    __inout PULONG Length
    );
#endif


#if defined(_IA64_)

extern volatile LARGE_INTEGER KeTickCount;

#elif defined(_X86_)

extern volatile KSYSTEM_TIME KeTickCount;

#endif



typedef enum _MEMORY_CACHING_TYPE_ORIG {
    MmFrameBufferCached = 2
} MEMORY_CACHING_TYPE_ORIG;

typedef enum _MEMORY_CACHING_TYPE {
    MmNonCached = FALSE,
    MmCached = TRUE,
    MmWriteCombined = MmFrameBufferCached,
    MmHardwareCoherentCached,
    MmNonCachedUnordered,       // IA64
    MmUSWCCached,
    MmMaximumCacheType
} MEMORY_CACHING_TYPE;



#define GM_LOCK_BIT          0x1 // Actual lock bit, 0 = Unlocked, 1 = Locked
#define GM_LOCK_BIT_V        0x0 // Lock bit as a bit number
#define GM_LOCK_WAITER_WOKEN 0x2 // A single waiter has been woken to acquire this lock
#define GM_LOCK_WAITER_INC   0x4 // Increment value to change the waiters count

typedef struct _KGUARDED_MUTEX {
    volatile LONG Count;
    PKTHREAD Owner;
    ULONG Contention;
    KGATE Gate;
    union {
        struct {
            SHORT KernelApcDisable;
            SHORT SpecialApcDisable;
        };

        ULONG CombinedApcDisable;
    };

} KGUARDED_MUTEX, *PKGUARDED_MUTEX;


#if (NTDDI_VERSION >= NTDDI_WS03SP1)
__drv_maxIRQL(APC_LEVEL)
__drv_minIRQL(PASSIVE_LEVEL)
NTKERNELAPI
BOOLEAN
KeAreAllApcsDisabled (
    VOID
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
__drv_maxIRQL(APC_LEVEL)
__drv_minIRQL(PASSIVE_LEVEL)
NTKERNELAPI
VOID
FASTCALL
KeInitializeGuardedMutex (
    __out PKGUARDED_MUTEX Mutex
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
__drv_neverHoldCriticalRegion
__drv_acquiresCriticalRegion
__drv_maxIRQL(APC_LEVEL)
__drv_minIRQL(PASSIVE_LEVEL)
NTKERNELAPI
VOID
FASTCALL
KeAcquireGuardedMutex (
    __inout __deref __drv_neverHold(GuardedMutex) __deref __drv_acquiresResource(GuardedMutex)
    PKGUARDED_MUTEX Mutex
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
__drv_mustHoldCriticalRegion
__drv_releasesCriticalRegion
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
FASTCALL
KeReleaseGuardedMutex (
    __inout __deref __drv_releasesExclusiveResource(GuardedMutex)
    PKGUARDED_MUTEX Mutex
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
__checkReturn
__drv_maxIRQL(APC_LEVEL)
__drv_valueIs(==1;==0)
NTKERNELAPI
BOOLEAN
FASTCALL
KeTryToAcquireGuardedMutex (
    __inout __deref __drv_neverHold(GuardedMutex)
    __deref __drv_when(return==1, __drv_acquiresResource(GuardedMutex))
    PKGUARDED_MUTEX Mutex
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
__drv_maxIRQL(APC_LEVEL)
__drv_minIRQL(PASSIVE_LEVEL)
NTKERNELAPI
VOID
FASTCALL
KeAcquireGuardedMutexUnsafe (
    __inout __deref __drv_neverHold(KeFastMutex) __deref __drv_acquiresResource(KeFastMutex)
    PKGUARDED_MUTEX FastMutex
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
FASTCALL
KeReleaseGuardedMutexUnsafe (
    __inout __deref __drv_releasesExclusiveResource(KeFastMutex)
    __inout PKGUARDED_MUTEX FastMutex
    );
#endif


//
// Define dynamic processor add types.
//

typedef enum {
    KeProcessorAddStartNotify = 0,
    KeProcessorAddCompleteNotify,
    KeProcessorAddFailureNotify
} KE_PROCESSOR_CHANGE_NOTIFY_STATE;

typedef struct _KE_PROCESSOR_CHANGE_NOTIFY_CONTEXT {
    KE_PROCESSOR_CHANGE_NOTIFY_STATE State;
    ULONG NtNumber;
    NTSTATUS Status;

#if (NTDDI_VERSION >= NTDDI_WIN7)

    PROCESSOR_NUMBER ProcNumber;

#endif


} KE_PROCESSOR_CHANGE_NOTIFY_CONTEXT, *PKE_PROCESSOR_CHANGE_NOTIFY_CONTEXT;

typedef
__drv_sameIRQL
__drv_functionClass(PROCESSOR_CALLBACK_FUNCTION)
VOID
PROCESSOR_CALLBACK_FUNCTION (
    __in PVOID CallbackContext,
    __in PKE_PROCESSOR_CHANGE_NOTIFY_CONTEXT ChangeContext,
    __inout PNTSTATUS OperationStatus
    );

typedef PROCESSOR_CALLBACK_FUNCTION *PPROCESSOR_CALLBACK_FUNCTION;

#define KE_PROCESSOR_CHANGE_ADD_EXISTING 1

#if (NTDDI_VERSION >= NTDDI_WS08)
__drv_maxIRQL(APC_LEVEL)
PVOID
KeRegisterProcessorChangeCallback (
    __in PPROCESSOR_CALLBACK_FUNCTION CallbackFunction,
    __in_opt PVOID CallbackContext,
    __in ULONG Flags
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WS08)
__drv_maxIRQL(APC_LEVEL)
VOID
KeDeregisterProcessorChangeCallback (
    __in PVOID CallbackHandle
    );
#endif


#define INVALID_PROCESSOR_INDEX     0xffffffff

NTSTATUS
KeGetProcessorNumberFromIndex (
    __in ULONG ProcIndex,
    __out PPROCESSOR_NUMBER ProcNumber
    );

ULONG
KeGetProcessorIndexFromNumber (
    __in PPROCESSOR_NUMBER ProcNumber
    );


typedef struct _XSTATE_SAVE {

#if defined(_AMD64_)

    struct _XSTATE_SAVE* Prev;
    struct _KTHREAD* Thread;
    UCHAR Level;
    XSTATE_CONTEXT XStateContext;

#elif defined(_IA64_)

    ULONG Dummy;

#elif defined(_X86_)

    union {
        struct {
            LONG64 Reserved1;
            ULONG Reserved2;

            struct _XSTATE_SAVE* Prev;

            PXSAVE_AREA Reserved3;

            struct _KTHREAD* Thread;

            PVOID Reserved4;

            UCHAR Level;
        };

        XSTATE_CONTEXT XStateContext;
    };

#endif
} XSTATE_SAVE, *PXSTATE_SAVE;

#if (NTDDI_VERSION >= NTDDI_WIN7)
__checkReturn
__drv_maxIRQL(DISPATCH_LEVEL)
__drv_valueIs(<0;==0)
__drv_when(return==0, __drv_floatSaved)
NTKERNELAPI
NTSTATUS
NTAPI
KeSaveExtendedProcessorState (
    __in ULONG64 Mask,
    __out __deref __drv_neverHold(XStateSave)
    __drv_when(return==0, __deref __drv_acquiresResource(XStateSave))
    PXSTATE_SAVE XStateSave
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
__drv_floatRestored
NTKERNELAPI
VOID
NTAPI
KeRestoreExtendedProcessorState (
    __in __deref __drv_releasesExclusiveResource(XStateSave)
    PXSTATE_SAVE XStateSave
    );
#endif

//
// Define external data.
//

#if defined(_NTDDK_) || defined(_NTIFS_) || defined(_NTHAL_) || defined(_WDMDDK_) || defined(_NTOSP_)

extern PBOOLEAN KdDebuggerNotPresent;
extern PBOOLEAN KdDebuggerEnabled;
#define KD_DEBUGGER_ENABLED     *KdDebuggerEnabled
#define KD_DEBUGGER_NOT_PRESENT *KdDebuggerNotPresent

#else

extern BOOLEAN KdDebuggerNotPresent;
extern BOOLEAN KdDebuggerEnabled;
#define KD_DEBUGGER_ENABLED     KdDebuggerEnabled
#define KD_DEBUGGER_NOT_PRESENT KdDebuggerNotPresent

#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
KdDisableDebugger(
    VOID
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
KdEnableDebugger(
    VOID
    );
#endif

//
// KdRefreshDebuggerPresent attempts to communicate with
// the debugger host machine to refresh the state of
// KdDebuggerNotPresent.  It returns the state of
// KdDebuggerNotPresent while the kd locks are held.
// KdDebuggerNotPresent may immediately change state
// after the kd locks are released so it may not
// match the return value.
//

#if (NTDDI_VERSION >= NTDDI_WS03)
NTKERNELAPI
BOOLEAN
KdRefreshDebuggerNotPresent(
    VOID
    );
#endif

typedef enum _KD_OPTION {
    KD_OPTION_SET_BLOCK_ENABLE,
} KD_OPTION;

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
NTSTATUS
KdChangeOption(
    __in KD_OPTION Option,
    __in ULONG InBufferBytes OPTIONAL,
    __in PVOID InBuffer,
    __in ULONG OutBufferBytes OPTIONAL,
    __out PVOID OutBuffer,
    __out PULONG OutBufferNeeded OPTIONAL
    );
#endif


//
// Pool Allocation routines (in pool.c)
//

typedef enum _POOL_TYPE {
    NonPagedPool,
    PagedPool,
    NonPagedPoolMustSucceed,
    DontUseThisType,
    NonPagedPoolCacheAligned,
    PagedPoolCacheAligned,
    NonPagedPoolCacheAlignedMustS,
    MaxPoolType,

    //
    // Note these per session types are carefully chosen so that the appropriate
    // masking still applies as well as MaxPoolType above.
    //

    NonPagedPoolSession = 32,
    PagedPoolSession = NonPagedPoolSession + 1,
    NonPagedPoolMustSucceedSession = PagedPoolSession + 1,
    DontUseThisTypeSession = NonPagedPoolMustSucceedSession + 1,
    NonPagedPoolCacheAlignedSession = DontUseThisTypeSession + 1,
    PagedPoolCacheAlignedSession = NonPagedPoolCacheAlignedSession + 1,
    NonPagedPoolCacheAlignedMustSSession = PagedPoolCacheAlignedSession + 1,
} POOL_TYPE;

#define POOL_COLD_ALLOCATION 256     // Note this cannot encode into the header.


#define POOL_QUOTA_FAIL_INSTEAD_OF_RAISE 8
#define POOL_RAISE_IF_ALLOCATION_FAILURE 16

#if (NTDDI_VERSION >= NTDDI_WIN2K)

DECLSPEC_DEPRECATED_DDK                     // Use ExAllocatePoolWithTag
__drv_preferredFunction("ExAllocatePoolWithTag",
    "No tag interferes with debugging.")
__drv_allocatesMem(Mem)
__drv_when(((PoolType&0x1))!=0, __drv_maxIRQL(APC_LEVEL))
__drv_when(((PoolType&0x1))==0, __drv_maxIRQL(DISPATCH_LEVEL))
__drv_when(((PoolType&0x2))!=0,
    __drv_reportError("Must succeed pool allocations are forbidden. "
	"Allocation failures cause a system crash"))
__drv_when(((PoolType&(0x2|POOL_RAISE_IF_ALLOCATION_FAILURE)))==0,
    __post __maybenull __checkReturn)
__drv_when(((PoolType&(0x2|POOL_RAISE_IF_ALLOCATION_FAILURE)))!=0,
    __post __notnull)
__bcount(NumberOfBytes)
NTKERNELAPI
PVOID
ExAllocatePool(
    __drv_strictTypeMatch(__drv_typeExpr) __in POOL_TYPE PoolType,
    __in SIZE_T NumberOfBytes
    );

#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)

DECLSPEC_DEPRECATED_DDK                     // Use ExAllocatePoolWithQuotaTag
__drv_preferredFunction("ExAllocatePoolWithQuotaTag",
    "No tag interferes with debugging.")
__drv_allocatesMem(Mem)
__drv_when(((PoolType&0x1))!=0, __drv_maxIRQL(APC_LEVEL))
__drv_when(((PoolType&0x1))==0, __drv_maxIRQL(DISPATCH_LEVEL))
__drv_when(((PoolType&0x2))!=0,
    __drv_reportError("Must succeed pool allocations are forbidden. "
	"Allocation failures cause a system crash"))
__drv_when(((PoolType&POOL_QUOTA_FAIL_INSTEAD_OF_RAISE))!=0,
    __post __maybenull __checkReturn)
__drv_when(((PoolType&POOL_QUOTA_FAIL_INSTEAD_OF_RAISE))==0,
    __post __notnull)
__bcount(NumberOfBytes)
NTKERNELAPI
PVOID
ExAllocatePoolWithQuota(
    __drv_strictTypeMatch(__drv_typeExpr) __in POOL_TYPE PoolType,
    __in SIZE_T NumberOfBytes
    );

#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)

__drv_allocatesMem(Mem)
__drv_when(((PoolType&0x1))!=0, __drv_maxIRQL(APC_LEVEL))
__drv_when(((PoolType&0x1))==0, __drv_maxIRQL(DISPATCH_LEVEL))
__drv_when(((PoolType&0x2))!=0,
    __drv_reportError("Must succeed pool allocations are forbidden. "
	"Allocation failures cause a system crash"))
__drv_when(((PoolType&(0x2|POOL_RAISE_IF_ALLOCATION_FAILURE)))==0,
    __post __maybenull __checkReturn)
__drv_when(((PoolType&(0x2|POOL_RAISE_IF_ALLOCATION_FAILURE)))!=0,
    __post __notnull)
__bcount(NumberOfBytes)
NTKERNELAPI
PVOID
NTAPI
ExAllocatePoolWithTag(
    __in __drv_strictTypeMatch(__drv_typeExpr) POOL_TYPE PoolType,
    __in SIZE_T NumberOfBytes,
    __in ULONG Tag
    );

#endif

//
// _EX_POOL_PRIORITY_ provides a method for the system to handle requests
// intelligently in low resource conditions.
//
// LowPoolPriority should be used when it is acceptable to the driver for the
// mapping request to fail if the system is low on resources.  An example of
// this could be for a non-critical network connection where the driver can
// handle the failure case when system resources are close to being depleted.
//
// NormalPoolPriority should be used when it is acceptable to the driver for the
// mapping request to fail if the system is very low on resources.  An example
// of this could be for a non-critical local filesystem request.
//
// HighPoolPriority should be used when it is unacceptable to the driver for the
// mapping request to fail unless the system is completely out of resources.
// An example of this would be the paging file path in a driver.
//
// SpecialPool can be specified to bound the allocation at a page end (or
// beginning).  This should only be done on systems being debugged as the
// memory cost is expensive.
//
// N.B.  These values are very carefully chosen so that the pool allocation
//       code can quickly crack the priority request.
//

typedef enum _EX_POOL_PRIORITY {
    LowPoolPriority,
    LowPoolPrioritySpecialPoolOverrun = 8,
    LowPoolPrioritySpecialPoolUnderrun = 9,
    NormalPoolPriority = 16,
    NormalPoolPrioritySpecialPoolOverrun = 24,
    NormalPoolPrioritySpecialPoolUnderrun = 25,
    HighPoolPriority = 32,
    HighPoolPrioritySpecialPoolOverrun = 40,
    HighPoolPrioritySpecialPoolUnderrun = 41
} EX_POOL_PRIORITY;

#if (NTDDI_VERSION >= NTDDI_WIN2K)

__drv_allocatesMem(Mem)
__drv_when(((PoolType&0x1))!=0, __drv_maxIRQL(APC_LEVEL))
__drv_when(((PoolType&0x1))==0, __drv_maxIRQL(DISPATCH_LEVEL))
__drv_when(((PoolType&0x2))!=0,
    __drv_reportError("Must succeed pool allocations are forbidden. "
	"Allocation failures cause a system crash"))
__drv_when(((PoolType&(0x2|POOL_RAISE_IF_ALLOCATION_FAILURE)))==0,
    __post __maybenull __checkReturn)
__drv_when(((PoolType&(0x2|POOL_RAISE_IF_ALLOCATION_FAILURE)))!=0,
    __post __notnull)
__bcount(NumberOfBytes)
NTKERNELAPI
PVOID
NTAPI
ExAllocatePoolWithTagPriority(
    __in __drv_strictTypeMatch(__drv_typeCond) POOL_TYPE PoolType,
    __in SIZE_T NumberOfBytes,
    __in ULONG Tag,
    __in __drv_strictTypeMatch(__drv_typeExpr) EX_POOL_PRIORITY Priority
    );

#endif

#ifndef POOL_TAGGING
#define ExAllocatePoolWithTag(a,b,c) ExAllocatePool(a,b)
#endif //POOL_TAGGING

#if (NTDDI_VERSION >= NTDDI_WIN2K)

__drv_allocatesMem(Mem)
__drv_when(((PoolType&0x1))!=0, __drv_maxIRQL(APC_LEVEL))
__drv_when(((PoolType&0x1))==0, __drv_maxIRQL(DISPATCH_LEVEL))
__drv_when(((PoolType&0x2))!=0,
    __drv_reportError("Must succeed pool allocations are forbidden. "
	"Allocation failures cause a system crash"))
__drv_when(((PoolType&POOL_QUOTA_FAIL_INSTEAD_OF_RAISE))!=0,
    __post __maybenull __checkReturn)
__drv_when(((PoolType&POOL_QUOTA_FAIL_INSTEAD_OF_RAISE))==0,
    __post __notnull)
__bcount(NumberOfBytes)
NTKERNELAPI
PVOID
ExAllocatePoolWithQuotaTag(
    __in __drv_strictTypeMatch(__drv_typeExpr) POOL_TYPE PoolType,
    __in SIZE_T NumberOfBytes,
    __in ULONG Tag
    );

#endif

#ifndef POOL_TAGGING
#define ExAllocatePoolWithQuotaTag(a,b,c) ExAllocatePoolWithQuota(a,b)
#endif //POOL_TAGGING

#if (NTDDI_VERSION >= NTDDI_WIN2K)

__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
VOID
NTAPI
ExFreePool(
    __in __drv_freesMem(Mem) PVOID P
    );

#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)

__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
VOID
ExFreePoolWithTag(
    __in __drv_freesMem(Mem) PVOID P,
    __in ULONG Tag
    );

#endif


//
// Routines to support fast mutexes.
//

typedef struct _FAST_MUTEX {

#define FM_LOCK_BIT          0x1 // Actual lock bit, 1 = Unlocked, 0 = Locked
#define FM_LOCK_BIT_V        0x0 // Lock bit as a bit number
#define FM_LOCK_WAITER_WOKEN 0x2 // A single waiter has been woken to acquire this lock
#define FM_LOCK_WAITER_INC   0x4 // Increment value to change the waiters count

    volatile LONG Count;
    PKTHREAD Owner;
    ULONG Contention;
    KEVENT Event;
    ULONG OldIrql;
} FAST_MUTEX, *PFAST_MUTEX;

FORCEINLINE
VOID
ExInitializeFastMutex(
    __out PFAST_MUTEX FastMutex
    )

/*++

Routine Description:

    This function initializes a fast mutex object.

Arguments:

    FastMutex - Supplies a pointer to a fast mutex object.

Return Value:

    None.

--*/

{

    FastMutex->Count = FM_LOCK_BIT;
    FastMutex->Owner = NULL;
    FastMutex->Contention = 0;
    KeInitializeEvent(&FastMutex->Event, SynchronizationEvent, FALSE);
    return;
}

#if (NTDDI_VERSION >= NTDDI_WIN2K)

__drv_maxIRQL(APC_LEVEL)
__drv_mustHoldCriticalRegion
NTKERNELAPI
VOID
FASTCALL
ExAcquireFastMutexUnsafe(
    __inout __deref __drv_acquiresExclusiveResource(FastMutexType)
    PFAST_MUTEX FastMutex
    );

#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)

__drv_maxIRQL(APC_LEVEL)
__drv_mustHoldCriticalRegion
NTKERNELAPI
VOID
FASTCALL
ExReleaseFastMutexUnsafe(
    __inout __deref __drv_releasesExclusiveResource(FastMutexType)
    PFAST_MUTEX FastMutex
    );

#endif


#if defined(_NTHAL_) && defined(_X86_)

__drv_raisesIRQL(APC_LEVEL)
__drv_savesIRQLGlobal(OldIrql, FastMutex)
NTKERNELAPI
VOID
FASTCALL
ExiAcquireFastMutex(
    __inout __deref __drv_acquiresExclusiveResource(FastMutexType)
    PFAST_MUTEX FastMutex
    );

__drv_requiresIRQL(APC_LEVEL)
__drv_restoresIRQLGlobal(OldIrql, FastMutex)
NTKERNELAPI
VOID
FASTCALL
ExiReleaseFastMutex(
    __inout __deref __drv_releasesExclusiveResource(FastMutexType)
    __inout PFAST_MUTEX FastMutex
    );

__checkReturn
__success(return!=FALSE)
__drv_raisesIRQL(APC_LEVEL)
__drv_savesIRQLGlobal(OldIrql, FastMutex)
NTKERNELAPI
BOOLEAN
FASTCALL
ExiTryToAcquireFastMutex(
    __inout __deref __drv_acquiresExclusiveResource(FastMutexType)
    PFAST_MUTEX FastMutex
    );

#define ExAcquireFastMutex(FastMutex) ExiAcquireFastMutex(FastMutex)
#define ExReleaseFastMutex(FastMutex) ExiReleaseFastMutex(FastMutex)
#define ExTryToAcquireFastMutex(FastMutex) ExiTryToAcquireFastMutex(FastMutex)

#else

#if (NTDDI_VERSION >= NTDDI_WIN2K)

__drv_raisesIRQL(APC_LEVEL)
__drv_savesIRQLGlobal(OldIrql, FastMutex)
NTKERNELAPI
VOID
FASTCALL
ExAcquireFastMutex (
    __inout __deref __drv_acquiresExclusiveResource(FastMutexType)
    PFAST_MUTEX FastMutex
    );

#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)

__drv_requiresIRQL(APC_LEVEL)
__drv_restoresIRQLGlobal(OldIrql, FastMutex)
NTKERNELAPI
VOID
FASTCALL
ExReleaseFastMutex (
    __inout __deref __drv_releasesExclusiveResource(FastMutexType)
    PFAST_MUTEX FastMutex
    );

#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)

__checkReturn
__success(return!=FALSE)
__drv_raisesIRQL(APC_LEVEL)
__drv_savesIRQLGlobal(OldIrql, FastMutex)
NTKERNELAPI
BOOLEAN
FASTCALL
ExTryToAcquireFastMutex (
    __inout __deref __drv_acquiresExclusiveResource(FastMutexType)
    PFAST_MUTEX FastMutex
    );

#endif

#endif // _NTHAL_ && _X86_


//

#if defined(_WIN64)

#define ExInterlockedAddLargeStatistic(Addend, Increment) \
    (VOID)InterlockedAdd64(&(Addend)->QuadPart, Increment)

#else

#ifdef __cplusplus
extern "C" {
#endif

LONG
__cdecl
_InterlockedAddLargeStatistic (
    __inout LONGLONG volatile *Addend,
    __in ULONG Increment
    );

#ifdef __cplusplus
}
#endif

#pragma intrinsic(_InterlockedAddLargeStatistic)

#define ExInterlockedAddLargeStatistic(Addend, Increment) \
    (VOID)_InterlockedAddLargeStatistic((PLONGLONG)&(Addend)->QuadPart, Increment)

#endif // defined(_WIN64)



#if (NTDDI_VERSION >= NTDDI_WIN2K)

NTKERNELAPI
LARGE_INTEGER
ExInterlockedAddLargeInteger (
    __inout PLARGE_INTEGER Addend,
    __in LARGE_INTEGER Increment,
    __inout __deref __drv_neverHold(KeSpinLockType) PKSPIN_LOCK Lock
    );

#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)

NTKERNELAPI
ULONG
FASTCALL
ExInterlockedAddUlong (
    __inout PULONG Addend,
    __in ULONG Increment,
    __inout __deref __drv_neverHold(KeSpinLockType) PKSPIN_LOCK Lock
    );

#endif // NTDDI_VERSION >= NTDDI_WIN2K


#if defined(_AMD64_) || defined(_IA64_)

#define ExInterlockedCompareExchange64(Destination, Exchange, Comperand, Lock) \
    InterlockedCompareExchange64(Destination, *(Exchange), *(Comperand))

#else

#define ExInterlockedCompareExchange64(Destination, Exchange, Comperand, Lock) \
    ExfInterlockedCompareExchange64(Destination, Exchange, Comperand)

#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)

NTKERNELAPI
PLIST_ENTRY
FASTCALL
ExInterlockedInsertHeadList (
    __inout PLIST_ENTRY ListHead,
    __inout __drv_aliasesMem PLIST_ENTRY ListEntry,
    __inout __deref __drv_neverHold(KeSpinLockType) PKSPIN_LOCK Lock
    );

#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)

NTKERNELAPI
PLIST_ENTRY
FASTCALL
ExInterlockedInsertTailList (
    __inout PLIST_ENTRY ListHead,
    __inout __drv_aliasesMem PLIST_ENTRY ListEntry,
    __inout __deref __drv_neverHold(KeSpinLockType) PKSPIN_LOCK Lock
    );

#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)

NTKERNELAPI
PLIST_ENTRY
FASTCALL
ExInterlockedRemoveHeadList (
    __inout PLIST_ENTRY ListHead,
    __inout __deref __drv_neverHold(KeSpinLockType) PKSPIN_LOCK Lock
    );

#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)

NTKERNELAPI
PSINGLE_LIST_ENTRY
FASTCALL
ExInterlockedPopEntryList (
    __inout PSINGLE_LIST_ENTRY ListHead,
    __inout __deref __drv_neverHold(KeSpinLockType) PKSPIN_LOCK Lock
    );

#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)

NTKERNELAPI
PSINGLE_LIST_ENTRY
FASTCALL
ExInterlockedPushEntryList (
    __inout PSINGLE_LIST_ENTRY ListHead,
    __inout __drv_aliasesMem PSINGLE_LIST_ENTRY ListEntry,
    __inout __deref __drv_neverHold(KeSpinLockType) PKSPIN_LOCK Lock
    );

#endif


//
// Define interlocked sequenced listhead functions.
//
// A sequenced interlocked list is a singly linked list with a header that
// contains the current depth and a sequence number. Each time an entry is
// inserted or removed from the list the depth is updated and the sequence
// number is incremented. This enables AMD64, IA64, and Pentium and later
// machines to insert and remove from the list without the use of spinlocks.
//

#if !defined(_WINBASE_)

#if defined(_WIN64) && (defined(_NTDRIVER_) || defined(_NTDDK_) || defined(_NTIFS_) || defined(_NTHAL_) || defined(_NTOSP_))

NTKERNELAPI
VOID
InitializeSListHead (
    __out PSLIST_HEADER SListHead
    );

#else

//
// Since the following function will be compiled inline for user code, the
// initialization changes for IA64 will only take effect if the user code
// is recompiled with this new header. For those binaries that are recompiled
// with this new code, it will not have to go through an extra step of header
// initialization on its first push or pop operation. Note that the SLIST code
// will still work perfectly even without the changes in this initialization
// function.
//

__inline
VOID
InitializeSListHead (
    __out PSLIST_HEADER SListHead
    )

/*++

Routine Description:

    This function initializes a sequenced singly linked listhead.

Arguments:

    SListHead - Supplies a pointer to a sequenced singly linked listhead.

Return Value:

    None.

--*/

{

#if defined(_IA64_)

    ULONG64 FeatureBits;

#endif

    //
    // Slist headers must be 16 byte aligned.
    //

#if defined(_WIN64)

    if (((ULONG_PTR)SListHead & 0xf) != 0) {
        RtlRaiseStatus(STATUS_DATATYPE_MISALIGNMENT);
    }

#endif

    RtlZeroMemory(SListHead, sizeof(SLIST_HEADER));

    //
    // Check feature bits to determine if 16-byte atomic operations are
    // supported.
    //

#if defined(_IA64_)

    FeatureBits = __getReg(CV_IA64_CPUID4);
    if ((FeatureBits & KF_16BYTE_INSTR) != 0) {

        //
        // Initialize 16-byte header.
        //
        // NB: For the 8-byte header, all elements in the list must reside in
        // the same Region, but not necessarily the same as the Header. At this
        // point there is no information to where will the items reside, so
        // defer the actual initialization of 8-byte header to the first Push
        // operation.
        //

        SListHead->Header16.HeaderType = 1;
        SListHead->Header16.Init = 1;
    }

#endif

    return;
}

#endif

#endif // !defined(_WINBASE_)

#define ExInitializeSListHead InitializeSListHead

PSLIST_ENTRY
FirstEntrySList (
    __in PSLIST_HEADER SListHead
    );

#if defined(_WIN64)

#if (defined(_NTDRIVER_) || defined(_NTDDK_) || defined(_NTIFS_) || defined(_NTHAL_) || defined(_NTOSP_))

NTKERNELAPI
USHORT
ExQueryDepthSList (
    __in PSLIST_HEADER SListHead
    );

#else

__inline
USHORT
ExQueryDepthSList (
    __in PSLIST_HEADER SListHead
    )

/*++

Routine Description:

    This function queries the current number of entries contained in a
    sequenced single linked list.

Arguments:

    SListHead - Supplies a pointer to the sequenced listhead which is
        be queried.

Return Value:

    The current number of entries in the sequenced singly linked list is
    returned as the function value.

--*/

{

    return (USHORT)(SListHead->Alignment & 0xffff);
}

#endif

#else

#define ExQueryDepthSList(_listhead_) (_listhead_)->Depth

#endif

#if defined(_WIN64)

#define ExInterlockedPopEntrySList(Head, Lock) \
    ExpInterlockedPopEntrySList(Head)

#define ExInterlockedPushEntrySList(Head, Entry, Lock) \
    ExpInterlockedPushEntrySList(Head, Entry)

#define ExInterlockedFlushSList(Head) \
    ExpInterlockedFlushSList(Head)

#if !defined(_WINBASE_)

#define InterlockedPopEntrySList(Head) \
    ExpInterlockedPopEntrySList(Head)

#define InterlockedPushEntrySList(Head, Entry) \
    ExpInterlockedPushEntrySList(Head, Entry)

#define InterlockedFlushSList(Head) \
    ExpInterlockedFlushSList(Head)

#define QueryDepthSList(Head) \
    ExQueryDepthSList(Head)

#endif // !defined(_WINBASE_)

NTKERNELAPI
PSLIST_ENTRY
ExpInterlockedPopEntrySList (
    __inout PSLIST_HEADER ListHead
    );

NTKERNELAPI
PSLIST_ENTRY
ExpInterlockedPushEntrySList (
    __inout PSLIST_HEADER ListHead,
    __inout __drv_aliasesMem PSLIST_ENTRY ListEntry
    );

NTKERNELAPI
PSLIST_ENTRY
ExpInterlockedFlushSList (
    __inout PSLIST_HEADER ListHead
    );

#else

#if defined(_WIN2K_COMPAT_SLIST_USAGE) && defined(_X86_)

NTKERNELAPI
PSLIST_ENTRY
FASTCALL
ExInterlockedPopEntrySList (
    __inout PSLIST_HEADER ListHead,
    __inout __deref __drv_neverHold(KeSpinLockType) PKSPIN_LOCK Lock
    );

NTKERNELAPI
PSLIST_ENTRY
FASTCALL
ExInterlockedPushEntrySList (
    __inout PSLIST_HEADER ListHead,
    __inout __drv_aliasesMem PSLIST_ENTRY ListEntry,
    __inout __deref __drv_neverHold(KeSpinLockType) PKSPIN_LOCK Lock
    );

#else

#define ExInterlockedPopEntrySList(ListHead, Lock) \
    InterlockedPopEntrySList(ListHead)

#define ExInterlockedPushEntrySList(ListHead, ListEntry, Lock) \
    InterlockedPushEntrySList(ListHead, ListEntry)

#endif

NTKERNELAPI
PSLIST_ENTRY
FASTCALL
ExInterlockedFlushSList (
    __inout PSLIST_HEADER ListHead
    );

#if !defined(_WINBASE_)

NTKERNELAPI
PSLIST_ENTRY
FASTCALL
InterlockedPopEntrySList (
    __inout PSLIST_HEADER ListHead
    );

NTKERNELAPI
PSLIST_ENTRY
FASTCALL
InterlockedPushEntrySList (
    __inout PSLIST_HEADER ListHead,
    __inout __drv_aliasesMem PSLIST_ENTRY ListEntry
    );

#define InterlockedFlushSList(Head) \
    ExInterlockedFlushSList(Head)

#define QueryDepthSList(Head) \
    ExQueryDepthSList(Head)

#endif // !defined(_WINBASE_)

#endif // defined(_WIN64)


#define LOOKASIDE_MINIMUM_BLOCK_SIZE  (RTL_SIZEOF_THROUGH_FIELD (SLIST_ENTRY, Next))

//
// N.B. Note that this structure is not cache aligned to enable its use
//  in a larger containing structure.
//

typedef struct _LOOKASIDE_LIST_EX {
    GENERAL_LOOKASIDE_POOL L;
} LOOKASIDE_LIST_EX, *PLOOKASIDE_LIST_EX;

#if (NTDDI_VERSION >= NTDDI_VISTA)

#define EX_LOOKASIDE_LIST_EX_FLAGS_RAISE_ON_FAIL    0x00000001UL
#define EX_LOOKASIDE_LIST_EX_FLAGS_FAIL_NO_RAISE    0x00000002UL

#define EX_MAXIMUM_LOOKASIDE_DEPTH_BASE     256     // Base maximum depth
#define EX_MAXIMUM_LOOKASIDE_DEPTH_LIMIT    1024    // Upper limit maximum depth

__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
NTSTATUS
ExInitializeLookasideListEx (
    __out PLOOKASIDE_LIST_EX Lookaside,
    __in_opt PALLOCATE_FUNCTION_EX Allocate,
    __in_opt PFREE_FUNCTION_EX Free,
    __in POOL_TYPE PoolType,
    __in ULONG Flags,
    __in SIZE_T Size,
    __in ULONG Tag,
    __in USHORT Depth
    );

__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
VOID
ExDeleteLookasideListEx (
    __inout PLOOKASIDE_LIST_EX Lookaside
    );

__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
VOID
ExFlushLookasideListEx (
    __inout PLOOKASIDE_LIST_EX Lookaside
    );

__checkReturn
__drv_maxIRQL(DISPATCH_LEVEL)
FORCEINLINE
PVOID
ExAllocateFromLookasideListEx (
    __inout PLOOKASIDE_LIST_EX Lookaside
    )

/*++

Routine Description:

    This function removes (pops) the first entry from the specified
    lookaside list.

Arguments:

    Lookaside - Supplies a pointer to a LOOKASIDE_LIST_EX structure.

Return Value:

    If an entry is removed from the specified lookaside list, then the
    address of the entry is returned as the function value. Otherwise,
    NULL is returned.

--*/

{

    PVOID Entry;

    Lookaside->L.TotalAllocates += 1;
    Entry = InterlockedPopEntrySList(&Lookaside->L.ListHead);
    if (Entry == NULL) {
        Lookaside->L.AllocateMisses += 1;
        Entry = (Lookaside->L.AllocateEx)(Lookaside->L.Type,
                                          Lookaside->L.Size,
                                          Lookaside->L.Tag,
                                          Lookaside);
    }

    return Entry;
}

__drv_maxIRQL(DISPATCH_LEVEL)
FORCEINLINE
VOID
ExFreeToLookasideListEx (
    __inout PLOOKASIDE_LIST_EX Lookaside,
    __in PVOID Entry
    )

/*++

Routine Description:

    This function inserts (pushes) the specified entry into the specified
    lookaside list.

Arguments:

    Lookaside - Supplies a pointer to a LOOKASIDE_LIST_EX structure.

    Entry - Supples a pointer to the entry that is inserted in the
        lookaside list.

Return Value:

    None.

--*/

{

    Lookaside->L.TotalFrees += 1;
    if (ExQueryDepthSList(&Lookaside->L.ListHead) >= Lookaside->L.Depth) {
        Lookaside->L.FreeMisses += 1;
        (Lookaside->L.FreeEx)(Entry, Lookaside);

    } else {
        InterlockedPushEntrySList(&Lookaside->L.ListHead, (PSLIST_ENTRY)Entry);
    }

    return;
}

#endif // (NTDDI_VERSION >= NTDDI_VISTA)

typedef struct LOOKASIDE_ALIGN _NPAGED_LOOKASIDE_LIST {

    GENERAL_LOOKASIDE L;

#if !defined(_AMD64_) && !defined(_IA64_)

    KSPIN_LOCK Lock__ObsoleteButDoNotDelete;

#endif

} NPAGED_LOOKASIDE_LIST, *PNPAGED_LOOKASIDE_LIST;

#if (NTDDI_VERSION >= NTDDI_WIN2K)

__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
VOID
ExInitializeNPagedLookasideList (
    __out PNPAGED_LOOKASIDE_LIST Lookaside,
    __in_opt PALLOCATE_FUNCTION Allocate,
    __in_opt PFREE_FUNCTION Free,
    __in ULONG Flags,
    __in SIZE_T Size,
    __in ULONG Tag,
    __in USHORT Depth
    );

#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)

__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
VOID
ExDeleteNPagedLookasideList (
    __inout PNPAGED_LOOKASIDE_LIST Lookaside
    );

#endif

__drv_maxIRQL(DISPATCH_LEVEL)
__inline
PVOID
ExAllocateFromNPagedLookasideList (
    __inout PNPAGED_LOOKASIDE_LIST Lookaside
    )

/*++

Routine Description:

    This function removes (pops) the first entry from the specified
    nonpaged lookaside list.

Arguments:

    Lookaside - Supplies a pointer to a nonpaged lookaside list structure.

Return Value:

    If an entry is removed from the specified lookaside list, then the
    address of the entry is returned as the function value. Otherwise,
    NULL is returned.

--*/

{

    PVOID Entry;

    Lookaside->L.TotalAllocates += 1;

#if defined(_WIN2K_COMPAT_SLIST_USAGE) && defined(_X86_)

    Entry = ExInterlockedPopEntrySList(&Lookaside->L.ListHead,
                                       &Lookaside->Lock__ObsoleteButDoNotDelete);

#else

    Entry = InterlockedPopEntrySList(&Lookaside->L.ListHead);

#endif

    if (Entry == NULL) {
        Lookaside->L.AllocateMisses += 1;
        Entry = (Lookaside->L.Allocate)(Lookaside->L.Type,
                                        Lookaside->L.Size,
                                        Lookaside->L.Tag);
    }

    return Entry;
}

__drv_maxIRQL(DISPATCH_LEVEL)
__inline
VOID
ExFreeToNPagedLookasideList (
    __inout PNPAGED_LOOKASIDE_LIST Lookaside,
    __in PVOID Entry
    )

/*++

Routine Description:

    This function inserts (pushes) the specified entry into the specified
    nonpaged lookaside list.

Arguments:

    Lookaside - Supplies a pointer to a nonpaged lookaside list structure.

    Entry - Supples a pointer to the entry that is inserted in the
        lookaside list.

Return Value:

    None.

--*/

{

    Lookaside->L.TotalFrees += 1;
    if (ExQueryDepthSList(&Lookaside->L.ListHead) >= Lookaside->L.Depth) {
        Lookaside->L.FreeMisses += 1;
        (Lookaside->L.Free)(Entry);

    } else {

#if defined(_WIN2K_COMPAT_SLIST_USAGE) && defined(_X86_)

        ExInterlockedPushEntrySList(&Lookaside->L.ListHead,
                                    (PSLIST_ENTRY)Entry,
                                    &Lookaside->Lock__ObsoleteButDoNotDelete);

#else

        InterlockedPushEntrySList(&Lookaside->L.ListHead, (PSLIST_ENTRY)Entry);

#endif

    }

    return;
}



typedef struct LOOKASIDE_ALIGN _PAGED_LOOKASIDE_LIST {

    GENERAL_LOOKASIDE L;

#if !defined(_AMD64_) && !defined(_IA64_)

    FAST_MUTEX Lock__ObsoleteButDoNotDelete;

#endif

} PAGED_LOOKASIDE_LIST, *PPAGED_LOOKASIDE_LIST;


#if (NTDDI_VERSION >= NTDDI_WIN2K)

__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
ExInitializePagedLookasideList (
    __out PPAGED_LOOKASIDE_LIST Lookaside,
    __in_opt PALLOCATE_FUNCTION Allocate,
    __in_opt PFREE_FUNCTION Free,
    __in ULONG Flags,
    __in SIZE_T Size,
    __in ULONG Tag,
    __in USHORT Depth
    );

#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)

__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
ExDeletePagedLookasideList (
    __inout PPAGED_LOOKASIDE_LIST Lookaside
    );

#endif

#if defined(_WIN2K_COMPAT_SLIST_USAGE) && defined(_X86_)

__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
PVOID
ExAllocateFromPagedLookasideList (
    __inout PPAGED_LOOKASIDE_LIST Lookaside
    );

#else

__drv_maxIRQL(APC_LEVEL)
__inline
PVOID
ExAllocateFromPagedLookasideList (
    __inout PPAGED_LOOKASIDE_LIST Lookaside
    )

/*++

Routine Description:

    This function removes (pops) the first entry from the specified
    paged lookaside list.

Arguments:

    Lookaside - Supplies a pointer to a paged lookaside list structure.

Return Value:

    If an entry is removed from the specified lookaside list, then the
    address of the entry is returned as the function value. Otherwise,
    NULL is returned.

--*/

{

    PVOID Entry;

    Lookaside->L.TotalAllocates += 1;
    Entry = InterlockedPopEntrySList(&Lookaside->L.ListHead);
    if (Entry == NULL) {
        Lookaside->L.AllocateMisses += 1;
        Entry = (Lookaside->L.Allocate)(Lookaside->L.Type,
                                        Lookaside->L.Size,
                                        Lookaside->L.Tag);
    }

    return Entry;
}

#endif

#if defined(_WIN2K_COMPAT_SLIST_USAGE) && defined(_X86_)

__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
ExFreeToPagedLookasideList (
    __inout PPAGED_LOOKASIDE_LIST Lookaside,
    __in PVOID Entry
    );

#else

__drv_maxIRQL(APC_LEVEL)
__inline
VOID
ExFreeToPagedLookasideList (
    __inout PPAGED_LOOKASIDE_LIST Lookaside,
    __in PVOID Entry
    )

/*++

Routine Description:

    This function inserts (pushes) the specified entry into the specified
    paged lookaside list.

Arguments:

    Lookaside - Supplies a pointer to a nonpaged lookaside list structure.

    Entry - Supples a pointer to the entry that is inserted in the
        lookaside list.

Return Value:

    None.

--*/

{

    Lookaside->L.TotalFrees += 1;
    if (ExQueryDepthSList(&Lookaside->L.ListHead) >= Lookaside->L.Depth) {
        Lookaside->L.FreeMisses += 1;
        (Lookaside->L.Free)(Entry);

    } else {
        InterlockedPushEntrySList(&Lookaside->L.ListHead,
                                  (PSLIST_ENTRY)Entry);
    }

    return;
}

#endif


#if defined(_NTDDK_) || defined(_NTIFS_)

#if (NTDDI_VERSION >= NTDDI_WIN2K)

__drv_inTry
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
NTAPI
ProbeForRead (
    __in_data_source(USER_MODE) __out_validated(MEMORY) __in_bcount(Length)
    PVOID Address,
    __in SIZE_T Length,
    __in ULONG Alignment
    );

#endif

#endif

//
// Raise status from kernel mode.
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)

__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
DECLSPEC_NORETURN
VOID
NTAPI
ExRaiseStatus (
    __in NTSTATUS Status
    );

#endif



//
// Common probe for write functions.
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)

__drv_inTry
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
NTAPI
ProbeForWrite (
    __in_data_source(USER_MODE) __out_validated(MEMORY) __inout_bcount(Length)
    PVOID Address,
    __in SIZE_T Length,
    __in ULONG Alignment
    );

#endif

//
// Worker Thread
//

typedef enum _WORK_QUEUE_TYPE {
    CriticalWorkQueue,
    DelayedWorkQueue,
    HyperCriticalWorkQueue,
    MaximumWorkQueue
} WORK_QUEUE_TYPE;

typedef
__drv_sameIRQL
__drv_functionClass(WORKER_THREAD_ROUTINE)
VOID
WORKER_THREAD_ROUTINE (
    __in PVOID Parameter
    );

typedef WORKER_THREAD_ROUTINE *PWORKER_THREAD_ROUTINE;

typedef struct _WORK_QUEUE_ITEM {
    LIST_ENTRY List;
    PWORKER_THREAD_ROUTINE WorkerRoutine;
    __volatile PVOID Parameter;
} WORK_QUEUE_ITEM, *PWORK_QUEUE_ITEM;

#if PRAGMA_DEPRECATED_DDK
#pragma deprecated(ExInitializeWorkItem) // Use IoAllocateWorkItem
#endif

#define ExInitializeWorkItem(Item, Routine, Context) \
    (Item)->WorkerRoutine = (Routine);               \
    (Item)->Parameter = (Context);                   \
    (Item)->List.Flink = NULL;

#if (NTDDI_VERSION >= NTDDI_WIN2K)

#ifdef _NTDDK_

__drv_when( (!__drv_defined(_DRIVER_TYPE_FILESYSTEM)
    && !__drv_defined(_DRIVER_TYPE_FILESYSTEM_FILTER))
    || NTDDI_VERSION >= NTDDI_VISTA,
    __drv_preferredFunction("IoQueueWorkItem[Ex]",
    "Obsolete in all drivers for Vista. Obsolete downlevel except for limited "
	"use in IFS. See the documentation"))

#endif

__drv_maxIRQL(DISPATCH_LEVEL)
DECLSPEC_DEPRECATED_DDK // Use IoQueueWorkItem
NTKERNELAPI
VOID
ExQueueWorkItem(
    __inout __drv_aliasesMem PWORK_QUEUE_ITEM WorkItem,
    __drv_strictTypeMatch(__drv_typeExpr) __in WORK_QUEUE_TYPE QueueType
    );

#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)

__drv_maxIRQL(PASSIVE_LEVEL)
__drv_preferredFunction("nothing",
    "Drivers should not be dependent on processor features")
NTKERNELAPI
BOOLEAN
ExIsProcessorFeaturePresent(
    __in ULONG ProcessorFeature
    );

#endif


//
//  Define executive resource data structures.
//

typedef ULONG_PTR ERESOURCE_THREAD;
typedef ERESOURCE_THREAD *PERESOURCE_THREAD;

typedef struct _OWNER_ENTRY {
    ERESOURCE_THREAD OwnerThread;
    union {
        struct {
            ULONG IoPriorityBoosted : 1;
            ULONG OwnerReferenced   : 1;
            ULONG OwnerCount        : 30;
        };
        ULONG TableSize;
    };

} OWNER_ENTRY, *POWNER_ENTRY;

typedef struct _ERESOURCE {
    LIST_ENTRY SystemResourcesList;
    POWNER_ENTRY OwnerTable;

    //
    // ActiveEntries is the true, 32-bit count.  Existing code
    // checks for ActiveCount == 0, so this toggles between
    // 0 and 1 and back as ActiveEntries goes from 0 to
    // non-zero and back.
    //

    SHORT ActiveCount;
    USHORT Flag;
    __volatile PKSEMAPHORE SharedWaiters;
    __volatile PKEVENT ExclusiveWaiters;

    //
    // If the resource is owned exclusive, OwnerEntry contains the
    // resource owner.
    //
    // If the resource is owned shared, OwnerEntry may contain one
    // of the shared owners.
    //

    OWNER_ENTRY OwnerEntry;
    ULONG ActiveEntries;
    ULONG ContentionCount;
    ULONG NumberOfSharedWaiters;
    ULONG NumberOfExclusiveWaiters;

#if defined(_WIN64)

    PVOID Reserved2;

#endif

    union {
        PVOID Address;
        ULONG_PTR CreatorBackTraceIndex;
    };

    KSPIN_LOCK SpinLock;
} ERESOURCE, *PERESOURCE;
//
//  Values for ERESOURCE.Flag
//

#define ResourceNeverExclusive       0x10
#define ResourceReleaseByOtherThread 0x20
#define ResourceOwnedExclusive       0x80

#define RESOURCE_HASH_TABLE_SIZE 64

typedef struct _RESOURCE_HASH_ENTRY {
    LIST_ENTRY ListEntry;
    PVOID Address;
    ULONG ContentionCount;
    ULONG Number;
} RESOURCE_HASH_ENTRY, *PRESOURCE_HASH_ENTRY;

typedef struct _RESOURCE_PERFORMANCE_DATA {
    ULONG ActiveResourceCount;
    ULONG TotalResourceCount;
    ULONG ExclusiveAcquire;
    ULONG SharedFirstLevel;
    ULONG SharedSecondLevel;
    ULONG StarveFirstLevel;
    ULONG StarveSecondLevel;
    ULONG WaitForExclusive;
    ULONG OwnerTableExpands;
    ULONG MaximumTableExpand;
    LIST_ENTRY HashTable[RESOURCE_HASH_TABLE_SIZE];
} RESOURCE_PERFORMANCE_DATA, *PRESOURCE_PERFORMANCE_DATA;

//
// Define executive resource function prototypes.
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)

__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
NTSTATUS
ExInitializeResourceLite (
    __out PERESOURCE Resource
    );

#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)

__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
NTSTATUS
ExReinitializeResourceLite (
    __inout PERESOURCE Resource
    );

#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)

__drv_maxIRQL(APC_LEVEL)
__drv_mustHoldCriticalRegion
__drv_when(Wait!=0, __drv_valueIs(==1))
__drv_when(Wait==0, __drv_valueIs(==0;==1) __checkReturn)
NTKERNELAPI
BOOLEAN
ExAcquireResourceSharedLite (
    __inout __deref __drv_neverHold(ExResourceType)
    __deref __drv_when(return==1, __drv_acquiresResource(ExResourceType))
    PERESOURCE Resource,
    __in BOOLEAN Wait
    );

#endif

#if (NTDDI_VERSION >= NTDDI_VISTA || NTDDI_VERSION >= NTDDI_WS03SP1)

__drv_maxIRQL(APC_LEVEL)
__drv_acquiresCriticalRegion
NTKERNELAPI
PVOID
ExEnterCriticalRegionAndAcquireResourceShared (
    __inout __deref __drv_acquiresExclusiveResource(ExResourceType)
    PERESOURCE Resource
    );

#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)

__drv_maxIRQL(APC_LEVEL)
__drv_mustHoldCriticalRegion
__drv_when(Wait!=0, __drv_valueIs(==1))
__drv_when(Wait==0, __drv_valueIs(==0;==1) __checkReturn)
NTKERNELAPI
BOOLEAN
ExAcquireResourceExclusiveLite (
    __inout __deref __drv_neverHold(ExResourceType)
    __deref __drv_when(return==1, __drv_acquiresResource(ExResourceType))
    PERESOURCE Resource,
    __in __drv_constant BOOLEAN Wait
    );

#endif

#if (NTDDI_VERSION >= NTDDI_VISTA || NTDDI_VERSION >= NTDDI_WS03SP1)

__drv_maxIRQL(APC_LEVEL)
__drv_acquiresCriticalRegion
NTKERNELAPI
PVOID
ExEnterCriticalRegionAndAcquireResourceExclusive (
    __inout __deref __drv_acquiresExclusiveResource(ExResourceType)
    PERESOURCE Resource
    );

#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)

__drv_maxIRQL(APC_LEVEL)
__drv_mustHoldCriticalRegion
__drv_when(Wait!=0, __drv_valueIs(==1))
__drv_when(Wait==0, __drv_valueIs(==0;==1) __checkReturn)
NTKERNELAPI
BOOLEAN
ExAcquireSharedStarveExclusive(
    __inout __deref __drv_neverHold(ExResourceType)
    __deref __drv_when(return!=0, __drv_acquiresResource(ExResourceType))
    PERESOURCE Resource,
    __in BOOLEAN Wait
    );

#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)

__drv_maxIRQL(APC_LEVEL)
__drv_mustHoldCriticalRegion
__drv_when(Wait!=0, __drv_valueIs(==1))
__drv_when(Wait==0, __drv_valueIs(==0;==1) __checkReturn)
NTKERNELAPI
BOOLEAN
ExAcquireSharedWaitForExclusive(
    __inout __deref __drv_neverHold(ExResourceType)
    __deref __drv_when(return!=0, __drv_acquiresResource(ExResourceType))
    PERESOURCE Resource,
    __in BOOLEAN Wait
    );

#endif

#if (NTDDI_VERSION >= NTDDI_VISTA || NTDDI_VERSION >= NTDDI_WS03SP1)

__drv_maxIRQL(APC_LEVEL)
__drv_acquiresCriticalRegion
NTKERNELAPI
PVOID
ExEnterCriticalRegionAndAcquireSharedWaitForExclusive (
    __inout __deref __drv_acquiresExclusiveResource(ExResourceType)
    PERESOURCE Resource
    );

#endif

//
//  VOID
//  ExReleaseResource(
//      IN PERESOURCE Resource
//      );
//

#if PRAGMA_DEPRECATED_DDK
#pragma deprecated(ExReleaseResource)       // Use ExReleaseResourceLite
#endif

#define ExReleaseResource(R) (ExReleaseResourceLite(R))

#if (NTDDI_VERSION >= NTDDI_WIN2K)

__drv_maxIRQL(DISPATCH_LEVEL)
__drv_mustHoldCriticalRegion
NTKERNELAPI
VOID
FASTCALL
ExReleaseResourceLite(
    __inout __deref __drv_releasesExclusiveResource(ExResourceType)
    PERESOURCE Resource
    );

#endif

#if (NTDDI_VERSION >= NTDDI_VISTA || NTDDI_VERSION >= NTDDI_WS03SP1)

__drv_maxIRQL(DISPATCH_LEVEL)
__drv_releasesCriticalRegion
NTKERNELAPI
VOID
FASTCALL
ExReleaseResourceAndLeaveCriticalRegion(
    __inout __deref __drv_releasesExclusiveResource(ExResourceType)
    PERESOURCE Resource
    );

#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)

__drv_maxIRQL(DISPATCH_LEVEL)
__drv_mustHoldCriticalRegion
NTKERNELAPI
VOID
ExReleaseResourceForThreadLite(
    __inout __deref __drv_releasesExclusiveResource(ExResourceType)
    PERESOURCE Resource,
    __in ERESOURCE_THREAD ResourceThreadId
    );

#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)

__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
VOID
ExSetResourceOwnerPointer(
    __inout PERESOURCE Resource,
    __in PVOID OwnerPointer
    );

#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)

__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
VOID
ExSetResourceOwnerPointerEx(
    __inout PERESOURCE Resource,
    __in PVOID OwnerPointer,
    __in ULONG Flags
    );

#define FLAG_OWNER_POINTER_IS_THREAD 0x1

#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)

__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
VOID
ExConvertExclusiveToSharedLite(
    __inout __deref __drv_mustHold(ExResourceType) PERESOURCE Resource
    );

#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)

__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
NTSTATUS
ExDeleteResourceLite (
    __inout PERESOURCE Resource
    );

#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)

__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
ULONG
ExGetExclusiveWaiterCount (
    __in PERESOURCE Resource
    );

#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)

__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
ULONG
ExGetSharedWaiterCount (
    __in PERESOURCE Resource
    );

#endif


//
//  ERESOURCE_THREAD
//  ExGetCurrentResourceThread(
//      VOID
//      );
//

#define ExGetCurrentResourceThread() ((ULONG_PTR)PsGetCurrentThread())

#if (NTDDI_VERSION >= NTDDI_WIN2K)

__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
BOOLEAN
ExIsResourceAcquiredExclusiveLite (
    __in PERESOURCE Resource
    );

#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)

__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
ULONG
ExIsResourceAcquiredSharedLite (
    __in PERESOURCE Resource
    );

#endif

//
// An acquired resource is always owned shared, as shared ownership is a subset
// of exclusive ownership.
//

#define ExIsResourceAcquiredLite ExIsResourceAcquiredSharedLite


//
// Rundown protection structure
//

typedef struct _EX_RUNDOWN_REF {

#define EX_RUNDOWN_ACTIVE      0x1
#define EX_RUNDOWN_COUNT_SHIFT 0x1
#define EX_RUNDOWN_COUNT_INC   (1<<EX_RUNDOWN_COUNT_SHIFT)

    union {
        __volatile ULONG_PTR Count;
        __volatile PVOID Ptr;
    };
} EX_RUNDOWN_REF, *PEX_RUNDOWN_REF;

//
//  Opaque cache-aware rundown ref structure
//

typedef struct _EX_RUNDOWN_REF_CACHE_AWARE  *PEX_RUNDOWN_REF_CACHE_AWARE;


//
// Get previous mode
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)

__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
KPROCESSOR_MODE
ExGetPreviousMode(
    VOID
    );

#endif


//
// Set timer resolution.
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)

__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
ULONG
ExSetTimerResolution (
    __in ULONG DesiredTime,
    __in BOOLEAN SetResolution
    );

#endif

//
// Subtract time zone bias from system time to get local time.
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)

NTKERNELAPI
VOID
ExSystemTimeToLocalTime (
    __in PLARGE_INTEGER SystemTime,
    __out PLARGE_INTEGER LocalTime
    );

#endif

//
// Add time zone bias to local time to get system time.
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)

NTKERNELAPI
VOID
ExLocalTimeToSystemTime (
    __in PLARGE_INTEGER LocalTime,
    __out PLARGE_INTEGER SystemTime
    );

#endif


//
// Define the type for Callback function.
//

typedef struct _CALLBACK_OBJECT *PCALLBACK_OBJECT;

typedef
__drv_sameIRQL
__drv_functionClass(CALLBACK_FUNCTION)
VOID
CALLBACK_FUNCTION (
    __in_opt PVOID CallbackContext,
    __in_opt PVOID Argument1,
    __in_opt PVOID Argument2
    );

typedef CALLBACK_FUNCTION *PCALLBACK_FUNCTION;


#if (NTDDI_VERSION >= NTDDI_WIN2K)

__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
NTSTATUS
ExCreateCallback (
    __deref_out PCALLBACK_OBJECT *CallbackObject,
    __in POBJECT_ATTRIBUTES ObjectAttributes,
    __in BOOLEAN Create,
    __in BOOLEAN AllowMultipleCallbacks
    );

#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)

__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
PVOID
ExRegisterCallback (
    __inout PCALLBACK_OBJECT CallbackObject,
    __in PCALLBACK_FUNCTION CallbackFunction,
    __in_opt PVOID CallbackContext
    );

#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)

__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
ExUnregisterCallback (
    __inout PVOID CallbackRegistration
    );

#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)

__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
VOID
ExNotifyCallback (
    __in PVOID CallbackObject,
    __in_opt PVOID Argument1,
    __in_opt PVOID Argument2
    );

#endif


//
// suite support
//

#if (NTDDI_VERSION >= NTDDI_WINXP)

NTKERNELAPI
BOOLEAN
ExVerifySuite(
    __drv_strictTypeMatch(__drv_typeExpr) __in SUITE_TYPE SuiteType
    );

#endif


//
//  Rundown Locks
//

#if (NTDDI_VERSION >= NTDDI_WINXP)

NTKERNELAPI
VOID
FASTCALL
ExInitializeRundownProtection (
    __out PEX_RUNDOWN_REF RunRef
    );

#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)

NTKERNELAPI
VOID
FASTCALL
ExReInitializeRundownProtection (
    __inout PEX_RUNDOWN_REF RunRef
    );

#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)

__checkReturn
__drv_valueIs(==0;==1)
NTKERNELAPI
BOOLEAN
FASTCALL
ExAcquireRundownProtection (
    __inout PEX_RUNDOWN_REF RunRef
    );

#endif

#if (NTDDI_VERSION >= NTDDI_WINXPSP2 || NTDDI_VERSION >= NTDDI_WS03)

__checkReturn
__drv_valueIs(==0;==1)
NTKERNELAPI
BOOLEAN
FASTCALL
ExAcquireRundownProtectionEx (
    __inout PEX_RUNDOWN_REF RunRef,
    __in ULONG Count
    );

#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)

NTKERNELAPI
VOID
FASTCALL
ExReleaseRundownProtection (
    __inout PEX_RUNDOWN_REF RunRef
    );

#endif

#if (NTDDI_VERSION >= NTDDI_WINXPSP2 || NTDDI_VERSION >= NTDDI_WS03)

NTKERNELAPI
VOID
FASTCALL
ExReleaseRundownProtectionEx (
    __inout PEX_RUNDOWN_REF RunRef,
    __in ULONG Count
    );

#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)

NTKERNELAPI
VOID
FASTCALL
ExRundownCompleted (
    __out PEX_RUNDOWN_REF RunRef
    );

#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)

NTKERNELAPI
VOID
FASTCALL
ExWaitForRundownProtectionRelease (
    __inout PEX_RUNDOWN_REF RunRef
    );

#endif

#if (NTDDI_VERSION >= NTDDI_WS03SP1)

__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
PEX_RUNDOWN_REF_CACHE_AWARE
ExAllocateCacheAwareRundownProtection(
    __drv_strictTypeMatch(__drv_typeExpr) __in POOL_TYPE PoolType,
    __in ULONG PoolTag
    );

#endif

#if (NTDDI_VERSION >= NTDDI_WS03SP1)

__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
SIZE_T
ExSizeOfRundownProtectionCacheAware(
    VOID
    );

#endif

#if (NTDDI_VERSION >= NTDDI_WS03SP1)

__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
ExInitializeRundownProtectionCacheAware(
    __out PEX_RUNDOWN_REF_CACHE_AWARE RunRefCacheAware,
    __in SIZE_T RunRefSize
    );

#endif

#if (NTDDI_VERSION >= NTDDI_WS03SP1)

__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
ExFreeCacheAwareRundownProtection(
    __inout PEX_RUNDOWN_REF_CACHE_AWARE RunRefCacheAware
    );

#endif

#if (NTDDI_VERSION >= NTDDI_WS03SP1)

__checkReturn
__drv_valueIs(==0;==1)
NTKERNELAPI
BOOLEAN
FASTCALL
ExAcquireRundownProtectionCacheAware (
    __inout PEX_RUNDOWN_REF_CACHE_AWARE RunRefCacheAware
    );

#endif

#if (NTDDI_VERSION >= NTDDI_WS03SP1)

NTKERNELAPI
VOID
FASTCALL
ExReleaseRundownProtectionCacheAware (
    __inout PEX_RUNDOWN_REF_CACHE_AWARE RunRefCacheAware
    );

#endif

#if (NTDDI_VERSION >= NTDDI_WS03SP1)

__checkReturn
__drv_valueIs(==0;==1)
NTKERNELAPI
BOOLEAN
FASTCALL
ExAcquireRundownProtectionCacheAwareEx (
    __inout PEX_RUNDOWN_REF_CACHE_AWARE RunRefCacheAware,
    __in ULONG Count
    );

#endif

#if (NTDDI_VERSION >= NTDDI_WS03SP1)

NTKERNELAPI
VOID
FASTCALL
ExReleaseRundownProtectionCacheAwareEx (
    __inout PEX_RUNDOWN_REF_CACHE_AWARE RunRef,
    __in ULONG Count
    );

#endif

#if (NTDDI_VERSION >= NTDDI_WS03SP1)

NTKERNELAPI
VOID
FASTCALL
ExWaitForRundownProtectionReleaseCacheAware (
    __inout PEX_RUNDOWN_REF_CACHE_AWARE RunRef
    );

#endif

#if (NTDDI_VERSION >= NTDDI_WS03SP1)

NTKERNELAPI
VOID
FASTCALL
ExReInitializeRundownProtectionCacheAware (
    __inout PEX_RUNDOWN_REF_CACHE_AWARE RunRefCacheAware
    );

#endif

#if (NTDDI_VERSION >= NTDDI_WS03SP1)

NTKERNELAPI
VOID
FASTCALL
ExRundownCompletedCacheAware (
    __inout PEX_RUNDOWN_REF_CACHE_AWARE RunRefCacheAware
    );

#endif


//
// Define a block to hold the actual routine registration.
//

typedef
__drv_sameIRQL
__drv_functionClass(EX_CALLBACK_FUNCTION)
NTSTATUS
EX_CALLBACK_FUNCTION (
    __in PVOID CallbackContext,
    __in_opt PVOID Argument1,
    __in_opt PVOID Argument2
    );

typedef EX_CALLBACK_FUNCTION *PEX_CALLBACK_FUNCTION;



//
// Registry kernel mode callbacks
//

//
// Hook selector
//
typedef enum _REG_NOTIFY_CLASS {
    RegNtDeleteKey,
    RegNtPreDeleteKey = RegNtDeleteKey,
    RegNtSetValueKey,
    RegNtPreSetValueKey = RegNtSetValueKey,
    RegNtDeleteValueKey,
    RegNtPreDeleteValueKey = RegNtDeleteValueKey,
    RegNtSetInformationKey,
    RegNtPreSetInformationKey = RegNtSetInformationKey,
    RegNtRenameKey,
    RegNtPreRenameKey = RegNtRenameKey,
    RegNtEnumerateKey,
    RegNtPreEnumerateKey = RegNtEnumerateKey,
    RegNtEnumerateValueKey,
    RegNtPreEnumerateValueKey = RegNtEnumerateValueKey,
    RegNtQueryKey,
    RegNtPreQueryKey = RegNtQueryKey,
    RegNtQueryValueKey,
    RegNtPreQueryValueKey = RegNtQueryValueKey,
    RegNtQueryMultipleValueKey,
    RegNtPreQueryMultipleValueKey = RegNtQueryMultipleValueKey,
    RegNtPreCreateKey,
    RegNtPostCreateKey,
    RegNtPreOpenKey,
    RegNtPostOpenKey,
    RegNtKeyHandleClose,
    RegNtPreKeyHandleClose = RegNtKeyHandleClose,
    //
    // .Net only
    //    
    RegNtPostDeleteKey,
    RegNtPostSetValueKey,
    RegNtPostDeleteValueKey,
    RegNtPostSetInformationKey,
    RegNtPostRenameKey,
    RegNtPostEnumerateKey,
    RegNtPostEnumerateValueKey,
    RegNtPostQueryKey,
    RegNtPostQueryValueKey,
    RegNtPostQueryMultipleValueKey,
    RegNtPostKeyHandleClose,
    RegNtPreCreateKeyEx,
    RegNtPostCreateKeyEx,
    RegNtPreOpenKeyEx,
    RegNtPostOpenKeyEx,
    //
    // new to Windows Vista
    //
    RegNtPreFlushKey,
    RegNtPostFlushKey,
    RegNtPreLoadKey,
    RegNtPostLoadKey,
    RegNtPreUnLoadKey,
    RegNtPostUnLoadKey,
    RegNtPreQueryKeySecurity,
    RegNtPostQueryKeySecurity,
    RegNtPreSetKeySecurity,
    RegNtPostSetKeySecurity,
    //
    // per-object context cleanup
    //
    RegNtCallbackObjectContextCleanup,
    //
    // new in Vista SP2 
    //
    RegNtPreRestoreKey,
    RegNtPostRestoreKey,
    RegNtPreSaveKey,
    RegNtPostSaveKey,
    RegNtPreReplaceKey,
    RegNtPostReplaceKey,

    MaxRegNtNotifyClass //should always be the last enum
} REG_NOTIFY_CLASS;

//
// Parameter description for each notify class
//
typedef struct _REG_DELETE_KEY_INFORMATION {
    PVOID    Object;                      // IN
    PVOID    CallContext;  // new to Windows Vista
    PVOID    ObjectContext;// new to Windows Vista
    PVOID    Reserved;     // new to Windows Vista
} REG_DELETE_KEY_INFORMATION, *PREG_DELETE_KEY_INFORMATION
#if (NTDDI_VERSION >= NTDDI_VISTA)
, REG_FLUSH_KEY_INFORMATION, *PREG_FLUSH_KEY_INFORMATION
#endif // NTDDI_VERSION >= NTDDI_VISTA
;

typedef struct _REG_SET_VALUE_KEY_INFORMATION {
    PVOID               Object;                         // IN
    PUNICODE_STRING     ValueName;                      // IN
    ULONG               TitleIndex;                     // IN
    ULONG               Type;                           // IN
    PVOID               Data;                           // IN
    ULONG               DataSize;                       // IN
    PVOID               CallContext;  // new to Windows Vista
    PVOID               ObjectContext;// new to Windows Vista
    PVOID               Reserved;     // new to Windows Vista
} REG_SET_VALUE_KEY_INFORMATION, *PREG_SET_VALUE_KEY_INFORMATION;

typedef struct _REG_DELETE_VALUE_KEY_INFORMATION {
    PVOID               Object;                         // IN
    PUNICODE_STRING     ValueName;                      // IN
    PVOID               CallContext;  // new to Windows Vista
    PVOID               ObjectContext;// new to Windows Vista
    PVOID               Reserved;     // new to Windows Vista
} REG_DELETE_VALUE_KEY_INFORMATION, *PREG_DELETE_VALUE_KEY_INFORMATION;

typedef struct _REG_SET_INFORMATION_KEY_INFORMATION {
    PVOID                       Object;                 // IN
    KEY_SET_INFORMATION_CLASS   KeySetInformationClass; // IN
    PVOID                       KeySetInformation;      // IN
    ULONG                       KeySetInformationLength;// IN
    PVOID                       CallContext;  // new to Windows Vista
    PVOID                       ObjectContext;// new to Windows Vista
    PVOID                       Reserved;     // new to Windows Vista
} REG_SET_INFORMATION_KEY_INFORMATION, *PREG_SET_INFORMATION_KEY_INFORMATION;

typedef struct _REG_ENUMERATE_KEY_INFORMATION {
    PVOID                       Object;                 // IN
    ULONG                       Index;                  // IN
    KEY_INFORMATION_CLASS       KeyInformationClass;    // IN
    PVOID                       KeyInformation;         // IN
    ULONG                       Length;                 // IN
    PULONG                      ResultLength;           // OUT
    PVOID                       CallContext;  // new to Windows Vista
    PVOID                       ObjectContext;// new to Windows Vista
    PVOID                       Reserved;     // new to Windows Vista
} REG_ENUMERATE_KEY_INFORMATION, *PREG_ENUMERATE_KEY_INFORMATION;

typedef struct _REG_ENUMERATE_VALUE_KEY_INFORMATION {
    PVOID                           Object;                     // IN
    ULONG                           Index;                      // IN
    KEY_VALUE_INFORMATION_CLASS     KeyValueInformationClass;   // IN
    PVOID                           KeyValueInformation;        // IN
    ULONG                           Length;                     // IN
    PULONG                          ResultLength;               // OUT
    PVOID                           CallContext;  // new to Windows Vista
    PVOID                           ObjectContext;// new to Windows Vista
    PVOID                           Reserved;     // new to Windows Vista
} REG_ENUMERATE_VALUE_KEY_INFORMATION, *PREG_ENUMERATE_VALUE_KEY_INFORMATION;

typedef struct _REG_QUERY_KEY_INFORMATION {
    PVOID                       Object;                 // IN
    KEY_INFORMATION_CLASS       KeyInformationClass;    // IN
    PVOID                       KeyInformation;         // IN
    ULONG                       Length;                 // IN
    PULONG                      ResultLength;           // OUT
    PVOID                       CallContext;  // new to Windows Vista
    PVOID                       ObjectContext;// new to Windows Vista
    PVOID                       Reserved;     // new to Windows Vista
} REG_QUERY_KEY_INFORMATION, *PREG_QUERY_KEY_INFORMATION;

typedef struct _REG_QUERY_VALUE_KEY_INFORMATION {
    PVOID                           Object;                     // IN
    PUNICODE_STRING                 ValueName;                  // IN
    KEY_VALUE_INFORMATION_CLASS     KeyValueInformationClass;   // IN
    PVOID                           KeyValueInformation;        // IN
    ULONG                           Length;                     // IN
    PULONG                          ResultLength;               // OUT
    PVOID                           CallContext;  // new to Windows Vista
    PVOID                           ObjectContext;// new to Windows Vista
    PVOID                           Reserved;     // new to Windows Vista
} REG_QUERY_VALUE_KEY_INFORMATION, *PREG_QUERY_VALUE_KEY_INFORMATION;

typedef struct _REG_QUERY_MULTIPLE_VALUE_KEY_INFORMATION {
    PVOID               Object;                 // IN
    PKEY_VALUE_ENTRY    ValueEntries;           // IN
    ULONG               EntryCount;             // IN
    PVOID               ValueBuffer;            // IN
    PULONG              BufferLength;           // IN OUT
    PULONG              RequiredBufferLength;   // OUT
    PVOID               CallContext;  // new to Windows Vista
    PVOID               ObjectContext;// new to Windows Vista
    PVOID 	            Reserved;     // new to Windows Vista
} REG_QUERY_MULTIPLE_VALUE_KEY_INFORMATION, *PREG_QUERY_MULTIPLE_VALUE_KEY_INFORMATION;

typedef struct _REG_RENAME_KEY_INFORMATION {
    PVOID            Object;    // IN
    PUNICODE_STRING  NewName;   // IN
    PVOID            CallContext;  // new to Windows Vista
    PVOID            ObjectContext;// new to Windows Vista
    PVOID            Reserved;     // new to Windows Vista
} REG_RENAME_KEY_INFORMATION, *PREG_RENAME_KEY_INFORMATION;


typedef struct _REG_KEY_HANDLE_CLOSE_INFORMATION {
    PVOID               Object;         // IN
    PVOID               CallContext;  // new to Windows Vista
    PVOID               ObjectContext;// new to Windows Vista
    PVOID               Reserved;     // new to Windows Vista
} REG_KEY_HANDLE_CLOSE_INFORMATION, *PREG_KEY_HANDLE_CLOSE_INFORMATION;

/* .Net Only */
typedef struct _REG_CREATE_KEY_INFORMATION {
    PUNICODE_STRING     CompleteName; // IN
    PVOID               RootObject;   // IN
    PVOID               ObjectType;   // new to Windows Vista
    ULONG               CreateOptions;// new to Windows Vista
    PUNICODE_STRING     Class;        // new to Windows Vista
    PVOID               SecurityDescriptor;// new to Windows Vista
    PVOID               SecurityQualityOfService;// new to Windows Vista
    ACCESS_MASK         DesiredAccess;// new to Windows Vista
    ACCESS_MASK         GrantedAccess;// new to Windows Vista
			  		                  // to be filled in by callbacks 
                                      // when bypassing native code
    PULONG              Disposition;  // new to Windows Vista
                                      // on pass through, callback should fill 
                                      // in disposition
    PVOID               *ResultObject;// new to Windows Vista
				                      // on pass through, callback should return 
                                      // object to be used for the return handle
    PVOID               CallContext;  // new to Windows Vista
    PVOID               RootObjectContext;  // new to Windows Vista
    PVOID               Transaction;  // new to Windows Vista
    PVOID               Reserved;     // new to Windows Vista
} REG_CREATE_KEY_INFORMATION, REG_OPEN_KEY_INFORMATION,*PREG_CREATE_KEY_INFORMATION, *PREG_OPEN_KEY_INFORMATION;

typedef struct _REG_CREATE_KEY_INFORMATION_V1 {
    PUNICODE_STRING     CompleteName; // IN
    PVOID               RootObject;   // IN
    PVOID               ObjectType;   // new to Windows Vista
    ULONG               Options;      // new to Windows Vista
    PUNICODE_STRING     Class;        // new to Windows Vista
    PVOID               SecurityDescriptor;// new to Windows Vista
    PVOID               SecurityQualityOfService;// new to Windows Vista
    ACCESS_MASK         DesiredAccess;// new to Windows Vista
    ACCESS_MASK         GrantedAccess;// new to Windows Vista
			  		                  // to be filled in by callbacks 
                                      // when bypassing native code
    PULONG              Disposition;  // new to Windows Vista
                                      // on pass through, callback should fill 
                                      // in disposition
    PVOID               *ResultObject;// new to Windows Vista
				                      // on pass through, callback should return 
                                      // object to be used for the return handle
    PVOID               CallContext;  // new to Windows Vista
    PVOID               RootObjectContext;  // new to Windows Vista
    PVOID               Transaction;  // new to Windows Vista

    ULONG_PTR           Version;      // following is new to Windows 7
    PUNICODE_STRING     RemainingName;// the true path left to parse
    ULONG               Wow64Flags;   // Wow64 specific flags gotten from DesiredAccess input
    ULONG               Attributes;   // ObjectAttributes->Attributes
    KPROCESSOR_MODE     CheckAccessMode;  // mode used for the securiry checks 
} REG_CREATE_KEY_INFORMATION_V1, REG_OPEN_KEY_INFORMATION_V1,*PREG_CREATE_KEY_INFORMATION_V1, *PREG_OPEN_KEY_INFORMATION_V1;



typedef struct _REG_POST_OPERATION_INFORMATION {
    PVOID               Object;         // IN
    NTSTATUS            Status;         // IN
    PVOID               PreInformation; // new to Windows Vista; identical with the pre information that was sent
                                        // in the pre notification
    NTSTATUS            ReturnStatus;   // new to Windows Vista; callback can now change the outcome of the operation
                                        // during post by returning the new staus here
    PVOID               CallContext;    // new to Windows Vista
    PVOID               ObjectContext;  // new to Windows Vista
    PVOID               Reserved;       // new to Windows Vista
} REG_POST_OPERATION_INFORMATION,*PREG_POST_OPERATION_INFORMATION;
/* end .Net Only */

/* XP only */
typedef struct _REG_PRE_CREATE_KEY_INFORMATION {
    PUNICODE_STRING     CompleteName;   // IN
} REG_PRE_CREATE_KEY_INFORMATION, REG_PRE_OPEN_KEY_INFORMATION,*PREG_PRE_CREATE_KEY_INFORMATION, *PREG_PRE_OPEN_KEY_INFORMATION;;

typedef struct _REG_POST_CREATE_KEY_INFORMATION {
    PUNICODE_STRING     CompleteName;   // IN
    PVOID               Object;         // IN
    NTSTATUS            Status;         // IN
} REG_POST_CREATE_KEY_INFORMATION,REG_POST_OPEN_KEY_INFORMATION, *PREG_POST_CREATE_KEY_INFORMATION, *PREG_POST_OPEN_KEY_INFORMATION;
/* end XP only */

/* new to Windows Vista */
#if (NTDDI_VERSION >= NTDDI_VISTA)
typedef struct _REG_LOAD_KEY_INFORMATION {
    PVOID               Object;
    PUNICODE_STRING     KeyName;
    PUNICODE_STRING     SourceFile;
	ULONG				Flags;
    PVOID               TrustClassObject;
	PVOID               UserEvent;
	ACCESS_MASK         DesiredAccess;
    PHANDLE             RootHandle;
    PVOID               CallContext;  
    PVOID               ObjectContext;
    PVOID               Reserved;     
} REG_LOAD_KEY_INFORMATION, *PREG_LOAD_KEY_INFORMATION;

typedef struct _REG_UNLOAD_KEY_INFORMATION {
    PVOID    Object;                      
    PVOID	 UserEvent;
    PVOID    CallContext;  
    PVOID    ObjectContext;
    PVOID    Reserved;     
} REG_UNLOAD_KEY_INFORMATION, *PREG_UNLOAD_KEY_INFORMATION;

typedef struct _REG_CALLBACK_CONTEXT_CLEANUP_INFORMATION {
    PVOID   Object;
    PVOID   ObjectContext;  
    PVOID   Reserved;     
} REG_CALLBACK_CONTEXT_CLEANUP_INFORMATION, *PREG_CALLBACK_CONTEXT_CLEANUP_INFORMATION;

typedef struct _REG_QUERY_KEY_SECURITY_INFORMATION {
    PVOID                   Object;
    PSECURITY_INFORMATION   SecurityInformation;  // IN
    PSECURITY_DESCRIPTOR    SecurityDescriptor;   // INOUT  
    PULONG                  Length;               // INOUT  
    PVOID                   CallContext;  
    PVOID                   ObjectContext;
    PVOID                   Reserved;     
} REG_QUERY_KEY_SECURITY_INFORMATION, *PREG_QUERY_KEY_SECURITY_INFORMATION;

typedef struct _REG_SET_KEY_SECURITY_INFORMATION {
    PVOID                   Object;
    PSECURITY_INFORMATION   SecurityInformation;  // IN
    PSECURITY_DESCRIPTOR    SecurityDescriptor;   // IN
    PVOID                   CallContext;  
    PVOID                   ObjectContext;
    PVOID                   Reserved;     
} REG_SET_KEY_SECURITY_INFORMATION, *PREG_SET_KEY_SECURITY_INFORMATION;

/* new in Vista SP2 - Restore, Save, Replace */
typedef struct _REG_RESTORE_KEY_INFORMATION {
    PVOID               Object;
    HANDLE              FileHandle;
    ULONG				Flags;
    PVOID               CallContext;  
    PVOID               ObjectContext;
    PVOID               Reserved;     
} REG_RESTORE_KEY_INFORMATION, *PREG_RESTORE_KEY_INFORMATION;

typedef struct _REG_SAVE_KEY_INFORMATION {
    PVOID               Object;
    HANDLE              FileHandle;
    ULONG               Format;
    PVOID               CallContext;  
    PVOID               ObjectContext;
    PVOID               Reserved;     
} REG_SAVE_KEY_INFORMATION, *PREG_SAVE_KEY_INFORMATION;

typedef struct _REG_REPLACE_KEY_INFORMATION {
    PVOID               Object;
    PUNICODE_STRING     OldFileName;
    PUNICODE_STRING     NewFileName;
    PVOID               CallContext;  
    PVOID               ObjectContext;
    PVOID               Reserved;     
} REG_REPLACE_KEY_INFORMATION, *PREG_REPLACE_KEY_INFORMATION;
#endif // NTDDI_VERSION >= NTDDI_VISTA

#if (NTDDI_VERSION >= NTDDI_WINXP)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
NTSTATUS
CmRegisterCallback(__in     PEX_CALLBACK_FUNCTION Function,
                   __in_opt PVOID                 Context,
                   __out    PLARGE_INTEGER        Cookie
                    );
NTKERNELAPI
NTSTATUS
__drv_maxIRQL(APC_LEVEL)
CmUnRegisterCallback(__in LARGE_INTEGER    Cookie);

#endif // NTDDI_VERSION >= NTDDI_WINXP

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
NTSTATUS
CmRegisterCallbackEx (  __in        PEX_CALLBACK_FUNCTION   Function,
                        __in        PCUNICODE_STRING        Altitude,
                        __in        PVOID                   Driver, //PDRIVER_OBJECT
                        __in_opt    PVOID                 	Context,
                        __out       PLARGE_INTEGER    	    Cookie,
                        __reserved  PVOID			        Reserved
                    );

__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID 
CmGetCallbackVersion (  __out_opt   PULONG  Major,
                        __out_opt   PULONG  Minor
                        );

__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
NTSTATUS
CmSetCallbackObjectContext (__inout     PVOID	        Object,
                            __in        PLARGE_INTEGER  Cookie,
                            __in        PVOID           NewContext,
                            __out_opt   PVOID           *OldContext
                           );

__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
NTSTATUS
CmCallbackGetKeyObjectID (  __in            PLARGE_INTEGER      Cookie,
                            __in 	        PVOID	            Object,
                            __out_opt       PULONG_PTR          ObjectID,
                            __deref_opt_out PCUNICODE_STRING    *ObjectName
                           );

__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
PVOID
CmGetBoundTransaction(__in  PLARGE_INTEGER  Cookie,
                      __in	PVOID	        Object );

#endif // NTDDI_VERSION >= NTDDI_VISTA

//
// Priority increment definitions.  The comment for each definition gives
// the names of the system services that use the definition when satisfying
// a wait.
//

//
// Priority increment used when satisfying a wait on an executive event
// (NtPulseEvent and NtSetEvent)
//

#define EVENT_INCREMENT                 1

//
// Priority increment when no I/O has been done.  This is used by device
// and file system drivers when completing an IRP (IoCompleteRequest).
//

#define IO_NO_INCREMENT                 0


//
// Priority increment for completing CD-ROM I/O.  This is used by CD-ROM device
// and file system drivers when completing an IRP (IoCompleteRequest)
//

#define IO_CD_ROM_INCREMENT             1

//
// Priority increment for completing disk I/O.  This is used by disk device
// and file system drivers when completing an IRP (IoCompleteRequest)
//

#define IO_DISK_INCREMENT               1



//
// Priority increment for completing keyboard I/O.  This is used by keyboard
// device drivers when completing an IRP (IoCompleteRequest)
//

#define IO_KEYBOARD_INCREMENT           6


//
// Priority increment for completing mailslot I/O.  This is used by the mail-
// slot file system driver when completing an IRP (IoCompleteRequest).
//

#define IO_MAILSLOT_INCREMENT           2


//
// Priority increment for completing mouse I/O.  This is used by mouse device
// drivers when completing an IRP (IoCompleteRequest)
//

#define IO_MOUSE_INCREMENT              6


//
// Priority increment for completing named pipe I/O.  This is used by the
// named pipe file system driver when completing an IRP (IoCompleteRequest).
//

#define IO_NAMED_PIPE_INCREMENT         2

//
// Priority increment for completing network I/O.  This is used by network
// device and network file system drivers when completing an IRP
// (IoCompleteRequest).
//

#define IO_NETWORK_INCREMENT            2


//
// Priority increment for completing parallel I/O.  This is used by parallel
// device drivers when completing an IRP (IoCompleteRequest)
//

#define IO_PARALLEL_INCREMENT           1

//
// Priority increment for completing serial I/O.  This is used by serial device
// drivers when completing an IRP (IoCompleteRequest)
//

#define IO_SERIAL_INCREMENT             2

//
// Priority increment for completing sound I/O.  This is used by sound device
// drivers when completing an IRP (IoCompleteRequest)
//

#define IO_SOUND_INCREMENT              8

//
// Priority increment for completing video I/O.  This is used by video device
// drivers when completing an IRP (IoCompleteRequest)
//

#define IO_VIDEO_INCREMENT              1

//
// Priority increment used when satisfying a wait on an executive semaphore
// (NtReleaseSemaphore)
//

#define SEMAPHORE_INCREMENT             1

//
//  Indicates the system may do I/O to physical addresses above 4 GB.
//

extern PBOOLEAN Mm64BitPhysicalAddress;


//
//  Provides a known bad pointer address which always bugchecks if
//  acccessed.   This gives drivers a way to find pointer bugs by
//  initializing invalid pointers to this value.
//

extern PVOID MmBadPointer;

//
// Define the old maximum disk transfer size to be used by MM and Cache
// Manager.  Current transfer sizes can typically be much larger.
//

#define MM_MAXIMUM_DISK_IO_SIZE          (0x10000)

//++
//
// ULONG_PTR
// ROUND_TO_PAGES (
//     __in ULONG_PTR Size
//     )
//
// Routine Description:
//
//     The ROUND_TO_PAGES macro takes a size in bytes and rounds it up to a
//     multiple of the page size.
//
//     NOTE: This macro fails for values 0xFFFFFFFF - (PAGE_SIZE - 1).
//
// Arguments:
//
//     Size - Size in bytes to round up to a page multiple.
//
// Return Value:
//
//     Returns the size rounded up to a multiple of the page size.
//
//--

#define ROUND_TO_PAGES(Size)  (((ULONG_PTR)(Size) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))

//++
//
// ULONG
// BYTES_TO_PAGES (
//     __in ULONG Size
//     )
//
// Routine Description:
//
//     The BYTES_TO_PAGES macro takes the size in bytes and calculates the
//     number of pages required to contain the bytes.
//
// Arguments:
//
//     Size - Size in bytes.
//
// Return Value:
//
//     Returns the number of pages required to contain the specified size.
//
//--

#define BYTES_TO_PAGES(Size)  (((Size) >> PAGE_SHIFT) + \
                               (((Size) & (PAGE_SIZE - 1)) != 0))

//++
//
// ULONG
// BYTE_OFFSET (
//     __in PVOID Va
//     )
//
// Routine Description:
//
//     The BYTE_OFFSET macro takes a virtual address and returns the byte offset
//     of that address within the page.
//
// Arguments:
//
//     Va - Virtual address.
//
// Return Value:
//
//     Returns the byte offset portion of the virtual address.
//
//--

#define BYTE_OFFSET(Va) ((ULONG)((LONG_PTR)(Va) & (PAGE_SIZE - 1)))

//++
//
// PVOID
// PAGE_ALIGN (
//     __in PVOID Va
//     )
//
// Routine Description:
//
//     The PAGE_ALIGN macro takes a virtual address and returns a page-aligned
//     virtual address for that page.
//
// Arguments:
//
//     Va - Virtual address.
//
// Return Value:
//
//     Returns the page aligned virtual address.
//
//--

#define PAGE_ALIGN(Va) ((PVOID)((ULONG_PTR)(Va) & ~(PAGE_SIZE - 1)))

//++
//
// ULONG
// ADDRESS_AND_SIZE_TO_SPAN_PAGES (
//     __in PVOID Va,
//     __in ULONG Size
//     )
//
// Routine Description:
//
//     The ADDRESS_AND_SIZE_TO_SPAN_PAGES macro takes a virtual address and
//     size and returns the number of pages spanned by the size.
//
// Arguments:
//
//     Va - Virtual address.
//
//     Size - Size in bytes.
//
// Return Value:
//
//     Returns the number of pages spanned by the size.
//
//--

#define ADDRESS_AND_SIZE_TO_SPAN_PAGES(Va,Size) \
    ((ULONG)((((ULONG_PTR)(Size)) >> PAGE_SHIFT) + ((BYTE_OFFSET (Va) + BYTE_OFFSET (Size) + PAGE_SIZE - 1) >> PAGE_SHIFT)))

#if PRAGMA_DEPRECATED_DDK
#pragma deprecated(COMPUTE_PAGES_SPANNED)   // Use ADDRESS_AND_SIZE_TO_SPAN_PAGES
#endif

#define COMPUTE_PAGES_SPANNED(Va, Size) ADDRESS_AND_SIZE_TO_SPAN_PAGES(Va,Size)


//++
// PPFN_NUMBER
// MmGetMdlPfnArray (
//     __in PMDL Mdl
//     )
//
// Routine Description:
//
//     The MmGetMdlPfnArray routine returns the virtual address of the
//     first element of the array of physical page numbers associated with
//     the MDL.
//
// Arguments:
//
//     Mdl - Pointer to an MDL.
//
// Return Value:
//
//     Returns the virtual address of the first element of the array of
//     physical page numbers associated with the MDL.
//
//--

#define MmGetMdlPfnArray(Mdl) ((PPFN_NUMBER)(Mdl + 1))

//++
//
// PVOID
// MmGetMdlVirtualAddress (
//     __in PMDL Mdl
//     )
//
// Routine Description:
//
//     The MmGetMdlVirtualAddress returns the virtual address of the buffer
//     described by the Mdl.
//
// Arguments:
//
//     Mdl - Pointer to an MDL.
//
// Return Value:
//
//     Returns the virtual address of the buffer described by the Mdl
//
//--

#define MmGetMdlVirtualAddress(Mdl)                                     \
    ((PVOID) ((PCHAR) ((Mdl)->StartVa) + (Mdl)->ByteOffset))

//++
//
// ULONG
// MmGetMdlByteCount (
//     __in PMDL Mdl
//     )
//
// Routine Description:
//
//     The MmGetMdlByteCount returns the length in bytes of the buffer
//     described by the Mdl.
//
// Arguments:
//
//     Mdl - Pointer to an MDL.
//
// Return Value:
//
//     Returns the byte count of the buffer described by the Mdl
//
//--

#define MmGetMdlByteCount(Mdl)  ((Mdl)->ByteCount)

//++
//
// ULONG
// MmGetMdlByteOffset (
//     __in PMDL Mdl
//     )
//
// Routine Description:
//
//     The MmGetMdlByteOffset returns the byte offset within the page
//     of the buffer described by the Mdl.
//
// Arguments:
//
//     Mdl - Pointer to an MDL.
//
// Return Value:
//
//     Returns the byte offset within the page of the buffer described by the Mdl
//
//--

#define MmGetMdlByteOffset(Mdl)  ((Mdl)->ByteOffset)

//++
//
// PVOID
// MmGetMdlStartVa (
//     __in PMDL Mdl
//     )
//
// Routine Description:
//
//     The MmGetMdlBaseVa returns the virtual address of the buffer
//     described by the Mdl rounded down to the nearest page.
//
// Arguments:
//
//     Mdl - Pointer to an MDL.
//
// Return Value:
//
//     Returns the returns the starting virtual address of the MDL.
//
//
//--

#define MmGetMdlBaseVa(Mdl)  ((Mdl)->StartVa)

typedef enum _MM_SYSTEM_SIZE {
    MmSmallSystem,
    MmMediumSystem,
    MmLargeSystem
} MM_SYSTEMSIZE;

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
MM_SYSTEMSIZE
MmQuerySystemSize (
    VOID
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WINXP)
__drv_maxIRQL (APC_LEVEL)
NTKERNELAPI
NTSTATUS
MmIsVerifierEnabled (
    __out PULONG VerifierFlags
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
__drv_maxIRQL (APC_LEVEL)
NTKERNELAPI
NTSTATUS
MmAddVerifierThunks (
    __in_bcount (ThunkBufferSize) PVOID ThunkBuffer,
    __in ULONG ThunkBufferSize
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL (APC_LEVEL)
NTKERNELAPI
VOID
MmProbeAndLockProcessPages (
    __inout PMDL MemoryDescriptorList,
    __in PEPROCESS Process,
    __in KPROCESSOR_MODE AccessMode,
    __in LOCK_OPERATION Operation
    );
#endif

//
// I/O support routines.
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
VOID
MmProbeAndLockPages (
    __inout PMDLX MemoryDescriptorList,
    __in KPROCESSOR_MODE AccessMode,
    __in LOCK_OPERATION Operation
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
VOID
MmUnlockPages (
    __inout PMDLX MemoryDescriptorList
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
VOID
MmBuildMdlForNonPagedPool (
    __inout PMDLX MemoryDescriptorList
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn 
__drv_preferredFunction("MmMapLockedPagesSpecifyCache",
    "Obsolete except on Windows 98.  Use MmGetSystemAddressForMdlSafe if this "
	"is a call to MmGetSystemAddressForMdl.") 
__drv_when(AccessMode==0, __drv_maxIRQL(DISPATCH_LEVEL))
__drv_when(AccessMode==1, __drv_inTry __drv_maxIRQL(APC_LEVEL)) 
DECLSPEC_DEPRECATED_DDK
NTKERNELAPI
PVOID
MmMapLockedPages (
    __in PMDL MemoryDescriptorList,
    __in __drv_strictType(KPROCESSOR_MODE/enum _MODE,__drv_typeConst) 
    KPROCESSOR_MODE AccessMode
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WS03)
__drv_maxIRQL (DISPATCH_LEVEL)
NTKERNELAPI
LOGICAL
MmIsIoSpaceActive (
    __in PHYSICAL_ADDRESS StartAddress,
    __in SIZE_T NumberOfBytes
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
PVOID
MmGetSystemRoutineAddress (
    __in PUNICODE_STRING SystemRoutineName
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
NTSTATUS
MmAdvanceMdl (
    __inout PMDLX Mdl,
    __in ULONG NumberOfBytes
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
__checkReturn 
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
NTSTATUS
MmProtectMdlSystemAddress (
    __in PMDLX MemoryDescriptorList,
    __in ULONG NewProtect
    );
#endif

//
// _MM_PAGE_PRIORITY_ provides a method for the system to handle requests
// intelligently in low resource conditions.
//
// LowPagePriority should be used when it is acceptable to the driver for the
// mapping request to fail if the system is low on resources.  An example of
// this could be for a non-critical network connection where the driver can
// handle the failure case when system resources are close to being depleted.
//
// NormalPagePriority should be used when it is acceptable to the driver for the
// mapping request to fail if the system is very low on resources.  An example
// of this could be for a non-critical local filesystem request.
//
// HighPagePriority should be used when it is unacceptable to the driver for the
// mapping request to fail unless the system is completely out of resources.
// An example of this would be the paging file path in a driver.
//



typedef enum _MM_PAGE_PRIORITY {
    LowPagePriority,
    NormalPagePriority = 16,
    HighPagePriority = 32
} MM_PAGE_PRIORITY;



//
// Note: This function is not available in WDM 1.0
//
#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn 
__drv_when(AccessMode==0, __drv_maxIRQL(DISPATCH_LEVEL)) 
__drv_when(AccessMode==1, __drv_inTry __drv_maxIRQL(APC_LEVEL))
NTKERNELAPI
PVOID
MmMapLockedPagesSpecifyCache (
    __in PMDLX MemoryDescriptorList,
    __in __drv_strictType(KPROCESSOR_MODE/enum _MODE,__drv_typeConst) 
    KPROCESSOR_MODE AccessMode,
    __in __drv_strictTypeMatch(__drv_typeCond) MEMORY_CACHING_TYPE CacheType,
    __in_opt PVOID BaseAddress,
    __in ULONG BugCheckOnFailure,
    __in __drv_strictTypeMatch(__drv_typeCond) MM_PAGE_PRIORITY Priority
     );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
VOID
MmUnmapLockedPages (
    __in PVOID BaseAddress,
    __in PMDL MemoryDescriptorList
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
__checkReturn 
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
__out_bcount_opt (NumberOfBytes) PVOID
MmAllocateMappingAddress (
     __in SIZE_T NumberOfBytes,
     __in ULONG PoolTag
     );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
MmFreeMappingAddress (
     __in PVOID BaseAddress,
     __in ULONG PoolTag
     );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
__checkReturn 
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
PVOID
MmMapLockedPagesWithReservedMapping (
    __in PVOID MappingAddress,
    __in ULONG PoolTag,
    __in PMDLX MemoryDescriptorList,
    __in __drv_strictTypeMatch(__drv_typeCond) MEMORY_CACHING_TYPE CacheType
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
VOID
MmUnmapReservedMapping (
     __in PVOID BaseAddress,
     __in ULONG PoolTag,
     __in PMDLX MemoryDescriptorList
     );
#endif


#define MM_DONT_ZERO_ALLOCATION                 0x00000001
#define MM_ALLOCATE_FROM_LOCAL_NODE_ONLY        0x00000002
#define MM_ALLOCATE_FULLY_REQUIRED              0x00000004
#define MM_ALLOCATE_NO_WAIT                     0x00000008
#define MM_ALLOCATE_PREFER_CONTIGUOUS           0x00000010
#define MM_ALLOCATE_REQUIRE_CONTIGUOUS_CHUNKS   0x00000020

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
__checkReturn 
__drv_maxIRQL (DISPATCH_LEVEL)
NTKERNELAPI
PMDL
MmAllocatePagesForMdlEx (
    __in PHYSICAL_ADDRESS LowAddress,
    __in PHYSICAL_ADDRESS HighAddress,
    __in PHYSICAL_ADDRESS SkipBytes,
    __in SIZE_T TotalBytes,
    __in MEMORY_CACHING_TYPE CacheType,
    __in ULONG Flags
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn 
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
PMDL
MmAllocatePagesForMdl (
    __in PHYSICAL_ADDRESS LowAddress,
    __in PHYSICAL_ADDRESS HighAddress,
    __in PHYSICAL_ADDRESS SkipBytes,
    __in SIZE_T TotalBytes
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
VOID
MmFreePagesFromMdl (
    __in PMDLX MemoryDescriptorList
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn 
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
__out_bcount_opt (NumberOfBytes) 
PVOID
MmMapIoSpace (
    __in PHYSICAL_ADDRESS PhysicalAddress,
    __in SIZE_T NumberOfBytes,
    __in MEMORY_CACHING_TYPE CacheType
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
VOID
MmUnmapIoSpace (
    __in_bcount (NumberOfBytes) PVOID BaseAddress,
    __in SIZE_T NumberOfBytes
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn 
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
__bcount (NumberOfBytes) PVOID
MmAllocateContiguousMemory (
    __in SIZE_T NumberOfBytes,
    __in PHYSICAL_ADDRESS HighestAcceptableAddress
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn 
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
__out_bcount_opt (NumberOfBytes) PVOID
MmAllocateContiguousMemorySpecifyCache (
    __in SIZE_T NumberOfBytes,
    __in PHYSICAL_ADDRESS LowestAcceptableAddress,
    __in PHYSICAL_ADDRESS HighestAcceptableAddress,
    __in_opt PHYSICAL_ADDRESS BoundaryAddressMultiple,
    __in MEMORY_CACHING_TYPE CacheType
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)



typedef ULONG NODE_REQUIREMENT;

#define MM_ANY_NODE_OK          0x80000000



__checkReturn 
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
__out_bcount_opt (NumberOfBytes) PVOID
MmAllocateContiguousMemorySpecifyCacheNode (
    __in SIZE_T NumberOfBytes,
    __in PHYSICAL_ADDRESS LowestAcceptableAddress,
    __in PHYSICAL_ADDRESS HighestAcceptableAddress,
    __in_opt PHYSICAL_ADDRESS BoundaryAddressMultiple,
    __in MEMORY_CACHING_TYPE CacheType,
    __in NODE_REQUIREMENT PreferredNode
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
VOID
MmFreeContiguousMemory (
    __in PVOID BaseAddress
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL (DISPATCH_LEVEL)
NTKERNELAPI
VOID
MmFreeContiguousMemorySpecifyCache (
    __in_bcount (NumberOfBytes) PVOID BaseAddress,
    __in SIZE_T NumberOfBytes,
    __in MEMORY_CACHING_TYPE CacheType
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
SIZE_T
MmSizeOfMdl (
    __in_bcount_opt (Length) PVOID Base,
    __in SIZE_T Length
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
DECLSPEC_DEPRECATED_DDK                 // Use IoAllocateMdl
__drv_preferredFunction("IoAllocateMdl","Obsolete")
NTKERNELAPI
PMDL
MmCreateMdl (
    __in_opt PMDL MemoryDescriptorList,
    __in_bcount_opt (Length) PVOID Base,
    __in SIZE_T Length
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn 
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
PVOID
MmLockPagableDataSection (
    __in PVOID AddressWithinSection
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
MmResetDriverPaging (
    __in PVOID AddressWithinSection
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
PVOID
MmPageEntireDriver (
    __in PVOID AddressWithinSection
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
VOID
MmUnlockPagableImageSection (
    __in PVOID ImageSectionHandle
    );
#endif


//++
//
// VOID
// MmInitializeMdl (
//     __in PMDL MemoryDescriptorList,
//     __in PVOID BaseVa,
//     __in SIZE_T Length
//     )
//
// Routine Description:
//
//     This routine initializes the header of a Memory Descriptor List (MDL).
//
// Arguments:
//
//     MemoryDescriptorList - Pointer to the MDL to initialize.
//
//     BaseVa - Base virtual address mapped by the MDL.
//
//     Length - Length, in bytes, of the buffer mapped by the MDL.
//
// Return Value:
//
//     None.
//
//--

#define MmInitializeMdl(MemoryDescriptorList, BaseVa, Length) { \
    (MemoryDescriptorList)->Next = (PMDL) NULL; \
    (MemoryDescriptorList)->Size = (CSHORT)(sizeof(MDL) +  \
            (sizeof(PFN_NUMBER) * ADDRESS_AND_SIZE_TO_SPAN_PAGES((BaseVa), (Length)))); \
    (MemoryDescriptorList)->MdlFlags = 0; \
    (MemoryDescriptorList)->StartVa = (PVOID) PAGE_ALIGN((BaseVa)); \
    (MemoryDescriptorList)->ByteOffset = BYTE_OFFSET((BaseVa)); \
    (MemoryDescriptorList)->ByteCount = (ULONG)(Length); \
    }

//++
//
// PVOID
// MmGetSystemAddressForMdlSafe (
//     __in PMDL MDL,
//     __in MM_PAGE_PRIORITY PRIORITY
//     )
//
// Routine Description:
//
//     This routine returns the mapped address of an MDL. If the
//     Mdl is not already mapped or a system address, it is mapped.
//
// Arguments:
//
//     MemoryDescriptorList - Pointer to the MDL to map.
//
//     Priority - Supplies an indication as to how important it is that this
//                request succeed under low available PTE conditions.
//
// Return Value:
//
//     Returns the base address where the pages are mapped.  The base address
//     has the same offset as the virtual address in the MDL.
//
//     Unlike MmGetSystemAddressForMdl, Safe guarantees that it will always
//     return NULL on failure instead of bugchecking the system.
//
//     This macro is not usable by WDM 1.0 drivers as 1.0 did not include
//     MmMapLockedPagesSpecifyCache.  The solution for WDM 1.0 drivers is to
//     provide synchronization and set/reset the MDL_MAPPING_CAN_FAIL bit.
//
//--

#define MmGetSystemAddressForMdlSafe(MDL, PRIORITY)                    \
     (((MDL)->MdlFlags & (MDL_MAPPED_TO_SYSTEM_VA |                    \
                        MDL_SOURCE_IS_NONPAGED_POOL)) ?                \
                             ((MDL)->MappedSystemVa) :                 \
                             (MmMapLockedPagesSpecifyCache((MDL),      \
                                                           KernelMode, \
                                                           MmCached,   \
                                                           NULL,       \
                                                           FALSE,      \
                                                           (PRIORITY))))

//++
//
// PVOID
// MmGetSystemAddressForMdl (
//     __in PMDL MDL
//     )
//
// Routine Description:
//
//     This routine returns the mapped address of an MDL, if the
//     Mdl is not already mapped or a system address, it is mapped.
//
// Arguments:
//
//     MemoryDescriptorList - Pointer to the MDL to map.
//
// Return Value:
//
//     Returns the base address where the pages are mapped.  The base address
//     has the same offset as the virtual address in the MDL.
//
//--

//#define MmGetSystemAddressForMdl(MDL)
//     (((MDL)->MdlFlags & (MDL_MAPPED_TO_SYSTEM_VA)) ?
//                             ((MDL)->MappedSystemVa) :
//                ((((MDL)->MdlFlags & (MDL_SOURCE_IS_NONPAGED_POOL)) ?
//                      ((PVOID)((ULONG)(MDL)->StartVa | (MDL)->ByteOffset)) :
//                            (MmMapLockedPages((MDL),KernelMode)))))

#if PRAGMA_DEPRECATED_DDK
#pragma deprecated(MmGetSystemAddressForMdl)    // Use MmGetSystemAddressForMdlSafe
#endif

#define MmGetSystemAddressForMdl(MDL)                                  \
     (((MDL)->MdlFlags & (MDL_MAPPED_TO_SYSTEM_VA |                    \
                        MDL_SOURCE_IS_NONPAGED_POOL)) ?                \
                             ((MDL)->MappedSystemVa) :                 \
                             (MmMapLockedPages((MDL),KernelMode)))

//++
//
// VOID
// MmPrepareMdlForReuse (
//     __in PMDL MDL
//     )
//
// Routine Description:
//
//     This routine will take all of the steps necessary to allow an MDL to be
//     re-used.
//
// Arguments:
//
//     MemoryDescriptorList - Pointer to the MDL that will be re-used.
//
// Return Value:
//
//     None.
//
//--

#define MmPrepareMdlForReuse(MDL)                                       \
    if (((MDL)->MdlFlags & MDL_PARTIAL_HAS_BEEN_MAPPED) != 0) {         \
        ASSERT(((MDL)->MdlFlags & MDL_PARTIAL) != 0);                   \
        MmUnmapLockedPages( (MDL)->MappedSystemVa, (MDL) );             \
    } else if (((MDL)->MdlFlags & MDL_PARTIAL) == 0) {                  \
        ASSERT(((MDL)->MdlFlags & MDL_MAPPED_TO_SYSTEM_VA) == 0);       \
    }

typedef NTSTATUS (*PMM_DLL_INITIALIZE) (
    __in PUNICODE_STRING RegistryPath
    );

typedef NTSTATUS (*PMM_DLL_UNLOAD) (
    VOID
    );



//
// Define an empty typedef for the _DRIVER_OBJECT structure so it may be
// referenced by function types before it is actually defined.
//
struct _DRIVER_OBJECT;

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
LOGICAL
MmIsDriverVerifying (
    __in struct _DRIVER_OBJECT *DriverObject
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL (APC_LEVEL)
NTKERNELAPI
LOGICAL
MmIsDriverVerifyingByAddress (
    __in PVOID AddressWithinSection
    );
#endif

//
//  Security operation codes
//

typedef enum _SECURITY_OPERATION_CODE {
    SetSecurityDescriptor,
    QuerySecurityDescriptor,
    DeleteSecurityDescriptor,
    AssignSecurityDescriptor
    } SECURITY_OPERATION_CODE, *PSECURITY_OPERATION_CODE;

//
//  Data structure used to capture subject security context
//  for access validations and auditing.
//
//  THE FIELDS OF THIS DATA STRUCTURE SHOULD BE CONSIDERED OPAQUE
//  BY ALL EXCEPT THE SECURITY ROUTINES.
//

typedef struct _SECURITY_SUBJECT_CONTEXT {
    PACCESS_TOKEN ClientToken;
    SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
    PACCESS_TOKEN PrimaryToken;
    PVOID ProcessAuditId;
    } SECURITY_SUBJECT_CONTEXT, *PSECURITY_SUBJECT_CONTEXT;

///////////////////////////////////////////////////////////////////////////////
//                                                                           //
//                  ACCESS_STATE and related structures                      //
//                                                                           //
///////////////////////////////////////////////////////////////////////////////

//
//  Initial Privilege Set - Room for three privileges, which should
//  be enough for most applications.  This structure exists so that
//  it can be imbedded in an ACCESS_STATE structure.  Use PRIVILEGE_SET
//  for all other references to Privilege sets.
//

#define INITIAL_PRIVILEGE_COUNT         3

typedef struct _INITIAL_PRIVILEGE_SET {
    ULONG PrivilegeCount;
    ULONG Control;
    LUID_AND_ATTRIBUTES Privilege[INITIAL_PRIVILEGE_COUNT];
    } INITIAL_PRIVILEGE_SET, * PINITIAL_PRIVILEGE_SET;



//
// Combine the information that describes the state
// of an access-in-progress into a single structure
//


typedef struct _ACCESS_STATE {
   LUID OperationID;                // Currently unused, replaced by TransactionId in AUX_ACCESS_DATA
   BOOLEAN SecurityEvaluated;
   BOOLEAN GenerateAudit;
   BOOLEAN GenerateOnClose;
   BOOLEAN PrivilegesAllocated;
   ULONG Flags;
   ACCESS_MASK RemainingDesiredAccess;
   ACCESS_MASK PreviouslyGrantedAccess;
   ACCESS_MASK OriginalDesiredAccess;
   SECURITY_SUBJECT_CONTEXT SubjectSecurityContext;
   PSECURITY_DESCRIPTOR SecurityDescriptor; // it stores SD supplied by caller when creating a new object.
   PVOID AuxData;
   union {
      INITIAL_PRIVILEGE_SET InitialPrivilegeSet;
      PRIVILEGE_SET PrivilegeSet;
      } Privileges;

   BOOLEAN AuditPrivileges;
   UNICODE_STRING ObjectName;
   UNICODE_STRING ObjectTypeName;

   } ACCESS_STATE, *PACCESS_STATE;


typedef VOID
(*PNTFS_DEREF_EXPORTED_SECURITY_DESCRIPTOR)(
    __in PVOID  Vcb,
    __in PSECURITY_DESCRIPTOR SecurityDescriptor);



#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
SeCaptureSubjectContext (
    __out PSECURITY_SUBJECT_CONTEXT SubjectContext
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
SeLockSubjectContext(
    __in PSECURITY_SUBJECT_CONTEXT SubjectContext
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
SeUnlockSubjectContext(
    __in PSECURITY_SUBJECT_CONTEXT SubjectContext
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
SeReleaseSubjectContext (
    __inout PSECURITY_SUBJECT_CONTEXT SubjectContext
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
NTSTATUS
SeAssignSecurity (
    __in_opt PSECURITY_DESCRIPTOR ParentDescriptor,
    __in_opt PSECURITY_DESCRIPTOR ExplicitDescriptor,
    __out PSECURITY_DESCRIPTOR *NewDescriptor,
    __in BOOLEAN IsDirectoryObject,
    __in PSECURITY_SUBJECT_CONTEXT SubjectContext,
    __in PGENERIC_MAPPING GenericMapping,
    __in POOL_TYPE PoolType
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
NTKERNELAPI
ULONG
SeComputeAutoInheritByObjectType(
    __in PVOID ObjectType,
    __in_opt PSECURITY_DESCRIPTOR SecurityDescriptor,
    __in_opt PSECURITY_DESCRIPTOR ParentSecurityDescriptor
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
SeAssignSecurityEx (
    __in_opt PSECURITY_DESCRIPTOR ParentDescriptor,
    __in_opt PSECURITY_DESCRIPTOR ExplicitDescriptor,
    __out PSECURITY_DESCRIPTOR *NewDescriptor,
    __in_opt GUID *ObjectType,
    __in BOOLEAN IsDirectoryObject,
    __in ULONG AutoInheritFlags,
    __in PSECURITY_SUBJECT_CONTEXT SubjectContext,
    __in PGENERIC_MAPPING GenericMapping,
    __in POOL_TYPE PoolType
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
NTSTATUS
SeDeassignSecurity (
    __deref_inout PSECURITY_DESCRIPTOR *SecurityDescriptor
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
ULONG
SeObjectCreateSaclAccessBits(
    __in PSECURITY_DESCRIPTOR SecurityDescriptor
    );

__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
BOOLEAN
SeAccessCheck (
    __in PSECURITY_DESCRIPTOR SecurityDescriptor,
    __in PSECURITY_SUBJECT_CONTEXT SubjectSecurityContext,
    __in BOOLEAN SubjectContextLocked,
    __in ACCESS_MASK DesiredAccess,
    __in ACCESS_MASK PreviouslyGrantedAccess,
    __deref_opt_out PPRIVILEGE_SET *Privileges,
    __in PGENERIC_MAPPING GenericMapping,
    __in KPROCESSOR_MODE AccessMode,
    __out PACCESS_MASK GrantedAccess,
    __out PNTSTATUS AccessStatus
    );
#endif


#ifdef SE_NTFS_WORLD_CACHE

#if (NTDDI_VERSION >= NTDDI_VISTA)
VOID
SeGetWorldRights (
    __in PSECURITY_DESCRIPTOR SecurityDescriptor,
    __in PGENERIC_MAPPING GenericMapping,
    __out PACCESS_MASK GrantedAccess
    );
#endif

#endif

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
NTSTATUS
SeSetAuditParameter(
    __inout PSE_ADT_PARAMETER_ARRAY AuditParameters,
    __in SE_ADT_PARAMETER_TYPE Type,
    __in ULONG Index,
    __in PVOID Data
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
NTSTATUS
SeReportSecurityEvent(
    __in ULONG Flags,
    __in PUNICODE_STRING SourceName,
    __in_opt PSID UserSid,
    __in PSE_ADT_PARAMETER_ARRAY AuditParameters
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
BOOLEAN
SeValidSecurityDescriptor(
    __in ULONG Length,
    __in_bcount(Length) PSECURITY_DESCRIPTOR SecurityDescriptor
    );
#endif


#if !defined(_PSGETCURRENTTHREAD_)

#define _PSGETCURRENTTHREAD_

__drv_maxIRQL(DISPATCH_LEVEL)
FORCEINLINE
PETHREAD
PsGetCurrentThread (
    VOID
    )

/*++

Routine Description:

    This function returns a pointer to the current executive thread object.

Arguments:

    None.

Return Value:

    A pointer to the current executive thread object.

--*/

{

    return (PETHREAD)KeGetCurrentThread();
}

#endif

//
// System Thread and Process Creation and Termination
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL) 
__drv_valueIs(==0;<0)
NTKERNELAPI
__checkReturn
NTSTATUS
PsCreateSystemThread(
    __out PHANDLE ThreadHandle,
    __in ULONG DesiredAccess,
    __in_opt POBJECT_ATTRIBUTES ObjectAttributes,
    __in_opt  HANDLE ProcessHandle,
    __out_opt PCLIENT_ID ClientId,
    __in PKSTART_ROUTINE StartRoutine,
    __in_opt __drv_when(return==0, __drv_aliasesMem) PVOID StartContext
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
NTSTATUS
PsTerminateSystemThread(
    __in NTSTATUS ExitStatus
    );
#endif

NTKERNELAPI
NTSTATUS
PsWrapApcWow64Thread (
    __inout PVOID *ApcContext,
    __inout PVOID *ApcRoutine);


//
// Define I/O system data structure type codes.  Each major data structure in
// the I/O system has a type code  The type field in each structure is at the
// same offset.  The following values can be used to determine which type of
// data structure a pointer refers to.
//

#define IO_TYPE_ADAPTER                 0x00000001
#define IO_TYPE_CONTROLLER              0x00000002
#define IO_TYPE_DEVICE                  0x00000003
#define IO_TYPE_DRIVER                  0x00000004
#define IO_TYPE_FILE                    0x00000005
#define IO_TYPE_IRP                     0x00000006
#define IO_TYPE_MASTER_ADAPTER          0x00000007
#define IO_TYPE_OPEN_PACKET             0x00000008
#define IO_TYPE_TIMER                   0x00000009
#define IO_TYPE_VPB                     0x0000000a
#define IO_TYPE_ERROR_LOG               0x0000000b
#define IO_TYPE_ERROR_MESSAGE           0x0000000c
#define IO_TYPE_DEVICE_OBJECT_EXTENSION 0x0000000d


//
// Define the major function codes for IRPs.
//


#define IRP_MJ_CREATE                   0x00
#define IRP_MJ_CREATE_NAMED_PIPE        0x01
#define IRP_MJ_CLOSE                    0x02
#define IRP_MJ_READ                     0x03
#define IRP_MJ_WRITE                    0x04
#define IRP_MJ_QUERY_INFORMATION        0x05
#define IRP_MJ_SET_INFORMATION          0x06
#define IRP_MJ_QUERY_EA                 0x07
#define IRP_MJ_SET_EA                   0x08
#define IRP_MJ_FLUSH_BUFFERS            0x09
#define IRP_MJ_QUERY_VOLUME_INFORMATION 0x0a
#define IRP_MJ_SET_VOLUME_INFORMATION   0x0b
#define IRP_MJ_DIRECTORY_CONTROL        0x0c
#define IRP_MJ_FILE_SYSTEM_CONTROL      0x0d
#define IRP_MJ_DEVICE_CONTROL           0x0e
#define IRP_MJ_INTERNAL_DEVICE_CONTROL  0x0f
#define IRP_MJ_SHUTDOWN                 0x10
#define IRP_MJ_LOCK_CONTROL             0x11
#define IRP_MJ_CLEANUP                  0x12
#define IRP_MJ_CREATE_MAILSLOT          0x13
#define IRP_MJ_QUERY_SECURITY           0x14
#define IRP_MJ_SET_SECURITY             0x15
#define IRP_MJ_POWER                    0x16
#define IRP_MJ_SYSTEM_CONTROL           0x17
#define IRP_MJ_DEVICE_CHANGE            0x18
#define IRP_MJ_QUERY_QUOTA              0x19
#define IRP_MJ_SET_QUOTA                0x1a
#define IRP_MJ_PNP                      0x1b
#define IRP_MJ_PNP_POWER                IRP_MJ_PNP      // Obsolete....
#define IRP_MJ_MAXIMUM_FUNCTION         0x1b

//
// Make the Scsi major code the same as internal device control.
//

#define IRP_MJ_SCSI                     IRP_MJ_INTERNAL_DEVICE_CONTROL

//
// Define the minor function codes for IRPs.  The lower 128 codes, from 0x00 to
// 0x7f are reserved to Microsoft.  The upper 128 codes, from 0x80 to 0xff, are
// reserved to customers of Microsoft.
//

//
// Device Control Request minor function codes for SCSI support. Note that
// user requests are assumed to be zero.
//

#define IRP_MN_SCSI_CLASS               0x01

//
// PNP minor function codes.
//

#define IRP_MN_START_DEVICE                 0x00
#define IRP_MN_QUERY_REMOVE_DEVICE          0x01
#define IRP_MN_REMOVE_DEVICE                0x02
#define IRP_MN_CANCEL_REMOVE_DEVICE         0x03
#define IRP_MN_STOP_DEVICE                  0x04
#define IRP_MN_QUERY_STOP_DEVICE            0x05
#define IRP_MN_CANCEL_STOP_DEVICE           0x06

#define IRP_MN_QUERY_DEVICE_RELATIONS       0x07
#define IRP_MN_QUERY_INTERFACE              0x08
#define IRP_MN_QUERY_CAPABILITIES           0x09
#define IRP_MN_QUERY_RESOURCES              0x0A
#define IRP_MN_QUERY_RESOURCE_REQUIREMENTS  0x0B
#define IRP_MN_QUERY_DEVICE_TEXT            0x0C
#define IRP_MN_FILTER_RESOURCE_REQUIREMENTS 0x0D

#define IRP_MN_READ_CONFIG                  0x0F
#define IRP_MN_WRITE_CONFIG                 0x10
#define IRP_MN_EJECT                        0x11
#define IRP_MN_SET_LOCK                     0x12
#define IRP_MN_QUERY_ID                     0x13
#define IRP_MN_QUERY_PNP_DEVICE_STATE       0x14
#define IRP_MN_QUERY_BUS_INFORMATION        0x15
#define IRP_MN_DEVICE_USAGE_NOTIFICATION    0x16
#define IRP_MN_SURPRISE_REMOVAL             0x17

#if (NTDDI_VERSION >= NTDDI_WIN7)
#define IRP_MN_DEVICE_ENUMERATED            0x19
#endif


//
// POWER minor function codes
//
#define IRP_MN_WAIT_WAKE                    0x00
#define IRP_MN_POWER_SEQUENCE               0x01
#define IRP_MN_SET_POWER                    0x02
#define IRP_MN_QUERY_POWER                  0x03


//
// WMI minor function codes under IRP_MJ_SYSTEM_CONTROL
//

#define IRP_MN_QUERY_ALL_DATA               0x00
#define IRP_MN_QUERY_SINGLE_INSTANCE        0x01
#define IRP_MN_CHANGE_SINGLE_INSTANCE       0x02
#define IRP_MN_CHANGE_SINGLE_ITEM           0x03
#define IRP_MN_ENABLE_EVENTS                0x04
#define IRP_MN_DISABLE_EVENTS               0x05
#define IRP_MN_ENABLE_COLLECTION            0x06
#define IRP_MN_DISABLE_COLLECTION           0x07
#define IRP_MN_REGINFO                      0x08
#define IRP_MN_EXECUTE_METHOD               0x09
// Minor code 0x0a is reserved
#define IRP_MN_REGINFO_EX                   0x0b
// Minor code 0x0c is reserved



//
// Define option flags for IoCreateFile.  Note that these values must be
// exactly the same as the SL_... flags for a create function.  Note also
// that there are flags that may be passed to IoCreateFile that are not
// placed in the stack location for the create IRP.  These flags start in
// the next byte.
//

#define IO_FORCE_ACCESS_CHECK           0x0001
#define IO_NO_PARAMETER_CHECKING        0x0100

//
// Define Information fields for whether or not a REPARSE or a REMOUNT has
// occurred in the file system.
//

#define IO_REPARSE                      0x0
#define IO_REMOUNT                      0x1

//
// Define the objects that can be created by IoCreateFile.
//

typedef enum _CREATE_FILE_TYPE {
    CreateFileTypeNone,
    CreateFileTypeNamedPipe,
    CreateFileTypeMailslot
} CREATE_FILE_TYPE;

//
// Define the structures used by the I/O system
//

//
// Define empty typedefs for the _IRP, _DEVICE_OBJECT, and _DRIVER_OBJECT
// structures so they may be referenced by function types before they are
// actually defined.
//
struct _DEVICE_DESCRIPTION;
struct _DEVICE_OBJECT;
struct _DMA_ADAPTER;
struct _DRIVER_OBJECT;
struct _DRIVE_LAYOUT_INFORMATION;
struct _DISK_PARTITION;

struct _FILE_OBJECT;

#if defined(_WIN64)
#define POINTER_ALIGNMENT DECLSPEC_ALIGN(8)
#else
#define POINTER_ALIGNMENT
#endif

struct DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT) _IRP;
struct _SCSI_REQUEST_BLOCK;
struct _SCATTER_GATHER_LIST;

//
// Define the I/O version of a DPC routine.
//

__drv_functionClass(IO_DPC_ROUTINE)
__drv_minFunctionIRQL(DISPATCH_LEVEL)
__drv_requiresIRQL(DISPATCH_LEVEL)
__drv_sameIRQL
typedef
VOID
IO_DPC_ROUTINE (
    __in PKDPC Dpc,
    __in struct _DEVICE_OBJECT *DeviceObject,
    __inout struct _IRP *Irp,
    __in_opt PVOID Context
    );

typedef IO_DPC_ROUTINE *PIO_DPC_ROUTINE;

//
// Define driver timer routine type.
//

__drv_functionClass(IO_TIMER_ROUTINE)
__drv_sameIRQL
typedef
VOID
IO_TIMER_ROUTINE (
    __in struct _DEVICE_OBJECT *DeviceObject,
    __in_opt PVOID Context
    );

typedef IO_TIMER_ROUTINE *PIO_TIMER_ROUTINE;

//
// Define driver initialization routine type.
//
__drv_functionClass(DRIVER_INITIALIZE)
__drv_sameIRQL
typedef
NTSTATUS
DRIVER_INITIALIZE (
    __in struct _DRIVER_OBJECT *DriverObject,
    __in PUNICODE_STRING RegistryPath
    );

typedef DRIVER_INITIALIZE *PDRIVER_INITIALIZE;

//
// Define driver cancel routine type.
//

__drv_functionClass(DRIVER_CANCEL)
__drv_mustHoldCancelSpinLock
__drv_releasesCancelSpinLock
__drv_minFunctionIRQL(DISPATCH_LEVEL)
__drv_requiresIRQL(DISPATCH_LEVEL)
typedef
VOID
DRIVER_CANCEL (
    __inout struct _DEVICE_OBJECT *DeviceObject,
    __inout __drv_useCancelIRQL struct _IRP *Irp
    );

typedef DRIVER_CANCEL *PDRIVER_CANCEL;

//
// Define driver dispatch routine type.
//

__drv_functionClass(DRIVER_DISPATCH)
__drv_requiresIRQL(PASSIVE_LEVEL)
__drv_sameIRQL
typedef
NTSTATUS
DRIVER_DISPATCH (
    __in struct _DEVICE_OBJECT *DeviceObject,
    __inout struct _IRP *Irp
    );

typedef DRIVER_DISPATCH *PDRIVER_DISPATCH;

//
// Define driver start I/O routine type.
//

__drv_functionClass(DRIVER_STARTIO)
__drv_minFunctionIRQL(DISPATCH_LEVEL)
__drv_requiresIRQL(DISPATCH_LEVEL)
__drv_sameIRQL
typedef
VOID
DRIVER_STARTIO (
    __inout struct _DEVICE_OBJECT *DeviceObject,
    __inout struct _IRP *Irp
    );

typedef DRIVER_STARTIO *PDRIVER_STARTIO;

//
// Define driver unload routine type.
//
__drv_functionClass(DRIVER_UNLOAD)
__drv_requiresIRQL(PASSIVE_LEVEL)
__drv_sameIRQL
typedef
VOID
DRIVER_UNLOAD (
    __in struct _DRIVER_OBJECT *DriverObject
    );

typedef DRIVER_UNLOAD *PDRIVER_UNLOAD;

//
// Define driver AddDevice routine type.
//

__drv_functionClass(DRIVER_ADD_DEVICE)
__drv_requiresIRQL(PASSIVE_LEVEL)
__drv_sameIRQL
__drv_when(return>=0, __drv_clearDoInit(yes))
typedef
NTSTATUS
DRIVER_ADD_DEVICE (
    __in struct _DRIVER_OBJECT *DriverObject,
    __in struct _DEVICE_OBJECT *PhysicalDeviceObject
    );

typedef DRIVER_ADD_DEVICE *PDRIVER_ADD_DEVICE;


//
// Define fast I/O procedure prototypes.
//
// Fast I/O read and write procedures.
//

__drv_functionClass(FAST_IO_CHECK_IF_POSSIBLE)
__drv_sameIRQL
typedef
BOOLEAN
FAST_IO_CHECK_IF_POSSIBLE (
    __in struct _FILE_OBJECT *FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in BOOLEAN Wait,
    __in ULONG LockKey,
    __in BOOLEAN CheckForReadOperation,
    __out PIO_STATUS_BLOCK IoStatus,
    __in struct _DEVICE_OBJECT *DeviceObject
    );

typedef FAST_IO_CHECK_IF_POSSIBLE *PFAST_IO_CHECK_IF_POSSIBLE;

__drv_functionClass(FAST_IO_READ)
__drv_sameIRQL
typedef
BOOLEAN
FAST_IO_READ (
    __in struct _FILE_OBJECT *FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in BOOLEAN Wait,
    __in ULONG LockKey,
    __out PVOID Buffer,
    __out PIO_STATUS_BLOCK IoStatus,
    __in struct _DEVICE_OBJECT *DeviceObject
    );

typedef FAST_IO_READ *PFAST_IO_READ;

__drv_functionClass(FAST_IO_WRITE)
__drv_sameIRQL
typedef
BOOLEAN
FAST_IO_WRITE (
    __in struct _FILE_OBJECT *FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in BOOLEAN Wait,
    __in ULONG LockKey,
    __in PVOID Buffer,
    __out PIO_STATUS_BLOCK IoStatus,
    __in struct _DEVICE_OBJECT *DeviceObject
    );

typedef FAST_IO_WRITE *PFAST_IO_WRITE;

//
// Fast I/O query basic and standard information procedures.
//

__drv_functionClass(FAST_IO_QUERY_BASIC_INFO)
__drv_sameIRQL
typedef
BOOLEAN
FAST_IO_QUERY_BASIC_INFO (
    __in struct _FILE_OBJECT *FileObject,
    __in BOOLEAN Wait,
    __out PFILE_BASIC_INFORMATION Buffer,
    __out PIO_STATUS_BLOCK IoStatus,
    __in struct _DEVICE_OBJECT *DeviceObject
    );

typedef FAST_IO_QUERY_BASIC_INFO *PFAST_IO_QUERY_BASIC_INFO;

__drv_functionClass(FAST_IO_QUERY_STANDARD_INFO)
__drv_sameIRQL
typedef
BOOLEAN
FAST_IO_QUERY_STANDARD_INFO (
    __in struct _FILE_OBJECT *FileObject,
    __in BOOLEAN Wait,
    __out PFILE_STANDARD_INFORMATION Buffer,
    __out PIO_STATUS_BLOCK IoStatus,
    __in struct _DEVICE_OBJECT *DeviceObject
    );

typedef FAST_IO_QUERY_STANDARD_INFO *PFAST_IO_QUERY_STANDARD_INFO;

//
// Fast I/O lock and unlock procedures.
//

__drv_functionClass(FAST_IO_LOCK)
__drv_sameIRQL
typedef
BOOLEAN
FAST_IO_LOCK (
    __in struct _FILE_OBJECT *FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in PLARGE_INTEGER Length,
    __in PEPROCESS ProcessId,
    __in ULONG Key,
    __in BOOLEAN FailImmediately,
    __in BOOLEAN ExclusiveLock,
    __out PIO_STATUS_BLOCK IoStatus,
    __in struct _DEVICE_OBJECT *DeviceObject
    );

typedef FAST_IO_LOCK *PFAST_IO_LOCK;

__drv_functionClass(FAST_IO_UNLOCK_SINGLE)
__drv_sameIRQL
typedef
BOOLEAN
FAST_IO_UNLOCK_SINGLE (
    __in struct _FILE_OBJECT *FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in PLARGE_INTEGER Length,
    __in PEPROCESS ProcessId,
    __in ULONG Key,
    __out PIO_STATUS_BLOCK IoStatus,
    __in struct _DEVICE_OBJECT *DeviceObject
    );

typedef FAST_IO_UNLOCK_SINGLE *PFAST_IO_UNLOCK_SINGLE;

__drv_functionClass(FAST_IO_UNLOCK_ALL)
__drv_sameIRQL
typedef
BOOLEAN
FAST_IO_UNLOCK_ALL (
    __in struct _FILE_OBJECT *FileObject,
    __in PEPROCESS ProcessId,
    __out PIO_STATUS_BLOCK IoStatus,
    __in struct _DEVICE_OBJECT *DeviceObject
    );

typedef FAST_IO_UNLOCK_ALL *PFAST_IO_UNLOCK_ALL;

__drv_functionClass(FAST_IO_UNLOCK_ALL_BY_KEY)
__drv_sameIRQL
typedef
BOOLEAN
FAST_IO_UNLOCK_ALL_BY_KEY (
    __in struct _FILE_OBJECT *FileObject,
    __in PVOID ProcessId,
    __in ULONG Key,
    __out PIO_STATUS_BLOCK IoStatus,
    __in struct _DEVICE_OBJECT *DeviceObject
    );

typedef FAST_IO_UNLOCK_ALL_BY_KEY *PFAST_IO_UNLOCK_ALL_BY_KEY;

//
// Fast I/O device control procedure.
//

__drv_functionClass(FAST_IO_DEVICE_CONTROL)
__drv_sameIRQL
typedef
BOOLEAN
FAST_IO_DEVICE_CONTROL (
    __in struct _FILE_OBJECT *FileObject,
    __in BOOLEAN Wait,
    __in_opt PVOID InputBuffer,
    __in ULONG InputBufferLength,
    __out_opt PVOID OutputBuffer,
    __in ULONG OutputBufferLength,
    __in ULONG IoControlCode,
    __out PIO_STATUS_BLOCK IoStatus,
    __in struct _DEVICE_OBJECT *DeviceObject
    );

typedef FAST_IO_DEVICE_CONTROL *PFAST_IO_DEVICE_CONTROL;

//
// Define callbacks for NtCreateSection to synchronize correctly with
// the file system.  It pre-acquires the resources that will be needed
// when calling to query and set file/allocation size in the file system.
//

__drv_functionClass(FAST_IO_ACQUIRE_FILE)
__drv_sameIRQL
typedef
VOID
FAST_IO_ACQUIRE_FILE (
    __in struct _FILE_OBJECT *FileObject
    );

typedef FAST_IO_ACQUIRE_FILE *PFAST_IO_ACQUIRE_FILE;

__drv_functionClass(FAST_IO_RELEASE_FILE)
__drv_sameIRQL
typedef
VOID
FAST_IO_RELEASE_FILE (
    __in struct _FILE_OBJECT *FileObject
    );

typedef FAST_IO_RELEASE_FILE *PFAST_IO_RELEASE_FILE;

//
// Define callback for drivers that have device objects attached to lower-
// level drivers' device objects.  This callback is made when the lower-level
// driver is deleting its device object.
//

__drv_functionClass(FAST_IO_DETACH_DEVICE)
__drv_sameIRQL
typedef
VOID
FAST_IO_DETACH_DEVICE (
    __in struct _DEVICE_OBJECT *SourceDevice,
    __in struct _DEVICE_OBJECT *TargetDevice
    );

typedef FAST_IO_DETACH_DEVICE *PFAST_IO_DETACH_DEVICE;

//
// This structure is used by the server to quickly get the information needed
// to service a server open call.  It is takes what would be two fast io calls
// one for basic information and the other for standard information and makes
// it into one call.
//

__drv_functionClass(FAST_IO_QUERY_NETWORK_OPEN_INFO)
__drv_sameIRQL
typedef
BOOLEAN
FAST_IO_QUERY_NETWORK_OPEN_INFO (
    __in struct _FILE_OBJECT *FileObject,
    __in BOOLEAN Wait,
    __out struct _FILE_NETWORK_OPEN_INFORMATION *Buffer,
    __out struct _IO_STATUS_BLOCK *IoStatus,
    __in struct _DEVICE_OBJECT *DeviceObject
    );

typedef FAST_IO_QUERY_NETWORK_OPEN_INFO *PFAST_IO_QUERY_NETWORK_OPEN_INFO;

//
//  Define Mdl-based routines for the server to call
//

__drv_functionClass(FAST_IO_MDL_READ)
__drv_sameIRQL
typedef
BOOLEAN
FAST_IO_MDL_READ (
    __in struct _FILE_OBJECT *FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in ULONG LockKey,
    __out PMDL *MdlChain,
    __out PIO_STATUS_BLOCK IoStatus,
    __in struct _DEVICE_OBJECT *DeviceObject
    );

typedef FAST_IO_MDL_READ *PFAST_IO_MDL_READ;

__drv_functionClass(FAST_IO_MDL_READ_COMPLETE)
__drv_sameIRQL
typedef
BOOLEAN
FAST_IO_MDL_READ_COMPLETE (
    __in struct _FILE_OBJECT *FileObject,
    __in PMDL MdlChain,
    __in struct _DEVICE_OBJECT *DeviceObject
    );

typedef FAST_IO_MDL_READ_COMPLETE *PFAST_IO_MDL_READ_COMPLETE;

__drv_functionClass(FAST_IO_PREPARE_MDL_WRITE)
__drv_sameIRQL
typedef
BOOLEAN
FAST_IO_PREPARE_MDL_WRITE (
    __in struct _FILE_OBJECT *FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in ULONG LockKey,
    __out PMDL *MdlChain,
    __out PIO_STATUS_BLOCK IoStatus,
    __in struct _DEVICE_OBJECT *DeviceObject
    );

typedef FAST_IO_PREPARE_MDL_WRITE *PFAST_IO_PREPARE_MDL_WRITE;

__drv_functionClass(FAST_IO_MDL_WRITE_COMPLETE)
__drv_sameIRQL
typedef
BOOLEAN
FAST_IO_MDL_WRITE_COMPLETE (
    __in struct _FILE_OBJECT *FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in PMDL MdlChain,
    __in struct _DEVICE_OBJECT *DeviceObject
    );

typedef FAST_IO_MDL_WRITE_COMPLETE *PFAST_IO_MDL_WRITE_COMPLETE;

//
//  If this routine is present, it will be called by FsRtl
//  to acquire the file for the mapped page writer.
//

__drv_functionClass(FAST_IO_ACQUIRE_FOR_MOD_WRITE)
__drv_sameIRQL
typedef
NTSTATUS
FAST_IO_ACQUIRE_FOR_MOD_WRITE (
    __in struct _FILE_OBJECT *FileObject,
    __in PLARGE_INTEGER EndingOffset,
    __out struct _ERESOURCE **ResourceToRelease,
    __in struct _DEVICE_OBJECT *DeviceObject
             );

typedef FAST_IO_ACQUIRE_FOR_MOD_WRITE *PFAST_IO_ACQUIRE_FOR_MOD_WRITE;

__drv_functionClass(FAST_IO_RELEASE_FOR_MOD_WRITE)
__drv_sameIRQL
typedef
NTSTATUS
FAST_IO_RELEASE_FOR_MOD_WRITE (
    __in struct _FILE_OBJECT *FileObject,
    __in struct _ERESOURCE *ResourceToRelease,
    __in struct _DEVICE_OBJECT *DeviceObject
             );

typedef FAST_IO_RELEASE_FOR_MOD_WRITE *PFAST_IO_RELEASE_FOR_MOD_WRITE;

//
//  If this routine is present, it will be called by FsRtl
//  to acquire the file for the mapped page writer.
//

__drv_functionClass(FAST_IO_ACQUIRE_FOR_CCFLUSH)
__drv_sameIRQL
typedef
NTSTATUS
FAST_IO_ACQUIRE_FOR_CCFLUSH (
    __in struct _FILE_OBJECT *FileObject,
    __in struct _DEVICE_OBJECT *DeviceObject
             );

typedef FAST_IO_ACQUIRE_FOR_CCFLUSH *PFAST_IO_ACQUIRE_FOR_CCFLUSH;

__drv_functionClass(FAST_IO_RELEASE_FOR_CCFLUSH)
__drv_sameIRQL
typedef
NTSTATUS
FAST_IO_RELEASE_FOR_CCFLUSH (
    __in struct _FILE_OBJECT *FileObject,
    __in struct _DEVICE_OBJECT *DeviceObject
             );

typedef FAST_IO_RELEASE_FOR_CCFLUSH *PFAST_IO_RELEASE_FOR_CCFLUSH;

__drv_functionClass(FAST_IO_READ_COMPRESSED)
__drv_sameIRQL
typedef
BOOLEAN
FAST_IO_READ_COMPRESSED (
    __in struct _FILE_OBJECT *FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in ULONG LockKey,
    __out PVOID Buffer,
    __out PMDL *MdlChain,
    __out PIO_STATUS_BLOCK IoStatus,
    __out struct _COMPRESSED_DATA_INFO *CompressedDataInfo,
    __in ULONG CompressedDataInfoLength,
    __in struct _DEVICE_OBJECT *DeviceObject
    );

typedef FAST_IO_READ_COMPRESSED *PFAST_IO_READ_COMPRESSED;

__drv_functionClass(FAST_IO_WRITE_COMPRESSED)
__drv_sameIRQL
typedef
BOOLEAN
FAST_IO_WRITE_COMPRESSED (
    __in struct _FILE_OBJECT *FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in ULONG LockKey,
    __in PVOID Buffer,
    __out PMDL *MdlChain,
    __out PIO_STATUS_BLOCK IoStatus,
    __in struct _COMPRESSED_DATA_INFO *CompressedDataInfo,
    __in ULONG CompressedDataInfoLength,
    __in struct _DEVICE_OBJECT *DeviceObject
    );

typedef FAST_IO_WRITE_COMPRESSED *PFAST_IO_WRITE_COMPRESSED;

__drv_functionClass(FAST_IO_MDL_READ_COMPLETE_COMPRESSED)
__drv_sameIRQL
typedef
BOOLEAN
FAST_IO_MDL_READ_COMPLETE_COMPRESSED (
    __in struct _FILE_OBJECT *FileObject,
    __in PMDL MdlChain,
    __in struct _DEVICE_OBJECT *DeviceObject
    );

typedef FAST_IO_MDL_READ_COMPLETE_COMPRESSED *PFAST_IO_MDL_READ_COMPLETE_COMPRESSED;

__drv_functionClass(FAST_IO_MDL_WRITE_COMPLETE_COMPRESSED)
__drv_sameIRQL
typedef
BOOLEAN
FAST_IO_MDL_WRITE_COMPLETE_COMPRESSED (
    __in struct _FILE_OBJECT *FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in PMDL MdlChain,
    __in struct _DEVICE_OBJECT *DeviceObject
    );

typedef FAST_IO_MDL_WRITE_COMPLETE_COMPRESSED *PFAST_IO_MDL_WRITE_COMPLETE_COMPRESSED;

__drv_functionClass(FAST_IO_QUERY_OPEN)
__drv_sameIRQL
typedef
BOOLEAN
FAST_IO_QUERY_OPEN (
    __inout struct _IRP *Irp,
    __out PFILE_NETWORK_OPEN_INFORMATION NetworkInformation,
    __in struct _DEVICE_OBJECT *DeviceObject
    );

typedef FAST_IO_QUERY_OPEN *PFAST_IO_QUERY_OPEN;

//
// Define the structure to describe the Fast I/O dispatch routines.  Any
// additions made to this structure MUST be added monotonically to the end
// of the structure, and fields CANNOT be removed from the middle.
//

typedef struct _FAST_IO_DISPATCH {
    ULONG SizeOfFastIoDispatch;
    PFAST_IO_CHECK_IF_POSSIBLE FastIoCheckIfPossible;
    PFAST_IO_READ FastIoRead;
    PFAST_IO_WRITE FastIoWrite;
    PFAST_IO_QUERY_BASIC_INFO FastIoQueryBasicInfo;
    PFAST_IO_QUERY_STANDARD_INFO FastIoQueryStandardInfo;
    PFAST_IO_LOCK FastIoLock;
    PFAST_IO_UNLOCK_SINGLE FastIoUnlockSingle;
    PFAST_IO_UNLOCK_ALL FastIoUnlockAll;
    PFAST_IO_UNLOCK_ALL_BY_KEY FastIoUnlockAllByKey;
    PFAST_IO_DEVICE_CONTROL FastIoDeviceControl;
    PFAST_IO_ACQUIRE_FILE AcquireFileForNtCreateSection;
    PFAST_IO_RELEASE_FILE ReleaseFileForNtCreateSection;
    PFAST_IO_DETACH_DEVICE FastIoDetachDevice;
    PFAST_IO_QUERY_NETWORK_OPEN_INFO FastIoQueryNetworkOpenInfo;
    PFAST_IO_ACQUIRE_FOR_MOD_WRITE AcquireForModWrite;
    PFAST_IO_MDL_READ MdlRead;
    PFAST_IO_MDL_READ_COMPLETE MdlReadComplete;
    PFAST_IO_PREPARE_MDL_WRITE PrepareMdlWrite;
    PFAST_IO_MDL_WRITE_COMPLETE MdlWriteComplete;
    PFAST_IO_READ_COMPRESSED FastIoReadCompressed;
    PFAST_IO_WRITE_COMPRESSED FastIoWriteCompressed;
    PFAST_IO_MDL_READ_COMPLETE_COMPRESSED MdlReadCompleteCompressed;
    PFAST_IO_MDL_WRITE_COMPLETE_COMPRESSED MdlWriteCompleteCompressed;
    PFAST_IO_QUERY_OPEN FastIoQueryOpen;
    PFAST_IO_RELEASE_FOR_MOD_WRITE ReleaseForModWrite;
    PFAST_IO_ACQUIRE_FOR_CCFLUSH AcquireForCcFlush;
    PFAST_IO_RELEASE_FOR_CCFLUSH ReleaseForCcFlush;
} FAST_IO_DISPATCH, *PFAST_IO_DISPATCH;

//
// Define the actions that a driver execution routine may request of the
// adapter/controller allocation routines upon return.
//

typedef enum _IO_ALLOCATION_ACTION {
    KeepObject = 1,
    DeallocateObject,
    DeallocateObjectKeepRegisters
} IO_ALLOCATION_ACTION, *PIO_ALLOCATION_ACTION;

//
// Define device driver adapter/controller execution routine.
//

typedef
__drv_functionClass(DRIVER_CONTROL)
__drv_sameIRQL
IO_ALLOCATION_ACTION
DRIVER_CONTROL (
    __in struct _DEVICE_OBJECT *DeviceObject,
    __inout struct _IRP *Irp,
    __in PVOID MapRegisterBase,
    __in PVOID Context
    );
typedef DRIVER_CONTROL *PDRIVER_CONTROL;

//
// Define the I/O system's security context type for use by file system's
// when checking access to volumes, files, and directories.
//

typedef struct _IO_SECURITY_CONTEXT {
    PSECURITY_QUALITY_OF_SERVICE SecurityQos;
    PACCESS_STATE AccessState;
    ACCESS_MASK DesiredAccess;
    ULONG FullCreateOptions;
} IO_SECURITY_CONTEXT, *PIO_SECURITY_CONTEXT;

//
// Define Volume Parameter Block (VPB) flags.
//

#define VPB_MOUNTED                     0x00000001
#define VPB_LOCKED                      0x00000002
#define VPB_PERSISTENT                  0x00000004
#define VPB_REMOVE_PENDING              0x00000008
#define VPB_RAW_MOUNT                   0x00000010
#define VPB_DIRECT_WRITES_ALLOWED       0x00000020


//
// Volume Parameter Block (VPB)
//

#define MAXIMUM_VOLUME_LABEL_LENGTH  (32 * sizeof(WCHAR)) // 32 characters

typedef struct _VPB {
    CSHORT Type;
    CSHORT Size;
    USHORT Flags;
    USHORT VolumeLabelLength; // in bytes
    struct _DEVICE_OBJECT *DeviceObject;
    struct _DEVICE_OBJECT *RealDevice;
    ULONG SerialNumber;
    ULONG ReferenceCount;
    WCHAR VolumeLabel[MAXIMUM_VOLUME_LABEL_LENGTH / sizeof(WCHAR)];
} VPB, *PVPB;


#if defined(_WIN64)

//
// Use __inline DMA macros (hal.h)
//
#ifndef USE_DMA_MACROS
#define USE_DMA_MACROS
#endif

//
// Only PnP drivers!
//
#ifndef NO_LEGACY_DRIVERS
#define NO_LEGACY_DRIVERS
#endif

#endif // _WIN64


#if defined(USE_DMA_MACROS) && !defined(_NTHAL_) && ( defined(_NTDDK_) || defined(_NTDRIVER_) || defined(_NTOSP_))

//
// Define object type specific fields of various objects used by the I/O system
//

typedef struct _DMA_ADAPTER *PADAPTER_OBJECT;

#elif defined(_WDM_INCLUDED_)

typedef struct _DMA_ADAPTER *PADAPTER_OBJECT;

#else

//
// Define object type specific fields of various objects used by the I/O system
//

typedef struct _ADAPTER_OBJECT *PADAPTER_OBJECT; 

#endif // USE_DMA_MACROS && (_NTDDK_ || _NTDRIVER_ || _NTOSP_)

//
// Define Wait Context Block (WCB)
//

typedef struct _WAIT_CONTEXT_BLOCK {
    KDEVICE_QUEUE_ENTRY WaitQueueEntry;
    PDRIVER_CONTROL DeviceRoutine;
    PVOID DeviceContext;
    ULONG NumberOfMapRegisters;
    PVOID DeviceObject;
    PVOID CurrentIrp;
    PKDPC BufferChainingDpc;
} WAIT_CONTEXT_BLOCK, *PWAIT_CONTEXT_BLOCK;

//
// Define Device Object (DO) flags
//
#define DO_VERIFY_VOLUME                    0x00000002      
#define DO_BUFFERED_IO                      0x00000004      
#define DO_EXCLUSIVE                        0x00000008      
#define DO_DIRECT_IO                        0x00000010      
#define DO_MAP_IO_BUFFER                    0x00000020      
#define DO_DEVICE_INITIALIZING              0x00000080      
#define DO_SHUTDOWN_REGISTERED              0x00000800      
#define DO_BUS_ENUMERATED_DEVICE            0x00001000      
#define DO_POWER_PAGABLE                    0x00002000      
#define DO_POWER_INRUSH                     0x00004000      
//
// Device Object structure definition
//

#if _MSC_VER >= 1200
#pragma warning(push)
#pragma warning(disable:4324) // structure was padded due to __declspec(align())
#endif

typedef struct DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT) _DEVICE_OBJECT {
    CSHORT Type;
    USHORT Size;
    LONG ReferenceCount;
    struct _DRIVER_OBJECT *DriverObject;
    struct _DEVICE_OBJECT *NextDevice;
    struct _DEVICE_OBJECT *AttachedDevice;
    struct _IRP *CurrentIrp;
    PIO_TIMER Timer;
    ULONG Flags;                                // See above:  DO_...
    ULONG Characteristics;                      // See ntioapi:  FILE_...
    __volatile PVPB Vpb;
    PVOID DeviceExtension;
    DEVICE_TYPE DeviceType;
    CCHAR StackSize;
    union {
        LIST_ENTRY ListEntry;
        WAIT_CONTEXT_BLOCK Wcb;
    } Queue;
    ULONG AlignmentRequirement;
    KDEVICE_QUEUE DeviceQueue;
    KDPC Dpc;

    //
    //  The following field is for exclusive use by the filesystem to keep
    //  track of the number of Fsp threads currently using the device
    //

    ULONG ActiveThreadCount;
    PSECURITY_DESCRIPTOR SecurityDescriptor;
    KEVENT DeviceLock;

    USHORT SectorSize;
    USHORT Spare1;

    struct _DEVOBJ_EXTENSION  *DeviceObjectExtension;
    PVOID  Reserved;

} DEVICE_OBJECT;

typedef struct _DEVICE_OBJECT *PDEVICE_OBJECT; 

#if _MSC_VER >= 1200
#pragma warning(pop)
#endif


struct  _DEVICE_OBJECT_POWER_EXTENSION;

typedef struct _DEVOBJ_EXTENSION {

    CSHORT          Type;
    USHORT          Size;

    //
    // Public part of the DeviceObjectExtension structure
    //

    PDEVICE_OBJECT  DeviceObject;               // owning device object


} DEVOBJ_EXTENSION, *PDEVOBJ_EXTENSION;

//
// Define Driver Object (DRVO) flags
//

#define DRVO_UNLOAD_INVOKED             0x00000001
#define DRVO_LEGACY_DRIVER              0x00000002
#define DRVO_BUILTIN_DRIVER             0x00000004    // Driver objects for Hal, PnP Mgr

typedef struct _DRIVER_EXTENSION {

    //
    // Back pointer to Driver Object
    //

    struct _DRIVER_OBJECT *DriverObject;

    //
    // The AddDevice entry point is called by the Plug & Play manager
    // to inform the driver when a new device instance arrives that this
    // driver must control.
    //

    PDRIVER_ADD_DEVICE AddDevice;

    //
    // The count field is used to count the number of times the driver has
    // had its registered reinitialization routine invoked.
    //

    ULONG Count;

    //
    // The service name field is used by the pnp manager to determine
    // where the driver related info is stored in the registry.
    //

    UNICODE_STRING ServiceKeyName;

    //
    // Note: any new shared fields get added here.
    //


} DRIVER_EXTENSION, *PDRIVER_EXTENSION;

typedef struct _DRIVER_OBJECT {
    CSHORT Type;
    CSHORT Size;

    //
    // The following links all of the devices created by a single driver
    // together on a list, and the Flags word provides an extensible flag
    // location for driver objects.
    //

    PDEVICE_OBJECT DeviceObject;
    ULONG Flags;

    //
    // The following section describes where the driver is loaded.  The count
    // field is used to count the number of times the driver has had its
    // registered reinitialization routine invoked.
    //

    PVOID DriverStart;
    ULONG DriverSize;
    PVOID DriverSection;
    PDRIVER_EXTENSION DriverExtension;

    //
    // The driver name field is used by the error log thread
    // determine the name of the driver that an I/O request is/was bound.
    //

    UNICODE_STRING DriverName;

    //
    // The following section is for registry support.  Thise is a pointer
    // to the path to the hardware information in the registry
    //

    PUNICODE_STRING HardwareDatabase;

    //
    // The following section contains the optional pointer to an array of
    // alternate entry points to a driver for "fast I/O" support.  Fast I/O
    // is performed by invoking the driver routine directly with separate
    // parameters, rather than using the standard IRP call mechanism.  Note
    // that these functions may only be used for synchronous I/O, and when
    // the file is cached.
    //

    PFAST_IO_DISPATCH FastIoDispatch;

    //
    // The following section describes the entry points to this particular
    // driver.  Note that the major function dispatch table must be the last
    // field in the object so that it remains extensible.
    //

    PDRIVER_INITIALIZE DriverInit;
    PDRIVER_STARTIO DriverStartIo;
    PDRIVER_UNLOAD DriverUnload;
    PDRIVER_DISPATCH MajorFunction[IRP_MJ_MAXIMUM_FUNCTION + 1];

} DRIVER_OBJECT;
typedef struct _DRIVER_OBJECT *PDRIVER_OBJECT; 



//
// The following structure is pointed to by the SectionObject pointer field
// of a file object, and is allocated by the various NT file systems.
//

typedef struct _SECTION_OBJECT_POINTERS {
    PVOID DataSectionObject;
    PVOID SharedCacheMap;
    PVOID ImageSectionObject;
} SECTION_OBJECT_POINTERS;
typedef SECTION_OBJECT_POINTERS *PSECTION_OBJECT_POINTERS;

//
// Define the format of a completion message.
//

typedef struct _IO_COMPLETION_CONTEXT {
    PVOID Port;
    PVOID Key;
} IO_COMPLETION_CONTEXT, *PIO_COMPLETION_CONTEXT;

//
// Define File Object (FO) flags
//

#define FO_FILE_OPEN                    0x00000001
#define FO_SYNCHRONOUS_IO               0x00000002
#define FO_ALERTABLE_IO                 0x00000004
#define FO_NO_INTERMEDIATE_BUFFERING    0x00000008
#define FO_WRITE_THROUGH                0x00000010
#define FO_SEQUENTIAL_ONLY              0x00000020
#define FO_CACHE_SUPPORTED              0x00000040
#define FO_NAMED_PIPE                   0x00000080
#define FO_STREAM_FILE                  0x00000100
#define FO_MAILSLOT                     0x00000200
#define FO_GENERATE_AUDIT_ON_CLOSE      0x00000400
#define FO_QUEUE_IRP_TO_THREAD          FO_GENERATE_AUDIT_ON_CLOSE
#define FO_DIRECT_DEVICE_OPEN           0x00000800
#define FO_FILE_MODIFIED                0x00001000
#define FO_FILE_SIZE_CHANGED            0x00002000
#define FO_CLEANUP_COMPLETE             0x00004000
#define FO_TEMPORARY_FILE               0x00008000
#define FO_DELETE_ON_CLOSE              0x00010000
#define FO_OPENED_CASE_SENSITIVE        0x00020000
#define FO_HANDLE_CREATED               0x00040000
#define FO_FILE_FAST_IO_READ            0x00080000
#define FO_RANDOM_ACCESS                0x00100000
#define FO_FILE_OPEN_CANCELLED          0x00200000
#define FO_VOLUME_OPEN                  0x00400000
#define FO_REMOTE_ORIGIN                0x01000000
#define FO_DISALLOW_EXCLUSIVE           0x02000000
#define FO_SKIP_COMPLETION_PORT         FO_DISALLOW_EXCLUSIVE
#define FO_SKIP_SET_EVENT               0x04000000
#define FO_SKIP_SET_FAST_IO             0x08000000

//
// This mask allows us to re-use flags that are not present during a create
// operation for uses that are only valid for the duration of the create.
//
#define FO_FLAGS_VALID_ONLY_DURING_CREATE FO_DISALLOW_EXCLUSIVE

typedef struct _FILE_OBJECT {
    CSHORT Type;
    CSHORT Size;
    PDEVICE_OBJECT DeviceObject;
    PVPB Vpb;
    PVOID FsContext;
    PVOID FsContext2;
    PSECTION_OBJECT_POINTERS SectionObjectPointer;
    PVOID PrivateCacheMap;
    NTSTATUS FinalStatus;
    struct _FILE_OBJECT *RelatedFileObject;
    BOOLEAN LockOperation;
    BOOLEAN DeletePending;
    BOOLEAN ReadAccess;
    BOOLEAN WriteAccess;
    BOOLEAN DeleteAccess;
    BOOLEAN SharedRead;
    BOOLEAN SharedWrite;
    BOOLEAN SharedDelete;
    ULONG Flags;
    UNICODE_STRING FileName;
    LARGE_INTEGER CurrentByteOffset;
    __volatile ULONG Waiters;
    __volatile ULONG Busy;
    PVOID LastLock;
    KEVENT Lock;
    KEVENT Event;
    __volatile PIO_COMPLETION_CONTEXT CompletionContext;
    KSPIN_LOCK IrpListLock;
    LIST_ENTRY IrpList;
    __volatile PVOID FileObjectExtension;
} FILE_OBJECT;
typedef struct _FILE_OBJECT *PFILE_OBJECT; 

//
// Define I/O Request Packet (IRP) flags
//

#define IRP_NOCACHE                     0x00000001
#define IRP_PAGING_IO                   0x00000002
#define IRP_MOUNT_COMPLETION            0x00000002
#define IRP_SYNCHRONOUS_API             0x00000004
#define IRP_ASSOCIATED_IRP              0x00000008
#define IRP_BUFFERED_IO                 0x00000010
#define IRP_DEALLOCATE_BUFFER           0x00000020
#define IRP_INPUT_OPERATION             0x00000040
#define IRP_SYNCHRONOUS_PAGING_IO       0x00000040
#define IRP_CREATE_OPERATION            0x00000080
#define IRP_READ_OPERATION              0x00000100
#define IRP_WRITE_OPERATION             0x00000200
#define IRP_CLOSE_OPERATION             0x00000400
#define IRP_DEFER_IO_COMPLETION         0x00000800
#define IRP_OB_QUERY_NAME               0x00001000
#define IRP_HOLD_DEVICE_QUEUE           0x00002000

//
// Define I/O request packet (IRP) alternate flags for allocation control.
//

#define IRP_QUOTA_CHARGED               0x01
#define IRP_ALLOCATED_MUST_SUCCEED      0x02
#define IRP_ALLOCATED_FIXED_SIZE        0x04
#define IRP_LOOKASIDE_ALLOCATION        0x08



//
// I/O Request Packet (IRP) definition
//

typedef struct DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT) _IRP {
    CSHORT Type;
    USHORT Size;

    //
    // Define the common fields used to control the IRP.
    //

    //
    // Define a pointer to the Memory Descriptor List (MDL) for this I/O
    // request.  This field is only used if the I/O is "direct I/O".
    //

    PMDL MdlAddress;

    //
    // Flags word - used to remember various flags.
    //

    ULONG Flags;

    //
    // The following union is used for one of three purposes:
    //
    //    1. This IRP is an associated IRP.  The field is a pointer to a master
    //       IRP.
    //
    //    2. This is the master IRP.  The field is the count of the number of
    //       IRPs which must complete (associated IRPs) before the master can
    //       complete.
    //
    //    3. This operation is being buffered and the field is the address of
    //       the system space buffer.
    //

    union {
        struct _IRP *MasterIrp;
        __volatile LONG IrpCount;
        PVOID SystemBuffer;
    } AssociatedIrp;

    //
    // Thread list entry - allows queueing the IRP to the thread pending I/O
    // request packet list.
    //

    LIST_ENTRY ThreadListEntry;

    //
    // I/O status - final status of operation.
    //

    IO_STATUS_BLOCK IoStatus;

    //
    // Requestor mode - mode of the original requestor of this operation.
    //

    KPROCESSOR_MODE RequestorMode;

    //
    // Pending returned - TRUE if pending was initially returned as the
    // status for this packet.
    //

    BOOLEAN PendingReturned;

    //
    // Stack state information.
    //

    CHAR StackCount;
    CHAR CurrentLocation;

    //
    // Cancel - packet has been canceled.
    //

    BOOLEAN Cancel;

    //
    // Cancel Irql - Irql at which the cancel spinlock was acquired.
    //

    KIRQL CancelIrql;

    //
    // ApcEnvironment - Used to save the APC environment at the time that the
    // packet was initialized.
    //

    CCHAR ApcEnvironment;

    //
    // Allocation control flags.
    //

    UCHAR AllocationFlags;

    //
    // User parameters.
    //

    PIO_STATUS_BLOCK UserIosb;
    PKEVENT UserEvent;
    union {
        struct {
            union {
                PIO_APC_ROUTINE UserApcRoutine;
                PVOID IssuingProcess;
            };
            PVOID UserApcContext;
        } AsynchronousParameters;
        LARGE_INTEGER AllocationSize;
    } Overlay;

    //
    // CancelRoutine - Used to contain the address of a cancel routine supplied
    // by a device driver when the IRP is in a cancelable state.
    //

    __volatile PDRIVER_CANCEL CancelRoutine;

    //
    // Note that the UserBuffer parameter is outside of the stack so that I/O
    // completion can copy data back into the user's address space without
    // having to know exactly which service was being invoked.  The length
    // of the copy is stored in the second half of the I/O status block. If
    // the UserBuffer field is NULL, then no copy is performed.
    //

    PVOID UserBuffer;

    //
    // Kernel structures
    //
    // The following section contains kernel structures which the IRP needs
    // in order to place various work information in kernel controller system
    // queues.  Because the size and alignment cannot be controlled, they are
    // placed here at the end so they just hang off and do not affect the
    // alignment of other fields in the IRP.
    //

    union {

        struct {

            union {

                //
                // DeviceQueueEntry - The device queue entry field is used to
                // queue the IRP to the device driver device queue.
                //

                KDEVICE_QUEUE_ENTRY DeviceQueueEntry;

                struct {

                    //
                    // The following are available to the driver to use in
                    // whatever manner is desired, while the driver owns the
                    // packet.
                    //

                    PVOID DriverContext[4];

                } ;

            } ;

            //
            // Thread - pointer to caller's Thread Control Block.
            //

            PETHREAD Thread;

            //
            // Auxiliary buffer - pointer to any auxiliary buffer that is
            // required to pass information to a driver that is not contained
            // in a normal buffer.
            //

            PCHAR AuxiliaryBuffer;

            //
            // The following unnamed structure must be exactly identical
            // to the unnamed structure used in the minipacket header used
            // for completion queue entries.
            //

            struct {

                //
                // List entry - used to queue the packet to completion queue, among
                // others.
                //

                LIST_ENTRY ListEntry;

                union {

                    //
                    // Current stack location - contains a pointer to the current
                    // IO_STACK_LOCATION structure in the IRP stack.  This field
                    // should never be directly accessed by drivers.  They should
                    // use the standard functions.
                    //

                    struct _IO_STACK_LOCATION *CurrentStackLocation;

                    //
                    // Minipacket type.
                    //

                    ULONG PacketType;
                };
            };

            //
            // Original file object - pointer to the original file object
            // that was used to open the file.  This field is owned by the
            // I/O system and should not be used by any other drivers.
            //

            PFILE_OBJECT OriginalFileObject;

        } Overlay;

        //
        // APC - This APC control block is used for the special kernel APC as
        // well as for the caller's APC, if one was specified in the original
        // argument list.  If so, then the APC is reused for the normal APC for
        // whatever mode the caller was in and the "special" routine that is
        // invoked before the APC gets control simply deallocates the IRP.
        //

        KAPC Apc;

        //
        // CompletionKey - This is the key that is used to distinguish
        // individual I/O operations initiated on a single file handle.
        //

        PVOID CompletionKey;

    } Tail;

} IRP;

typedef IRP *PIRP;

//
// Define completion routine types for use in stack locations in an IRP
//

__drv_functionClass(IO_COMPLETION_ROUTINE)
__drv_sameIRQL
typedef
NTSTATUS
IO_COMPLETION_ROUTINE (
    __in PDEVICE_OBJECT DeviceObject,
    __in PIRP Irp,
    __in_xcount_opt("varies") PVOID Context
    );

typedef IO_COMPLETION_ROUTINE *PIO_COMPLETION_ROUTINE;

//
// Define stack location control flags
//

#define SL_PENDING_RETURNED             0x01
#define SL_ERROR_RETURNED               0x02
#define SL_INVOKE_ON_CANCEL             0x20
#define SL_INVOKE_ON_SUCCESS            0x40
#define SL_INVOKE_ON_ERROR              0x80

//
// Define flags for various functions
//

//
// Create / Create Named Pipe
//
// The following flags must exactly match those in the IoCreateFile call's
// options.  The case sensitive flag is added in later, by the parse routine,
// and is not an actual option to open.  Rather, it is part of the object
// manager's attributes structure.
//

#define SL_FORCE_ACCESS_CHECK           0x01
#define SL_OPEN_PAGING_FILE             0x02
#define SL_OPEN_TARGET_DIRECTORY        0x04
#define SL_STOP_ON_SYMLINK              0x08


#define SL_CASE_SENSITIVE               0x80

//
// Read / Write
//

#define SL_KEY_SPECIFIED                0x01
#define SL_OVERRIDE_VERIFY_VOLUME       0x02
#define SL_WRITE_THROUGH                0x04
#define SL_FT_SEQUENTIAL_WRITE          0x08
#define SL_FORCE_DIRECT_WRITE           0x10
#define SL_REALTIME_STREAM              0x20

//
// Device I/O Control
//
//
// Same SL_OVERRIDE_VERIFY_VOLUME as for read/write above.
//

#define SL_READ_ACCESS_GRANTED          0x01
#define SL_WRITE_ACCESS_GRANTED         0x04    // Gap for SL_OVERRIDE_VERIFY_VOLUME

//
// Lock
//

#define SL_FAIL_IMMEDIATELY             0x01
#define SL_EXCLUSIVE_LOCK               0x02

//
// QueryDirectory / QueryEa / QueryQuota
//

#define SL_RESTART_SCAN                 0x01
#define SL_RETURN_SINGLE_ENTRY          0x02
#define SL_INDEX_SPECIFIED              0x04

//
// NotifyDirectory
//

#define SL_WATCH_TREE                   0x01

//
// FileSystemControl
//
//    minor: mount/verify volume
//

#define SL_ALLOW_RAW_MOUNT              0x01

//
// Define PNP/POWER types required by IRP_MJ_PNP/IRP_MJ_POWER.
//

typedef enum _DEVICE_RELATION_TYPE {
    BusRelations,
    EjectionRelations,
    PowerRelations,
    RemovalRelations,
    TargetDeviceRelation,
    SingleBusRelations,
    TransportRelations
} DEVICE_RELATION_TYPE, *PDEVICE_RELATION_TYPE;

typedef struct _DEVICE_RELATIONS {
    ULONG Count;
    PDEVICE_OBJECT Objects[1];  // variable length
} DEVICE_RELATIONS, *PDEVICE_RELATIONS;

typedef enum _DEVICE_USAGE_NOTIFICATION_TYPE {
    DeviceUsageTypeUndefined,
    DeviceUsageTypePaging,
    DeviceUsageTypeHibernation,
    DeviceUsageTypeDumpFile
} DEVICE_USAGE_NOTIFICATION_TYPE;



// workaround overloaded definition (rpc generated headers all define INTERFACE
// to match the class name).
#undef INTERFACE

typedef struct _INTERFACE {
    USHORT Size;
    USHORT Version;
    PVOID Context;
    PINTERFACE_REFERENCE InterfaceReference;
    PINTERFACE_DEREFERENCE InterfaceDereference;
    // interface specific entries go here
} INTERFACE, *PINTERFACE;



typedef __struct_bcount(Size) struct _DEVICE_CAPABILITIES {
    USHORT Size;
    USHORT Version;  // the version documented here is version 1
    ULONG DeviceD1:1;
    ULONG DeviceD2:1;
    ULONG LockSupported:1;
    ULONG EjectSupported:1; // Ejectable in S0
    ULONG Removable:1;
    ULONG DockDevice:1;
    ULONG UniqueID:1;
    ULONG SilentInstall:1;
    ULONG RawDeviceOK:1;
    ULONG SurpriseRemovalOK:1;
    ULONG WakeFromD0:1;
    ULONG WakeFromD1:1;
    ULONG WakeFromD2:1;
    ULONG WakeFromD3:1;
    ULONG HardwareDisabled:1;
    ULONG NonDynamic:1;
    ULONG WarmEjectSupported:1;
    ULONG NoDisplayInUI:1;
    ULONG Reserved1:1;
    ULONG Reserved:13;

    ULONG Address;
    ULONG UINumber;

    DEVICE_POWER_STATE DeviceState[POWER_SYSTEM_MAXIMUM];
    SYSTEM_POWER_STATE SystemWake;
    DEVICE_POWER_STATE DeviceWake;
    ULONG D1Latency;
    ULONG D2Latency;
    ULONG D3Latency;
} DEVICE_CAPABILITIES, *PDEVICE_CAPABILITIES;

typedef struct _POWER_SEQUENCE {
    ULONG SequenceD1;
    ULONG SequenceD2;
    ULONG SequenceD3;
} POWER_SEQUENCE, *PPOWER_SEQUENCE;

typedef enum {
    BusQueryDeviceID = 0,       // <Enumerator>\<Enumerator-specific device id>
    BusQueryHardwareIDs = 1,    // Hardware ids
    BusQueryCompatibleIDs = 2,  // compatible device ids
    BusQueryInstanceID = 3,     // persistent id for this instance of the device
    BusQueryDeviceSerialNumber = 4,   // serial number for this device
    BusQueryContainerID = 5     // unique id of the device's physical container
} BUS_QUERY_ID_TYPE, *PBUS_QUERY_ID_TYPE;

typedef ULONG PNP_DEVICE_STATE, *PPNP_DEVICE_STATE;

#define PNP_DEVICE_DISABLED                      0x00000001
#define PNP_DEVICE_DONT_DISPLAY_IN_UI            0x00000002
#define PNP_DEVICE_FAILED                        0x00000004
#define PNP_DEVICE_REMOVED                       0x00000008
#define PNP_DEVICE_RESOURCE_REQUIREMENTS_CHANGED 0x00000010
#define PNP_DEVICE_NOT_DISABLEABLE               0x00000020

typedef enum {
    DeviceTextDescription = 0,            // DeviceDesc property
    DeviceTextLocationInformation = 1     // DeviceLocation property
} DEVICE_TEXT_TYPE, *PDEVICE_TEXT_TYPE;

//
// Define I/O Request Packet (IRP) stack locations
//

#if !defined(_AMD64_) && !defined(_IA64_)
#include "pshpack4.h"
#endif



#if defined(_WIN64)
#define POINTER_ALIGNMENT DECLSPEC_ALIGN(8)
#else
#define POINTER_ALIGNMENT
#endif



#if _MSC_VER >= 1200
#pragma warning(push)
#pragma warning(disable:4324) // structure was padded due to __declspec(align())
#endif

typedef struct _IO_STACK_LOCATION {
    UCHAR MajorFunction;
    UCHAR MinorFunction;
    UCHAR Flags;
    UCHAR Control;

    //
    // The following user parameters are based on the service that is being
    // invoked.  Drivers and file systems can determine which set to use based
    // on the above major and minor function codes.
    //

    union {

        //
        // System service parameters for:  NtCreateFile
        //

        struct {
            PIO_SECURITY_CONTEXT SecurityContext;
            ULONG Options;
            USHORT POINTER_ALIGNMENT FileAttributes;
            USHORT ShareAccess;
            ULONG POINTER_ALIGNMENT EaLength;
        } Create;


        //
        // System service parameters for:  NtReadFile
        //

        struct {
            ULONG Length;
            ULONG POINTER_ALIGNMENT Key;
            LARGE_INTEGER ByteOffset;
        } Read;

        //
        // System service parameters for:  NtWriteFile
        //

        struct {
            ULONG Length;
            ULONG POINTER_ALIGNMENT Key;
            LARGE_INTEGER ByteOffset;
        } Write;

        //
        // System service parameters for:  NtQueryDirectoryFile
        //

        struct {
            ULONG Length;
            PUNICODE_STRING FileName;
            FILE_INFORMATION_CLASS FileInformationClass;
            ULONG POINTER_ALIGNMENT FileIndex;
        } QueryDirectory;

        //
        // System service parameters for:  NtNotifyChangeDirectoryFile
        //

        struct {
            ULONG Length;
            ULONG POINTER_ALIGNMENT CompletionFilter;
        } NotifyDirectory;

        //
        // System service parameters for:  NtQueryInformationFile
        //

        struct {
            ULONG Length;
            FILE_INFORMATION_CLASS POINTER_ALIGNMENT FileInformationClass;
        } QueryFile;

        //
        // System service parameters for:  NtSetInformationFile
        //

        struct {
            ULONG Length;
            FILE_INFORMATION_CLASS POINTER_ALIGNMENT FileInformationClass;
            PFILE_OBJECT FileObject;
            union {
                struct {
                    BOOLEAN ReplaceIfExists;
                    BOOLEAN AdvanceOnly;
                };
                ULONG ClusterCount;
                HANDLE DeleteHandle;
            };
        } SetFile;



        //
        // System service parameters for:  NtQueryEaFile
        //

        struct {
            ULONG Length;
            PVOID EaList;
            ULONG EaListLength;
            ULONG POINTER_ALIGNMENT EaIndex;
        } QueryEa;

        //
        // System service parameters for:  NtSetEaFile
        //

        struct {
            ULONG Length;
        } SetEa;



        //
        // System service parameters for:  NtQueryVolumeInformationFile
        //

        struct {
            ULONG Length;
            FS_INFORMATION_CLASS POINTER_ALIGNMENT FsInformationClass;
        } QueryVolume;



        //
        // System service parameters for:  NtSetVolumeInformationFile
        //

        struct {
            ULONG Length;
            FS_INFORMATION_CLASS POINTER_ALIGNMENT FsInformationClass;
        } SetVolume;

        //
        // System service parameters for:  NtFsControlFile
        //
        // Note that the user's output buffer is stored in the UserBuffer field
        // and the user's input buffer is stored in the SystemBuffer field.
        //

        struct {
            ULONG OutputBufferLength;
            ULONG POINTER_ALIGNMENT InputBufferLength;
            ULONG POINTER_ALIGNMENT FsControlCode;
            PVOID Type3InputBuffer;
        } FileSystemControl;
        //
        // System service parameters for:  NtLockFile/NtUnlockFile
        //

        struct {
            PLARGE_INTEGER Length;
            ULONG POINTER_ALIGNMENT Key;
            LARGE_INTEGER ByteOffset;
        } LockControl;

        //
        // System service parameters for:  NtFlushBuffersFile
        //
        // No extra user-supplied parameters.
        //



        //
        // System service parameters for:  NtCancelIoFile
        //
        // No extra user-supplied parameters.
        //



        //
        // System service parameters for:  NtDeviceIoControlFile
        //
        // Note that the user's output buffer is stored in the UserBuffer field
        // and the user's input buffer is stored in the SystemBuffer field.
        //

        struct {
            ULONG OutputBufferLength;
            ULONG POINTER_ALIGNMENT InputBufferLength;
            ULONG POINTER_ALIGNMENT IoControlCode;
            PVOID Type3InputBuffer;
        } DeviceIoControl;

        //
        // System service parameters for:  NtQuerySecurityObject
        //

        struct {
            SECURITY_INFORMATION SecurityInformation;
            ULONG POINTER_ALIGNMENT Length;
        } QuerySecurity;

        //
        // System service parameters for:  NtSetSecurityObject
        //

        struct {
            SECURITY_INFORMATION SecurityInformation;
            PSECURITY_DESCRIPTOR SecurityDescriptor;
        } SetSecurity;

        //
        // Non-system service parameters.
        //
        // Parameters for MountVolume
        //

        struct {
            PVPB Vpb;
            PDEVICE_OBJECT DeviceObject;
        } MountVolume;

        //
        // Parameters for VerifyVolume
        //

        struct {
            PVPB Vpb;
            PDEVICE_OBJECT DeviceObject;
        } VerifyVolume;

        //
        // Parameters for Scsi with internal device contorl.
        //

        struct {
            struct _SCSI_REQUEST_BLOCK *Srb;
        } Scsi;



        //
        // System service parameters for:  NtQueryQuotaInformationFile
        //

        struct {
            ULONG Length;
            PSID StartSid;
            PFILE_GET_QUOTA_INFORMATION SidList;
            ULONG SidListLength;
        } QueryQuota;

        //
        // System service parameters for:  NtSetQuotaInformationFile
        //

        struct {
            ULONG Length;
        } SetQuota;



        //
        // Parameters for IRP_MN_QUERY_DEVICE_RELATIONS
        //

        struct {
            DEVICE_RELATION_TYPE Type;
        } QueryDeviceRelations;

        //
        // Parameters for IRP_MN_QUERY_INTERFACE
        //

        struct {
            CONST GUID *InterfaceType;
            USHORT Size;
            USHORT Version;
            PINTERFACE Interface;
            PVOID InterfaceSpecificData;
        } QueryInterface;

        //
        // Parameters for IRP_MN_QUERY_CAPABILITIES
        //

        struct {
            PDEVICE_CAPABILITIES Capabilities;
        } DeviceCapabilities;

        //
        // Parameters for IRP_MN_FILTER_RESOURCE_REQUIREMENTS
        //

        struct {
            PIO_RESOURCE_REQUIREMENTS_LIST IoResourceRequirementList;
        } FilterResourceRequirements;

        //
        // Parameters for IRP_MN_READ_CONFIG and IRP_MN_WRITE_CONFIG
        //

        struct {
            ULONG WhichSpace;
            PVOID Buffer;
            ULONG Offset;
            ULONG POINTER_ALIGNMENT Length;
        } ReadWriteConfig;

        //
        // Parameters for IRP_MN_SET_LOCK
        //

        struct {
            BOOLEAN Lock;
        } SetLock;

        //
        // Parameters for IRP_MN_QUERY_ID
        //

        struct {
            BUS_QUERY_ID_TYPE IdType;
        } QueryId;

        //
        // Parameters for IRP_MN_QUERY_DEVICE_TEXT
        //

        struct {
            DEVICE_TEXT_TYPE DeviceTextType;
            LCID POINTER_ALIGNMENT LocaleId;
        } QueryDeviceText;

        //
        // Parameters for IRP_MN_DEVICE_USAGE_NOTIFICATION
        //

        struct {
            BOOLEAN InPath;
            BOOLEAN Reserved[3];
            DEVICE_USAGE_NOTIFICATION_TYPE POINTER_ALIGNMENT Type;
        } UsageNotification;

        //
        // Parameters for IRP_MN_WAIT_WAKE
        //

        struct {
            SYSTEM_POWER_STATE PowerState;
        } WaitWake;

        //
        // Parameter for IRP_MN_POWER_SEQUENCE
        //

        struct {
            PPOWER_SEQUENCE PowerSequence;
        } PowerSequence;

        //
        // Parameters for IRP_MN_SET_POWER and IRP_MN_QUERY_POWER
        //

#if (NTDDI_VERSION >= NTDDI_VISTA)
        struct {
            union {
                ULONG SystemContext;
                SYSTEM_POWER_STATE_CONTEXT SystemPowerStateContext;
            };
            POWER_STATE_TYPE POINTER_ALIGNMENT Type;
            POWER_STATE POINTER_ALIGNMENT State;
            POWER_ACTION POINTER_ALIGNMENT ShutdownType;
        } Power;
#else
        struct {
            ULONG SystemContext;
            POWER_STATE_TYPE POINTER_ALIGNMENT Type;
            POWER_STATE POINTER_ALIGNMENT State;
            POWER_ACTION POINTER_ALIGNMENT ShutdownType;
        } Power;
#endif // (NTDDI_VERSION >= NTDDI_VISTA)

        //
        // Parameters for StartDevice
        //

        struct {
            PCM_RESOURCE_LIST AllocatedResources;
            PCM_RESOURCE_LIST AllocatedResourcesTranslated;
        } StartDevice;

        //
        // Parameters for Cleanup
        //
        // No extra parameters supplied
        //

        //
        // WMI Irps
        //

        struct {
            ULONG_PTR ProviderId;
            PVOID DataPath;
            ULONG BufferSize;
            PVOID Buffer;
        } WMI;

        //
        // Others - driver-specific
        //

        struct {
            PVOID Argument1;
            PVOID Argument2;
            PVOID Argument3;
            PVOID Argument4;
        } Others;

    } Parameters;

    //
    // Save a pointer to this device driver's device object for this request
    // so it can be passed to the completion routine if needed.
    //

    PDEVICE_OBJECT DeviceObject;

    //
    // The following location contains a pointer to the file object for this
    // request.
    //

    PFILE_OBJECT FileObject;

    //
    // The following routine is invoked depending on the flags in the above
    // flags field.
    //

    PIO_COMPLETION_ROUTINE CompletionRoutine;

    //
    // The following is used to store the address of the context parameter
    // that should be passed to the CompletionRoutine.
    //

    PVOID Context;

} IO_STACK_LOCATION, *PIO_STACK_LOCATION;

#if _MSC_VER >= 1200
#pragma warning(pop)
#endif

#if !defined(_AMD64_) && !defined(_IA64_)
#include "poppack.h"
#endif

//
// Define the share access structure used by file systems to determine
// whether or not another accessor may open the file.
//

typedef struct _SHARE_ACCESS {
    ULONG OpenCount;
    ULONG Readers;
    ULONG Writers;
    ULONG Deleters;
    ULONG SharedRead;
    ULONG SharedWrite;
    ULONG SharedDelete;
} SHARE_ACCESS, *PSHARE_ACCESS;

//
// Public I/O routine definitions
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_acquiresCancelSpinLock
__drv_neverHoldCancelSpinLock
__drv_maxIRQL(DISPATCH_LEVEL)
__drv_setsIRQL(DISPATCH_LEVEL)
NTKERNELAPI
VOID
IoAcquireCancelSpinLock(
    __out __deref __drv_savesIRQL PKIRQL Irql
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
__drv_valueIs(<0;==0)
NTKERNELAPI
NTSTATUS
IoAllocateDriverObjectExtension(
    __in  PDRIVER_OBJECT DriverObject,
    __in  PVOID ClientIdentificationAddress,
    __in  ULONG DriverObjectExtensionSize,
    // When successful, this always allocates already-aliased memory.
    __post __deref __drv_when(return==0,
    __out __drv_aliasesMem __drv_allocatesMem(Mem) __drv_valueIs(!=0))
    PVOID *DriverObjectExtension
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
PVOID
IoAllocateErrorLogEntry(
    __in PVOID IoObject,
    __in UCHAR EntrySize
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
PIRP
IoAllocateIrp(
    __in CCHAR StackSize,
    __in BOOLEAN ChargeQuota
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
PMDL
IoAllocateMdl(
    __in_opt __drv_aliasesMem PVOID VirtualAddress,
    __in ULONG Length,
    __in BOOLEAN SecondaryBuffer,
    __in BOOLEAN ChargeQuota,
    __inout_opt PIRP Irp
    );
#endif

typedef enum _IO_PAGING_PRIORITY {
    IoPagingPriorityInvalid,        // Returned if a non-paging IO IRP is passed.
    IoPagingPriorityNormal,         // For regular paging IO
    IoPagingPriorityHigh,           // For high priority paging IO
    IoPagingPriorityReserved1,      // Reserved for future use.
    IoPagingPriorityReserved2       // Reserved for future use.
} IO_PAGING_PRIORITY;

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
__drv_valueIs(==0;<0)
NTKERNELAPI
NTSTATUS
IoAttachDevice(
    __in __drv_mustHold(Memory) __drv_when(return==0, __drv_aliasesMem)
    PDEVICE_OBJECT SourceDevice,
    __in  PUNICODE_STRING TargetDevice,
    __out PDEVICE_OBJECT *AttachedDevice
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn
__drv_maxIRQL(DISPATCH_LEVEL)
__drv_valueIs(!=0;==0)
NTKERNELAPI
PDEVICE_OBJECT
IoAttachDeviceToDeviceStack(
    __in __drv_mustHold(Memory) __drv_when(return!=0, __drv_aliasesMem)
    PDEVICE_OBJECT SourceDevice,
    __in PDEVICE_OBJECT TargetDevice
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn
__drv_aliasesMem
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
PIRP
IoBuildAsynchronousFsdRequest(
    __in ULONG MajorFunction,
    __in PDEVICE_OBJECT DeviceObject,
    __inout_opt PVOID Buffer,
    __in_opt ULONG Length,
    __in_opt PLARGE_INTEGER StartingOffset,
    __in_opt PIO_STATUS_BLOCK IoStatusBlock
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn
__drv_aliasesMem
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
PIRP
IoBuildDeviceIoControlRequest(
    __in  ULONG IoControlCode,
    __in  PDEVICE_OBJECT DeviceObject,
    __in_opt  PVOID InputBuffer,
    __in  ULONG InputBufferLength,
    __out_opt PVOID OutputBuffer,
    __in ULONG OutputBufferLength,
    __in BOOLEAN InternalDeviceIoControl,
    __in PKEVENT Event,
    __out PIO_STATUS_BLOCK IoStatusBlock
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
VOID
IoBuildPartialMdl(
    __in PMDL SourceMdl,
    __inout PMDL TargetMdl,
    __in PVOID VirtualAddress,
    __in ULONG Length
    );
#endif

typedef struct _BOOTDISK_INFORMATION {
    LONGLONG BootPartitionOffset;
    LONGLONG SystemPartitionOffset;
    ULONG BootDeviceSignature;
    ULONG SystemDeviceSignature;
} BOOTDISK_INFORMATION, *PBOOTDISK_INFORMATION;

//
// This structure should follow the previous structure field for field.
//
typedef struct _BOOTDISK_INFORMATION_EX {
    LONGLONG BootPartitionOffset;
    LONGLONG SystemPartitionOffset;
    ULONG BootDeviceSignature;
    ULONG SystemDeviceSignature;
    GUID BootDeviceGuid;
    GUID SystemDeviceGuid;
    BOOLEAN BootDeviceIsGpt;
    BOOLEAN SystemDeviceIsGpt;
} BOOTDISK_INFORMATION_EX, *PBOOTDISK_INFORMATION_EX;

#if (NTDDI_VERSION >= NTDDI_WIN7)
typedef struct _LOADER_PARTITION_INFORMATION_EX {
    ULONG PartitionStyle;
    ULONG PartitionNumber;
    union {
        ULONG Signature;
        GUID DeviceId;
    };
    ULONG Flags;
} LOADER_PARTITION_INFORMATION_EX, *PLOADER_PARTITION_INFORMATION_EX;

typedef struct _BOOTDISK_INFORMATION_LITE {
    ULONG NumberEntries;
    LOADER_PARTITION_INFORMATION_EX Entries[1];
} BOOTDISK_INFORMATION_LITE, *PBOOTDISK_INFORMATION_LITE;
#else

#if (NTDDI_VERSION >= NTDDI_VISTA)
typedef struct _BOOTDISK_INFORMATION_LITE {
    ULONG BootDeviceSignature;
    ULONG SystemDeviceSignature;
    GUID BootDeviceGuid;
    GUID SystemDeviceGuid;
    BOOLEAN BootDeviceIsGpt;
    BOOLEAN SystemDeviceIsGpt;
} BOOTDISK_INFORMATION_LITE, *PBOOTDISK_INFORMATION_LITE;
#endif // NTDDI_VERSION >= NTDDI_VISTA

#endif // NTDDI_VERSION >= NTDDI_VISTA

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
IoGetBootDiskInformation(
    __inout PBOOTDISK_INFORMATION BootDiskInformation,
    __in ULONG Size
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
NTKERNELAPI
NTSTATUS
IoGetBootDiskInformationLite(
    __deref_out PBOOTDISK_INFORMATION_LITE *BootDiskInformation
    );

#endif // NTDDI_VERSION >= NTDDI_VISTA


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn
__drv_aliasesMem
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
PIRP
IoBuildSynchronousFsdRequest(
    __in  ULONG MajorFunction,
    __in  PDEVICE_OBJECT DeviceObject,
    __inout_opt PVOID Buffer,
    __in_opt ULONG Length,
    __in_opt PLARGE_INTEGER StartingOffset,
    __in  PKEVENT Event,
    __out PIO_STATUS_BLOCK IoStatusBlock
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
__success(TRUE)
NTKERNELAPI
NTSTATUS
FASTCALL
IofCallDriver(
    __in PDEVICE_OBJECT DeviceObject,
    __inout __drv_aliasesMem PIRP Irp
    );
#endif

#define IoCallDriver(a,b)   \
        IofCallDriver(a,b)


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
BOOLEAN
IoCancelIrp(
    __in PIRP Irp
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
NTSTATUS
IoCheckShareAccess(
    __in ACCESS_MASK DesiredAccess,
    __in ULONG DesiredShareAccess,
    __inout PFILE_OBJECT FileObject,
    __inout PSHARE_ACCESS ShareAccess,
    __in BOOLEAN Update
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
NTKERNELAPI
NTSTATUS
IoCheckShareAccessEx(
    __in ACCESS_MASK DesiredAccess,
    __in ULONG DesiredShareAccess,
    __inout PFILE_OBJECT FileObject,
    __inout PSHARE_ACCESS ShareAccess,
    __in BOOLEAN Update,
    __in PBOOLEAN WritePermission
    );
#endif

//
// This value should be returned from completion routines to continue
// completing the IRP upwards. Otherwise, STATUS_MORE_PROCESSING_REQUIRED
// should be returned.
//
#define STATUS_CONTINUE_COMPLETION      STATUS_SUCCESS

//
// Completion routines can also use this enumeration in place of status codes.
//
typedef enum _IO_COMPLETION_ROUTINE_RESULT {

    ContinueCompletion = STATUS_CONTINUE_COMPLETION,
    StopCompletion = STATUS_MORE_PROCESSING_REQUIRED

} IO_COMPLETION_ROUTINE_RESULT, *PIO_COMPLETION_ROUTINE_RESULT;

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
__drv_neverHold(KeSpinLockType)
NTKERNELAPI
VOID
FASTCALL
IofCompleteRequest(
    __in PIRP Irp,
    __in CCHAR PriorityBoost
    );
#endif

#define IoCompleteRequest(a,b)  \
        IofCompleteRequest(a,b)

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
NTSTATUS
IoConnectInterrupt(
    __out PKINTERRUPT *InterruptObject,
    __in  PKSERVICE_ROUTINE ServiceRoutine,
    __in_opt PVOID ServiceContext,
    __in_opt PKSPIN_LOCK SpinLock,
    __in  ULONG Vector,
    __in  KIRQL Irql,
    __in  KIRQL SynchronizeIrql,
    __in  KINTERRUPT_MODE InterruptMode,
    __in  BOOLEAN ShareVector,
    __in  KAFFINITY ProcessorEnableMask,
    __in  BOOLEAN FloatingSave
    );
#endif

//
// Interrupt message information table entry definition
//

typedef struct _IO_INTERRUPT_MESSAGE_INFO_ENTRY {

    //
    // Message address - indicates the address the device should use to
    // generate this message signaled interrupt.
    //

    PHYSICAL_ADDRESS MessageAddress;

    //
    // Target processor set - indicates the set of processors that this
    // message in allowed to interrupt.
    //

    KAFFINITY TargetProcessorSet;

    //
    // Interrupt object - holds a pointer to the interrupt object associated
    // with this interrupt message.  This structure is opaque to drivers.
    //

    PKINTERRUPT InterruptObject;

    //
    // Message data - supplies the value that the device should write to the
    // message address in order to generate this interrupt message.
    //

    ULONG MessageData;

    //
    // The remaining fields indicate the system interrupt vector, IRQL,
    // trigger mode, and interrupt polarity associated with this interrupt
    // message.  These first three values are suitable for use in a fully
    // specified connection parameter structure in a call to
    // IoConnectInterruptEx.
    //

    ULONG Vector;
    KIRQL Irql;
    KINTERRUPT_MODE Mode;
    KINTERRUPT_POLARITY Polarity;

} IO_INTERRUPT_MESSAGE_INFO_ENTRY, *PIO_INTERRUPT_MESSAGE_INFO_ENTRY;

//
// Interrupt message information table definition
//

typedef struct _IO_INTERRUPT_MESSAGE_INFO {

    //
    // Unified IRQL - indicates the IRQL that will be used when calling a
    // message service routine associated with any of the interrupt messages
    // in this table.  Such a unified IRQL will only exist in cases where 1) a
    // driver provides a spinlock to IoConnectInterruptEx with the intent of
    // serializing delivery of all of the messages listed in this table or 2)
    // the driver provides a synchronization IRQL, and no spinlock, with the
    // intent of blocking any message service routine associated with this
    // table from directly preempting another one.  If neither of these cases
    // applies, then the different messages in this table are allowed to be
    // delivered in parallel and at different IRQLs.  In this case this field
    // will be set to zero.
    //

    KIRQL UnifiedIrql;

    //
    // Message count - indicates the number of entries contained in this
    // message information table.
    //

    ULONG MessageCount;

    //
    // Message info - lies at the start of a variable size array of
    // information table entries, with the size of the array dictated by the
    // message count associated with this table.  Each entry describes a
    // different interrupt message that has been allocated to this device.
    //

    IO_INTERRUPT_MESSAGE_INFO_ENTRY MessageInfo[1];

} IO_INTERRUPT_MESSAGE_INFO, *PIO_INTERRUPT_MESSAGE_INFO;

//
// Define the connection parameters associated with a fully specified
// interrupt connection request.
//

typedef struct _IO_CONNECT_INTERRUPT_FULLY_SPECIFIED_PARAMETERS {

    //
    // PhysicalDeviceObject - Supplies the physical device object associated
    //     with the interrupt being connected.  This is normally the physical
    //     device object associated with the device that generates the given
    //     interrupt.
    //

    __in PDEVICE_OBJECT PhysicalDeviceObject;

    //
    // InterruptObject - Supplies a pointer to the location that will be used
    //     to return a pointer to the interrupt object allocated in
    //     association with the interrupt being connected.
    //

    __out PKINTERRUPT *InterruptObject;

    //
    // ServiceRoutine - Supplies the address of the interrupt service routine
    //     (ISR) that should be executed when the interrupt occurs.
    //

    __in PKSERVICE_ROUTINE ServiceRoutine;

    //
    // ServiceContext - Supplies an opaque pointer to the driver context
    //     information that should be passed to the ISR.
    //

    __in PVOID ServiceContext;

    //
    // SpinLock - Supplies an optional pointer to a spin lock that will be
    //     acquired before every call to the ISR.  After providing a spin
    //     lock, the driver can synchronize with the ISR by acquiring the spin
    //     lock at the synchronization IRQL associated with the interrupt.  If
    //     this parameter is not provided, then an internal spin lock will be
    //     acquired before each call to the ISR.  The driver can use
    //     KeSynchronizeExecution to acquire this internal spin lock at the
    //     appropriate IRQL and thus synchronize with the ISR.
    //

    __in_opt PKSPIN_LOCK SpinLock;

    //
    // SynchronizeIrql - Supplies the IRQL at which the interrupt spin lock
    //     should be acquired and at which the ISR should be executed.  This
    //     parameter must be greater than or equal to the IRQL associated with
    //     the interrupt.  This parameter is most often used in conjunction
    //     with a caller provided spin lock to serialize ISR execution across
    //     multiple interrupts, however it can also be used without a spin
    //     lock to block this ISR from directly preempting or being directly
    //     preempted by some other ISR.
    //

    __in KIRQL SynchronizeIrql;

    //
    // FloatingSave - Supplies an indication of whether or not the machine's
    //     floating point state should be saved before invoking the ISR.
    //

    __in BOOLEAN FloatingSave;

    //
    // ShareVector - Supplies an indication of whether this interrupt vector
    //     can be shared with other interrupt objects.  This value is usually
    //     passed to a driver as part of the translated resources sent along
    //     with IRP_MN_START_DEVICE.
    //

    __in BOOLEAN ShareVector;

    //
    // Vector - Supplies the system interrupt vector associated with the
    //     interrupt being connected.  This value is usually passed to a
    //     driver as part of the translated resources sent along with
    //     IRP_MN_START_DEVICE.
    //

    __in ULONG Vector;

    //
    // Irql - Supplies the IRQL associated with the interrupt being connected.
    //     This value is usually passed to a driver as part of its translated
    //     resources sent along with IRP_MN_START_DEVICE.
    //

    __in KIRQL Irql;

    //
    // InterruptMode - Supplies the trigger mode of the interrupt being
    //     connected.  This parameter must be LevelSensitive for level
    //     triggered interrupts and Latched for edge triggered interrupts.
    //     This value is usually passed to a driver as part of its translated
    //     resources sent along with IRP_MN_START_DEVICE.
    //

    __in KINTERRUPT_MODE InterruptMode;

    //
    // ProcessorEnableMask - Supplies an affinity mask indicating the set of
    //     processors on which delivery of the interrupt should be allowed.
    //     This value is usually passed to a driver as part of its translated
    //     resources sent along with IRP_MN_START_DEVICE.
    //

    __in KAFFINITY ProcessorEnableMask;

    //
    // Group - Supplies a group number indicating the group of the processors
    //     on which delivery of the interrupt should be allowed. This value
    //     is usually passed to a driver as part of its translated resources
    //     sent along with IRP_MN_START_DEVICE. This value is ignored if the
    //     the version CONNECT_FULLY_SPECIFIED is used, in which case the
    //     group number is always 0.
    //

    __in USHORT Group;

} IO_CONNECT_INTERRUPT_FULLY_SPECIFIED_PARAMETERS,
  *PIO_CONNECT_INTERRUPT_FULLY_SPECIFIED_PARAMETERS;

//
// Define the connection parameters associated with a line based interrupt
// connection request.
//

typedef struct _IO_CONNECT_INTERRUPT_LINE_BASED_PARAMETERS {

    //
    // PhysicalDeviceObject - Supplies the physical device object associated
    //     with the line based interrupt being connected.  In order to
    //     correctly determine the interrupt to connect, this is generally
    //     required to be the physical device object associated with the
    //     device that generates the interrupt of interest.
    //

    __in PDEVICE_OBJECT PhysicalDeviceObject;

    //
    // InterruptObject - Supplies a pointer to the location that will be used
    //     to return a pointer to the interrupt object allocated in
    //     association with the interrupt being connected.
    //

    __out PKINTERRUPT *InterruptObject;

    //
    // ServiceRoutine - Supplies the address of the interrupt service routine
    //     (ISR) that should be executed when the interrupt occurs.
    //

    __in PKSERVICE_ROUTINE ServiceRoutine;

    //
    // ServiceContext - Supplies an opaque pointer to the driver context
    //     information that should be passed to the ISR.
    //

    __in PVOID ServiceContext;

    //
    // SpinLock - Supplies an optional pointer to a spin lock that will be
    //     acquired before every call to the ISR.  After providing a spin
    //     lock, the driver can synchronize with the ISR by acquiring the spin
    //     lock at the synchronization IRQL associated with the interrupt.  If
    //     this parameter is not provided, then an internal spin lock will be
    //     acquired before each call to the ISR.  The driver can use
    //     KeSynchronizeExecution to acquire this internal spin lock at the
    //     appropriate IRQL and thus synchronize with the ISR.
    //

    __in_opt PKSPIN_LOCK SpinLock;

    //
    // SynchronizeIrql - Supplies an optional IRQL at which the interrupt spin
    //     lock should be acquired and at which the ISR should be executed.
    //     If a nonzero value is provided for this parameter, it must be
    //     greater than or equal to the IRQL associated with the interrupt.
    //     This parameter is most often used in conjunction with a caller
    //     provided spin lock to serialize ISR execution across multiple
    //     interrupts, however it can also be used without a spin lock to
    //     block this ISR from directly preempting or being directly preempted
    //     by some other ISR.  If this parameter is omitted then the IRQL of
    //     the interrupt being connected is used as the sychronization IRQL,
    //     both in the case where the caller provides a spin lock and in the
    //     case where the spin lock is omitted.
    //

    __in_opt KIRQL SynchronizeIrql;

    //
    // FloatingSave - Supplies an indication of whether or not the machine's
    //     floating point state should be saved before invoking the ISR.
    //

    __in BOOLEAN FloatingSave;

} IO_CONNECT_INTERRUPT_LINE_BASED_PARAMETERS,
  *PIO_CONNECT_INTERRUPT_LINE_BASED_PARAMETERS;

//
// Define the connection parameters associated with a message signaled
// interrupt connection request.
//

typedef struct _IO_CONNECT_INTERRUPT_MESSAGE_BASED_PARAMETERS {

    //
    // PhysicalDeviceObject - Supplies the physical device object associated
    //     with the interrupt messages being connected.  In order to correctly
    //     determine the set of messages to connect, this is generally
    //     required to be the physical device object associated with the
    //     device that generates the interrupt messages of interest.
    //

    __in PDEVICE_OBJECT PhysicalDeviceObject;

    //
    // ConnectionContext - Supplies a union containing a pointer to the
    //     location that will be used to return the interrupt connection
    //     context to the caller.  If message based interrupt connection is
    //     successful, then the connection context is a pointer to the
    //     associated interrupt message information table.  If connection
    //     succeeds only after falling back on the associated line based
    //     interrupt, then the connection context is a pointer to the
    //     associated interrupt object.
    //

    union {
        __out PVOID *Generic;
        __out PIO_INTERRUPT_MESSAGE_INFO *InterruptMessageTable;
        __out PKINTERRUPT *InterruptObject;
    } ConnectionContext;

    //
    // MessageServiceRoutine - Supplies the interrupt message service routine
    //     (IMSR) that should be executed every time any one of the interrupt
    //     messages being connected is signaled.
    //

    __in PKMESSAGE_SERVICE_ROUTINE MessageServiceRoutine;

    //
    // ServiceContext - Supplies an opaque pointer to the driver context
    //     information that should be passed to the IMSR.
    //

    __in PVOID ServiceContext;

    //
    // SpinLock - Supplies an optional pointer to a spin lock that will be
    //     acquired before every call to the IMSR.  After providing a spin
    //     lock, the driver can synchronize with the IMSR by acquiring the
    //     spin lock at the synchronization IRQL associated with the IMSR.
    //     Note that providing a spin lock will serialize processing of all of
    //     the interrupt messages being connected.  In other words, providing
    //     a spin lock implies that no two interrupt messages out of the set
    //     being connected can ever be serviced in parallel by the IMSR.
    //
    //     If this parameter is not provided, then an internal spin lock will
    //     be acquired before each call to the IMSR.  This internal spin lock
    //     is associated with the interrupt object corresponding to the actual
    //     message that caused us to execute the IMSR, meaning that the IMSR
    //     can run on multiple processors and potentially at multiple IRQLs in
    //     this case.  KeSynchronizeExecution can be used to acquire this
    //     internal spin lock at the appropriate IRQL, thus synchronizing with
    //     IMSR execution associated with a specific interrupt message while
    //     still allowing all other messages to be serviced as they are
    //     signaled.
    //

    __in_opt PKSPIN_LOCK SpinLock;

    //
    // SynchronizeIrql - Supplies an optional IRQL at which the interrupt spin
    //     lock should be acquired and at which the IMSR should be executed.
    //     If a nonzero value is provided for this parameter, it must be
    //     greater than or equal to the maximum IRQL associated with any of
    //     the interrupt messages being connected.
    //
    //     This parameter is most often used in conjunction with a caller
    //     provided spin lock to serialize IMSR execution across multiple
    //     messages.  If a spin lock is provided and this parameter is
    //     omitted, then the synchronization IRQL will be set to the maximum
    //     IRQL associated with any of the interrupt messages.
    //
    //     This parameter can be used without a spin lock to block this IMSR
    //     from directly preempting or being directly preempted by itself,
    //     some other IMSR, or some other line based interrupt service
    //     routine.  If this parameter is omitted and the spin lock is also
    //     omitted, then the IMSR will be executed at the IRQL associated with
    //     the individual message being serviced.  In this case it is possible
    //     for the IMSR to preempt itself if it is connected to multiple
    //     messages with different associated IRQLs.
    //

    __in_opt KIRQL SynchronizeIrql;

    //
    // FloatingSave - Supplies an indication of whether or not the machine's
    //     floating point state should be saved before invoking the IMSR.
    //

    __in BOOLEAN FloatingSave;

    //
    // FallBackServiceRoutine - Supplies an optional address of an interrupt
    //     service routine (ISR) that should be executed when the line based
    //     interrupt associated with this device is signaled.  This parameter
    //     will only be used when connection to this device's interrupt
    //     messages fails, which most commonly occurs when no interrupt
    //     messages are available for this device.
    //
    //     Connection to the fall back service routine is functionally
    //     identical to a normal line based interrupt connection operation,
    //     the only difference being that in this case the service context,
    //     spin lock, synchronization IRQL, and floating save parameters given
    //     for the IMSR are reused when connecting the ISR.
    //

    __in_opt PKSERVICE_ROUTINE FallBackServiceRoutine;

} IO_CONNECT_INTERRUPT_MESSAGE_BASED_PARAMETERS,
  *PIO_CONNECT_INTERRUPT_MESSAGE_BASED_PARAMETERS;

//
// Define the different interrupt connection types that can be requested
// through IoConnectInterruptEx
//

#define CONNECT_FULLY_SPECIFIED         0x1
#define CONNECT_LINE_BASED              0x2
#define CONNECT_MESSAGE_BASED           0x3
#define CONNECT_FULLY_SPECIFIED_GROUP   0x4
#define CONNECT_CURRENT_VERSION         0x4

//
// Interrupt connection parameter structure definition
//

typedef struct _IO_CONNECT_INTERRUPT_PARAMETERS {

    //
    // Version - Supplies the type of interrupt connection requested by this
    //     structure.  This field must hold one of the following values.
    //
    //         CONNECT_FULLY_SPECIFIED - Indicates that an attempt should be
    //             made to connect to the precise interrupt described by this
    //             structure.  This vector can be either line based or message
    //             signaled.
    //
    //         CONNECT_LINE_BASED - Indicates that an attempt should be made
    //             to connect to the line based interrupt associated with this
    //             device.
    //
    //         CONNECT_MESSAGE_BASED - Indicates that an attempt should be
    //             made to connect to the interrupt messages that have been
    //             allocated for this device, optionally falling back on the
    //             device's line based interrupt if interrupt messages aren't
    //             available.
    //
    //         CONNECT_FULLY_SPECIFIED_GROUP - Same as CONNECT_FULLY_SPECIFIED,
    //             except that a group number is also specified to indicate
    //             the group of processors on which the interrupt is allowed to
    //             be delivered.
    //
    //     After successfully connecting an interrupt, this field is filled on
    //     output with the type of connection that was performed.  This will
    //     always be the connection type given by the caller except in the
    //     case of a message based connection attempt that falls back to
    //     connection to the associated line based interrupt.
    //
    //     If the caller passes an unsupported connection type, this field is
    //     filled on output with the maximum connection type supported by the
    //     interrupt connection routine.
    //

    __inout ULONG Version;

    //
    // Define a union to overlay the connection parameter structures
    // associated with the different connection types on top of one another.
    //

    union {
        IO_CONNECT_INTERRUPT_FULLY_SPECIFIED_PARAMETERS FullySpecified;
        IO_CONNECT_INTERRUPT_LINE_BASED_PARAMETERS LineBased;
        IO_CONNECT_INTERRUPT_MESSAGE_BASED_PARAMETERS MessageBased;
    };

} IO_CONNECT_INTERRUPT_PARAMETERS, *PIO_CONNECT_INTERRUPT_PARAMETERS;

#if (NTDDI_VERSION >= NTDDI_VISTA)
NTKERNELAPI
NTSTATUS
IoConnectInterruptEx (
    __inout PIO_CONNECT_INTERRUPT_PARAMETERS Parameters
    );
#endif // NTDDI_VERSION >= NTDDI_VISTA


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
__drv_valueIs(==0;<0)
NTKERNELAPI
NTSTATUS
IoCreateDevice(
    __in  PDRIVER_OBJECT DriverObject,
    __in  ULONG DeviceExtensionSize,
    __in_opt PUNICODE_STRING DeviceName,
    __in  DEVICE_TYPE DeviceType,
    __in  ULONG DeviceCharacteristics,
    __in  BOOLEAN Exclusive,
    __out
    __drv_out_deref(
        __drv_allocatesMem(Mem)
        __drv_when((((inFunctionClass$("DRIVER_INITIALIZE"))
             ||(inFunctionClass$("DRIVER_DISPATCH")))),
             __drv_aliasesMem)
        __on_failure(__null))
    PDEVICE_OBJECT *DeviceObject
    );
#endif

#define WDM_MAJORVERSION        0x06
#define WDM_MINORVERSION        0x00

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
__drv_preferredFunction("RtlIsNtDdiVersionAvailable","Preferred")
NTKERNELAPI
BOOLEAN
IoIsWdmVersionAvailable(
    __drv_when(MajorVersion!=1&&MajorVersion!=6,
    __in __drv_reportError("MajorVersion must be 1 or 6")) UCHAR MajorVersion,
    __in __drv_when(MinorVersion!=0 && MinorVersion!=5 && MinorVersion!=16
                    && MinorVersion!=32 && MinorVersion!=48,
    __drv_reportError("MinorVersion must be 0, 0x5, 0x10, 0x20, or 0x30"))
    UCHAR MinorVersion
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
NTSTATUS
IoCreateFile(
    __out PHANDLE FileHandle,
    __in  ACCESS_MASK DesiredAccess,
    __in  POBJECT_ATTRIBUTES ObjectAttributes,
    __out PIO_STATUS_BLOCK IoStatusBlock,
    __in_opt PLARGE_INTEGER AllocationSize,
    __in  ULONG FileAttributes,
    __in  ULONG ShareAccess,
    __in  ULONG Disposition,
    __in  ULONG CreateOptions,
    __in_opt PVOID EaBuffer,
    __in  ULONG EaLength,
    __in  CREATE_FILE_TYPE CreateFileType,
    __in_opt PVOID InternalParameters,
    __in  ULONG Options
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
PKEVENT
IoCreateNotificationEvent(
    __in  PUNICODE_STRING EventName,
    __out PHANDLE EventHandle
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
NTSTATUS
IoCreateSymbolicLink(
    __in PUNICODE_STRING SymbolicLinkName,
    __in PUNICODE_STRING DeviceName
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
PKEVENT
IoCreateSynchronizationEvent(
    __in  PUNICODE_STRING EventName,
    __out PHANDLE EventHandle
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
NTSTATUS
IoCreateUnprotectedSymbolicLink(
    __in PUNICODE_STRING SymbolicLinkName,
    __in PUNICODE_STRING DeviceName
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
__drv_clearDoInit(__yes)
NTKERNELAPI
VOID
IoDeleteDevice(
    __in __drv_mustHold(Memory) __drv_freesMem(Mem) PDEVICE_OBJECT DeviceObject
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
NTSTATUS
IoDeleteSymbolicLink(
    __in PUNICODE_STRING SymbolicLinkName
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
VOID
IoDetachDevice(
    __inout PDEVICE_OBJECT TargetDevice
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
VOID
IoDisconnectInterrupt(
    __in PKINTERRUPT InterruptObject
    );
#endif

//
// Interrupt disconnection parameter structure definition
//

typedef struct _IO_DISCONNECT_INTERRUPT_PARAMETERS {

    //
    // Version - Supplies the type of interrupt disconnection operation
    //     requested by this structure.  This field must match the connection
    //     type returned by a corresponding successful call to
    //     IoConnectInterruptEx.
    //

    __in ULONG Version;

    //
    // ConnectionContext - Supplies a union containing the connection context
    //     associated with the interrupt being disconnected.  When
    //     disconnecting fully specified or line based interrupts, this
    //     parameter supplies the interrupt object pointer that was returned
    //     when the interrupt was initially connected.  When disconnecting a
    //     set of interrupt messages, this parameter supplies the interrupt
    //     message information table pointer that was returned when the
    //     interrupt messages were initially connected.
    //

    union {
        __in PVOID Generic;
        __in PKINTERRUPT InterruptObject;
        __in PIO_INTERRUPT_MESSAGE_INFO InterruptMessageTable;
    } ConnectionContext;

} IO_DISCONNECT_INTERRUPT_PARAMETERS, *PIO_DISCONNECT_INTERRUPT_PARAMETERS;

#if (NTDDI_VERSION >= NTDDI_VISTA)
NTKERNELAPI
VOID
IoDisconnectInterruptEx (
    __in PIO_DISCONNECT_INTERRUPT_PARAMETERS Parameters
    );
#endif // NTDDI_VERSION >= NTDDI_VISTA

#if (NTDDI_VERSION >= NTDDI_WIN7)
NTKERNELAPI
NTSTATUS
IoGetAffinityInterrupt (
    __in PKINTERRUPT InterruptObject,
    __out PGROUP_AFFINITY GroupAffinity
    );
#endif // NTDDI_VERSION >= NTDDI_WIN7


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_freesMem(Mem)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
VOID
IoFreeIrp(
    __in PIRP Irp
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
VOID
IoFreeMdl(
    PMDL Mdl
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)          
NTKERNELAPI                                 
PDEVICE_OBJECT                              
__drv_maxIRQL(DISPATCH_LEVEL)               
IoGetAttachedDeviceReference(               
    __in PDEVICE_OBJECT DeviceObject        
    );                                      
#endif                                      
                                            

FORCEINLINE
__drv_aliasesMem
PIO_STACK_LOCATION
IoGetCurrentIrpStackLocation(
    __in PIRP Irp
)
/*--

Routine Description:

    This routine is invoked to return a pointer to the current stack location
    in an I/O Request Packet (IRP).

Arguments:

    Irp - Pointer to the I/O Request Packet.

Return Value:

    The function value is a pointer to the current stack location in the
    packet.

--*/
{
    ASSERT(Irp->CurrentLocation <= Irp->StackCount + 1);
    return Irp->Tail.Overlay.CurrentStackLocation;
}


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_aliasesMem
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
PVOID
IoGetDriverObjectExtension(
    __in PDRIVER_OBJECT DriverObject,
    __in PVOID ClientIdentificationAddress
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
PEPROCESS
IoGetCurrentProcess(
    VOID
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
NTSTATUS
IoGetDeviceObjectPointer(
    __in  PUNICODE_STRING ObjectName,
    __in  ACCESS_MASK DesiredAccess,
    __out PFILE_OBJECT *FileObject,
    __out PDEVICE_OBJECT *DeviceObject
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn
__drv_maxIRQL(PASSIVE_LEVEL)
__drv_valueIs(!=0;==0)
NTKERNELAPI
struct _DMA_ADAPTER *
IoGetDmaAdapter(
    __in_opt PDEVICE_OBJECT PhysicalDeviceObject,           // required for PnP drivers
    __in struct _DEVICE_DESCRIPTION *DeviceDescription,
    __out __drv_when(return!=0, __drv_IoGetDmaAdapter __deref __checkReturn)
    PULONG NumberOfMapRegisters
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
NTKERNELAPI
BOOLEAN
IoForwardIrpSynchronously(
    __in PDEVICE_OBJECT DeviceObject,
    __in PIRP Irp
    );

#define IoForwardAndCatchIrp IoForwardIrpSynchronously

#endif


//++
//
// ULONG
// IoGetFunctionCodeFromCtlCode(
//     __in ULONG ControlCode
//     )
//
// Routine Description:
//
//     This routine extracts the function code from IOCTL and FSCTL function
//     control codes.
//     This routine should only be used by kernel mode code.
//
// Arguments:
//
//     ControlCode - A function control code (IOCTL or FSCTL) from which the
//         function code must be extracted.
//
// Return Value:
//
//     The extracted function code.
//
// Note:
//
//     The CTL_CODE macro, used to create IOCTL and FSCTL function control
//     codes, is defined in ntioapi.h
//
//--

#define IoGetFunctionCodeFromCtlCode( ControlCode ) (\
    ( ControlCode >> 2) & 0x00000FFF )

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
PVOID
IoGetInitialStack(
    VOID
    );
#endif

__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
IoGetStackLimits (
    __out PULONG_PTR LowLimit,
    __out PULONG_PTR HighLimit
    );

#if (NTDDI_VERSION >= NTDDI_VISTA)
LOGICAL
IoWithinStackLimits(
    __in ULONG_PTR RegionStart,
    __in SIZE_T RegionSize
    );
#endif


#define IoCallDriverStackSafeDefault(a, b) IoCallDriver(a, b)

//
//  The following function is used to tell the caller how much stack is available
//

__drv_maxIRQL(APC_LEVEL)
FORCEINLINE
ULONG_PTR
IoGetRemainingStackSize (
    VOID
    )
{
    ULONG_PTR Top;
    ULONG_PTR Bottom;

    IoGetStackLimits( &Bottom, &Top );
    return((ULONG_PTR)(&Top) - Bottom );
}

FORCEINLINE
__drv_aliasesMem
PIO_STACK_LOCATION
IoGetNextIrpStackLocation(
    __in PIRP Irp
    )
/*++
Routine Description:

    This routine is invoked to return a pointer to the next stack location
    in an I/O Request Packet (IRP).

Arguments:

    Irp - Pointer to the I/O Request Packet.

Return Value:

    The function value is a pointer to the next stack location in the packet.

--*/
{
    ASSERT(Irp->CurrentLocation > 0);

    return ((Irp)->Tail.Overlay.CurrentStackLocation - 1 );
}

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
PDEVICE_OBJECT
IoGetRelatedDeviceObject(
    __in PFILE_OBJECT FileObject
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
PIRP
IoGetTopLevelIrp(
    VOID
    );
#endif



VOID
FORCEINLINE
IoInitializeDpcRequest(
    __in PDEVICE_OBJECT DeviceObject,
    __in PIO_DPC_ROUTINE DpcRoutine
    )
/*++

Routine Description:

    This routine is invoked to initialize the DPC in a device object for a
    device driver during its initialization routine.  The DPC is used later
    when the driver interrupt service routine requests that a DPC routine
    be queued for later execution.

Arguments:

    DeviceObject - Pointer to the device object that the request is for.

    DpcRoutine - Address of the driver's DPC routine to be executed when
        the DPC is dequeued for processing.

Return Value:

    None.

--*/
{
    KeInitializeDpc( &DeviceObject->Dpc,
#pragma warning (suppress: 28165) // implementation of the required way
                     (PKDEFERRED_ROUTINE) DpcRoutine,
                     DeviceObject );
}

#if (NTDDI_VERSION >= NTDDI_WS03)
VOID
FORCEINLINE
IoInitializeThreadedDpcRequest(
    __in PDEVICE_OBJECT DeviceObject,
    __in PIO_DPC_ROUTINE DpcRoutine
    )
/*++

Routine Description:

    This routine is invoked to initialize the DPC in a device object for a
    device driver during its initialization routine.  The DPC is used later
    when the driver interrupt service routine requests that a DPC routine
    be queued for later execution.

    This initializes the DPC as a threaded DPC.

Arguments:

    DeviceObject - Pointer to the device object that the request is for.

    DpcRoutine - Address of the driver's DPC routine to be executed when
        the DPC is dequeued for processing.

Return Value:

    None.

--*/
{
#pragma warning (suppress: 28128) // implementation of the required way
    KeInitializeThreadedDpc( &DeviceObject->Dpc,
#pragma warning (suppress: 28165) // implementation of the required way
                             (PKDEFERRED_ROUTINE) DpcRoutine,
                             DeviceObject );
}
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
VOID
IoInitializeIrp(
    __inout PIRP Irp,
    __in USHORT PacketSize,
    __in CCHAR StackSize
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
NTSTATUS
IoInitializeTimer(
    __in PDEVICE_OBJECT DeviceObject,
    __in PIO_TIMER_ROUTINE TimerRoutine,
    __in_opt __drv_aliasesMem PVOID Context
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
VOID
IoReuseIrp(
    __inout PIRP Irp,
    __in NTSTATUS Iostatus
    );
#endif


//++
//
// BOOLEAN
// IoIsErrorUserInduced(
//     __in NTSTATUS Status
//     )
//
// Routine Description:
//
//     This routine is invoked to determine if an error was as a
//     result of user actions.  Typically these error are related
//     to removable media and will result in a pop-up.
//
// Arguments:
//
//     Status - The status value to check.
//
// Return Value:
//     The function value is TRUE if the user induced the error,
//     otherwise FALSE is returned.
//
//--
#define IoIsErrorUserInduced( Status ) ((BOOLEAN)  \
    (((Status) == STATUS_DEVICE_NOT_READY) ||      \
     ((Status) == STATUS_IO_TIMEOUT) ||            \
     ((Status) == STATUS_MEDIA_WRITE_PROTECTED) || \
     ((Status) == STATUS_NO_MEDIA_IN_DEVICE) ||    \
     ((Status) == STATUS_VERIFY_REQUIRED) ||       \
     ((Status) == STATUS_UNRECOGNIZED_MEDIA) ||    \
     ((Status) == STATUS_WRONG_VOLUME)))




FORCEINLINE
VOID
IoMarkIrpPending(
    __inout PIRP Irp
)
/*++
Routine Description:

    This routine marks the specified I/O Request Packet (IRP) to indicate
    that an initial status of STATUS_PENDING was returned to the caller.
    This is used so that I/O completion can determine whether or not to
    fully complete the I/O operation requested by the packet.

Arguments:

    Irp - Pointer to the I/O Request Packet to be marked pending.

Return Value:

    None.

--*/
{
    IoGetCurrentIrpStackLocation( (Irp) )->Control |= SL_PENDING_RETURNED;
}


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
NTSTATUS
IoRegisterShutdownNotification(
    __in PDEVICE_OBJECT DeviceObject
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
NTSTATUS
IoRegisterLastChanceShutdownNotification(
    __in PDEVICE_OBJECT DeviceObject
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_mustHoldCancelSpinLock
__drv_releasesCancelSpinLock
__drv_maxIRQL(DISPATCH_LEVEL)
__drv_minIRQL(DISPATCH_LEVEL)
NTKERNELAPI
VOID
IoReleaseCancelSpinLock(
    __in __drv_restoresIRQL __drv_useCancelIRQL KIRQL Irql
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
VOID
IoRemoveShareAccess(
    __in PFILE_OBJECT FileObject,
    __inout PSHARE_ACCESS ShareAccess
    );
#endif


//++
//
// VOID
// IoRequestDpc(
//     __in PDEVICE_OBJECT DeviceObject,
//     __in PIRP Irp,
//     __in PVOID Context
//     )
//
// Routine Description:
//
//     This routine is invoked by the device driver's interrupt service routine
//     to request that a DPC routine be queued for later execution at a lower
//     IRQL.
//
// Arguments:
//
//     DeviceObject - Device object for which the request is being processed.
//
//     Irp - Pointer to the current I/O Request Packet (IRP) for the specified
//         device.
//
//     Context - Provides a general context parameter to be passed to the
//         DPC routine.
//
// Return Value:
//
//     None.
//
//--

#define IoRequestDpc( DeviceObject, Irp, Context ) ( \
    KeInsertQueueDpc( &(DeviceObject)->Dpc, (Irp), (Context) ) )

//++
//
// PDRIVER_CANCEL
// IoSetCancelRoutine(
//     __in PIRP Irp,
//     __in PDRIVER_CANCEL CancelRoutine
//     )
//
// Routine Description:
//
//     This routine is invoked to set the address of a cancel routine which
//     is to be invoked when an I/O packet has been canceled.
//
// Arguments:
//
//     Irp - Pointer to the I/O Request Packet itself.
//
//     CancelRoutine - Address of the cancel routine that is to be invoked
//         if the IRP is cancelled.
//
// Return Value:
//
//     Previous value of CancelRoutine field in the IRP.
//
//--

#define IoSetCancelRoutine( Irp, NewCancelRoutine ) (  \
    (PDRIVER_CANCEL) (ULONG_PTR) InterlockedExchangePointer( (PVOID *) &(Irp)->CancelRoutine, (PVOID) (ULONG_PTR)(NewCancelRoutine) ) )

__drv_maxIRQL(DISPATCH_LEVEL)
FORCEINLINE
VOID
IoSetCompletionRoutine(
    __in PIRP Irp,
    __in_opt PIO_COMPLETION_ROUTINE CompletionRoutine,
    __in_opt __drv_aliasesMem PVOID Context,
    __in BOOLEAN InvokeOnSuccess,
    __in BOOLEAN InvokeOnError,
    __in BOOLEAN InvokeOnCancel
    )
//++
//
// Routine Description:
//
//     This routine is invoked to set the address of a completion routine which
//     is to be invoked when an I/O packet has been completed by a lower-level
//     driver.
//
// Arguments:
//
//     Irp - Pointer to the I/O Request Packet itself.
//
//     CompletionRoutine - Address of the completion routine that is to be
//         invoked once the next level driver completes the packet.
//
//     Context - Specifies a context parameter to be passed to the completion
//         routine.
//
//     InvokeOnSuccess - Specifies that the completion routine is invoked when the
//         operation is successfully completed.
//
//     InvokeOnError - Specifies that the completion routine is invoked when the
//         operation completes with an error status.
//
//     InvokeOnCancel - Specifies that the completion routine is invoked when the
//         operation is being canceled.
//
// Return Value:
//
//     None.
//
//--
{
    PIO_STACK_LOCATION irpSp;
    ASSERT( (InvokeOnSuccess || InvokeOnError || InvokeOnCancel) ? (CompletionRoutine != NULL) : TRUE );
    irpSp = IoGetNextIrpStackLocation(Irp);
    irpSp->CompletionRoutine = CompletionRoutine;
    irpSp->Context = Context;
    irpSp->Control = 0;

    if (InvokeOnSuccess) {
        irpSp->Control = SL_INVOKE_ON_SUCCESS;
    }

    if (InvokeOnError) {
        irpSp->Control |= SL_INVOKE_ON_ERROR;
    }

    if (InvokeOnCancel) {
        irpSp->Control |= SL_INVOKE_ON_CANCEL;
    }
}

#if (NTDDI_VERSION >= NTDDI_WINXP)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
__checkReturn
NTSTATUS
IoSetCompletionRoutineEx(
    __in PDEVICE_OBJECT DeviceObject,
    __in PIRP Irp,
    __in PIO_COMPLETION_ROUTINE CompletionRoutine,
    __in_opt PVOID Context,
    __in BOOLEAN InvokeOnSuccess,
    __in BOOLEAN InvokeOnError,
    __in BOOLEAN InvokeOnCancel
    );
#endif


FORCEINLINE
VOID
IoSetNextIrpStackLocation (
   __inout PIRP Irp
    )
/*--

Routine Description:

    This routine is invoked to set the current IRP stack location to
    the next stack location, i.e. it "pushes" the stack.

Arguments:

    Irp - Pointer to the I/O Request Packet (IRP).

Return Value:

    None.

--*/
{
    ASSERT(Irp->CurrentLocation > 0);
    Irp->CurrentLocation--;
    Irp->Tail.Overlay.CurrentStackLocation--;
}

FORCEINLINE
VOID
IoCopyCurrentIrpStackLocationToNext(
    __inout PIRP Irp
)
/*--

Routine Description:

    This routine is invoked to copy the IRP stack arguments and file
    pointer from the current IrpStackLocation to the next
    in an I/O Request Packet (IRP).

    If the caller wants to call IoCallDriver with a completion routine
    but does not wish to change the arguments otherwise,
    the caller first calls IoCopyCurrentIrpStackLocationToNext,
    then IoSetCompletionRoutine, then IoCallDriver.

Arguments:

    Irp - Pointer to the I/O Request Packet.

Return Value:

    None.

--*/
{
    PIO_STACK_LOCATION irpSp;
    PIO_STACK_LOCATION nextIrpSp;
    irpSp = IoGetCurrentIrpStackLocation(Irp);
    nextIrpSp = IoGetNextIrpStackLocation(Irp);
    RtlCopyMemory( nextIrpSp, irpSp, FIELD_OFFSET(IO_STACK_LOCATION, CompletionRoutine));
    nextIrpSp->Control = 0;
}

FORCEINLINE
VOID
IoSkipCurrentIrpStackLocation (
    __inout PIRP Irp
)
/*--
Routine Description:

    This routine is invoked to increment the current stack location of
    a given IRP.

    If the caller wishes to call the next driver in a stack, and does not
    wish to change the arguments, nor does he wish to set a completion
    routine, then the caller first calls IoSkipCurrentIrpStackLocation
    and the calls IoCallDriver.

Arguments:

    Irp - Pointer to the I/O Request Packet.

Return Value:

    None
--*/
{
    ASSERT(Irp->CurrentLocation <= Irp->StackCount);
    Irp->CurrentLocation++;
    Irp->Tail.Overlay.CurrentStackLocation++;
}

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
IoSetShareAccess(
    __in  ACCESS_MASK DesiredAccess,
    __in  ULONG DesiredShareAccess,
    __inout PFILE_OBJECT FileObject,
    __out PSHARE_ACCESS ShareAccess
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
NTKERNELAPI
VOID
IoSetShareAccessEx(
    __in  ACCESS_MASK DesiredAccess,
    __in  ULONG DesiredShareAccess,
    __inout PFILE_OBJECT FileObject,
    __out PSHARE_ACCESS ShareAccess,
    __in PBOOLEAN WritePermission
    );
#endif




#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
IoSetTopLevelIrp(
    __in_opt PIRP Irp
    );
#endif





typedef struct _IO_REMOVE_LOCK_TRACKING_BLOCK * PIO_REMOVE_LOCK_TRACKING_BLOCK;

typedef struct _IO_REMOVE_LOCK_COMMON_BLOCK {
    BOOLEAN     Removed;
    BOOLEAN     Reserved [3];
    __volatile LONG        IoCount;
    KEVENT      RemoveEvent;

} IO_REMOVE_LOCK_COMMON_BLOCK;

typedef struct _IO_REMOVE_LOCK_DBG_BLOCK {
    LONG        Signature;
    ULONG       HighWatermark;
    LONGLONG    MaxLockedTicks;
    LONG        AllocateTag;
    LIST_ENTRY  LockList;
    KSPIN_LOCK  Spin;
    __volatile LONG        LowMemoryCount;
    ULONG       Reserved1[4];
    PVOID       Reserved2;
    PIO_REMOVE_LOCK_TRACKING_BLOCK Blocks;
} IO_REMOVE_LOCK_DBG_BLOCK;

typedef struct _IO_REMOVE_LOCK {
    IO_REMOVE_LOCK_COMMON_BLOCK Common;
#if DBG
    IO_REMOVE_LOCK_DBG_BLOCK Dbg;
#endif
} IO_REMOVE_LOCK, *PIO_REMOVE_LOCK;

#define IoInitializeRemoveLock(Lock, Tag, Maxmin, HighWater) \
        IoInitializeRemoveLockEx (Lock, Tag, Maxmin, HighWater, sizeof (IO_REMOVE_LOCK))

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
VOID
NTAPI
IoInitializeRemoveLockEx(
    __in PIO_REMOVE_LOCK Lock,
    __in ULONG  AllocateTag, // Used only on checked kernels
    __in ULONG  MaxLockedMinutes, // Used only on checked kernels
    __in ULONG  HighWatermark, // Used only on checked kernels
    __in ULONG  RemlockSize // are we checked or free
    );
#endif

//
//  Initialize a remove lock.
//
//  Note: Allocation for remove locks needs to be within the device extension,
//  so that the memory for this structure stays allocated until such time as the
//  device object itself is deallocated.
//

#if DBG
#define IoAcquireRemoveLock(RemoveLock, Tag) \
        IoAcquireRemoveLockEx(RemoveLock, Tag, __FILE__, __LINE__, sizeof (IO_REMOVE_LOCK))
#else
#define IoAcquireRemoveLock(RemoveLock, Tag) \
        IoAcquireRemoveLockEx(RemoveLock, Tag, "", 1, sizeof (IO_REMOVE_LOCK))
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
NTSTATUS
NTAPI
IoAcquireRemoveLockEx (
    __in PIO_REMOVE_LOCK RemoveLock,
    __in_opt PVOID      Tag, // Optional
    __in PCSTR          File,
    __in ULONG          Line,
    __in ULONG          RemlockSize // are we checked or free
    );
#endif

//
// Routine Description:
//
//    This routine is called to acquire the remove lock for a device object.
//    While the lock is held, the caller can assume that no pending pnp REMOVE
//    requests will be completed.
//
//    The lock should be acquired immediately upon entering a dispatch routine.
//    It should also be acquired before creating any new reference to the
//    device object if there's a chance of releasing the reference before the
//    new one is done, in addition to references to the driver code itself,
//    which is removed from memory when the last device object goes.
//
//    Arguments:
//
//    RemoveLock - A pointer to an initialized REMOVE_LOCK structure.
//
//    Tag - Used for tracking lock allocation and release.  The same tag
//          specified when acquiring the lock must be used to release the lock.
//          Tags are only checked in checked versions of the driver.
//
//    File - set to __FILE__ as the location in the code where the lock was taken.
//
//    Line - set to __LINE__.
//
// Return Value:
//
//    Returns whether or not the remove lock was obtained.
//    If successful the caller should continue with work calling
//    IoReleaseRemoveLock when finished.
//
//    If not successful the lock was not obtained.  The caller should abort the
//    work but not call IoReleaseRemoveLock.
//

#define IoReleaseRemoveLock(RemoveLock, Tag) \
        IoReleaseRemoveLockEx(RemoveLock, Tag, sizeof (IO_REMOVE_LOCK))

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
NTAPI
IoReleaseRemoveLockEx(
    __in PIO_REMOVE_LOCK RemoveLock,
    __in_opt PVOID       Tag, // Optional
    __in ULONG           RemlockSize // are we checked or free
    );
#endif

//
//
// Routine Description:
//
//    This routine is called to release the remove lock on the device object.  It
//    must be called when finished using a previously locked reference to the
//    device object.  If an Tag was specified when acquiring the lock then the
//    same Tag must be specified when releasing the lock.
//
//    When the lock count reduces to zero, this routine will signal the waiting
//    event to release the waiting thread deleting the device object protected
//    by this lock.
//
// Arguments:
//
//    DeviceObject - the device object to lock
//
//    Tag - The TAG (if any) specified when acquiring the lock.  This is used
//          for lock tracking purposes
//
// Return Value:
//
//    none
//

#define IoReleaseRemoveLockAndWait(RemoveLock, Tag) \
        IoReleaseRemoveLockAndWaitEx(RemoveLock, Tag, sizeof (IO_REMOVE_LOCK))

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
VOID
NTAPI
IoReleaseRemoveLockAndWaitEx(
    __in PIO_REMOVE_LOCK RemoveLock,
    __in_opt PVOID       Tag,
    __in ULONG           RemlockSize // are we checked or free
    );
#endif

//
//
// Routine Description:
//
//    This routine is called when the client would like to delete the
//    remove-locked resource.  This routine will block until all the remove
//    locks have released.
//
//    This routine MUST be called after acquiring the lock.
//
// Arguments:
//
//    RemoveLock
//
// Return Value:
//
//    none
//


//++
//
// USHORT
// IoSizeOfIrp(
//     __in CCHAR StackSize
//     )
//
// Routine Description:
//
//     Determines the size of an IRP given the number of stack locations
//     the IRP will have.
//
// Arguments:
//
//     StackSize - Number of stack locations for the IRP.
//
// Return Value:
//
//     Size in bytes of the IRP.
//
//--

#define IoSizeOfIrp( StackSize ) \
    ((USHORT) (sizeof( IRP ) + ((StackSize) * (sizeof( IO_STACK_LOCATION )))))

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL) __drv_minIRQL(DISPATCH_LEVEL)
NTKERNELAPI
VOID
IoStartNextPacket(
    __in PDEVICE_OBJECT DeviceObject,
    __in BOOLEAN Cancelable
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
VOID
IoStartNextPacketByKey(
    __in PDEVICE_OBJECT DeviceObject,
    __in BOOLEAN Cancelable,
    __in ULONG Key
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
VOID
IoStartPacket(
    __in PDEVICE_OBJECT DeviceObject,
    __in PIRP Irp,
    __in_opt PULONG Key,
    __in_opt PDRIVER_CANCEL CancelFunction
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
VOID
IoSetStartIoAttributes(
    __in PDEVICE_OBJECT DeviceObject,
    __in BOOLEAN DeferredStartIo,
    __in BOOLEAN NonCancelable
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
VOID
IoStartTimer(
    __in PDEVICE_OBJECT DeviceObject
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
VOID
IoStopTimer(
    __in PDEVICE_OBJECT DeviceObject
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
VOID
IoUnregisterShutdownNotification(
    __in PDEVICE_OBJECT DeviceObject
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
VOID
IoUpdateShareAccess(
    __in PFILE_OBJECT FileObject,
    __inout PSHARE_ACCESS ShareAccess
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)              
NTKERNELAPI                                     
VOID                                            
__drv_maxIRQL(DISPATCH_LEVEL)                   
IoWriteErrorLogEntry(                           
    __in PVOID ElEntry                          
    );                                          
#endif                                          

typedef struct _IO_WORKITEM *PIO_WORKITEM;

#if (NTDDI_VERSION >= NTDDI_VISTA)
ULONG
IoSizeofWorkItem(
    VOID
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
VOID
IoInitializeWorkItem(
    __in PVOID IoObject,
    __in PIO_WORKITEM IoWorkItem
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
VOID
IoUninitializeWorkItem(
    __in PIO_WORKITEM IoWorkItem
    );
#endif

__drv_functionClass(IO_WORKITEM_ROUTINE)
__drv_requiresIRQL(PASSIVE_LEVEL)
__drv_sameIRQL
typedef
VOID
IO_WORKITEM_ROUTINE (
    __in PDEVICE_OBJECT DeviceObject,
    __in_opt PVOID Context
    );

typedef IO_WORKITEM_ROUTINE *PIO_WORKITEM_ROUTINE;

typedef
VOID
IO_WORKITEM_ROUTINE_EX (
    __in PVOID IoObject,
    __in_opt PVOID Context,
    __in PIO_WORKITEM IoWorkItem
    );

typedef IO_WORKITEM_ROUTINE_EX *PIO_WORKITEM_ROUTINE_EX;

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
PIO_WORKITEM
IoAllocateWorkItem(
    __in PDEVICE_OBJECT DeviceObject
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
IoFreeWorkItem(
    __in PIO_WORKITEM IoWorkItem
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
VOID
IoQueueWorkItem(
    __in PIO_WORKITEM IoWorkItem,
    __in PIO_WORKITEM_ROUTINE WorkerRoutine,
    __in WORK_QUEUE_TYPE QueueType,
    __in_opt __drv_aliasesMem PVOID Context
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(DISPATCH_LEVEL)
VOID
IoQueueWorkItemEx(
    __in PIO_WORKITEM IoWorkItem,
    __in PIO_WORKITEM_ROUTINE_EX WorkerRoutine,
    __in WORK_QUEUE_TYPE QueueType,
    __in_opt __drv_aliasesMem PVOID Context
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
NTSTATUS
IoWMIRegistrationControl(
    __in PDEVICE_OBJECT DeviceObject,
    __in ULONG Action
);
#endif

//
// Action code for IoWMIRegistrationControl api
//

#define WMIREG_ACTION_REGISTER      1
#define WMIREG_ACTION_DEREGISTER    2
#define WMIREG_ACTION_REREGISTER    3
#define WMIREG_ACTION_UPDATE_GUIDS  4
#define WMIREG_ACTION_BLOCK_IRPS    5

//
// Code passed in IRP_MN_REGINFO WMI irp
//

#define WMIREGISTER                 0
#define WMIUPDATE                   1

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
NTSTATUS
IoWMIAllocateInstanceIds(
    __in GUID *Guid,
    __in ULONG InstanceCount,
    __out ULONG *FirstInstanceId
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
IoWMISuggestInstanceName(
    __in_opt PDEVICE_OBJECT PhysicalDeviceObject,
    __in_opt PUNICODE_STRING SymbolicLinkName,
    __in BOOLEAN CombineNames,
    __out PUNICODE_STRING SuggestedInstanceName
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn
__drv_maxIRQL(APC_LEVEL)
__drv_valueIs(==0;<0)
NTKERNELAPI
NTSTATUS
IoWMIWriteEvent(
    __inout __drv_when(return==0, __drv_aliasesMem) PVOID WnodeEventItem
    );
#endif

#if defined(_WIN64)
NTKERNELAPI
ULONG
IoWMIDeviceObjectToProviderId(
    __in PDEVICE_OBJECT DeviceObject
    );
#else
#define IoWMIDeviceObjectToProviderId(DeviceObject) ((ULONG)(DeviceObject))
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
NTKERNELAPI
NTSTATUS
IoWMIOpenBlock(
    __in GUID *DataBlockGuid,
    __in ULONG DesiredAccess,
    __out PVOID *DataBlockObject
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
NTKERNELAPI
NTSTATUS
IoWMIQueryAllData(
    __in PVOID DataBlockObject,
    __inout ULONG *InOutBufferSize,
    __out_bcount_opt(*InOutBufferSize) /* non paged */ PVOID OutBuffer
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
NTKERNELAPI
NTSTATUS
IoWMIQueryAllDataMultiple(
    __in_ecount(ObjectCount) PVOID *DataBlockObjectList,
    __in ULONG ObjectCount,
    __inout ULONG *InOutBufferSize,
    __out_bcount_opt(*InOutBufferSize) /* non paged */ PVOID OutBuffer
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
NTKERNELAPI
NTSTATUS
IoWMIQuerySingleInstance(
    __in PVOID DataBlockObject,
    __in PUNICODE_STRING InstanceName,
    __inout ULONG *InOutBufferSize,
    __out_bcount_opt(*InOutBufferSize) /* non paged */ PVOID OutBuffer
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
IoWMIQuerySingleInstanceMultiple(
    __in_ecount(ObjectCount) PVOID *DataBlockObjectList,
    __in_ecount(ObjectCount) PUNICODE_STRING InstanceNames,
    __in ULONG ObjectCount,
    __inout ULONG *InOutBufferSize,
    __out_bcount_opt(*InOutBufferSize) /* non paged */ PVOID OutBuffer
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
NTKERNELAPI
NTSTATUS
IoWMISetSingleInstance(
    __in PVOID DataBlockObject,
    __in PUNICODE_STRING InstanceName,
    __in ULONG Version,
    __in ULONG ValueBufferSize,
    __in_bcount(ValueBufferSize) PVOID ValueBuffer
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
NTKERNELAPI
NTSTATUS
IoWMISetSingleItem(
    __in PVOID DataBlockObject,
    __in PUNICODE_STRING InstanceName,
    __in ULONG DataItemId,
    __in ULONG Version,
    __in ULONG ValueBufferSize,
    __in_bcount(ValueBufferSize) PVOID ValueBuffer
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
NTKERNELAPI
NTSTATUS
IoWMIExecuteMethod(
    __in PVOID DataBlockObject,
    __in PUNICODE_STRING InstanceName,
    __in ULONG MethodId,
    __in ULONG InBufferSize,
    __inout PULONG OutBufferSize,
    __inout_bcount_part_opt(*OutBufferSize, InBufferSize) PUCHAR InOutBuffer
    );
#endif

typedef
__drv_functionClass(WMI_NOTIFICATION_CALLBACK)
__drv_sameIRQL
VOID FWMI_NOTIFICATION_CALLBACK (
    PVOID Wnode,
    PVOID Context
    );
typedef FWMI_NOTIFICATION_CALLBACK *WMI_NOTIFICATION_CALLBACK;

#if (NTDDI_VERSION >= NTDDI_WINXP)
NTKERNELAPI
NTSTATUS
IoWMISetNotificationCallback(
    __inout PVOID Object,
    __in WMI_NOTIFICATION_CALLBACK Callback,
    __in_opt PVOID Context
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
NTKERNELAPI
NTSTATUS
IoWMIHandleToInstanceName(
    __in PVOID DataBlockObject,
    __in HANDLE FileHandle,
    __out PUNICODE_STRING InstanceName
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
NTKERNELAPI
NTSTATUS
IoWMIDeviceObjectToInstanceName(
    __in PVOID DataBlockObject,
    __in PDEVICE_OBJECT DeviceObject,
    __out PUNICODE_STRING InstanceName
    );
#endif


#if defined(_WIN64)

__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
BOOLEAN
IoIs32bitProcess(
    __in_opt PIRP Irp
    );

#endif


#if (NTDDI_VERSION >= NTDDI_WINXP)
NTKERNELAPI
VOID
IoFreeErrorLogEntry(
    __in PVOID ElEntry
    );
#endif

// Cancel SAFE API set start
//
// The following APIs are to help ease the pain of writing queue packages that
// handle the cancellation race well. The idea of this set of APIs is to not
// force a single queue data structure but allow the cancel logic to be hidden
// from the drivers. A driver implements a queue and as part of its header
// includes the IO_CSQ structure. In its initialization routine it calls
// IoInitializeCsq. Then in the dispatch routine when the driver wants to
// insert an IRP into the queue it calls IoCsqInsertIrp. When the driver wants
// to remove something from the queue it calls IoCsqRemoveIrp. Note that Insert
// can fail if the IRP was cancelled in the meantime. Remove can also fail if
// the IRP was already cancelled.
//
// There are typically two modes where drivers queue IRPs. These two modes are
// covered by the cancel safe queue API set.
//
// Mode 1:
// One is where the driver queues the IRP and at some later
// point in time dequeues an IRP and issues the IO request.
// For this mode the driver should use IoCsqInsertIrp and IoCsqRemoveNextIrp.
// The driver in this case is expected to pass NULL to the irp context
// parameter in IoInsertIrp.
//
// Mode 2:
// In this the driver queues theIRP, issues the IO request (like issuing a DMA
// request or writing to a register) and when the IO request completes (either
// using a DPC or timer) the driver dequeues the IRP and completes it. For this
// mode the driver should use IoCsqInsertIrp and IoCsqRemoveIrp. In this case
// the driver should allocate an IRP context and pass it in to IoCsqInsertIrp.
// The cancel API code creates an association between the IRP and the context
// and thus ensures that when the time comes to remove the IRP it can ascertain
// correctly.
//
// Note that the cancel API set assumes that the field DriverContext[3] is
// always available for use and that the driver does not use it.
//


//
// Bookkeeping structure. This should be opaque to drivers.
// Drivers typically include this as part of their queue headers.
// Given a CSQ pointer the driver should be able to get its
// queue header using CONTAINING_RECORD macro
//

typedef struct _IO_CSQ IO_CSQ, *PIO_CSQ;

#define IO_TYPE_CSQ_IRP_CONTEXT 1
#define IO_TYPE_CSQ             2
#define IO_TYPE_CSQ_EX          3

//
// IRP context structure. This structure is necessary if the driver is using
// the second mode.
//

typedef struct _IO_CSQ_IRP_CONTEXT {
    ULONG   Type;
    PIRP    Irp;
    PIO_CSQ Csq;
} IO_CSQ_IRP_CONTEXT, *PIO_CSQ_IRP_CONTEXT;

//
// Routines that insert/remove IRP
//

typedef VOID
IO_CSQ_INSERT_IRP (
    __in struct _IO_CSQ    *Csq,
    __in PIRP              Irp
    );

typedef IO_CSQ_INSERT_IRP *PIO_CSQ_INSERT_IRP;

typedef NTSTATUS
IO_CSQ_INSERT_IRP_EX (
    __in struct _IO_CSQ    *Csq,
    __in PIRP              Irp,
    __in PVOID             InsertContext
    );

typedef IO_CSQ_INSERT_IRP_EX *PIO_CSQ_INSERT_IRP_EX;

typedef VOID
IO_CSQ_REMOVE_IRP (
    __in PIO_CSQ Csq,
    __in PIRP    Irp
    );

typedef IO_CSQ_REMOVE_IRP *PIO_CSQ_REMOVE_IRP;

//
// Retrieves next entry after Irp from the queue.
// Returns NULL if there are no entries in the queue.
// If Irp is NUL, returns the entry in the head of the queue.
// This routine does not remove the IRP from the queue.
//


typedef PIRP
IO_CSQ_PEEK_NEXT_IRP (
    __in PIO_CSQ Csq,
    __in PIRP    Irp,
    __in PVOID   PeekContext
    );

typedef IO_CSQ_PEEK_NEXT_IRP *PIO_CSQ_PEEK_NEXT_IRP;

//
// Lock routine that protects the cancel safe queue.
//

typedef VOID
IO_CSQ_ACQUIRE_LOCK (
     __in PIO_CSQ Csq,
     __out PKIRQL  Irql
     );

typedef IO_CSQ_ACQUIRE_LOCK *PIO_CSQ_ACQUIRE_LOCK;

typedef VOID
IO_CSQ_RELEASE_LOCK (
     __in PIO_CSQ Csq,
     __in KIRQL   Irql
     );

typedef IO_CSQ_RELEASE_LOCK *PIO_CSQ_RELEASE_LOCK;

//
// Completes the IRP with STATUS_CANCELLED. IRP is guaranteed to be valid
// In most cases this routine just calls IoCompleteRequest(Irp, STATUS_CANCELLED);
//

typedef VOID
IO_CSQ_COMPLETE_CANCELED_IRP (
    __in PIO_CSQ    Csq,
    __in PIRP       Irp
    );

typedef IO_CSQ_COMPLETE_CANCELED_IRP *PIO_CSQ_COMPLETE_CANCELED_IRP;

//
// Bookkeeping structure. This should be opaque to drivers.
// Drivers typically include this as part of their queue headers.
// Given a CSQ pointer the driver should be able to get its
// queue header using CONTAINING_RECORD macro
//

typedef struct _IO_CSQ {
    ULONG                            Type;
    PIO_CSQ_INSERT_IRP               CsqInsertIrp;
    PIO_CSQ_REMOVE_IRP               CsqRemoveIrp;
    PIO_CSQ_PEEK_NEXT_IRP            CsqPeekNextIrp;
    PIO_CSQ_ACQUIRE_LOCK             CsqAcquireLock;
    PIO_CSQ_RELEASE_LOCK             CsqReleaseLock;
    PIO_CSQ_COMPLETE_CANCELED_IRP    CsqCompleteCanceledIrp;
    PVOID                            ReservePointer;    // Future expansion
} IO_CSQ, *PIO_CSQ;

//
// Initializes the cancel queue structure.
//

#if (NTDDI_VERSION >= NTDDI_WINXP)
NTKERNELAPI
NTSTATUS
IoCsqInitialize(
    __in PIO_CSQ                        Csq,
    __in PIO_CSQ_INSERT_IRP             CsqInsertIrp,
    __in PIO_CSQ_REMOVE_IRP             CsqRemoveIrp,
    __in PIO_CSQ_PEEK_NEXT_IRP          CsqPeekNextIrp,
    __in PIO_CSQ_ACQUIRE_LOCK           CsqAcquireLock,
    __in PIO_CSQ_RELEASE_LOCK           CsqReleaseLock,
    __in PIO_CSQ_COMPLETE_CANCELED_IRP  CsqCompleteCanceledIrp
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WS03)
NTKERNELAPI
NTSTATUS
IoCsqInitializeEx(
    __in PIO_CSQ                        Csq,
    __in PIO_CSQ_INSERT_IRP_EX          CsqInsertIrp,
    __in PIO_CSQ_REMOVE_IRP             CsqRemoveIrp,
    __in PIO_CSQ_PEEK_NEXT_IRP          CsqPeekNextIrp,
    __in PIO_CSQ_ACQUIRE_LOCK           CsqAcquireLock,
    __in PIO_CSQ_RELEASE_LOCK           CsqReleaseLock,
    __in PIO_CSQ_COMPLETE_CANCELED_IRP  CsqCompleteCanceledIrp
    );
#endif

//
// The caller calls this routine to insert the IRP and return STATUS_PENDING.
//

#if (NTDDI_VERSION >= NTDDI_WINXP)
NTKERNELAPI
VOID
IoCsqInsertIrp(
    __in PIO_CSQ                 Csq,
    __in PIRP                    Irp,
    __in_opt PIO_CSQ_IRP_CONTEXT Context
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WS03)
NTKERNELAPI
NTSTATUS
IoCsqInsertIrpEx(
    __in PIO_CSQ                 Csq,
    __in PIRP                    Irp,
    __in_opt PIO_CSQ_IRP_CONTEXT Context,
    __in_opt PVOID               InsertContext
    );
#endif

//
// Returns an IRP if one can be found. NULL otherwise.
//

#if (NTDDI_VERSION >= NTDDI_WINXP)
NTKERNELAPI
PIRP
IoCsqRemoveNextIrp(
    __in     PIO_CSQ Csq,
    __in_opt PVOID   PeekContext
    );
#endif

//
// This routine is called from timeout or DPCs.
// The context is presumably part of the DPC or timer context.
// If succesfull returns the IRP associated with context.
//

#if (NTDDI_VERSION >= NTDDI_WINXP)
NTKERNELAPI
PIRP
IoCsqRemoveIrp(
    __in PIO_CSQ             Csq,
    __in PIO_CSQ_IRP_CONTEXT Context
    );
#endif

// Cancel SAFE API set end


#if (NTDDI_VERSION >= NTDDI_WINXPSP1)
NTKERNELAPI
NTSTATUS
IoValidateDeviceIoControlAccess(
    __in PIRP   Irp,
    __in ULONG  RequiredAccess
    );
#endif


#if (NTDDI_VERSION >= NTDDI_VISTA)
IO_PRIORITY_HINT
IoGetIoPriorityHint(
    __in PIRP Irp
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
NTSTATUS
IoSetIoPriorityHint(
    __in PIRP               Irp,
    __in IO_PRIORITY_HINT   PriorityHint
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
NTSTATUS
IoAllocateSfioStreamIdentifier(
    __in  PFILE_OBJECT  FileObject,
    __in  ULONG         Length,
    __in  PVOID         Signature,
    __out PVOID         *StreamIdentifier
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
PVOID
IoGetSfioStreamIdentifier(
    __in PFILE_OBJECT   FileObject,
    __in PVOID          Signature
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
NTSTATUS
IoFreeSfioStreamIdentifier(
    __in PFILE_OBJECT   FileObject,
    __in PVOID          Signature
    );
#endif

typedef enum _IO_ACCESS_TYPE {

    //
    // Indicates that the Io will
    // be comprised solely of reads
    //
    ReadAccess,

    //
    // Indicates that the Io will
    // be comprised solely of writes
    //
    WriteAccess,

    //
    // Indicates that the Io will be
    // comprised of reads and writes
    //
    ModifyAccess

} IO_ACCESS_TYPE;

typedef enum _IO_ACCESS_MODE {

    //
    // Indicates that the Io will be
    // sent down in a sequential order
    //
    SequentialAccess,

    //
    // Indicates that the Io might
    // not be in a predictable order
    //
    RandomAccess

} IO_ACCESS_MODE;

typedef enum _IO_CONTAINER_NOTIFICATION_CLASS {
    IoSessionStateNotification, // 0 - Session State Notifications
    IoMaxContainerNotificationClass
} IO_CONTAINER_NOTIFICATION_CLASS;

typedef struct _IO_SESSION_STATE_NOTIFICATION {
    ULONG Size;
    ULONG Flags;
    PVOID IoObject;
    ULONG EventMask;
    PVOID Context;
} IO_SESSION_STATE_NOTIFICATION, *PIO_SESSION_STATE_NOTIFICATION;

typedef enum _IO_CONTAINER_INFORMATION_CLASS {
    IoSessionStateInformation, // 0 - Session State Information
    IoMaxContainerInformationClass
} IO_CONTAINER_INFORMATION_CLASS;

typedef struct _IO_SESSION_STATE_INFORMATION {
    ULONG SessionId;
    IO_SESSION_STATE SessionState;
    BOOLEAN LocalSession;
} IO_SESSION_STATE_INFORMATION, *PIO_SESSION_STATE_INFORMATION;

#if (NTDDI_VERSION >= NTDDI_WIN7)
NTSTATUS
IoGetContainerInformation (
    __in IO_CONTAINER_INFORMATION_CLASS InformationClass,
    __in_opt PVOID ContainerObject,
    __inout_bcount_opt(BufferLength) PVOID Buffer,
    __in ULONG BufferLength
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)

typedef NTSTATUS (*PIO_CONTAINER_NOTIFICATION_FUNCTION)();

typedef
NTSTATUS
IO_SESSION_NOTIFICATION_FUNCTION (
    __in PVOID SessionObject,
    __in PVOID IoObject,
    __in ULONG Event,
    __in PVOID Context,
    __in_bcount_opt(PayloadLength) PVOID NotificationPayload,
    __in ULONG PayloadLength
    );

typedef IO_SESSION_NOTIFICATION_FUNCTION *PIO_SESSION_NOTIFICATION_FUNCTION;
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
NTSTATUS
IoRegisterContainerNotification(
    __in IO_CONTAINER_NOTIFICATION_CLASS NotificationClass,
    __in PIO_CONTAINER_NOTIFICATION_FUNCTION CallbackFunction,
    __in_bcount_opt(NotificationInformationLength) PVOID NotificationInformation,
    __in ULONG NotificationInformationLength,
    __out PVOID CallbackRegistration
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
VOID
IoUnregisterContainerNotification(
    __in PVOID CallbackRegistration
    );
#endif


#ifdef RUN_WPP

#include <evntrace.h>
#include <stdarg.h>

#endif // #ifdef RUN_WPP



#ifndef _TRACEHANDLE_DEFINED
#define _TRACEHANDLE_DEFINED
typedef ULONG64 TRACEHANDLE, *PTRACEHANDLE;
#endif

//
// Trace Provider APIs
//

#ifdef RUN_WPP

#if (NTDDI_VERSION >= NTDDI_WINXP)
__drv_maxIRQL(HIGH_LEVEL)
NTKERNELAPI
NTSTATUS
WmiTraceMessage(
    __in TRACEHANDLE LoggerHandle,
    __in ULONG MessageFlags,
    __in LPCGUID MessageGuid,
    __in USHORT MessageNumber,
    ...
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
__drv_maxIRQL(HIGH_LEVEL)
NTKERNELAPI
NTSTATUS
WmiTraceMessageVa(
    __in TRACEHANDLE LoggerHandle,
    __in ULONG MessageFlags,
    __in LPCGUID MessageGuid,
    __in USHORT MessageNumber,
    __in va_list MessageArgList
    );
#endif

#endif // #ifdef RUN_WPP

#ifndef TRACE_INFORMATION_CLASS_DEFINE

typedef struct _ETW_TRACE_SESSION_SETTINGS {
    ULONG Version;
    ULONG BufferSize;
    ULONG MinimumBuffers;
    ULONG MaximumBuffers;
    ULONG LoggerMode;
    ULONG FlushTimer;
    ULONG FlushThreshold;
    ULONG ClockType;
} ETW_TRACE_SESSION_SETTINGS, *PETW_TRACE_SESSION_SETTINGS;

typedef enum _TRACE_INFORMATION_CLASS {
    TraceIdClass,
    TraceHandleClass,
    TraceEnableFlagsClass,
    TraceEnableLevelClass,
    GlobalLoggerHandleClass,
    EventLoggerHandleClass,
    AllLoggerHandlesClass,
    TraceHandleByNameClass,
    LoggerEventsLostClass,
    TraceSessionSettingsClass,
    LoggerEventsLoggedClass,
    MaxTraceInformationClass
} TRACE_INFORMATION_CLASS;

#if (NTDDI_VERSION >= NTDDI_WINXP)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
NTSTATUS
WmiQueryTraceInformation(
    __in TRACE_INFORMATION_CLASS TraceInformationClass,
    __out_bcount(TraceInformationLength) PVOID TraceInformation,
    __in ULONG TraceInformationLength,
    __out_opt PULONG RequiredLength,
    __in_opt PVOID Buffer
    );
#endif 

#define TRACE_INFORMATION_CLASS_DEFINE
#endif // TRACE_INFOPRMATION_CLASS_DEFINE


#ifndef _ETW_KM_
#define _ETW_KM_
#endif

#include <evntprov.h>


//
// Optional callback function that users provide.
//

__drv_sameIRQL
typedef
VOID
(NTAPI *PETWENABLECALLBACK) (
    __in LPCGUID SourceId,
    __in ULONG ControlCode,
    __in UCHAR Level,
    __in ULONGLONG MatchAnyKeyword,
    __in ULONGLONG MatchAllKeyword,
    __in_opt PEVENT_FILTER_DESCRIPTOR FilterData,
    __inout_opt PVOID CallbackContext
    );

//
// Kernel Mode Registration APIs.
//

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSTATUS
NTKERNELAPI
EtwRegister(
    __in LPCGUID ProviderId,
    __in_opt PETWENABLECALLBACK EnableCallback,
    __in_opt PVOID CallbackContext,
    __out PREGHANDLE RegHandle
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSTATUS
NTKERNELAPI
EtwUnregister(
    __in REGHANDLE RegHandle
    );
#endif

//
// Kernel Mode Control (Is Enabled) APIs
//

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(HIGH_LEVEL)
BOOLEAN
NTKERNELAPI
EtwEventEnabled(
    __in REGHANDLE RegHandle,
    __in PCEVENT_DESCRIPTOR EventDescriptor
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(HIGH_LEVEL)
BOOLEAN
NTKERNELAPI
EtwProviderEnabled(
    __in REGHANDLE RegHandle,
    __in UCHAR Level,
    __in ULONGLONG Keyword
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_when(ControlCode==EVENT_ACTIVITY_CTRL_CREATE_ID, __drv_maxIRQL(HIGH_LEVEL))
__drv_when(ControlCode!=EVENT_ACTIVITY_CTRL_CREATE_ID, __drv_maxIRQL(APC_LEVEL))
NTSTATUS
NTKERNELAPI
EtwActivityIdControl(
    __in ULONG ControlCode,
    __inout_bcount(sizeof(GUID))LPGUID ActivityId
    );
#endif

//
// Kernel Mode Writing (Publishing/Logging) APIs
//

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(HIGH_LEVEL)
NTSTATUS
NTKERNELAPI
EtwWrite(
    __in REGHANDLE RegHandle,
    __in PCEVENT_DESCRIPTOR EventDescriptor,
    __in_opt LPCGUID ActivityId,
    __in ULONG UserDataCount,
    __in_ecount_opt(UserDataCount) PEVENT_DATA_DESCRIPTOR  UserData
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(HIGH_LEVEL)
NTSTATUS
NTKERNELAPI
EtwWriteTransfer(
    __in REGHANDLE RegHandle,
    __in PCEVENT_DESCRIPTOR EventDescriptor,
    __in_opt LPCGUID ActivityId,
    __in_opt LPCGUID RelatedActivityId,
    __in ULONG UserDataCount,
    __in_ecount_opt(UserDataCount) PEVENT_DATA_DESCRIPTOR UserData
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(HIGH_LEVEL)
NTSTATUS
NTKERNELAPI
EtwWriteString(
    __in REGHANDLE RegHandle,
    __in UCHAR Level,
    __in ULONGLONG Keyword,
    __in_opt LPCGUID ActivityId,
    __in PCWSTR String
    );
#endif

#define EVENT_WRITE_FLAG_NO_FAULTING 0x00000001

#if (NTDDI_VERSION >= NTDDI_WIN7)
__drv_maxIRQL(HIGH_LEVEL)
NTSTATUS
NTKERNELAPI
EtwWriteEx(
    __in REGHANDLE RegHandle,
    __in PCEVENT_DESCRIPTOR EventDescriptor,
    __in ULONG64 Filter,
    __in ULONG Flags,
    __in_opt LPCGUID ActivityId,
    __in_opt LPCGUID RelatedActivityId,
    __in ULONG UserDataCount,
    __in_ecount_opt(UserDataCount) PEVENT_DATA_DESCRIPTOR UserData
    );
#endif


//
// Define PnP Device Property for IoGetDeviceProperty
//

#ifdef _PREFAST_
#define __string_type 0x1000
#define __guid_type 0x2000
#define __multiString_type 0x4000
#else
#define __string_type 0
#define __guid_type 0
#define __multiString_type 0
#endif

typedef enum {
    DevicePropertyDeviceDescription = 0x0 | __string_type,
    DevicePropertyHardwareID = 0x1 | __multiString_type,
    DevicePropertyCompatibleIDs = 0x2 | __multiString_type,
    DevicePropertyBootConfiguration = 0x3,
    DevicePropertyBootConfigurationTranslated = 0x4,
    DevicePropertyClassName = 0x5 | __string_type,
    DevicePropertyClassGuid = 0x6 | __string_type,
    DevicePropertyDriverKeyName = 0x7 | __string_type,
    DevicePropertyManufacturer = 0x8 | __string_type,
    DevicePropertyFriendlyName = 0x9 | __string_type,
    DevicePropertyLocationInformation = 0xa | __string_type,
    DevicePropertyPhysicalDeviceObjectName = 0xb | __string_type,
    DevicePropertyBusTypeGuid = 0xc | __guid_type,
    DevicePropertyLegacyBusType = 0xd,
    DevicePropertyBusNumber = 0xe,
    DevicePropertyEnumeratorName = 0xf | __string_type,
    DevicePropertyAddress = 0x10,
    DevicePropertyUINumber = 0x11,
    DevicePropertyInstallState = 0x12,
    DevicePropertyRemovalPolicy = 0x13,
    DevicePropertyResourceRequirements = 0x14,
    DevicePropertyAllocatedResources = 0x15,
    DevicePropertyContainerID = 0x16 | __string_type
} DEVICE_REGISTRY_PROPERTY;

typedef
__drv_functionClass(TRANSLATE_BUS_ADDRESS)
__drv_sameIRQL
BOOLEAN TRANSLATE_BUS_ADDRESS(
    __inout_opt PVOID Context,
    __in PHYSICAL_ADDRESS BusAddress,
    __in ULONG Length,
    __out PULONG AddressSpace,
    __out PPHYSICAL_ADDRESS TranslatedAddress
    );
typedef TRANSLATE_BUS_ADDRESS *PTRANSLATE_BUS_ADDRESS;

typedef
__drv_functionClass(GET_DMA_ADAPTER)
__drv_sameIRQL
struct _DMA_ADAPTER *GET_DMA_ADAPTER(
    __inout_opt PVOID Context,
    __in struct _DEVICE_DESCRIPTION *DeviceDescriptor,
    __out PULONG NumberOfMapRegisters
    );
typedef GET_DMA_ADAPTER *PGET_DMA_ADAPTER;

typedef
__drv_functionClass(GET_SET_DEVICE_DATA)
__drv_sameIRQL
ULONG GET_SET_DEVICE_DATA (
    __inout_opt PVOID Context,
    __in ULONG DataType,
    __inout_bcount(Length) PVOID Buffer,
    __in ULONG Offset,
    __in ULONG Length
    );
typedef GET_SET_DEVICE_DATA *PGET_SET_DEVICE_DATA;

typedef enum _DEVICE_INSTALL_STATE {
    InstallStateInstalled,
    InstallStateNeedsReinstall,
    InstallStateFailedInstall,
    InstallStateFinishInstall
} DEVICE_INSTALL_STATE, *PDEVICE_INSTALL_STATE;

//
// Define structure returned in response to IRP_MN_QUERY_BUS_INFORMATION by a
// PDO indicating the type of bus the device exists on.
//

typedef struct _PNP_BUS_INFORMATION {
    GUID BusTypeGuid;
    INTERFACE_TYPE LegacyBusType;
    ULONG BusNumber;
} PNP_BUS_INFORMATION, *PPNP_BUS_INFORMATION;

//
// Define structure returned in response to IRP_MN_QUERY_LEGACY_BUS_INFORMATION
// by an FDO indicating the type of bus it is.  This is normally the same bus
// type as the device's children (i.e., as retrieved from the child PDO's via
// IRP_MN_QUERY_BUS_INFORMATION) except for cases like CardBus, which can
// support both 16-bit (PCMCIABus) and 32-bit (PCIBus) cards.
//

typedef struct _LEGACY_BUS_INFORMATION {
    GUID BusTypeGuid;
    INTERFACE_TYPE LegacyBusType;
    ULONG BusNumber;
} LEGACY_BUS_INFORMATION, *PLEGACY_BUS_INFORMATION;

//
// Defines for IoGetDeviceProperty(DevicePropertyRemovalPolicy).
//
typedef enum _DEVICE_REMOVAL_POLICY {

    RemovalPolicyExpectNoRemoval = 1,
    RemovalPolicyExpectOrderlyRemoval = 2,
    RemovalPolicyExpectSurpriseRemoval = 3

} DEVICE_REMOVAL_POLICY, *PDEVICE_REMOVAL_POLICY;



typedef struct _BUS_INTERFACE_STANDARD {
    //
    // generic interface header
    //
    USHORT Size;
    USHORT Version;
    PVOID Context;
    PINTERFACE_REFERENCE InterfaceReference;
    PINTERFACE_DEREFERENCE InterfaceDereference;
    //
    // standard bus interfaces
    //
    PTRANSLATE_BUS_ADDRESS TranslateBusAddress;
    PGET_DMA_ADAPTER GetDmaAdapter;
    PGET_SET_DEVICE_DATA SetBusData;
    PGET_SET_DEVICE_DATA GetBusData;

} BUS_INTERFACE_STANDARD, *PBUS_INTERFACE_STANDARD;

typedef
VOID
(*PREENUMERATE_SELF)(
    __in PVOID Context
    );

typedef struct _REENUMERATE_SELF_INTERFACE_STANDARD {
    //
    // generic interface header
    //
    USHORT Size;
    USHORT Version;
    PVOID Context;
    PINTERFACE_REFERENCE InterfaceReference;
    PINTERFACE_DEREFERENCE InterfaceDereference;
    //
    // Self-reenumeration interface
    //
    PREENUMERATE_SELF SurpriseRemoveAndReenumerateSelf;
} REENUMERATE_SELF_INTERFACE_STANDARD, *PREENUMERATE_SELF_INTERFACE_STANDARD;


//
// The following definitions are used in ACPI QueryInterface
//
typedef BOOLEAN (* PGPE_SERVICE_ROUTINE) (
                            PVOID,
                            PVOID);

typedef
__drv_maxIRQL(DISPATCH_LEVEL)
__checkReturn
NTSTATUS (* PGPE_CONNECT_VECTOR) (
                            PDEVICE_OBJECT,
                            ULONG,
                            KINTERRUPT_MODE,
                            BOOLEAN,
                            PGPE_SERVICE_ROUTINE,
                            PVOID,
                            PVOID);

typedef
__drv_maxIRQL(DISPATCH_LEVEL)
__checkReturn
NTSTATUS (* PGPE_DISCONNECT_VECTOR) (
                            PVOID);

typedef
__drv_maxIRQL(DISPATCH_LEVEL)
__checkReturn
NTSTATUS (* PGPE_ENABLE_EVENT) (
                            PDEVICE_OBJECT,
                            PVOID);

typedef
__drv_maxIRQL(DISPATCH_LEVEL)
__checkReturn
NTSTATUS (* PGPE_DISABLE_EVENT) (
                            PDEVICE_OBJECT,
                            PVOID);

typedef
__drv_maxIRQL(DISPATCH_LEVEL)
__checkReturn
NTSTATUS (* PGPE_CLEAR_STATUS) (
                            PDEVICE_OBJECT,
                            PVOID);

typedef
VOID (* PDEVICE_NOTIFY_CALLBACK) (
                            PVOID,
                            ULONG);

typedef
__drv_maxIRQL(DISPATCH_LEVEL)
__checkReturn
NTSTATUS (* PREGISTER_FOR_DEVICE_NOTIFICATIONS) (
                            PDEVICE_OBJECT,
                            PDEVICE_NOTIFY_CALLBACK,
                            PVOID);

typedef
__drv_maxIRQL(DISPATCH_LEVEL)
void (* PUNREGISTER_FOR_DEVICE_NOTIFICATIONS) (
                            PDEVICE_OBJECT,
                            PDEVICE_NOTIFY_CALLBACK);

typedef struct _ACPI_INTERFACE_STANDARD {
    //
    // Generic interface header
    //
    USHORT                  Size;
    USHORT                  Version;
    PVOID                   Context;
    PINTERFACE_REFERENCE    InterfaceReference;
    PINTERFACE_DEREFERENCE  InterfaceDereference;
    //
    // ACPI interfaces
    //
    PGPE_CONNECT_VECTOR                     GpeConnectVector;
    PGPE_DISCONNECT_VECTOR                  GpeDisconnectVector;
    PGPE_ENABLE_EVENT                       GpeEnableEvent;
    PGPE_DISABLE_EVENT                      GpeDisableEvent;
    PGPE_CLEAR_STATUS                       GpeClearStatus;
    PREGISTER_FOR_DEVICE_NOTIFICATIONS      RegisterForDeviceNotifications;
    PUNREGISTER_FOR_DEVICE_NOTIFICATIONS    UnregisterForDeviceNotifications;

} ACPI_INTERFACE_STANDARD, *PACPI_INTERFACE_STANDARD;

//
// The following definitions are used in GUID_ACPI_INTERFACE_STANDARD2,
// The first version (above) passes in DEVICE_OBJECs, where this one
// is based on Contexts.
//

typedef
BOOLEAN
(*PGPE_SERVICE_ROUTINE2) (
    PVOID   ObjectContext,
    PVOID   ServiceContext
    );

typedef
__drv_maxIRQL(DISPATCH_LEVEL)
__checkReturn
NTSTATUS
(*PGPE_CONNECT_VECTOR2) (
    PVOID           Context,
    ULONG           GpeNumber,
    KINTERRUPT_MODE Mode,
    BOOLEAN         Shareable,
    PGPE_SERVICE_ROUTINE    ServiceRoutine,
    PVOID           ServiceContext,
    PVOID           *ObjectContext
    );

typedef
__drv_maxIRQL(DISPATCH_LEVEL)
__checkReturn
NTSTATUS
(*PGPE_DISCONNECT_VECTOR2) (
    PVOID   Context,
    PVOID   ObjectContext
    );

typedef
__drv_maxIRQL(DISPATCH_LEVEL)
__checkReturn
NTSTATUS
(*PGPE_ENABLE_EVENT2) (
    PVOID   Context,
    PVOID   ObjectContext
    );

typedef
__drv_maxIRQL(DISPATCH_LEVEL)
__checkReturn
NTSTATUS
(*PGPE_DISABLE_EVENT2) (
    PVOID   Context,
    PVOID   ObjectContext
    );

typedef
__drv_maxIRQL(DISPATCH_LEVEL)
__checkReturn
NTSTATUS
(*PGPE_CLEAR_STATUS2) (
    PVOID   Context,
    PVOID   ObjectContext
    );

typedef
__drv_maxIRQL(DISPATCH_LEVEL)
VOID
(*PDEVICE_NOTIFY_CALLBACK2) (
    PVOID   NotificationContext,
    ULONG   NotifyCode
    );

typedef
__drv_maxIRQL(DISPATCH_LEVEL)
__checkReturn
NTSTATUS
(*PREGISTER_FOR_DEVICE_NOTIFICATIONS2) (
    PVOID   Context,
    PDEVICE_NOTIFY_CALLBACK2    NotificationHandler,
    PVOID   NotificationContext
    );

typedef
__drv_maxIRQL(DISPATCH_LEVEL)
VOID
(*PUNREGISTER_FOR_DEVICE_NOTIFICATIONS2) (
    PVOID   Context
    );

typedef struct {
    //
    // Generic interface header
    //
    USHORT                  Size;
    USHORT                  Version;
    PVOID                   Context;
    PINTERFACE_REFERENCE    InterfaceReference;
    PINTERFACE_DEREFERENCE  InterfaceDereference;
    //
    // ACPI interfaces
    //
    PGPE_CONNECT_VECTOR2                    GpeConnectVector;
    PGPE_DISCONNECT_VECTOR2                 GpeDisconnectVector;
    PGPE_ENABLE_EVENT2                      GpeEnableEvent;
    PGPE_DISABLE_EVENT2                     GpeDisableEvent;
    PGPE_CLEAR_STATUS2                      GpeClearStatus;
    PREGISTER_FOR_DEVICE_NOTIFICATIONS2     RegisterForDeviceNotifications;
    PUNREGISTER_FOR_DEVICE_NOTIFICATIONS2   UnregisterForDeviceNotifications;

} ACPI_INTERFACE_STANDARD2, *PACPI_INTERFACE_STANDARD2;


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
VOID
IoInvalidateDeviceRelations(
    __in PDEVICE_OBJECT DeviceObject,
    __in DEVICE_RELATION_TYPE Type
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
VOID
IoRequestDeviceEject(
    __in PDEVICE_OBJECT PhysicalDeviceObject
    );
#endif

typedef VOID (*PIO_DEVICE_EJECT_CALLBACK)(
    __in NTSTATUS Status,
    __inout_opt PVOID Context
    );

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(DISPATCH_LEVEL)
__checkReturn
NTKERNELAPI
NTSTATUS
IoRequestDeviceEjectEx(
    __in PDEVICE_OBJECT PhysicalDeviceObject,
    __in_opt PIO_DEVICE_EJECT_CALLBACK Callback,
    __in_opt PVOID Context,
    __in_opt PDRIVER_OBJECT DriverObject
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
__drv_when((DeviceProperty & __string_type),
    __drv_at(PropertyBuffer,
        __post __nullterminated)
    )
__drv_when((DeviceProperty & __multiString_type),
    __drv_at(PropertyBuffer,
        __post __nullnullterminated)
    )
NTKERNELAPI
NTSTATUS
IoGetDeviceProperty(
    __in PDEVICE_OBJECT DeviceObject,
    __in DEVICE_REGISTRY_PROPERTY DeviceProperty,
    __in ULONG BufferLength,
    __out_bcount_opt(BufferLength) PVOID PropertyBuffer,
    __out PULONG ResultLength
    );
#endif

//
// The following definitions are used in IoOpenDeviceRegistryKey
//

#define PLUGPLAY_REGKEY_DEVICE  1
#define PLUGPLAY_REGKEY_DRIVER  2
#define PLUGPLAY_REGKEY_CURRENT_HWPROFILE 4

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
__checkReturn
NTKERNELAPI
NTSTATUS
IoOpenDeviceRegistryKey(
    __in PDEVICE_OBJECT DeviceObject,
    __in ULONG DevInstKeyType,
    __in ACCESS_MASK DesiredAccess,
    __out PHANDLE DevInstRegKey
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
__checkReturn
NTKERNELAPI
NTSTATUS
NTAPI
IoRegisterDeviceInterface(
    __in PDEVICE_OBJECT PhysicalDeviceObject,
    __in CONST GUID *InterfaceClassGuid,
    __in_opt PUNICODE_STRING ReferenceString,
    __out __drv_when(return==0, 
                     __drv_at(SymbolicLinkName->Buffer, __drv_allocatesMem(Mem)))
    PUNICODE_STRING SymbolicLinkName
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
__checkReturn
NTKERNELAPI
NTSTATUS
IoOpenDeviceInterfaceRegistryKey(
    __in PUNICODE_STRING SymbolicLinkName,
    __in ACCESS_MASK DesiredAccess,
    __out PHANDLE DeviceInterfaceKey
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL) __drv_valueIs(>=0;<0)
__checkReturn
NTKERNELAPI
NTSTATUS
IoSetDeviceInterfaceState(
    __in PUNICODE_STRING SymbolicLinkName,
    __in BOOLEAN Enable
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
__checkReturn
NTKERNELAPI
NTSTATUS
NTAPI
IoGetDeviceInterfaces(
    __in CONST GUID *InterfaceClassGuid,
    __in_opt PDEVICE_OBJECT PhysicalDeviceObject,
    __in ULONG Flags,
    __deref_out 
    __drv_deref(
        __drv_when(return==0, __drv_allocatesMem(Mem) __drv_valueIs(!=0))
        __drv_when(return<0, __drv_valueIs(==0))) 
    PWSTR *SymbolicLinkList
    );
#endif

#define DEVICE_INTERFACE_INCLUDE_NONACTIVE   0x00000001

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
__checkReturn
NTKERNELAPI
NTSTATUS
NTAPI
IoGetDeviceInterfaceAlias(
    __in PUNICODE_STRING SymbolicLinkName,
    __in CONST GUID *AliasInterfaceClassGuid,
    __out 
    __drv_when(return==0, 
               __drv_at(AliasSymbolicLinkName->Buffer, __drv_allocatesMem(Mem)))
    PUNICODE_STRING AliasSymbolicLinkName
    );
#endif

//
// Define PnP notification event categories
//

typedef enum _IO_NOTIFICATION_EVENT_CATEGORY {
    EventCategoryReserved,
    EventCategoryHardwareProfileChange,
    EventCategoryDeviceInterfaceChange,
    EventCategoryTargetDeviceChange
} IO_NOTIFICATION_EVENT_CATEGORY;

//
// Define flags that modify the behavior of IoRegisterPlugPlayNotification
// for the various event categories...
//

#define PNPNOTIFY_DEVICE_INTERFACE_INCLUDE_EXISTING_INTERFACES    0x00000001

typedef
__drv_functionClass(DRIVER_NOTIFICATION_CALLBACK_ROUTINE)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSTATUS
DRIVER_NOTIFICATION_CALLBACK_ROUTINE (
    __in PVOID NotificationStructure,
    __inout_opt PVOID Context
);
typedef DRIVER_NOTIFICATION_CALLBACK_ROUTINE
    *PDRIVER_NOTIFICATION_CALLBACK_ROUTINE;


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
__checkReturn
NTKERNELAPI
NTSTATUS
IoRegisterPlugPlayNotification(
    __in IO_NOTIFICATION_EVENT_CATEGORY EventCategory,
    __in ULONG EventCategoryFlags,
    __in_opt PVOID EventCategoryData,
    __in PDRIVER_OBJECT DriverObject,
    __in PDRIVER_NOTIFICATION_CALLBACK_ROUTINE CallbackRoutine,
    __inout_opt __drv_aliasesMem PVOID Context,
    __deref_out 
    __drv_deref(
        __drv_when(return==0, __drv_allocatesMem(Mem) __drv_valueIs(!=0)) 
        __drv_when(return<0, __drv_valueIs(==0)))
    PVOID *NotificationEntry
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
__drv_freesMem(Pool)
NTKERNELAPI
NTSTATUS
IoUnregisterPlugPlayNotification(
    __in PVOID NotificationEntry
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
__drv_maxIRQL(PASSIVE_LEVEL)
__drv_freesMem(Pool)
NTKERNELAPI
NTSTATUS
IoUnregisterPlugPlayNotificationEx(
    __in PVOID NotificationEntry
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
NTSTATUS
IoReportTargetDeviceChange(
    __in PDEVICE_OBJECT PhysicalDeviceObject,
    __in PVOID NotificationStructure  // always begins with a PLUGPLAY_NOTIFICATION_HEADER
    );
#endif

typedef
__drv_functionClass(DEVICE_CHANGE_COMPLETE_CALLBACK)
__drv_sameIRQL
VOID
DEVICE_CHANGE_COMPLETE_CALLBACK(
    __inout_opt PVOID Context
    );
typedef DEVICE_CHANGE_COMPLETE_CALLBACK *PDEVICE_CHANGE_COMPLETE_CALLBACK;

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
VOID
IoInvalidateDeviceState(
    __in PDEVICE_OBJECT PhysicalDeviceObject
    );
#endif

#define IoAdjustPagingPathCount(_count_,_paging_) {     \
    if (_paging_) {                                     \
        InterlockedIncrement(_count_);                  \
    } else {                                            \
        InterlockedDecrement(_count_);                  \
    }                                                   \
}

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
NTSTATUS
IoReportTargetDeviceChangeAsynchronous(
    __in PDEVICE_OBJECT PhysicalDeviceObject,
    __in PVOID NotificationStructure,  // always begins with a PLUGPLAY_NOTIFICATION_HEADER
    __in_opt PDEVICE_CHANGE_COMPLETE_CALLBACK Callback,
    __inout_opt PVOID Context
    );
#endif


//
// Header structure for all Plug&Play notification events...
//

typedef struct _PLUGPLAY_NOTIFICATION_HEADER {
    USHORT Version; // presently at version 1.
    USHORT Size;    // size (in bytes) of header + event-specific data.
    GUID Event;
    //
    // Event-specific stuff starts here.
    //
} PLUGPLAY_NOTIFICATION_HEADER, *PPLUGPLAY_NOTIFICATION_HEADER;

//
// Notification structure for all EventCategoryHardwareProfileChange events...
//

typedef struct _HWPROFILE_CHANGE_NOTIFICATION {
    USHORT Version;
    USHORT Size;
    GUID Event;
    //
    // (No event-specific data)
    //
} HWPROFILE_CHANGE_NOTIFICATION, *PHWPROFILE_CHANGE_NOTIFICATION;


//
// Notification structure for all EventCategoryDeviceInterfaceChange events...
//

typedef struct _DEVICE_INTERFACE_CHANGE_NOTIFICATION {
    USHORT Version;
    USHORT Size;
    GUID Event;
    //
    // Event-specific data
    //
    GUID InterfaceClassGuid;
    PUNICODE_STRING SymbolicLinkName;
} DEVICE_INTERFACE_CHANGE_NOTIFICATION, *PDEVICE_INTERFACE_CHANGE_NOTIFICATION;


//
// Notification structures for EventCategoryTargetDeviceChange...
//

//
// The following structure is used for TargetDeviceQueryRemove,
// TargetDeviceRemoveCancelled, and TargetDeviceRemoveComplete:
//
typedef struct _TARGET_DEVICE_REMOVAL_NOTIFICATION {
    USHORT Version;
    USHORT Size;
    GUID Event;
    //
    // Event-specific data
    //
    PFILE_OBJECT FileObject;
} TARGET_DEVICE_REMOVAL_NOTIFICATION, *PTARGET_DEVICE_REMOVAL_NOTIFICATION;

//
// The following structure header is used for all other (i.e., 3rd-party)
// target device change events.  The structure accommodates both a
// variable-length binary data buffer, and a variable-length unicode text
// buffer.  The header must indicate where the text buffer begins, so that
// the data can be delivered in the appropriate format (ANSI or Unicode)
// to user-mode recipients (i.e., that have registered for handle-based
// notification via RegisterDeviceNotification).
//

typedef struct _TARGET_DEVICE_CUSTOM_NOTIFICATION {
    USHORT Version;
    USHORT Size;
    GUID Event;
    //
    // Event-specific data
    //
    PFILE_OBJECT FileObject;    // This field must be set to NULL by callers of
                                // IoReportTargetDeviceChange.  Clients that
                                // have registered for target device change
                                // notification on the affected PDO will be
                                // called with this field set to the file object
                                // they specified during registration.
                                //
    LONG NameBufferOffset;      // offset (in bytes) from beginning of
                                // CustomDataBuffer where text begins (-1 if none)
                                //
    UCHAR CustomDataBuffer[1];  // variable-length buffer, containing (optionally)
                                // a binary data at the start of the buffer,
                                // followed by an optional unicode text buffer
                                // (word-aligned).
                                //
} TARGET_DEVICE_CUSTOM_NOTIFICATION, *PTARGET_DEVICE_CUSTOM_NOTIFICATION;

#if (NTDDI_VERSION >= NTDDI_VISTA)

//
// Custom device properties...
//

#include <devpropdef.h>

//
// Definitions of property flags.
//

#define PLUGPLAY_PROPERTY_PERSISTENT  0x00000001

#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(PASSIVE_LEVEL)
__checkReturn
NTKERNELAPI
NTSTATUS
IoSetDevicePropertyData (
    __in PDEVICE_OBJECT     Pdo,
    __in CONST DEVPROPKEY   *PropertyKey,
    __in LCID               Lcid,
    __in ULONG              Flags,
    __in DEVPROPTYPE        Type,
    __in ULONG              Size,
    __in_opt PVOID          Data
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(PASSIVE_LEVEL)
__checkReturn
NTKERNELAPI
NTSTATUS
IoGetDevicePropertyData (
    __in PDEVICE_OBJECT     Pdo,
    __in CONST DEVPROPKEY   *PropertyKey,
    __in LCID               Lcid,
    __reserved ULONG        Flags,
    __in ULONG              Size,
    __out PVOID             Data,
    __out PULONG            RequiredSize,
    __out PDEVPROPTYPE      Type
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
__drv_maxIRQL(PASSIVE_LEVEL)
__checkReturn
NTKERNELAPI
NTSTATUS
IoGetDeviceNumaNode (
    __in PDEVICE_OBJECT Pdo,
    __out PUSHORT NodeNumber
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WS08)
__drv_maxIRQL(PASSIVE_LEVEL)
__checkReturn
NTKERNELAPI
NTSTATUS
NTAPI
IoReplacePartitionUnit (
    __in PDEVICE_OBJECT TargetPdo,
    __in PDEVICE_OBJECT SparePdo,
    __in ULONG Flags
    );
#endif


//
// Define replace driver entrypoint.
//

typedef struct _PNP_REPLACE_DRIVER_INTERFACE *PPNP_REPLACE_DRIVER_INTERFACE;

typedef
__checkReturn
NTSTATUS
(*PREPLACE_DRIVER_INIT) (
    __inout PPNP_REPLACE_DRIVER_INTERFACE Interface,
    __in PVOID Unused
    );

//
// Define parameters to replace driver.
//

#define PNP_REPLACE_NO_MAP MAXLONGLONG

typedef
__checkReturn
NTSTATUS
(*PREPLACE_MAP_MEMORY) (
    __in    PHYSICAL_ADDRESS    TargetPhysicalAddress,
    __in    PHYSICAL_ADDRESS    SparePhysicalAddress,
    __inout PLARGE_INTEGER      NumberOfBytes,
    __deref_out PVOID *TargetAddress,
    __deref_out PVOID *SpareAddress
    );

typedef struct _PNP_REPLACE_MEMORY_LIST {

    ULONG AllocatedCount;
    ULONG Count;
    ULONGLONG TotalLength;
    struct {
        PHYSICAL_ADDRESS Address;
        ULONGLONG Length;
    } Ranges[ANYSIZE_ARRAY];

} PNP_REPLACE_MEMORY_LIST, *PPNP_REPLACE_MEMORY_LIST;

typedef struct _PNP_REPLACE_PROCESSOR_LIST {

    PKAFFINITY Affinity;
    ULONG GroupCount;
    ULONG AllocatedCount;
    ULONG Count;
    ULONG ApicIds[ANYSIZE_ARRAY];

} PNP_REPLACE_PROCESSOR_LIST, *PPNP_REPLACE_PROCESSOR_LIST;

typedef struct _PNP_REPLACE_PROCESSOR_LIST_V1 {

    KAFFINITY AffinityMask;
    ULONG AllocatedCount;
    ULONG Count;
    ULONG ApicIds[ANYSIZE_ARRAY];

} PNP_REPLACE_PROCESSOR_LIST_V1, *PPNP_REPLACE_PROCESSOR_LIST_V1;

#define PNP_REPLACE_PARAMETERS_VERSION 2

typedef struct _PNP_REPLACE_PARAMETERS {

    ULONG Size;
    ULONG Version;

    ULONG64 Target;
    ULONG64 Spare;
    PPNP_REPLACE_PROCESSOR_LIST TargetProcessors;
    PPNP_REPLACE_PROCESSOR_LIST SpareProcessors;
    PPNP_REPLACE_MEMORY_LIST TargetMemory;
    PPNP_REPLACE_MEMORY_LIST SpareMemory;

    PREPLACE_MAP_MEMORY MapMemory;

} PNP_REPLACE_PARAMETERS, *PPNP_REPLACE_PARAMETERS;

//
// Define replace driver interface.
//

typedef
VOID
(*PREPLACE_UNLOAD) (
    VOID
    );

typedef
__checkReturn
NTSTATUS
(*PREPLACE_BEGIN) (
    __in PPNP_REPLACE_PARAMETERS Parameters,
    __deref_out PVOID *Context
);

typedef
__checkReturn
NTSTATUS
(*PREPLACE_END) (
    __in PVOID Context
    );

typedef
__checkReturn
NTSTATUS
(*PREPLACE_MIRROR_PHYSICAL_MEMORY) (
    __in PVOID Context,
    __in PHYSICAL_ADDRESS PhysicalAddress,
    __in LARGE_INTEGER ByteCount
    );

typedef
__checkReturn
NTSTATUS
(*PREPLACE_SET_PROCESSOR_ID) (
    __in PVOID Context,
    __in ULONG ApicId,
    __in BOOLEAN Target
    );

typedef
__checkReturn
NTSTATUS
(*PREPLACE_SWAP) (
    __in PVOID Context
    );

typedef
__checkReturn
NTSTATUS
(*PREPLACE_INITIATE_HARDWARE_MIRROR) (
    __in PVOID Context
    );

typedef
__checkReturn
NTSTATUS
(*PREPLACE_MIRROR_PLATFORM_MEMORY) (
    __in PVOID Context
    );

typedef
__checkReturn
NTSTATUS
(*PREPLACE_GET_MEMORY_DESTINATION) (
    __in PVOID Context,
    __in PHYSICAL_ADDRESS SourceAddress,
    __out PPHYSICAL_ADDRESS DestinationAddress
    );

typedef
__checkReturn NTSTATUS
(*PREPLACE_ENABLE_DISABLE_HARDWARE_QUIESCE) (
    __in PVOID Context,
    __in BOOLEAN Enable
    );

#define PNP_REPLACE_DRIVER_INTERFACE_VERSION 1
#define PNP_REPLACE_DRIVER_INTERFACE_MINIMUM_SIZE \
             FIELD_OFFSET(PNP_REPLACE_DRIVER_INTERFACE, InitiateHardwareMirror)

#define PNP_REPLACE_MEMORY_SUPPORTED            0x0001
#define PNP_REPLACE_PROCESSOR_SUPPORTED         0x0002
#define PNP_REPLACE_HARDWARE_MEMORY_MIRRORING   0x0004
#define PNP_REPLACE_HARDWARE_PAGE_COPY          0x0008
#define PNP_REPLACE_HARDWARE_QUIESCE            0x0010

//
// Define interface structure.
//

typedef struct _PNP_REPLACE_DRIVER_INTERFACE {

    ULONG Size;
    ULONG Version;

    ULONG Flags;
    PREPLACE_UNLOAD Unload;
    PREPLACE_BEGIN BeginReplace;
    PREPLACE_END EndReplace;
    PREPLACE_MIRROR_PHYSICAL_MEMORY MirrorPhysicalMemory;
    PREPLACE_SET_PROCESSOR_ID SetProcessorId;
    PREPLACE_SWAP Swap;
    PREPLACE_INITIATE_HARDWARE_MIRROR InitiateHardwareMirror;
    PREPLACE_MIRROR_PLATFORM_MEMORY MirrorPlatformMemory;
    PREPLACE_GET_MEMORY_DESTINATION GetMemoryDestination;
    PREPLACE_ENABLE_DISABLE_HARDWARE_QUIESCE EnableDisableHardwareQuiesce;

} PNP_REPLACE_DRIVER_INTERFACE, *PPNP_REPLACE_DRIVER_INTERFACE;

//
// Define the device description structure.
//

typedef struct _DEVICE_DESCRIPTION {
    ULONG Version;
    BOOLEAN Master;
    BOOLEAN ScatterGather;
    BOOLEAN DemandMode;
    BOOLEAN AutoInitialize;
    BOOLEAN Dma32BitAddresses;
    BOOLEAN IgnoreCount;
    BOOLEAN Reserved1;          // must be false
    BOOLEAN Dma64BitAddresses;
    ULONG BusNumber; // unused for WDM
    ULONG DmaChannel;
    INTERFACE_TYPE  InterfaceType;
    DMA_WIDTH DmaWidth;
    DMA_SPEED DmaSpeed;
    ULONG MaximumLength;
    ULONG DmaPort;
} DEVICE_DESCRIPTION, *PDEVICE_DESCRIPTION;

//
// Define the supported version numbers for the device description structure.
//

#define DEVICE_DESCRIPTION_VERSION  0
#define DEVICE_DESCRIPTION_VERSION1 1
#define DEVICE_DESCRIPTION_VERSION2 2

                                                

#if defined(_IA64_)
FORCEINLINE
VOID
KeFlushWriteBuffer (
    VOID
    )
{
    __mf ();
    return;
}

#else
NTHALAPI
VOID
KeFlushWriteBuffer (
    VOID
    );

#endif

//
// Performance counter function.
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTHALAPI
LARGE_INTEGER
KeQueryPerformanceCounter (
   __out_opt PLARGE_INTEGER PerformanceFrequency
   );
#endif


//
// Stall processor execution function.
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTHALAPI
VOID
KeStallExecutionProcessor (
    __in ULONG MicroSeconds
    );
#endif


typedef struct _SCATTER_GATHER_ELEMENT {
    PHYSICAL_ADDRESS Address;
    ULONG Length;
    ULONG_PTR Reserved;
} SCATTER_GATHER_ELEMENT, *PSCATTER_GATHER_ELEMENT;

#if defined(_MSC_EXTENSIONS)

#if _MSC_VER >= 1200
#pragma warning(push)
#endif
#pragma warning(disable:4200)
typedef struct _SCATTER_GATHER_LIST {
    ULONG NumberOfElements;
    ULONG_PTR Reserved;
    SCATTER_GATHER_ELEMENT Elements[];
} SCATTER_GATHER_LIST, *PSCATTER_GATHER_LIST;
#if _MSC_VER >= 1200
#pragma warning(pop)
#else
#pragma warning(default:4200)
#endif

#else

struct _SCATTER_GATHER_LIST;
typedef struct _SCATTER_GATHER_LIST SCATTER_GATHER_LIST, *PSCATTER_GATHER_LIST;

#endif



typedef struct _DMA_OPERATIONS *PDMA_OPERATIONS;

typedef struct _DMA_ADAPTER {
    USHORT Version;
    USHORT Size;
    PDMA_OPERATIONS DmaOperations;
    // Private Bus Device Driver data follows,
} DMA_ADAPTER, *PDMA_ADAPTER;



typedef VOID (*PPUT_DMA_ADAPTER)(
    PDMA_ADAPTER DmaAdapter
    );

typedef PVOID (*PALLOCATE_COMMON_BUFFER)(
    __in PDMA_ADAPTER DmaAdapter,
    __in ULONG Length,
    __out PPHYSICAL_ADDRESS LogicalAddress,
    __in BOOLEAN CacheEnabled
    );

typedef VOID (*PFREE_COMMON_BUFFER)(
    __in PDMA_ADAPTER DmaAdapter,
    __in ULONG Length,
    __in PHYSICAL_ADDRESS LogicalAddress,
    __in PVOID VirtualAddress,
    __in BOOLEAN CacheEnabled
    );

typedef NTSTATUS (*PALLOCATE_ADAPTER_CHANNEL)(
    __in PDMA_ADAPTER DmaAdapter,
    __in PDEVICE_OBJECT DeviceObject,
    __in ULONG NumberOfMapRegisters,
    __in PDRIVER_CONTROL ExecutionRoutine,
    __in PVOID Context
    );

typedef BOOLEAN (*PFLUSH_ADAPTER_BUFFERS)(
    __in PDMA_ADAPTER DmaAdapter,
    __in PMDL Mdl,
    __in PVOID MapRegisterBase,
    __in PVOID CurrentVa,
    __in ULONG Length,
    __in BOOLEAN WriteToDevice
    );

typedef VOID (*PFREE_ADAPTER_CHANNEL)(
    __in PDMA_ADAPTER DmaAdapter
    );

typedef VOID (*PFREE_MAP_REGISTERS)(
    __in PDMA_ADAPTER DmaAdapter,
    PVOID MapRegisterBase,
    ULONG NumberOfMapRegisters
    );

typedef PHYSICAL_ADDRESS (*PMAP_TRANSFER)(
    __in PDMA_ADAPTER DmaAdapter,
    __in PMDL Mdl,
    __in PVOID MapRegisterBase,
    __in PVOID CurrentVa,
    __inout PULONG Length,
    __in BOOLEAN WriteToDevice
    );

typedef ULONG (*PGET_DMA_ALIGNMENT)(
    __in PDMA_ADAPTER DmaAdapter
    );

typedef ULONG (*PREAD_DMA_COUNTER)(
    __in PDMA_ADAPTER DmaAdapter
    );

typedef
__drv_functionClass(DRIVER_LIST_CONTROL)
__drv_sameIRQL
VOID
DRIVER_LIST_CONTROL(
    __in struct _DEVICE_OBJECT *DeviceObject,
    __in struct _IRP *Irp,
    __in PSCATTER_GATHER_LIST ScatterGather,
    __in PVOID Context
    );
typedef DRIVER_LIST_CONTROL *PDRIVER_LIST_CONTROL;

typedef NTSTATUS
(*PGET_SCATTER_GATHER_LIST)(
    __in PDMA_ADAPTER DmaAdapter,
    __in PDEVICE_OBJECT DeviceObject,
    __in PMDL Mdl,
    __in PVOID CurrentVa,
    __in ULONG Length,
    __in PDRIVER_LIST_CONTROL ExecutionRoutine,
    __in PVOID Context,
    __in BOOLEAN WriteToDevice
    );

typedef VOID
(*PPUT_SCATTER_GATHER_LIST)(
    __in PDMA_ADAPTER DmaAdapter,
    __in PSCATTER_GATHER_LIST ScatterGather,
    __in BOOLEAN WriteToDevice
    );

typedef NTSTATUS
(*PCALCULATE_SCATTER_GATHER_LIST_SIZE)(
     __in PDMA_ADAPTER DmaAdapter,
     __in OPTIONAL PMDL Mdl,
     __in PVOID CurrentVa,
     __in ULONG Length,
     __out PULONG  ScatterGatherListSize,
     __out OPTIONAL PULONG pNumberOfMapRegisters
     );

typedef NTSTATUS
(*PBUILD_SCATTER_GATHER_LIST)(
     __in PDMA_ADAPTER DmaAdapter,
     __in PDEVICE_OBJECT DeviceObject,
     __in PMDL Mdl,
     __in PVOID CurrentVa,
     __in ULONG Length,
     __in PDRIVER_LIST_CONTROL ExecutionRoutine,
     __in PVOID Context,
     __in BOOLEAN WriteToDevice,
     __in PVOID   ScatterGatherBuffer,
     __in ULONG   ScatterGatherLength
     );

typedef NTSTATUS
(*PBUILD_MDL_FROM_SCATTER_GATHER_LIST)(
    __in PDMA_ADAPTER DmaAdapter,
    __in PSCATTER_GATHER_LIST ScatterGather,
    __in PMDL OriginalMdl,
    __out PMDL *TargetMdl
    );


typedef struct _DMA_OPERATIONS {
    ULONG Size;
    PPUT_DMA_ADAPTER PutDmaAdapter;
    PALLOCATE_COMMON_BUFFER AllocateCommonBuffer;
    PFREE_COMMON_BUFFER FreeCommonBuffer;
    PALLOCATE_ADAPTER_CHANNEL AllocateAdapterChannel;
    PFLUSH_ADAPTER_BUFFERS FlushAdapterBuffers;
    PFREE_ADAPTER_CHANNEL FreeAdapterChannel;
    PFREE_MAP_REGISTERS FreeMapRegisters;
    PMAP_TRANSFER MapTransfer;
    PGET_DMA_ALIGNMENT GetDmaAlignment;
    PREAD_DMA_COUNTER ReadDmaCounter;
    PGET_SCATTER_GATHER_LIST GetScatterGatherList;
    PPUT_SCATTER_GATHER_LIST PutScatterGatherList;
    PCALCULATE_SCATTER_GATHER_LIST_SIZE CalculateScatterGatherList;
    PBUILD_SCATTER_GATHER_LIST BuildScatterGatherList;
    PBUILD_MDL_FROM_SCATTER_GATHER_LIST BuildMdlFromScatterGatherList;
} DMA_OPERATIONS;



#if defined(USE_DMA_MACROS) && !defined(_NTHAL_) && (defined(_NTDDK_) || defined(_NTDRIVER_)) || defined(_WDM_INCLUDED_) // ntddk

DECLSPEC_DEPRECATED_DDK                 // Use AllocateCommonBuffer
__drv_preferredFunction("AllocateCommonBuffer","Obsolete")
FORCEINLINE
PVOID
HalAllocateCommonBuffer(
    __in PDMA_ADAPTER DmaAdapter,
    __in ULONG Length,
    __out PPHYSICAL_ADDRESS LogicalAddress,
    __in BOOLEAN CacheEnabled
    ){

    PALLOCATE_COMMON_BUFFER allocateCommonBuffer;
    PVOID commonBuffer;

    allocateCommonBuffer = *(DmaAdapter)->DmaOperations->AllocateCommonBuffer;
    ASSERT( allocateCommonBuffer != NULL );

    commonBuffer = allocateCommonBuffer( DmaAdapter,
                                         Length,
                                         LogicalAddress,
                                         CacheEnabled );

    return commonBuffer;
}

DECLSPEC_DEPRECATED_DDK                 // Use FreeCommonBuffer
__drv_preferredFunction("FreeCommonBuffer","Obsolete")
FORCEINLINE
VOID
HalFreeCommonBuffer(
    __in PDMA_ADAPTER DmaAdapter,
    __in ULONG Length,
    __in PHYSICAL_ADDRESS LogicalAddress,
    __in PVOID VirtualAddress,
    __in BOOLEAN CacheEnabled
    ){

    PFREE_COMMON_BUFFER freeCommonBuffer;

    freeCommonBuffer = *(DmaAdapter)->DmaOperations->FreeCommonBuffer;
    ASSERT( freeCommonBuffer != NULL );

    freeCommonBuffer( DmaAdapter,
                      Length,
                      LogicalAddress,
                      VirtualAddress,
                      CacheEnabled );
}

DECLSPEC_DEPRECATED_DDK                 // Use AllocateAdapterChannel
__drv_maxIRQL(DISPATCH_LEVEL)
__drv_minIRQL(DISPATCH_LEVEL)
__drv_preferredFunction("AllocateAdapterChannel","obsolete")
FORCEINLINE
NTSTATUS
IoAllocateAdapterChannel(
    __in PDMA_ADAPTER DmaAdapter,
    __in PDEVICE_OBJECT DeviceObject,
    __in ULONG NumberOfMapRegisters,
    __in PDRIVER_CONTROL ExecutionRoutine,
    __in PVOID Context
    ){

    PALLOCATE_ADAPTER_CHANNEL allocateAdapterChannel;
    NTSTATUS status;

    allocateAdapterChannel =
        *(DmaAdapter)->DmaOperations->AllocateAdapterChannel;

    ASSERT( allocateAdapterChannel != NULL );

    status = allocateAdapterChannel( DmaAdapter,
                                     DeviceObject,
                                     NumberOfMapRegisters,
                                     ExecutionRoutine,
                                     Context );

    return status;
}

DECLSPEC_DEPRECATED_DDK                 // Use FlushAdapterBuffers
__drv_preferredFunction("FlushAdapterBuffers","Obsolete")
FORCEINLINE
BOOLEAN
IoFlushAdapterBuffers(
    __in PDMA_ADAPTER DmaAdapter,
    __in PMDL Mdl,
    __in PVOID MapRegisterBase,
    __in PVOID CurrentVa,
    __in ULONG Length,
    __in BOOLEAN WriteToDevice
    ){

    PFLUSH_ADAPTER_BUFFERS flushAdapterBuffers;
    BOOLEAN result;

    flushAdapterBuffers = *(DmaAdapter)->DmaOperations->FlushAdapterBuffers;
    ASSERT( flushAdapterBuffers != NULL );

    result = flushAdapterBuffers( DmaAdapter,
                                  Mdl,
                                  MapRegisterBase,
                                  CurrentVa,
                                  Length,
                                  WriteToDevice );
    return result;
}

DECLSPEC_DEPRECATED_DDK                 // Use FreeAdapterChannel
__drv_preferredFunction("FreeAdapterChannel","Obsolete")
FORCEINLINE
VOID
IoFreeAdapterChannel(
    __in PDMA_ADAPTER DmaAdapter
    ){

    PFREE_ADAPTER_CHANNEL freeAdapterChannel;

    freeAdapterChannel = *(DmaAdapter)->DmaOperations->FreeAdapterChannel;
    ASSERT( freeAdapterChannel != NULL );

    freeAdapterChannel( DmaAdapter );
}

DECLSPEC_DEPRECATED_DDK                 // Use FreeMapRegisters
__drv_preferredFunction("FreeMapRegisters","Obsolete")
FORCEINLINE
VOID
IoFreeMapRegisters(
    __in PDMA_ADAPTER DmaAdapter,
    __in PVOID MapRegisterBase,
    __in ULONG NumberOfMapRegisters
    ){

    PFREE_MAP_REGISTERS freeMapRegisters;

    freeMapRegisters = *(DmaAdapter)->DmaOperations->FreeMapRegisters;
    ASSERT( freeMapRegisters != NULL );

    freeMapRegisters( DmaAdapter,
                      MapRegisterBase,
                      NumberOfMapRegisters );
}


DECLSPEC_DEPRECATED_DDK                 // Use MapTransfer
__drv_preferredFunction("MapTransfer","Obsolete")
FORCEINLINE
PHYSICAL_ADDRESS
IoMapTransfer(
    __in PDMA_ADAPTER DmaAdapter,
    __in PMDL Mdl,
    __in PVOID MapRegisterBase,
    __in PVOID CurrentVa,
    __inout PULONG Length,
    __in BOOLEAN WriteToDevice
    ){

    PHYSICAL_ADDRESS physicalAddress;
    PMAP_TRANSFER mapTransfer;

    mapTransfer = *(DmaAdapter)->DmaOperations->MapTransfer;
    ASSERT( mapTransfer != NULL );

    physicalAddress = mapTransfer( DmaAdapter,
                                   Mdl,
                                   MapRegisterBase,
                                   CurrentVa,
                                   Length,
                                   WriteToDevice );

    return physicalAddress;
}

DECLSPEC_DEPRECATED_DDK                 // Use GetDmaAlignment
FORCEINLINE
ULONG
HalGetDmaAlignment(
    __in PDMA_ADAPTER DmaAdapter
    )
{
    PGET_DMA_ALIGNMENT getDmaAlignment;
    ULONG alignment;

    getDmaAlignment = *(DmaAdapter)->DmaOperations->GetDmaAlignment;
    ASSERT( getDmaAlignment != NULL );

    alignment = getDmaAlignment( DmaAdapter );
    return alignment;
}

DECLSPEC_DEPRECATED_DDK                 // Use ReadDmaCounter
__drv_preferredFunction("ReadDmaCounter","Obsolete")
FORCEINLINE
ULONG
HalReadDmaCounter(
    __in PDMA_ADAPTER DmaAdapter
    )
{
    PREAD_DMA_COUNTER readDmaCounter;
    ULONG counter;

    readDmaCounter = *(DmaAdapter)->DmaOperations->ReadDmaCounter;
    ASSERT( readDmaCounter != NULL );

    counter = readDmaCounter( DmaAdapter );
    return counter;
}

#endif // USE_DMA_MACROS && (_NTDDK_ || _NTDRIVER_)


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
VOID
PoSetSystemState (
    __in EXECUTION_STATE Flags
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
PVOID
PoRegisterSystemState (
    __inout_opt PVOID StateHandle,
    __in EXECUTION_STATE Flags
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
NTSTATUS
PoCreatePowerRequest (
    __deref_out PVOID *PowerRequest,
    __in PDEVICE_OBJECT DeviceObject,
    __in PCOUNTED_REASON_CONTEXT Context
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
NTSTATUS
PoSetPowerRequest (
    __inout PVOID PowerRequest,
    __in POWER_REQUEST_TYPE Type
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
NTSTATUS
PoClearPowerRequest (
    __inout PVOID PowerRequest,
    __in POWER_REQUEST_TYPE Type
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
PoDeletePowerRequest (
    __inout PVOID PowerRequest
    );
#endif


typedef
__drv_functionClass(REQUEST_POWER_COMPLETE)
__drv_sameIRQL
VOID
REQUEST_POWER_COMPLETE (
    __in PDEVICE_OBJECT DeviceObject,
    __in UCHAR MinorFunction,
    __in POWER_STATE PowerState,
    __in_opt PVOID Context,
    __in PIO_STATUS_BLOCK IoStatus
    );

typedef REQUEST_POWER_COMPLETE *PREQUEST_POWER_COMPLETE;

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
NTSTATUS
PoRequestPowerIrp (
    __in PDEVICE_OBJECT DeviceObject,
    __in UCHAR MinorFunction,
    __in POWER_STATE PowerState,
    __in_opt PREQUEST_POWER_COMPLETE CompletionFunction,
    __in_opt __drv_aliasesMem PVOID Context,
    __deref_opt_out PIRP *Irp
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
VOID
PoSetSystemWake (
    __inout PIRP Irp
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
BOOLEAN
PoGetSystemWake (
    __in PIRP Irp
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
PoUnregisterSystemState (
    __inout PVOID StateHandle
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
POWER_STATE
PoSetPowerState (
    __in PDEVICE_OBJECT DeviceObject,
    __in POWER_STATE_TYPE Type,
    __in POWER_STATE State
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
NTSTATUS
PoCallDriver (
    __in PDEVICE_OBJECT DeviceObject,
    __inout __drv_aliasesMem PIRP Irp
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
VOID
PoStartNextPowerIrp(
    __inout PIRP Irp
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
PULONG
PoRegisterDeviceForIdleDetection (
    __in PDEVICE_OBJECT DeviceObject,
    __in ULONG ConservationIdleTime,
    __in ULONG PerformanceIdleTime,
    __in DEVICE_POWER_STATE State
    );
#endif

#define PoSetDeviceBusy(IdlePointer) \
    *IdlePointer = 0
    
#if (NTDDI_VERSION >= NTDDI_WIN6SP1)
NTKERNELAPI
VOID
PoSetDeviceBusyEx (
    __inout PULONG IdlePointer
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
NTKERNELAPI
VOID
PoStartDeviceBusy (
    __inout PULONG IdlePointer
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
NTKERNELAPI
VOID
PoEndDeviceBusy (
    __inout PULONG IdlePointer
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
BOOLEAN
PoQueryWatchdogTime (
    __in PDEVICE_OBJECT Pdo,
    __out PULONG SecondsRemaining
    );
#endif

typedef 
__drv_functionClass(POWER_SETTING_CALLBACK)
__drv_sameIRQL
NTSTATUS
POWER_SETTING_CALLBACK (  
    __in LPCGUID SettingGuid,
    __in_bcount(ValueLength) PVOID Value,
    __in ULONG ValueLength,
    __inout_opt PVOID Context
);

typedef POWER_SETTING_CALLBACK *PPOWER_SETTING_CALLBACK;

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
NTSTATUS
PoRegisterPowerSettingCallback (
    __in_opt PDEVICE_OBJECT DeviceObject,
    __in LPCGUID SettingGuid,
    __in PPOWER_SETTING_CALLBACK Callback,
    __in_opt PVOID Context,
    __deref_opt_out PVOID *Handle
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
NTSTATUS
PoUnregisterPowerSettingCallback (
    __inout PVOID Handle
    );
#endif

//
// \Callback\PowerState values
//

#define PO_CB_SYSTEM_POWER_POLICY       0
#define PO_CB_AC_STATUS                 1
#define PO_CB_BUTTON_COLLISION          2 // deprecated
#define PO_CB_SYSTEM_STATE_LOCK         3
#define PO_CB_LID_SWITCH_STATE          4
#define PO_CB_PROCESSOR_POWER_POLICY    5 // deprecated

//
// Object Manager types
//

typedef struct _OBJECT_HANDLE_INFORMATION {
    ULONG HandleAttributes;
    ACCESS_MASK GrantedAccess;
} OBJECT_HANDLE_INFORMATION, *POBJECT_HANDLE_INFORMATION;


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
NTSTATUS
ObReferenceObjectByHandle(
    __in HANDLE Handle,
    __in ACCESS_MASK DesiredAccess,
    __in_opt POBJECT_TYPE ObjectType,
    __in KPROCESSOR_MODE AccessMode,
    __out PVOID *Object,
    __out_opt POBJECT_HANDLE_INFORMATION HandleInformation
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
NTSTATUS
ObReferenceObjectByHandleWithTag(
    __in HANDLE Handle,
    __in ACCESS_MASK DesiredAccess,
    __in_opt POBJECT_TYPE ObjectType,
    __in KPROCESSOR_MODE AccessMode,
    __in ULONG Tag,
    __out PVOID *Object,
    __out_opt POBJECT_HANDLE_INFORMATION HandleInformation
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN7)

#define ObDereferenceObject(a)                                     \
        ObfDereferenceObject(a)

#define ObReferenceObject(Object) ObfReferenceObject(Object)

#define ObDereferenceObjectWithTag(a, t)                                \
        ObfDereferenceObjectWithTag(a, t)

#define ObReferenceObjectWithTag(Object, Tag) ObfReferenceObjectWithTag(Object, Tag)

#else

#define ObDereferenceObject(a)                                     \
        ObfDereferenceObject(a)

#define ObReferenceObject(Object) ObfReferenceObject(Object)

#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
LONG_PTR
FASTCALL
ObfReferenceObject(
    __in PVOID Object
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
LONG_PTR
FASTCALL
ObfReferenceObjectWithTag(
    __in PVOID Object,
    __in ULONG Tag
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
NTSTATUS
ObReferenceObjectByPointer(
    __in PVOID Object,
    __in ACCESS_MASK DesiredAccess,
    __in_opt POBJECT_TYPE ObjectType,
    __in KPROCESSOR_MODE AccessMode
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
NTSTATUS
ObReferenceObjectByPointerWithTag(
    __in PVOID Object,
    __in ACCESS_MASK DesiredAccess,
    __in_opt POBJECT_TYPE ObjectType,
    __in KPROCESSOR_MODE AccessMode,
    __in ULONG Tag
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
LONG_PTR
FASTCALL
ObfDereferenceObject(
    __in PVOID Object
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
LONG_PTR
FASTCALL
ObfDereferenceObjectWithTag(
    __in PVOID Object,
    __in ULONG Tag
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
NTKERNELAPI
VOID
ObDereferenceObjectDeferDelete(
    __in PVOID Object
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
NTKERNELAPI
VOID
ObDereferenceObjectDeferDeleteWithTag(
    __in PVOID Object,
    __in ULONG Tag
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
NTSTATUS
ObGetObjectSecurity(
    __in PVOID Object,
    __out PSECURITY_DESCRIPTOR *SecurityDescriptor,
    __out PBOOLEAN MemoryAllocated
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
ObReleaseObjectSecurity(
    __in PSECURITY_DESCRIPTOR SecurityDescriptor,
    __in BOOLEAN MemoryAllocated
    );
#endif


//
// Registration version for Vista SP1 and Windows Server 2007
//
#define OB_FLT_REGISTRATION_VERSION_0100  0x0100

//
// This value should be used by filters for registration
//
#define OB_FLT_REGISTRATION_VERSION OB_FLT_REGISTRATION_VERSION_0100

typedef ULONG OB_OPERATION;

#define OB_OPERATION_HANDLE_CREATE              0x00000001
#define OB_OPERATION_HANDLE_DUPLICATE           0x00000002

typedef struct _OB_PRE_CREATE_HANDLE_INFORMATION {
    __inout ACCESS_MASK         DesiredAccess;
    __in ACCESS_MASK            OriginalDesiredAccess;
} OB_PRE_CREATE_HANDLE_INFORMATION, *POB_PRE_CREATE_HANDLE_INFORMATION;

typedef struct _OB_PRE_DUPLICATE_HANDLE_INFORMATION {
    __inout ACCESS_MASK         DesiredAccess;
    __in ACCESS_MASK            OriginalDesiredAccess;
    __in PVOID                  SourceProcess;
    __in PVOID                  TargetProcess;
} OB_PRE_DUPLICATE_HANDLE_INFORMATION, * POB_PRE_DUPLICATE_HANDLE_INFORMATION;

typedef union _OB_PRE_OPERATION_PARAMETERS {
    __inout OB_PRE_CREATE_HANDLE_INFORMATION        CreateHandleInformation;
    __inout OB_PRE_DUPLICATE_HANDLE_INFORMATION     DuplicateHandleInformation;
} OB_PRE_OPERATION_PARAMETERS, *POB_PRE_OPERATION_PARAMETERS;

typedef struct _OB_PRE_OPERATION_INFORMATION {
    __in OB_OPERATION           Operation;
    union {
        __in ULONG Flags;
        struct {
            __in ULONG KernelHandle:1;
            __in ULONG Reserved:31;
        };
    };
    __in PVOID                         Object;
    __in POBJECT_TYPE                  ObjectType;
    __out PVOID                        CallContext;
    __in POB_PRE_OPERATION_PARAMETERS  Parameters;
} OB_PRE_OPERATION_INFORMATION, *POB_PRE_OPERATION_INFORMATION;

typedef struct _OB_POST_CREATE_HANDLE_INFORMATION {
    __in ACCESS_MASK            GrantedAccess;
} OB_POST_CREATE_HANDLE_INFORMATION, *POB_POST_CREATE_HANDLE_INFORMATION;

typedef struct _OB_POST_DUPLICATE_HANDLE_INFORMATION {
    __in ACCESS_MASK            GrantedAccess;
} OB_POST_DUPLICATE_HANDLE_INFORMATION, * POB_POST_DUPLICATE_HANDLE_INFORMATION;

typedef union _OB_POST_OPERATION_PARAMETERS {
    __in OB_POST_CREATE_HANDLE_INFORMATION       CreateHandleInformation;
    __in OB_POST_DUPLICATE_HANDLE_INFORMATION    DuplicateHandleInformation;
} OB_POST_OPERATION_PARAMETERS, *POB_POST_OPERATION_PARAMETERS;

typedef struct _OB_POST_OPERATION_INFORMATION {
    __in OB_OPERATION  Operation;
    union {
        __in ULONG Flags;
        struct {
            __in ULONG KernelHandle:1;
            __in ULONG Reserved:31;
        };
    };
    __in PVOID                          Object;
    __in POBJECT_TYPE                   ObjectType;
    __in PVOID                          CallContext;
    __in NTSTATUS                       ReturnStatus;
    __in POB_POST_OPERATION_PARAMETERS  Parameters;
} OB_POST_OPERATION_INFORMATION,*POB_POST_OPERATION_INFORMATION;

typedef enum _OB_PREOP_CALLBACK_STATUS {
    OB_PREOP_SUCCESS
} OB_PREOP_CALLBACK_STATUS, *POB_PREOP_CALLBACK_STATUS;

typedef OB_PREOP_CALLBACK_STATUS
(*POB_PRE_OPERATION_CALLBACK) (
    __in PVOID RegistrationContext,
    __inout POB_PRE_OPERATION_INFORMATION OperationInformation
    );

typedef VOID
(*POB_POST_OPERATION_CALLBACK) (
    __in PVOID RegistrationContext,
    __in POB_POST_OPERATION_INFORMATION OperationInformation
    );

typedef struct _OB_OPERATION_REGISTRATION {
    __in POBJECT_TYPE                *ObjectType;
    __in OB_OPERATION                Operations;
    __in POB_PRE_OPERATION_CALLBACK  PreOperation;
    __in POB_POST_OPERATION_CALLBACK PostOperation;
} OB_OPERATION_REGISTRATION, *POB_OPERATION_REGISTRATION;

typedef struct _OB_CALLBACK_REGISTRATION {
    __in USHORT                     Version;
    __in USHORT                     OperationRegistrationCount;
    __in UNICODE_STRING             Altitude;
    __in PVOID                      RegistrationContext;
    __in OB_OPERATION_REGISTRATION  *OperationRegistration;
} OB_CALLBACK_REGISTRATION, *POB_CALLBACK_REGISTRATION;

#if (NTDDI_VERSION >= NTDDI_VISTASP1)
NTKERNELAPI
NTSTATUS
ObRegisterCallbacks (
    __in POB_CALLBACK_REGISTRATION CallbackRegistration,
    __deref_out PVOID *RegistrationHandle
    );

NTKERNELAPI
VOID
ObUnRegisterCallbacks (
    __in PVOID RegistrationHandle
    );

NTKERNELAPI
USHORT
ObGetFilterVersion ();
#endif

#ifndef _PCI_X_
#define _PCI_X_

//
// A PCI driver can read the complete 256 bytes of configuration
// information for any PCI device by calling:
//
//      ULONG
//      HalGetBusData (
//          __in BUS_DATA_TYPE        PCIConfiguration,
//          __in ULONG                PciBusNumber,
//          __in PCI_SLOT_NUMBER      VirtualSlotNumber,
//          __in PPCI_COMMON_CONFIG   &PCIDeviceConfig,
//          __in ULONG                sizeof (PCIDeviceConfig)
//      );
//
//      A return value of 0 means that the specified PCI bus does not exist.
//
//      A return value of 2, with a VendorID of PCI_INVALID_VENDORID means
//      that the PCI bus does exist, but there is no device at the specified
//      VirtualSlotNumber (PCI Device/Function number).
//
//



typedef struct _PCI_SLOT_NUMBER {
    union {
        struct {
            ULONG   DeviceNumber:5;
            ULONG   FunctionNumber:3;
            ULONG   Reserved:24;
        } bits;
        ULONG   AsULONG;
    } u;
} PCI_SLOT_NUMBER, *PPCI_SLOT_NUMBER;


#define PCI_TYPE0_ADDRESSES             6
#define PCI_TYPE1_ADDRESSES             2
#define PCI_TYPE2_ADDRESSES             5

typedef struct _PCI_COMMON_HEADER {
    USHORT  VendorID;                   // (ro)
    USHORT  DeviceID;                   // (ro)
    USHORT  Command;                    // Device control
    USHORT  Status;
    UCHAR   RevisionID;                 // (ro)
    UCHAR   ProgIf;                     // (ro)
    UCHAR   SubClass;                   // (ro)
    UCHAR   BaseClass;                  // (ro)
    UCHAR   CacheLineSize;              // (ro+)
    UCHAR   LatencyTimer;               // (ro+)
    UCHAR   HeaderType;                 // (ro)
    UCHAR   BIST;                       // Built in self test

    union {
        struct _PCI_HEADER_TYPE_0 {
            ULONG   BaseAddresses[PCI_TYPE0_ADDRESSES];
            ULONG   CIS;
            USHORT  SubVendorID;
            USHORT  SubSystemID;
            ULONG   ROMBaseAddress;
            UCHAR   CapabilitiesPtr;
            UCHAR   Reserved1[3];
            ULONG   Reserved2;
            UCHAR   InterruptLine;      //
            UCHAR   InterruptPin;       // (ro)
            UCHAR   MinimumGrant;       // (ro)
            UCHAR   MaximumLatency;     // (ro)
        } type0;



        //
        // PCI to PCI Bridge
        //

        struct _PCI_HEADER_TYPE_1 {
            ULONG   BaseAddresses[PCI_TYPE1_ADDRESSES];
            UCHAR   PrimaryBus;
            UCHAR   SecondaryBus;
            UCHAR   SubordinateBus;
            UCHAR   SecondaryLatency;
            UCHAR   IOBase;
            UCHAR   IOLimit;
            USHORT  SecondaryStatus;
            USHORT  MemoryBase;
            USHORT  MemoryLimit;
            USHORT  PrefetchBase;
            USHORT  PrefetchLimit;
            ULONG   PrefetchBaseUpper32;
            ULONG   PrefetchLimitUpper32;
            USHORT  IOBaseUpper16;
            USHORT  IOLimitUpper16;
            UCHAR   CapabilitiesPtr;
            UCHAR   Reserved1[3];
            ULONG   ROMBaseAddress;
            UCHAR   InterruptLine;
            UCHAR   InterruptPin;
            USHORT  BridgeControl;
        } type1;

        //
        // PCI to CARDBUS Bridge
        //

        struct _PCI_HEADER_TYPE_2 {
            ULONG   SocketRegistersBaseAddress;
            UCHAR   CapabilitiesPtr;
            UCHAR   Reserved;
            USHORT  SecondaryStatus;
            UCHAR   PrimaryBus;
            UCHAR   SecondaryBus;
            UCHAR   SubordinateBus;
            UCHAR   SecondaryLatency;
            struct  {
                ULONG   Base;
                ULONG   Limit;
            }       Range[PCI_TYPE2_ADDRESSES-1];
            UCHAR   InterruptLine;
            UCHAR   InterruptPin;
            USHORT  BridgeControl;
        } type2;



    } u;

} PCI_COMMON_HEADER, *PPCI_COMMON_HEADER;

#ifdef __cplusplus

typedef struct _PCI_COMMON_CONFIG : PCI_COMMON_HEADER {
    UCHAR   DeviceSpecific[192];
} PCI_COMMON_CONFIG, *PPCI_COMMON_CONFIG;

#else

typedef struct _PCI_COMMON_CONFIG {
    PCI_COMMON_HEADER DUMMYSTRUCTNAME;
    UCHAR   DeviceSpecific[192];
} PCI_COMMON_CONFIG, *PPCI_COMMON_CONFIG;

#endif

#define PCI_COMMON_HDR_LENGTH (FIELD_OFFSET (PCI_COMMON_CONFIG, DeviceSpecific))
#define PCI_EXTENDED_CONFIG_LENGTH          0x1000

#define PCI_MAX_DEVICES                     32
#define PCI_MAX_FUNCTION                    8
#define PCI_MAX_BRIDGE_NUMBER               0xFF

#define PCI_INVALID_VENDORID                0xFFFF

//
// Bit encodings for  PCI_COMMON_CONFIG.HeaderType
//

#define PCI_MULTIFUNCTION                   0x80
#define PCI_DEVICE_TYPE                     0x00
#define PCI_BRIDGE_TYPE                     0x01
#define PCI_CARDBUS_BRIDGE_TYPE             0x02

#define PCI_CONFIGURATION_TYPE(PciData) \
    (((PPCI_COMMON_CONFIG)(PciData))->HeaderType & ~PCI_MULTIFUNCTION)

#define PCI_MULTIFUNCTION_DEVICE(PciData) \
    ((((PPCI_COMMON_CONFIG)(PciData))->HeaderType & PCI_MULTIFUNCTION) != 0)

//
// Bit encodings for PCI_COMMON_CONFIG.Command
//

#define PCI_ENABLE_IO_SPACE                 0x0001
#define PCI_ENABLE_MEMORY_SPACE             0x0002
#define PCI_ENABLE_BUS_MASTER               0x0004
#define PCI_ENABLE_SPECIAL_CYCLES           0x0008
#define PCI_ENABLE_WRITE_AND_INVALIDATE     0x0010
#define PCI_ENABLE_VGA_COMPATIBLE_PALETTE   0x0020
#define PCI_ENABLE_PARITY                   0x0040  // (ro+)
#define PCI_ENABLE_WAIT_CYCLE               0x0080  // (ro+)
#define PCI_ENABLE_SERR                     0x0100  // (ro+)
#define PCI_ENABLE_FAST_BACK_TO_BACK        0x0200  // (ro)
#define PCI_DISABLE_LEVEL_INTERRUPT         0x0400

//
// Bit encodings for PCI_COMMON_CONFIG.Status
//

#define PCI_STATUS_INTERRUPT_PENDING        0x0008
#define PCI_STATUS_CAPABILITIES_LIST        0x0010  // (ro)
#define PCI_STATUS_66MHZ_CAPABLE            0x0020  // (ro)
#define PCI_STATUS_UDF_SUPPORTED            0x0040  // (ro)
#define PCI_STATUS_FAST_BACK_TO_BACK        0x0080  // (ro)
#define PCI_STATUS_DATA_PARITY_DETECTED     0x0100
#define PCI_STATUS_DEVSEL                   0x0600  // 2 bits wide
#define PCI_STATUS_SIGNALED_TARGET_ABORT    0x0800
#define PCI_STATUS_RECEIVED_TARGET_ABORT    0x1000
#define PCI_STATUS_RECEIVED_MASTER_ABORT    0x2000
#define PCI_STATUS_SIGNALED_SYSTEM_ERROR    0x4000
#define PCI_STATUS_DETECTED_PARITY_ERROR    0x8000

//
// The NT PCI Driver uses a WhichSpace parameter on its CONFIG_READ/WRITE
// routines.   The following values are defined-
//

#define PCI_WHICHSPACE_CONFIG               0x0
#define PCI_WHICHSPACE_ROM                  0x52696350

//
// PCI Capability IDs
//

#define PCI_CAPABILITY_ID_POWER_MANAGEMENT  0x01
#define PCI_CAPABILITY_ID_AGP               0x02
#define PCI_CAPABILITY_ID_VPD               0x03
#define PCI_CAPABILITY_ID_SLOT_ID           0x04
#define PCI_CAPABILITY_ID_MSI               0x05
#define PCI_CAPABILITY_ID_CPCI_HOTSWAP      0x06
#define PCI_CAPABILITY_ID_PCIX              0x07
#define PCI_CAPABILITY_ID_HYPERTRANSPORT    0x08
#define PCI_CAPABILITY_ID_VENDOR_SPECIFIC   0x09
#define PCI_CAPABILITY_ID_DEBUG_PORT        0x0A
#define PCI_CAPABILITY_ID_CPCI_RES_CTRL     0x0B
#define PCI_CAPABILITY_ID_SHPC              0x0C
#define PCI_CAPABILITY_ID_P2P_SSID          0x0D
#define PCI_CAPABILITY_ID_AGP_TARGET        0x0E
#define PCI_CAPABILITY_ID_SECURE            0x0F
#define PCI_CAPABILITY_ID_PCI_EXPRESS       0x10
#define PCI_CAPABILITY_ID_MSIX              0x11

//
// All PCI Capability structures have the following header.
//
// CapabilityID is used to identify the type of the structure (is
// one of the PCI_CAPABILITY_ID values above.
//
// Next is the offset in PCI Configuration space (0x40 - 0xfc) of the
// next capability structure in the list, or 0x00 if there are no more
// entries.
//
typedef struct _PCI_CAPABILITIES_HEADER {
    UCHAR   CapabilityID;
    UCHAR   Next;
} PCI_CAPABILITIES_HEADER, *PPCI_CAPABILITIES_HEADER;

//
// Power Management Capability
//

typedef struct _PCI_PMC {
    UCHAR       Version:3;
    UCHAR       PMEClock:1;
    UCHAR       Rsvd1:1;
    UCHAR       DeviceSpecificInitialization:1;
    UCHAR       Rsvd2:2;
    struct _PM_SUPPORT {
        UCHAR   Rsvd2:1;
        UCHAR   D1:1;
        UCHAR   D2:1;
        UCHAR   PMED0:1;
        UCHAR   PMED1:1;
        UCHAR   PMED2:1;
        UCHAR   PMED3Hot:1;
        UCHAR   PMED3Cold:1;
    } Support;
} PCI_PMC, *PPCI_PMC;

typedef struct _PCI_PMCSR {
    USHORT      PowerState:2;
    USHORT      Rsvd1:6;
    USHORT      PMEEnable:1;
    USHORT      DataSelect:4;
    USHORT      DataScale:2;
    USHORT      PMEStatus:1;
} PCI_PMCSR, *PPCI_PMCSR;


typedef struct _PCI_PMCSR_BSE {
    UCHAR       Rsvd1:6;
    UCHAR       D3HotSupportsStopClock:1;       // B2_B3#
    UCHAR       BusPowerClockControlEnabled:1;  // BPCC_EN
} PCI_PMCSR_BSE, *PPCI_PMCSR_BSE;


typedef struct _PCI_PM_CAPABILITY {

    PCI_CAPABILITIES_HEADER Header;

    //
    // Power Management Capabilities (Offset = 2)
    //

    union {
        PCI_PMC         Capabilities;
        USHORT          AsUSHORT;
    } PMC;

    //
    // Power Management Control/Status (Offset = 4)
    //

    union {
        PCI_PMCSR       ControlStatus;
        USHORT          AsUSHORT;
    } PMCSR;

    //
    // PMCSR PCI-PCI Bridge Support Extensions
    //

    union {
        PCI_PMCSR_BSE   BridgeSupport;
        UCHAR           AsUCHAR;
    } PMCSR_BSE;

    //
    // Optional read only 8 bit Data register.  Contents controlled by
    // DataSelect and DataScale in ControlStatus.
    //

    UCHAR   Data;

} PCI_PM_CAPABILITY, *PPCI_PM_CAPABILITY;


//
// PCI-X Capability
//

typedef struct {

    PCI_CAPABILITIES_HEADER Header;

    union {
        struct {
            USHORT  DataParityErrorRecoveryEnable:1;
            USHORT  EnableRelaxedOrdering:1;
            USHORT  MaxMemoryReadByteCount:2;
            USHORT  MaxOutstandingSplitTransactions:3;
            USHORT  Reserved:9;
        } bits;
        USHORT  AsUSHORT;
    } Command;

    union {
        struct {
            ULONG   FunctionNumber:3;
            ULONG   DeviceNumber:5;
            ULONG   BusNumber:8;
            ULONG   Device64Bit:1;
            ULONG   Capable133MHz:1;
            ULONG   SplitCompletionDiscarded:1;
            ULONG   UnexpectedSplitCompletion:1;
            ULONG   DeviceComplexity:1;
            ULONG   DesignedMaxMemoryReadByteCount:2;
            ULONG   DesignedMaxOutstandingSplitTransactions:3;
            ULONG   DesignedMaxCumulativeReadSize:3;
            ULONG   ReceivedSplitCompletionErrorMessage:1;
            ULONG   CapablePCIX266:1;
            ULONG   CapablePCIX533:1;
        } bits;
        ULONG   AsULONG;
    } Status;
} PCI_X_CAPABILITY, *PPCI_X_CAPABILITY;


//
// PCI Express Extended Capabilities.
//

#define PCI_EXPRESS_ADVANCED_ERROR_REPORTING_CAP_ID                     0x0001
#define PCI_EXPRESS_VIRTUAL_CHANNEL_CAP_ID                              0x0002
#define PCI_EXPRESS_DEVICE_SERIAL_NUMBER_CAP_ID                         0x0003
#define PCI_EXPRESS_POWER_BUDGETING_CAP_ID                              0x0004
#define PCI_EXPRESS_RC_LINK_DECLARATION_CAP_ID                          0x0005
#define PCI_EXPRESS_RC_INTERNAL_LINK_CONTROL_CAP_ID                     0x0006
#define PCI_EXPRESS_RC_EVENT_COLLECTOR_ENDPOINT_ASSOCIATION_CAP_ID      0x0007
#define PCI_EXPRESS_MFVC_CAP_ID                                         0x0008
#define PCI_EXPRESS_VC_AND_MFVC_CAP_ID                                  0x0009
#define PCI_EXPRESS_RCRB_HEADER_CAP_ID                                  0x000A
#define PCI_EXPRESS_SINGLE_ROOT_IO_VIRTUALIZATION_CAP_ID                0x0010

//
// All Enhanced capabilities have the following header.
//

typedef struct _PCI_EXPRESS_ENHANCED_CAPABILITY_HEADER {

    USHORT CapabilityID;
    USHORT Version:4;
    USHORT Next:12;

} PCI_EXPRESS_ENHANCED_CAPABILITY_HEADER, *PPCI_EXPRESS_ENHANCED_CAPABILITY_HEADER;

//
// Serial Number Capability.
//

typedef struct _PCI_EXPRESS_SERIAL_NUMBER_CAPABILITY {

    PCI_EXPRESS_ENHANCED_CAPABILITY_HEADER Header;

    ULONG LowSerialNumber;
    ULONG HighSerialNumber;

} PCI_EXPRESS_SERIAL_NUMBER_CAPABILITY, *PPCI_EXPRESS_SERIAL_NUMBER_CAPABILITY;

//
// PCI Express Advanced Error Reporting structures.
//

typedef union _PCI_EXPRESS_UNCORRECTABLE_ERROR_STATUS {

    struct {
        ULONG Undefined:1;
        ULONG Reserved1:3;
        ULONG DataLinkProtocolError:1;
        ULONG SurpriseDownError:1;
        ULONG Reserved2:6;
        ULONG PoisonedTLP:1;
        ULONG FlowControlProtocolError:1;
        ULONG CompletionTimeout:1;
        ULONG CompleterAbort:1;
        ULONG UnexpectedCompletion:1;
        ULONG ReceiverOverflow:1;
        ULONG MalformedTLP:1;
        ULONG ECRCError:1;
        ULONG UnsupportedRequestError:1;
        ULONG Reserved3:11;
    } DUMMYSTRUCTNAME;

    ULONG AsULONG;

} PCI_EXPRESS_UNCORRECTABLE_ERROR_STATUS, *PPCI_EXPRESS_UNCORRECTABLE_ERROR_STATUS;

typedef union _PCI_EXPRESS_UNCORRECTABLE_ERROR_MASK {

    struct {
        ULONG Undefined:1;
        ULONG Reserved1:3;
        ULONG DataLinkProtocolError:1;
        ULONG SurpriseDownError:1;
        ULONG Reserved2:6;
        ULONG PoisonedTLP:1;
        ULONG FlowControlProtocolError:1;
        ULONG CompletionTimeout:1;
        ULONG CompleterAbort:1;
        ULONG UnexpectedCompletion:1;
        ULONG ReceiverOverflow:1;
        ULONG MalformedTLP:1;
        ULONG ECRCError:1;
        ULONG UnsupportedRequestError:1;
        ULONG Reserved3:11;
    } DUMMYSTRUCTNAME;

    ULONG AsULONG;

} PCI_EXPRESS_UNCORRECTABLE_ERROR_MASK, *PPCI_EXPRESS_UNCORRECTABLE_ERROR_MASK;

typedef union _PCI_EXPRESS_UNCORRECTABLE_ERROR_SEVERITY {

    struct {
        ULONG Undefined:1;
        ULONG Reserved1:3;
        ULONG DataLinkProtocolError:1;
        ULONG SurpriseDownError:1;
        ULONG Reserved2:6;
        ULONG PoisonedTLP:1;
        ULONG FlowControlProtocolError:1;
        ULONG CompletionTimeout:1;
        ULONG CompleterAbort:1;
        ULONG UnexpectedCompletion:1;
        ULONG ReceiverOverflow:1;
        ULONG MalformedTLP:1;
        ULONG ECRCError:1;
        ULONG UnsupportedRequestError:1;
        ULONG Reserved3:11;
    } DUMMYSTRUCTNAME;

    ULONG AsULONG;

} PCI_EXPRESS_UNCORRECTABLE_ERROR_SEVERITY, *PPCI_EXPRESS_UNCORRECTABLE_ERROR_SEVERITY;

typedef union _PCI_EXPRESS_CORRECTABLE_ERROR_STATUS {

    struct {
        ULONG ReceiverError:1;
        ULONG Reserved1:5;
        ULONG BadTLP:1;
        ULONG BadDLLP:1;
        ULONG ReplayNumRollover:1;
        ULONG Reserved2:3;
        ULONG ReplayTimerTimeout:1;
        ULONG AdvisoryNonFatalError:1;
        ULONG Reserved3:18;
    } DUMMYSTRUCTNAME;

    ULONG AsULONG;

} PCI_EXPRESS_CORRECTABLE_ERROR_STATUS, *PPCI_CORRECTABLE_ERROR_STATUS;

typedef union _PCI_EXPRESS_CORRECTABLE_ERROR_MASK {

    struct {
        ULONG ReceiverError:1;
        ULONG Reserved1:5;
        ULONG BadTLP:1;
        ULONG BadDLLP:1;
        ULONG ReplayNumRollover:1;
        ULONG Reserved2:3;
        ULONG ReplayTimerTimeout:1;
        ULONG AdvisoryNonFatalError:1;
        ULONG Reserved3:18;
    } DUMMYSTRUCTNAME;

    ULONG AsULONG;

} PCI_EXPRESS_CORRECTABLE_ERROR_MASK, *PPCI_CORRECTABLE_ERROR_MASK;

typedef union _PCI_EXPRESS_AER_CAPABILITIES {

    struct {
        ULONG FirstErrorPointer:5;
        ULONG ECRCGenerationCapable:1;
        ULONG ECRCGenerationEnable:1;
        ULONG ECRCCheckCapable:1;
        ULONG ECRCCheckEnable:1;
        ULONG Reserved:23;
    } DUMMYSTRUCTNAME;

    ULONG AsULONG;

} PCI_EXPRESS_AER_CAPABILITIES, *PPCI_EXPRESS_AER_CAPABILITIES;

typedef union _PCI_EXPRESS_ROOT_ERROR_COMMAND {

    struct {
        ULONG CorrectableErrorReportingEnable:1;
        ULONG NonFatalErrorReportingEnable:1;
        ULONG FatalErrorReportingEnable:1;
        ULONG Reserved:29;
    } DUMMYSTRUCTNAME;

    ULONG AsULONG;

} PCI_EXPRESS_ROOT_ERROR_COMMAND, *PPCI_EXPRESS_ROOT_ERROR_COMMAND;

typedef union _PCI_EXPRESS_ROOT_ERROR_STATUS {

    struct {
        ULONG CorrectableErrorReceived:1;
        ULONG MultipleCorrectableErrorsReceived:1;
        ULONG UncorrectableErrorReceived:1;
        ULONG MultipleUncorrectableErrorsReceived:1;
        ULONG FirstUncorrectableFatal:1;
        ULONG NonFatalErrorMessagesReceived:1;
        ULONG FatalErrorMessagesReceived:1;
        ULONG Reserved:20;
        ULONG AdvancedErrorInterruptMessageNumber:5;
    } DUMMYSTRUCTNAME;

    ULONG AsULONG;

} PCI_EXPRESS_ROOT_ERROR_STATUS, *PPCI_EXPRESS_ROOT_ERROR_STATUS;

typedef union _PCI_EXPRESS_ERROR_SOURCE_ID {

    struct {
        USHORT CorrectableSourceIdFun:3;
        USHORT CorrectableSourceIdDev:5;
        USHORT CorrectableSourceIdBus:8;
        USHORT UncorrectableSourceIdFun:3;
        USHORT UncorrectableSourceIdDev:5;
        USHORT UncorrectableSourceIdBus:8;
    } DUMMYSTRUCTNAME;

    ULONG AsULONG;

} PCI_EXPRESS_ERROR_SOURCE_ID, *PPCI_EXPRESS_ERROR_SOURCE_ID;

typedef union _PCI_EXPRESS_SEC_UNCORRECTABLE_ERROR_STATUS {

    struct {
        ULONG TargetAbortOnSplitCompletion:1;
        ULONG MasterAbortOnSplitCompletion:1;
        ULONG ReceivedTargetAbort:1;
        ULONG ReceivedMasterAbort:1;
        ULONG RsvdZ:1;
        ULONG UnexpectedSplitCompletionError:1;
        ULONG UncorrectableSplitCompletion:1;
        ULONG UncorrectableDataError:1;
        ULONG UncorrectableAttributeError:1;
        ULONG UncorrectableAddressError:1;
        ULONG DelayedTransactionDiscardTimerExpired:1;
        ULONG PERRAsserted:1;
        ULONG SERRAsserted:1;
        ULONG InternalBridgeError:1;
        ULONG Reserved:18;
    } DUMMYSTRUCTNAME;

    ULONG AsULONG;

} PCI_EXPRESS_SEC_UNCORRECTABLE_ERROR_STATUS,
  *PPCI_EXPRESS_SEC_UNCORRECTABLE_ERROR_STATUS;

typedef union _PCI_EXPRESS_SEC_UNCORRECTABLE_ERROR_MASK {

    struct {
        ULONG TargetAbortOnSplitCompletion:1;
        ULONG MasterAbortOnSplitCompletion:1;
        ULONG ReceivedTargetAbort:1;
        ULONG ReceivedMasterAbort:1;
        ULONG RsvdZ:1;
        ULONG UnexpectedSplitCompletionError:1;
        ULONG UncorrectableSplitCompletion:1;
        ULONG UncorrectableDataError:1;
        ULONG UncorrectableAttributeError:1;
        ULONG UncorrectableAddressError:1;
        ULONG DelayedTransactionDiscardTimerExpired:1;
        ULONG PERRAsserted:1;
        ULONG SERRAsserted:1;
        ULONG InternalBridgeError:1;
        ULONG Reserved:18;
    } DUMMYSTRUCTNAME;

    ULONG AsULONG;

} PCI_EXPRESS_SEC_UNCORRECTABLE_ERROR_MASK,
  *PPCI_EXPRESS_SEC_UNCORRECTABLE_ERROR_MASK;

typedef union _PCI_EXPRESS_SEC_UNCORRECTABLE_ERROR_SEVERITY {

    struct {
        ULONG TargetAbortOnSplitCompletion:1;
        ULONG MasterAbortOnSplitCompletion:1;
        ULONG ReceivedTargetAbort:1;
        ULONG ReceivedMasterAbort:1;
        ULONG RsvdZ:1;
        ULONG UnexpectedSplitCompletionError:1;
        ULONG UncorrectableSplitCompletion:1;
        ULONG UncorrectableDataError:1;
        ULONG UncorrectableAttributeError:1;
        ULONG UncorrectableAddressError:1;
        ULONG DelayedTransactionDiscardTimerExpired:1;
        ULONG PERRAsserted:1;
        ULONG SERRAsserted:1;
        ULONG InternalBridgeError:1;
        ULONG Reserved:18;
    } DUMMYSTRUCTNAME;

    ULONG AsULONG;

} PCI_EXPRESS_SEC_UNCORRECTABLE_ERROR_SEVERITY,
  *PPCI_EXPRESS_SEC_UNCORRECTABLE_ERROR_SEVERITY;

typedef union _PCI_EXPRESS_SEC_AER_CAPABILITIES {

    struct {
        ULONG SecondaryUncorrectableFirstErrorPtr:5;
        ULONG Reserved:27;
    } DUMMYSTRUCTNAME;

    ULONG AsULONG;

} PCI_EXPRESS_SEC_AER_CAPABILITIES, *PPCI_EXPRESS_SEC_AER_CAPABILITIES;

#define ROOT_CMD_ENABLE_CORRECTABLE_ERROR_REPORTING  0x00000001
#define ROOT_CMD_ENABLE_NONFATAL_ERROR_REPORTING     0x00000002
#define ROOT_CMD_ENABLE_FATAL_ERROR_REPORTING        0x00000004

#define ROOT_CMD_ERROR_REPORTING_ENABLE_MASK \
    (ROOT_CMD_ENABLE_FATAL_ERROR_REPORTING | \
     ROOT_CMD_ENABLE_NONFATAL_ERROR_REPORTING | \
     ROOT_CMD_ENABLE_CORRECTABLE_ERROR_REPORTING)

//
// Advanced Error Reporting Capability structure.
//

typedef struct _PCI_EXPRESS_AER_CAPABILITY {

    PCI_EXPRESS_ENHANCED_CAPABILITY_HEADER Header;

    PCI_EXPRESS_UNCORRECTABLE_ERROR_STATUS UncorrectableErrorStatus;
    PCI_EXPRESS_UNCORRECTABLE_ERROR_MASK UncorrectableErrorMask;
    PCI_EXPRESS_UNCORRECTABLE_ERROR_SEVERITY UncorrectableErrorSeverity;
    PCI_EXPRESS_CORRECTABLE_ERROR_STATUS CorrectableErrorStatus;
    PCI_EXPRESS_CORRECTABLE_ERROR_MASK CorrectableErrorMask;
    PCI_EXPRESS_AER_CAPABILITIES CapabilitiesAndControl;
    ULONG HeaderLog[4];
    PCI_EXPRESS_SEC_UNCORRECTABLE_ERROR_STATUS SecUncorrectableErrorStatus;
    PCI_EXPRESS_SEC_UNCORRECTABLE_ERROR_MASK SecUncorrectableErrorMask;
    PCI_EXPRESS_SEC_UNCORRECTABLE_ERROR_SEVERITY SecUncorrectableErrorSeverity;
    PCI_EXPRESS_SEC_AER_CAPABILITIES SecCapabilitiesAndControl;
    ULONG SecHeaderLog[4];

} PCI_EXPRESS_AER_CAPABILITY, *PPCI_EXPRESS_AER_CAPABILITY;

//
// Advanced Error Reporting Capability structure for root port.
//

typedef struct _PCI_EXPRESS_ROOTPORT_AER_CAPABILITY {

    PCI_EXPRESS_ENHANCED_CAPABILITY_HEADER Header;

    PCI_EXPRESS_UNCORRECTABLE_ERROR_STATUS UncorrectableErrorStatus;
    PCI_EXPRESS_UNCORRECTABLE_ERROR_MASK UncorrectableErrorMask;
    PCI_EXPRESS_UNCORRECTABLE_ERROR_SEVERITY UncorrectableErrorSeverity;
    PCI_EXPRESS_CORRECTABLE_ERROR_STATUS CorrectableErrorStatus;
    PCI_EXPRESS_CORRECTABLE_ERROR_MASK CorrectableErrorMask;
    PCI_EXPRESS_AER_CAPABILITIES CapabilitiesAndControl;
    ULONG HeaderLog[4];
    PCI_EXPRESS_ROOT_ERROR_COMMAND RootErrorCommand;
    PCI_EXPRESS_ROOT_ERROR_STATUS RootErrorStatus;
    PCI_EXPRESS_ERROR_SOURCE_ID ErrorSourceId;

} PCI_EXPRESS_ROOTPORT_AER_CAPABILITY, *PPCI_EXPRESS_ROOTPORT_AER_CAPABILITY;

//
// Advanced Error Reporting Capability structure for root port.
//

typedef struct _PCI_EXPRESS_BRIDGE_AER_CAPABILITY {

    PCI_EXPRESS_ENHANCED_CAPABILITY_HEADER Header;

    PCI_EXPRESS_UNCORRECTABLE_ERROR_STATUS UncorrectableErrorStatus;
    PCI_EXPRESS_UNCORRECTABLE_ERROR_MASK UncorrectableErrorMask;
    PCI_EXPRESS_UNCORRECTABLE_ERROR_SEVERITY UncorrectableErrorSeverity;
    PCI_EXPRESS_CORRECTABLE_ERROR_STATUS CorrectableErrorStatus;
    PCI_EXPRESS_CORRECTABLE_ERROR_MASK CorrectableErrorMask;
    PCI_EXPRESS_AER_CAPABILITIES CapabilitiesAndControl;
    ULONG HeaderLog[4];
    PCI_EXPRESS_SEC_UNCORRECTABLE_ERROR_STATUS SecUncorrectableErrorStatus;
    PCI_EXPRESS_SEC_UNCORRECTABLE_ERROR_MASK SecUncorrectableErrorMask;
    PCI_EXPRESS_SEC_UNCORRECTABLE_ERROR_SEVERITY SecUncorrectableErrorSeverity;
    PCI_EXPRESS_SEC_AER_CAPABILITIES SecCapabilitiesAndControl;
    ULONG SecHeaderLog[4];

} PCI_EXPRESS_BRIDGE_AER_CAPABILITY, *PPCI_EXPRESS_BRIDGE_AER_CAPABILITY;

//
// Single-Root I/O Virtualization Capability structure for endpoints
// 

typedef union _PCI_EXPRESS_SRIOV_CAPS {

    struct {
        ULONG VFMigrationCapable:1;
        ULONG Reserved1:20;
        ULONG VFMigrationInterruptNumber:11;
    } DUMMYSTRUCTNAME;

    ULONG AsULONG;

} PCI_EXPRESS_SRIOV_CAPS, *PPCI_EXPRESS_SRIOV_CAPS;

typedef union _PCI_EXPRESS_SRIOV_CONTROL {

    struct {
        USHORT VFEnable:1;
        USHORT VFMigrationEnable:1;
        USHORT VFMigrationInterruptEnable:1;
        USHORT VFMemorySpaceEnable:1;
        USHORT ARICapableHierarchy:1;
        USHORT Reserved1:11;
    } DUMMYSTRUCTNAME;

    USHORT AsUSHORT;

} PCI_EXPRESS_SRIOV_CONTROL, *PPCI_EXPRESS_SRIOV_CONTROL;

typedef union _PCI_EXPRESS_SRIOV_STATUS {

    struct {
        USHORT VFMigrationStatus:1;
        USHORT Reserved1:15;
    } DUMMYSTRUCTNAME;

    USHORT AsUSHORT;

} PCI_EXPRESS_SRIOV_STATUS, *PPCI_EXPRESS_SRIOV_STATUS;

typedef union _PCI_EXPRESS_SRIOV_MIGRATION_STATE_ARRAY {

    struct {
        ULONG VFMigrationStateBIR:3;
        ULONG VFMigrationStateOffset:29;
    } DUMMYSTRUCTNAME;

    ULONG AsULONG;

} PCI_EXPRESS_SRIOV_MIGRATION_STATE_ARRAY, *PPCI_EXPRESS_SRIOV_MIGRATION_STATE_ARRAY;

typedef struct _PCI_EXPRESS_SRIOV_CAPABILITY {

    PCI_EXPRESS_ENHANCED_CAPABILITY_HEADER  Header;

    PCI_EXPRESS_SRIOV_CAPS                  SRIOVCapabilities;
    PCI_EXPRESS_SRIOV_CONTROL               SRIOVControl;
    PCI_EXPRESS_SRIOV_STATUS                SRIOVStatus;
    USHORT                                  InitialVFs;
    USHORT                                  TotalVFs;
    USHORT                                  NumVFs;
    UCHAR                                   FunctionDependencyLink;
    UCHAR                                   RsvdP1;
    USHORT                                  FirstVFOffset;
    USHORT                                  VFStride;
    USHORT                                  RsvdP2;
    USHORT                                  VFDeviceId;
    ULONG                                   SupportedPageSizes;
    ULONG                                   SystemPageSize;
    ULONG                                   BaseAddresses[PCI_TYPE0_ADDRESSES];
    PCI_EXPRESS_SRIOV_MIGRATION_STATE_ARRAY VFMigrationStateArrayOffset;

} PCI_EXPRESS_SRIOV_CAPABILITY, *PPCI_EXPRESS_SRIOV_CAPABILITY;

//
// Base Class Code encodings for Base Class (from PCI spec rev 2.1).
//

#define PCI_CLASS_PRE_20                    0x00
#define PCI_CLASS_MASS_STORAGE_CTLR         0x01
#define PCI_CLASS_NETWORK_CTLR              0x02
#define PCI_CLASS_DISPLAY_CTLR              0x03
#define PCI_CLASS_MULTIMEDIA_DEV            0x04
#define PCI_CLASS_MEMORY_CTLR               0x05
#define PCI_CLASS_BRIDGE_DEV                0x06
#define PCI_CLASS_SIMPLE_COMMS_CTLR         0x07
#define PCI_CLASS_BASE_SYSTEM_DEV           0x08
#define PCI_CLASS_INPUT_DEV                 0x09
#define PCI_CLASS_DOCKING_STATION           0x0a
#define PCI_CLASS_PROCESSOR                 0x0b
#define PCI_CLASS_SERIAL_BUS_CTLR           0x0c
#define PCI_CLASS_WIRELESS_CTLR             0x0d
#define PCI_CLASS_INTELLIGENT_IO_CTLR       0x0e
#define PCI_CLASS_SATELLITE_COMMS_CTLR      0x0f
#define PCI_CLASS_ENCRYPTION_DECRYPTION     0x10
#define PCI_CLASS_DATA_ACQ_SIGNAL_PROC      0x11

// 0d thru fe reserved

#define PCI_CLASS_NOT_DEFINED               0xff

//
// Sub Class Code encodings (PCI rev 2.1).
//

// Class 00 - PCI_CLASS_PRE_20

#define PCI_SUBCLASS_PRE_20_NON_VGA         0x00
#define PCI_SUBCLASS_PRE_20_VGA             0x01

// Class 01 - PCI_CLASS_MASS_STORAGE_CTLR

#define PCI_SUBCLASS_MSC_SCSI_BUS_CTLR      0x00
#define PCI_SUBCLASS_MSC_IDE_CTLR           0x01
#define PCI_SUBCLASS_MSC_FLOPPY_CTLR        0x02
#define PCI_SUBCLASS_MSC_IPI_CTLR           0x03
#define PCI_SUBCLASS_MSC_RAID_CTLR          0x04
#define PCI_SUBCLASS_MSC_OTHER              0x80

// Class 02 - PCI_CLASS_NETWORK_CTLR

#define PCI_SUBCLASS_NET_ETHERNET_CTLR      0x00
#define PCI_SUBCLASS_NET_TOKEN_RING_CTLR    0x01
#define PCI_SUBCLASS_NET_FDDI_CTLR          0x02
#define PCI_SUBCLASS_NET_ATM_CTLR           0x03
#define PCI_SUBCLASS_NET_ISDN_CTLR          0x04
#define PCI_SUBCLASS_NET_OTHER              0x80

// Class 03 - PCI_CLASS_DISPLAY_CTLR

// N.B. Sub Class 00 could be VGA or 8514 depending on Interface byte

#define PCI_SUBCLASS_VID_VGA_CTLR           0x00
#define PCI_SUBCLASS_VID_XGA_CTLR           0x01
#define PCI_SUBLCASS_VID_3D_CTLR            0x02
#define PCI_SUBCLASS_VID_OTHER              0x80

// Class 04 - PCI_CLASS_MULTIMEDIA_DEV

#define PCI_SUBCLASS_MM_VIDEO_DEV           0x00
#define PCI_SUBCLASS_MM_AUDIO_DEV           0x01
#define PCI_SUBCLASS_MM_TELEPHONY_DEV       0x02
#define PCI_SUBCLASS_MM_OTHER               0x80

// Class 05 - PCI_CLASS_MEMORY_CTLR

#define PCI_SUBCLASS_MEM_RAM                0x00
#define PCI_SUBCLASS_MEM_FLASH              0x01
#define PCI_SUBCLASS_MEM_OTHER              0x80

// Class 06 - PCI_CLASS_BRIDGE_DEV

#define PCI_SUBCLASS_BR_HOST                0x00
#define PCI_SUBCLASS_BR_ISA                 0x01
#define PCI_SUBCLASS_BR_EISA                0x02
#define PCI_SUBCLASS_BR_MCA                 0x03
#define PCI_SUBCLASS_BR_PCI_TO_PCI          0x04
#define PCI_SUBCLASS_BR_PCMCIA              0x05
#define PCI_SUBCLASS_BR_NUBUS               0x06
#define PCI_SUBCLASS_BR_CARDBUS             0x07
#define PCI_SUBCLASS_BR_RACEWAY             0x08
#define PCI_SUBCLASS_BR_OTHER               0x80

// Class 07 - PCI_CLASS_SIMPLE_COMMS_CTLR

// N.B. Sub Class 00 and 01 additional info in Interface byte

#define PCI_SUBCLASS_COM_SERIAL             0x00
#define PCI_SUBCLASS_COM_PARALLEL           0x01
#define PCI_SUBCLASS_COM_MULTIPORT          0x02
#define PCI_SUBCLASS_COM_MODEM              0x03
#define PCI_SUBCLASS_COM_OTHER              0x80

// Class 08 - PCI_CLASS_BASE_SYSTEM_DEV

// N.B. See Interface byte for additional info.

#define PCI_SUBCLASS_SYS_INTERRUPT_CTLR     0x00
#define PCI_SUBCLASS_SYS_DMA_CTLR           0x01
#define PCI_SUBCLASS_SYS_SYSTEM_TIMER       0x02
#define PCI_SUBCLASS_SYS_REAL_TIME_CLOCK    0x03
#define PCI_SUBCLASS_SYS_GEN_HOTPLUG_CTLR   0x04
#define PCI_SUBCLASS_SYS_SDIO_CTRL          0x05
#define PCI_SUBCLASS_SYS_OTHER              0x80

// Class 09 - PCI_CLASS_INPUT_DEV

#define PCI_SUBCLASS_INP_KEYBOARD           0x00
#define PCI_SUBCLASS_INP_DIGITIZER          0x01
#define PCI_SUBCLASS_INP_MOUSE              0x02
#define PCI_SUBCLASS_INP_SCANNER            0x03
#define PCI_SUBCLASS_INP_GAMEPORT           0x04
#define PCI_SUBCLASS_INP_OTHER              0x80

// Class 0a - PCI_CLASS_DOCKING_STATION

#define PCI_SUBCLASS_DOC_GENERIC            0x00
#define PCI_SUBCLASS_DOC_OTHER              0x80

// Class 0b - PCI_CLASS_PROCESSOR

#define PCI_SUBCLASS_PROC_386               0x00
#define PCI_SUBCLASS_PROC_486               0x01
#define PCI_SUBCLASS_PROC_PENTIUM           0x02
#define PCI_SUBCLASS_PROC_ALPHA             0x10
#define PCI_SUBCLASS_PROC_POWERPC           0x20
#define PCI_SUBCLASS_PROC_COPROCESSOR       0x40

// Class 0c - PCI_CLASS_SERIAL_BUS_CTLR

#define PCI_SUBCLASS_SB_IEEE1394            0x00
#define PCI_SUBCLASS_SB_ACCESS              0x01
#define PCI_SUBCLASS_SB_SSA                 0x02
#define PCI_SUBCLASS_SB_USB                 0x03
#define PCI_SUBCLASS_SB_FIBRE_CHANNEL       0x04
#define PCI_SUBCLASS_SB_SMBUS               0x05

// Class 0d - PCI_CLASS_WIRELESS_CTLR

#define PCI_SUBCLASS_WIRELESS_IRDA          0x00
#define PCI_SUBCLASS_WIRELESS_CON_IR        0x01
#define PCI_SUBCLASS_WIRELESS_RF            0x10
#define PCI_SUBCLASS_WIRELESS_OTHER         0x80

// Class 0e - PCI_CLASS_INTELLIGENT_IO_CTLR

#define PCI_SUBCLASS_INTIO_I2O              0x00

// Class 0f - PCI_CLASS_SATELLITE_CTLR

#define PCI_SUBCLASS_SAT_TV                 0x01
#define PCI_SUBCLASS_SAT_AUDIO              0x02
#define PCI_SUBCLASS_SAT_VOICE              0x03
#define PCI_SUBCLASS_SAT_DATA               0x04

// Class 10 - PCI_CLASS_ENCRYPTION_DECRYPTION

#define PCI_SUBCLASS_CRYPTO_NET_COMP        0x00
#define PCI_SUBCLASS_CRYPTO_ENTERTAINMENT   0x10
#define PCI_SUBCLASS_CRYPTO_OTHER           0x80

// Class 11 - PCI_CLASS_DATA_ACQ_SIGNAL_PROC

#define PCI_SUBCLASS_DASP_DPIO              0x00
#define PCI_SUBCLASS_DASP_OTHER             0x80



//
// Bit encodes for PCI_COMMON_CONFIG.u.type0.BaseAddresses
//

#define PCI_ADDRESS_IO_SPACE                0x00000001  // (ro)
#define PCI_ADDRESS_MEMORY_TYPE_MASK        0x00000006  // (ro)
#define PCI_ADDRESS_MEMORY_PREFETCHABLE     0x00000008  // (ro)

#define PCI_ADDRESS_IO_ADDRESS_MASK         0xfffffffc
#define PCI_ADDRESS_MEMORY_ADDRESS_MASK     0xfffffff0
#define PCI_ADDRESS_ROM_ADDRESS_MASK        0xfffff800

#define PCI_TYPE_32BIT      0
#define PCI_TYPE_20BIT      2
#define PCI_TYPE_64BIT      4

//
// Bit encodes for PCI_COMMON_CONFIG.u.type0.ROMBaseAddresses
//

#define PCI_ROMADDRESS_ENABLED              0x00000001


//
// Reference notes for PCI configuration fields:
//
// ro   these field are read only.  changes to these fields are ignored
//
// ro+  these field are intended to be read only and should be initialized
//      by the system to their proper values.  However, driver may change
//      these settings.
//
// ---
//
//      All resources comsumed by a PCI device start as unitialized
//      under NT.  An uninitialized memory or I/O base address can be
//      determined by checking it's corrisponding enabled bit in the
//      PCI_COMMON_CONFIG.Command value.  An InterruptLine is unitialized
//      if it contains the value of -1.
//


#endif // _PCI_X_


//
// Device Presence interface
//
#define PCI_DEVICE_PRESENT_INTERFACE_VERSION 1

//
// Flags for PCI_DEVICE_PRESENCE_PARAMETERS
//
#define PCI_USE_SUBSYSTEM_IDS   0x00000001
#define PCI_USE_REVISION        0x00000002
// The following flags are only valid for IsDevicePresentEx
#define PCI_USE_VENDEV_IDS      0x00000004
#define PCI_USE_CLASS_SUBCLASS  0x00000008
#define PCI_USE_PROGIF          0x00000010
#define PCI_USE_LOCAL_BUS       0x00000020
#define PCI_USE_LOCAL_DEVICE    0x00000040

//
// Search parameters structure for IsDevicePresentEx
//
typedef struct _PCI_DEVICE_PRESENCE_PARAMETERS {

    ULONG Size;
    ULONG Flags;

    USHORT VendorID;
    USHORT DeviceID;
    UCHAR RevisionID;
    USHORT SubVendorID;
    USHORT SubSystemID;
    UCHAR BaseClass;
    UCHAR SubClass;
    UCHAR ProgIf;

} PCI_DEVICE_PRESENCE_PARAMETERS, *PPCI_DEVICE_PRESENCE_PARAMETERS;

__drv_maxIRQL(PASSIVE_LEVEL)
__checkReturn
typedef
BOOLEAN
PCI_IS_DEVICE_PRESENT (
    __in USHORT VendorID,
    __in USHORT DeviceID,
    __in UCHAR RevisionID,
    __in USHORT SubVendorID,
    __in USHORT SubSystemID,
    __in ULONG Flags
);

typedef PCI_IS_DEVICE_PRESENT *PPCI_IS_DEVICE_PRESENT;

__drv_maxIRQL(PASSIVE_LEVEL)
__checkReturn
typedef
BOOLEAN
PCI_IS_DEVICE_PRESENT_EX (
    __in PVOID Context,
    __in PPCI_DEVICE_PRESENCE_PARAMETERS Parameters
    );

typedef PCI_IS_DEVICE_PRESENT_EX *PPCI_IS_DEVICE_PRESENT_EX;

typedef struct _PCI_DEVICE_PRESENT_INTERFACE {
    //
    // generic interface header
    //
    USHORT Size;
    USHORT Version;
    PVOID Context;
    PINTERFACE_REFERENCE InterfaceReference;
    PINTERFACE_DEREFERENCE InterfaceDereference;
    //
    // pci device info
    //
    PPCI_IS_DEVICE_PRESENT IsDevicePresent;

    PPCI_IS_DEVICE_PRESENT_EX IsDevicePresentEx;

} PCI_DEVICE_PRESENT_INTERFACE, *PPCI_DEVICE_PRESENT_INTERFACE;

//
// Pci Express Link Quiesce Interface
//

#define PCI_EXPRESS_LINK_QUIESCENT_INTERFACE_VERSION      1

__drv_maxIRQL(PASSIVE_LEVEL)
__checkReturn
typedef
NTSTATUS
PCI_EXPRESS_ENTER_LINK_QUIESCENT_MODE (
    __inout PVOID Context
    );

typedef PCI_EXPRESS_ENTER_LINK_QUIESCENT_MODE *PPCI_EXPRESS_ENTER_LINK_QUIESCENT_MODE;

__drv_maxIRQL(PASSIVE_LEVEL)
__checkReturn
typedef
NTSTATUS
PCI_EXPRESS_EXIT_LINK_QUIESCENT_MODE (
    __inout PVOID Context
    );

typedef PCI_EXPRESS_EXIT_LINK_QUIESCENT_MODE *PPCI_EXPRESS_EXIT_LINK_QUIESCENT_MODE;

typedef struct _PCI_EXPRESS_LINK_QUIESCENT_INTERFACE {

    USHORT Size;
    USHORT Version;
    PVOID Context;
    PINTERFACE_REFERENCE InterfaceReference;
    PINTERFACE_DEREFERENCE InterfaceDereference;

    PPCI_EXPRESS_ENTER_LINK_QUIESCENT_MODE PciExpressEnterLinkQuiescentMode;
    PPCI_EXPRESS_EXIT_LINK_QUIESCENT_MODE PciExpressExitLinkQuiescentMode;

} PCI_EXPRESS_LINK_QUIESCENT_INTERFACE, *PPCI_EXPRESS_LINK_QUIESCENT_INTERFACE;

//
// Pci Express Root Port Access Interface
//

#define PCI_EXPRESS_ROOT_PORT_INTERFACE_VERSION        1

typedef
ULONG
(*PPCI_EXPRESS_ROOT_PORT_READ_CONFIG_SPACE) (
    __in PVOID Context,
    __out_bcount(Length) PVOID Buffer,
    __in ULONG Offset,
    __in ULONG Length
    );

typedef
ULONG
(*PPCI_EXPRESS_ROOT_PORT_WRITE_CONFIG_SPACE) (
    __in PVOID Context,
    __in_bcount(Length) PVOID Buffer,
    __in ULONG Offset,
    __in ULONG Length
    );

typedef struct _PCI_EXPRESS_ROOT_PORT_INTERFACE {

    USHORT Size;
    USHORT Version;
    PVOID Context;
    PINTERFACE_REFERENCE InterfaceReference;
    PINTERFACE_DEREFERENCE InterfaceDereference;

    PPCI_EXPRESS_ROOT_PORT_READ_CONFIG_SPACE ReadConfigSpace;
    PPCI_EXPRESS_ROOT_PORT_WRITE_CONFIG_SPACE WriteConfigSpace;

} PCI_EXPRESS_ROOT_PORT_INTERFACE, *PPCI_EXPRESS_ROOT_PORT_INTERFACE;

//
// MSI-X interrupt table configuration interface
//

#define PCI_MSIX_TABLE_CONFIG_INTERFACE_VERSION 1

__checkReturn
typedef
NTSTATUS
PCI_MSIX_SET_ENTRY (
    __in PVOID Context,
    __in ULONG TableEntry,
    __in ULONG MessageNumber
    );

typedef PCI_MSIX_SET_ENTRY *PPCI_MSIX_SET_ENTRY;

__checkReturn
typedef
NTSTATUS
PCI_MSIX_MASKUNMASK_ENTRY (
    __in PVOID Context,
    __in ULONG TableEntry
    );

typedef PCI_MSIX_MASKUNMASK_ENTRY *PPCI_MSIX_MASKUNMASK_ENTRY;

__checkReturn
typedef
NTSTATUS
PCI_MSIX_GET_ENTRY (
    __in PVOID Context,
    __in ULONG TableEntry,
    __out PULONG MessageNumber,
    __out PBOOLEAN Masked
    );

typedef PCI_MSIX_GET_ENTRY *PPCI_MSIX_GET_ENTRY;

__checkReturn
typedef
NTSTATUS
PCI_MSIX_GET_TABLE_SIZE (
    __in PVOID Context,
    __out PULONG TableSize
    );

typedef PCI_MSIX_GET_TABLE_SIZE *PPCI_MSIX_GET_TABLE_SIZE;

typedef struct _PCI_MSIX_TABLE_CONFIG_INTERFACE {
    USHORT Size;
    USHORT Version;
    PVOID Context;
    PINTERFACE_REFERENCE InterfaceReference;
    PINTERFACE_DEREFERENCE InterfaceDereference;

    PPCI_MSIX_SET_ENTRY SetTableEntry;
    PPCI_MSIX_MASKUNMASK_ENTRY MaskTableEntry;
    PPCI_MSIX_MASKUNMASK_ENTRY UnmaskTableEntry;
    PPCI_MSIX_GET_ENTRY GetTableEntry;
    PPCI_MSIX_GET_TABLE_SIZE GetTableSize;
} PCI_MSIX_TABLE_CONFIG_INTERFACE, *PPCI_MSIX_TABLE_CONFIG_INTERFACE;

#define PCI_MSIX_TABLE_CONFIG_MINIMUM_SIZE \
        RTL_SIZEOF_THROUGH_FIELD(PCI_MSIX_TABLE_CONFIG_INTERFACE, UnmaskTableEntry)

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwCreateFile(
    __out PHANDLE FileHandle,
    __in ACCESS_MASK DesiredAccess,
    __in POBJECT_ATTRIBUTES ObjectAttributes,
    __out PIO_STATUS_BLOCK IoStatusBlock,
    __in_opt PLARGE_INTEGER AllocationSize,
    __in ULONG FileAttributes,
    __in ULONG ShareAccess,
    __in ULONG CreateDisposition,
    __in ULONG CreateOptions,
    __in_bcount_opt(EaLength) PVOID EaBuffer,
    __in ULONG EaLength
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwOpenFile(
    __out PHANDLE FileHandle,
    __in ACCESS_MASK DesiredAccess,
    __in POBJECT_ATTRIBUTES ObjectAttributes,
    __out PIO_STATUS_BLOCK IoStatusBlock,
    __in ULONG ShareAccess,
    __in ULONG OpenOptions
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwLoadDriver(
    __in PUNICODE_STRING DriverServiceName
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwUnloadDriver(
    __in PUNICODE_STRING DriverServiceName
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwQueryInformationFile(
    __in HANDLE FileHandle,
    __out PIO_STATUS_BLOCK IoStatusBlock,
    __out_bcount(Length) PVOID FileInformation,
    __in ULONG Length,
    __in FILE_INFORMATION_CLASS FileInformationClass
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwSetInformationFile(
    __in HANDLE FileHandle,
    __out PIO_STATUS_BLOCK IoStatusBlock,
    __in_bcount(Length) PVOID FileInformation,
    __in ULONG Length,
    __in FILE_INFORMATION_CLASS FileInformationClass
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwReadFile(
    __in HANDLE FileHandle,
    __in_opt HANDLE Event,
    __in_opt PIO_APC_ROUTINE ApcRoutine,
    __in_opt PVOID ApcContext,
    __out PIO_STATUS_BLOCK IoStatusBlock,
    __out_bcount(Length) PVOID Buffer,
    __in ULONG Length,
    __in_opt PLARGE_INTEGER ByteOffset,
    __in_opt PULONG Key
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwWriteFile(
    __in HANDLE FileHandle,
    __in_opt HANDLE Event,
    __in_opt PIO_APC_ROUTINE ApcRoutine,
    __in_opt PVOID ApcContext,
    __out PIO_STATUS_BLOCK IoStatusBlock,
    __in_bcount(Length) PVOID Buffer,
    __in ULONG Length,
    __in_opt PLARGE_INTEGER ByteOffset,
    __in_opt PULONG Key
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwClose(
    __in HANDLE Handle
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwCreateDirectoryObject(
    __out PHANDLE DirectoryHandle,
    __in ACCESS_MASK DesiredAccess,
    __in POBJECT_ATTRIBUTES ObjectAttributes
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwMakeTemporaryObject(
    __in HANDLE Handle
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwCreateSection (
    __out PHANDLE SectionHandle,
    __in ACCESS_MASK DesiredAccess,
    __in_opt POBJECT_ATTRIBUTES ObjectAttributes,
    __in_opt PLARGE_INTEGER MaximumSize,
    __in ULONG SectionPageProtection,
    __in ULONG AllocationAttributes,
    __in_opt HANDLE FileHandle
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwOpenSection(
    __out PHANDLE SectionHandle,
    __in ACCESS_MASK DesiredAccess,
    __in POBJECT_ATTRIBUTES ObjectAttributes
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwMapViewOfSection(
    __in HANDLE SectionHandle,
    __in HANDLE ProcessHandle,
    __inout PVOID *BaseAddress,
    __in ULONG_PTR ZeroBits,
    __in SIZE_T CommitSize,
    __inout_opt PLARGE_INTEGER SectionOffset,
    __inout PSIZE_T ViewSize,
    __in SECTION_INHERIT InheritDisposition,
    __in ULONG AllocationType,
    __in ULONG Win32Protect
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwUnmapViewOfSection(
    __in HANDLE ProcessHandle,
    __in_opt PVOID BaseAddress
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwCreateKey(
    __out PHANDLE KeyHandle,
    __in ACCESS_MASK DesiredAccess,
    __in POBJECT_ATTRIBUTES ObjectAttributes,
    __reserved ULONG TitleIndex,
    __in_opt PUNICODE_STRING Class,
    __in ULONG CreateOptions,
    __out_opt PULONG Disposition
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
ZwCreateKeyTransacted(
    __out PHANDLE KeyHandle,
    __in ACCESS_MASK DesiredAccess,
    __in POBJECT_ATTRIBUTES ObjectAttributes,
    __reserved ULONG TitleIndex,
    __in_opt PUNICODE_STRING Class,
    __in ULONG CreateOptions,
    __in HANDLE TransactionHandle,
    __out_opt PULONG Disposition
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwOpenKey(
    __out PHANDLE KeyHandle,
    __in ACCESS_MASK DesiredAccess,
    __in POBJECT_ATTRIBUTES ObjectAttributes
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwOpenKeyEx(
    __out PHANDLE KeyHandle,
    __in ACCESS_MASK DesiredAccess,
    __in POBJECT_ATTRIBUTES ObjectAttributes,
    __in ULONG OpenOptions
    );
#endif



#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwOpenKeyTransacted(
    __out PHANDLE KeyHandle,
    __in ACCESS_MASK DesiredAccess,
    __in POBJECT_ATTRIBUTES ObjectAttributes,
    __in HANDLE TransactionHandle
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN7)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwOpenKeyTransactedEx(
    __out PHANDLE KeyHandle,
    __in ACCESS_MASK DesiredAccess,
    __in POBJECT_ATTRIBUTES ObjectAttributes,
    __in ULONG OpenOptions,
    __in HANDLE TransactionHandle
    );
#endif



#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwDeleteKey(
    __in HANDLE KeyHandle
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwDeleteValueKey(
    __in HANDLE KeyHandle,
    __in PUNICODE_STRING ValueName
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
__drv_when(Length==0, __drv_valueIs(<0))
__drv_when(Length>0, __drv_valueIs(<0;==0))
NTSYSAPI
NTSTATUS
NTAPI
ZwEnumerateKey(
    __in HANDLE KeyHandle,
    __in ULONG Index,
    __in KEY_INFORMATION_CLASS KeyInformationClass,
    __out_bcount_opt(Length) PVOID KeyInformation,
    __in ULONG Length,
    __out PULONG ResultLength
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
__drv_when(Length==0, __drv_valueIs(<0))
__drv_when(Length>0, __drv_valueIs(<0;==0))
NTSYSAPI
NTSTATUS
NTAPI
ZwEnumerateValueKey(
    __in HANDLE KeyHandle,
    __in ULONG Index,
    __in KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    __out_bcount_opt(Length) PVOID KeyValueInformation,
    __in ULONG Length,
    __out PULONG ResultLength
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwFlushKey(
    __in HANDLE KeyHandle
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwNotifyChangeMultipleKeys(
    __in HANDLE MasterKeyHandle,
    __in_opt ULONG Count,
    __in_ecount_opt(Count) OBJECT_ATTRIBUTES SubordinateObjects[],
    __in_opt HANDLE Event,
    __in_opt PIO_APC_ROUTINE ApcRoutine,
    __in_opt PVOID ApcContext,
    __out PIO_STATUS_BLOCK IoStatusBlock,
    __in ULONG CompletionFilter,
    __in BOOLEAN WatchTree,
    __out_bcount_opt(BufferSize) PVOID Buffer,
    __in ULONG BufferSize,
    __in BOOLEAN Asynchronous
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwQueryMultipleValueKey(
    __in HANDLE KeyHandle,
    __inout_ecount(EntryCount) PKEY_VALUE_ENTRY ValueEntries,
    __in ULONG EntryCount,
    __out_bcount(*BufferLength) PVOID ValueBuffer,
    __inout PULONG BufferLength,
    __out_opt PULONG RequiredBufferLength
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
__drv_when(Length==0, __drv_valueIs(<0))
__drv_when(Length>0, __drv_valueIs(<0;==0))
NTSYSAPI
NTSTATUS
NTAPI
ZwQueryKey(
    __in HANDLE KeyHandle,
    __in KEY_INFORMATION_CLASS KeyInformationClass,
    __out_bcount_opt(Length) PVOID KeyInformation,
    __in ULONG Length,
    __out PULONG ResultLength
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
__drv_when(Length==0, __drv_valueIs(<0))
__drv_when(Length>0, __drv_valueIs(<0;==0))
NTSYSAPI
NTSTATUS
NTAPI
ZwQueryValueKey(
    __in HANDLE KeyHandle,
    __in PUNICODE_STRING ValueName,
    __in KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    __out_bcount_opt(Length) PVOID KeyValueInformation,
    __in ULONG Length,
    __out PULONG ResultLength
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwRenameKey(
    __in HANDLE           KeyHandle,
    __in PUNICODE_STRING  NewName
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwSetInformationKey(
    __in HANDLE KeyHandle,
    __in KEY_SET_INFORMATION_CLASS KeySetInformationClass,
    __in_bcount(KeySetInformationLength) PVOID KeySetInformation,
    __in ULONG KeySetInformationLength
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwSetValueKey(
    __in HANDLE KeyHandle,
    __in PUNICODE_STRING ValueName,
    __in_opt ULONG TitleIndex,
    __in ULONG Type,
    __in_bcount_opt(DataSize) PVOID Data,
    __in ULONG DataSize
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwOpenSymbolicLinkObject(
    __out PHANDLE LinkHandle,
    __in ACCESS_MASK DesiredAccess,
    __in POBJECT_ATTRIBUTES ObjectAttributes
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySymbolicLinkObject(
    __in HANDLE LinkHandle,
    __inout PUNICODE_STRING LinkTarget,
    __out_opt PULONG ReturnedLength
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwCreateTransactionManager (
    __out PHANDLE TmHandle,
    __in ACCESS_MASK DesiredAccess,
    __in_opt POBJECT_ATTRIBUTES ObjectAttributes,
    __in_opt PUNICODE_STRING LogFileName,
    __in_opt ULONG CreateOptions,
    __in_opt ULONG CommitStrength
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwOpenTransactionManager (
    __out PHANDLE TmHandle,
    __in ACCESS_MASK DesiredAccess,
    __in_opt POBJECT_ATTRIBUTES ObjectAttributes,
    __in_opt PUNICODE_STRING LogFileName,
    __in_opt LPGUID TmIdentity,
    __in_opt ULONG OpenOptions
    );
#endif


#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwRollforwardTransactionManager (
    __in HANDLE TransactionManagerHandle,
    __in_opt PLARGE_INTEGER TmVirtualClock
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwRecoverTransactionManager (
    __in HANDLE TransactionManagerHandle
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwQueryInformationTransactionManager (
    __in HANDLE TransactionManagerHandle,
    __in TRANSACTIONMANAGER_INFORMATION_CLASS TransactionManagerInformationClass,
    __out_bcount(TransactionManagerInformationLength) PVOID TransactionManagerInformation,
    __in ULONG TransactionManagerInformationLength,
    __out_opt PULONG ReturnLength
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwSetInformationTransactionManager (
    __in HANDLE TmHandle,
    __in TRANSACTIONMANAGER_INFORMATION_CLASS TransactionManagerInformationClass,
    __in PVOID TransactionManagerInformation,
    __in ULONG TransactionManagerInformationLength
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwEnumerateTransactionObject (
    __in_opt HANDLE            RootObjectHandle,
    __in     KTMOBJECT_TYPE    QueryType,
    __inout_bcount(ObjectCursorLength) PKTMOBJECT_CURSOR ObjectCursor,
    __in     ULONG             ObjectCursorLength,
    __out    PULONG            ReturnLength
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwCreateTransaction (
    __out PHANDLE TransactionHandle,
    __in ACCESS_MASK DesiredAccess,
    __in_opt POBJECT_ATTRIBUTES ObjectAttributes,
    __in_opt LPGUID Uow,
    __in_opt HANDLE TmHandle,
    __in_opt ULONG CreateOptions,
    __in_opt ULONG IsolationLevel,
    __in_opt ULONG IsolationFlags,
    __in_opt PLARGE_INTEGER Timeout,
    __in_opt PUNICODE_STRING Description
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwOpenTransaction (
    __out PHANDLE TransactionHandle,
    __in ACCESS_MASK DesiredAccess,
    __in_opt POBJECT_ATTRIBUTES ObjectAttributes,
    __in LPGUID Uow,
    __in_opt HANDLE TmHandle
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwQueryInformationTransaction (
    __in HANDLE TransactionHandle,
    __in TRANSACTION_INFORMATION_CLASS TransactionInformationClass,
    __out_bcount(TransactionInformationLength) PVOID TransactionInformation,
    __in ULONG TransactionInformationLength,
    __out_opt PULONG ReturnLength
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwSetInformationTransaction (
    __in HANDLE TransactionHandle,
    __in TRANSACTION_INFORMATION_CLASS TransactionInformationClass,
    __in PVOID TransactionInformation,
    __in ULONG TransactionInformationLength
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwCommitTransaction (
    __in HANDLE  TransactionHandle,
    __in BOOLEAN Wait
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwRollbackTransaction (
    __in HANDLE  TransactionHandle,
    __in BOOLEAN Wait
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwCreateResourceManager (
    __out PHANDLE ResourceManagerHandle,
    __in ACCESS_MASK DesiredAccess,
    __in HANDLE TmHandle,
    __in_opt LPGUID ResourceManagerGuid,
    __in_opt POBJECT_ATTRIBUTES ObjectAttributes,
    __in_opt ULONG CreateOptions,
    __in_opt PUNICODE_STRING Description
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwOpenResourceManager (
    __out PHANDLE ResourceManagerHandle,
    __in ACCESS_MASK DesiredAccess,
    __in HANDLE TmHandle,
    __in LPGUID ResourceManagerGuid,
    __in_opt POBJECT_ATTRIBUTES ObjectAttributes
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwRecoverResourceManager (
    __in HANDLE ResourceManagerHandle
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwGetNotificationResourceManager (
    __in HANDLE             ResourceManagerHandle,
    __out PTRANSACTION_NOTIFICATION TransactionNotification,
    __in ULONG              NotificationLength,
    __in PLARGE_INTEGER         Timeout,
    __out_opt PULONG                    ReturnLength,
    __in ULONG                          Asynchronous,
    __in_opt ULONG_PTR                  AsynchronousContext
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwQueryInformationResourceManager (
    __in HANDLE ResourceManagerHandle,
    __in RESOURCEMANAGER_INFORMATION_CLASS ResourceManagerInformationClass,
    __out_bcount(ResourceManagerInformationLength) PVOID ResourceManagerInformation,
    __in ULONG ResourceManagerInformationLength,
    __out_opt PULONG ReturnLength
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwSetInformationResourceManager (
    __in HANDLE ResourceManagerHandle,
    __in RESOURCEMANAGER_INFORMATION_CLASS ResourceManagerInformationClass,
    __in_bcount(ResourceManagerInformationLength) PVOID ResourceManagerInformation,
    __in ULONG ResourceManagerInformationLength
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwCreateEnlistment (
    __out PHANDLE EnlistmentHandle,
    __in ACCESS_MASK DesiredAccess,
    __in HANDLE ResourceManagerHandle,
    __in HANDLE TransactionHandle,
    __in_opt POBJECT_ATTRIBUTES ObjectAttributes,
    __in_opt ULONG CreateOptions,
    __in NOTIFICATION_MASK NotificationMask,
    __in_opt PVOID EnlistmentKey
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwOpenEnlistment (
    __out PHANDLE EnlistmentHandle,
    __in ACCESS_MASK DesiredAccess,
    __in HANDLE RmHandle,
    __in LPGUID EnlistmentGuid,
    __in_opt POBJECT_ATTRIBUTES ObjectAttributes
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwQueryInformationEnlistment (
    __in HANDLE EnlistmentHandle,
    __in ENLISTMENT_INFORMATION_CLASS EnlistmentInformationClass,
    __out_bcount(EnlistmentInformationLength) PVOID EnlistmentInformation,
    __in ULONG EnlistmentInformationLength,
    __out_opt PULONG ReturnLength
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwSetInformationEnlistment (
    __in HANDLE EnlistmentHandle,
    __in ENLISTMENT_INFORMATION_CLASS EnlistmentInformationClass,
    __in_bcount(EnlistmentInformationLength) PVOID EnlistmentInformation,
    __in ULONG EnlistmentInformationLength
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwRecoverEnlistment (
    __in HANDLE EnlistmentHandle,
    __in_opt PVOID EnlistmentKey
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwPrePrepareEnlistment (
    __in HANDLE EnlistmentHandle,
    __in_opt PLARGE_INTEGER TmVirtualClock
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwPrepareEnlistment (
    __in HANDLE EnlistmentHandle,
    __in_opt PLARGE_INTEGER TmVirtualClock
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwCommitEnlistment (
    __in HANDLE EnlistmentHandle,
    __in_opt PLARGE_INTEGER TmVirtualClock
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwRollbackEnlistment (
    __in HANDLE EnlistmentHandle,
    __in_opt PLARGE_INTEGER TmVirtualClock
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwPrePrepareComplete (
    __in HANDLE            EnlistmentHandle,
    __in_opt PLARGE_INTEGER TmVirtualClock
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwPrepareComplete (
    __in HANDLE            EnlistmentHandle,
    __in_opt PLARGE_INTEGER TmVirtualClock
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwCommitComplete (
    __in HANDLE            EnlistmentHandle,
    __in_opt PLARGE_INTEGER TmVirtualClock
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwReadOnlyEnlistment (
    __in HANDLE            EnlistmentHandle,
    __in_opt PLARGE_INTEGER TmVirtualClock
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwRollbackComplete (
    __in HANDLE            EnlistmentHandle,
    __in_opt PLARGE_INTEGER TmVirtualClock
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwSinglePhaseReject (
    __in HANDLE            EnlistmentHandle,
    __in_opt PLARGE_INTEGER TmVirtualClock
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2003)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwOpenEvent (
    __out PHANDLE EventHandle,
    __in ACCESS_MASK DesiredAccess,
    __in POBJECT_ATTRIBUTES ObjectAttributes
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwQueryFullAttributesFile(
    __in POBJECT_ATTRIBUTES ObjectAttributes,
    __out PFILE_NETWORK_OPEN_INFORMATION FileInformation
    );
#endif



//
// Enum for state of a EM rule
//
typedef
enum {
    STATE_FALSE,
    STATE_UNKNOWN,
    STATE_TRUE
} EM_RULE_STATE, *PEM_RULE_STATE;

//
// Define the entry data structure
//

typedef struct _EM_ENTRY_DATA {
    PVOID Data;
    ULONG DataLength;
} EM_ENTRY_DATA, *PEM_ENTRY_DATA;

//
// Define the Callback function pointer declaration
//

__drv_functionClass(EM_CALLBACK_ROUTINE)
__drv_maxIRQL(APC_LEVEL)
__drv_sameIRQL
typedef
EM_RULE_STATE
(EM_CALLBACK_ROUTINE) (
    __in_ecount_opt(NumberofEntries) EM_ENTRY_DATA **InputEntries,
    __in ULONG NumberofEntries,
    __in_ecount_opt(NumberofStrings) LPCSTR *InputStrings,
    __in ULONG NumberofStrings,
    __in_ecount_opt(NumberofNumerics) PULONG InputNumerics,
    __in ULONG NumberofNumerics,
    __in_opt PVOID Context
    );

typedef EM_CALLBACK_ROUTINE *PEM_CALLBACK_ROUTINE;
typedef PEM_CALLBACK_ROUTINE EM_CALLBACK_FUNC;

//
// Define the lazy entry registration callback function
//

__drv_functionClass(EM_LAZYENTRY_CALLBACK_ROUTINE)
__drv_maxIRQL(APC_LEVEL)
__drv_sameIRQL
typedef
VOID
(EM_LAZYENTRY_CALLBACK_ROUTINE) (
    __in LPCGUID EntryGuid,
    __in_opt PVOID Context
    );

typedef EM_LAZYENTRY_CALLBACK_ROUTINE *PEM_LAZYENTRY_CALLBACK_ROUTINE;
typedef PEM_LAZYENTRY_CALLBACK_ROUTINE EM_LAZYENTRY_CALLBACK;


//
//  Define the Lazy Registration Structure
//

typedef struct _EM_ENTRY_REGISTRATION {
    LPCGUID EntryGuid;

    //
    // If LazyEntryCallback is provided, the Entry will be considered lazy
    //

    EM_LAZYENTRY_CALLBACK LazyEntryCallback;
    PVOID LazyCallbackContext;
} EM_ENTRY_REGISTRATION, *PEM_ENTRY_REGISTRATION;

//
// Define the Callback registration structure
//

typedef struct _EM_CALLBACK_REGISTRATION {
    LPCGUID CallbackGuid;
    EM_CALLBACK_FUNC CallbackFunction;
    PVOID Context;
} EM_CALLBACK_REGISTRATION, *PEM_CALLBACK_REGISTRATION;


//
// Define client rule notification function
//

__drv_functionClass(EM_RULE_STATE_NOTIFY_ROUTINE)
__drv_maxIRQL(APC_LEVEL)
__drv_sameIRQL
typedef
VOID
(EM_RULE_STATE_NOTIFY_ROUTINE) (
    __in EM_RULE_STATE State,
    __in LPCGUID RuleId,
    __in_opt PVOID Context
    );

typedef EM_RULE_STATE_NOTIFY_ROUTINE *PEM_RULE_STATE_NOTIFY_ROUTINE;
typedef PEM_RULE_STATE_NOTIFY_ROUTINE EM_RULE_STATE_NOTIFY;




//
// Define client rule notification registration structure
//

typedef struct _EM_CLIENT_NOTIFICATION_REGISTRATION {
    LPCGUID RuleId;
    EM_RULE_STATE_NOTIFY RuleNotifyCallback;
    PVOID Context;
} EM_CLIENT_NOTIFICATION_REGISTRATION, *PEM_CLIENT_NOTIFICATION_REGISTRATION;

//
// Em Provider APIs
//

__drv_maxIRQL(APC_LEVEL)
NTSTATUS
EmProviderRegister(
    __in PDRIVER_OBJECT DriverObject,
    __in_ecount_opt(NumberOfEntry) PEM_ENTRY_REGISTRATION EntryRegistration,
    __in ULONG NumberOfEntry,
    __in_ecount_opt(NumberOfCallback) PEM_CALLBACK_REGISTRATION CallbackRegistration,
    __in ULONG NumberOfCallback,
    __out PVOID *ProviderHandle
    );

__drv_maxIRQL(APC_LEVEL)
VOID
EmProviderDeregister(
    __in PVOID ProviderHandle
    );

__drv_maxIRQL(APC_LEVEL)
NTSTATUS
EmProviderRegisterEntry(
    __in PVOID ProviderHandle,
    __in LPCGUID EntryId,
    __in PEM_ENTRY_DATA EntryData,
    __out PVOID *EntryHandle
    );


__drv_maxIRQL(APC_LEVEL)
VOID
EmProviderDeregisterEntry(
    __in PVOID EntryHandle
    );

//
// Em Client APIs
//

__drv_maxIRQL(APC_LEVEL)
NTSTATUS
EmClientRuleEvaluate(
    __in LPCGUID RuleId,
    __in_ecount(NumberOfEntries) EM_ENTRY_DATA **InputEntries,
    __in ULONG NumberOfEntries,
    __out PEM_RULE_STATE State
    );

__drv_maxIRQL(APC_LEVEL)
NTSTATUS
EmClientRuleRegisterNotification(
    __in PDRIVER_OBJECT DriverObject,
    __in_ecount(NumberOfNotificatoinRegistration) PEM_CLIENT_NOTIFICATION_REGISTRATION RuleNotificationsRegistration,
    __in ULONG NumberOfNotificatoinRegistration,
    __out PVOID *NotificationHandle
    );

__drv_maxIRQL(APC_LEVEL)
VOID
EmClientRuleDeregisterNotification(
    __in PVOID NotificationHandle
    );

__drv_maxIRQL(APC_LEVEL)
NTSTATUS
EmClientQueryRuleState(
    __in LPCGUID RuleId,
    __out PEM_RULE_STATE State
    );

#ifndef _CLFS_PUBLIC_H_
#define _CLFS_PUBLIC_H_
#define CLFSUSER_API

#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)

//
// FILE_ATTRIBUTE_DEDICATED is defined as FILE_ATTRIBUTE_TEMPORARY.
//

#define FILE_ATTRIBUTE_DEDICATED    FILE_ATTRIBUTE_TEMPORARY

//
// Container name and container size extended attribute entry names.
//

#define EA_CONTAINER_NAME           "ContainerName"
#define EA_CONTAINER_SIZE           "ContainerSize"

//
// Base log file name 3-letter extension.
//

#define CLFS_BASELOG_EXTENSION      L".blf"

//
// Common log file system public flags and constants.
//

#define CLFS_FLAG_NO_FLAGS              0x00000000      // No flags.
#define CLFS_FLAG_FORCE_APPEND          0x00000001      // Flag to force an append to log queue
#define CLFS_FLAG_FORCE_FLUSH           0x00000002      // Flag to force a log flush
#define CLFS_FLAG_USE_RESERVATION       0x00000004      // Flag to charge a data append to reservation
#define CLFS_FLAG_REENTRANT_FILE_SYSTEM 0x00000008      // Kernel mode create flag indicating a re-entrant file system.
#define CLFS_FLAG_NON_REENTRANT_FILTER  0x00000010      // Kernel mode create flag indicating non-reentrant filter.
#define CLFS_FLAG_REENTRANT_FILTER      0x00000020      // Kernel mode create flag indicating reentrant filter.
#define CLFS_FLAG_IGNORE_SHARE_ACCESS   0x00000040      // Kernel mode create flag indicating IO_IGNORE_SHARE_ACCESS_CHECK semantics.
#define CLFS_FLAG_READ_IN_PROGRESS      0x00000080      // Flag indicating read in progress and not completed.
#define CLFS_FLAG_MINIFILTER_LEVEL      0x00000100      // Kernel mode create flag indicating mini-filter target.
#define CLFS_FLAG_HIDDEN_SYSTEM_LOG     0x00000200      // Kernel mode create flag indicating the log and containers should be marked hidden & system.


//
// Flag indicating all CLFS I/O will be targeted to an intermediate level of the I/O stack
//

#define CLFS_FLAG_FILTER_INTERMEDIATE_LEVEL CLFS_FLAG_NON_REENTRANT_FILTER
    
//
// Flag indicating all CLFS I/O will be targeted to the top level of the I/O stack
//

#define CLFS_FLAG_FILTER_TOP_LEVEL          CLFS_FLAG_REENTRANT_FILTER

//
// CLFS_CONTAINER_INDEX
//
// Index into the container table.
//

typedef ULONG                       CLFS_CONTAINER_ID;
typedef CLFS_CONTAINER_ID           *PCLFS_CONTAINER_ID;
typedef CLFS_CONTAINER_ID           **PPCLFS_CONTAINER_ID;

#endif /* NTDDI_VERSION || _WIN32_WINNT */

#ifdef __CLFS_PRIVATE_LSN__

#include <clfslsn.h>

#else

#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)

//
// CLS_LSN
//

typedef struct _CLS_LSN
{

    ULONGLONG               Internal;

} CLS_LSN, *PCLS_LSN, **PPCLS_LSN;

#endif /* NTDDI_VERSION || _WIN32_WINNT */

#endif /* __CLFS_PRIVATE_LSN__ */

#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)

//
// Alias CLS prefixed types with CLFS prefixes.
//

typedef CLS_LSN CLFS_LSN;
typedef CLFS_LSN *PCLFS_LSN, **PPCLFS_LSN;

#endif /* NTDDI_VERSION || _WIN32_WINNT */

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
extern __declspec(dllimport) const CLFS_LSN CLFS_LSN_INVALID;
extern __declspec(dllimport) const CLFS_LSN CLFS_LSN_NULL;
#endif /* NTDDI_VERSION || _WIN32_WINNT */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)

//
// CLS_RECORD_TYPE
//
// Definition of record types.
//

#ifdef __cplusplus

const UCHAR  ClfsNullRecord          =   0x00;           // Null record type.        
const UCHAR  ClfsDataRecord          =   0x01;           // Client data record.
const UCHAR  ClfsRestartRecord       =   0x02;           // Restart record.


// Valid client records are restart and data records.

const UCHAR  ClfsClientRecord        =   0x03; 

#else

#define ClfsNullRecord                  0x00            // Null record type.        
#define ClfsDataRecord                  0x01            // Client data record.
#define ClfsRestartRecord               0x02            // Restart record.


// Valid client records are restart and data records.

#define ClfsClientRecord (ClfsDataRecord|ClfsRestartRecord) 

#endif /* _cplusplus */

#endif /* NTDDI_VERSION || _WIN32_WINNT */

#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
//
// Log container path prefix indicating the log container's location is
// actually a stream inside of the BLF.
//

#ifdef _cplusplus

const LPCWSTR CLFS_CONTAINER_STREAM_PREFIX     = L"%BLF%:"

#else

#define CLFS_CONTAINER_STREAM_PREFIX             L"%BLF%:"

#endif /* _cplusplus */

#endif /* NTDDI_VERSION || _WIN32_WINNT */

#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
//
// Log container path prefix indicating the log container's location is
// relative to the base log file (BLF) and not an absolute path.
// Paths which do not being with said prefix are absolute paths.
//

#ifdef _cplusplus

const LPCWSTR CLFS_CONTAINER_RELATIVE_PREFIX    = L"%BLF%\\"

#else

#define CLFS_CONTAINER_RELATIVE_PREFIX            L"%BLF%\\"

#endif /* _cplusplus */

#endif /* NTDDI_VERSION || _WIN32_WINNT */

#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
//
// Alias CLS prefix with CLFS prefixes.
//

typedef UCHAR CLS_RECORD_TYPE, *PCLS_RECORD_TYPE, **PPCLS_RECORD_TYPE;
typedef CLS_RECORD_TYPE CLFS_RECORD_TYPE, *PCLFS_RECORD_TYPE, **PPCLFS_RECORD_TYPE;
#endif /* NTDDI_VERSION || _WIN32_WINNT */

#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
//
// CLS_CONTEXT_MODE
//
// The context mode specifies the dirction and access methods used to scan the
// log file. 
//

typedef enum _CLS_CONTEXT_MODE
{
    ClsContextNone = 0x00,
    ClsContextUndoNext,
    ClsContextPrevious,
    ClsContextForward

} CLS_CONTEXT_MODE, *PCLS_CONTEXT_MODE, **PPCLS_CONTEXT_MODE;
#endif /* NTDDI_VERSION || _WIN32_WINNT */

#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
//
// Alias all CLS prefixes with CLFS prefixes.
//

typedef enum _CLFS_CONTEXT_MODE
{
    ClfsContextNone = 0x00,
    ClfsContextUndoNext,
    ClfsContextPrevious,
    ClfsContextForward

} CLFS_CONTEXT_MODE, *PCLFS_CONTEXT_MODE, **PPCLFS_CONTEXT_MODE;
#endif /* NTDDI_VERSION || _WIN32_WINNT */


#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
//
// CLFSD_NODE_ID
//
// Common log file system node identifier.  Every CLFS file system
// structure has a node identity and type.  The node type is a signature
// field while the size is used in for consistency checking.
//

typedef struct _CLFS_NODE_ID
{
    ULONG   cType;                                      // CLFS node type.
    ULONG   cbNode;                                     // CLFS node size.

} CLFS_NODE_ID, *PCLFS_NODE_ID;
#endif /* NTDDI_VERSION || _WIN32_WINNT */


#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
//
//  CLS_WRITE_ENTRY
//
// Write entry specifying the contents of a user buffer and length that are
// marshalled in the space reservation and append interface of the CLS API.
//

typedef struct _CLS_WRITE_ENTRY
{
    PVOID Buffer;
    ULONG ByteLength;
} CLS_WRITE_ENTRY, *PCLS_WRITE_ENTRY, **PPCLS_WRITE_ENTRY;
#endif /* NTDDI_VERSION || _WIN32_WINNT */

#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
//
// Alias all CLS prefixes with CLFS prefixes.
//

typedef CLS_WRITE_ENTRY CLFS_WRITE_ENTRY;
typedef CLFS_WRITE_ENTRY *PCLFS_WRITE_ENTRY, **PPCLFS_WRITE_ENTRY;
#endif /* NTDDI_VERSION || _WIN32_WINNT */

#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
//
// CLFS_LOG_ID
// 
// A log identifier is a GUID that describes uniquely a physical log file.
//

typedef GUID CLFS_LOG_ID;
#endif /* NTDDI_VERSION || _WIN32_WINNT */

#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
//
// CLFS_INFORMATION
//
// Logical log file information structure describing either virtual or physical log
// file data, depending on the type of information queried.
//

typedef struct _CLS_INFORMATION
{
    LONGLONG TotalAvailable;                            // Total log data space available.
    LONGLONG CurrentAvailable;                          // Useable space in the log file.
    LONGLONG TotalReservation;                       // Space reserved for UNDO's (aggregate for physical log)
    ULONGLONG BaseFileSize;                             // Size of the base log file.
    ULONGLONG ContainerSize;                            // Uniform size of log containers.
    ULONG TotalContainers;                              // Total number of containers.
    ULONG FreeContainers;                               // Number of containers not in active log.
    ULONG TotalClients;                                 // Total number of clients.
    ULONG Attributes;                                   // Log file attributes.
    ULONG FlushThreshold;                               // Log file flush threshold.
    ULONG SectorSize;                                   // Underlying container sector size.
    CLS_LSN MinArchiveTailLsn;                          // Marks the global archive tail.
    CLS_LSN BaseLsn;                                    // Start of the active log region.
    CLS_LSN LastFlushedLsn;                             // Last flushed LSN in active log.
    CLS_LSN LastLsn;                                    // End of active log region.
    CLS_LSN RestartLsn;                                 // Location of restart record.
    GUID Identity;                                      // Unique identifier for the log.
} CLS_INFORMATION, *PCLS_INFORMATION, *PPCLS_INFORMATION;
#endif /* NTDDI_VERSION || _WIN32_WINNT */

#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
//
// Alias CLS prefixes with CLS prefixes.
//

typedef CLS_INFORMATION CLFS_INFORMATION;
typedef CLFS_INFORMATION *PCLFS_INFORMATION, *PPCLFS_INFORMATION;
#endif /* NTDDI_VERSION || _WIN32_WINNT */
/*
//
// CLFS_CLIENT_INFORMATION
// 
// The client information structure maintains client-based log metadata.
//

typedef struct _CLS_CLIENT_INFORMATION
{
    CLS_INFORMATION ClfsInfo;                           // Contains base log file information.
    ULONG ClientAttributes;                             // Virtual log file attributes.
    LONGLONG ClientUndoCommitment;                      // Max. undo commitment for client.
    CLS_LSN ClientArchiveTailLsn;                       // Marks the client archive tail.
    CLS_LSN ClientBaseLsn;                              // Min. client LSN in active log region.
    CLS_LSN ClientLastLsn;                              // Max. client LSN in active log region.
    CLS_LSN ClientRestartLsn;                           // Location of restart record.

} CLS_CLIENT_INFORMATION, *PCLS_CLIENT_INFORMATION, **PPCLS_CLIENT_INFORMATION;

//
// Alias CLS prefixes with CLS prefixes.
//

typedef CLS_CLIENT_INFORMATION CLFS_CLIENT_INFORMATION;
typedef CLFS_CLIENT_INFORMATION *PCLFS_CLIENT_INFORMATION, *PPCLFS_CLIENT_INFORMATION;
*/

#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
//
// CLFS_LOG_NAME_INFORMATION
// 
// The client information structure stores the name of a log.  It is used
// to communicate ClfsLogNameInformation and ClfsLogPhysicalNameInformation.
//

typedef struct _CLFS_LOG_NAME_INFORMATION
{

    USHORT NameLengthInBytes;
    WCHAR  Name[1];

} CLFS_LOG_NAME_INFORMATION, *PCLFS_LOG_NAME_INFORMATION, **PPCLFS_LOG_NAME_INFORMATION;
#endif /* NTDDI_VERSION || _WIN32_WINNT */

#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
//
// CLFS_STREAM_ID_INFORMATION
// 
// The client information structure provides a permanent identifier unique
// to the log for the stream in question.
//

typedef struct _CLFS_STREAM_ID_INFORMATION
{

    UCHAR StreamIdentifier;

} CLFS_STREAM_ID_INFORMATION, *PCLFS_STREAM_ID_INFORMATION, **PPCLFS_STREAM_ID_INFORMATION;
#endif /* NTDDI_VERSION || _WIN32_WINNT */

#if (NTDDI_VERSION >= NTDDI_VISTA) || (_WIN32_WINNT >= _WIN32_WINNT_LONGHORN)
//
// CLFS_PHYSICAL_LSN_INFORMATION
// 
// An information structure that describes a virtual:physical LSN pairing 
// for the stream identified in the structure.
//
#pragma pack(push,8)
typedef struct _CLFS_PHYSICAL_LSN_INFORMATION
{
    UCHAR          StreamIdentifier;
    CLFS_LSN       VirtualLsn;
    CLFS_LSN       PhysicalLsn;

} CLFS_PHYSICAL_LSN_INFORMATION, *PCLFS_PHYSICAL_LSN_INFORMATION;
#pragma pack(pop)
#endif /* NTDDI_VERSION || _WIN32_WINNT */

#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
//
// CLS_CONTAINER_STATE
//
// At any point in time a container could be inactive or unitialized, active,
// pending deletion from the list of free containers, pending archival, or 
// pending deletion while waiting to be archived.
//

typedef UINT32 CLS_CONTAINER_STATE, *PCLS_CONTAINER_STATE, *PPCLS_CONTAINER_STATE;
typedef CLS_CONTAINER_STATE  CLFS_CONTAINER_STATE, *PCLFS_CONTAINER_STATE, *PPCLFS_CONTAINER_STATE;
#endif /* NTDDI_VERSION || _WIN32_WINNT */

#ifdef __cplusplus

#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
const CLFS_CONTAINER_STATE  ClsContainerInitializing            = 0x01;
const CLFS_CONTAINER_STATE  ClsContainerInactive                = 0x02;
const CLFS_CONTAINER_STATE  ClsContainerActive                  = 0x04;
const CLFS_CONTAINER_STATE  ClsContainerActivePendingDelete     = 0x08;
const CLFS_CONTAINER_STATE  ClsContainerPendingArchive          = 0x10;
const CLFS_CONTAINER_STATE  ClsContainerPendingArchiveAndDelete = 0x20;

const CLFS_CONTAINER_STATE  ClfsContainerInitializing           = 0x01;
const CLFS_CONTAINER_STATE  ClfsContainerInactive               = 0x02;
const CLFS_CONTAINER_STATE  ClfsContainerActive                 = 0x04;
const CLFS_CONTAINER_STATE  ClfsContainerActivePendingDelete    = 0x08;
const CLFS_CONTAINER_STATE  ClfsContainerPendingArchive         = 0x10;
const CLFS_CONTAINER_STATE  ClfsContainerPendingArchiveAndDelete= 0x20;
#endif /* NTDDI_VERSION || _WIN32_WINNT */

#else

#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
#define ClsContainerInitializing                                  0x01
#define ClsContainerInactive                                      0x02
#define ClsContainerActive                                        0x04
#define ClsContainerActivePendingDelete                           0x08
#define ClsContainerPendingArchive                                0x10
#define ClsContainerPendingArchiveAndDelete                       0x20

#define ClfsContainerInitializing                                 0x01
#define ClfsContainerInactive                                     0x02
#define ClfsContainerActive                                       0x04
#define ClfsContainerActivePendingDelete                          0x08
#define ClfsContainerPendingArchive                               0x10
#define ClfsContainerPendingArchiveAndDelete                      0x20
#endif /* NTDDI_VERSION || _WIN32_WINNT */

#endif /* __cplusplus */

#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
//
// CLFS_MAX_CONTAINER_INFO
//
// The maximum length, in bytes, of the FileName field in the CLFS
// container information structure.
//

#ifdef __cplusplus

const ULONG CLFS_MAX_CONTAINER_INFO = (256);

#else

#define CLFS_MAX_CONTAINER_INFO       (256)

#endif /* __cplusplus */

#endif /* NTDDI_VERSION || _WIN32_WINNT */


#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
//
// CLS_CONTAINER_INFORMATION
//
// This structure defines a container descriptor.  The descriptor specifies the
// container's creation and access times, size, file system name, file system
// attributes, state, minimum, and maximum LSNs.
//

typedef struct _CLS_CONTAINER_INFORMATION
{
    ULONG FileAttributes;                    // File system attribute flag.
    ULONGLONG CreationTime;                  // File creation time.
    ULONGLONG LastAccessTime;                // Last time container was read/written.
    ULONGLONG LastWriteTime;                 // Last time container was written.
    LONGLONG ContainerSize;                  // Size of container in bytes.
    ULONG FileNameActualLength;              // Length of the actual file name.
    ULONG FileNameLength;                    // Length of file name in buffer
    WCHAR FileName [CLFS_MAX_CONTAINER_INFO];// File system name for container.
    CLFS_CONTAINER_STATE State;              // Current state of the container.
    CLFS_CONTAINER_ID PhysicalContainerId;   // Physical container identifier.
    CLFS_CONTAINER_ID LogicalContainerId;    // Logical container identifier.

} CLS_CONTAINER_INFORMATION, *PCLS_CONTAINER_INFORMATION, **PPCLS_CONTAINER_INFORMATION;

//
// Alias all CLS prefixes with CLFS prefixes.
//

typedef CLS_CONTAINER_INFORMATION CLFS_CONTAINER_INFORMATION;
typedef CLFS_CONTAINER_INFORMATION *PCLFS_CONTAINER_INFORMATION, **PPCLFS_CONTAINER_INFORMATION;
#endif /* NTDDI_VERSION || _WIN32_WINNT */


#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
//
// CLFS_LOG_INFORMATION_CLASS
//
// The information class specifies the kind of information a caller
// wishes to query or set on a log file.
//

typedef enum _CLS_LOG_INFORMATION_CLASS
{

    ClfsLogBasicInformation = 0x00,         // For virtual or physical logs, indicates the respective basic information.
    ClfsLogBasicInformationPhysical,        // Always indicates physical log basic information.
    ClfsLogPhysicalNameInformation,         // Always indicates physical name information.
    ClfsLogStreamIdentifierInformation,     // Virtual/physical log agnostic.
#if (NTDDI_VERSION >= NTDDI_VISTA) || (_WIN32_WINNT >= _WIN32_WINNT_LONGHORN)
    ClfsLogSystemMarkingInformation,        // Count of system marking references.
    ClfsLogPhysicalLsnInformation           // Maps virtual LSNs to physical LSNs; only valid for physical logs.
#endif /* NTDDI_VERSION || _WIN32_WINNT */

} CLS_LOG_INFORMATION_CLASS, *PCLS_LOG_INFORMATION_CLASS, **PPCLS_LOG_INFORMATION_CLASS;

//
// Alias all CLS prefixes with CLFS prefixes.
//

typedef CLS_LOG_INFORMATION_CLASS CLFS_LOG_INFORMATION_CLASS;
typedef CLFS_LOG_INFORMATION_CLASS *PCLFS_LOG_INFORMATION_CLASS, **PPCLFS_LOG_INFORMATION_CLASS;
#endif /* NTDDI_VERSION || _WIN32_WINNT */

#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
//
// CLS_IOSTATS_CLASS
//
// Enumerated type defining the class of I/O statistics.
//

typedef enum _CLS_IOSTATS_CLASS
{
    ClsIoStatsDefault = 0x0000,
    ClsIoStatsMax     = 0xFFFF

} CLS_IOSTATS_CLASS, *PCLS_IOSTATS_CLASS, **PPCLS_IOSTATS_CLASS;
#endif /* NTDDI_VERSION || _WIN32_WINNT */


#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
//
// CLFS_IOSTATS_CLASS
//
// Alias all CLS prefixes with CLFS prefixes.
//

typedef enum _CLFS_IOSTATS_CLASS
{
    ClfsIoStatsDefault = 0x0000,
    ClfsIoStatsMax     = 0xFFFF

} CLFS_IOSTATS_CLASS, *PCLFS_IOSTATS_CLASS, **PPCLFS_IOSTATS_CLASS;
#endif /* NTDDI_VERSION || _WIN32_WINNT */


#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
//
// CLS_IO_STATISTICS
//
// This structure defines I/O performance counters particular to a log file.  It consists
// of a header followed by the I/O statistics counters.  The header is being ignored for
// now.
//

typedef struct _CLS_IO_STATISTICS_HEADER
{
    UCHAR                ubMajorVersion;     // Major version of the statistics buffer.
    UCHAR                ubMinorVersion;     // Minor version of the statistics buffer.
    CLFS_IOSTATS_CLASS  eStatsClass;        // I/O statistics class.
    USHORT              cbLength;           // Length of the statistics buffer.                     
    ULONG               coffData;           // Offset of statistics counters.

} CLS_IO_STATISTICS_HEADER, *PCLS_IO_STATISTICS_HEADER, **PPCLS_IO_STATISTICS_HEADER;

//
// Alias all CLS prefixes with CLFS prefixes.
//

typedef CLS_IO_STATISTICS_HEADER CLFS_IO_STATISTICS_HEADER;
typedef CLFS_IO_STATISTICS_HEADER *PCLFS_IO_STATISTICS_HEADER, **PPCLFS_IO_STATISTICS_HEADER;
#endif /* NTDDI_VERSION || _WIN32_WINNT */


#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
typedef struct _CLS_IO_STATISTICS
{
    CLS_IO_STATISTICS_HEADER hdrIoStats;    // Statistics buffer header.
    ULONGLONG cFlush;                       // Flush count.
    ULONGLONG cbFlush;                      // Cumulative number of bytes flushed.
    ULONGLONG cMetaFlush;                   // Metadata flush count.
    ULONGLONG cbMetaFlush;                  // Cumulative number of metadata bytes flushed.

} CLS_IO_STATISTICS, *PCLS_IO_STATISTICS, **PPCLS_IO_STATISTICS;

//
// Alias all CLS prefixes with CLFS prefixes.
//

typedef CLS_IO_STATISTICS CLFS_IO_STATISTICS;
typedef CLFS_IO_STATISTICS *PCLFS_IO_STATISTICS, **PPCLFS_IO_STATISTICS;
#endif /* NTDDI_VERSION || _WIN32_WINNT */

#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
//
// CLFS_SCAN_MODE
//
// Container scan mode flags.
//

#ifdef __cplusplus

const   UCHAR CLFS_SCAN_INIT         =   0x01;
const   UCHAR CLFS_SCAN_FORWARD      =   0x02;
const   UCHAR CLFS_SCAN_BACKWARD     =   0x04;
const   UCHAR CLFS_SCAN_CLOSE        =   0x08;
const   UCHAR CLFS_SCAN_INITIALIZED  =   0x10;
const   UCHAR CLFS_SCAN_BUFFERED     =   0x20;

#else

#define CLFS_SCAN_INIT                  0x01
#define CLFS_SCAN_FORWARD               0x02
#define CLFS_SCAN_BACKWARD              0x04
#define CLFS_SCAN_CLOSE                 0x08
#define CLFS_SCAN_INITIALIZED           0x10
#define CLFS_SCAN_BUFFERED              0x20

#endif

typedef UCHAR CLFS_SCAN_MODE, *PCLFS_SCAN_MODE;
#endif /* NTDDI_VERSION || _WIN32_WINNT */


#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)

//
// CLFS_SCAN_CONTEXT
//
// Container scan context for scanning all containers in a given physical log
// file.
//

//
// The log file object wraps an NT file object and the size of the structure. 
// The log file object may be modified in the near future and there should be no
// dependencies on the size of the structure itself.
//

typedef FILE_OBJECT LOG_FILE_OBJECT, *PLOG_FILE_OBJECT, **PPLOG_FILE_OBJECT;

#if defined(_MSC_VER)
#if (_MSC_VER >= 1200)
#pragma warning(push)
#pragma warning(disable:4324) // structure padded due to __declspec(align())
#endif
#endif

typedef struct _CLS_SCAN_CONTEXT
{
    CLFS_NODE_ID cidNode;
    PLOG_FILE_OBJECT plfoLog;
    __declspec(align(8)) ULONG cIndex;
    __declspec(align(8)) ULONG cContainers;
    __declspec(align(8)) ULONG cContainersReturned;
    __declspec(align(8)) CLFS_SCAN_MODE eScanMode;
    __declspec(align(8)) PCLS_CONTAINER_INFORMATION pinfoContainer;
    
} CLS_SCAN_CONTEXT, *PCLS_SCAN_CONTEXT, **PPCLS_SCAN_CONTEXT;

#if defined(_MSC_VER)
#if (_MSC_VER >= 1200)
#pragma warning(pop)
#endif
#endif

#endif /* NTDDI_VERSION || _WIN32_WINNT */


#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
//
// Alias all CLS prefixes with CLFS prefixes.
//

typedef CLS_SCAN_CONTEXT CLFS_SCAN_CONTEXT;
typedef CLFS_SCAN_CONTEXT *PCLFS_SCAN_CONTEXT, **PPCLFS_SCAN_CONTEXT;
#endif /* NTDDI_VERSION || _WIN32_WINNT */

#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
//
// CLFS_ARCHIVE_DESCRIPTOR
//
// Log archive descriptors describe the set of discrete but logically
// contiguous disk extents comprising a snapshot of the active log when
// preparing for archival.  Log archive descriptors specify enough information
// for log archive clients directly access the relevant contents of containers
// for archiving and restoring a snapshot of the log.
//

typedef struct _CLS_ARCHIVE_DESCRIPTOR
{
    ULONGLONG coffLow;
    ULONGLONG coffHigh;
    CLS_CONTAINER_INFORMATION infoContainer;

} CLS_ARCHIVE_DESCRIPTOR, *PCLS_ARCHIVE_DESCRIPTOR, **PPCLS_ARCHIVE_DESCRIPTOR;

//
// Alias CLS prefixes with CLFS prefixes.
//

typedef CLS_ARCHIVE_DESCRIPTOR CLFS_ARCHIVE_DESCRIPTOR;
typedef CLFS_ARCHIVE_DESCRIPTOR *PCLFS_ARCHIVE_DESCRIPTOR, **PPCLFS_ARCHIVE_DESCRIPTOR;
#endif /* NTDDI_VERSION || _WIN32_WINNT */

#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
//
// CLFS_ALLOCATION_ROUTINE
//
// Allocate a blocks for marshalled reads or writes
//

typedef PVOID (* CLFS_BLOCK_ALLOCATION) (ULONG cbBufferLength, PVOID pvUserContext);

//
// CLFS_DEALLOCATION_ROUTINE
//
// Deallocate buffers allocated by the CLFS_ALLOCATION_ROUTINE.
//

typedef void (* CLFS_BLOCK_DEALLOCATION) (PVOID pvBuffer, PVOID pvUserContext);
#endif /* NTDDI_VERSION || _WIN32_WINNT */

#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
//
// CLFS_LOG_ARCHIVE_MODE
//
// Describes the archive support behavior for the log.
//

typedef enum _CLFS_LOG_ARCHIVE_MODE
{

    ClfsLogArchiveEnabled = 0x01,
    ClfsLogArchiveDisabled = 0x02

} CLFS_LOG_ARCHIVE_MODE, *PCLFS_LOG_ARCHIVE_MODE;
#endif /* NTDDI_VERSION || _WIN32_WINNT */


//-----------------------------------------------------------------------------
// LSN OPERATORS
//-----------------------------------------------------------------------------

#ifdef __cplusplus
extern "C"
{
#endif


#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
//-----------------------------------------------------------------------------
// ClfsLsnEqual
//
//      Method Description:
//
//          Check for the equivalence of LSNs.
//
//      Arguments:
//
//          plsn1   -- first LSN comparator
//          plsn2   -- second LSN comparator
//          
//
//      Return Value:
//
//          TRUE if LSN values are equivalent and FALSE otherwise.
//
//-----------------------------------------------------------------------------

CLFSUSER_API BOOLEAN NTAPI
ClfsLsnEqual
(
    __in const CLFS_LSN* plsn1,
    __in const CLFS_LSN* plsn2
);
#endif /* NTDDI_VERSION || _WIN32_WINNT */


#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
//-----------------------------------------------------------------------------
// ClfsLsnLess
//
//      Method Description:
//
//          Check if LSN1 is less than LSN2.
//
//      Arguments:
//
//          plsn1   -- first LSN comparator
//          plsn2   -- second LSN comparator
//          
//
//      Return Value:
//
//          TRUE if LSN1 is less than LSN2 and FALSE otherwise.
//
//-----------------------------------------------------------------------------

CLFSUSER_API BOOLEAN NTAPI
ClfsLsnLess
(
    __in const CLFS_LSN* plsn1,
    __in const CLFS_LSN* plsn2
);
#endif /* NTDDI_VERSION || _WIN32_WINNT */


#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
//-----------------------------------------------------------------------------
// ClfsLsnGreater
//
//      Method Description:
//
//          Check if LSN1 is  greater than LSN2.
//
//      Arguments:
//
//          plsn1   -- first LSN comparator
//          plsn2   -- second LSN comparator
//          
//
//      Return Value:
//
//          TRUE if LSN1 is greater than LSN2 and FALSE otherwise.
//
//-----------------------------------------------------------------------------

CLFSUSER_API BOOLEAN NTAPI
ClfsLsnGreater
(
    __in const CLFS_LSN* plsn1,
    __in const CLFS_LSN* plsn2
);
#endif /* NTDDI_VERSION || _WIN32_WINNT */


#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
//-----------------------------------------------------------------------------
// ClfsLsnNull (Inline)
//
//      Method Description:
//
//          Check whether or not an LSN is CLFS_LSN_NULL.
//
//      Arguments:
//
//          plsn    -- reference to LSN tested against the NULL value.
//          
//
//      Return Value:
//
//          TRUE if and only if an LSN is equivalent to CLFS_LSN_NULL.  
//          LSNs with the value CLFS_LSN_INVALID will return FALSE.
//
//-----------------------------------------------------------------------------

CLFSUSER_API BOOLEAN NTAPI
ClfsLsnNull
(
    __in const CLFS_LSN* plsn
);
#endif /* NTDDI_VERSION || _WIN32_WINNT */


#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
//-----------------------------------------------------------------------------
// ClfsLsnContainer (Inline)
//
//      Routine Description:
//
//      Extract the container identifier from the LSN.
//
//      Arguments:
//
//          plsn -- get block offset from this LSN
//
//      Return Value:
//
//          Returns the container identifier for the LSN.
//
//-----------------------------------------------------------------------------

CLFSUSER_API CLFS_CONTAINER_ID NTAPI
ClfsLsnContainer
(
  __in const CLFS_LSN* plsn
);
#endif /* NTDDI_VERSION || _WIN32_WINNT */


#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
//-----------------------------------------------------------------------------
// ClfsLsnCreate (Inline)
//
//      Routine Description:
//
//      Create an LSN given a log identifier, a container identifier, a block
//      offset and a bucket identifier.  Caller must test for invalid LSN after
//      making this call.
//
//      Arguments:
//
//          cidContainer    -- container identifier
//          offBlock        -- block offset
//          cRecord         -- ordinal number of the record in block
//
//      Return Value:
//
//          Returns a valid LSN if successful, otherwise it returns
//          CLFS_LSN_INVALID
//
//-----------------------------------------------------------------------------

CLFSUSER_API CLFS_LSN NTAPI
ClfsLsnCreate
(
    __in CLFS_CONTAINER_ID    cidContainer,
    __in ULONG                offBlock,
    __in ULONG                cRecord
);
#endif /* NTDDI_VERSION || _WIN32_WINNT */


#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
//-----------------------------------------------------------------------------
// ClfsLsnBlockOffset (Inline)
//
//      Routine Description:
//
//      Extract the block offset from the LSN.
//
//      Arguments:
//
//          plsn -- get block offset from this LSN
//
//      Return Value:
//
//          Returns the block offset for the LSN.
//
//-----------------------------------------------------------------------------

CLFSUSER_API ULONG NTAPI
ClfsLsnBlockOffset
(
  __in const CLFS_LSN* plsn
);
#endif /* NTDDI_VERSION || _WIN32_WINNT */


#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
//-----------------------------------------------------------------------------
// ClfsLsnRecordSequence (Inline)
//
//      Routine Description:
//
//          Extract the bucket identifier from the LSN.
//
//      Arguments:
//
//          plsn    -- get block offset from this LSN
//
//      Return Value:
//
//          Returns the bucket identifier for the LSN.
//
//-----------------------------------------------------------------------------

CLFSUSER_API ULONG NTAPI
ClfsLsnRecordSequence
(
    __in const CLFS_LSN* plsn
);
#endif /* NTDDI_VERSION || _WIN32_WINNT */


#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
//-----------------------------------------------------------------------------
// ClfsLsnInvalid
//
//      Method Description:
//
//          Check whether or not an LSN is CLFS_LSN_INVALID.
//
//      Arguments:
//
//          plsn    -- reference to LSN tested against CLFS_LSN_INVALID.
//          
//
//      Return Value:
//
//          TRUE if and only if an LSN is equivalent to CLFS_LSN_INVALID.  
//          LSNs with the value CLFS_LSN_NULL will return FALSE.
//
//-----------------------------------------------------------------------------

CLFSUSER_API BOOLEAN NTAPI
ClfsLsnInvalid
(
    __in const CLFS_LSN* plsn
);
#endif /* NTDDI_VERSION || _WIN32_WINNT */


#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
//-----------------------------------------------------------------------------
// ClfsLsnIncrement
//
//      Method Description:
//
//          Increment and LSN by 1
//
//      Arguments:
//
//          plsn -- LSN to be incremented.
//          
//
//      Return Value:
//
//          A valid LSN next in sequence to the input LSN, if successful.
//          Otherwise, this function returns CLFS_LSN_INVALID.
//
//-----------------------------------------------------------------------------

CLFSUSER_API CLFS_LSN NTAPI
ClfsLsnIncrement (__in PCLFS_LSN  plsn);
#endif /* NTDDI_VERSION || _WIN32_WINNT */


#ifdef __cplusplus
}
#endif

#ifdef __cplusplus

#ifdef CLFS_OPERATORS

#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
//
// LSN arithmetic increment operator.
//

inline CLFS_LSN
operator++
(
    __inout CLFS_LSN& refLsn
)
{
    //
    // Prefix increment operator.
    //

    refLsn = ClfsLsnIncrement (&refLsn);
    return refLsn;
}
#endif /* NTDDI_VERSION || _WIN32_WINNT */

#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
//
// BOOLEAN LSN operators.
//

inline BOOLEAN      
operator<
(
    __in const CLFS_LSN& refLsn1, 
    __in const CLFS_LSN& refLsn2
)
{
    return (ClfsLsnLess ((PCLFS_LSN) &refLsn1, (PCLFS_LSN) &refLsn2));
}
#endif /* NTDDI_VERSION || _WIN32_WINNT */

#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
inline BOOLEAN  
operator>
(
    __in const CLFS_LSN& refLsn1, 
    __in const CLFS_LSN& refLsn2
)
{
    return (ClfsLsnGreater ((PCLFS_LSN) &refLsn1, (PCLFS_LSN) &refLsn2));
}
#endif /* NTDDI_VERSION || _WIN32_WINNT */

#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
inline BOOLEAN  
operator==
(
    __in const CLFS_LSN& refLsn1, 
    __in const CLFS_LSN& refLsn2
)
{
    return (ClfsLsnEqual ((PCLFS_LSN) &refLsn1, (PCLFS_LSN) &refLsn2));
}
#endif /* NTDDI_VERSION || _WIN32_WINNT */

#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
inline BOOLEAN
operator!=
(
    __in const CLFS_LSN& refLsn1,
    __in const CLFS_LSN& refLsn2
)
{
    return (!ClfsLsnEqual ((PCLFS_LSN) &refLsn1, (PCLFS_LSN) &refLsn2));
}
#endif /* NTDDI_VERSION || _WIN32_WINNT */

#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
inline BOOLEAN      
operator<=
(
    __in const CLFS_LSN& refLsn1, 
    __in const CLFS_LSN& refLsn2
)
{
    return (!ClfsLsnGreater ((PCLFS_LSN) &refLsn1, (PCLFS_LSN) &refLsn2));
}
#endif /* NTDDI_VERSION || _WIN32_WINNT */

#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
inline BOOLEAN  
operator>=
(
    __in const CLFS_LSN& refLsn1, 
    __in const CLFS_LSN& refLsn2
)
{
    return (!ClfsLsnLess ((PCLFS_LSN) &refLsn1, (PCLFS_LSN) &refLsn2));
}
#endif /* NTDDI_VERSION || _WIN32_WINNT */

#endif /* CLFS_OPERATORS */

#endif /* __cplusplus */

#endif /* _CLFS_PUBLIC_H_ */

#ifdef __cplusplus
extern "C" {
#endif

#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
//
// We start with the information that is shared
// between user and kernel mode.
//

typedef enum _CLFS_MGMT_POLICY_TYPE {

    ClfsMgmtPolicyMaximumSize = 0x0,
    ClfsMgmtPolicyMinimumSize,
    ClfsMgmtPolicyNewContainerSize,
    ClfsMgmtPolicyGrowthRate,
    ClfsMgmtPolicyLogTail,
    ClfsMgmtPolicyAutoShrink,
    ClfsMgmtPolicyAutoGrow,
    ClfsMgmtPolicyNewContainerPrefix,
    ClfsMgmtPolicyNewContainerSuffix,
    ClfsMgmtPolicyNewContainerExtension,

    ClfsMgmtPolicyInvalid

} CLFS_MGMT_POLICY_TYPE, *PCLFS_MGMT_POLICY_TYPE;
#endif /* NTDDI_VERSION || _WIN32_WINNT */

#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
#define CLFS_MGMT_NUM_POLICIES ((ULONG)ClfsMgmtPolicyInvalid)
#endif /* NTDDI_VERSION || _WIN32_WINNT */


#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
//
// Relative sizes used when explicitly setting log size.
//
#define CLFS_LOG_SIZE_MINIMUM ((ULONGLONG)(0))
#define CLFS_LOG_SIZE_MAXIMUM ((ULONGLONG)(-1))
#endif /* NTDDI_VERSION || _WIN32_WINNT */


#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
//
// The version of a given policy structure.  See CLFS_MGMT_POLICY.
//
#define CLFS_MGMT_POLICY_VERSION (0x01)
#endif /* NTDDI_VERSION || _WIN32_WINNT */


#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
//
// Log policy flags.
//
// LOG_POLICY_OVERWRITE: If set when adding a log policy, the previous
//                       policy of given type will be replaced.
//
// LOG_POLICY_PERSIST:   If set when adding a log policy, the policy
//                       will be persisted with the log metadata.
//
#define LOG_POLICY_OVERWRITE   (0x01)
#define LOG_POLICY_PERSIST     (0x02)
#endif /* NTDDI_VERSION || _WIN32_WINNT */


#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
//
// CLFS_MGMT_POLICY
//
// This structure describes one particular policy that
// may be present on a log file.  These are installed
// via InstallLogPolicy (Win32) or ClfsMgmtInstallPolicy (kernel).
//
typedef struct _CLFS_MGMT_POLICY {

    //
    // Version of the structure.  Should be CLFS_MGMT_POLICY_VERSION.
    //
    ULONG                   Version;

    //
    // The entire length of the structure.
    //
    ULONG                   LengthInBytes;

    //
    // Flags which apply to all policies, such as LOG_POLICY_OVERWRITE
    // and LOG_POLICY_PERSIST.
    //
    ULONG                   PolicyFlags;

    //
    // Determines how PolicyParameters union is interpreted.
    //
    CLFS_MGMT_POLICY_TYPE   PolicyType;

    //
    // The way to interpret the PolicyParameters union is
    // determined by the value of PolicyType -- if it is
    // ClfsMgmtPolicyMaximumSize, for instance, then the
    // MaximumSize structure is the relevant one.
    //

    union {

        struct {
            ULONG       Containers;
        } MaximumSize;

        struct {
            ULONG       Containers;
        } MinimumSize;

        struct {
            ULONG       SizeInBytes;
        } NewContainerSize;

        struct {
            ULONG       AbsoluteGrowthInContainers;
            ULONG       RelativeGrowthPercentage;
        } GrowthRate;

        struct {
            ULONG       MinimumAvailablePercentage;
            ULONG       MinimumAvailableContainers;
        } LogTail;

        struct {
            ULONG       Percentage;
        } AutoShrink;

        struct {
            ULONG       Enabled;
        } AutoGrow;

        struct {
            USHORT      PrefixLengthInBytes;
            WCHAR       PrefixString[1]; // dynamic in length depending on PrefixLength
        } NewContainerPrefix;

        struct {
            ULONGLONG   NextContainerSuffix;
        } NewContainerSuffix;

        struct {
            USHORT      ExtensionLengthInBytes;
            WCHAR       ExtensionString[1]; // dynamic in length depending on ExtensionLengthInBytes
        } NewContainerExtension;

    } PolicyParameters;

    //
    // Nothing will be added down here since the structure above
    // can be of dynamic length.
    //

} CLFS_MGMT_POLICY, *PCLFS_MGMT_POLICY;
#endif /* NTDDI_VERSION || _WIN32_WINNT */


#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
//
// CLFS_MGMT_NOTIFICATION_TYPE
// 
// The types of notifications given to either the callback proxy
// or to readers of notifications.
//

typedef enum _CLFS_MGMT_NOTIFICATION_TYPE
{

    //
    // Notification to advance base LSN.
    //

    ClfsMgmtAdvanceTailNotification = 0,

    //
    // Notification that a request to handle log full condition
    // has completed.
    //

    ClfsMgmtLogFullHandlerNotification,

    //
    // Notification that a previously pinned log is now considered
    // unpinned.
    //

    ClfsMgmtLogUnpinnedNotification,

    //
    // Notification that a non-zero number of bytes has been written
    // to the log.
    //

    ClfsMgmtLogWriteNotification

} CLFS_MGMT_NOTIFICATION_TYPE, *PCLFS_MGMT_NOTIFICATION_TYPE;
#endif /* NTDDI_VERSION || _WIN32_WINNT */


#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
//
// CLFS_MGMT_NOTIFICATION
//
// A notification and associated parameters.
//

typedef struct _CLFS_MGMT_NOTIFICATION
{

    //
    // Nature of the notification.
    //

    CLFS_MGMT_NOTIFICATION_TYPE     Notification;
    
    //
    // Target LSN for base LSN advancement if the
    // notification type is ClfsMgmtAdvanceTailNotification.
    //

    CLFS_LSN                        Lsn;

    //
    // TRUE if the log is pinned, FALSE otherwise.
    // Especially meaningful when receiving an error
    // status for ClfsMgmtLogFullHandlerNotification.
    //

    USHORT                          LogIsPinned;

} CLFS_MGMT_NOTIFICATION, *PCLFS_MGMT_NOTIFICATION;
#endif /* NTDDI_VERSION || _WIN32_WINNT */


//
// Kernel interface described below.
//


#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
//
// The advance tail callback is required when log clients 
// register for management.  It is invoked whenever the 
// management library decides that this client needs to 
// advance the tail of its log. Only minimal processing is 
// allowed.
//
typedef
NTSTATUS
(*PCLFS_CLIENT_ADVANCE_TAIL_CALLBACK) (
    __in PLOG_FILE_OBJECT LogFile,
    __in PCLFS_LSN TargetLsn,
    __in PVOID ClientData
    );
#endif /* NTDDI_VERSION || _WIN32_WINNT */

#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
//
// The log file full handler complete callback is invoked upon
// completion of a log growth request (that is, via a call 
// to ClfsMgmtHandleLogFileFull).
//
typedef
VOID
(*PCLFS_CLIENT_LFF_HANDLER_COMPLETE_CALLBACK) (
    __in PLOG_FILE_OBJECT LogFile,
    __in NTSTATUS OperationStatus,
    __in BOOLEAN LogIsPinned,
    __in PVOID ClientData
    );
#endif /* NTDDI_VERSION || _WIN32_WINNT */

#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
//
// The log pinned callback is invoked when log space is freed up
// after a log file full handler completion callback indicates an 
// NT_ERROR status code and LogIsPinned = TRUE.
//

typedef
VOID
(*PCLFS_CLIENT_LOG_UNPINNED_CALLBACK) (
    __in PLOG_FILE_OBJECT LogFile,
    __in PVOID ClientData
    );
#endif /* NTDDI_VERSION || _WIN32_WINNT */


#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
//
// The log size complete callback is invoked whenever
// ClfsMgmtSetLogFileSize operation which returned
// STATUS_PENDING is completed.
//

typedef
VOID
(*PCLFS_SET_LOG_SIZE_COMPLETE_CALLBACK) (
    __in PLOG_FILE_OBJECT LogFile,
    __in NTSTATUS OperationStatus,
    __in PVOID ClientData
    );
#endif /* NTDDI_VERSION || _WIN32_WINNT */


#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
//
// CLFS_MGMT_CLIENT_REGISTRATION
//
// This structure is given to the CLFS management infrastructure
// by clients who wish to be managed (via ClfsMgmtRegisterManagedClient).
// The CLFS_MGMT_CLIENT_REGISTRATION_VERSION value must be stored
// in the 'Version' field of the structure.
//

#define CLFS_MGMT_CLIENT_REGISTRATION_VERSION (0x1)

typedef struct _CLFS_MGMT_CLIENT_REGISTRATION {

    //
    // Initialize Version to CLFS_MGMT_CLIENT_REGISTRATION_VERSION.
    //

    ULONG   Version;  

    PCLFS_CLIENT_ADVANCE_TAIL_CALLBACK AdvanceTailCallback;
    PVOID                              AdvanceTailCallbackData;

    PCLFS_CLIENT_LFF_HANDLER_COMPLETE_CALLBACK LogGrowthCompleteCallback;
    PVOID                                      LogGrowthCompleteCallbackData;

    PCLFS_CLIENT_LOG_UNPINNED_CALLBACK LogUnpinnedCallback;
    PVOID                              LogUnpinnedCallbackData;

} CLFS_MGMT_CLIENT_REGISTRATION, *PCLFS_MGMT_CLIENT_REGISTRATION;
#endif /* NTDDI_VERSION || _WIN32_WINNT */


#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
//
// CLFS_MGMT_CLIENT
//
// This is the cookie that clients are given when registering and
// must give back to the management infrastructure whenever 
// performing an operation.
//
typedef PVOID CLFS_MGMT_CLIENT, *PCLFS_MGMT_CLIENT;
#endif /* NTDDI_VERSION || _WIN32_WINNT */


#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
NTSTATUS
ClfsMgmtRegisterManagedClient(
    __in PLOG_FILE_OBJECT LogFile,
    __in PCLFS_MGMT_CLIENT_REGISTRATION RegistrationData,
    __out PCLFS_MGMT_CLIENT ClientCookie
    );
#endif /* NTDDI_VERSION || _WIN32_WINNT */

#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
NTSTATUS
ClfsMgmtDeregisterManagedClient(
    __in CLFS_MGMT_CLIENT ClientCookie
    );
#endif /* NTDDI_VERSION || _WIN32_WINNT */

#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
NTSTATUS
ClfsMgmtTailAdvanceFailure(
    __in CLFS_MGMT_CLIENT Client,
    __in NTSTATUS Reason
    );
#endif /* NTDDI_VERSION || _WIN32_WINNT */

#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
NTSTATUS
ClfsMgmtHandleLogFileFull(
    __in CLFS_MGMT_CLIENT Client
    );
#endif /* NTDDI_VERSION || _WIN32_WINNT */

#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
NTSTATUS
ClfsMgmtInstallPolicy(
    __in PLOG_FILE_OBJECT  LogFile,
    __in_bcount(PolicyLength) PCLFS_MGMT_POLICY Policy,
    __in ULONG PolicyLength
    );
#endif /* NTDDI_VERSION || _WIN32_WINNT */

#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
NTSTATUS
ClfsMgmtQueryPolicy(
    __in PLOG_FILE_OBJECT LogFile,
    __in CLFS_MGMT_POLICY_TYPE PolicyType,
    __out_bcount(*PolicyLength) PCLFS_MGMT_POLICY Policy,
    __out PULONG PolicyLength
    );
#endif /* NTDDI_VERSION || _WIN32_WINNT */

#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
NTSTATUS
ClfsMgmtRemovePolicy(
    __in PLOG_FILE_OBJECT LogFile,
    __in CLFS_MGMT_POLICY_TYPE PolicyType
    );
#endif /* NTDDI_VERSION || _WIN32_WINNT */

#if (NTDDI_VERSION >= NTDDI_WS03SP1) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
NTSTATUS
ClfsMgmtSetLogFileSize(
    __in PLOG_FILE_OBJECT LogFile,
    __in PULONGLONG NewSizeInContainers,
    __out_opt PULONGLONG ResultingSizeInContainers,
    __in_opt PCLFS_SET_LOG_SIZE_COMPLETE_CALLBACK CompletionRoutine,
    __in_opt PVOID CompletionRoutineData
    );
#endif /* NTDDI_VERSION || _WIN32_WINNT */


#if (NTDDI_VERSION >= NTDDI_VISTA) || (_WIN32_WINNT >= _WIN32_WINNT_LONGHORN)
NTSTATUS
ClfsMgmtSetLogFileSizeAsClient(
    __in PLOG_FILE_OBJECT LogFile,
    __in_opt PCLFS_MGMT_CLIENT ClientCookie,
    __in PULONGLONG NewSizeInContainers,
    __out_opt PULONGLONG ResultingSizeInContainers,
    __in_opt PCLFS_SET_LOG_SIZE_COMPLETE_CALLBACK CompletionRoutine,
    __in_opt PVOID CompletionRoutineData
    );
#endif /* NTDDI_VERSION || _WIN32_WINNT */


#ifdef __cplusplus
} // extern "C"
#endif

#ifndef __CLFSPROC_H__
#define __CLFSPROC_H__

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
//------------------------------------------------------------------------------
// ClfsInitialize
//
// Utility to initialize CLFS global resources, lookaside lists, and memory.
//------------------------------------------------------------------------------

NTSTATUS ClfsInitialize (void);
#endif /* NTDDI_VERSION */

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
//------------------------------------------------------------------------------
// ClfsFinalize
//
// Utility to cleanup CLFS global resources, lookaside lists, and memory.
//------------------------------------------------------------------------------

void ClfsFinalize (void);
#endif /* NTDDI_VERSION */


#if (NTDDI_VERSION >= NTDDI_WS03SP1)
//------------------------------------------------------------------------------
// ClfsCreateLogFile
//
// Entry point to create a physical log file consisting of uniformly sized
// containers lying in a given directory path.
//------------------------------------------------------------------------------

NTSTATUS ClfsCreateLogFile (
                    __out PPLOG_FILE_OBJECT pplfoLog,
                    __in PUNICODE_STRING puszLogFileName,
                    __in ACCESS_MASK fDesiredAccess,
                    __in ULONG dwShareMode,
                    __in_opt PSECURITY_DESCRIPTOR psdLogFile,
                    __in ULONG fCreateDisposition,
                    __in ULONG fCreateOptions,
                    __in ULONG fFlagsAndAttributes,
                    __in ULONG fLogOptionFlag,
                    __in_bcount_opt(cbContext) PVOID pvContext,
                    __in ULONG cbContext
                    );
#endif /* NTDDI_VERSION */

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
//------------------------------------------------------------------------------
// ClfsDeleteLogByPointer
//
// Entry point to delete a physical log file and its underlying container
// storage referencing a log file object.
//------------------------------------------------------------------------------

NTSTATUS ClfsDeleteLogByPointer (__in PLOG_FILE_OBJECT plfoLog);
#endif /* NTDDI_VERSION */

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
//------------------------------------------------------------------------------
// ClfsDeleteLogFile
//
// Entry point to delete a physical log file and its underlying container
// storage by name.
//------------------------------------------------------------------------------

NTSTATUS ClfsDeleteLogFile (
                    __in PUNICODE_STRING puszLogFileName,
                    __in_opt PVOID pvReserved,
                    __in ULONG fLogOptionFlag,
                    __in_bcount_opt(cbContext) PVOID pvContext,
                    __in ULONG cbContext
                    );
#endif /* NTDDI_VERSION */

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
//------------------------------------------------------------------------------
// ClfsAddLogContainer
//
// Adds a log container to a given physical file identified by the log
// file object pointer.
//------------------------------------------------------------------------------

NTSTATUS ClfsAddLogContainer (
                    __in PLOG_FILE_OBJECT plfoLog,
                    __in PULONGLONG pcbContainer,
                    __in PUNICODE_STRING puszContainerPath
                    );
#endif /* NTDDI_VERSION */

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
//------------------------------------------------------------------------------
// ClfsAddLogContainerSet
//
// Adds a set of log containers to a given physical file identified by the log
// file object pointer.
//------------------------------------------------------------------------------

NTSTATUS ClfsAddLogContainerSet (
                    __in PLOG_FILE_OBJECT plfoLog,
                    __in USHORT cContainers,
                    __in_opt PULONGLONG pcbContainer,
                    __in_ecount(cContainers) PUNICODE_STRING rguszContainerPath
                    );
#endif /* NTDDI_VERSION */

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
//------------------------------------------------------------------------------
// ClfsRemoveLogContainer
//
// Removes a log container from a physical log file identified by
// the log file object pointer.
//------------------------------------------------------------------------------

NTSTATUS ClfsRemoveLogContainer (
                    __in PLOG_FILE_OBJECT plfoLog,
                    __in PUNICODE_STRING puszContainerPath,
                    __in BOOLEAN fForce
                    );
#endif /* NTDDI_VERSION */

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
//------------------------------------------------------------------------------
// ClfsRemoveLogContainerSet
//
// Removes a set of log containers from a physical log file identified by
// the log file object pointer.
//------------------------------------------------------------------------------

NTSTATUS ClfsRemoveLogContainerSet (
                    __in PLOG_FILE_OBJECT plfoLog,
                    __in USHORT cContainers,
                    __in_ecount(cContainers) PUNICODE_STRING rgwszContainerPath,
                    __in BOOLEAN fForce
                    );
#endif /* NTDDI_VERSION */

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
//------------------------------------------------------------------------------
// ClfsSetArchiveTail
//
// Sets the archive tail for either a client or physical log file
// depending on the type of the log handle.
//------------------------------------------------------------------------------

NTSTATUS ClfsSetArchiveTail (
                    __in PLOG_FILE_OBJECT plfoLog,
                    __in PCLFS_LSN plsnArchiveTail
                    );
#endif /* NTDDI_VERSION */

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
//------------------------------------------------------------------------------
// ClfsSetEndOfLog
//
// Sets the end of log for either a client or physical log file
// depending on the type of the log handle.
//------------------------------------------------------------------------------

NTSTATUS ClfsSetEndOfLog (
                    __in PLOG_FILE_OBJECT plfoLog,
                    __in PCLFS_LSN plsnEnd
                    );
#endif /* NTDDI_VERSION */

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
//------------------------------------------------------------------------------
// ClfsCreateScanContext
//
// Create a scan context to enumerate scan descriptors for storage containers 
// that back the physical log file object.
//------------------------------------------------------------------------------

NTSTATUS ClfsCreateScanContext (
                    __in PLOG_FILE_OBJECT plfoLog,
                    __in ULONG cFromContainer,
                    __in ULONG cContainers,
                    __in CLFS_SCAN_MODE eScanMode,
                    __inout PCLFS_SCAN_CONTEXT pcxScan
                    );
#endif /* NTDDI_VERSION */

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
//------------------------------------------------------------------------------
// ClfsScanLogContainers
//
// Scan descriptors for storage containers backing the physical
// log file stream.
//------------------------------------------------------------------------------

NTSTATUS ClfsScanLogContainers (
                    __inout PCLFS_SCAN_CONTEXT pcxScan,
                    __in CLFS_SCAN_MODE eScanMode
                    );
#endif /* NTDDI_VERSION */

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
//------------------------------------------------------------------------------
// ClfsGetContainerName
//
// ClfsGetContainerName gets the full path name of a container given its logical
// container identifier.
//
//------------------------------------------------------------------------------

NTSTATUS ClfsGetContainerName (
                    __in PLOG_FILE_OBJECT plfoLog,
                    __in CLFS_CONTAINER_ID cidLogicalContainer,
                    __out PUNICODE_STRING puszContainerName,
                    __out_opt PULONG pcActualLenContainerName
                    );
#endif /* NTDDI_VERSION */

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
//------------------------------------------------------------------------------
// ClfsGetLogFileInformation
//
// Get log file information for a physical log and client stream
// specific to the log file object pointer.
//
// Deprecated.  Use ClfsQueryLogFileInformation instead (it is equivalent
// to this call if ClfsLogBasicInformation is used as information class).
//
//------------------------------------------------------------------------------

NTSTATUS ClfsGetLogFileInformation (
                    __in PLOG_FILE_OBJECT plfoLog,
                    __out_bcount_part(*pcbInfoBuffer, *pcbInfoBuffer) PCLFS_INFORMATION pinfoBuffer,
                    __inout PULONG pcbInfoBuffer
                    );
#endif /* NTDDI_VERSION */

#if (NTDDI_VERSION >= NTDDI_VISTA)
//------------------------------------------------------------------------------
// ClfsQueryLogFileInformation
//
// Get log file information for a physical log and client stream
// specific to the log file object pointer.
//------------------------------------------------------------------------------

NTSTATUS ClfsQueryLogFileInformation (
                    __in PLOG_FILE_OBJECT plfoLog,
                    __in CLFS_LOG_INFORMATION_CLASS eInformationClass,
                    __in_bcount_opt(cbinfoInputBuffer) PVOID pinfoInputBuffer,
                    __in_opt ULONG cbinfoInputBuffer,
                    __out_bcount(*pcbInfoBuffer) PVOID pinfoBuffer,
                    __inout PULONG pcbInfoBuffer
                    );
#endif /* NTDDI_VERSION */

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
//------------------------------------------------------------------------------
// ClfsSetLogFileInformation
//
// Sets log file information for a physical log and client stream
// specific to the log file object pointer.
//------------------------------------------------------------------------------

NTSTATUS ClfsSetLogFileInformation (
                    __in PLOG_FILE_OBJECT plfoLog,
                    __in CLFS_LOG_INFORMATION_CLASS eInformationClass,
                    __in_bcount(cbBuffer) PVOID pinfoBuffer,
                    __in ULONG cbBuffer
                    );
#endif /* NTDDI_VERSION */

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
//------------------------------------------------------------------------------
// ClfsReadRestartArea
//
// Read the last restart area successfully written to a physical or 
// client log stream given a marshalling context.
//------------------------------------------------------------------------------

NTSTATUS ClfsReadRestartArea (
                    __inout PVOID pvMarshalContext,
                    __deref_out_bcount(*pcbRestartBuffer) PVOID *ppvRestartBuffer,
                    __out PULONG pcbRestartBuffer,
                    __out PCLFS_LSN plsn,
                    __deref_out PVOID *ppvReadContext
                    );
#endif /* NTDDI_VERSION */

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
//------------------------------------------------------------------------------
// ClfsReadPreviousRestartArea
//
// Read the previous restart area successfully written to a physical or 
// client log stream given the read context created by the a call to
// ClfsReadRestartArea.
//------------------------------------------------------------------------------

NTSTATUS ClfsReadPreviousRestartArea (
                    __in PVOID pvReadContext,
                    __deref_out_bcount(*pcbRestartBuffer) PVOID *ppvRestartBuffer,
                    __out PULONG pcbRestartBuffer,
                    __out PCLFS_LSN plsnRestart
                    );
#endif /* NTDDI_VERSION */

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
//------------------------------------------------------------------------------
// ClfsWriteRestartArea
//
// Write a new restart area to a physical or client log stream given a
// a marshalling context.
//------------------------------------------------------------------------------

NTSTATUS ClfsWriteRestartArea (
                    __inout PVOID pvMarshalContext,
                    __in_bcount(cbRestartBuffer) PVOID pvRestartBuffer,
                    __in ULONG cbRestartBuffer,
                    __in_opt PCLFS_LSN plsnBase,
                    __in ULONG fFlags,
                    __out_opt PULONG pcbWritten,
                    __out_opt PCLFS_LSN plsnNext
                    );
#endif /* NTDDI_VERSION */

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
//------------------------------------------------------------------------------
// ClfsAdvanceLogBase
//
// Set a new log base LSN without writing a restart record.
//------------------------------------------------------------------------------

NTSTATUS ClfsAdvanceLogBase (
                    __inout PVOID pvMarshalContext,
                    __in PCLFS_LSN plsnBase,
                    __in ULONG fFlags
                    );
#endif /* NTDDI_VERSION */

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
//------------------------------------------------------------------------------
// ClfsCloseAndResetLogFile
//
// Orderly shutdown of a physical or client log file stream given the log file
// object pointer.
//------------------------------------------------------------------------------

NTSTATUS ClfsCloseAndResetLogFile (__in PLOG_FILE_OBJECT plfoLog);
#endif /* NTDDI_VERSION */

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
//------------------------------------------------------------------------------
// ClfsCloseLogFileObject
//
// Close a log file object without the orderly shutdown of the log.
//------------------------------------------------------------------------------

NTSTATUS  ClfsCloseLogFileObject (__in PLOG_FILE_OBJECT plfoLog);
#endif /* NTDDI_VERSION */

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
//------------------------------------------------------------------------------
// ClfsCreateMarshallingArea
//
// Initalize a marshalling area for a physical or client log
// file stream given log file object pointer.
//------------------------------------------------------------------------------

NTSTATUS ClfsCreateMarshallingArea (
                    __in PLOG_FILE_OBJECT plfoLog,
                    __in POOL_TYPE ePoolType,
                    __in_opt PALLOCATE_FUNCTION pfnAllocBuffer,
                    __in_opt PFREE_FUNCTION pfnFreeBuffer,
                    __in ULONG cbMarshallingBuffer,
                    __in ULONG cMaxWriteBuffers,
                    __in ULONG cMaxReadBuffers,
                    __deref_out PVOID *ppvMarshalContext
                    );
#endif /* NTDDI_VERSION */

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
//------------------------------------------------------------------------------
// ClfsDeleteMarshallingArea
//
// Delete a marshalling area for a physical or client log
// file stream.
//------------------------------------------------------------------------------

NTSTATUS ClfsDeleteMarshallingArea (__in PVOID pvMarshalContext);
#endif /* NTDDI_VERSION */

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
//------------------------------------------------------------------------------
// ClfsReserveAndAppendLog
//
// Reserve space and append log buffers to a physical or client
// log stream.
//------------------------------------------------------------------------------

NTSTATUS ClfsReserveAndAppendLog (
                    __in PVOID pvMarshalContext,
                    __in_ecount_opt(cWriteEntries) PCLFS_WRITE_ENTRY rgWriteEntries,
                    __in ULONG cWriteEntries,
                    __in_opt PCLFS_LSN plsnUndoNext,
                    __in_opt PCLFS_LSN plsnPrevious,
                    __in ULONG cReserveRecords,
                    __inout_ecount_opt(cReserveRecords) PLONGLONG rgcbReservation,
                    __in ULONG fFlags,
                    __out_opt PCLFS_LSN plsn
                    );
#endif /* NTDDI_VERSION */

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
//------------------------------------------------------------------------------
// ClfsReserveAndAppendLogAligned
//
// Reserve space and append log buffers to a physical or client
// log stream, aligning each of the write entries according to
// the alignment specified.
//------------------------------------------------------------------------------

NTSTATUS ClfsReserveAndAppendLogAligned (
                    __in PVOID pvMarshalContext,
                    __in_ecount_opt(cWriteEntries) PCLFS_WRITE_ENTRY rgWriteEntries,
                    __in ULONG cWriteEntries,
                    __in ULONG cbEntryAlignment,
                    __in_opt PCLFS_LSN plsnUndoNext,
                    __in_opt PCLFS_LSN plsnPrevious,
                    __in ULONG cReserveRecords,
                    __inout_ecount_opt(cReserveRecords) PLONGLONG rgcbReservation,
                    __in ULONG fFlags,
                    __out_opt PCLFS_LSN plsn
                    );
#endif /* NTDDI_VERSION */

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
//------------------------------------------------------------------------------
// ClfsAlignReservedLog
//
// Given a valid marshalling context, allocate an aggregate number of reserved
// records and bytes.
//------------------------------------------------------------------------------

NTSTATUS ClfsAlignReservedLog (
                    __in PVOID pvMarshalContext,
                    __in ULONG cRecords,
                    __in_ecount(cRecords) LONGLONG rgcbReservation [],
                    __out PLONGLONG pcbAlignReservation
                    );
#endif /* NTDDI_VERSION */

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
//------------------------------------------------------------------------------
// ClfsAllocReservedLog
//
// Given a valid marshalling context, allocate an aggregate number of reserved
// records and bytes.
//------------------------------------------------------------------------------

NTSTATUS ClfsAllocReservedLog (
                    __in PVOID pvMarshalContext,
                    __in ULONG cRecords,
                    __in_ecount(cRecords) PLONGLONG pcbAdjustment
                    );
#endif /* NTDDI_VERSION */

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
//------------------------------------------------------------------------------
// ClfsFreeReservedLog
//
// Set the reserved log space to a new size or specify a delta
// for the reserved space given log file.
//------------------------------------------------------------------------------

NTSTATUS ClfsFreeReservedLog (
                    __in PVOID pvMarshalContext,
                    __in ULONG cRecords,
                    __in_ecount(cRecords) PLONGLONG pcbAdjustment
                    );
#endif /* NTDDI_VERSION */

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
//------------------------------------------------------------------------------
// ClfsFlushBuffers
// 
// Append all buffers in the marshalling area up to the flush queue and flush
// all buffers up to the disk.
//------------------------------------------------------------------------------

NTSTATUS ClfsFlushBuffers (__in PVOID pvMarshalContext);
#endif /* NTDDI_VERSION */

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
//------------------------------------------------------------------------------
// ClfsFlushToLsn
// 
// Flush all buffers in the marshalling area up to a target LSN to the flush
// queue and flush all buffers up to the target LSN to the disk.
//------------------------------------------------------------------------------

NTSTATUS ClfsFlushToLsn (
                    __in PVOID pvMarshalContext,
                    __in PCLFS_LSN plsnFlush,
                    __out_opt PCLFS_LSN plsnLastFlushed
                    );
#endif /* NTDDI_VERSION */

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
//------------------------------------------------------------------------------
// ClfsReadLogRecord
//
// Read a log record from a physical or client log stream given
// a starting LSN.
//------------------------------------------------------------------------------

NTSTATUS ClfsReadLogRecord (
                    __in PVOID pvMarshalContext,
                    __inout PCLFS_LSN plsnFirst,
                    __in CLFS_CONTEXT_MODE peContextMode,
                    __deref_out_bcount(*pcbReadBuffer) PVOID *ppvReadBuffer,
                    __out PULONG pcbReadBuffer,
                    __out PCLFS_RECORD_TYPE peRecordType,
                    __out PCLFS_LSN plsnUndoNext,
                    __out PCLFS_LSN plsnPrevious,
                    __deref_out PVOID* ppvReadContext
                    );
#endif /* NTDDI_VERSION */

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
//------------------------------------------------------------------------------
// ClfsReadNextLogRecord
//
// Read the next log record from a given marshalling context.
//------------------------------------------------------------------------------

NTSTATUS ClfsReadNextLogRecord (
                    __inout PVOID pvReadContext,
                    __deref_out_bcount(*pcbBuffer) PVOID *ppvBuffer,
                    __out PULONG pcbBuffer,
                    __inout PCLFS_RECORD_TYPE peRecordType,
                    __in_opt PCLFS_LSN plsnUser,
                    __out PCLFS_LSN plsnUndoNext,
                    __out PCLFS_LSN plsnPrevious,
                    __out PCLFS_LSN plsnRecord
                    );
#endif /* NTDDI_VERSION */

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
//------------------------------------------------------------------------------
// ClfsTerminateReadLog
//
// Terminate the read context.
//------------------------------------------------------------------------------

NTSTATUS ClfsTerminateReadLog (__in PVOID pvCursorContext);
#endif /* NTDDI_VERSION */

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
//------------------------------------------------------------------------------
// ClfsGetLastLsn
//
// Get the last used LSN.
//------------------------------------------------------------------------------

NTSTATUS ClfsGetLastLsn (
                    __in PLOG_FILE_OBJECT plfoLog,
                    __out PCLFS_LSN plsnLast
                    );
#endif /* NTDDI_VERSION */

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
//------------------------------------------------------------------------------
// ClfsGetIoStatistics
//
// Get I/O statistics on the CLFS log file.
//------------------------------------------------------------------------------

NTSTATUS ClfsGetIoStatistics (
                    __in PLOG_FILE_OBJECT plfoLog,
                    __inout_bcount(cbStatsBuffer) PVOID pvStatsBuffer,
                    __in ULONG cbStatsBuffer,
                    __in CLFS_IOSTATS_CLASS eStatsClass,
                    __out_opt PULONG pcbStatsWritten
                    );
#endif /* NTDDI_VERSION */

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
//-----------------------------------------------------------------------------
// ClfsLaterLsn
//
//      Method Description:
//
//          Increment an LSN by 1
//
//      Arguments:
//
//          plsn -- LSN to be incremented.
//          
//
//      Return Value:
//
//          A valid LSN next in sequence to the input LSN, if successful.
//          Otherwise, this function returns CLFS_LSN_INVALID.
//
//-----------------------------------------------------------------------------

CLFS_LSN
ClfsLaterLsn (__in PCLFS_LSN plsn);
#endif /* NTDDI_VERSION */

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
//-----------------------------------------------------------------------------
// ClfsEarlierLsn
//
//      Method Description:
//
//          Decrement an LSN by 1
//
//      Arguments:
//
//          plsn -- LSN to be decremented.
//          
//
//      Return Value:
//
//          A valid LSN next in sequence to the input LSN, if successful.
//          Otherwise, this function returns CLFS_LSN_INVALID.
//
//-----------------------------------------------------------------------------

CLFS_LSN
ClfsEarlierLsn (__in PCLFS_LSN plsn);
#endif /* NTDDI_VERSION */

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
//----------------------------------------------------------------------------
// ClfsLsnDifference
//
//      Method Description:
//
//          Find the approximate number of bytes between two LSNs.
//
//      Arguments:
//
//          plsnStart       -- LSN start of the log file range
//          plsnFinish      -- LSN finish of the log file range
//          cbContainer     -- size of a container
//          cbMaxBlock      -- maximum size of an I/O block
//          pcbDifference   -- approximate number of bytes between two LSNs.
//          
//          
//
//      Return Value:
//
//          STATUS_SUCCESS if difference is succeeds and an error status
//          otherwise.
//
//-----------------------------------------------------------------------------

NTSTATUS
ClfsLsnDifference (
    __in PCLFS_LSN plsnStart,
    __in PCLFS_LSN plsnFinish,
    __in ULONG cbContainer,
    __in ULONG cbMaxBlock,
    __out PLONGLONG pcbDifference
    );
#endif /* NTDDI_VERSION */

#if (NTDDI_VERSION >= NTDDI_VISTA)
//----------------------------------------------------------------------------
// ClfsValidTopLevelContext
//
//      Method Description:
//
//          Check that the current top level context is a common log (CLFS)
//          context.
//
//      Arguments:
//
//          pirp            -- reference to top of top-level context stack      
//          
//      Return Value:
//
//          TRUE if this is a valid CLFS top-level context and FALSE otherwise.
//
//-----------------------------------------------------------------------------

BOOLEAN
ClfsValidTopLevelContext (__in PIRP pirpTopLevelContext);
#endif /* NTDDI_VERSION */


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __CLFSPROC_H__ */

typedef struct _KTRANSACTION KTRANSACTION, *PKTRANSACTION, *RESTRICTED_POINTER PRKTRANSACTION;
typedef struct _KENLISTMENT KENLISTMENT, *PKENLISTMENT, *RESTRICTED_POINTER PRKENLISTMENT;
typedef struct _KRESOURCEMANAGER KRESOURCEMANAGER, *PKRESOURCEMANAGER, *RESTRICTED_POINTER PRKRESOURCEMANAGER;
typedef struct _KTM KTM, *PKTM, *RESTRICTED_POINTER PRKTM;

typedef GUID UOW, *PUOW;
typedef GUID *PGUID;

//
// Define ResourceManager Notification routine type.
//

typedef
NTSTATUS
(NTAPI *PTM_RM_NOTIFICATION) (
    __in     PKENLISTMENT EnlistmentObject,
    __in     PVOID RMContext,
    __in     PVOID TransactionContext,
    __in     ULONG TransactionNotification,
    __inout  PLARGE_INTEGER TmVirtualClock,
    __in     ULONG ArgumentLength,
    __in     PVOID Argument
    );

//
// CRM Protocol object
//

typedef GUID KCRM_PROTOCOL_ID, *PKCRM_PROTOCOL_ID;

typedef
NTSTATUS
(NTAPI *PTM_PROPAGATE_ROUTINE) (
    __in PVOID    PropagationCookie,
    __in PVOID    CallbackData,
    __in NTSTATUS PropagationStatus,
    __in GUID     TransactionGuid
    );

//
// Tm-level Transaction APIs
//

__checkReturn 
__drv_maxIRQL (APC_LEVEL) 
NTKERNELAPI
NTSTATUS
NTAPI
TmInitializeTransactionManager (
    __in PRKTM TransactionManager,
    __in PCUNICODE_STRING LogFileName,
    __in PGUID TmId,
    __in_opt ULONG CreateOptions
    );


__checkReturn 
__drv_maxIRQL (APC_LEVEL) 
NTKERNELAPI
NTSTATUS
NTAPI
TmRenameTransactionManager (
    __in PUNICODE_STRING LogFileName,
    __in LPGUID ExistingTransactionManagerGuid
    );

__checkReturn 
__drv_maxIRQL (APC_LEVEL) 
NTKERNELAPI
NTSTATUS
NTAPI
TmRecoverTransactionManager (
    __in PKTM Tm,
    __in PLARGE_INTEGER TargetVirtualClock
    );

__drv_maxIRQL (APC_LEVEL) 
NTKERNELAPI
NTSTATUS
NTAPI
TmCommitTransaction (
    __in PKTRANSACTION Transaction,
    __in BOOLEAN       Wait
    );


__drv_maxIRQL (APC_LEVEL) 
NTKERNELAPI
NTSTATUS
NTAPI
TmRollbackTransaction (
    __in PKTRANSACTION Transaction,
    __in BOOLEAN       Wait
    );


__checkReturn 
__drv_maxIRQL (APC_LEVEL) 
NTKERNELAPI
NTSTATUS
NTAPI
TmCreateEnlistment (
    __out PHANDLE           EnlistmentHandle,
    __in KPROCESSOR_MODE    PreviousMode,
    __in ACCESS_MASK        DesiredAccess,
    __in POBJECT_ATTRIBUTES ObjectAttributes,
    __in PRKRESOURCEMANAGER ResourceManager,
    __in PKTRANSACTION      Transaction,
    __in_opt ULONG          CreateOptions,
    __in NOTIFICATION_MASK  NotificationMask,
    __in_opt PVOID          EnlistmentKey
    );

__checkReturn 
__drv_maxIRQL (APC_LEVEL) 
NTKERNELAPI
NTSTATUS
NTAPI
TmRecoverEnlistment (
    __in PKENLISTMENT Enlistment,
    __in PVOID        EnlistmentKey
    );

__checkReturn 
__drv_maxIRQL (APC_LEVEL) 
NTKERNELAPI
NTSTATUS
NTAPI
TmPrePrepareEnlistment (
    __in PKENLISTMENT Enlistment,
    __in PLARGE_INTEGER TmVirtualClock
    );

__checkReturn 
__drv_maxIRQL (APC_LEVEL) 
NTKERNELAPI
NTSTATUS
NTAPI
TmPrepareEnlistment (
    __in PKENLISTMENT Enlistment,
    __in PLARGE_INTEGER TmVirtualClock
    );

__checkReturn 
__drv_maxIRQL (APC_LEVEL) 
NTKERNELAPI
NTSTATUS
NTAPI
TmCommitEnlistment (
    __in PKENLISTMENT Enlistment,
    __in PLARGE_INTEGER TmVirtualClock
    );

__drv_maxIRQL (APC_LEVEL) 
NTKERNELAPI
NTSTATUS
NTAPI
TmRollbackEnlistment (
    __in PKENLISTMENT Enlistment,
    __in PLARGE_INTEGER TmVirtualClock
    );

__drv_maxIRQL (APC_LEVEL) 
NTKERNELAPI
NTSTATUS
NTAPI
TmPrePrepareComplete (
    __in PKENLISTMENT Enlistment,
    __in PLARGE_INTEGER TmVirtualClock
    );

__drv_maxIRQL (APC_LEVEL) 
NTKERNELAPI
NTSTATUS
NTAPI
TmPrepareComplete (
    __in PKENLISTMENT Enlistment,
    __in PLARGE_INTEGER TmVirtualClock
    );

__drv_maxIRQL (APC_LEVEL) 
NTKERNELAPI
NTSTATUS
NTAPI
TmReadOnlyEnlistment (
    __in PKENLISTMENT Enlistment,
    __in PLARGE_INTEGER TmVirtualClock
    );

__drv_maxIRQL (APC_LEVEL) 
NTKERNELAPI
NTSTATUS
NTAPI
TmCommitComplete (
    __in PKENLISTMENT Enlistment,
    __in PLARGE_INTEGER TmVirtualClock
    );

__drv_maxIRQL (APC_LEVEL) 
NTKERNELAPI
NTSTATUS
NTAPI
TmRollbackComplete (
    __in PKENLISTMENT Enlistment,
    __in PLARGE_INTEGER TmVirtualClock
    );

__checkReturn 
__drv_maxIRQL (APC_LEVEL) 
NTKERNELAPI
NTSTATUS
NTAPI
TmReferenceEnlistmentKey (
    __in PKENLISTMENT Enlistment,
    __out PVOID *Key
    );

__checkReturn 
__drv_maxIRQL (APC_LEVEL) 
NTKERNELAPI
NTSTATUS
NTAPI
TmDereferenceEnlistmentKey (
    __in PKENLISTMENT Enlistment,
    __out_opt PBOOLEAN LastReference
    );

__drv_maxIRQL (APC_LEVEL) 
NTKERNELAPI
NTSTATUS
NTAPI
TmSinglePhaseReject (
    __in PKENLISTMENT Enlistment,
    __in PLARGE_INTEGER TmVirtualClock
    );

__drv_maxIRQL (APC_LEVEL) 
NTKERNELAPI
NTSTATUS
NTAPI
TmRequestOutcomeEnlistment (
    __in PKENLISTMENT Enlistment,
    __in PLARGE_INTEGER TmVirtualClock
    );


//
// ResourceManager APIs
//

__checkReturn 
__drv_maxIRQL (APC_LEVEL) 
NTKERNELAPI
NTSTATUS
NTAPI
TmEnableCallbacks (
    __in PKRESOURCEMANAGER ResourceManager,
    __in PTM_RM_NOTIFICATION CallbackRoutine,
    __in_opt PVOID RMKey
    );

__checkReturn 
__drv_maxIRQL (APC_LEVEL) 
NTKERNELAPI
NTSTATUS
NTAPI
TmRecoverResourceManager (
    __in PKRESOURCEMANAGER ResourceManager
    );

__checkReturn 
__drv_maxIRQL (APC_LEVEL) 
NTKERNELAPI
NTSTATUS
NTAPI
TmRegisterProtocolAddressInformation(
    __in PKRESOURCEMANAGER ResourceManager,
    __in PKCRM_PROTOCOL_ID ProtocolId,
    __in ULONG             ProtocolInformationSize,
    __in PVOID             ProtocolInformation
    );

__drv_maxIRQL (APC_LEVEL) 
NTKERNELAPI
NTSTATUS
NTAPI
TmPropagationComplete(
    __in  PKRESOURCEMANAGER ResourceManager,
    __in  ULONG             RequestCookie,
    __in  ULONG             BufferLength,
    __in  PVOID             Buffer
    );

__drv_maxIRQL (APC_LEVEL) 
NTKERNELAPI
NTSTATUS
NTAPI
TmPropagationFailed(
    __in  PKRESOURCEMANAGER ResourceManager,
    __in  ULONG             RequestCookie,
    __in  NTSTATUS          Status
    );

__drv_maxIRQL (APC_LEVEL) 
NTKERNELAPI
VOID
NTAPI
TmGetTransactionId(
    __in  PKTRANSACTION Transaction,
    __out PUOW TransactionId
    );

__checkReturn 
__drv_maxIRQL (APC_LEVEL) 
NTKERNELAPI
BOOLEAN
NTAPI
TmIsTransactionActive (
    __in PKTRANSACTION Transaction
    );


#define PCW_VERSION_1 0x0100
#define PCW_CURRENT_VERSION PCW_VERSION_1

typedef struct _PCW_INSTANCE *PPCW_INSTANCE;
typedef struct _PCW_REGISTRATION *PPCW_REGISTRATION;
typedef struct _PCW_BUFFER *PPCW_BUFFER;

typedef struct _PCW_COUNTER_DESCRIPTOR {
    USHORT Id;
    USHORT StructIndex;
    USHORT Offset;
    USHORT Size;
} PCW_COUNTER_DESCRIPTOR, *PPCW_COUNTER_DESCRIPTOR;

typedef struct _PCW_DATA {
    __in_bcount(Size) const VOID *Data;
    __in ULONG Size;
} PCW_DATA, *PPCW_DATA;

typedef struct _PCW_COUNTER_INFORMATION {
    ULONG64 CounterMask;
    PCUNICODE_STRING InstanceMask;
} PCW_COUNTER_INFORMATION, *PPCW_COUNTER_INFORMATION;

typedef struct _PCW_MASK_INFORMATION {
    ULONG64 CounterMask;
    PCUNICODE_STRING InstanceMask;
    ULONG InstanceId;
    BOOLEAN CollectMultiple;
    PPCW_BUFFER Buffer;
    PKEVENT CancelEvent;
} PCW_MASK_INFORMATION, *PPCW_MASK_INFORMATION;

typedef union _PCW_CALLBACK_INFORMATION {
    PCW_COUNTER_INFORMATION AddCounter;
    PCW_COUNTER_INFORMATION RemoveCounter;
    PCW_MASK_INFORMATION EnumerateInstances;
    PCW_MASK_INFORMATION CollectData;
} PCW_CALLBACK_INFORMATION, *PPCW_CALLBACK_INFORMATION;

typedef enum _PCW_CALLBACK_TYPE {
    PcwCallbackAddCounter = 0,
    PcwCallbackRemoveCounter,
    PcwCallbackEnumerateInstances,
    PcwCallbackCollectData,
} PCW_CALLBACK_TYPE, *PPCW_CALLBACK_TYPE;

typedef
NTSTATUS NTAPI
PCW_CALLBACK(
    __in PCW_CALLBACK_TYPE Type,
    __in PPCW_CALLBACK_INFORMATION Info,
    __in_opt PVOID Context
    );

typedef PCW_CALLBACK *PPCW_CALLBACK;

typedef struct _PCW_REGISTRATION_INFORMATION {
    __in ULONG Version;
    __in PCUNICODE_STRING Name;
    __in ULONG CounterCount;
    __in_ecount(CounterCount) PPCW_COUNTER_DESCRIPTOR Counters;
    __in_opt PPCW_CALLBACK Callback;
    __in_opt PVOID CallbackContext;
} PCW_REGISTRATION_INFORMATION, *PPCW_REGISTRATION_INFORMATION;

#if (NTDDI_VERSION >= NTDDI_WIN7)
__drv_maxIRQL(APC_LEVEL)
NTSTATUS
NTAPI
PcwRegister(
    __deref_out PPCW_REGISTRATION *Registration,
    __in PPCW_REGISTRATION_INFORMATION Info
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
__drv_maxIRQL(APC_LEVEL)
VOID
NTAPI
PcwUnregister(
    __in PPCW_REGISTRATION Registration
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
__drv_maxIRQL(APC_LEVEL)
NTSTATUS
NTAPI
PcwCreateInstance(
    __deref_out PPCW_INSTANCE *Instance,
    __in PPCW_REGISTRATION Registration,
    __in PCUNICODE_STRING Name,
    __in ULONG Count,
    __in_ecount(Count) PPCW_DATA Data
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
__drv_maxIRQL(APC_LEVEL)
VOID
NTAPI
PcwCloseInstance(
    __in PPCW_INSTANCE Instance
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
__drv_maxIRQL(APC_LEVEL)
NTSTATUS
NTAPI
PcwAddInstance(
    __in PPCW_BUFFER Buffer,
    __in PCUNICODE_STRING Name,
    __in ULONG Id,
    __in ULONG Count,
    __in_ecount(Count) PPCW_DATA Data
    );
#endif



extern POBJECT_TYPE *CmKeyObjectType;
extern POBJECT_TYPE *IoFileObjectType;
extern POBJECT_TYPE *ExEventObjectType;
extern POBJECT_TYPE *ExSemaphoreObjectType;
extern POBJECT_TYPE *TmTransactionManagerObjectType;
extern POBJECT_TYPE *TmResourceManagerObjectType;
extern POBJECT_TYPE *TmEnlistmentObjectType;
extern POBJECT_TYPE *TmTransactionObjectType;
extern POBJECT_TYPE *PsProcessType;
extern POBJECT_TYPE *PsThreadType;
extern POBJECT_TYPE *SeTokenObjectType;

#ifdef __cplusplus
}
#endif

#if _MSC_VER >= 1200
#pragma warning(pop)
#else
#pragma warning(default:4115)
#pragma warning(default:4201)
#pragma warning(default:4214)
#endif

#endif // _WDMDDK_

