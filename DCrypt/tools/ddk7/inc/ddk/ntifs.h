/*++ BUILD Version: 0146    // Increment this if a change has global effects

Copyright (c) Microsoft Corporation. All rights reserved.

Module Name:

    ntifs.h

Abstract:

    This module defines the NT types, constants, and functions that are
    exposed to file system drivers.

Revision History:

--*/

#ifndef _NTIFS_
#define _NTIFS_

#define _NTIFS_INCLUDED_

#ifndef RC_INVOKED
#if _MSC_VER < 1300
#error Compiler version not supported by Windows DDK
#endif
#endif // RC_INVOKED

#ifndef __cplusplus
#pragma warning(disable:4116)       // TYPE_ALIGNMENT generates this - move it
                                    // outside the warning push/pop scope.
#endif

#define NT_INCLUDED
#define _NTMSV1_0_
#define _CTYPE_DISABLE_MACROS

#if _MSC_VER >= 1200
#pragma warning(push)
#endif

#pragma warning(disable:4115) // named type definition in parentheses
#pragma warning(disable:4201) // nameless struct/union
#pragma warning(disable:4214) // bit field types other than int


#include <ntddk.h>
#include <excpt.h>
#include <ntdef.h>
#include <ntnls.h>
#include <ntstatus.h>
#include <bugcodes.h>
#include <ntiologc.h>


//
//  These macros are used to test, set and clear flags respectivly
//

#ifndef FlagOn
#define FlagOn(_F,_SF)        ((_F) & (_SF))
#endif

#ifndef BooleanFlagOn
#define BooleanFlagOn(F,SF)   ((BOOLEAN)(((F) & (SF)) != 0))
#endif

#ifndef SetFlag
#define SetFlag(_F,_SF)       ((_F) |= (_SF))
#endif

#ifndef ClearFlag
#define ClearFlag(_F,_SF)     ((_F) &= ~(_SF))
#endif

//
// Define types that are not exported.
//

typedef struct _BUS_HANDLER *PBUS_HANDLER;
typedef struct _CALLBACK_OBJECT *PCALLBACK_OBJECT;
typedef struct _DEVICE_HANDLER_OBJECT *PDEVICE_HANDLER_OBJECT;
typedef struct _IO_TIMER *PIO_TIMER;
typedef struct _KINTERRUPT *PKINTERRUPT;
typedef struct _KPROCESS *PKPROCESS ,*PRKPROCESS, *PEPROCESS;
typedef struct _KTHREAD *PKTHREAD, *PRKTHREAD, *PETHREAD;
typedef struct _OBJECT_TYPE *POBJECT_TYPE;
typedef struct _PEB *PPEB;
typedef struct _ACL *PACL;

#ifdef __cplusplus
extern "C" {
#endif

#define PsGetCurrentProcess IoGetCurrentProcess

#if (NTDDI_VERSION >= NTDDI_VISTA)
extern NTSYSAPI volatile CCHAR KeNumberProcessors;
#elif (NTDDI_VERSION >= NTDDI_WINXP)
extern NTSYSAPI CCHAR KeNumberProcessors;
#else
extern PCCHAR KeNumberProcessors;
#endif

typedef UNICODE_STRING LSA_UNICODE_STRING, *PLSA_UNICODE_STRING;
typedef STRING LSA_STRING, *PLSA_STRING;
typedef OBJECT_ATTRIBUTES LSA_OBJECT_ATTRIBUTES, *PLSA_OBJECT_ATTRIBUTES;

#ifndef SID_IDENTIFIER_AUTHORITY_DEFINED
#define SID_IDENTIFIER_AUTHORITY_DEFINED
typedef struct _SID_IDENTIFIER_AUTHORITY {
    UCHAR Value[6];
} SID_IDENTIFIER_AUTHORITY, *PSID_IDENTIFIER_AUTHORITY;
#endif


#ifndef SID_DEFINED
#define SID_DEFINED
typedef struct _SID {
   UCHAR Revision;
   UCHAR SubAuthorityCount;
   SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
#ifdef MIDL_PASS
   [size_is(SubAuthorityCount)] ULONG SubAuthority[*];
#else // MIDL_PASS
   ULONG SubAuthority[ANYSIZE_ARRAY];
#endif // MIDL_PASS
} SID, *PISID;
#endif

#define SID_REVISION                     (1)    // Current revision level
#define SID_MAX_SUB_AUTHORITIES          (15)
#define SID_RECOMMENDED_SUB_AUTHORITIES  (1)    // Will change to around 6

                                                // in a future release.
#ifndef MIDL_PASS
#define SECURITY_MAX_SID_SIZE  \
      (sizeof(SID) - sizeof(ULONG) + (SID_MAX_SUB_AUTHORITIES * sizeof(ULONG)))
#endif // MIDL_PASS


typedef enum _SID_NAME_USE {
    SidTypeUser = 1,
    SidTypeGroup,
    SidTypeDomain,
    SidTypeAlias,
    SidTypeWellKnownGroup,
    SidTypeDeletedAccount,
    SidTypeInvalid,
    SidTypeUnknown,
    SidTypeComputer,
    SidTypeLabel
} SID_NAME_USE, *PSID_NAME_USE;

typedef struct _SID_AND_ATTRIBUTES {
#ifdef MIDL_PASS
    PISID Sid;
#else // MIDL_PASS
    PSID Sid;
#endif // MIDL_PASS
    ULONG Attributes;
    } SID_AND_ATTRIBUTES, * PSID_AND_ATTRIBUTES;

typedef SID_AND_ATTRIBUTES SID_AND_ATTRIBUTES_ARRAY[ANYSIZE_ARRAY];
typedef SID_AND_ATTRIBUTES_ARRAY *PSID_AND_ATTRIBUTES_ARRAY;

#define SID_HASH_SIZE 32
typedef ULONG_PTR SID_HASH_ENTRY, *PSID_HASH_ENTRY;

typedef struct _SID_AND_ATTRIBUTES_HASH {
    ULONG SidCount;
    PSID_AND_ATTRIBUTES SidAttr;
    SID_HASH_ENTRY Hash[SID_HASH_SIZE];
} SID_AND_ATTRIBUTES_HASH, *PSID_AND_ATTRIBUTES_HASH;


/////////////////////////////////////////////////////////////////////////////
//                                                                         //
// Universal well-known SIDs                                               //
//                                                                         //
//     Null SID                     S-1-0-0                                //
//     World                        S-1-1-0                                //
//     Local                        S-1-2-0                                //
//     Creator Owner ID             S-1-3-0                                //
//     Creator Group ID             S-1-3-1                                //
//     Creator Owner Server ID      S-1-3-2                                //
//     Creator Group Server ID      S-1-3-3                                //
//                                                                         //
//     (Non-unique IDs)             S-1-4                                  //
//                                                                         //
/////////////////////////////////////////////////////////////////////////////

#define SECURITY_NULL_SID_AUTHORITY         {0,0,0,0,0,0}
#define SECURITY_WORLD_SID_AUTHORITY        {0,0,0,0,0,1}
#define SECURITY_LOCAL_SID_AUTHORITY        {0,0,0,0,0,2}
#define SECURITY_CREATOR_SID_AUTHORITY      {0,0,0,0,0,3}
#define SECURITY_NON_UNIQUE_AUTHORITY       {0,0,0,0,0,4}
#define SECURITY_RESOURCE_MANAGER_AUTHORITY {0,0,0,0,0,9}


#define SECURITY_NULL_RID                 (0x00000000L)
#define SECURITY_WORLD_RID                (0x00000000L)
#define SECURITY_LOCAL_RID                (0x00000000L)
#define SECURITY_LOCAL_LOGON_RID          (0x00000001L)

#define SECURITY_CREATOR_OWNER_RID        (0x00000000L)
#define SECURITY_CREATOR_GROUP_RID        (0x00000001L)

#define SECURITY_CREATOR_OWNER_SERVER_RID (0x00000002L)
#define SECURITY_CREATOR_GROUP_SERVER_RID (0x00000003L)

#define SECURITY_CREATOR_OWNER_RIGHTS_RID (0x00000004L)

///////////////////////////////////////////////////////////////////////////////
//                                                                           //
// NT well-known SIDs                                                        //
//                                                                           //
//     NT Authority            S-1-5                                         //
//     Dialup                  S-1-5-1                                       //
//                                                                           //
//     Network                 S-1-5-2                                       //
//     Batch                   S-1-5-3                                       //
//     Interactive             S-1-5-4                                       //
//     (Logon IDs)             S-1-5-5-X-Y                                   //
//     Service                 S-1-5-6                                       //
//     AnonymousLogon          S-1-5-7       (aka null logon session)        //
//     Proxy                   S-1-5-8                                       //
//     Enterprise DC (EDC)     S-1-5-9       (aka domain controller account) //
//     Self                    S-1-5-10      (self RID)                      //
//     Authenticated User      S-1-5-11      (Authenticated user somewhere)  //
//     Restricted Code         S-1-5-12      (Running restricted code)       //
//     Terminal Server         S-1-5-13      (Running on Terminal Server)    //
//     Remote Logon            S-1-5-14      (Remote Interactive Logon)      //
//     This Organization       S-1-5-15                                      //
//                                                                           //
//     IUser                   S-1-5-17
//     Local System            S-1-5-18                                      //
//     Local Service           S-1-5-19                                      //
//     Network Service         S-1-5-20                                      //
//                                                                           //
//     (NT non-unique IDs)     S-1-5-0x15-... (NT Domain Sids)               //
//                                                                           //
//     (Built-in domain)       S-1-5-0x20                                    //
//                                                                           //
//     (Security Package IDs)  S-1-5-0x40                                    //
//     NTLM Authentication     S-1-5-0x40-10                                 //
//     SChannel Authentication S-1-5-0x40-14                                 //
//     Digest Authentication   S-1-5-0x40-21                                 //
//                                                                           //
//     Other Organization      S-1-5-1000    (>=1000 can not be filtered)    //
//                                                                           //
//                                                                           //
// NOTE: the relative identifier values (RIDs) determine which security      //
//       boundaries the SID is allowed to cross.  Before adding new RIDs,    //
//       a determination needs to be made regarding which range they should  //
//       be added to in order to ensure proper "SID filtering"               //
//                                                                           //
///////////////////////////////////////////////////////////////////////////////


#define SECURITY_NT_AUTHORITY           {0,0,0,0,0,5}   // ntifs

#define SECURITY_DIALUP_RID             (0x00000001L)
#define SECURITY_NETWORK_RID            (0x00000002L)
#define SECURITY_BATCH_RID              (0x00000003L)
#define SECURITY_INTERACTIVE_RID        (0x00000004L)
#define SECURITY_LOGON_IDS_RID          (0x00000005L)
#define SECURITY_LOGON_IDS_RID_COUNT    (3L)
#define SECURITY_SERVICE_RID            (0x00000006L)
#define SECURITY_ANONYMOUS_LOGON_RID    (0x00000007L)
#define SECURITY_PROXY_RID              (0x00000008L)
#define SECURITY_ENTERPRISE_CONTROLLERS_RID (0x00000009L)
#define SECURITY_SERVER_LOGON_RID       SECURITY_ENTERPRISE_CONTROLLERS_RID
#define SECURITY_PRINCIPAL_SELF_RID     (0x0000000AL)
#define SECURITY_AUTHENTICATED_USER_RID (0x0000000BL)
#define SECURITY_RESTRICTED_CODE_RID    (0x0000000CL)
#define SECURITY_TERMINAL_SERVER_RID    (0x0000000DL)
#define SECURITY_REMOTE_LOGON_RID       (0x0000000EL)
#define SECURITY_THIS_ORGANIZATION_RID  (0x0000000FL)
#define SECURITY_IUSER_RID              (0x00000011L)
#define SECURITY_LOCAL_SYSTEM_RID       (0x00000012L)
#define SECURITY_LOCAL_SERVICE_RID      (0x00000013L)
#define SECURITY_NETWORK_SERVICE_RID    (0x00000014L)

#define SECURITY_NT_NON_UNIQUE          (0x00000015L)
#define SECURITY_NT_NON_UNIQUE_SUB_AUTH_COUNT  (3L)

#define SECURITY_ENTERPRISE_READONLY_CONTROLLERS_RID (0x00000016L)

#define SECURITY_BUILTIN_DOMAIN_RID     (0x00000020L)
#define SECURITY_WRITE_RESTRICTED_CODE_RID (0x00000021L)


#define SECURITY_PACKAGE_BASE_RID       (0x00000040L)
#define SECURITY_PACKAGE_RID_COUNT      (2L)
#define SECURITY_PACKAGE_NTLM_RID       (0x0000000AL)
#define SECURITY_PACKAGE_SCHANNEL_RID   (0x0000000EL)
#define SECURITY_PACKAGE_DIGEST_RID     (0x00000015L)

#define SECURITY_CRED_TYPE_BASE_RID             (0x00000041L)
#define SECURITY_CRED_TYPE_RID_COUNT            (2L)
#define SECURITY_CRED_TYPE_THIS_ORG_CERT_RID    (0x00000001L)

#define SECURITY_MIN_BASE_RID           (0x00000050L)

#define SECURITY_SERVICE_ID_BASE_RID    (0x00000050L)
#define SECURITY_SERVICE_ID_RID_COUNT   (6L)

#define SECURITY_RESERVED_ID_BASE_RID   (0x00000051L)

#define SECURITY_APPPOOL_ID_BASE_RID    (0x00000052L)
#define SECURITY_APPPOOL_ID_RID_COUNT   (6L)

#define SECURITY_VIRTUALSERVER_ID_BASE_RID    (0x00000053L)
#define SECURITY_VIRTUALSERVER_ID_RID_COUNT   (6L)

#define SECURITY_USERMODEDRIVERHOST_ID_BASE_RID  (0x00000054L)
#define SECURITY_USERMODEDRIVERHOST_ID_RID_COUNT (6L)

#define SECURITY_CLOUD_INFRASTRUCTURE_SERVICES_ID_BASE_RID  (0x00000055L)
#define SECURITY_CLOUD_INFRASTRUCTURE_SERVICES_ID_RID_COUNT (6L)

#define SECURITY_WMIHOST_ID_BASE_RID  (0x00000056L)
#define SECURITY_WMIHOST_ID_RID_COUNT (6L)

#define SECURITY_TASK_ID_BASE_RID                 (0x00000057L)

#define SECURITY_NFS_ID_BASE_RID        (0x00000058L)

#define SECURITY_COM_ID_BASE_RID        (0x00000059L)

#define SECURITY_VIRTUALACCOUNT_ID_RID_COUNT   (6L)

#define SECURITY_MAX_BASE_RID		(0x0000006FL)
#define SECURITY_MAX_ALWAYS_FILTERED    (0x000003E7L)
#define SECURITY_MIN_NEVER_FILTERED     (0x000003E8L)

#define SECURITY_OTHER_ORGANIZATION_RID (0x000003E8L)

//
//Service SID type RIDs are in the range 0x50- 0x6F.  Therefore, we are giving  the next available RID to Windows Mobile team.
//
#define SECURITY_WINDOWSMOBILE_ID_BASE_RID (0x00000070L)


/////////////////////////////////////////////////////////////////////////////
//                                                                         //
// well-known domain relative sub-authority values (RIDs)...               //
//                                                                         //
/////////////////////////////////////////////////////////////////////////////



#define DOMAIN_GROUP_RID_ENTERPRISE_READONLY_DOMAIN_CONTROLLERS (0x000001F2L)

#define FOREST_USER_RID_MAX            (0x000001F3L)

// Well-known users ...

#define DOMAIN_USER_RID_ADMIN          (0x000001F4L)
#define DOMAIN_USER_RID_GUEST          (0x000001F5L)
#define DOMAIN_USER_RID_KRBTGT         (0x000001F6L)

#define DOMAIN_USER_RID_MAX            (0x000003E7L)


// well-known groups ...

#define DOMAIN_GROUP_RID_ADMINS        (0x00000200L)
#define DOMAIN_GROUP_RID_USERS         (0x00000201L)
#define DOMAIN_GROUP_RID_GUESTS        (0x00000202L)
#define DOMAIN_GROUP_RID_COMPUTERS     (0x00000203L)
#define DOMAIN_GROUP_RID_CONTROLLERS   (0x00000204L)
#define DOMAIN_GROUP_RID_CERT_ADMINS   (0x00000205L)
#define DOMAIN_GROUP_RID_SCHEMA_ADMINS (0x00000206L)
#define DOMAIN_GROUP_RID_ENTERPRISE_ADMINS (0x00000207L)
#define DOMAIN_GROUP_RID_POLICY_ADMINS (0x00000208L)
#define DOMAIN_GROUP_RID_READONLY_CONTROLLERS (0x00000209L)

// well-known aliases ...

#define DOMAIN_ALIAS_RID_ADMINS                         (0x00000220L)
#define DOMAIN_ALIAS_RID_USERS                          (0x00000221L)
#define DOMAIN_ALIAS_RID_GUESTS                         (0x00000222L)
#define DOMAIN_ALIAS_RID_POWER_USERS                    (0x00000223L)

#define DOMAIN_ALIAS_RID_ACCOUNT_OPS                    (0x00000224L)
#define DOMAIN_ALIAS_RID_SYSTEM_OPS                     (0x00000225L)
#define DOMAIN_ALIAS_RID_PRINT_OPS                      (0x00000226L)
#define DOMAIN_ALIAS_RID_BACKUP_OPS                     (0x00000227L)

#define DOMAIN_ALIAS_RID_REPLICATOR                     (0x00000228L)
#define DOMAIN_ALIAS_RID_RAS_SERVERS                    (0x00000229L)
#define DOMAIN_ALIAS_RID_PREW2KCOMPACCESS               (0x0000022AL)
#define DOMAIN_ALIAS_RID_REMOTE_DESKTOP_USERS           (0x0000022BL)
#define DOMAIN_ALIAS_RID_NETWORK_CONFIGURATION_OPS      (0x0000022CL)
#define DOMAIN_ALIAS_RID_INCOMING_FOREST_TRUST_BUILDERS (0x0000022DL)

#define DOMAIN_ALIAS_RID_MONITORING_USERS               (0x0000022EL)
#define DOMAIN_ALIAS_RID_LOGGING_USERS                  (0x0000022FL)
#define DOMAIN_ALIAS_RID_AUTHORIZATIONACCESS            (0x00000230L)
#define DOMAIN_ALIAS_RID_TS_LICENSE_SERVERS             (0x00000231L)
#define DOMAIN_ALIAS_RID_DCOM_USERS                     (0x00000232L)
#define DOMAIN_ALIAS_RID_IUSERS                         (0x00000238L)
#define DOMAIN_ALIAS_RID_CRYPTO_OPERATORS               (0x00000239L)
#define DOMAIN_ALIAS_RID_CACHEABLE_PRINCIPALS_GROUP     (0x0000023BL)
#define DOMAIN_ALIAS_RID_NON_CACHEABLE_PRINCIPALS_GROUP (0x0000023CL)
#define DOMAIN_ALIAS_RID_EVENT_LOG_READERS_GROUP        (0x0000023DL)
#define DOMAIN_ALIAS_RID_CERTSVC_DCOM_ACCESS_GROUP      (0x0000023EL)


#define SECURITY_MANDATORY_LABEL_AUTHORITY          {0,0,0,0,0,16}
#define SECURITY_MANDATORY_UNTRUSTED_RID            (0x00000000L)
#define SECURITY_MANDATORY_LOW_RID                  (0x00001000L)
#define SECURITY_MANDATORY_MEDIUM_RID               (0x00002000L)
#define SECURITY_MANDATORY_MEDIUM_PLUS_RID          (SECURITY_MANDATORY_MEDIUM_RID + 0x100)
#define SECURITY_MANDATORY_HIGH_RID                 (0x00003000L)
#define SECURITY_MANDATORY_SYSTEM_RID               (0x00004000L)
#define SECURITY_MANDATORY_PROTECTED_PROCESS_RID    (0x00005000L)

//
// SECURITY_MANDATORY_MAXIMUM_USER_RID is the highest RID that
// can be set by a usermode caller.
//

#define SECURITY_MANDATORY_MAXIMUM_USER_RID   SECURITY_MANDATORY_SYSTEM_RID

#define MANDATORY_LEVEL_TO_MANDATORY_RID(IL) (IL * 0x1000)

//
// Allocate the System Luid.  The first 1000 LUIDs are reserved.
// Use #999 here (0x3e7 = 999)
//

#define SYSTEM_LUID                     { 0x3e7, 0x0 }
#define ANONYMOUS_LOGON_LUID            { 0x3e6, 0x0 }
#define LOCALSERVICE_LUID               { 0x3e5, 0x0 }
#define NETWORKSERVICE_LUID             { 0x3e4, 0x0 }
#define IUSER_LUID                      { 0x3e3, 0x0 }


//
//  The structure of an ACE is a common ace header followed by ace type
//  specific data.  Pictorally the structure of the common ace header is
//  as follows:
//
//       3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//       1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//      +---------------+-------+-------+---------------+---------------+
//      |            AceSize            |    AceFlags   |     AceType   |
//      +---------------+-------+-------+---------------+---------------+
//
//  AceType denotes the type of the ace, there are some predefined ace
//  types
//
//  AceSize is the size, in bytes, of ace.
//
//  AceFlags are the Ace flags for audit and inheritance, defined shortly.

typedef struct _ACE_HEADER {
    UCHAR AceType;
    UCHAR AceFlags;
    USHORT AceSize;
} ACE_HEADER;
typedef ACE_HEADER *PACE_HEADER;

//
//  The following are the predefined ace types that go into the AceType
//  field of an Ace header.
//

#define ACCESS_MIN_MS_ACE_TYPE                  (0x0)
#define ACCESS_ALLOWED_ACE_TYPE                 (0x0)
#define ACCESS_DENIED_ACE_TYPE                  (0x1)
#define SYSTEM_AUDIT_ACE_TYPE                   (0x2)
#define SYSTEM_ALARM_ACE_TYPE                   (0x3)
#define ACCESS_MAX_MS_V2_ACE_TYPE               (0x3)

#define ACCESS_ALLOWED_COMPOUND_ACE_TYPE        (0x4)
#define ACCESS_MAX_MS_V3_ACE_TYPE               (0x4)

#define ACCESS_MIN_MS_OBJECT_ACE_TYPE           (0x5)
#define ACCESS_ALLOWED_OBJECT_ACE_TYPE          (0x5)
#define ACCESS_DENIED_OBJECT_ACE_TYPE           (0x6)
#define SYSTEM_AUDIT_OBJECT_ACE_TYPE            (0x7)
#define SYSTEM_ALARM_OBJECT_ACE_TYPE            (0x8)
#define ACCESS_MAX_MS_OBJECT_ACE_TYPE           (0x8)

#define ACCESS_MAX_MS_V4_ACE_TYPE               (0x8)
#define ACCESS_MAX_MS_ACE_TYPE                  (0x8)

#define ACCESS_ALLOWED_CALLBACK_ACE_TYPE        (0x9)
#define ACCESS_DENIED_CALLBACK_ACE_TYPE         (0xA)
#define ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE (0xB)
#define ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE  (0xC)
#define SYSTEM_AUDIT_CALLBACK_ACE_TYPE          (0xD)
#define SYSTEM_ALARM_CALLBACK_ACE_TYPE          (0xE)
#define SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE   (0xF)
#define SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE   (0x10)

#define SYSTEM_MANDATORY_LABEL_ACE_TYPE         (0x11)
#define ACCESS_MAX_MS_V5_ACE_TYPE               (0x11)

// end_winnt


// begin_winnt

//
//  The following are the inherit flags that go into the AceFlags field
//  of an Ace header.
//

#define OBJECT_INHERIT_ACE                (0x1)
#define CONTAINER_INHERIT_ACE             (0x2)
#define NO_PROPAGATE_INHERIT_ACE          (0x4)
#define INHERIT_ONLY_ACE                  (0x8)
#define INHERITED_ACE                     (0x10)
#define VALID_INHERIT_FLAGS               (0x1F)


//  The following are the currently defined ACE flags that go into the
//  AceFlags field of an ACE header.  Each ACE type has its own set of
//  AceFlags.
//
//  SUCCESSFUL_ACCESS_ACE_FLAG - used only with system audit and alarm ACE
//  types to indicate that a message is generated for successful accesses.
//
//  FAILED_ACCESS_ACE_FLAG - used only with system audit and alarm ACE types
//  to indicate that a message is generated for failed accesses.
//

//
//  SYSTEM_AUDIT and SYSTEM_ALARM AceFlags
//
//  These control the signaling of audit and alarms for success or failure.
//

#define SUCCESSFUL_ACCESS_ACE_FLAG       (0x40)
#define FAILED_ACCESS_ACE_FLAG           (0x80)


//
//  We'll define the structure of the predefined ACE types.  Pictorally
//  the structure of the predefined ACE's is as follows:
//
//       3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//       1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//      +---------------+-------+-------+---------------+---------------+
//      |    AceFlags   | Resd  |Inherit|    AceSize    |     AceType   |
//      +---------------+-------+-------+---------------+---------------+
//      |                              Mask                             |
//      +---------------------------------------------------------------+
//      |                                                               |
//      +                                                               +
//      |                                                               |
//      +                              Sid                              +
//      |                                                               |
//      +                                                               +
//      |                                                               |
//      +---------------------------------------------------------------+
//
//  Mask is the access mask associated with the ACE.  This is either the
//  access allowed, access denied, audit, or alarm mask.
//
//  Sid is the Sid associated with the ACE.
//

//  The following are the four predefined ACE types.

//  Examine the AceType field in the Header to determine
//  which structure is appropriate to use for casting.


typedef struct _ACCESS_ALLOWED_ACE {
    ACE_HEADER Header;
    ACCESS_MASK Mask;
    ULONG SidStart;
} ACCESS_ALLOWED_ACE;

typedef ACCESS_ALLOWED_ACE *PACCESS_ALLOWED_ACE;

typedef struct _ACCESS_DENIED_ACE {
    ACE_HEADER Header;
    ACCESS_MASK Mask;
    ULONG SidStart;
} ACCESS_DENIED_ACE;
typedef ACCESS_DENIED_ACE *PACCESS_DENIED_ACE;

typedef struct _SYSTEM_AUDIT_ACE {
    ACE_HEADER Header;
    ACCESS_MASK Mask;
    ULONG SidStart;
} SYSTEM_AUDIT_ACE;
typedef SYSTEM_AUDIT_ACE *PSYSTEM_AUDIT_ACE;

typedef struct _SYSTEM_ALARM_ACE {
    ACE_HEADER Header;
    ACCESS_MASK Mask;
    ULONG SidStart;
} SYSTEM_ALARM_ACE;
typedef SYSTEM_ALARM_ACE *PSYSTEM_ALARM_ACE;

typedef struct _SYSTEM_MANDATORY_LABEL_ACE {
    ACE_HEADER Header;
    ACCESS_MASK Mask;
    ULONG SidStart;
} SYSTEM_MANDATORY_LABEL_ACE, *PSYSTEM_MANDATORY_LABEL_ACE;

#define SYSTEM_MANDATORY_LABEL_NO_WRITE_UP         0x1
#define SYSTEM_MANDATORY_LABEL_NO_READ_UP          0x2
#define SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP       0x4

#define SYSTEM_MANDATORY_LABEL_VALID_MASK (SYSTEM_MANDATORY_LABEL_NO_WRITE_UP   | \
                                           SYSTEM_MANDATORY_LABEL_NO_READ_UP    | \
                                           SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP)

#define SECURITY_DESCRIPTOR_MIN_LENGTH   (sizeof(SECURITY_DESCRIPTOR))


typedef USHORT SECURITY_DESCRIPTOR_CONTROL, *PSECURITY_DESCRIPTOR_CONTROL;

#define SE_OWNER_DEFAULTED               (0x0001)
#define SE_GROUP_DEFAULTED               (0x0002)
#define SE_DACL_PRESENT                  (0x0004)
#define SE_DACL_DEFAULTED                (0x0008)
#define SE_SACL_PRESENT                  (0x0010)
#define SE_SACL_DEFAULTED                (0x0020)
// end_winnt
#define SE_DACL_UNTRUSTED                (0x0040)
#define SE_SERVER_SECURITY               (0x0080)
// begin_winnt
#define SE_DACL_AUTO_INHERIT_REQ         (0x0100)
#define SE_SACL_AUTO_INHERIT_REQ         (0x0200)
#define SE_DACL_AUTO_INHERITED           (0x0400)
#define SE_SACL_AUTO_INHERITED           (0x0800)
#define SE_DACL_PROTECTED                (0x1000)
#define SE_SACL_PROTECTED                (0x2000)
#define SE_RM_CONTROL_VALID              (0x4000)
#define SE_SELF_RELATIVE                 (0x8000)

//
//  Where:
//
//      SE_OWNER_DEFAULTED - This boolean flag, when set, indicates that the
//          SID pointed to by the Owner field was provided by a
//          defaulting mechanism rather than explicitly provided by the
//          original provider of the security descriptor.  This may
//          affect the treatment of the SID with respect to inheritence
//          of an owner.
//
//      SE_GROUP_DEFAULTED - This boolean flag, when set, indicates that the
//          SID in the Group field was provided by a defaulting mechanism
//          rather than explicitly provided by the original provider of
//          the security descriptor.  This may affect the treatment of
//          the SID with respect to inheritence of a primary group.
//
//      SE_DACL_PRESENT - This boolean flag, when set, indicates that the
//          security descriptor contains a discretionary ACL.  If this
//          flag is set and the Dacl field of the SECURITY_DESCRIPTOR is
//          null, then a null ACL is explicitly being specified.
//
//      SE_DACL_DEFAULTED - This boolean flag, when set, indicates that the
//          ACL pointed to by the Dacl field was provided by a defaulting
//          mechanism rather than explicitly provided by the original
//          provider of the security descriptor.  This may affect the
//          treatment of the ACL with respect to inheritence of an ACL.
//          This flag is ignored if the DaclPresent flag is not set.
//
//      SE_SACL_PRESENT - This boolean flag, when set,  indicates that the
//          security descriptor contains a system ACL pointed to by the
//          Sacl field.  If this flag is set and the Sacl field of the
//          SECURITY_DESCRIPTOR is null, then an empty (but present)
//          ACL is being specified.
//
//      SE_SACL_DEFAULTED - This boolean flag, when set, indicates that the
//          ACL pointed to by the Sacl field was provided by a defaulting
//          mechanism rather than explicitly provided by the original
//          provider of the security descriptor.  This may affect the
//          treatment of the ACL with respect to inheritence of an ACL.
//          This flag is ignored if the SaclPresent flag is not set.
//
// end_winnt
//      SE_DACL_TRUSTED - This boolean flag, when set, indicates that the
//          ACL pointed to by the Dacl field was provided by a trusted source
//          and does not require any editing of compound ACEs.  If this flag
//          is not set and a compound ACE is encountered, the system will
//          substitute known valid SIDs for the server SIDs in the ACEs.
//
//      SE_SERVER_SECURITY - This boolean flag, when set, indicates that the
//         caller wishes the system to create a Server ACL based on the
//         input ACL, regardess of its source (explicit or defaulting.
//         This is done by replacing all of the GRANT ACEs with compound
//         ACEs granting the current server.  This flag is only
//         meaningful if the subject is impersonating.
//
// begin_winnt
//      SE_SELF_RELATIVE - This boolean flag, when set, indicates that the
//          security descriptor is in self-relative form.  In this form,
//          all fields of the security descriptor are contiguous in memory
//          and all pointer fields are expressed as offsets from the
//          beginning of the security descriptor.  This form is useful
//          for treating security descriptors as opaque data structures
//          for transmission in communication protocol or for storage on
//          secondary media.
//
//
//
// Pictorially the structure of a security descriptor is as follows:
//
//       3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//       1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//      +---------------------------------------------------------------+
//      |            Control            |Reserved1 (SBZ)|   Revision    |
//      +---------------------------------------------------------------+
//      |                            Owner                              |
//      +---------------------------------------------------------------+
//      |                            Group                              |
//      +---------------------------------------------------------------+
//      |                            Sacl                               |
//      +---------------------------------------------------------------+
//      |                            Dacl                               |
//      +---------------------------------------------------------------+
//
// In general, this data structure should be treated opaquely to ensure future
// compatibility.
//
//

typedef struct _SECURITY_DESCRIPTOR_RELATIVE {
    UCHAR Revision;
    UCHAR Sbz1;
    SECURITY_DESCRIPTOR_CONTROL Control;
    ULONG Owner;
    ULONG Group;
    ULONG Sacl;
    ULONG Dacl;
    } SECURITY_DESCRIPTOR_RELATIVE, *PISECURITY_DESCRIPTOR_RELATIVE;

typedef struct _SECURITY_DESCRIPTOR {
   UCHAR Revision;
   UCHAR Sbz1;
   SECURITY_DESCRIPTOR_CONTROL Control;
   PSID Owner;
   PSID Group;
   PACL Sacl;
   PACL Dacl;

   } SECURITY_DESCRIPTOR, *PISECURITY_DESCRIPTOR;



////////////////////////////////////////////////////////////////////////
//                                                                    //
//               Object Type list for AccessCheckByType               //
//                                                                    //
////////////////////////////////////////////////////////////////////////

typedef struct _OBJECT_TYPE_LIST {
    USHORT Level;
    USHORT Sbz;
    GUID *ObjectType;
} OBJECT_TYPE_LIST, *POBJECT_TYPE_LIST;

//
// DS values for Level
//

#define ACCESS_OBJECT_GUID       0
#define ACCESS_PROPERTY_SET_GUID 1
#define ACCESS_PROPERTY_GUID     2

#define ACCESS_MAX_LEVEL         4

//
// Parameters to NtAccessCheckByTypeAndAditAlarm
//

typedef enum _AUDIT_EVENT_TYPE {
    AuditEventObjectAccess,
    AuditEventDirectoryServiceAccess
} AUDIT_EVENT_TYPE, *PAUDIT_EVENT_TYPE;

#define AUDIT_ALLOW_NO_PRIVILEGE 0x1

//
// DS values for Source and ObjectTypeName
//

#define ACCESS_DS_SOURCE_A "DS"
#define ACCESS_DS_SOURCE_W L"DS"
#define ACCESS_DS_OBJECT_TYPE_NAME_A "Directory Service Object"
#define ACCESS_DS_OBJECT_TYPE_NAME_W L"Directory Service Object"

////////////////////////////////////////////////////////////////////////
//                                                                    //
//               Privilege Related Data Structures                    //
//                                                                    //
////////////////////////////////////////////////////////////////////////



//
// Values for different access granted\denied reasons:
// AccessReasonAceN = AccessReasonAce + N.
// AccessReasonPrivilegeN = AccessReasonPrivilege + N.
//

#define ACCESS_REASON_TYPE_MASK 0xffff0000
#define ACCESS_REASON_DATA_MASK 0x0000ffff

typedef enum _ACCESS_REASON_TYPE{

    AccessReasonNone = 0x00000000,  // Indicate no reason for the bit. The bit may not be checked, or just no known reason.

    //
    // The lowest 2 bytes store the index of the ACE that grant/deny this bit.
    // If the corresponding access maskt is zero, then it is deny ACE; otherwise,
    // it is allow ACE.
    //
    AccessReasonAllowedAce = 0x00010000,    // Granted a permission.
    AccessReasonDeniedAce = 0x00020000,     // Denied a permission.

    AccessReasonAllowedParentAce = 0x00030000,    // Granted a permission from parent ACE
    AccessReasonDeniedParentAce = 0x00040000,     // Denied a permission from parent ACE

    AccessReasonMissingPrivilege = 0x00100000,
    AccessReasonFromPrivilege = 0x00200000,


    AccessReasonIntegrityLevel = 0x00300000,

    AccessReasonOwnership = 0x00400000,

    AccessReasonNullDacl = 0x00500000,
    AccessReasonEmptyDacl = 0x00600000,

    AccessReasonNoSD = 0x00700000,
    AccessReasonNoGrant = 0x00800000    // this access bit is not granted by any ACE.
} ACCESS_REASON_TYPE;

 //
// Structure to hold access denied\granted reason for every bit of ACCESS_MASK.
// There are 32-bits in ACCESS_MASK and only 27-bits are actually valid on
// return from AccessCheck because MAXIMUM_ALLOWED, GENERIC_READ,
// GENERIC_WRITE, GENERIC_EXECUTE, and GENERIC_ALL are never returned.
//
// The content in Data fields depends on the Access Reason, for example,
// if the reason is AccessReasonAce, the Data will be the ACE ID.
// If there are more than one reason (more than one bit is set), the array size
// of the Data is equal to the number of bits set (or number of reasons).
// The Data could be null for a particular reason.
//

typedef ULONG ACCESS_REASON;

typedef struct _ACCESS_REASONS{
        ACCESS_REASON Data[32];
} ACCESS_REASONS, *PACCESS_REASONS;


/*
The following data structures are defined to consolidate various falvors of
access check functions. In particular for Windows 7, the new access check
function will enable security attribute check, plus returning the reason
for a access check result.

The new access check function based on these data structures will
form the foundation to reimplement other flavors of access check
functions.

*/

//
// Structure to hold pointer to security descriptor and its unique id, which
// can be used for caching access check results.
// (NOTE NOTE) The cache key can be constructed by SecurityDescriptorId, Token and
// PrincipalSelfSid. Watch how GenericMapping affects the cache results.
//
#define SE_SECURITY_DESCRIPTOR_FLAG_NO_OWNER_ACE    0x00000001
#define SE_SECURITY_DESCRIPTOR_FLAG_NO_LABEL_ACE    0x00000002
#define SE_SECURITY_DESCRIPTOR_VALID_FLAGS          0x00000003

typedef struct _SE_SECURITY_DESCRIPTOR
{
    ULONG Size;
    ULONG Flags;
    PSECURITY_DESCRIPTOR SecurityDescriptor;
} SE_SECURITY_DESCRIPTOR, *PSE_SECURITY_DESCRIPTOR;

typedef struct _SE_ACCESS_REQUEST
{
    ULONG Size;
    PSE_SECURITY_DESCRIPTOR SeSecurityDescriptor;
    ACCESS_MASK DesiredAccess;
    ACCESS_MASK PreviouslyGrantedAccess;
    PSID PrincipalSelfSid;      // Need to watch how this field affects the cache.
    PGENERIC_MAPPING GenericMapping;
    ULONG ObjectTypeListCount;
    POBJECT_TYPE_LIST ObjectTypeList;
} SE_ACCESS_REQUEST, *PSE_ACCESS_REQUEST;


typedef struct _SE_ACCESS_REPLY
{
    ULONG Size;
    ULONG ResultListCount;  // Indicate the array size of GrantedAccess and AccessStatus, it only can be either 1 or ObjectTypeListCount.
    PACCESS_MASK GrantedAccess;
    PNTSTATUS AccessStatus;
    PACCESS_REASONS AccessReason;
    PPRIVILEGE_SET* Privileges;
} SE_ACCESS_REPLY, *PSE_ACCESS_REPLY;

// end_winnt

typedef enum _SE_AUDIT_OPERATION
{
    AuditPrivilegeObject,
    AuditPrivilegeService,
    AuditAccessCheck,
    AuditOpenObject,
    AuditOpenObjectWithTransaction,
    AuditCloseObject,
    AuditDeleteObject,
    AuditOpenObjectForDelete,
    AuditOpenObjectForDeleteWithTransaction,
    AuditCloseNonObject,
    AuditOpenNonObject,
    AuditObjectReference,
    AuditHandleCreation,
} SE_AUDIT_OPERATION, *PSE_AUDIT_OPERATION;



typedef struct _SE_AUDIT_INFO
{
    ULONG Size;
    AUDIT_EVENT_TYPE AuditType;
    SE_AUDIT_OPERATION AuditOperation;
    ULONG AuditFlags;
    UNICODE_STRING SubsystemName;
    UNICODE_STRING ObjectTypeName;
    UNICODE_STRING ObjectName;
    PVOID HandleId;
    GUID* TransactionId;
    LUID* OperationId;
    BOOLEAN ObjectCreation;
    BOOLEAN GenerateOnClose;
} SE_AUDIT_INFO, *PSE_AUDIT_INFO;



////////////////////////////////////////////////////////////////////
//                                                                //
//           Token Object Definitions                             //
//                                                                //
//                                                                //
////////////////////////////////////////////////////////////////////


//
// Token Specific Access Rights.
//

#define TOKEN_ASSIGN_PRIMARY    (0x0001)
#define TOKEN_DUPLICATE         (0x0002)
#define TOKEN_IMPERSONATE       (0x0004)
#define TOKEN_QUERY             (0x0008)
#define TOKEN_QUERY_SOURCE      (0x0010)
#define TOKEN_ADJUST_PRIVILEGES (0x0020)
#define TOKEN_ADJUST_GROUPS     (0x0040)
#define TOKEN_ADJUST_DEFAULT    (0x0080)
#define TOKEN_ADJUST_SESSIONID  (0x0100)

#define TOKEN_ALL_ACCESS_P (STANDARD_RIGHTS_REQUIRED  |\
                          TOKEN_ASSIGN_PRIMARY      |\
                          TOKEN_DUPLICATE           |\
                          TOKEN_IMPERSONATE         |\
                          TOKEN_QUERY               |\
                          TOKEN_QUERY_SOURCE        |\
                          TOKEN_ADJUST_PRIVILEGES   |\
                          TOKEN_ADJUST_GROUPS       |\
                          TOKEN_ADJUST_DEFAULT )

#if ((defined(_WIN32_WINNT) && (_WIN32_WINNT > 0x0400)) || (!defined(_WIN32_WINNT)))
#define TOKEN_ALL_ACCESS  (TOKEN_ALL_ACCESS_P |\
                          TOKEN_ADJUST_SESSIONID )
#else
#define TOKEN_ALL_ACCESS  (TOKEN_ALL_ACCESS_P)
#endif

#define TOKEN_READ       (STANDARD_RIGHTS_READ      |\
                          TOKEN_QUERY)


#define TOKEN_WRITE      (STANDARD_RIGHTS_WRITE     |\
                          TOKEN_ADJUST_PRIVILEGES   |\
                          TOKEN_ADJUST_GROUPS       |\
                          TOKEN_ADJUST_DEFAULT)

#define TOKEN_EXECUTE    (STANDARD_RIGHTS_EXECUTE)

//
//
// Token Types
//

typedef enum _TOKEN_TYPE {
    TokenPrimary = 1,
    TokenImpersonation
    } TOKEN_TYPE;
typedef TOKEN_TYPE *PTOKEN_TYPE;

//
// Token elevation values describe the relative strength of a given token.
// A full token is a token with all groups and privileges to which the principal
// is authorized.  A limited token is one with some groups or privileges removed.
//

typedef enum _TOKEN_ELEVATION_TYPE {
    TokenElevationTypeDefault = 1,
    TokenElevationTypeFull,
    TokenElevationTypeLimited,
} TOKEN_ELEVATION_TYPE, *PTOKEN_ELEVATION_TYPE;

//
// Token Information Classes.
//


typedef enum _TOKEN_INFORMATION_CLASS {
    TokenUser = 1,
    TokenGroups,
    TokenPrivileges,
    TokenOwner,
    TokenPrimaryGroup,
    TokenDefaultDacl,
    TokenSource,
    TokenType,
    TokenImpersonationLevel,
    TokenStatistics,
    TokenRestrictedSids,
    TokenSessionId,
    TokenGroupsAndPrivileges,
    TokenSessionReference,
    TokenSandBoxInert,
    TokenAuditPolicy,
    TokenOrigin,
    TokenElevationType,
    TokenLinkedToken,
    TokenElevation,
    TokenHasRestrictions,
    TokenAccessInformation,
    TokenVirtualizationAllowed,
    TokenVirtualizationEnabled,
    TokenIntegrityLevel,
    TokenUIAccess,
    TokenMandatoryPolicy,
    TokenLogonSid,
    MaxTokenInfoClass  // MaxTokenInfoClass should always be the last enum
} TOKEN_INFORMATION_CLASS, *PTOKEN_INFORMATION_CLASS;

//
// Token information class structures
//


typedef struct _TOKEN_USER {
    SID_AND_ATTRIBUTES User;
} TOKEN_USER, *PTOKEN_USER;

typedef struct _TOKEN_GROUPS {
    ULONG GroupCount;
#ifdef MIDL_PASS
    [size_is(GroupCount)] SID_AND_ATTRIBUTES Groups[*];
#else // MIDL_PASS
    SID_AND_ATTRIBUTES Groups[ANYSIZE_ARRAY];
#endif // MIDL_PASS
} TOKEN_GROUPS, *PTOKEN_GROUPS;


typedef struct _TOKEN_PRIVILEGES {
    ULONG PrivilegeCount;
    LUID_AND_ATTRIBUTES Privileges[ANYSIZE_ARRAY];
} TOKEN_PRIVILEGES, *PTOKEN_PRIVILEGES;


typedef struct _TOKEN_OWNER {
    PSID Owner;
} TOKEN_OWNER, *PTOKEN_OWNER;


typedef struct _TOKEN_PRIMARY_GROUP {
    PSID PrimaryGroup;
} TOKEN_PRIMARY_GROUP, *PTOKEN_PRIMARY_GROUP;


typedef struct _TOKEN_DEFAULT_DACL {
    PACL DefaultDacl;
} TOKEN_DEFAULT_DACL, *PTOKEN_DEFAULT_DACL;

typedef struct _TOKEN_GROUPS_AND_PRIVILEGES {
    ULONG SidCount;
    ULONG SidLength;
    PSID_AND_ATTRIBUTES Sids;
    ULONG RestrictedSidCount;
    ULONG RestrictedSidLength;
    PSID_AND_ATTRIBUTES RestrictedSids;
    ULONG PrivilegeCount;
    ULONG PrivilegeLength;
    PLUID_AND_ATTRIBUTES Privileges;
    LUID AuthenticationId;
} TOKEN_GROUPS_AND_PRIVILEGES, *PTOKEN_GROUPS_AND_PRIVILEGES;

typedef struct _TOKEN_LINKED_TOKEN {
    HANDLE LinkedToken;
} TOKEN_LINKED_TOKEN, *PTOKEN_LINKED_TOKEN;

typedef struct _TOKEN_ELEVATION {
    ULONG TokenIsElevated;
} TOKEN_ELEVATION, *PTOKEN_ELEVATION;

typedef struct _TOKEN_MANDATORY_LABEL {
    SID_AND_ATTRIBUTES Label;
} TOKEN_MANDATORY_LABEL, *PTOKEN_MANDATORY_LABEL;

#define TOKEN_MANDATORY_POLICY_OFF             0x0
#define TOKEN_MANDATORY_POLICY_NO_WRITE_UP     0x1
#define TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN 0x2

#define TOKEN_MANDATORY_POLICY_VALID_MASK      (TOKEN_MANDATORY_POLICY_NO_WRITE_UP | \
                                                TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN)

typedef struct _TOKEN_MANDATORY_POLICY {
    ULONG Policy;
} TOKEN_MANDATORY_POLICY, *PTOKEN_MANDATORY_POLICY;

typedef struct _TOKEN_ACCESS_INFORMATION {
    PSID_AND_ATTRIBUTES_HASH SidHash;
    PSID_AND_ATTRIBUTES_HASH RestrictedSidHash;
    PTOKEN_PRIVILEGES Privileges;
    LUID AuthenticationId;
    TOKEN_TYPE TokenType;
    SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
    TOKEN_MANDATORY_POLICY MandatoryPolicy;
    ULONG Flags;
} TOKEN_ACCESS_INFORMATION, *PTOKEN_ACCESS_INFORMATION;

//
// Valid bits for each TOKEN_AUDIT_POLICY policy mask field.
//

#define POLICY_AUDIT_SUBCATEGORY_COUNT (53)

typedef struct _TOKEN_AUDIT_POLICY {
    UCHAR PerUserPolicy[((POLICY_AUDIT_SUBCATEGORY_COUNT) >> 1) + 1];
} TOKEN_AUDIT_POLICY, *PTOKEN_AUDIT_POLICY;

#define TOKEN_SOURCE_LENGTH 8

typedef struct _TOKEN_SOURCE {
    CHAR SourceName[TOKEN_SOURCE_LENGTH];
    LUID SourceIdentifier;
} TOKEN_SOURCE, *PTOKEN_SOURCE;


typedef struct _TOKEN_STATISTICS {
    LUID TokenId;
    LUID AuthenticationId;
    LARGE_INTEGER ExpirationTime;
    TOKEN_TYPE TokenType;
    SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
    ULONG DynamicCharged;
    ULONG DynamicAvailable;
    ULONG GroupCount;
    ULONG PrivilegeCount;
    LUID ModifiedId;
} TOKEN_STATISTICS, *PTOKEN_STATISTICS;



typedef struct _TOKEN_CONTROL {
    LUID TokenId;
    LUID AuthenticationId;
    LUID ModifiedId;
    TOKEN_SOURCE TokenSource;
} TOKEN_CONTROL, *PTOKEN_CONTROL;

typedef struct _TOKEN_ORIGIN {
    LUID OriginatingLogonSession ;
} TOKEN_ORIGIN, * PTOKEN_ORIGIN ;


typedef enum _MANDATORY_LEVEL {
    MandatoryLevelUntrusted = 0,
    MandatoryLevelLow,
    MandatoryLevelMedium,
    MandatoryLevelHigh,
    MandatoryLevelSystem,
    MandatoryLevelSecureProcess,
    MandatoryLevelCount
} MANDATORY_LEVEL, *PMANDATORY_LEVEL;




// end_winnt

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn
__kernel_entry NTSYSCALLAPI
NTSTATUS
NTAPI
NtOpenThreadToken(
    __in HANDLE ThreadHandle,
    __in ACCESS_MASK DesiredAccess,
    __in BOOLEAN OpenAsSelf,
    __out PHANDLE TokenHandle
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
__checkReturn
__kernel_entry NTSYSCALLAPI
NTSTATUS
NTAPI
NtOpenThreadTokenEx(
    __in HANDLE ThreadHandle,
    __in ACCESS_MASK DesiredAccess,
    __in BOOLEAN OpenAsSelf,
    __in ULONG HandleAttributes,
    __out PHANDLE TokenHandle
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn
__kernel_entry NTSYSCALLAPI
NTSTATUS
NTAPI
NtOpenProcessToken(
    __in HANDLE ProcessHandle,
    __in ACCESS_MASK DesiredAccess,
    __out PHANDLE TokenHandle
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
__checkReturn
__kernel_entry NTSYSCALLAPI
NTSTATUS
NTAPI
NtOpenProcessTokenEx(
    __in HANDLE ProcessHandle,
    __in ACCESS_MASK DesiredAccess,
    __in ULONG HandleAttributes,
    __out PHANDLE TokenHandle
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
__checkReturn
NTSYSAPI
NTSTATUS
NTAPI
NtOpenJobObjectToken(
    __in HANDLE JobHandle,
    __in ACCESS_MASK DesiredAccess,
    __out PHANDLE TokenHandle
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
__checkReturn
__kernel_entry NTSYSCALLAPI
NTSTATUS
NTAPI
NtDuplicateToken(
    __in HANDLE ExistingTokenHandle,
    __in ACCESS_MASK DesiredAccess,
    __in POBJECT_ATTRIBUTES ObjectAttributes,
    __in BOOLEAN EffectiveOnly,
    __in TOKEN_TYPE TokenType,
    __out PHANDLE NewTokenHandle
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
__checkReturn
__kernel_entry NTSYSCALLAPI
NTSTATUS
NTAPI
NtFilterToken (
    __in HANDLE ExistingTokenHandle,
    __in ULONG Flags,
    __in_opt PTOKEN_GROUPS SidsToDisable,
    __in_opt PTOKEN_PRIVILEGES PrivilegesToDelete,
    __in_opt PTOKEN_GROUPS RestrictedSids,
    __out PHANDLE NewTokenHandle
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WINXP)
__checkReturn
__kernel_entry NTSYSCALLAPI
NTSTATUS
NTAPI
NtImpersonateAnonymousToken(
    __in HANDLE ThreadHandle
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn
__kernel_entry NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryInformationToken (
    __in HANDLE TokenHandle,
    __in TOKEN_INFORMATION_CLASS TokenInformationClass,
    __out_bcount_part_opt(TokenInformationLength, *ReturnLength) PVOID TokenInformation,
    __in ULONG TokenInformationLength,
    __out PULONG ReturnLength
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
__checkReturn
__kernel_entry NTSYSCALLAPI
NTSTATUS
NTAPI
NtSetInformationToken (
    __in HANDLE TokenHandle,
    __in TOKEN_INFORMATION_CLASS TokenInformationClass,
    __in_bcount(TokenInformationLength) PVOID TokenInformation,
    __in ULONG TokenInformationLength
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn
__kernel_entry NTSYSCALLAPI
NTSTATUS
NTAPI
NtAdjustPrivilegesToken (
    __in HANDLE TokenHandle,
    __in BOOLEAN DisableAllPrivileges,
    __in_opt PTOKEN_PRIVILEGES NewState,
    __in ULONG BufferLength,
    __out_bcount_part_opt(BufferLength, *ReturnLength) PTOKEN_PRIVILEGES PreviousState,
    __out __drv_when(PreviousState == NULL, __out_opt) PULONG ReturnLength
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
__checkReturn
__kernel_entry NTSYSCALLAPI
NTSTATUS
NTAPI
NtAdjustGroupsToken (
    __in HANDLE TokenHandle,
    __in BOOLEAN ResetToDefault,
    __in_opt PTOKEN_GROUPS NewState,
    __in_opt ULONG BufferLength,
    __out_bcount_part_opt(BufferLength, *ReturnLength) PTOKEN_GROUPS PreviousState,
    __out PULONG ReturnLength
    );
#endif // NTDDI_VERSION >= NTDDI_WINXP

#if (NTDDI_VERSION >= NTDDI_WINXP)
__checkReturn
__kernel_entry NTSYSCALLAPI
NTSTATUS
NTAPI
NtPrivilegeCheck (
    __in HANDLE ClientToken,
    __inout PPRIVILEGE_SET RequiredPrivileges,
    __out PBOOLEAN Result
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
__checkReturn
__kernel_entry NTSYSCALLAPI
NTSTATUS
NTAPI
NtAccessCheckAndAuditAlarm (
    __in PUNICODE_STRING SubsystemName,
    __in_opt PVOID HandleId,
    __in PUNICODE_STRING ObjectTypeName,
    __in PUNICODE_STRING ObjectName,
    __in PSECURITY_DESCRIPTOR SecurityDescriptor,
    __in ACCESS_MASK DesiredAccess,
    __in PGENERIC_MAPPING GenericMapping,
    __in BOOLEAN ObjectCreation,
    __out PACCESS_MASK GrantedAccess,
    __out PNTSTATUS AccessStatus,
    __out PBOOLEAN GenerateOnClose
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
__checkReturn
__kernel_entry NTSYSCALLAPI
NTSTATUS
NTAPI
NtAccessCheckByTypeAndAuditAlarm (
    __in PUNICODE_STRING SubsystemName,
    __in_opt PVOID HandleId,
    __in PUNICODE_STRING ObjectTypeName,
    __in PUNICODE_STRING ObjectName,
    __in PSECURITY_DESCRIPTOR SecurityDescriptor,
    __in_opt PSID PrincipalSelfSid,
    __in ACCESS_MASK DesiredAccess,
    __in AUDIT_EVENT_TYPE AuditType,
    __in ULONG Flags,
    __in_ecount_opt(ObjectTypeListLength) POBJECT_TYPE_LIST ObjectTypeList,
    __in ULONG ObjectTypeListLength,
    __in PGENERIC_MAPPING GenericMapping,
    __in BOOLEAN ObjectCreation,
    __out PACCESS_MASK GrantedAccess,
    __out PNTSTATUS AccessStatus,
    __out PBOOLEAN GenerateOnClose
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
__checkReturn
__kernel_entry NTSYSCALLAPI
NTSTATUS
NTAPI
NtAccessCheckByTypeResultListAndAuditAlarm (
    __in PUNICODE_STRING SubsystemName,
    __in_opt PVOID HandleId,
    __in PUNICODE_STRING ObjectTypeName,
    __in PUNICODE_STRING ObjectName,
    __in PSECURITY_DESCRIPTOR SecurityDescriptor,
    __in_opt PSID PrincipalSelfSid,
    __in ACCESS_MASK DesiredAccess,
    __in AUDIT_EVENT_TYPE AuditType,
    __in ULONG Flags,
    __in_ecount_opt(ObjectTypeListLength) POBJECT_TYPE_LIST ObjectTypeList,
    __in ULONG ObjectTypeListLength,
    __in PGENERIC_MAPPING GenericMapping,
    __in BOOLEAN ObjectCreation,
    __out_ecount(ObjectTypeListLength) PACCESS_MASK GrantedAccess,
    __out_ecount(ObjectTypeListLength) PNTSTATUS AccessStatus,
    __out PBOOLEAN GenerateOnClose
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
__checkReturn
__kernel_entry NTSYSCALLAPI
NTSTATUS
NTAPI
NtAccessCheckByTypeResultListAndAuditAlarmByHandle (
    __in PUNICODE_STRING SubsystemName,
    __in_opt PVOID HandleId,
    __in HANDLE ClientToken,
    __in PUNICODE_STRING ObjectTypeName,
    __in PUNICODE_STRING ObjectName,
    __in PSECURITY_DESCRIPTOR SecurityDescriptor,
    __in_opt PSID PrincipalSelfSid,
    __in ACCESS_MASK DesiredAccess,
    __in AUDIT_EVENT_TYPE AuditType,
    __in ULONG Flags,
    __in_ecount_opt(ObjectTypeListLength) POBJECT_TYPE_LIST ObjectTypeList,
    __in ULONG ObjectTypeListLength,
    __in PGENERIC_MAPPING GenericMapping,
    __in BOOLEAN ObjectCreation,
    __out_ecount(ObjectTypeListLength) PACCESS_MASK GrantedAccess,
    __out_ecount(ObjectTypeListLength) PNTSTATUS AccessStatus,
    __out PBOOLEAN GenerateOnClose
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
__kernel_entry NTSYSCALLAPI
NTSTATUS
NTAPI
NtOpenObjectAuditAlarm (
    __in PUNICODE_STRING SubsystemName,
    __in_opt PVOID HandleId,
    __in PUNICODE_STRING ObjectTypeName,
    __in PUNICODE_STRING ObjectName,
    __in_opt PSECURITY_DESCRIPTOR SecurityDescriptor,
    __in HANDLE ClientToken,
    __in ACCESS_MASK DesiredAccess,
    __in ACCESS_MASK GrantedAccess,
    __in_opt PPRIVILEGE_SET Privileges,
    __in BOOLEAN ObjectCreation,
    __in BOOLEAN AccessGranted,
    __out PBOOLEAN GenerateOnClose
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
__kernel_entry NTSYSCALLAPI
NTSTATUS
NTAPI
NtPrivilegeObjectAuditAlarm (
    __in PUNICODE_STRING SubsystemName,
    __in_opt PVOID HandleId,
    __in HANDLE ClientToken,
    __in ACCESS_MASK DesiredAccess,
    __in PPRIVILEGE_SET Privileges,
    __in BOOLEAN AccessGranted
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
__kernel_entry NTSYSCALLAPI
NTSTATUS
NTAPI
NtCloseObjectAuditAlarm (
    __in PUNICODE_STRING SubsystemName,
    __in_opt PVOID HandleId,
    __in BOOLEAN GenerateOnClose
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
__kernel_entry NTSYSCALLAPI
NTSTATUS
NTAPI
NtDeleteObjectAuditAlarm (
    __in PUNICODE_STRING SubsystemName,
    __in_opt PVOID HandleId,
    __in BOOLEAN GenerateOnClose
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
__kernel_entry NTSYSCALLAPI
NTSTATUS
NTAPI
NtPrivilegedServiceAuditAlarm (
    __in PUNICODE_STRING SubsystemName,
    __in PUNICODE_STRING ServiceName,
    __in HANDLE ClientToken,
    __in PPRIVILEGE_SET Privileges,
    __in BOOLEAN AccessGranted
    );
#endif


typedef
__drv_functionClass(RTL_HEAP_COMMIT_ROUTINE)
__drv_sameIRQL
NTSTATUS
NTAPI
RTL_HEAP_COMMIT_ROUTINE(
    __in PVOID Base,
    __inout PVOID *CommitAddress,
    __inout PSIZE_T CommitSize
    );
typedef RTL_HEAP_COMMIT_ROUTINE *PRTL_HEAP_COMMIT_ROUTINE;

typedef struct _RTL_HEAP_PARAMETERS {
    ULONG Length;
    SIZE_T SegmentReserve;
    SIZE_T SegmentCommit;
    SIZE_T DeCommitFreeBlockThreshold;
    SIZE_T DeCommitTotalFreeThreshold;
    SIZE_T MaximumAllocationSize;
    SIZE_T VirtualMemoryThreshold;
    SIZE_T InitialCommit;
    SIZE_T InitialReserve;
    PRTL_HEAP_COMMIT_ROUTINE CommitRoutine;
    SIZE_T Reserved[ 2 ];
} RTL_HEAP_PARAMETERS, *PRTL_HEAP_PARAMETERS;

#if (NTDDI_VERSION >= NTDDI_WINXP)
__checkReturn
NTSYSAPI
PVOID
NTAPI
RtlCreateHeap(
    __in     ULONG Flags,
    __in_opt PVOID HeapBase,
    __in_opt SIZE_T ReserveSize,
    __in_opt SIZE_T CommitSize,
    __in_opt PVOID Lock,
    __in_opt PRTL_HEAP_PARAMETERS Parameters
    );
#endif // NTDDI_VERSION >= NTDDI_WINXP


#define HEAP_NO_SERIALIZE               0x00000001      // winnt
#define HEAP_GROWABLE                   0x00000002      // winnt
#define HEAP_GENERATE_EXCEPTIONS        0x00000004      // winnt
#define HEAP_ZERO_MEMORY                0x00000008      // winnt
#define HEAP_REALLOC_IN_PLACE_ONLY      0x00000010      // winnt
#define HEAP_TAIL_CHECKING_ENABLED      0x00000020      // winnt
#define HEAP_FREE_CHECKING_ENABLED      0x00000040      // winnt
#define HEAP_DISABLE_COALESCE_ON_FREE   0x00000080      // winnt

#define HEAP_CREATE_ALIGN_16            0x00010000      // winnt Create heap with 16 byte alignment (obsolete)
#define HEAP_CREATE_ENABLE_TRACING      0x00020000      // winnt Create heap call tracing enabled (obsolete)
#define HEAP_CREATE_ENABLE_EXECUTE      0x00040000      // winnt Create heap with executable pages

#define HEAP_SETTABLE_USER_VALUE        0x00000100
#define HEAP_SETTABLE_USER_FLAG1        0x00000200
#define HEAP_SETTABLE_USER_FLAG2        0x00000400
#define HEAP_SETTABLE_USER_FLAG3        0x00000800
#define HEAP_SETTABLE_USER_FLAGS        0x00000E00

#define HEAP_CLASS_0                    0x00000000      // process heap
#define HEAP_CLASS_1                    0x00001000      // private heap
#define HEAP_CLASS_2                    0x00002000      // Kernel Heap
#define HEAP_CLASS_3                    0x00003000      // GDI heap
#define HEAP_CLASS_4                    0x00004000      // User heap
#define HEAP_CLASS_5                    0x00005000      // Console heap
#define HEAP_CLASS_6                    0x00006000      // User Desktop heap
#define HEAP_CLASS_7                    0x00007000      // Csrss Shared heap
#define HEAP_CLASS_8                    0x00008000      // Csr Port heap
#define HEAP_CLASS_MASK                 0x0000F000

#define HEAP_MAXIMUM_TAG                0x0FFF              // winnt
#define HEAP_GLOBAL_TAG                 0x0800
#define HEAP_PSEUDO_TAG_FLAG            0x8000              // winnt
#define HEAP_TAG_SHIFT                  18                  // winnt
#define HEAP_TAG_MASK                  (HEAP_MAXIMUM_TAG << HEAP_TAG_SHIFT)

#define HEAP_CREATE_VALID_MASK         (HEAP_NO_SERIALIZE |             \
                                        HEAP_GROWABLE |                 \
                                        HEAP_GENERATE_EXCEPTIONS |      \
                                        HEAP_ZERO_MEMORY |              \
                                        HEAP_REALLOC_IN_PLACE_ONLY |    \
                                        HEAP_TAIL_CHECKING_ENABLED |    \
                                        HEAP_FREE_CHECKING_ENABLED |    \
                                        HEAP_DISABLE_COALESCE_ON_FREE | \
                                        HEAP_CLASS_MASK |               \
                                        HEAP_CREATE_ALIGN_16 |          \
                                        HEAP_CREATE_ENABLE_TRACING |    \
                                        HEAP_CREATE_ENABLE_EXECUTE)

// begin_winnt
#if !defined(MIDL_PASS)
FORCEINLINE
ULONG
HEAP_MAKE_TAG_FLAGS (
    __in ULONG TagBase,
    __in ULONG Tag
    )

{
    __assume_bound(TagBase);
    return ((ULONG)((TagBase) + ((Tag) << HEAP_TAG_SHIFT)));
}
#endif
// end_winnt

#if (NTDDI_VERSION >= NTDDI_WINXP)
NTSYSAPI
PVOID
NTAPI
RtlDestroyHeap(
    __in __post_invalid PVOID HeapHandle
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTSYSAPI
__checkReturn
__bcount_opt(Size) __allocator
PVOID
NTAPI
RtlAllocateHeap(
    __in PVOID HeapHandle,
    __in_opt ULONG Flags,
    __in SIZE_T Size
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__success(return != 0)
NTSYSAPI
BOOLEAN
NTAPI
RtlFreeHeap(
    __in PVOID HeapHandle,
    __in_opt ULONG Flags,
    __in __post_invalid  PVOID BaseAddress
    );
#endif // NTDDI_VERSION >= NTDDI_WIN2K



#if (NTDDI_VERSION > NTDDI_WINXP)
NTSYSAPI
USHORT
NTAPI
RtlCaptureStackBackTrace(
    __in ULONG FramesToSkip,
    __in ULONG FramesToCapture,
    __out_ecount(FramesToCapture) PVOID *BackTrace,
    __out_opt PULONG BackTraceHash
   );
#endif

#if (NTDDI_VERSION > NTDDI_WIN2K)
NTSYSAPI
VOID
NTAPI
RtlCaptureContext (
    __out PCONTEXT ContextRecord
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__range(<, MAXLONG)
NTSYSAPI
ULONG
NTAPI
RtlRandom (
    __inout PULONG Seed
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
__range(<, MAXLONG)
NTSYSAPI
ULONG
NTAPI
RtlRandomEx (
    __inout PULONG Seed
    );
#endif // NTDDI_VERSION >= NTDDI_WINXP

#if (NTDDI_VERSION >= NTDDI_WINXP)
__drv_maxIRQL(DISPATCH_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
RtlInitUnicodeStringEx(
    __out PUNICODE_STRING DestinationString,
    __in_z_opt __drv_aliasesMem PCWSTR SourceString
    );
#endif // NTDDI_VERSION >= NTDDI_WINXP

#if (NTDDI_VERSION >= NTDDI_WS03)
__drv_maxIRQL(DISPATCH_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
RtlInitAnsiStringEx(
    __out PANSI_STRING DestinationString,
    __in_z_opt __drv_aliasesMem PCSZ SourceString
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
__success(return != 0)
__checkReturn
NTSYSAPI
BOOLEAN
NTAPI
RtlCreateUnicodeString(
    __out __drv_at(DestinationString->Buffer, __drv_allocatesMem(Mem))
        PUNICODE_STRING DestinationString,
    __in_z PCWSTR SourceString
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
RtlAppendStringToString (
    __inout PSTRING Destination,
    __in const STRING * Source
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
__checkReturn
NTSYSAPI
NTSTATUS
NTAPI
RtlOemStringToUnicodeString(
    __drv_when(AllocateDestinationString, __out __drv_at(DestinationString->Buffer, __drv_allocatesMem(Mem)))
    __drv_when(!AllocateDestinationString, __inout)
        PUNICODE_STRING DestinationString,
    __in PCOEM_STRING SourceString,
    __in BOOLEAN AllocateDestinationString
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
__checkReturn
NTSYSAPI
NTSTATUS
NTAPI
RtlUnicodeStringToOemString(
    __drv_when(AllocateDestinationString, __out __drv_at(DestinationString->Buffer, __drv_allocatesMem(Mem)))
    __drv_when(!AllocateDestinationString, __inout)
        POEM_STRING DestinationString,
    __in PCUNICODE_STRING SourceString,
    __in BOOLEAN AllocateDestinationString
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
__checkReturn
NTSYSAPI
NTSTATUS
NTAPI
RtlUpcaseUnicodeStringToOemString(
    __drv_when(AllocateDestinationString, __out __drv_at(DestinationString->Buffer, __drv_allocatesMem(Mem)))
    __drv_when(!AllocateDestinationString, __inout)
        POEM_STRING DestinationString,
    __in PCUNICODE_STRING SourceString,
    __in BOOLEAN AllocateDestinationString
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
__checkReturn
NTSYSAPI
NTSTATUS
NTAPI
RtlOemStringToCountedUnicodeString(
    __drv_when(AllocateDestinationString, __out __drv_at(DestinationString->Buffer, __drv_allocatesMem(Mem)))
    __drv_when(!AllocateDestinationString, __inout)
        PUNICODE_STRING DestinationString,
    __in PCOEM_STRING SourceString,
    __in BOOLEAN AllocateDestinationString
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
__checkReturn
NTSYSAPI
NTSTATUS
NTAPI
RtlUnicodeStringToCountedOemString(
    __drv_when(AllocateDestinationString, __out __drv_at(DestinationString->Buffer, __drv_allocatesMem(Mem)))
    __drv_when(!AllocateDestinationString, __inout)
        POEM_STRING DestinationString,
    __in PCUNICODE_STRING SourceString,
    __in BOOLEAN AllocateDestinationString
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
__checkReturn
NTSYSAPI
NTSTATUS
NTAPI
RtlUpcaseUnicodeStringToCountedOemString(
    __drv_when(AllocateDestinationString, __out __drv_at(DestinationString->Buffer, __drv_allocatesMem(Mem)))
    __drv_when(!AllocateDestinationString, __inout)
        POEM_STRING DestinationString,
    __in PCUNICODE_STRING SourceString,
    __in BOOLEAN AllocateDestinationString
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WINXP)
__checkReturn
NTSYSAPI
NTSTATUS
NTAPI
RtlValidateUnicodeString(
    __in __reserved ULONG Flags,
    __in PCUNICODE_STRING String
    );
#endif // NTDDI_VERSION >= NTDDI_WINXP


#define RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE (0x00000001)
#define RTL_DUPLICATE_UNICODE_STRING_ALLOCATE_NULL_STRING (0x00000002)

#if (NTDDI_VERSION >= NTDDI_WINXP)
__drv_maxIRQL(PASSIVE_LEVEL)
__checkReturn
NTSYSAPI
NTSTATUS
NTAPI
RtlDuplicateUnicodeString(
    __in ULONG Flags,
    __in PCUNICODE_STRING StringIn,
    __out __drv_at(StringOut->Buffer, __drv_allocatesMem(Mem))
        PUNICODE_STRING StringOut
    );
#endif // NTDDI_VERSION >= NTDDI_WINXP


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
__drv_when(AllocateDestinationString, __checkReturn)
NTSYSAPI
NTSTATUS
NTAPI
RtlDowncaseUnicodeString(
    __drv_when(AllocateDestinationString, __out __drv_at(DestinationString->Buffer, __drv_allocatesMem(Mem)))
    __drv_when(!AllocateDestinationString, __inout)
        PUNICODE_STRING DestinationString,
    __in PCUNICODE_STRING SourceString,
    __in BOOLEAN AllocateDestinationString
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
VOID
NTAPI
RtlFreeOemString(
    __inout __drv_at(OemString->Buffer, __drv_freesMem(Mem))
        POEM_STRING OemString
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
ULONG
NTAPI
RtlxUnicodeStringToOemSize(
    __in PCUNICODE_STRING UnicodeString
    );
#endif

//
//  NTSYSAPI
//  ULONG
//  NTAPI
//  RtlUnicodeStringToOemSize(
//      PUNICODE_STRING UnicodeString
//      );
//

#define RtlUnicodeStringToOemSize(STRING) (                   \
    NLS_MB_OEM_CODE_PAGE_TAG ?                                \
    RtlxUnicodeStringToOemSize(STRING) :                      \
    ((STRING)->Length + sizeof(UNICODE_NULL)) / sizeof(WCHAR) \
)


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
ULONG
NTAPI
RtlxOemStringToUnicodeSize(
    __in PCOEM_STRING OemString
    );
#endif

//
//  NTSYSAPI
//  ULONG
//  NTAPI
//  RtlOemStringToUnicodeSize(
//      POEM_STRING OemString
//      );
//

#define RtlOemStringToUnicodeSize(STRING) (                  \
    NLS_MB_OEM_CODE_PAGE_TAG ?                               \
    RtlxOemStringToUnicodeSize(STRING) :                     \
    ((STRING)->Length + sizeof(ANSI_NULL)) * sizeof(WCHAR) \
)

//
//  ULONG
//  RtlOemStringToCountedUnicodeSize(
//      POEM_STRING OemString
//      );
//

#define RtlOemStringToCountedUnicodeSize(STRING) (                    \
    (ULONG)(RtlOemStringToUnicodeSize(STRING) - sizeof(UNICODE_NULL)) \
    )

// Use Unicode if possible
#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
RtlMultiByteToUnicodeN(
    __out_bcount_part(MaxBytesInUnicodeString, *BytesInUnicodeString) PWCH UnicodeString,
    __in ULONG MaxBytesInUnicodeString,
    __out_opt PULONG BytesInUnicodeString,
    __in_bcount(BytesInMultiByteString) const CHAR *MultiByteString,
    __in ULONG BytesInMultiByteString
    );
#endif

// Use Unicode if possible
#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
RtlMultiByteToUnicodeSize(
    __out PULONG BytesInUnicodeString,
    __in_bcount(BytesInMultiByteString) const CHAR *MultiByteString,
    __in ULONG BytesInMultiByteString
    );
#endif

// Use Unicode if possible
#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
RtlUnicodeToMultiByteSize(
    __out PULONG BytesInMultiByteString,
    __in_bcount(BytesInUnicodeString) PCWCH UnicodeString,
    __in ULONG BytesInUnicodeString
    );
#endif

// Use Unicode if possible
#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
RtlUnicodeToMultiByteN(
    __out_bcount_part(MaxBytesInMultiByteString, *BytesInMultiByteString) PCHAR MultiByteString,
    __in ULONG MaxBytesInMultiByteString,
    __out_opt PULONG BytesInMultiByteString,
    __in_bcount(BytesInUnicodeString) PCWCH UnicodeString,
    __in ULONG BytesInUnicodeString
    );
#endif

// UTF 8 conversion

// begin_wdm
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
// end_wdm

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
RtlUpcaseUnicodeToMultiByteN(
    __out_bcount_part(MaxBytesInMultiByteString, *BytesInMultiByteString) PCHAR MultiByteString,
    __in ULONG MaxBytesInMultiByteString,
    __out_opt PULONG BytesInMultiByteString,
    __in_bcount(BytesInUnicodeString) PCWCH UnicodeString,
    __in ULONG BytesInUnicodeString
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
RtlOemToUnicodeN(
    __out_bcount_part(MaxBytesInUnicodeString, *BytesInUnicodeString) PWCH UnicodeString,
    __in ULONG MaxBytesInUnicodeString,
    __out_opt PULONG BytesInUnicodeString,
    __in_bcount(BytesInOemString) PCCH OemString,
    __in ULONG BytesInOemString
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
RtlUnicodeToOemN(
    __out_bcount_part(MaxBytesInOemString, *BytesInOemString) PCHAR OemString,
    __in ULONG MaxBytesInOemString,
    __out_opt PULONG BytesInOemString,
    __in_bcount(BytesInUnicodeString) PCWCH UnicodeString,
    __in ULONG BytesInUnicodeString
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
RtlUpcaseUnicodeToOemN(
    __out_bcount_part(MaxBytesInOemString, *BytesInOemString) PCHAR OemString,
    __in ULONG MaxBytesInOemString,
    __out_opt PULONG BytesInOemString,
    __in_bcount(BytesInUnicodeString) PCWCH UnicodeString,
    __in ULONG BytesInUnicodeString
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
NTSYSAPI
NTSTATUS
NTAPI
RtlNormalizeString(
    __in ULONG NormForm,
    __in PCWSTR SourceString,
    __in LONG SourceStringLength,
    __out_ecount_part(*DestinationStringLength, *DestinationStringLength) PWSTR DestinationString,
    __inout PLONG DestinationStringLength
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
NTSYSAPI
NTSTATUS
NTAPI
RtlIsNormalizedString(
    __in ULONG NormForm,
    __in PCWSTR SourceString,
    __in LONG SourceStringLength,
    __out PBOOLEAN Normalized
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
NTSYSAPI
NTSTATUS
NTAPI
RtlIdnToAscii(
    __in ULONG Flags,
    __in PCWSTR SourceString,
    __in LONG SourceStringLength,
    __out_ecount_part(*DestinationStringLength, *DestinationStringLength) PWSTR DestinationString,
    __inout PLONG DestinationStringLength
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
NTSYSAPI
NTSTATUS
NTAPI
RtlIdnToUnicode(
    __in ULONG Flags,
    __in PCWSTR SourceString,
    __in LONG SourceStringLength,
    __out_ecount_part(*DestinationStringLength, *DestinationStringLength) PWSTR DestinationString,
    __inout PLONG DestinationStringLength
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
NTSYSAPI
NTSTATUS
NTAPI
RtlIdnToNameprepUnicode(
    __in ULONG Flags,
    __in PCWSTR SourceString,
    __in LONG SourceStringLength,
    __out_ecount_part(*DestinationStringLength, *DestinationStringLength) PWSTR DestinationString,
    __inout PLONG DestinationStringLength
    );
#endif


typedef
__drv_functionClass(RTL_ALLOCATE_STRING_ROUTINE)
__drv_maxIRQL(PASSIVE_LEVEL)
__drv_allocatesMem(Mem)
PVOID
NTAPI
RTL_ALLOCATE_STRING_ROUTINE (
    __in SIZE_T NumberOfBytes
    );
typedef RTL_ALLOCATE_STRING_ROUTINE *PRTL_ALLOCATE_STRING_ROUTINE;

#if _WIN32_WINNT >= 0x0600

typedef
__drv_functionClass(RTL_REALLOCATE_STRING_ROUTINE)
__drv_maxIRQL(PASSIVE_LEVEL)
__drv_allocatesMem(Mem)
PVOID
NTAPI
RTL_REALLOCATE_STRING_ROUTINE(
    __in SIZE_T NumberOfBytes,
    __in __drv_freesMem(Mem) __post_invalid PVOID Buffer
    );
typedef RTL_REALLOCATE_STRING_ROUTINE *PRTL_REALLOCATE_STRING_ROUTINE;

#endif // _WIN32_WINNT >= 0x0600

typedef
__drv_functionClass(RTL_FREE_STRING_ROUTINE)
__drv_maxIRQL(PASSIVE_LEVEL)
VOID
NTAPI
RTL_FREE_STRING_ROUTINE (
    __in __drv_freesMem(Mem) __post_invalid PVOID Buffer
    );
typedef RTL_FREE_STRING_ROUTINE *PRTL_FREE_STRING_ROUTINE;

extern const PRTL_ALLOCATE_STRING_ROUTINE RtlAllocateStringRoutine;
extern const PRTL_FREE_STRING_ROUTINE RtlFreeStringRoutine;

#if _WIN32_WINNT >= 0x0600
extern const PRTL_REALLOCATE_STRING_ROUTINE RtlReallocateStringRoutine;
#endif // _WIN32_WINNT >= 0x0600

//
//  Defines and Routines for handling GUID's.
//

//
//  Routine for generating 8.3 names from long names.
//

//
//  The context structure is used when generating 8.3 names.  The caller must
//  always zero out the structure before starting a new generation sequence
//

typedef struct _GENERATE_NAME_CONTEXT {

    //
    //  The structure is divided into two strings.  The Name, and extension.
    //  Each part contains the value that was last inserted in the name.
    //  The length values are in terms of wchars and not bytes.  We also
    //  store the last index value used in the generation collision algorithm.
    //

    USHORT Checksum;
    BOOLEAN ChecksumInserted;

    __field_range(<=, 8) UCHAR NameLength;        // not including extension
    WCHAR NameBuffer[8];                          // e.g., "ntoskrnl"

    __field_range(<=, 4) ULONG ExtensionLength;   // including dot
    WCHAR ExtensionBuffer[4];                     // e.g., ".exe"

    ULONG LastIndexValue;

} GENERATE_NAME_CONTEXT;
typedef GENERATE_NAME_CONTEXT *PGENERATE_NAME_CONTEXT;

#if (NTDDI_VERSION >= NTDDI_WIN2K)
#if (NTDDI_VERSION >= NTDDI_VISTASP1)
//
//  In Vista SP1 and beyond this routine now returns
//  STATUS_FILE_SYSTEM_LIMITATION if the system can not generate a unique
//  shortname for a given file.  It returns this error after 1 million retry
//  attempts for a single given longname.
//

__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
RtlGenerate8dot3Name (
    __in    PCUNICODE_STRING Name,
    __in    BOOLEAN AllowExtendedCharacters,
    __inout PGENERATE_NAME_CONTEXT Context,
    __inout PUNICODE_STRING Name8dot3
    );
#else   // (NTDDI_VERSION < NTDDI_VISTASP1)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
VOID
NTAPI
RtlGenerate8dot3Name (
    __in    PCUNICODE_STRING Name,
    __in    BOOLEAN AllowExtendedCharacters,
    __inout PGENERATE_NAME_CONTEXT Context,
    __inout PUNICODE_STRING Name8dot3
    );
#endif
#endif  // (NTDDI_VERSION >= NTDDI_WIN2K)

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
__checkReturn
NTSYSAPI
BOOLEAN
NTAPI
RtlIsNameLegalDOS8Dot3 (
    __in PCUNICODE_STRING Name,
    __inout_opt POEM_STRING OemName,
    __out_opt PBOOLEAN NameContainsSpaces
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
__checkReturn
NTSYSAPI
BOOLEAN
NTAPI
RtlIsValidOemCharacter (
    __inout PWCHAR Char
    );
#endif

//
//  Prefix package types and procedures.
//
//  Note that the following two record structures should really be opaque
//  to the user of this package.  The only information about the two
//  structures available for the user should be the size and alignment
//  of the structures.
//

typedef struct _PREFIX_TABLE_ENTRY {
    CSHORT NodeTypeCode;
    CSHORT NameLength;
    struct _PREFIX_TABLE_ENTRY *NextPrefixTree;
    RTL_SPLAY_LINKS Links;
    PSTRING Prefix;
} PREFIX_TABLE_ENTRY;
typedef PREFIX_TABLE_ENTRY *PPREFIX_TABLE_ENTRY;

typedef struct _PREFIX_TABLE {
    CSHORT NodeTypeCode;
    CSHORT NameLength;
    PPREFIX_TABLE_ENTRY NextPrefixTree;
} PREFIX_TABLE;
typedef PREFIX_TABLE *PPREFIX_TABLE;

//
//  The procedure prototypes for the prefix package
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
VOID
NTAPI
PfxInitialize (
    __out PPREFIX_TABLE PrefixTable
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
BOOLEAN
NTAPI
PfxInsertPrefix (
    __in PPREFIX_TABLE PrefixTable,
    __in __drv_aliasesMem PSTRING Prefix,
    __out PPREFIX_TABLE_ENTRY PrefixTableEntry
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
VOID
NTAPI
PfxRemovePrefix (
    __in PPREFIX_TABLE PrefixTable,
    __in PPREFIX_TABLE_ENTRY PrefixTableEntry
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
__checkReturn
NTSYSAPI
PPREFIX_TABLE_ENTRY
NTAPI
PfxFindPrefix (
    __in PPREFIX_TABLE PrefixTable,
    __in PSTRING FullName
    );
#endif

//
//  The following definitions are for the unicode version of the prefix
//  package.
//

typedef struct _UNICODE_PREFIX_TABLE_ENTRY {
    CSHORT NodeTypeCode;
    CSHORT NameLength;
    struct _UNICODE_PREFIX_TABLE_ENTRY *NextPrefixTree;
    struct _UNICODE_PREFIX_TABLE_ENTRY *CaseMatch;
    RTL_SPLAY_LINKS Links;
    PUNICODE_STRING Prefix;
} UNICODE_PREFIX_TABLE_ENTRY;
typedef UNICODE_PREFIX_TABLE_ENTRY *PUNICODE_PREFIX_TABLE_ENTRY;

typedef struct _UNICODE_PREFIX_TABLE {
    CSHORT NodeTypeCode;
    CSHORT NameLength;
    PUNICODE_PREFIX_TABLE_ENTRY NextPrefixTree;
    PUNICODE_PREFIX_TABLE_ENTRY LastNextEntry;
} UNICODE_PREFIX_TABLE;
typedef UNICODE_PREFIX_TABLE *PUNICODE_PREFIX_TABLE;

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
VOID
NTAPI
RtlInitializeUnicodePrefix (
    __out PUNICODE_PREFIX_TABLE PrefixTable
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
BOOLEAN
NTAPI
RtlInsertUnicodePrefix (
    __in PUNICODE_PREFIX_TABLE PrefixTable,
    __in __drv_aliasesMem PUNICODE_STRING Prefix,
    __out PUNICODE_PREFIX_TABLE_ENTRY PrefixTableEntry
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
VOID
NTAPI
RtlRemoveUnicodePrefix (
    __in PUNICODE_PREFIX_TABLE PrefixTable,
    __in PUNICODE_PREFIX_TABLE_ENTRY PrefixTableEntry
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
__checkReturn
NTSYSAPI
PUNICODE_PREFIX_TABLE_ENTRY
NTAPI
RtlFindUnicodePrefix (
    __in PUNICODE_PREFIX_TABLE PrefixTable,
    __in PCUNICODE_STRING FullName,
    __in ULONG CaseInsensitiveIndex
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
__checkReturn
NTSYSAPI
PUNICODE_PREFIX_TABLE_ENTRY
NTAPI
RtlNextUnicodePrefix (
    __in PUNICODE_PREFIX_TABLE PrefixTable,
    __in BOOLEAN Restart
    );
#endif

//
//
//  Compression package types and procedures.
//

#define COMPRESSION_FORMAT_NONE          (0x0000)   // winnt
#define COMPRESSION_FORMAT_DEFAULT       (0x0001)   // winnt
#define COMPRESSION_FORMAT_LZNT1         (0x0002)   // winnt

#define COMPRESSION_ENGINE_STANDARD      (0x0000)   // winnt
#define COMPRESSION_ENGINE_MAXIMUM       (0x0100)   // winnt
#define COMPRESSION_ENGINE_HIBER         (0x0200)   // winnt

//
//  Compressed Data Information structure.  This structure is
//  used to describe the state of a compressed data buffer,
//  whose uncompressed size is known.  All compressed chunks
//  described by this structure must be compressed with the
//  same format.  On compressed reads, this entire structure
//  is an output, and on compressed writes the entire structure
//  is an input.
//

typedef struct _COMPRESSED_DATA_INFO {

    //
    //  Code for the compression format (and engine) as
    //  defined in ntrtl.h.  Note that COMPRESSION_FORMAT_NONE
    //  and COMPRESSION_FORMAT_DEFAULT are invalid if
    //  any of the described chunks are compressed.
    //

    USHORT CompressionFormatAndEngine;

    //
    //  Since chunks and compression units are expected to be
    //  powers of 2 in size, we express then log2.  So, for
    //  example (1 << ChunkShift) == ChunkSizeInBytes.  The
    //  ClusterShift indicates how much space must be saved
    //  to successfully compress a compression unit - each
    //  successfully compressed compression unit must occupy
    //  at least one cluster less in bytes than an uncompressed
    //  compression unit.
    //

    UCHAR CompressionUnitShift;
    UCHAR ChunkShift;
    UCHAR ClusterShift;
    UCHAR Reserved;

    //
    //  This is the number of entries in the CompressedChunkSizes
    //  array.
    //

    USHORT NumberOfChunks;

    //
    //  This is an array of the sizes of all chunks resident
    //  in the compressed data buffer.  There must be one entry
    //  in this array for each chunk possible in the uncompressed
    //  buffer size.  A size of FSRTL_CHUNK_SIZE indicates the
    //  corresponding chunk is uncompressed and occupies exactly
    //  that size.  A size of 0 indicates that the corresponding
    //  chunk contains nothing but binary 0's, and occupies no
    //  space in the compressed data.  All other sizes must be
    //  less than FSRTL_CHUNK_SIZE, and indicate the exact size
    //  of the compressed data in bytes.
    //

    ULONG CompressedChunkSizes[ANYSIZE_ARRAY];

} COMPRESSED_DATA_INFO;
typedef COMPRESSED_DATA_INFO *PCOMPRESSED_DATA_INFO;

#if (NTDDI_VERSION >= NTDDI_WINXP)
NTSYSAPI
NTSTATUS
NTAPI
RtlGetCompressionWorkSpaceSize (
    __in USHORT CompressionFormatAndEngine,
    __out PULONG CompressBufferWorkSpaceSize,
    __out PULONG CompressFragmentWorkSpaceSize
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
NTSYSAPI
NTSTATUS
NTAPI
RtlCompressBuffer (
    __in USHORT CompressionFormatAndEngine,
    __in_bcount(UncompressedBufferSize) PUCHAR UncompressedBuffer,
    __in ULONG UncompressedBufferSize,
    __out_bcount_part(CompressedBufferSize, *FinalCompressedSize) PUCHAR CompressedBuffer,
    __in ULONG CompressedBufferSize,
    __in ULONG UncompressedChunkSize,
    __out PULONG FinalCompressedSize,
    __in PVOID WorkSpace
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
__drv_maxIRQL(APC_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
RtlDecompressBuffer (
    __in USHORT CompressionFormat,
    __out_bcount_part(UncompressedBufferSize, *FinalUncompressedSize) PUCHAR UncompressedBuffer,
    __in ULONG UncompressedBufferSize,
    __in_bcount(CompressedBufferSize) PUCHAR CompressedBuffer,
    __in ULONG CompressedBufferSize,
    __out PULONG FinalUncompressedSize
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
__drv_maxIRQL(APC_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
RtlDecompressFragment (
    __in USHORT CompressionFormat,
    __out_bcount_part(UncompressedFragmentSize, *FinalUncompressedSize) PUCHAR UncompressedFragment,
    __in ULONG UncompressedFragmentSize,
    __in_bcount(CompressedBufferSize) PUCHAR CompressedBuffer,
    __in ULONG CompressedBufferSize,
    __in_range(<, CompressedBufferSize) ULONG FragmentOffset,
    __out PULONG FinalUncompressedSize,
    __in PVOID WorkSpace
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
__drv_maxIRQL(APC_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
RtlDescribeChunk (
    __in USHORT CompressionFormat,
    __inout PUCHAR *CompressedBuffer,
    __in PUCHAR EndOfCompressedBufferPlus1,
    __out PUCHAR *ChunkBuffer,
    __out PULONG ChunkSize
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
__drv_maxIRQL(APC_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
RtlReserveChunk (
    __in USHORT CompressionFormat,
    __inout PUCHAR *CompressedBuffer,
    __in PUCHAR EndOfCompressedBufferPlus1,
    __out PUCHAR *ChunkBuffer,
    __in ULONG ChunkSize
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
__drv_maxIRQL(APC_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
RtlDecompressChunks (
    __out_bcount(UncompressedBufferSize) PUCHAR UncompressedBuffer,
    __in ULONG UncompressedBufferSize,
    __in_bcount(CompressedBufferSize) PUCHAR CompressedBuffer,
    __in ULONG CompressedBufferSize,
    __in_bcount(CompressedTailSize) PUCHAR CompressedTail,
    __in ULONG CompressedTailSize,
    __in PCOMPRESSED_DATA_INFO CompressedDataInfo
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
__drv_maxIRQL(APC_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
RtlCompressChunks (
    __in_bcount(UncompressedBufferSize) PUCHAR UncompressedBuffer,
    __in ULONG UncompressedBufferSize,
    __out_bcount(CompressedBufferSize) PUCHAR CompressedBuffer,
    __in_range(>=, (UncompressedBufferSize - (UncompressedBufferSize / 16))) ULONG CompressedBufferSize,
    __inout_bcount(CompressedDataInfoLength) PCOMPRESSED_DATA_INFO CompressedDataInfo,
    __in_range(>, sizeof(COMPRESSED_DATA_INFO)) ULONG CompressedDataInfoLength,
    __in PVOID WorkSpace
    );
#endif // NTDDI_VERSION >= NTDDI_WINXP


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn
NTSYSAPI
SIZE_T
NTAPI
RtlCompareMemoryUlong (
    __in_bcount(Length) PVOID Source,
    __in SIZE_T Length,
    __in ULONG Pattern
    );

#endif

#if defined(_M_AMD64)

#if !defined(MIDL_PASS)

FORCEINLINE
VOID
RtlFillMemoryUlong (
    __out_bcount_full(Length) PVOID Destination,
    __in SIZE_T Length,
    __in ULONG Pattern
    )

{

    PULONG Address = (PULONG)Destination;

    //
    // If the number of DWORDs is not zero, then fill the specified buffer
    // with the specified pattern.
    //

    if ((Length /= 4) != 0) {

        //
        // If the destination is not quadword aligned (ignoring low bits),
        // then align the destination by storing one DWORD.
        //

        if (((ULONG64)Address & 4) != 0) {
            *Address = Pattern;
            if ((Length -= 1) == 0) {
                return;
            }

            Address += 1;
        }

        //
        // If the number of QWORDs is not zero, then fill the destination
        // buffer a QWORD at a time.
        //

         __stosq((PULONG64)(Address),
                 Pattern | ((ULONG64)Pattern << 32),
                 Length / 2);

        if ((Length & 1) != 0) {
            Address[Length - 1] = Pattern;
        }
    }

    return;
}

#define RtlFillMemoryUlonglong(Destination, Length, Pattern)                \
    __stosq((PULONG64)(Destination), Pattern, (Length) / 8)

#endif

#else

#if (NTDDI_VERSION >= NTDDI_WINXP)
NTSYSAPI
VOID
NTAPI
RtlFillMemoryUlong (
    __out_bcount_full(Length) PVOID Destination,
    __in SIZE_T Length,
    __in ULONG Pattern
   );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
NTSYSAPI
VOID
NTAPI
RtlFillMemoryUlonglong (
   __out_bcount_full(Length) PVOID Destination,
   __in SIZE_T Length,
   __in ULONGLONG Pattern
   );
#endif

#endif // defined(_M_AMD64)



//
//  A 64 bit Time value -> Seconds since the start of 1980
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__success(return != 0)
NTSYSAPI
BOOLEAN
NTAPI
RtlTimeToSecondsSince1980 (
    __in PLARGE_INTEGER Time,
    __out PULONG ElapsedSeconds
    );
#endif

//
//  Seconds since the start of 1980 -> 64 bit Time value
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTSYSAPI
VOID
NTAPI
RtlSecondsSince1980ToTime (
    __in ULONG ElapsedSeconds,
    __out PLARGE_INTEGER Time
    );
#endif

//
//  A 64 bit Time value -> Seconds since the start of 1970
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__success(return != 0)
NTSYSAPI
BOOLEAN
NTAPI
RtlTimeToSecondsSince1970 (
    __in PLARGE_INTEGER Time,
    __out PULONG ElapsedSeconds
    );
#endif

//
//  Seconds since the start of 1970 -> 64 bit Time value
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTSYSAPI
VOID
NTAPI
RtlSecondsSince1970ToTime (
    __in ULONG ElapsedSeconds,
    __out PLARGE_INTEGER Time
    );
#endif


//++
//
// PCHAR
// RtlOffsetToPointer (
//     PVOID Base,
//     ULONG Offset
//     )
//
// Routine Description:
//
// This macro generates a pointer which points to the byte that is 'Offset'
// bytes beyond 'Base'. This is useful for referencing fields within
// self-relative data structures.
//
// Arguments:
//
//     Base - The address of the base of the structure.
//
//     Offset - An unsigned integer offset of the byte whose address is to
//         be generated.
//
// Return Value:
//
//     A PCHAR pointer to the byte that is 'Offset' bytes beyond 'Base'.
//
//
//--

#define RtlOffsetToPointer(B,O)  ((PCHAR)( ((PCHAR)(B)) + ((ULONG_PTR)(O))  ))


//++
//
// ULONG
// RtlPointerToOffset (
//     PVOID Base,
//     PVOID Pointer
//     )
//
// Routine Description:
//
// This macro calculates the offset from Base to Pointer.  This is useful
// for producing self-relative offsets for structures.
//
// Arguments:
//
//     Base - The address of the base of the structure.
//
//     Pointer - A pointer to a field, presumably within the structure
//         pointed to by Base.  This value must be larger than that specified
//         for Base.
//
// Return Value:
//
//     A ULONG offset from Base to Pointer.
//
//
//--

#define RtlPointerToOffset(B,P)  ((ULONG)( ((PCHAR)(P)) - ((PCHAR)(B))  ))

//
//  Security ID RTL routine definitions
//


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
__checkReturn
NTSYSAPI
BOOLEAN
NTAPI
RtlValidSid (
    __in PSID Sid
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn
NTSYSAPI
BOOLEAN
NTAPI
RtlEqualSid (
    __in PSID Sid1,
    __in PSID Sid2
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
__checkReturn
NTSYSAPI
BOOLEAN
NTAPI
RtlEqualPrefixSid (
    __in PSID Sid1,
    __in PSID Sid2
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTSYSAPI
ULONG
NTAPI
RtlLengthRequiredSid (
    __in ULONG SubAuthorityCount
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTSYSAPI
PVOID
NTAPI
RtlFreeSid(
    __in __post_invalid PSID Sid
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn
NTSYSAPI
NTSTATUS
NTAPI
RtlAllocateAndInitializeSid(
    __in PSID_IDENTIFIER_AUTHORITY IdentifierAuthority,
    __in UCHAR SubAuthorityCount,
    __in ULONG SubAuthority0,
    __in ULONG SubAuthority1,
    __in ULONG SubAuthority2,
    __in ULONG SubAuthority3,
    __in ULONG SubAuthority4,
    __in ULONG SubAuthority5,
    __in ULONG SubAuthority6,
    __in ULONG SubAuthority7,
    __deref_out PSID *Sid
    );
#endif // NTDDI_VERSION >= NTDDI_WIN2K


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
RtlInitializeSid (
    __out PSID Sid,
    __in PSID_IDENTIFIER_AUTHORITY IdentifierAuthority,
    __in UCHAR SubAuthorityCount
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WINXP)
__drv_maxIRQL(APC_LEVEL)
NTSYSAPI
PSID_IDENTIFIER_AUTHORITY
NTAPI
RtlIdentifierAuthoritySid (
    __in PSID Sid
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTSYSAPI
PULONG
NTAPI
RtlSubAuthoritySid (
    __in PSID Sid,
    __in ULONG SubAuthority
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
NTSYSAPI
PUCHAR
NTAPI
RtlSubAuthorityCountSid (
    __in PSID Sid
    );
#endif // NTDDI_VERSION >= NTDDI_WINXP

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTSYSAPI
ULONG
NTAPI
RtlLengthSid (
    __in PSID Sid
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
RtlCopySid (
    __in ULONG DestinationSidLength,
    __in_bcount(DestinationSidLength) PSID DestinationSid,
    __in PSID SourceSid
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
NTSYSAPI
NTSTATUS
NTAPI
RtlCreateServiceSid(
    __in PUNICODE_STRING ServiceName,
    __out_bcount(*ServiceSidLength) PSID ServiceSid,
    __inout PULONG ServiceSidLength
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
__drv_maxIRQL(APC_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
RtlGetSaclSecurityDescriptor (
    __in PSECURITY_DESCRIPTOR SecurityDescriptor,
    __out PBOOLEAN SaclPresent,
    __out PACL *Sacl,
    __out PBOOLEAN SaclDefaulted
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
__drv_maxIRQL(APC_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
RtlReplaceSidInSd(
    __inout PSECURITY_DESCRIPTOR SecurityDescriptor,
    __in PSID OldSid,
    __in PSID NewSid,
    __out ULONG *NumChanges
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlCreateVirtualAccountSid (
    __in PCUNICODE_STRING Name,
    __in ULONG BaseSubAuthority,
    __out_bcount(*SidLength) PSID Sid,
    __inout PULONG SidLength
    );
#endif

//
// MAX_UNICODE_STACK_BUFFER_LENGTH is the maximum stack buffer
// that RtlConvertSidToUnicodeString can fill if the caller
// specifies AllocateDestinationString = FALSE.
//

#define MAX_UNICODE_STACK_BUFFER_LENGTH 256

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
RtlConvertSidToUnicodeString(
    __inout PUNICODE_STRING UnicodeString,
    __in PSID Sid,
    __in BOOLEAN AllocateDestinationString
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTSYSAPI
VOID
NTAPI
RtlCopyLuid (
    __out PLUID DestinationLuid,
    __in PLUID SourceLuid
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
RtlCreateAcl (
    __out_bcount(AclLength) PACL Acl,
    __in ULONG AclLength,
    __in ULONG AclRevision
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
RtlAddAce (
    __inout PACL Acl,
    __in ULONG AceRevision,
    __in ULONG StartingAceIndex,
    __in_bcount(AceListLength) PVOID AceList,
    __in ULONG AceListLength
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
RtlDeleteAce (
    __inout PACL Acl,
    __in ULONG AceIndex
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTSYSAPI
NTSTATUS
NTAPI
RtlGetAce (
    __in PACL Acl,
    __in ULONG AceIndex,
    __deref_out PVOID *Ace
    );
#endif // NTDDI_VERSION >= NTDDI_WIN2K

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
RtlAddAccessAllowedAce (
    __inout PACL Acl,
    __in ULONG AceRevision,
    __in ACCESS_MASK AccessMask,
    __in PSID Sid
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
RtlAddAccessAllowedAceEx (
    __inout PACL Acl,
    __in ULONG AceRevision,
    __in ULONG AceFlags,
    __in ACCESS_MASK AccessMask,
    __in PSID Sid
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
RtlCreateSecurityDescriptorRelative (
    __out PISECURITY_DESCRIPTOR_RELATIVE SecurityDescriptor,
    __in ULONG Revision
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTSYSAPI
NTSTATUS
NTAPI
RtlGetDaclSecurityDescriptor (
    __in PSECURITY_DESCRIPTOR SecurityDescriptor,
    __out PBOOLEAN DaclPresent,
    __out PACL *Dacl,
    __out PBOOLEAN DaclDefaulted
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
RtlSetOwnerSecurityDescriptor (
    __inout PSECURITY_DESCRIPTOR SecurityDescriptor,
    __in_opt PSID Owner,
    __in_opt BOOLEAN OwnerDefaulted
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
__drv_maxIRQL(APC_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
RtlSetGroupSecurityDescriptor (
    __inout PSECURITY_DESCRIPTOR SecurityDescriptor,
    __in_opt PSID Group,
    __in_opt BOOLEAN GroupDefaulted
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
__drv_maxIRQL(APC_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
RtlGetGroupSecurityDescriptor (
    __in PSECURITY_DESCRIPTOR SecurityDescriptor,
    __out PSID *Group,
    __out PBOOLEAN GroupDefaulted
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
__drv_maxIRQL(APC_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
RtlAbsoluteToSelfRelativeSD (
    __in PSECURITY_DESCRIPTOR AbsoluteSecurityDescriptor,
    __out_bcount_part_opt(*BufferLength, *BufferLength) PSECURITY_DESCRIPTOR SelfRelativeSecurityDescriptor,
    __inout PULONG BufferLength
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
__drv_maxIRQL(APC_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
RtlSelfRelativeToAbsoluteSD (
    __in PSECURITY_DESCRIPTOR SelfRelativeSecurityDescriptor,
    __out_bcount_part_opt(*AbsoluteSecurityDescriptorSize, *AbsoluteSecurityDescriptorSize) PSECURITY_DESCRIPTOR AbsoluteSecurityDescriptor,
    __inout PULONG AbsoluteSecurityDescriptorSize,
    __out_bcount_part_opt(*DaclSize, *DaclSize) PACL Dacl,
    __inout PULONG DaclSize,
    __out_bcount_part_opt(*SaclSize, *SaclSize) PACL Sacl,
    __inout PULONG SaclSize,
    __out_bcount_part_opt(*OwnerSize, *OwnerSize) PSID Owner,
    __inout PULONG OwnerSize,
    __out_bcount_part_opt(*PrimaryGroupSize, *PrimaryGroupSize) PSID PrimaryGroup,
    __inout PULONG PrimaryGroupSize
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
RtlGetOwnerSecurityDescriptor (
    __in PSECURITY_DESCRIPTOR SecurityDescriptor,
    __out PSID *Owner,
    __out PBOOLEAN OwnerDefaulted
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTSYSAPI
ULONG
NTAPI
RtlNtStatusToDosError (
   __in NTSTATUS Status
   );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
NTSYSAPI
ULONG
NTAPI
RtlNtStatusToDosErrorNoTeb (
   __in NTSTATUS Status
   );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
RtlCustomCPToUnicodeN(
    __in PCPTABLEINFO CustomCP,
    __out_bcount_part(MaxBytesInUnicodeString, *BytesInUnicodeString) PWCH UnicodeString,
    __in ULONG MaxBytesInUnicodeString,
    __out_opt PULONG BytesInUnicodeString,
    __in_bcount(BytesInCustomCPString) PCH CustomCPString,
    __in ULONG BytesInCustomCPString
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
RtlUnicodeToCustomCPN(
    __in PCPTABLEINFO CustomCP,
    __out_bcount_part(MaxBytesInCustomCPString, *BytesInCustomCPString) PCH CustomCPString,
    __in ULONG MaxBytesInCustomCPString,
    __out_opt PULONG BytesInCustomCPString,
    __in_bcount(BytesInUnicodeString) PWCH UnicodeString,
    __in ULONG BytesInUnicodeString
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
RtlUpcaseUnicodeToCustomCPN(
    __in PCPTABLEINFO CustomCP,
    __out_bcount_part(MaxBytesInCustomCPString, *BytesInCustomCPString) PCH CustomCPString,
    __in ULONG MaxBytesInCustomCPString,
    __out_opt PULONG BytesInCustomCPString,
    __in_bcount(BytesInUnicodeString) PWCH UnicodeString,
    __in ULONG BytesInUnicodeString
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
VOID
NTAPI
RtlInitCodePageTable(
    __in PUSHORT TableBase,
    __inout PCPTABLEINFO CodePageTable
    );
#endif


//
// Routine for verifying or creating the "System Volume Information"
// folder on NTFS volumes.
//

#if (NTDDI_VERSION >= NTDDI_WINXP)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
RtlCreateSystemVolumeInformationFolder(
    __in PCUNICODE_STRING VolumeRootPath
    );
#endif

#define RTL_SYSTEM_VOLUME_INFORMATION_FOLDER    L"System Volume Information"

//
//  Altitude Routines
//

#if (NTDDI_VERSION >= NTDDI_VISTA)
NTSYSAPI
LONG
NTAPI
RtlCompareAltitudes(
    __in PCUNICODE_STRING Altitude1,
    __in PCUNICODE_STRING Altitude2
    );
#endif

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


#if (NTDDI_VERSION >= NTDDI_WINXP)
__kernel_entry NTSYSCALLAPI
NTSTATUS
NTAPI
NtSetInformationThread (
    __in HANDLE ThreadHandle,
    __in THREADINFOCLASS ThreadInformationClass,
    __in_bcount(ThreadInformationLength) PVOID ThreadInformation,
    __in ULONG ThreadInformationLength
    );

#endif // NTDDI_VERSION >= NTDDI_WINXP


//
// Security operation mode of the system is held in a control
// longword.
//

typedef ULONG  LSA_OPERATIONAL_MODE, *PLSA_OPERATIONAL_MODE;

//
// Used by a logon process to indicate what type of logon is being
// requested.
//

typedef enum _SECURITY_LOGON_TYPE {
    UndefinedLogonType = 0, // This is used to specify an undefied logon type
    Interactive = 2,      // Interactively logged on (locally or remotely)
    Network,              // Accessing system via network
    Batch,                // Started via a batch queue
    Service,              // Service started by service controller
    Proxy,                // Proxy logon
    Unlock,               // Unlock workstation
    NetworkCleartext,     // Network logon with cleartext credentials
    NewCredentials,       // Clone caller, new default credentials
    //The types below only exist in Windows XP and greater
#if (_WIN32_WINNT >= 0x0501)
    RemoteInteractive,  // Remote, yet interactive. Terminal server
    CachedInteractive,  // Try cached credentials without hitting the net.
    // The types below only exist in Windows Server 2003 and greater
#endif
#if (_WIN32_WINNT >= 0x0502)
    CachedRemoteInteractive, // Same as RemoteInteractive, this is used internally for auditing purpose
    CachedUnlock        // Cached Unlock workstation
#endif
} SECURITY_LOGON_TYPE, *PSECURITY_LOGON_TYPE;


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


__drv_sameIRQL
__drv_maxIRQL(PASSIVE_LEVEL)
NTSTATUS
NTAPI
LsaRegisterLogonProcess (
    __in PLSA_STRING LogonProcessName,
    __out PHANDLE LsaHandle,
    __out PLSA_OPERATIONAL_MODE SecurityMode
    );

//
// The function below did not exist in NTIFS before windows XP
// However, the function has always been there, so it is okay to use
// even on w2k
//
__drv_sameIRQL
__drv_maxIRQL(PASSIVE_LEVEL)
NTSTATUS
NTAPI
LsaLogonUser (
    __in HANDLE LsaHandle,
    __in PLSA_STRING OriginName,
    __in SECURITY_LOGON_TYPE LogonType,
    __in ULONG AuthenticationPackage,
    __in_bcount(AuthenticationInformationLength) PVOID AuthenticationInformation,
    __in ULONG AuthenticationInformationLength,
    __in_opt PTOKEN_GROUPS LocalGroups,
    __in PTOKEN_SOURCE SourceContext,
    __out PVOID *ProfileBuffer,
    __out PULONG ProfileBufferLength,
    __out PLUID LogonId,
    __out PHANDLE Token,
    __out PQUOTA_LIMITS Quotas,
    __out PNTSTATUS SubStatus
    );



__drv_sameIRQL
NTSTATUS
NTAPI
LsaFreeReturnBuffer (
    __in PVOID Buffer
    );


#ifndef _NTLSA_IFS_
#define _NTLSA_IFS_
#endif

/////////////////////////////////////////////////////////////////////////
//                                                                     //
// Name of the MSV1_0 authentication package                           //
//                                                                     //
/////////////////////////////////////////////////////////////////////////

#define MSV1_0_PACKAGE_NAME     "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0"
#define MSV1_0_PACKAGE_NAMEW    L"MICROSOFT_AUTHENTICATION_PACKAGE_V1_0"
#define MSV1_0_PACKAGE_NAMEW_LENGTH sizeof(MSV1_0_PACKAGE_NAMEW) - sizeof(WCHAR)

//
// Location of MSV authentication package data
//
#define MSV1_0_SUBAUTHENTICATION_KEY "SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0"
#define MSV1_0_SUBAUTHENTICATION_VALUE "Auth"


/////////////////////////////////////////////////////////////////////////
//                                                                     //
// Widely used MSV1_0 data types                                       //
//                                                                     //
/////////////////////////////////////////////////////////////////////////



///////////////////////////////////////////////////////////////////////////////
//                                                                           //
//       LOGON      Related Data Structures
//
//                                                                           //
///////////////////////////////////////////////////////////////////////////////

//
// When a LsaLogonUser() call is dispatched to the MsV1_0 authentication
// package, the beginning of the AuthenticationInformation buffer is
// cast to a MSV1_0_LOGON_SUBMIT_TYPE to determine the type of logon
// being requested.  Similarly, upon return, the type of profile buffer
// can be determined by typecasting it to a MSV_1_0_PROFILE_BUFFER_TYPE.
//

//
//  MSV1.0 LsaLogonUser() submission message types.
//

typedef enum _MSV1_0_LOGON_SUBMIT_TYPE {
    MsV1_0InteractiveLogon = 2,
    MsV1_0Lm20Logon,
    MsV1_0NetworkLogon,
    MsV1_0SubAuthLogon,
    MsV1_0WorkstationUnlockLogon = 7,
    // defined in Windows Server 2008 and up
    MsV1_0S4ULogon = 12,
    MsV1_0VirtualLogon = 82
} MSV1_0_LOGON_SUBMIT_TYPE, *PMSV1_0_LOGON_SUBMIT_TYPE;


//
//  MSV1.0 LsaLogonUser() profile buffer types.
//

typedef enum _MSV1_0_PROFILE_BUFFER_TYPE {
    MsV1_0InteractiveProfile = 2,
    MsV1_0Lm20LogonProfile,
    MsV1_0SmartCardProfile
} MSV1_0_PROFILE_BUFFER_TYPE, *PMSV1_0_PROFILE_BUFFER_TYPE;

//
// MsV1_0InteractiveLogon
//
// The AuthenticationInformation buffer of an LsaLogonUser() call to
// perform an interactive logon contains the following data structure:
//

typedef struct _MSV1_0_INTERACTIVE_LOGON {
    MSV1_0_LOGON_SUBMIT_TYPE MessageType;
    UNICODE_STRING LogonDomainName;
    UNICODE_STRING UserName;
    UNICODE_STRING Password;
} MSV1_0_INTERACTIVE_LOGON, *PMSV1_0_INTERACTIVE_LOGON;

//
// Where:
//
//     MessageType - Contains the type of logon being requested.  This
//         field must be set to MsV1_0InteractiveLogon.
//
//     UserName - Is a string representing the user's account name.  The
//         name may be up to 255 characters long.  The name is treated case
//         insensitive.
//
//     Password - Is a string containing the user's cleartext password.
//         The password may be up to 255 characters long and contain any
//         UNICODE value.
//
//


//
// The ProfileBuffer returned upon a successful logon of this type
// contains the following data structure:
//

typedef struct _MSV1_0_INTERACTIVE_PROFILE {
    MSV1_0_PROFILE_BUFFER_TYPE MessageType;
    USHORT LogonCount;
    USHORT BadPasswordCount;
    LARGE_INTEGER LogonTime;
    LARGE_INTEGER LogoffTime;
    LARGE_INTEGER KickOffTime;
    LARGE_INTEGER PasswordLastSet;
    LARGE_INTEGER PasswordCanChange;
    LARGE_INTEGER PasswordMustChange;
    UNICODE_STRING LogonScript;
    UNICODE_STRING HomeDirectory;
    UNICODE_STRING FullName;
    UNICODE_STRING ProfilePath;
    UNICODE_STRING HomeDirectoryDrive;
    UNICODE_STRING LogonServer;
    ULONG UserFlags;
} MSV1_0_INTERACTIVE_PROFILE, *PMSV1_0_INTERACTIVE_PROFILE;

//
// where:
//
//     MessageType - Identifies the type of profile data being returned.
//         Contains the type of logon being requested.  This field must
//         be set to MsV1_0InteractiveProfile.
//
//     LogonCount - Number of times the user is currently logged on.
//
//     BadPasswordCount - Number of times a bad password was applied to
//         the account since last successful logon.
//
//     LogonTime - Time when user last logged on.  This is an absolute
//         format NT standard time value.
//
//     LogoffTime - Time when user should log off.  This is an absolute
//         format NT standard time value.
//
//     KickOffTime - Time when system should force user logoff.  This is
//         an absolute format NT standard time value.
//
//     PasswordLastChanged - Time and date the password was last
//         changed.  This is an absolute format NT standard time
//         value.
//
//     PasswordCanChange - Time and date when the user can change the
//         password.  This is an absolute format NT time value.  To
//         prevent a password from ever changing, set this field to a
//         date very far into the future.
//
//     PasswordMustChange - Time and date when the user must change the
//         password.  If the user can never change the password, this
//         field is undefined.  This is an absolute format NT time
//         value.
//
//     LogonScript - The (relative) path to the account's logon
//         script.
//
//     HomeDirectory - The home directory for the user.
//


//
// MsV1_0Lm20Logon and MsV1_0NetworkLogon
//
// The AuthenticationInformation buffer of an LsaLogonUser() call to
// perform an network logon contains the following data structure:
//
// MsV1_0NetworkLogon logon differs from MsV1_0Lm20Logon in that the
// ParameterControl field exists.
//

#define MSV1_0_CHALLENGE_LENGTH 8
#define MSV1_0_USER_SESSION_KEY_LENGTH 16
#define MSV1_0_LANMAN_SESSION_KEY_LENGTH 8

//
// Values for ParameterControl.
//

#define MSV1_0_CLEARTEXT_PASSWORD_ALLOWED    0x02
#define MSV1_0_UPDATE_LOGON_STATISTICS       0x04
#define MSV1_0_RETURN_USER_PARAMETERS        0x08
#define MSV1_0_DONT_TRY_GUEST_ACCOUNT        0x10
#define MSV1_0_ALLOW_SERVER_TRUST_ACCOUNT    0x20
#define MSV1_0_RETURN_PASSWORD_EXPIRY        0x40
// this next flag says that CaseInsensitiveChallengeResponse
//  (aka LmResponse) contains a client challenge in the first 8 bytes
#define MSV1_0_USE_CLIENT_CHALLENGE          0x80
#define MSV1_0_TRY_GUEST_ACCOUNT_ONLY        0x100
#define MSV1_0_RETURN_PROFILE_PATH           0x200
#define MSV1_0_TRY_SPECIFIED_DOMAIN_ONLY     0x400
#define MSV1_0_ALLOW_WORKSTATION_TRUST_ACCOUNT 0x800
//#if (_WIN32_WINNT >= 0x0501) -- Disabled until IIS fixes their target version.
#define MSV1_0_DISABLE_PERSONAL_FALLBACK     0x00001000
#define MSV1_0_ALLOW_FORCE_GUEST             0x00002000
//#endif
#if (_WIN32_WINNT >= 0x0502)
#define MSV1_0_CLEARTEXT_PASSWORD_SUPPLIED   0x00004000
// Start
// Doesnt exist in Windows XP but does exist in Windows 2000 Security Rollup and up
#define MSV1_0_USE_DOMAIN_FOR_ROUTING_ONLY   0x00008000
#endif
#define MSV1_0_SUBAUTHENTICATION_DLL_EX      0x00100000
// Defined in Windows Server 2003 SP1 and above
#define MSV1_0_ALLOW_MSVCHAPV2               0x00010000

#if (_WIN32_WINNT >= 0x0600)

//Defined in Windows Server 2008 and up
#define MSV1_0_S4U2SELF                      0x00020000 // no password is needed
#define MSV1_0_CHECK_LOGONHOURS_FOR_S4U      0x00040000 // check logon hours for S4U logon

#endif

//
// The high order byte is a value indicating the SubAuthentication DLL.
//  Zero indicates no SubAuthentication DLL.
//
#define MSV1_0_SUBAUTHENTICATION_DLL         0xFF000000
#define MSV1_0_SUBAUTHENTICATION_DLL_SHIFT   24
#define MSV1_0_MNS_LOGON                     0x01000000

//
// This is the list of subauthentication dlls used in MS
//

#define MSV1_0_SUBAUTHENTICATION_DLL_RAS     2
#define MSV1_0_SUBAUTHENTICATION_DLL_IIS     132

typedef struct _MSV1_0_LM20_LOGON {
    MSV1_0_LOGON_SUBMIT_TYPE MessageType;
    UNICODE_STRING LogonDomainName;
    UNICODE_STRING UserName;
    UNICODE_STRING Workstation;
    UCHAR ChallengeToClient[MSV1_0_CHALLENGE_LENGTH];
    STRING CaseSensitiveChallengeResponse;
    STRING CaseInsensitiveChallengeResponse;
    ULONG ParameterControl;
} MSV1_0_LM20_LOGON, * PMSV1_0_LM20_LOGON;

//
// NT 5.0 SubAuth dlls can use this struct
//

typedef struct _MSV1_0_SUBAUTH_LOGON{
    MSV1_0_LOGON_SUBMIT_TYPE MessageType;
    UNICODE_STRING LogonDomainName;
    UNICODE_STRING UserName;
    UNICODE_STRING Workstation;
    UCHAR ChallengeToClient[MSV1_0_CHALLENGE_LENGTH];
    STRING AuthenticationInfo1;
    STRING AuthenticationInfo2;
    ULONG ParameterControl;
    ULONG SubAuthPackageId;
} MSV1_0_SUBAUTH_LOGON, * PMSV1_0_SUBAUTH_LOGON;

#if (_WIN32_WINNT >= 0x0600)

//
// s4u2self logon
//
// Defined in Windows Server 2008 and above

//
// request to enforce logon hours policy
//

#define MSV1_0_S4U_LOGON_FLAG_CHECK_LOGONHOURS 0x2

typedef struct _MSV1_0_S4U_LOGON {
    MSV1_0_LOGON_SUBMIT_TYPE MessageType;
    ULONG Flags;
    UNICODE_STRING UserPrincipalName; // username or username@domain
    UNICODE_STRING DomainName; // Optional: if missing, using the local machine
} MSV1_0_S4U_LOGON, *PMSV1_0_S4U_LOGON;

#endif 

//
// Values for UserFlags.
//

#define LOGON_GUEST                 0x01
#define LOGON_NOENCRYPTION          0x02
#define LOGON_CACHED_ACCOUNT        0x04
#define LOGON_USED_LM_PASSWORD      0x08
#define LOGON_EXTRA_SIDS            0x20
#define LOGON_SUBAUTH_SESSION_KEY   0x40
#define LOGON_SERVER_TRUST_ACCOUNT  0x80
#define LOGON_NTLMV2_ENABLED        0x100       // says DC understands NTLMv2
#define LOGON_RESOURCE_GROUPS       0x200
#define LOGON_PROFILE_PATH_RETURNED 0x400
// Defined in Windows Server 2008 and above
#define LOGON_NT_V2                 0x800   // NT response was used for validation
#define LOGON_LM_V2                 0x1000  // LM response was used for validation
#define LOGON_NTLM_V2               0x2000  // LM response was used to authenticate but NT response was used to derive the session key

#if (_WIN32_WINNT >= 0x0600)

#define LOGON_OPTIMIZED             0x4000  // this is an optimized logon
#define LOGON_WINLOGON              0x8000  // the logon session was created for winlogon
#define LOGON_PKINIT               0x10000  // Kerberos PKINIT extension was used to authenticate the user
#define LOGON_NO_OPTIMIZED         0x20000  // optimized logon has been disabled for this account

#endif

//
// The high order byte is reserved for return by SubAuthentication DLLs.
//

#define MSV1_0_SUBAUTHENTICATION_FLAGS 0xFF000000

// Values returned by the MSV1_0_MNS_LOGON SubAuthentication DLL
#define LOGON_GRACE_LOGON              0x01000000

typedef struct _MSV1_0_LM20_LOGON_PROFILE {
    MSV1_0_PROFILE_BUFFER_TYPE MessageType;
    LARGE_INTEGER KickOffTime;
    LARGE_INTEGER LogoffTime;
    ULONG UserFlags;
    UCHAR UserSessionKey[MSV1_0_USER_SESSION_KEY_LENGTH];
    UNICODE_STRING LogonDomainName;
    UCHAR LanmanSessionKey[MSV1_0_LANMAN_SESSION_KEY_LENGTH];
    UNICODE_STRING LogonServer;
    UNICODE_STRING UserParameters;
} MSV1_0_LM20_LOGON_PROFILE, * PMSV1_0_LM20_LOGON_PROFILE;


//
// Supplemental credentials structure used for passing credentials into
// MSV1_0 from other packages
//

#define MSV1_0_OWF_PASSWORD_LENGTH 16
#define MSV1_0_CRED_LM_PRESENT 0x1
#define MSV1_0_CRED_NT_PRESENT 0x2
#define MSV1_0_CRED_VERSION 0

typedef struct _MSV1_0_SUPPLEMENTAL_CREDENTIAL {
    ULONG Version;
    ULONG Flags;
    UCHAR LmPassword[MSV1_0_OWF_PASSWORD_LENGTH];
    UCHAR NtPassword[MSV1_0_OWF_PASSWORD_LENGTH];
} MSV1_0_SUPPLEMENTAL_CREDENTIAL, *PMSV1_0_SUPPLEMENTAL_CREDENTIAL;


//
// NTLM3 definitions.
//

#define MSV1_0_NTLM3_RESPONSE_LENGTH 16
#define MSV1_0_NTLM3_OWF_LENGTH 16

//
// this is the longest amount of time we'll allow challenge response
// pairs to be used. Note that this also has to allow for worst case clock skew
//
#if (_WIN32_WINNT == 0x0500)
#define MSV1_0_MAX_NTLM3_LIFE 1800     // 30 minutes (in seconds)
#else
#define MSV1_0_MAX_NTLM3_LIFE 129600     // 36 hours (in seconds)
#endif
#define MSV1_0_MAX_AVL_SIZE 64000

#if (_WIN32_WINNT >= 0x0501)
//
// MsvAvFlags bit values
//
// Exists only after Windows 2000
//

#define MSV1_0_AV_FLAG_FORCE_GUEST                  0x00000001
#if (_WIN32_WINNT >= 0x0600)
#define MSV1_0_AV_FLAG_MIC_HANDSHAKE_MESSAGES       0x00000002 // the client supports
                                                               // hand-shake messages integrity
#endif
#endif

// this is an MSV1_0 private data structure, defining the layout of an NTLM3 response, as sent by a
//  client in the NtChallengeResponse field of the NETLOGON_NETWORK_INFO structure. If can be differentiated
//  from an old style NT response by its length. This is crude, but it needs to pass through servers and
//  the servers' DCs that do not understand NTLM3 but that are willing to pass longer responses.
typedef struct _MSV1_0_NTLM3_RESPONSE {
    UCHAR Response[MSV1_0_NTLM3_RESPONSE_LENGTH]; // hash of OWF of password with all the following fields
    UCHAR RespType;     // id number of response; current is 1
    UCHAR HiRespType;   // highest id number understood by client
    USHORT Flags;       // reserved; must be sent as zero at this version
    ULONG MsgWord;      // 32 bit message from client to server (for use by auth protocol)
    ULONGLONG TimeStamp;    // time stamp when client generated response -- NT system time, quad part
    UCHAR ChallengeFromClient[MSV1_0_CHALLENGE_LENGTH];
    ULONG AvPairsOff;   // offset to start of AvPairs (to allow future expansion)
    UCHAR Buffer[1];    // start of buffer with AV pairs (or future stuff -- so use the offset)
} MSV1_0_NTLM3_RESPONSE, *PMSV1_0_NTLM3_RESPONSE;

#define MSV1_0_NTLM3_INPUT_LENGTH (sizeof(MSV1_0_NTLM3_RESPONSE) - MSV1_0_NTLM3_RESPONSE_LENGTH)
#if(_WIN32_WINNT >= 0x0502)
#define MSV1_0_NTLM3_MIN_NT_RESPONSE_LENGTH RTL_SIZEOF_THROUGH_FIELD(MSV1_0_NTLM3_RESPONSE, AvPairsOff)
#endif

typedef enum {
    MsvAvEOL,                 // end of list
    MsvAvNbComputerName,      // server's computer name -- NetBIOS
    MsvAvNbDomainName,        // server's domain name -- NetBIOS
    MsvAvDnsComputerName,     // server's computer name -- DNS
    MsvAvDnsDomainName,       // server's domain name -- DNS
#if (_WIN32_WINNT >= 0x0501)
    MsvAvDnsTreeName,         // server's tree name -- DNS
    MsvAvFlags,               // server's extended flags -- DWORD mask
#if (_WIN32_WINNT >= 0x0600)
    MsvAvTimestamp,           // contains the server's local time in FILETIME,
                              // (64 bit 100 ns ticks since 1602
                              // (UTC)) in little endian byte order
    MsvAvRestrictions,        // token restrictions                              
    MsvAvTargetName,
    MsvAvChannelBindings,
#endif
#endif
} MSV1_0_AVID;

typedef struct  _MSV1_0_AV_PAIR {
    USHORT AvId;
    USHORT AvLen;
    // Data is treated as byte array following structure
} MSV1_0_AV_PAIR, *PMSV1_0_AV_PAIR;



///////////////////////////////////////////////////////////////////////////////
//                                                                           //
//       CALL PACKAGE Related Data Structures                                //
//                                                                           //
///////////////////////////////////////////////////////////////////////////////


//
//  MSV1.0 LsaCallAuthenticationPackage() submission and response
//  message types.
//

typedef enum _MSV1_0_PROTOCOL_MESSAGE_TYPE {
    MsV1_0Lm20ChallengeRequest = 0,          // Both submission and response
    MsV1_0Lm20GetChallengeResponse,          // Both submission and response
    MsV1_0EnumerateUsers,                    // Both submission and response
    MsV1_0GetUserInfo,                       // Both submission and response
    MsV1_0ReLogonUsers,                      // Submission only
    MsV1_0ChangePassword,                    // Both submission and response
    MsV1_0ChangeCachedPassword,              // Both submission and response
    MsV1_0GenericPassthrough,                // Both submission and response
    MsV1_0CacheLogon,                        // Submission only, no response
    MsV1_0SubAuth,                           // Both submission and response
    MsV1_0DeriveCredential,                  // Both submission and response
    MsV1_0CacheLookup,                       // Both submission and response
#if (_WIN32_WINNT >= 0x0501)
    MsV1_0SetProcessOption,                  // Submission only, no response
#endif
#if (_WIN32_WINNT >= 0x0600)
    MsV1_0ConfigLocalAliases,
    MsV1_0ClearCachedCredentials,
#endif    
} MSV1_0_PROTOCOL_MESSAGE_TYPE, *PMSV1_0_PROTOCOL_MESSAGE_TYPE;

// end_ntsecapi

//
// MsV1_0Lm20ChallengeRequest submit buffer and response
//

typedef struct _MSV1_0_LM20_CHALLENGE_REQUEST {
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
} MSV1_0_LM20_CHALLENGE_REQUEST, *PMSV1_0_LM20_CHALLENGE_REQUEST;

typedef struct _MSV1_0_LM20_CHALLENGE_RESPONSE {
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
    UCHAR ChallengeToClient[MSV1_0_CHALLENGE_LENGTH];
} MSV1_0_LM20_CHALLENGE_RESPONSE, *PMSV1_0_LM20_CHALLENGE_RESPONSE;

//
// MsV1_0Lm20GetChallengeResponse submit buffer and response
//

#define USE_PRIMARY_PASSWORD            0x01
#define RETURN_PRIMARY_USERNAME         0x02
#define RETURN_PRIMARY_LOGON_DOMAINNAME 0x04
#define RETURN_NON_NT_USER_SESSION_KEY  0x08
#define GENERATE_CLIENT_CHALLENGE       0x10
#define GCR_NTLM3_PARMS                 0x20
#define GCR_TARGET_INFO                 0x40    // ServerName field contains target info AV pairs
#define RETURN_RESERVED_PARAMETER       0x80    // was 0x10
#define GCR_ALLOW_NTLM                 0x100    // allow the use of NTLM
// Exists in Windows XPSP2 and later
#define GCR_USE_OEM_SET                0x200    // response uses oem character set
#define GCR_MACHINE_CREDENTIAL         0x400
#define GCR_USE_OWF_PASSWORD           0x800    // use owf passwords
#define GCR_ALLOW_LM                  0x1000    // allow the use of LM
// Defined in Windows Server 2003 and above
#define GCR_ALLOW_NO_TARGET           0x2000    // allow no target server or target domain name

//
// version 1 of the GETCHALLENRESP structure, which was used by RAS and others.
// compiled before the additional fields added to GETCHALLENRESP_REQUEST.
// here to allow sizing operations for backwards compatibility.
//

typedef struct _MSV1_0_GETCHALLENRESP_REQUEST_V1 {
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
    ULONG ParameterControl;
    LUID LogonId;
    UNICODE_STRING Password;
    UCHAR ChallengeToClient[MSV1_0_CHALLENGE_LENGTH];
} MSV1_0_GETCHALLENRESP_REQUEST_V1, *PMSV1_0_GETCHALLENRESP_REQUEST_V1;

typedef struct _MSV1_0_GETCHALLENRESP_REQUEST {
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
    ULONG ParameterControl;
    LUID LogonId;
    UNICODE_STRING Password;
    UCHAR ChallengeToClient[MSV1_0_CHALLENGE_LENGTH];

    //
    // the following 3 fields are only present if GCR_NTLM3_PARMS is set in ParameterControl
    //

    UNICODE_STRING UserName;
    UNICODE_STRING LogonDomainName;
    UNICODE_STRING ServerName;      // server domain or target info AV pairs
} MSV1_0_GETCHALLENRESP_REQUEST, *PMSV1_0_GETCHALLENRESP_REQUEST;

typedef struct _MSV1_0_GETCHALLENRESP_RESPONSE {
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
    STRING CaseSensitiveChallengeResponse;
    STRING CaseInsensitiveChallengeResponse;
    UNICODE_STRING UserName;
    UNICODE_STRING LogonDomainName;
    UCHAR UserSessionKey[MSV1_0_USER_SESSION_KEY_LENGTH];
    UCHAR LanmanSessionKey[MSV1_0_LANMAN_SESSION_KEY_LENGTH];
} MSV1_0_GETCHALLENRESP_RESPONSE, *PMSV1_0_GETCHALLENRESP_RESPONSE;

//
// MsV1_0EnumerateUsers submit buffer and response
//

typedef struct _MSV1_0_ENUMUSERS_REQUEST {
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
} MSV1_0_ENUMUSERS_REQUEST, *PMSV1_0_ENUMUSERS_REQUEST;

typedef struct _MSV1_0_ENUMUSERS_RESPONSE {
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
    ULONG NumberOfLoggedOnUsers;
    PLUID LogonIds;
    PULONG EnumHandles;
} MSV1_0_ENUMUSERS_RESPONSE, *PMSV1_0_ENUMUSERS_RESPONSE;

//
// MsV1_0GetUserInfo submit buffer and response
//

typedef struct _MSV1_0_GETUSERINFO_REQUEST {
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
    LUID LogonId;
} MSV1_0_GETUSERINFO_REQUEST, *PMSV1_0_GETUSERINFO_REQUEST;

typedef struct _MSV1_0_GETUSERINFO_RESPONSE {
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
    PSID UserSid;
    UNICODE_STRING UserName;
    UNICODE_STRING LogonDomainName;
    UNICODE_STRING LogonServer;
    SECURITY_LOGON_TYPE LogonType;
} MSV1_0_GETUSERINFO_RESPONSE, *PMSV1_0_GETUSERINFO_RESPONSE;


//
// Define the I/O status information return values for requests for oplocks
// via NtFsControlFile
//

#define FILE_OPLOCK_BROKEN_TO_LEVEL_2   0x00000007
#define FILE_OPLOCK_BROKEN_TO_NONE      0x00000008

//
// Define the I/O status information return values for NtCreateFile/NtOpenFile
// when the sharing access fails but a batch oplock break is in progress
//

#define FILE_OPBATCH_BREAK_UNDERWAY     0x00000009

//
// Define the filter flags for NtNotifyChangeDirectoryFile
//

#define FILE_NOTIFY_CHANGE_FILE_NAME    0x00000001   // winnt
#define FILE_NOTIFY_CHANGE_DIR_NAME     0x00000002   // winnt
#define FILE_NOTIFY_CHANGE_NAME         0x00000003
#define FILE_NOTIFY_CHANGE_ATTRIBUTES   0x00000004   // winnt
#define FILE_NOTIFY_CHANGE_SIZE         0x00000008   // winnt
#define FILE_NOTIFY_CHANGE_LAST_WRITE   0x00000010   // winnt
#define FILE_NOTIFY_CHANGE_LAST_ACCESS  0x00000020   // winnt
#define FILE_NOTIFY_CHANGE_CREATION     0x00000040   // winnt
#define FILE_NOTIFY_CHANGE_EA           0x00000080
#define FILE_NOTIFY_CHANGE_SECURITY     0x00000100   // winnt
#define FILE_NOTIFY_CHANGE_STREAM_NAME  0x00000200
#define FILE_NOTIFY_CHANGE_STREAM_SIZE  0x00000400
#define FILE_NOTIFY_CHANGE_STREAM_WRITE 0x00000800
#define FILE_NOTIFY_VALID_MASK          0x00000fff

//
// Define the file action type codes for NtNotifyChangeDirectoryFile
//

#define FILE_ACTION_ADDED                   0x00000001   // winnt
#define FILE_ACTION_REMOVED                 0x00000002   // winnt
#define FILE_ACTION_MODIFIED                0x00000003   // winnt
#define FILE_ACTION_RENAMED_OLD_NAME        0x00000004   // winnt
#define FILE_ACTION_RENAMED_NEW_NAME        0x00000005   // winnt
#define FILE_ACTION_ADDED_STREAM            0x00000006
#define FILE_ACTION_REMOVED_STREAM          0x00000007
#define FILE_ACTION_MODIFIED_STREAM         0x00000008
#define FILE_ACTION_REMOVED_BY_DELETE       0x00000009
#define FILE_ACTION_ID_NOT_TUNNELLED        0x0000000A
#define FILE_ACTION_TUNNELLED_ID_COLLISION  0x0000000B

//
// Define the NamedPipeType flags for NtCreateNamedPipeFile
//

#define FILE_PIPE_BYTE_STREAM_TYPE          0x00000000
#define FILE_PIPE_MESSAGE_TYPE              0x00000001

#define FILE_PIPE_ACCEPT_REMOTE_CLIENTS     0x00000000
#define FILE_PIPE_REJECT_REMOTE_CLIENTS     0x00000002

#define FILE_PIPE_TYPE_VALID_MASK           0x00000003

//
// Define the CompletionMode flags for NtCreateNamedPipeFile
//

#define FILE_PIPE_QUEUE_OPERATION       0x00000000
#define FILE_PIPE_COMPLETE_OPERATION    0x00000001

//
// Define the ReadMode flags for NtCreateNamedPipeFile
//

#define FILE_PIPE_BYTE_STREAM_MODE      0x00000000
#define FILE_PIPE_MESSAGE_MODE          0x00000001

//
// Define the NamedPipeConfiguration flags for NtQueryInformation
//

#define FILE_PIPE_INBOUND               0x00000000
#define FILE_PIPE_OUTBOUND              0x00000001
#define FILE_PIPE_FULL_DUPLEX           0x00000002

//
// Define the NamedPipeState flags for NtQueryInformation
//

#define FILE_PIPE_DISCONNECTED_STATE    0x00000001
#define FILE_PIPE_LISTENING_STATE       0x00000002
#define FILE_PIPE_CONNECTED_STATE       0x00000003
#define FILE_PIPE_CLOSING_STATE         0x00000004

//
// Define the NamedPipeEnd flags for NtQueryInformation
//

#define FILE_PIPE_CLIENT_END            0x00000000
#define FILE_PIPE_SERVER_END            0x00000001


//
// Define the file system attributes flags
//

#define FILE_CASE_SENSITIVE_SEARCH          0x00000001  // winnt
#define FILE_CASE_PRESERVED_NAMES           0x00000002  // winnt
#define FILE_UNICODE_ON_DISK                0x00000004  // winnt
#define FILE_PERSISTENT_ACLS                0x00000008  // winnt
#define FILE_FILE_COMPRESSION               0x00000010  // winnt
#define FILE_VOLUME_QUOTAS                  0x00000020  // winnt
#define FILE_SUPPORTS_SPARSE_FILES          0x00000040  // winnt
#define FILE_SUPPORTS_REPARSE_POINTS        0x00000080  // winnt
#define FILE_SUPPORTS_REMOTE_STORAGE        0x00000100  // winnt
#define FILE_VOLUME_IS_COMPRESSED           0x00008000  // winnt
#define FILE_SUPPORTS_OBJECT_IDS            0x00010000  // winnt
#define FILE_SUPPORTS_ENCRYPTION            0x00020000  // winnt
#define FILE_NAMED_STREAMS                  0x00040000  // winnt
#define FILE_READ_ONLY_VOLUME               0x00080000  // winnt
#define FILE_SEQUENTIAL_WRITE_ONCE          0x00100000  // winnt
#define FILE_SUPPORTS_TRANSACTIONS          0x00200000  // winnt
#define FILE_SUPPORTS_HARD_LINKS            0x00400000  // winnt
#define FILE_SUPPORTS_EXTENDED_ATTRIBUTES   0x00800000  // winnt
//
//  When enabled this attribute implies that the FileID's for the supported
//  file system are also durable.  This means the FileID will not change due
//  to other file system operations like rename or defrag.  If a file
//  is deleted and re-created the ID will change.
//
#define FILE_SUPPORTS_OPEN_BY_FILE_ID       0x01000000  // winnt
#define FILE_SUPPORTS_USN_JOURNAL           0x02000000  // winnt



//
// Define the flags for NtSet(Query)EaFile service structure entries
//

#define FILE_NEED_EA                    0x00000080

//
// Define EA type values
//

#define FILE_EA_TYPE_BINARY             0xfffe
#define FILE_EA_TYPE_ASCII              0xfffd
#define FILE_EA_TYPE_BITMAP             0xfffb
#define FILE_EA_TYPE_METAFILE           0xfffa
#define FILE_EA_TYPE_ICON               0xfff9
#define FILE_EA_TYPE_EA                 0xffee
#define FILE_EA_TYPE_MVMT               0xffdf
#define FILE_EA_TYPE_MVST               0xffde
#define FILE_EA_TYPE_ASN1               0xffdd
#define FILE_EA_TYPE_FAMILY_IDS         0xff01


//
// Define the file notification information structure
//

typedef struct _FILE_NOTIFY_INFORMATION {
    ULONG NextEntryOffset;
    ULONG Action;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_NOTIFY_INFORMATION, *PFILE_NOTIFY_INFORMATION;


//
// NtQueryDirectoryFile return types:
//
//      FILE_DIRECTORY_INFORMATION
//      FILE_FULL_DIR_INFORMATION
//      FILE_ID_FULL_DIR_INFORMATION
//      FILE_BOTH_DIR_INFORMATION
//      FILE_ID_BOTH_DIR_INFORMATION
//      FILE_NAMES_INFORMATION
//      FILE_OBJECTID_INFORMATION
//

typedef struct _FILE_DIRECTORY_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_DIRECTORY_INFORMATION, *PFILE_DIRECTORY_INFORMATION;

typedef struct _FILE_FULL_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    WCHAR FileName[1];
} FILE_FULL_DIR_INFORMATION, *PFILE_FULL_DIR_INFORMATION;

typedef struct _FILE_ID_FULL_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    LARGE_INTEGER FileId;
    WCHAR FileName[1];
} FILE_ID_FULL_DIR_INFORMATION, *PFILE_ID_FULL_DIR_INFORMATION;

typedef struct _FILE_BOTH_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    CCHAR ShortNameLength;
    WCHAR ShortName[12];
    WCHAR FileName[1];
} FILE_BOTH_DIR_INFORMATION, *PFILE_BOTH_DIR_INFORMATION;

typedef struct _FILE_ID_BOTH_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    CCHAR ShortNameLength;
    WCHAR ShortName[12];
    LARGE_INTEGER FileId;
    WCHAR FileName[1];
} FILE_ID_BOTH_DIR_INFORMATION, *PFILE_ID_BOTH_DIR_INFORMATION;

typedef struct _FILE_NAMES_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_NAMES_INFORMATION, *PFILE_NAMES_INFORMATION;

typedef struct _FILE_ID_GLOBAL_TX_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    LARGE_INTEGER FileId;
    GUID LockingTransactionId;
    ULONG TxInfoFlags;
    WCHAR FileName[1];
} FILE_ID_GLOBAL_TX_DIR_INFORMATION, *PFILE_ID_GLOBAL_TX_DIR_INFORMATION;

#define FILE_ID_GLOBAL_TX_DIR_INFO_FLAG_WRITELOCKED         0x00000001
#define FILE_ID_GLOBAL_TX_DIR_INFO_FLAG_VISIBLE_TO_TX       0x00000002
#define FILE_ID_GLOBAL_TX_DIR_INFO_FLAG_VISIBLE_OUTSIDE_TX  0x00000004

typedef struct _FILE_OBJECTID_INFORMATION {
    LONGLONG FileReference;
    UCHAR ObjectId[16];
    union {
        struct {
            UCHAR BirthVolumeId[16];
            UCHAR BirthObjectId[16];
            UCHAR DomainId[16];
        } DUMMYSTRUCTNAME;
        UCHAR ExtendedInfo[48];
    } DUMMYUNIONNAME;
} FILE_OBJECTID_INFORMATION, *PFILE_OBJECTID_INFORMATION;

//
//  The following constants provide addition meta characters to fully
//  support the more obscure aspects of DOS wild card processing.
//

#define ANSI_DOS_STAR   ('<')
#define ANSI_DOS_QM     ('>')
#define ANSI_DOS_DOT    ('"')

#define DOS_STAR        (L'<')
#define DOS_QM          (L'>')
#define DOS_DOT         (L'"')

//
// NtQuery(Set)InformationFile return types:
//
//      FILE_BASIC_INFORMATION
//      FILE_STANDARD_INFORMATION
//      FILE_INTERNAL_INFORMATION
//      FILE_EA_INFORMATION
//      FILE_ACCESS_INFORMATION
//      FILE_POSITION_INFORMATION
//      FILE_MODE_INFORMATION
//      FILE_ALIGNMENT_INFORMATION
//      FILE_NAME_INFORMATION
//      FILE_ALL_INFORMATION
//
//      FILE_NETWORK_OPEN_INFORMATION
//
//      FILE_ALLOCATION_INFORMATION
//      FILE_COMPRESSION_INFORMATION
//      FILE_DISPOSITION_INFORMATION
//      FILE_END_OF_FILE_INFORMATION
//      FILE_LINK_INFORMATION
//      FILE_MOVE_CLUSTER_INFORMATION
//      FILE_RENAME_INFORMATION
//      FILE_SHORT_NAME_INFORMATION
//      FILE_STREAM_INFORMATION
//      FILE_COMPLETION_INFORMATION
//
//      FILE_PIPE_INFORMATION
//      FILE_PIPE_LOCAL_INFORMATION
//      FILE_PIPE_REMOTE_INFORMATION
//
//      FILE_MAILSLOT_QUERY_INFORMATION
//      FILE_MAILSLOT_SET_INFORMATION
//      FILE_REPARSE_POINT_INFORMATION
//
//      FILE_NETWORK_PHYSICAL_NAME_INFORMATION
//


typedef struct _FILE_INTERNAL_INFORMATION {
    LARGE_INTEGER IndexNumber;
} FILE_INTERNAL_INFORMATION, *PFILE_INTERNAL_INFORMATION;

typedef struct _FILE_EA_INFORMATION {
    ULONG EaSize;
} FILE_EA_INFORMATION, *PFILE_EA_INFORMATION;

typedef struct _FILE_ACCESS_INFORMATION {
    ACCESS_MASK AccessFlags;
} FILE_ACCESS_INFORMATION, *PFILE_ACCESS_INFORMATION;

typedef struct _FILE_MODE_INFORMATION {
    ULONG Mode;
} FILE_MODE_INFORMATION, *PFILE_MODE_INFORMATION;

typedef struct _FILE_ALL_INFORMATION {
    FILE_BASIC_INFORMATION BasicInformation;
    FILE_STANDARD_INFORMATION StandardInformation;
    FILE_INTERNAL_INFORMATION InternalInformation;
    FILE_EA_INFORMATION EaInformation;
    FILE_ACCESS_INFORMATION AccessInformation;
    FILE_POSITION_INFORMATION PositionInformation;
    FILE_MODE_INFORMATION ModeInformation;
    FILE_ALIGNMENT_INFORMATION AlignmentInformation;
    FILE_NAME_INFORMATION NameInformation;
} FILE_ALL_INFORMATION, *PFILE_ALL_INFORMATION;


typedef struct _FILE_ALLOCATION_INFORMATION {
    LARGE_INTEGER AllocationSize;
} FILE_ALLOCATION_INFORMATION, *PFILE_ALLOCATION_INFORMATION;


typedef struct _FILE_COMPRESSION_INFORMATION {
    LARGE_INTEGER CompressedFileSize;
    USHORT CompressionFormat;
    UCHAR CompressionUnitShift;
    UCHAR ChunkShift;
    UCHAR ClusterShift;
    UCHAR Reserved[3];
} FILE_COMPRESSION_INFORMATION, *PFILE_COMPRESSION_INFORMATION;


#ifdef _MAC
#pragma warning( disable : 4121)
#endif

typedef struct _FILE_LINK_INFORMATION {
    BOOLEAN ReplaceIfExists;
    HANDLE RootDirectory;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_LINK_INFORMATION, *PFILE_LINK_INFORMATION;


#ifdef _MAC
#pragma warning( default : 4121 )
#endif

typedef struct _FILE_MOVE_CLUSTER_INFORMATION {
    ULONG ClusterCount;
    HANDLE RootDirectory;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_MOVE_CLUSTER_INFORMATION, *PFILE_MOVE_CLUSTER_INFORMATION;

#ifdef _MAC
#pragma warning( disable : 4121)
#endif

typedef struct _FILE_RENAME_INFORMATION {
    BOOLEAN ReplaceIfExists;
    HANDLE RootDirectory;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_RENAME_INFORMATION, *PFILE_RENAME_INFORMATION;

#ifdef _MAC
#pragma warning( default : 4121 )
#endif

typedef struct _FILE_STREAM_INFORMATION {
    ULONG NextEntryOffset;
    ULONG StreamNameLength;
    LARGE_INTEGER StreamSize;
    LARGE_INTEGER StreamAllocationSize;
    WCHAR StreamName[1];
} FILE_STREAM_INFORMATION, *PFILE_STREAM_INFORMATION;

typedef struct _FILE_TRACKING_INFORMATION {
    HANDLE DestinationFile;
    ULONG ObjectInformationLength;
    CHAR ObjectInformation[1];
} FILE_TRACKING_INFORMATION, *PFILE_TRACKING_INFORMATION;

typedef struct _FILE_COMPLETION_INFORMATION {
    HANDLE Port;
    PVOID Key;
} FILE_COMPLETION_INFORMATION, *PFILE_COMPLETION_INFORMATION;

typedef struct _FILE_PIPE_INFORMATION {
     ULONG ReadMode;
     ULONG CompletionMode;
} FILE_PIPE_INFORMATION, *PFILE_PIPE_INFORMATION;

typedef struct _FILE_PIPE_LOCAL_INFORMATION {
     ULONG NamedPipeType;
     ULONG NamedPipeConfiguration;
     ULONG MaximumInstances;
     ULONG CurrentInstances;
     ULONG InboundQuota;
     ULONG ReadDataAvailable;
     ULONG OutboundQuota;
     ULONG WriteQuotaAvailable;
     ULONG NamedPipeState;
     ULONG NamedPipeEnd;
} FILE_PIPE_LOCAL_INFORMATION, *PFILE_PIPE_LOCAL_INFORMATION;

typedef struct _FILE_PIPE_REMOTE_INFORMATION {
     LARGE_INTEGER CollectDataTime;
     ULONG MaximumCollectionCount;
} FILE_PIPE_REMOTE_INFORMATION, *PFILE_PIPE_REMOTE_INFORMATION;


typedef struct _FILE_MAILSLOT_QUERY_INFORMATION {
    ULONG MaximumMessageSize;
    ULONG MailslotQuota;
    ULONG NextMessageSize;
    ULONG MessagesAvailable;
    LARGE_INTEGER ReadTimeout;
} FILE_MAILSLOT_QUERY_INFORMATION, *PFILE_MAILSLOT_QUERY_INFORMATION;

typedef struct _FILE_MAILSLOT_SET_INFORMATION {
    PLARGE_INTEGER ReadTimeout;
} FILE_MAILSLOT_SET_INFORMATION, *PFILE_MAILSLOT_SET_INFORMATION;

typedef struct _FILE_REPARSE_POINT_INFORMATION {
    LONGLONG FileReference;
    ULONG Tag;
} FILE_REPARSE_POINT_INFORMATION, *PFILE_REPARSE_POINT_INFORMATION;

typedef struct _FILE_LINK_ENTRY_INFORMATION {
    ULONG NextEntryOffset;
    LONGLONG ParentFileId;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_LINK_ENTRY_INFORMATION, *PFILE_LINK_ENTRY_INFORMATION;

typedef struct _FILE_LINKS_INFORMATION {
    ULONG BytesNeeded;
    ULONG EntriesReturned;
    FILE_LINK_ENTRY_INFORMATION Entry;
} FILE_LINKS_INFORMATION, *PFILE_LINKS_INFORMATION;

typedef struct _FILE_NETWORK_PHYSICAL_NAME_INFORMATION {
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_NETWORK_PHYSICAL_NAME_INFORMATION, *PFILE_NETWORK_PHYSICAL_NAME_INFORMATION;

typedef struct _FILE_STANDARD_LINK_INFORMATION {
    ULONG NumberOfAccessibleLinks;
    ULONG TotalNumberOfLinks;
    BOOLEAN DeletePending;
    BOOLEAN Directory;
} FILE_STANDARD_LINK_INFORMATION, *PFILE_STANDARD_LINK_INFORMATION;

//
// NtQuery(Set)EaFile
//
// The offset for the start of EaValue is EaName[EaNameLength + 1]
//
// begin_wdm


typedef struct _FILE_GET_EA_INFORMATION {
    ULONG NextEntryOffset;
    UCHAR EaNameLength;
    CHAR EaName[1];
} FILE_GET_EA_INFORMATION, *PFILE_GET_EA_INFORMATION;


//
// File Remote protocol information (FileRemoteProtocolInformation)
//

#define REMOTE_PROTOCOL_FLAG_LOOPBACK       0x00000001
#define REMOTE_PROTOCOL_FLAG_OFFLINE        0x00000002

typedef struct _FILE_REMOTE_PROTOCOL_INFORMATION
{
    // Structure Version
    USHORT StructureVersion;     // 1
    USHORT StructureSize;        // sizeof(FILE_REMOTE_PROTOCOL_INFORMATION)
    
    ULONG  Protocol;             // Protocol (WNNC_NET_*) defined in winnetwk.h or ntifs.h.
    
    // Protocol Version & Type
    USHORT ProtocolMajorVersion;
    USHORT ProtocolMinorVersion;
    USHORT ProtocolRevision;
    
    USHORT Reserved;
    
    // Protocol-Generic Information
    ULONG  Flags;
    
    struct {
        ULONG Reserved[8];
    } GenericReserved;

    // Protocol specific information
    
    struct {
        ULONG Reserved[16];
    } ProtocolSpecificReserved;
    
} FILE_REMOTE_PROTOCOL_INFORMATION, *PFILE_REMOTE_PROTOCOL_INFORMATION;

//
// NtQuery(Set)QuotaInformationFile
//

typedef struct _FILE_GET_QUOTA_INFORMATION {
    ULONG NextEntryOffset;
    ULONG SidLength;
    SID Sid;
} FILE_GET_QUOTA_INFORMATION, *PFILE_GET_QUOTA_INFORMATION;

typedef struct _FILE_QUOTA_INFORMATION {
    ULONG NextEntryOffset;
    ULONG SidLength;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER QuotaUsed;
    LARGE_INTEGER QuotaThreshold;
    LARGE_INTEGER QuotaLimit;
    SID Sid;
} FILE_QUOTA_INFORMATION, *PFILE_QUOTA_INFORMATION;


typedef struct _FILE_FS_ATTRIBUTE_INFORMATION {
    ULONG FileSystemAttributes;
    LONG MaximumComponentNameLength;
    ULONG FileSystemNameLength;
    WCHAR FileSystemName[1];
} FILE_FS_ATTRIBUTE_INFORMATION, *PFILE_FS_ATTRIBUTE_INFORMATION;

typedef struct _FILE_FS_DRIVER_PATH_INFORMATION {
    BOOLEAN DriverInPath;
    ULONG   DriverNameLength;
    WCHAR   DriverName[1];
} FILE_FS_DRIVER_PATH_INFORMATION, *PFILE_FS_DRIVER_PATH_INFORMATION;

typedef struct _FILE_FS_VOLUME_FLAGS_INFORMATION {
    ULONG Flags;
} FILE_FS_VOLUME_FLAGS_INFORMATION, *PFILE_FS_VOLUME_FLAGS_INFORMATION;

//
// File system control flags
//

#define FILE_VC_QUOTA_NONE                  0x00000000
#define FILE_VC_QUOTA_TRACK                 0x00000001
#define FILE_VC_QUOTA_ENFORCE               0x00000002
#define FILE_VC_QUOTA_MASK                  0x00000003

#define FILE_VC_CONTENT_INDEX_DISABLED      0x00000008

#define FILE_VC_LOG_QUOTA_THRESHOLD         0x00000010
#define FILE_VC_LOG_QUOTA_LIMIT             0x00000020
#define FILE_VC_LOG_VOLUME_THRESHOLD        0x00000040
#define FILE_VC_LOG_VOLUME_LIMIT            0x00000080

#define FILE_VC_QUOTAS_INCOMPLETE           0x00000100
#define FILE_VC_QUOTAS_REBUILDING           0x00000200

#define FILE_VC_VALID_MASK                  0x000003ff

typedef struct _FILE_FS_CONTROL_INFORMATION {
    LARGE_INTEGER FreeSpaceStartFiltering;
    LARGE_INTEGER FreeSpaceThreshold;
    LARGE_INTEGER FreeSpaceStopFiltering;
    LARGE_INTEGER DefaultQuotaThreshold;
    LARGE_INTEGER DefaultQuotaLimit;
    ULONG FileSystemControlFlags;
} FILE_FS_CONTROL_INFORMATION, *PFILE_FS_CONTROL_INFORMATION;


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__kernel_entry NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreateFile (
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
__kernel_entry NTSYSCALLAPI
NTSTATUS
NTAPI
NtDeviceIoControlFile (
    __in HANDLE FileHandle,
    __in_opt HANDLE Event,
    __in_opt PIO_APC_ROUTINE ApcRoutine,
    __in_opt PVOID ApcContext,
    __out PIO_STATUS_BLOCK IoStatusBlock,
    __in ULONG IoControlCode,
    __in_bcount_opt(InputBufferLength) PVOID InputBuffer,
    __in ULONG InputBufferLength,
    __out_bcount_opt(OutputBufferLength) PVOID OutputBuffer,
    __in ULONG OutputBufferLength
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__kernel_entry NTSYSCALLAPI
NTSTATUS
NTAPI
NtFsControlFile (
    __in HANDLE FileHandle,
    __in_opt HANDLE Event,
    __in_opt PIO_APC_ROUTINE ApcRoutine,
    __in_opt PVOID ApcContext,
    __out PIO_STATUS_BLOCK IoStatusBlock,
    __in ULONG FsControlCode,
    __in_bcount_opt(InputBufferLength) PVOID InputBuffer,
    __in ULONG InputBufferLength,
    __out_bcount_opt(OutputBufferLength) PVOID OutputBuffer,
    __in ULONG OutputBufferLength
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__kernel_entry NTSYSCALLAPI
NTSTATUS
NTAPI
NtLockFile (
    __in HANDLE FileHandle,
    __in_opt HANDLE Event,
    __in_opt PIO_APC_ROUTINE ApcRoutine,
    __in_opt PVOID ApcContext,
    __out PIO_STATUS_BLOCK IoStatusBlock,
    __in PLARGE_INTEGER ByteOffset,
    __in PLARGE_INTEGER Length,
    __in ULONG Key,
    __in BOOLEAN FailImmediately,
    __in BOOLEAN ExclusiveLock
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__kernel_entry NTSYSCALLAPI
NTSTATUS
NTAPI
NtOpenFile (
    __out PHANDLE FileHandle,
    __in ACCESS_MASK DesiredAccess,
    __in POBJECT_ATTRIBUTES ObjectAttributes,
    __out PIO_STATUS_BLOCK IoStatusBlock,
    __in ULONG ShareAccess,
    __in ULONG OpenOptions
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__kernel_entry NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryDirectoryFile (
    __in HANDLE FileHandle,
    __in_opt HANDLE Event,
    __in_opt PIO_APC_ROUTINE ApcRoutine,
    __in_opt PVOID ApcContext,
    __out PIO_STATUS_BLOCK IoStatusBlock,
    __out_bcount(Length) PVOID FileInformation,
    __in ULONG Length,
    __in FILE_INFORMATION_CLASS FileInformationClass,
    __in BOOLEAN ReturnSingleEntry,
    __in_opt PUNICODE_STRING FileName,
    __in BOOLEAN RestartScan
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__kernel_entry NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryInformationFile (
    __in HANDLE FileHandle,
    __out PIO_STATUS_BLOCK IoStatusBlock,
    __out_bcount(Length) PVOID FileInformation,
    __in ULONG Length,
    __in FILE_INFORMATION_CLASS FileInformationClass
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__kernel_entry NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryQuotaInformationFile (
    __in HANDLE FileHandle,
    __out PIO_STATUS_BLOCK IoStatusBlock,
    __out_bcount(Length) PVOID Buffer,
    __in ULONG Length,
    __in BOOLEAN ReturnSingleEntry,
    __in_bcount_opt(SidListLength) PVOID SidList,
    __in ULONG SidListLength,
    __in_opt PSID StartSid,
    __in BOOLEAN RestartScan
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__kernel_entry NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryVolumeInformationFile (
    __in HANDLE FileHandle,
    __out PIO_STATUS_BLOCK IoStatusBlock,
    __out_bcount(Length) PVOID FsInformation,
    __in ULONG Length,
    __in FS_INFORMATION_CLASS FsInformationClass
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__kernel_entry NTSYSCALLAPI
NTSTATUS
NTAPI
NtReadFile (
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
__kernel_entry NTSYSCALLAPI
NTSTATUS
NTAPI
NtSetInformationFile (
    __in HANDLE FileHandle,
    __out PIO_STATUS_BLOCK IoStatusBlock,
    __in_bcount(Length) PVOID FileInformation,
    __in ULONG Length,
    __in FILE_INFORMATION_CLASS FileInformationClass
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__kernel_entry NTSYSCALLAPI
NTSTATUS
NTAPI
NtSetQuotaInformationFile (
    __in HANDLE FileHandle,
    __out PIO_STATUS_BLOCK IoStatusBlock,
    __in_bcount(Length) PVOID Buffer,
    __in ULONG Length
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__kernel_entry NTSYSCALLAPI
NTSTATUS
NTAPI
NtSetVolumeInformationFile (
    __in HANDLE FileHandle,
    __out PIO_STATUS_BLOCK IoStatusBlock,
    __in_bcount(Length) PVOID FsInformation,
    __in ULONG Length,
    __in FS_INFORMATION_CLASS FsInformationClass
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__kernel_entry NTSYSCALLAPI
NTSTATUS
NTAPI
NtWriteFile (
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
__kernel_entry NTSYSCALLAPI
NTSTATUS
NTAPI
NtUnlockFile (
    __in HANDLE FileHandle,
    __out PIO_STATUS_BLOCK IoStatusBlock,
    __in PLARGE_INTEGER ByteOffset,
    __in PLARGE_INTEGER Length,
    __in ULONG Key
    );
#endif

//
// Macro definition for defining IOCTL and FSCTL function control codes.  Note
// that function codes 0-2047 are reserved for Microsoft Corporation, and
// 2048-4095 are reserved for customers.
//
// These macros are defined in devioctl.h which contains the portable IO
// definitions (for use by both DOS and NT)
//

//
// The IoGetFunctionCodeFromCtlCode( ControlCode ) Macro is defined in io.h
// This macro is used to extract the function code from an IOCTL (or FSCTL).
// The macro can only be used in kernel mode code.
//

//
// General File System control codes - Note that these values are valid
// regardless of the actual file system type
//

//
//  IMPORTANT:  These values have been arranged in order of increasing
//              control codes.  Do NOT breaks this!!  Add all new codes
//              at end of list regardless of functionality type.
//
//  Note: FSCTL_QUERY_RETRIEVAL_POINTER and FSCTL_MARK_AS_SYSTEM_HIVE only
//        work from Kernel mode on local paging files or the system hives.
//

// begin_winioctl

#ifndef _FILESYSTEMFSCTL_
#define _FILESYSTEMFSCTL_

//
// The following is a list of the native file system fsctls followed by
// additional network file system fsctls.  Some values have been
// decommissioned.
//

#define FSCTL_REQUEST_OPLOCK_LEVEL_1    CTL_CODE(FILE_DEVICE_FILE_SYSTEM,  0, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_REQUEST_OPLOCK_LEVEL_2    CTL_CODE(FILE_DEVICE_FILE_SYSTEM,  1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_REQUEST_BATCH_OPLOCK      CTL_CODE(FILE_DEVICE_FILE_SYSTEM,  2, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_OPLOCK_BREAK_ACKNOWLEDGE  CTL_CODE(FILE_DEVICE_FILE_SYSTEM,  3, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_OPBATCH_ACK_CLOSE_PENDING CTL_CODE(FILE_DEVICE_FILE_SYSTEM,  4, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_OPLOCK_BREAK_NOTIFY       CTL_CODE(FILE_DEVICE_FILE_SYSTEM,  5, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_LOCK_VOLUME               CTL_CODE(FILE_DEVICE_FILE_SYSTEM,  6, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_UNLOCK_VOLUME             CTL_CODE(FILE_DEVICE_FILE_SYSTEM,  7, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_DISMOUNT_VOLUME           CTL_CODE(FILE_DEVICE_FILE_SYSTEM,  8, METHOD_BUFFERED, FILE_ANY_ACCESS)
// decommissioned fsctl value                                              9
#define FSCTL_IS_VOLUME_MOUNTED         CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 10, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_IS_PATHNAME_VALID         CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 11, METHOD_BUFFERED, FILE_ANY_ACCESS) // PATHNAME_BUFFER,
#define FSCTL_MARK_VOLUME_DIRTY         CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 12, METHOD_BUFFERED, FILE_ANY_ACCESS)
// decommissioned fsctl value                                             13
#define FSCTL_QUERY_RETRIEVAL_POINTERS  CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 14,  METHOD_NEITHER, FILE_ANY_ACCESS)
#define FSCTL_GET_COMPRESSION           CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 15, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_SET_COMPRESSION           CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 16, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
// decommissioned fsctl value                                             17
// decommissioned fsctl value                                             18
#define FSCTL_SET_BOOTLOADER_ACCESSED   CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 19,  METHOD_NEITHER, FILE_ANY_ACCESS)
#define FSCTL_OPLOCK_BREAK_ACK_NO_2     CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 20, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_INVALIDATE_VOLUMES        CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 21, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_QUERY_FAT_BPB             CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 22, METHOD_BUFFERED, FILE_ANY_ACCESS) // FSCTL_QUERY_FAT_BPB_BUFFER
#define FSCTL_REQUEST_FILTER_OPLOCK     CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 23, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_FILESYSTEM_GET_STATISTICS CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 24, METHOD_BUFFERED, FILE_ANY_ACCESS) // FILESYSTEM_STATISTICS

#if (_WIN32_WINNT >= 0x0400)
#define FSCTL_GET_NTFS_VOLUME_DATA      CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 25, METHOD_BUFFERED, FILE_ANY_ACCESS) // NTFS_VOLUME_DATA_BUFFER
#define FSCTL_GET_NTFS_FILE_RECORD      CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 26, METHOD_BUFFERED, FILE_ANY_ACCESS) // NTFS_FILE_RECORD_INPUT_BUFFER, NTFS_FILE_RECORD_OUTPUT_BUFFER
#define FSCTL_GET_VOLUME_BITMAP         CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 27,  METHOD_NEITHER, FILE_ANY_ACCESS) // STARTING_LCN_INPUT_BUFFER, VOLUME_BITMAP_BUFFER
#define FSCTL_GET_RETRIEVAL_POINTERS    CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 28,  METHOD_NEITHER, FILE_ANY_ACCESS) // STARTING_VCN_INPUT_BUFFER, RETRIEVAL_POINTERS_BUFFER
#define FSCTL_MOVE_FILE                 CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 29, METHOD_BUFFERED, FILE_SPECIAL_ACCESS) // MOVE_FILE_DATA,
#define FSCTL_IS_VOLUME_DIRTY           CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 30, METHOD_BUFFERED, FILE_ANY_ACCESS)
// decomissioned fsctl value                                              31
#define FSCTL_ALLOW_EXTENDED_DASD_IO    CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 32, METHOD_NEITHER,  FILE_ANY_ACCESS)
#endif /* _WIN32_WINNT >= 0x0400 */

#if (_WIN32_WINNT >= 0x0500)
// decommissioned fsctl value                                             33
// decommissioned fsctl value                                             34
#define FSCTL_FIND_FILES_BY_SID         CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 35, METHOD_NEITHER, FILE_ANY_ACCESS)
// decommissioned fsctl value                                             36
// decommissioned fsctl value                                             37
#define FSCTL_SET_OBJECT_ID             CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 38, METHOD_BUFFERED, FILE_SPECIAL_ACCESS) // FILE_OBJECTID_BUFFER
#define FSCTL_GET_OBJECT_ID             CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 39, METHOD_BUFFERED, FILE_ANY_ACCESS) // FILE_OBJECTID_BUFFER
#define FSCTL_DELETE_OBJECT_ID          CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 40, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define FSCTL_SET_REPARSE_POINT         CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 41, METHOD_BUFFERED, FILE_SPECIAL_ACCESS) // REPARSE_DATA_BUFFER,
#define FSCTL_GET_REPARSE_POINT         CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 42, METHOD_BUFFERED, FILE_ANY_ACCESS) // REPARSE_DATA_BUFFER
#define FSCTL_DELETE_REPARSE_POINT      CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 43, METHOD_BUFFERED, FILE_SPECIAL_ACCESS) // REPARSE_DATA_BUFFER,
#define FSCTL_ENUM_USN_DATA             CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 44,  METHOD_NEITHER, FILE_ANY_ACCESS) // MFT_ENUM_DATA,
#define FSCTL_SECURITY_ID_CHECK         CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 45,  METHOD_NEITHER, FILE_READ_DATA)  // BULK_SECURITY_TEST_DATA,
#define FSCTL_READ_USN_JOURNAL          CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 46,  METHOD_NEITHER, FILE_ANY_ACCESS) // READ_USN_JOURNAL_DATA, USN
#define FSCTL_SET_OBJECT_ID_EXTENDED    CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 47, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define FSCTL_CREATE_OR_GET_OBJECT_ID   CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 48, METHOD_BUFFERED, FILE_ANY_ACCESS) // FILE_OBJECTID_BUFFER
#define FSCTL_SET_SPARSE                CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 49, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define FSCTL_SET_ZERO_DATA             CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 50, METHOD_BUFFERED, FILE_WRITE_DATA) // FILE_ZERO_DATA_INFORMATION,
#define FSCTL_QUERY_ALLOCATED_RANGES    CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 51,  METHOD_NEITHER, FILE_READ_DATA)  // FILE_ALLOCATED_RANGE_BUFFER, FILE_ALLOCATED_RANGE_BUFFER
#define FSCTL_ENABLE_UPGRADE            CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 52, METHOD_BUFFERED, FILE_WRITE_DATA)
// decommissioned fsctl value                                             52
#define FSCTL_SET_ENCRYPTION            CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 53,  METHOD_NEITHER, FILE_ANY_ACCESS) // ENCRYPTION_BUFFER, DECRYPTION_STATUS_BUFFER
#define FSCTL_ENCRYPTION_FSCTL_IO       CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 54,  METHOD_NEITHER, FILE_ANY_ACCESS)
#define FSCTL_WRITE_RAW_ENCRYPTED       CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 55,  METHOD_NEITHER, FILE_SPECIAL_ACCESS) // ENCRYPTED_DATA_INFO, EXTENDED_ENCRYPTED_DATA_INFO
#define FSCTL_READ_RAW_ENCRYPTED        CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 56,  METHOD_NEITHER, FILE_SPECIAL_ACCESS) // REQUEST_RAW_ENCRYPTED_DATA, ENCRYPTED_DATA_INFO, EXTENDED_ENCRYPTED_DATA_INFO
#define FSCTL_CREATE_USN_JOURNAL        CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 57,  METHOD_NEITHER, FILE_ANY_ACCESS) // CREATE_USN_JOURNAL_DATA,
#define FSCTL_READ_FILE_USN_DATA        CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 58,  METHOD_NEITHER, FILE_ANY_ACCESS) // Read the Usn Record for a file
#define FSCTL_WRITE_USN_CLOSE_RECORD    CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 59,  METHOD_NEITHER, FILE_ANY_ACCESS) // Generate Close Usn Record
#define FSCTL_EXTEND_VOLUME             CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 60, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_QUERY_USN_JOURNAL         CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 61, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_DELETE_USN_JOURNAL        CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 62, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_MARK_HANDLE               CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 63, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_SIS_COPYFILE              CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 64, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_SIS_LINK_FILES            CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 65, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
// decommissional fsctl value                                             66
// decommissioned fsctl value                                             67
// decommissioned fsctl value                                             68
#define FSCTL_RECALL_FILE               CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 69, METHOD_NEITHER, FILE_ANY_ACCESS)
// decommissioned fsctl value                                             70
#define FSCTL_READ_FROM_PLEX            CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 71, METHOD_OUT_DIRECT, FILE_READ_DATA)
#define FSCTL_FILE_PREFETCH             CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 72, METHOD_BUFFERED, FILE_SPECIAL_ACCESS) // FILE_PREFETCH
#endif /* _WIN32_WINNT >= 0x0500 */

#if (_WIN32_WINNT >= 0x0600)
#define FSCTL_MAKE_MEDIA_COMPATIBLE         CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 76, METHOD_BUFFERED, FILE_WRITE_DATA) // UDFS R/W
#define FSCTL_SET_DEFECT_MANAGEMENT         CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 77, METHOD_BUFFERED, FILE_WRITE_DATA) // UDFS R/W
#define FSCTL_QUERY_SPARING_INFO            CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 78, METHOD_BUFFERED, FILE_ANY_ACCESS) // UDFS R/W
#define FSCTL_QUERY_ON_DISK_VOLUME_INFO     CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 79, METHOD_BUFFERED, FILE_ANY_ACCESS) // C/UDFS
#define FSCTL_SET_VOLUME_COMPRESSION_STATE  CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 80, METHOD_BUFFERED, FILE_SPECIAL_ACCESS) // VOLUME_COMPRESSION_STATE
// decommissioned fsctl value                                                 80
#define FSCTL_TXFS_MODIFY_RM                CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 81, METHOD_BUFFERED, FILE_WRITE_DATA) // TxF
#define FSCTL_TXFS_QUERY_RM_INFORMATION     CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 82, METHOD_BUFFERED, FILE_READ_DATA)  // TxF
// decommissioned fsctl value                                                 83
#define FSCTL_TXFS_ROLLFORWARD_REDO         CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 84, METHOD_BUFFERED, FILE_WRITE_DATA) // TxF
#define FSCTL_TXFS_ROLLFORWARD_UNDO         CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 85, METHOD_BUFFERED, FILE_WRITE_DATA) // TxF
#define FSCTL_TXFS_START_RM                 CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 86, METHOD_BUFFERED, FILE_WRITE_DATA) // TxF
#define FSCTL_TXFS_SHUTDOWN_RM              CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 87, METHOD_BUFFERED, FILE_WRITE_DATA) // TxF
#define FSCTL_TXFS_READ_BACKUP_INFORMATION  CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 88, METHOD_BUFFERED, FILE_READ_DATA)  // TxF
#define FSCTL_TXFS_WRITE_BACKUP_INFORMATION CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 89, METHOD_BUFFERED, FILE_WRITE_DATA) // TxF
#define FSCTL_TXFS_CREATE_SECONDARY_RM      CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 90, METHOD_BUFFERED, FILE_WRITE_DATA) // TxF
#define FSCTL_TXFS_GET_METADATA_INFO        CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 91, METHOD_BUFFERED, FILE_READ_DATA)  // TxF
#define FSCTL_TXFS_GET_TRANSACTED_VERSION   CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 92, METHOD_BUFFERED, FILE_READ_DATA)  // TxF
// decommissioned fsctl value                                                 93
#define FSCTL_TXFS_SAVEPOINT_INFORMATION    CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 94, METHOD_BUFFERED, FILE_WRITE_DATA) // TxF
#define FSCTL_TXFS_CREATE_MINIVERSION       CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 95, METHOD_BUFFERED, FILE_WRITE_DATA) // TxF
// decommissioned fsctl value                                                 96
// decommissioned fsctl value                                                 97
// decommissioned fsctl value                                                 98
#define FSCTL_TXFS_TRANSACTION_ACTIVE       CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 99, METHOD_BUFFERED, FILE_READ_DATA)  // TxF
#define FSCTL_SET_ZERO_ON_DEALLOCATION      CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 101, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define FSCTL_SET_REPAIR                    CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 102, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_GET_REPAIR                    CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 103, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_WAIT_FOR_REPAIR               CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 104, METHOD_BUFFERED, FILE_ANY_ACCESS)
// decommissioned fsctl value                                                 105
#define FSCTL_INITIATE_REPAIR               CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 106, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_CSC_INTERNAL                  CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 107, METHOD_NEITHER, FILE_ANY_ACCESS) // CSC internal implementation
#define FSCTL_SHRINK_VOLUME                 CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 108, METHOD_BUFFERED, FILE_SPECIAL_ACCESS) // SHRINK_VOLUME_INFORMATION
#define FSCTL_SET_SHORT_NAME_BEHAVIOR       CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 109, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_DFSR_SET_GHOST_HANDLE_STATE   CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 110, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
//  Values 111 - 119 are reserved for FSRM.
//

#define FSCTL_TXFS_LIST_TRANSACTION_LOCKED_FILES \
                                            CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 120, METHOD_BUFFERED, FILE_READ_DATA) // TxF
#define FSCTL_TXFS_LIST_TRANSACTIONS        CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 121, METHOD_BUFFERED, FILE_READ_DATA) // TxF
#define FSCTL_QUERY_PAGEFILE_ENCRYPTION     CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 122, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif /* _WIN32_WINNT >= 0x0600 */

#if (_WIN32_WINNT >= 0x0600)
#define FSCTL_RESET_VOLUME_ALLOCATION_HINTS CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 123, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif /* _WIN32_WINNT >= 0x0600 */

#if (_WIN32_WINNT >= 0x0601)
#define FSCTL_QUERY_DEPENDENT_VOLUME        CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 124, METHOD_BUFFERED, FILE_ANY_ACCESS)    // Dependency File System Filter
#define FSCTL_SD_GLOBAL_CHANGE              CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 125, METHOD_BUFFERED, FILE_ANY_ACCESS) // Update NTFS Security Descriptors
#endif /* _WIN32_WINNT >= 0x0601 */

#if (_WIN32_WINNT >= 0x0600)
#define FSCTL_TXFS_READ_BACKUP_INFORMATION2 CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 126, METHOD_BUFFERED, FILE_ANY_ACCESS) // TxF
#endif /* _WIN32_WINNT >= 0x0600 */

#if (_WIN32_WINNT >= 0x0601)
#define FSCTL_LOOKUP_STREAM_FROM_CLUSTER    CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 127, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_TXFS_WRITE_BACKUP_INFORMATION2 CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 128, METHOD_BUFFERED, FILE_ANY_ACCESS) // TxF
#define FSCTL_FILE_TYPE_NOTIFICATION        CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 129, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif


//
//  Values 130 - 130 are available
//

//
//  Values 131 - 139 are reserved for FSRM.
//

#if (_WIN32_WINNT >= 0x0601)
#define FSCTL_GET_BOOT_AREA_INFO            CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 140, METHOD_BUFFERED, FILE_ANY_ACCESS) // BOOT_AREA_INFO
#define FSCTL_GET_RETRIEVAL_POINTER_BASE    CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 141, METHOD_BUFFERED, FILE_ANY_ACCESS) // RETRIEVAL_POINTER_BASE
#define FSCTL_SET_PERSISTENT_VOLUME_STATE   CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 142, METHOD_BUFFERED, FILE_ANY_ACCESS)  // FILE_FS_PERSISTENT_VOLUME_INFORMATION
#define FSCTL_QUERY_PERSISTENT_VOLUME_STATE CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 143, METHOD_BUFFERED, FILE_ANY_ACCESS)  // FILE_FS_PERSISTENT_VOLUME_INFORMATION

#define FSCTL_REQUEST_OPLOCK                CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 144, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define FSCTL_CSV_TUNNEL_REQUEST            CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 145, METHOD_BUFFERED, FILE_ANY_ACCESS) // CSV_TUNNEL_REQUEST
#define FSCTL_IS_CSV_FILE                   CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 146, METHOD_BUFFERED, FILE_ANY_ACCESS) // IS_CSV_FILE

#define FSCTL_QUERY_FILE_SYSTEM_RECOGNITION CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 147, METHOD_BUFFERED, FILE_ANY_ACCESS) // 
#define FSCTL_CSV_GET_VOLUME_PATH_NAME      CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 148, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_CSV_GET_VOLUME_NAME_FOR_VOLUME_MOUNT_POINT CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 149, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_CSV_GET_VOLUME_PATH_NAMES_FOR_VOLUME_NAME CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 150,  METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_IS_FILE_ON_CSV_VOLUME         CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 151,  METHOD_BUFFERED, FILE_ANY_ACCESS)

#endif /* _WIN32_WINNT >= 0x0601 */

#define FSCTL_MARK_AS_SYSTEM_HIVE           FSCTL_SET_BOOTLOADER_ACCESSED


#if(_WIN32_WINNT >= 0x0601)

//
// Structure for FSCTL_IS_CSV_FILE
//

typedef struct _CSV_NAMESPACE_INFO {

    ULONG         Version;
    ULONG         DeviceNumber;
    LARGE_INTEGER StartingOffset;
    ULONG         SectorSize;

} CSV_NAMESPACE_INFO, *PCSV_NAMESPACE_INFO;

#define CSV_NAMESPACE_INFO_V1 (sizeof(CSV_NAMESPACE_INFO))
#define CSV_INVALID_DEVICE_NUMBER 0xFFFFFFFF

#endif /* _WIN32_WINNT >= 0x0601 */

//
// The following long list of structs are associated with the preceeding
// file system fsctls.
//

//
// Structure for FSCTL_IS_PATHNAME_VALID
//

typedef struct _PATHNAME_BUFFER {

    ULONG PathNameLength;
    WCHAR Name[1];

} PATHNAME_BUFFER, *PPATHNAME_BUFFER;

//
// Structure for FSCTL_QUERY_BPB_INFO
//

typedef struct _FSCTL_QUERY_FAT_BPB_BUFFER {

    UCHAR First0x24BytesOfBootSector[0x24];

} FSCTL_QUERY_FAT_BPB_BUFFER, *PFSCTL_QUERY_FAT_BPB_BUFFER;

#if (_WIN32_WINNT >= 0x0400)
//
// Structures for FSCTL_GET_NTFS_VOLUME_DATA.
// The user must pass the basic buffer below.  Ntfs
// will return as many fields as available in the extended
// buffer which follows immediately after the VOLUME_DATA_BUFFER.
//

typedef struct {

    LARGE_INTEGER VolumeSerialNumber;
    LARGE_INTEGER NumberSectors;
    LARGE_INTEGER TotalClusters;
    LARGE_INTEGER FreeClusters;
    LARGE_INTEGER TotalReserved;
    ULONG BytesPerSector;
    ULONG BytesPerCluster;
    ULONG BytesPerFileRecordSegment;
    ULONG ClustersPerFileRecordSegment;
    LARGE_INTEGER MftValidDataLength;
    LARGE_INTEGER MftStartLcn;
    LARGE_INTEGER Mft2StartLcn;
    LARGE_INTEGER MftZoneStart;
    LARGE_INTEGER MftZoneEnd;

} NTFS_VOLUME_DATA_BUFFER, *PNTFS_VOLUME_DATA_BUFFER;

typedef struct {

    ULONG ByteCount;

    USHORT MajorVersion;
    USHORT MinorVersion;

} NTFS_EXTENDED_VOLUME_DATA, *PNTFS_EXTENDED_VOLUME_DATA;
#endif /* _WIN32_WINNT >= 0x0400 */

#if (_WIN32_WINNT >= 0x0400)
//
// Structure for FSCTL_GET_VOLUME_BITMAP
//

typedef struct {

    LARGE_INTEGER StartingLcn;

} STARTING_LCN_INPUT_BUFFER, *PSTARTING_LCN_INPUT_BUFFER;

typedef struct {

    LARGE_INTEGER StartingLcn;
    LARGE_INTEGER BitmapSize;
    UCHAR Buffer[1];

} VOLUME_BITMAP_BUFFER, *PVOLUME_BITMAP_BUFFER;
#endif /* _WIN32_WINNT >= 0x0400 */

#if (_WIN32_WINNT >= 0x0400)
//
// Structure for FSCTL_GET_RETRIEVAL_POINTERS
//

typedef struct {

    LARGE_INTEGER StartingVcn;

} STARTING_VCN_INPUT_BUFFER, *PSTARTING_VCN_INPUT_BUFFER;

typedef struct RETRIEVAL_POINTERS_BUFFER {

    ULONG ExtentCount;
    LARGE_INTEGER StartingVcn;
    struct {
        LARGE_INTEGER NextVcn;
        LARGE_INTEGER Lcn;
    } Extents[1];

} RETRIEVAL_POINTERS_BUFFER, *PRETRIEVAL_POINTERS_BUFFER;
#endif /* _WIN32_WINNT >= 0x0400 */

#if (_WIN32_WINNT >= 0x0400)
//
// Structures for FSCTL_GET_NTFS_FILE_RECORD
//

typedef struct {

    LARGE_INTEGER FileReferenceNumber;

} NTFS_FILE_RECORD_INPUT_BUFFER, *PNTFS_FILE_RECORD_INPUT_BUFFER;

typedef struct {

    LARGE_INTEGER FileReferenceNumber;
    ULONG FileRecordLength;
    UCHAR FileRecordBuffer[1];

} NTFS_FILE_RECORD_OUTPUT_BUFFER, *PNTFS_FILE_RECORD_OUTPUT_BUFFER;
#endif /* _WIN32_WINNT >= 0x0400 */

#if (_WIN32_WINNT >= 0x0400)
//
// Structure for FSCTL_MOVE_FILE
//

typedef struct {

    HANDLE FileHandle;
    LARGE_INTEGER StartingVcn;
    LARGE_INTEGER StartingLcn;
    ULONG ClusterCount;

} MOVE_FILE_DATA, *PMOVE_FILE_DATA;

typedef struct {

    HANDLE FileHandle;
    LARGE_INTEGER SourceFileRecord;
    LARGE_INTEGER TargetFileRecord;

} MOVE_FILE_RECORD_DATA, *PMOVE_FILE_RECORD_DATA;


#if defined(_WIN64)
//
//  32/64 Bit thunking support structure
//

typedef struct _MOVE_FILE_DATA32 {

    UINT32 FileHandle;
    LARGE_INTEGER StartingVcn;
    LARGE_INTEGER StartingLcn;
    ULONG ClusterCount;

} MOVE_FILE_DATA32, *PMOVE_FILE_DATA32;
#endif
#endif /* _WIN32_WINNT >= 0x0400 */

#if (_WIN32_WINNT >= 0x0500)
//
// Structures for FSCTL_FIND_FILES_BY_SID
//

typedef struct {
    ULONG Restart;
    SID Sid;
} FIND_BY_SID_DATA, *PFIND_BY_SID_DATA;

typedef struct {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FIND_BY_SID_OUTPUT, *PFIND_BY_SID_OUTPUT;

#endif /* _WIN32_WINNT >= 0x0500 */

#if (_WIN32_WINNT >= 0x0500)
//
//  The following structures apply to Usn operations.
//

//
// Structure for FSCTL_ENUM_USN_DATA
//

typedef struct {

    ULONGLONG StartFileReferenceNumber;
    USN LowUsn;
    USN HighUsn;

} MFT_ENUM_DATA, *PMFT_ENUM_DATA;

//
// Structure for FSCTL_CREATE_USN_JOURNAL
//

typedef struct {

    ULONGLONG MaximumSize;
    ULONGLONG AllocationDelta;

} CREATE_USN_JOURNAL_DATA, *PCREATE_USN_JOURNAL_DATA;

//
// Structure for FSCTL_READ_USN_JOURNAL
//

typedef struct {

    USN StartUsn;
    ULONG ReasonMask;
    ULONG ReturnOnlyOnClose;
    ULONGLONG Timeout;
    ULONGLONG BytesToWaitFor;
    ULONGLONG UsnJournalID;

} READ_USN_JOURNAL_DATA, *PREAD_USN_JOURNAL_DATA;

//
//  The initial Major.Minor version of the Usn record will be 2.0.
//  In general, the MinorVersion may be changed if fields are added
//  to this structure in such a way that the previous version of the
//  software can still correctly the fields it knows about.  The
//  MajorVersion should only be changed if the previous version of
//  any software using this structure would incorrectly handle new
//  records due to structure changes.
//
//  The first update to this will force the structure to version 2.0.
//  This will add the extended information about the source as
//  well as indicate the file name offset within the structure.
//
//  The following structure is returned with these fsctls.
//
//      FSCTL_READ_USN_JOURNAL
//      FSCTL_READ_FILE_USN_DATA
//      FSCTL_ENUM_USN_DATA
//

typedef struct {

    ULONG RecordLength;
    USHORT MajorVersion;
    USHORT MinorVersion;
    ULONGLONG FileReferenceNumber;
    ULONGLONG ParentFileReferenceNumber;
    USN Usn;
    LARGE_INTEGER TimeStamp;
    ULONG Reason;
    ULONG SourceInfo;
    ULONG SecurityId;
    ULONG FileAttributes;
    USHORT FileNameLength;
    USHORT FileNameOffset;
    WCHAR FileName[1];

} USN_RECORD, *PUSN_RECORD;

#define USN_PAGE_SIZE                    (0x1000)

#define USN_REASON_DATA_OVERWRITE        (0x00000001)
#define USN_REASON_DATA_EXTEND           (0x00000002)
#define USN_REASON_DATA_TRUNCATION       (0x00000004)
#define USN_REASON_NAMED_DATA_OVERWRITE  (0x00000010)
#define USN_REASON_NAMED_DATA_EXTEND     (0x00000020)
#define USN_REASON_NAMED_DATA_TRUNCATION (0x00000040)
#define USN_REASON_FILE_CREATE           (0x00000100)
#define USN_REASON_FILE_DELETE           (0x00000200)
#define USN_REASON_EA_CHANGE             (0x00000400)
#define USN_REASON_SECURITY_CHANGE       (0x00000800)
#define USN_REASON_RENAME_OLD_NAME       (0x00001000)
#define USN_REASON_RENAME_NEW_NAME       (0x00002000)
#define USN_REASON_INDEXABLE_CHANGE      (0x00004000)
#define USN_REASON_BASIC_INFO_CHANGE     (0x00008000)
#define USN_REASON_HARD_LINK_CHANGE      (0x00010000)
#define USN_REASON_COMPRESSION_CHANGE    (0x00020000)
#define USN_REASON_ENCRYPTION_CHANGE     (0x00040000)
#define USN_REASON_OBJECT_ID_CHANGE      (0x00080000)
#define USN_REASON_REPARSE_POINT_CHANGE  (0x00100000)
#define USN_REASON_STREAM_CHANGE         (0x00200000)
#define USN_REASON_TRANSACTED_CHANGE     (0x00400000)
#define USN_REASON_CLOSE                 (0x80000000)

//
//  Structure for FSCTL_QUERY_USN_JOUNAL
//

typedef struct {

    ULONGLONG UsnJournalID;
    USN FirstUsn;
    USN NextUsn;
    USN LowestValidUsn;
    USN MaxUsn;
    ULONGLONG MaximumSize;
    ULONGLONG AllocationDelta;

} USN_JOURNAL_DATA, *PUSN_JOURNAL_DATA;

//
//  Structure for FSCTL_DELETE_USN_JOURNAL
//

typedef struct {

    ULONGLONG UsnJournalID;
    ULONG DeleteFlags;

} DELETE_USN_JOURNAL_DATA, *PDELETE_USN_JOURNAL_DATA;

#define USN_DELETE_FLAG_DELETE              (0x00000001)
#define USN_DELETE_FLAG_NOTIFY              (0x00000002)

#define USN_DELETE_VALID_FLAGS              (0x00000003)

//
//  Structure for FSCTL_MARK_HANDLE
//

typedef struct {

    ULONG UsnSourceInfo;
    HANDLE VolumeHandle;
    ULONG HandleInfo;

} MARK_HANDLE_INFO, *PMARK_HANDLE_INFO;

#if defined(_WIN64)
//
//  32/64 Bit thunking support structure
//

typedef struct {

    ULONG UsnSourceInfo;
    UINT32 VolumeHandle;
    ULONG HandleInfo;

} MARK_HANDLE_INFO32, *PMARK_HANDLE_INFO32;
#endif

//
//  Flags for the additional source information above.
//
//      USN_SOURCE_DATA_MANAGEMENT - Service is not modifying the external view
//          of any part of the file.  Typical case is HSM moving data to
//          and from external storage.
//
//      USN_SOURCE_AUXILIARY_DATA - Service is not modifying the external view
//          of the file with regard to the application that created this file.
//          Can be used to add private data streams to a file.
//
//      USN_SOURCE_REPLICATION_MANAGEMENT - Service is modifying a file to match
//          the contents of the same file which exists in another member of the
//          replica set.
//

#define USN_SOURCE_DATA_MANAGEMENT          (0x00000001)
#define USN_SOURCE_AUXILIARY_DATA           (0x00000002)
#define USN_SOURCE_REPLICATION_MANAGEMENT   (0x00000004)

//
//  Flags for the HandleInfo field above
//
//  MARK_HANDLE_PROTECT_CLUSTERS - disallow any defragmenting (FSCTL_MOVE_FILE) until the
//      the handle is closed
//
//  MARK_HANDLE_TXF_SYSTEM_LOG - indicates that this stream is being used as the Txf
//      log for an RM on the volume.  Must be called in the kernel using
//      IRP_MN_KERNEL_CALL.
//
//  MARK_HANDLE_NOT_TXF_SYSTEM_LOG - indicates that this user is no longer using this
//      object as a log file.
//

#define MARK_HANDLE_PROTECT_CLUSTERS        (0x00000001)
#define MARK_HANDLE_TXF_SYSTEM_LOG          (0x00000004)
#define MARK_HANDLE_NOT_TXF_SYSTEM_LOG      (0x00000008)

#endif /* _WIN32_WINNT >= 0x0500 */

#if (_WIN32_WINNT >= 0x0601)

#define MARK_HANDLE_REALTIME                (0x00000020)
#define MARK_HANDLE_NOT_REALTIME            (0x00000040)

#define NO_8DOT3_NAME_PRESENT               (0x00000001)
#define REMOVED_8DOT3_NAME                  (0x00000002)

#define PERSISTENT_VOLUME_STATE_SHORT_NAME_CREATION_DISABLED        (0x00000001)

#endif /* _WIN32_WINNT >= 0x0601 */


#if (_WIN32_WINNT >= 0x0500)
//
// Structure for FSCTL_SECURITY_ID_CHECK
//

typedef struct {

    ACCESS_MASK DesiredAccess;
    ULONG SecurityIds[1];

} BULK_SECURITY_TEST_DATA, *PBULK_SECURITY_TEST_DATA;
#endif /* _WIN32_WINNT >= 0x0500 */

#if (_WIN32_WINNT >= 0x0500)
//
//  Output flags for the FSCTL_IS_VOLUME_DIRTY
//

#define VOLUME_IS_DIRTY                  (0x00000001)
#define VOLUME_UPGRADE_SCHEDULED         (0x00000002)
#define VOLUME_SESSION_OPEN              (0x00000004)
#endif /* _WIN32_WINNT >= 0x0500 */

#if (_WIN32_WINNT >= 0x0500)
//
// Structures for FSCTL_FILE_PREFETCH
//

typedef struct _FILE_PREFETCH {
    ULONG Type;
    ULONG Count;
    ULONGLONG Prefetch[1];
} FILE_PREFETCH, *PFILE_PREFETCH;

typedef struct _FILE_PREFETCH_EX {
    ULONG Type;
    ULONG Count;
    PVOID Context;
    ULONGLONG Prefetch[1];
} FILE_PREFETCH_EX, *PFILE_PREFETCH_EX;

#define FILE_PREFETCH_TYPE_FOR_CREATE       0x1
#define FILE_PREFETCH_TYPE_FOR_DIRENUM      0x2
#define FILE_PREFETCH_TYPE_FOR_CREATE_EX    0x3
#define FILE_PREFETCH_TYPE_FOR_DIRENUM_EX   0x4

#define FILE_PREFETCH_TYPE_MAX              0x4

#endif /* _WIN32_WINNT >= 0x0500 */

//
// Structures for FSCTL_FILESYSTEM_GET_STATISTICS
//
// Filesystem performance counters
//

typedef struct _FILESYSTEM_STATISTICS {

    USHORT FileSystemType;
    USHORT Version;                     // currently version 1

    ULONG SizeOfCompleteStructure;      // must by a mutiple of 64 bytes

    ULONG UserFileReads;
    ULONG UserFileReadBytes;
    ULONG UserDiskReads;
    ULONG UserFileWrites;
    ULONG UserFileWriteBytes;
    ULONG UserDiskWrites;

    ULONG MetaDataReads;
    ULONG MetaDataReadBytes;
    ULONG MetaDataDiskReads;
    ULONG MetaDataWrites;
    ULONG MetaDataWriteBytes;
    ULONG MetaDataDiskWrites;

    //
    //  The file system's private structure is appended here.
    //

} FILESYSTEM_STATISTICS, *PFILESYSTEM_STATISTICS;

// values for FS_STATISTICS.FileSystemType

#define FILESYSTEM_STATISTICS_TYPE_NTFS     1
#define FILESYSTEM_STATISTICS_TYPE_FAT      2
#define FILESYSTEM_STATISTICS_TYPE_EXFAT    3

//
//  File System Specific Statistics Data
//

typedef struct _FAT_STATISTICS {
    ULONG CreateHits;
    ULONG SuccessfulCreates;
    ULONG FailedCreates;

    ULONG NonCachedReads;
    ULONG NonCachedReadBytes;
    ULONG NonCachedWrites;
    ULONG NonCachedWriteBytes;

    ULONG NonCachedDiskReads;
    ULONG NonCachedDiskWrites;
} FAT_STATISTICS, *PFAT_STATISTICS;

typedef struct _EXFAT_STATISTICS {
    ULONG CreateHits;
    ULONG SuccessfulCreates;
    ULONG FailedCreates;

    ULONG NonCachedReads;
    ULONG NonCachedReadBytes;
    ULONG NonCachedWrites;
    ULONG NonCachedWriteBytes;

    ULONG NonCachedDiskReads;
    ULONG NonCachedDiskWrites;
} EXFAT_STATISTICS, *PEXFAT_STATISTICS;

typedef struct _NTFS_STATISTICS {

    ULONG LogFileFullExceptions;
    ULONG OtherExceptions;

    //
    // Other meta data io's
    //

    ULONG MftReads;
    ULONG MftReadBytes;
    ULONG MftWrites;
    ULONG MftWriteBytes;
    struct {
        USHORT Write;
        USHORT Create;
        USHORT SetInfo;
        USHORT Flush;
    } MftWritesUserLevel;

    USHORT MftWritesFlushForLogFileFull;
    USHORT MftWritesLazyWriter;
    USHORT MftWritesUserRequest;

    ULONG Mft2Writes;
    ULONG Mft2WriteBytes;
    struct {
        USHORT Write;
        USHORT Create;
        USHORT SetInfo;
        USHORT Flush;
    } Mft2WritesUserLevel;

    USHORT Mft2WritesFlushForLogFileFull;
    USHORT Mft2WritesLazyWriter;
    USHORT Mft2WritesUserRequest;

    ULONG RootIndexReads;
    ULONG RootIndexReadBytes;
    ULONG RootIndexWrites;
    ULONG RootIndexWriteBytes;

    ULONG BitmapReads;
    ULONG BitmapReadBytes;
    ULONG BitmapWrites;
    ULONG BitmapWriteBytes;

    USHORT BitmapWritesFlushForLogFileFull;
    USHORT BitmapWritesLazyWriter;
    USHORT BitmapWritesUserRequest;

    struct {
        USHORT Write;
        USHORT Create;
        USHORT SetInfo;
    } BitmapWritesUserLevel;

    ULONG MftBitmapReads;
    ULONG MftBitmapReadBytes;
    ULONG MftBitmapWrites;
    ULONG MftBitmapWriteBytes;

    USHORT MftBitmapWritesFlushForLogFileFull;
    USHORT MftBitmapWritesLazyWriter;
    USHORT MftBitmapWritesUserRequest;

    struct {
        USHORT Write;
        USHORT Create;
        USHORT SetInfo;
        USHORT Flush;
    } MftBitmapWritesUserLevel;

    ULONG UserIndexReads;
    ULONG UserIndexReadBytes;
    ULONG UserIndexWrites;
    ULONG UserIndexWriteBytes;

    //
    // Additions for NT 5.0
    //

    ULONG LogFileReads;
    ULONG LogFileReadBytes;
    ULONG LogFileWrites;
    ULONG LogFileWriteBytes;

    struct {
        ULONG Calls;                // number of individual calls to allocate clusters
        ULONG Clusters;             // number of clusters allocated
        ULONG Hints;                // number of times a hint was specified

        ULONG RunsReturned;         // number of runs used to satisify all the requests

        ULONG HintsHonored;         // number of times the hint was useful
        ULONG HintsClusters;        // number of clusters allocated via the hint
        ULONG Cache;                // number of times the cache was useful other than the hint
        ULONG CacheClusters;        // number of clusters allocated via the cache other than the hint
        ULONG CacheMiss;            // number of times the cache wasn't useful
        ULONG CacheMissClusters;    // number of clusters allocated without the cache
    } Allocate;

} NTFS_STATISTICS, *PNTFS_STATISTICS;

#if (_WIN32_WINNT >= 0x0500)
//
// Structure for FSCTL_SET_OBJECT_ID, FSCTL_GET_OBJECT_ID, and FSCTL_CREATE_OR_GET_OBJECT_ID
//

#if _MSC_VER >= 1200
#pragma warning(push)
#endif
#pragma warning(disable:4201)       // unnamed struct

typedef struct _FILE_OBJECTID_BUFFER {

    //
    //  This is the portion of the object id that is indexed.
    //

    UCHAR ObjectId[16];

    //
    //  This portion of the object id is not indexed, it's just
    //  some metadata for the user's benefit.
    //

    union {
        struct {
            UCHAR BirthVolumeId[16];
            UCHAR BirthObjectId[16];
            UCHAR DomainId[16];
        } DUMMYSTRUCTNAME;
        UCHAR ExtendedInfo[48];
    } DUMMYUNIONNAME;

} FILE_OBJECTID_BUFFER, *PFILE_OBJECTID_BUFFER;

#if _MSC_VER >= 1200
#pragma warning(pop)
#else
#pragma warning( default : 4201 ) /* nonstandard extension used : nameless struct/union */
#endif

#endif /* _WIN32_WINNT >= 0x0500 */


#if (_WIN32_WINNT >= 0x0500)
//
// Structure for FSCTL_SET_SPARSE
//

typedef struct _FILE_SET_SPARSE_BUFFER {
    BOOLEAN SetSparse;
} FILE_SET_SPARSE_BUFFER, *PFILE_SET_SPARSE_BUFFER;


#endif /* _WIN32_WINNT >= 0x0500 */


#if (_WIN32_WINNT >= 0x0500)
//
// Structure for FSCTL_SET_ZERO_DATA
//

typedef struct _FILE_ZERO_DATA_INFORMATION {

    LARGE_INTEGER FileOffset;
    LARGE_INTEGER BeyondFinalZero;

} FILE_ZERO_DATA_INFORMATION, *PFILE_ZERO_DATA_INFORMATION;
#endif /* _WIN32_WINNT >= 0x0500 */

#if (_WIN32_WINNT >= 0x0500)
//
// Structure for FSCTL_QUERY_ALLOCATED_RANGES
//

//
// Querying the allocated ranges requires an output buffer to store the
// allocated ranges and an input buffer to specify the range to query.
// The input buffer contains a single entry, the output buffer is an
// array of the following structure.
//

typedef struct _FILE_ALLOCATED_RANGE_BUFFER {

    LARGE_INTEGER FileOffset;
    LARGE_INTEGER Length;

} FILE_ALLOCATED_RANGE_BUFFER, *PFILE_ALLOCATED_RANGE_BUFFER;
#endif /* _WIN32_WINNT >= 0x0500 */


#if (_WIN32_WINNT >= 0x0500)
//
// Structures for FSCTL_SET_ENCRYPTION, FSCTL_WRITE_RAW_ENCRYPTED, and FSCTL_READ_RAW_ENCRYPTED
//

//
//  The input buffer to set encryption indicates whether we are to encrypt/decrypt a file
//  or an individual stream.
//

typedef struct _ENCRYPTION_BUFFER {

    ULONG EncryptionOperation;
    UCHAR Private[1];

} ENCRYPTION_BUFFER, *PENCRYPTION_BUFFER;

#define FILE_SET_ENCRYPTION         0x00000001
#define FILE_CLEAR_ENCRYPTION       0x00000002
#define STREAM_SET_ENCRYPTION       0x00000003
#define STREAM_CLEAR_ENCRYPTION     0x00000004

#define MAXIMUM_ENCRYPTION_VALUE    0x00000004

//
//  The optional output buffer to set encryption indicates that the last encrypted
//  stream in a file has been marked as decrypted.
//

typedef struct _DECRYPTION_STATUS_BUFFER {

    BOOLEAN NoEncryptedStreams;

} DECRYPTION_STATUS_BUFFER, *PDECRYPTION_STATUS_BUFFER;

#define ENCRYPTION_FORMAT_DEFAULT        (0x01)

#define COMPRESSION_FORMAT_SPARSE        (0x4000)

//
//  Request Encrypted Data structure.  This is used to indicate
//  the range of the file to read.  It also describes the
//  output buffer used to return the data.
//

typedef struct _REQUEST_RAW_ENCRYPTED_DATA {

    //
    //  Requested file offset and requested length to read.
    //  The fsctl will round the starting offset down
    //  to a file system boundary.  It will also
    //  round the length up to a file system boundary.
    //

    LONGLONG FileOffset;
    ULONG Length;

} REQUEST_RAW_ENCRYPTED_DATA, *PREQUEST_RAW_ENCRYPTED_DATA;

//
//  Encrypted Data Information structure.  This structure
//  is used to return raw encrypted data from a file in
//  order to perform off-line recovery.  The data will be
//  encrypted or encrypted and compressed.  The off-line
//  service will need to use the encryption and compression
//  format information to recover the file data.  In the
//  event that the data is both encrypted and compressed then
//  the decryption must occur before decompression.  All
//  the data units below must be encrypted and compressed
//  with the same format.
//
//  The data will be returned in units.  The data unit size
//  will be fixed per request.  If the data is compressed
//  then the data unit size will be the compression unit size.
//
//  This structure is at the beginning of the buffer used to
//  return the encrypted data.  The actual raw bytes from
//  the file will follow this buffer.  The offset of the
//  raw bytes from the beginning of this structure is
//  specified in the REQUEST_RAW_ENCRYPTED_DATA structure
//  described above.
//

typedef struct _ENCRYPTED_DATA_INFO {

    //
    //  This is the file offset for the first entry in the
    //  data block array.  The file system will round
    //  the requested start offset down to a boundary
    //  that is consistent with the format of the file.
    //

    ULONGLONG StartingFileOffset;

    //
    //  Data offset in output buffer.  The output buffer
    //  begins with an ENCRYPTED_DATA_INFO structure.
    //  The file system will then store the raw bytes from
    //  disk beginning at the following offset within the
    //  output buffer.
    //

    ULONG OutputBufferOffset;

    //
    //  The number of bytes being returned that are within
    //  the size of the file.  If this value is less than
    //  (NumberOfDataBlocks << DataUnitShift), it means the
    //  end of the file occurs within this transfer.  Any
    //  data beyond file size is invalid and was never
    //  passed to the encryption driver.
    //

    ULONG BytesWithinFileSize;

    //
    //  The number of bytes being returned that are below
    //  valid data length.  If this value is less than
    //  (NumberOfDataBlocks << DataUnitShift), it means the
    //  end of the valid data occurs within this transfer.
    //  After decrypting the data from this transfer, any
    //  byte(s) beyond valid data length must be zeroed.
    //

    ULONG BytesWithinValidDataLength;

    //
    //  Code for the compression format as defined in
    //  ntrtl.h.  Note that COMPRESSION_FORMAT_NONE
    //  and COMPRESSION_FORMAT_DEFAULT are invalid if
    //  any of the described chunks are compressed.
    //

    USHORT CompressionFormat;

    //
    //  The DataUnit is the granularity used to access the
    //  disk.  It will be the same as the compression unit
    //  size for a compressed file.  For an uncompressed
    //  file, it will be some cluster-aligned power of 2 that
    //  the file system deems convenient.  A caller should
    //  not expect that successive calls will have the
    //  same data unit shift value as the previous call.
    //
    //  Since chunks and compression units are expected to be
    //  powers of 2 in size, we express them log2.  So, for
    //  example (1 << ChunkShift) == ChunkSizeInBytes.  The
    //  ClusterShift indicates how much space must be saved
    //  to successfully compress a compression unit - each
    //  successfully compressed data unit must occupy
    //  at least one cluster less in bytes than an uncompressed
    //  data block unit.
    //

    UCHAR DataUnitShift;
    UCHAR ChunkShift;
    UCHAR ClusterShift;

    //
    //  The format for the encryption.
    //

    UCHAR EncryptionFormat;

    //
    //  This is the number of entries in the data block size
    //  array.
    //

    USHORT NumberOfDataBlocks;

    //
    //  This is an array of sizes in the data block array.  There
    //  must be one entry in this array for each data block
    //  read from disk.  The size has a different meaning
    //  depending on whether the file is compressed.
    //
    //  A size of zero always indicates that the final data consists entirely
    //  of zeroes.  There is no decryption or decompression to
    //  perform.
    //
    //  If the file is compressed then the data block size indicates
    //  whether this block is compressed.  A size equal to
    //  the block size indicates that the corresponding block did
    //  not compress.  Any other non-zero size indicates the
    //  size of the compressed data which needs to be
    //  decrypted/decompressed.
    //
    //  If the file is not compressed then the data block size
    //  indicates the amount of data within the block that
    //  needs to be decrypted.  Any other non-zero size indicates
    //  that the remaining bytes in the data unit within the file
    //  consists of zeros.  An example of this is when the
    //  the read spans the valid data length of the file.  There
    //  is no data to decrypt past the valid data length.
    //

    ULONG DataBlockSize[ANYSIZE_ARRAY];

} ENCRYPTED_DATA_INFO;
typedef ENCRYPTED_DATA_INFO *PENCRYPTED_DATA_INFO;
#endif /* _WIN32_WINNT >= 0x0500 */


#if (_WIN32_WINNT >= 0x0500)
//
//  FSCTL_READ_FROM_PLEX support
//  Request Plex Read Data structure.  This is used to indicate
//  the range of the file to read.  It also describes
//  which plex to perform the read from.
//

typedef struct _PLEX_READ_DATA_REQUEST {

    //
    //  Requested offset and length to read.
    //  The offset can be the virtual offset (vbo) in to a file,
    //  or a volume. In the case of a file offset,
    //  the fsd will round the starting offset down
    //  to a file system boundary.  It will also
    //  round the length up to a file system boundary and
    //  enforce any other applicable limits.
    //

    LARGE_INTEGER ByteOffset;
    ULONG ByteLength;
    ULONG PlexNumber;

} PLEX_READ_DATA_REQUEST, *PPLEX_READ_DATA_REQUEST;
#endif /* _WIN32_WINNT >= 0x0500 */

#if (_WIN32_WINNT >= 0x0500)
//
// FSCTL_SIS_COPYFILE support
// Source and destination file names are passed in the FileNameBuffer.
// Both strings are null terminated, with the source name starting at
// the beginning of FileNameBuffer, and the destination name immediately
// following.  Length fields include terminating nulls.
//

typedef struct _SI_COPYFILE {
    ULONG SourceFileNameLength;
    ULONG DestinationFileNameLength;
    ULONG Flags;
    WCHAR FileNameBuffer[1];
} SI_COPYFILE, *PSI_COPYFILE;

#define COPYFILE_SIS_LINK       0x0001              // Copy only if source is SIS
#define COPYFILE_SIS_REPLACE    0x0002              // Replace destination if it exists, otherwise don't.
#define COPYFILE_SIS_FLAGS      0x0003
#endif /* _WIN32_WINNT >= 0x0500 */

#if (_WIN32_WINNT >= 0x0600)
//
//  Input parameter structure for FSCTL_MAKE_COMPATIBLE
//

typedef struct _FILE_MAKE_COMPATIBLE_BUFFER {
    BOOLEAN CloseDisc;
} FILE_MAKE_COMPATIBLE_BUFFER, *PFILE_MAKE_COMPATIBLE_BUFFER;

//
//  Input parameter structure for FSCTL_SET_DEFECT_MANAGEMENT
//

typedef struct _FILE_SET_DEFECT_MGMT_BUFFER {
    BOOLEAN Disable;
} FILE_SET_DEFECT_MGMT_BUFFER, *PFILE_SET_DEFECT_MGMT_BUFFER;

//
//  Output structure for FSCTL_QUERY_SPARING_INFO
//

typedef struct _FILE_QUERY_SPARING_BUFFER {
    ULONG SparingUnitBytes;
    BOOLEAN SoftwareSparing;
    ULONG TotalSpareBlocks;
    ULONG FreeSpareBlocks;
} FILE_QUERY_SPARING_BUFFER, *PFILE_QUERY_SPARING_BUFFER;

//
//  Output structure for FSCTL_QUERY_ON_DISK_VOLUME_INFO
//

typedef struct _FILE_QUERY_ON_DISK_VOL_INFO_BUFFER {
    LARGE_INTEGER DirectoryCount;       // -1 = unknown
    LARGE_INTEGER FileCount;            // -1 = unknown
    USHORT FsFormatMajVersion;          // -1 = unknown or n/a
    USHORT FsFormatMinVersion;          // -1 = unknown or n/a
    WCHAR FsFormatName[ 12];
    LARGE_INTEGER FormatTime;
    LARGE_INTEGER LastUpdateTime;
    WCHAR CopyrightInfo[ 34];
    WCHAR AbstractInfo[ 34];
    WCHAR FormattingImplementationInfo[ 34];
    WCHAR LastModifyingImplementationInfo[ 34];
} FILE_QUERY_ON_DISK_VOL_INFO_BUFFER, *PFILE_QUERY_ON_DISK_VOL_INFO_BUFFER;

//
//  Input flags for FSCTL_SET_REPAIR
//

#define SET_REPAIR_ENABLED                                      (0x00000001)
#define SET_REPAIR_VOLUME_BITMAP_SCAN                           (0x00000002)
#define SET_REPAIR_DELETE_CROSSLINK                             (0x00000004)
#define SET_REPAIR_WARN_ABOUT_DATA_LOSS                         (0x00000008)
#define SET_REPAIR_DISABLED_AND_BUGCHECK_ON_CORRUPT             (0x00000010)
#define SET_REPAIR_VALID_MASK                                   (0x0000001F)

//
//  Input structures for FSCTL_SHRINK_VOLUME.
//

typedef enum _SHRINK_VOLUME_REQUEST_TYPES
{
    ShrinkPrepare = 1,
    ShrinkCommit,
    ShrinkAbort

} SHRINK_VOLUME_REQUEST_TYPES, *PSHRINK_VOLUME_REQUEST_TYPES;

typedef struct _SHRINK_VOLUME_INFORMATION
{
    SHRINK_VOLUME_REQUEST_TYPES ShrinkRequestType;
    ULONGLONG Flags;
    LONGLONG NewNumberOfSectors;

} SHRINK_VOLUME_INFORMATION, *PSHRINK_VOLUME_INFORMATION;

//
//  Structures for FSCTL_TXFS_MODIFY_RM and FSCTL_TXFS_QUERY_RM_INFORMATION
//
//  For ModifyRM, TXFS_RM_FLAG_LOG_GROWTH_INCREMENT_NUM_CONTAINERS and
//  TXFS_RM_FLAG_LOG_GROWTH_INCREMENT_PERCENT are mutually exclusive.
//  You can specify the log growth amount in number of containers or as a percentage.
//
//  For ModifyRM, TXFS_RM_FLAG_LOG_CONTAINER_COUNT_MAX and
//  TXFS_RM_FLAG_LOG_NO_CONTAINER_COUNT_MAX are mutually exclusive.
//
//  For ModifyRM, TXFS_RM_FLAG_LOG_CONTAINER_COUNT_MIN and
//  TXFS_RM_FLAG_LOG_NO_CONTAINER_COUNT_MIN are mutually exclusive.
//
//  For ModifyRM, TXFS_RM_FLAG_RESET_RM_AT_NEXT_START and
//  TXFS_RM_FLAG_DO_NOT_RESET_RM_AT_NEXT_START are mutually exclusive and only
//  apply to default RMs.
//
//  For ModifyRM, TXFS_RM_FLAG_PREFER_CONSISTENCY and
//  TXFS_RM_FLAG_PREFER_AVAILABILITY are mutually exclusive.  After calling ModifyRM
//  with one of these flags set the RM must be restarted for the change to take effect.
//

#define TXFS_RM_FLAG_LOGGING_MODE                           0x00000001
#define TXFS_RM_FLAG_RENAME_RM                              0x00000002
#define TXFS_RM_FLAG_LOG_CONTAINER_COUNT_MAX                0x00000004
#define TXFS_RM_FLAG_LOG_CONTAINER_COUNT_MIN                0x00000008
#define TXFS_RM_FLAG_LOG_GROWTH_INCREMENT_NUM_CONTAINERS    0x00000010
#define TXFS_RM_FLAG_LOG_GROWTH_INCREMENT_PERCENT           0x00000020
#define TXFS_RM_FLAG_LOG_AUTO_SHRINK_PERCENTAGE             0x00000040
#define TXFS_RM_FLAG_LOG_NO_CONTAINER_COUNT_MAX             0x00000080
#define TXFS_RM_FLAG_LOG_NO_CONTAINER_COUNT_MIN             0x00000100
#define TXFS_RM_FLAG_GROW_LOG                               0x00000400
#define TXFS_RM_FLAG_SHRINK_LOG                             0x00000800
#define TXFS_RM_FLAG_ENFORCE_MINIMUM_SIZE                   0x00001000
#define TXFS_RM_FLAG_PRESERVE_CHANGES                       0x00002000
#define TXFS_RM_FLAG_RESET_RM_AT_NEXT_START                 0x00004000
#define TXFS_RM_FLAG_DO_NOT_RESET_RM_AT_NEXT_START          0x00008000
#define TXFS_RM_FLAG_PREFER_CONSISTENCY                     0x00010000
#define TXFS_RM_FLAG_PREFER_AVAILABILITY                    0x00020000

#define TXFS_LOGGING_MODE_SIMPLE        (0x0001)
#define TXFS_LOGGING_MODE_FULL          (0x0002)

#define TXFS_TRANSACTION_STATE_NONE         0x00
#define TXFS_TRANSACTION_STATE_ACTIVE       0x01
#define TXFS_TRANSACTION_STATE_PREPARED     0x02
#define TXFS_TRANSACTION_STATE_NOTACTIVE    0x03

#define TXFS_MODIFY_RM_VALID_FLAGS                                      \
                (TXFS_RM_FLAG_LOGGING_MODE                          |   \
                 TXFS_RM_FLAG_RENAME_RM                             |   \
                 TXFS_RM_FLAG_LOG_CONTAINER_COUNT_MAX               |   \
                 TXFS_RM_FLAG_LOG_CONTAINER_COUNT_MIN               |   \
                 TXFS_RM_FLAG_LOG_GROWTH_INCREMENT_NUM_CONTAINERS   |   \
                 TXFS_RM_FLAG_LOG_GROWTH_INCREMENT_PERCENT          |   \
                 TXFS_RM_FLAG_LOG_AUTO_SHRINK_PERCENTAGE            |   \
                 TXFS_RM_FLAG_LOG_NO_CONTAINER_COUNT_MAX            |   \
                 TXFS_RM_FLAG_LOG_NO_CONTAINER_COUNT_MIN            |   \
                 TXFS_RM_FLAG_SHRINK_LOG                            |   \
                 TXFS_RM_FLAG_GROW_LOG                              |   \
                 TXFS_RM_FLAG_ENFORCE_MINIMUM_SIZE                  |   \
                 TXFS_RM_FLAG_PRESERVE_CHANGES                      |   \
                 TXFS_RM_FLAG_RESET_RM_AT_NEXT_START                |   \
                 TXFS_RM_FLAG_DO_NOT_RESET_RM_AT_NEXT_START         |   \
                 TXFS_RM_FLAG_PREFER_CONSISTENCY                    |   \
                 TXFS_RM_FLAG_PREFER_AVAILABILITY)

typedef struct _TXFS_MODIFY_RM {

    //
    //  TXFS_RM_FLAG_* flags
    //

    ULONG Flags;

    //
    //  Maximum log container count if TXFS_RM_FLAG_LOG_CONTAINER_COUNT_MAX is set.
    //

    ULONG LogContainerCountMax;

    //
    //  Minimum log container count if TXFS_RM_FLAG_LOG_CONTAINER_COUNT_MIN is set.
    //

    ULONG LogContainerCountMin;

    //
    //  Target log container count for TXFS_RM_FLAG_SHRINK_LOG or _GROW_LOG.
    //

    ULONG LogContainerCount;

    //
    //  When the log is full, increase its size by this much.  Indicated as either a percent of
    //  the log size or absolute container count, depending on which of the TXFS_RM_FLAG_LOG_GROWTH_INCREMENT_*
    //  flags is set.
    //

    ULONG LogGrowthIncrement;

    //
    //  Sets autoshrink policy if TXFS_RM_FLAG_LOG_AUTO_SHRINK_PERCENTAGE is set.  Autoshrink
    //  makes the log shrink so that no more than this percentage of the log is free at any time.
    //

    ULONG LogAutoShrinkPercentage;

    //
    //  Reserved.
    //

    ULONGLONG Reserved;

    //
    //  If TXFS_RM_FLAG_LOGGING_MODE is set, this must contain one of TXFS_LOGGING_MODE_SIMPLE
    //  or TXFS_LOGGING_MODE_FULL.
    //

    USHORT LoggingMode;

} TXFS_MODIFY_RM,
 *PTXFS_MODIFY_RM;

#define TXFS_RM_STATE_NOT_STARTED       0
#define TXFS_RM_STATE_STARTING          1
#define TXFS_RM_STATE_ACTIVE            2
#define TXFS_RM_STATE_SHUTTING_DOWN     3

//
//  The flags field for query RM information is used for the following information:
//
//  1)  To indicate whether the LogGrowthIncrement field is reported as a percent
//      or as a number of containers.  Possible flag values for this are:
//
//      TXFS_RM_FLAG_LOG_GROWTH_INCREMENT_NUM_CONTAINERS xor TXFS_RM_FLAG_LOG_GROWTH_INCREMENT_PERCENT
//
//  2)  To indicate that there is no set maximum or minimum container count.  Possible
//      flag values for this are:
//
//      TXFS_RM_FLAG_LOG_NO_CONTAINER_COUNT_MAX
//      TXFS_RM_FLAG_LOG_NO_CONTAINER_COUNT_MIN
//
//      Note that these flags are not mutually exclusive.
//
//  2)  To report whether the RM will be reset the next time it is started.  Note that
//      only the default RM will report a meaningful value (secondary RMs will always
//      report DO_NOT_RESET) Possible flag values for this are:
//
//      TXFS_RM_FLAG_RESET_RM_AT_NEXT_START xor TXFS_RM_FLAG_DO_NOT_RESET_RM_AT_NEXT_START
//
//  3)  To report whether the RM is in consistency mode or availability mode.  Possible
//      flag values for this are:
//
//      TXFS_RM_FLAG_PREFER_CONSISTENCY xor TXFS_RM_FLAG_PREFER_AVAILABILITY
//
//  The RmState field can have exactly one of the above-defined TXF_RM_STATE_ values.
//

#define TXFS_QUERY_RM_INFORMATION_VALID_FLAGS                           \
                (TXFS_RM_FLAG_LOG_GROWTH_INCREMENT_NUM_CONTAINERS   |   \
                 TXFS_RM_FLAG_LOG_GROWTH_INCREMENT_PERCENT          |   \
                 TXFS_RM_FLAG_LOG_NO_CONTAINER_COUNT_MAX            |   \
                 TXFS_RM_FLAG_LOG_NO_CONTAINER_COUNT_MIN            |   \
                 TXFS_RM_FLAG_RESET_RM_AT_NEXT_START                |   \
                 TXFS_RM_FLAG_DO_NOT_RESET_RM_AT_NEXT_START         |   \
                 TXFS_RM_FLAG_PREFER_CONSISTENCY                    |   \
                 TXFS_RM_FLAG_PREFER_AVAILABILITY)

typedef struct _TXFS_QUERY_RM_INFORMATION {

    //
    //  If the return value is STATUS_BUFFER_OVERFLOW (ERROR_MORE_DATA), this
    //  will indicate how much space is required to hold everything.
    //

    ULONG BytesRequired;

    //
    //  LSN of earliest available record in the RM's log.
    //

    ULONGLONG TailLsn;

    //
    //  LSN of most recently-written record in the RM's log.
    //

    ULONGLONG CurrentLsn;

    //
    //  LSN of the log's archive tail.
    //

    ULONGLONG ArchiveTailLsn;

    //
    //  Size of a log container in bytes.
    //

    ULONGLONG LogContainerSize;

    //
    //  Highest virtual clock value recorded in this RM's log.
    //

    LARGE_INTEGER HighestVirtualClock;

    //
    //  Number of containers in this RM's log.
    //

    ULONG LogContainerCount;

    //
    //  Maximum-allowed log container count.
    //

    ULONG LogContainerCountMax;

    //
    //  Minimum-allowed log container count.
    //

    ULONG LogContainerCountMin;

    //
    //  Amount by which log will grow when it gets full.  Indicated as either a percent of
    //  the log size or absolute container count, depending on which of the TXFS_RM_FLAG_LOG_GROWTH_INCREMENT_*
    //  flags is set.
    //

    ULONG LogGrowthIncrement;

    //
    //  Reports on the autoshrink policy if.  Autoshrink makes the log shrink so that no more than this
    //  percentage of the log is free at any time.  A value of 0 indicates that autoshrink is off (i.e.
    //  the log will not automatically shrink).
    //

    ULONG LogAutoShrinkPercentage;

    //
    //  TXFS_RM_FLAG_* flags.  See the comment above at TXFS_QUERY_RM_INFORMATION_VALID_FLAGS to see
    //  what the flags here mean.
    //

    ULONG Flags;

    //
    //  Exactly one of TXFS_LOGGING_MODE_SIMPLE or TXFS_LOGGING_MODE_FULL.
    //

    USHORT LoggingMode;

    //
    //  Reserved.
    //

    USHORT Reserved;

    //
    //  Activity state of the RM.  May be exactly one of the above-defined TXF_RM_STATE_ values.
    //

    ULONG RmState;

    //
    //  Total capacity of the log in bytes.
    //

    ULONGLONG LogCapacity;

    //
    //  Amount of free space in the log in bytes.
    //

    ULONGLONG LogFree;

    //
    //  Size of $Tops in bytes.
    //

    ULONGLONG TopsSize;

    //
    //  Amount of space in $Tops in use.
    //

    ULONGLONG TopsUsed;

    //
    //  Number of transactions active in the RM at the time of the call.
    //

    ULONGLONG TransactionCount;

    //
    //  Total number of single-phase commits that have happened the RM.
    //

    ULONGLONG OnePCCount;

    //
    //  Total number of two-phase commits that have happened the RM.
    //

    ULONGLONG TwoPCCount;

    //
    //  Number of times the log has filled up.
    //

    ULONGLONG NumberLogFileFull;

    //
    //  Age of oldest active transaction in the RM, in milliseconds.
    //

    ULONGLONG OldestTransactionAge;

    //
    //  Name of the RM.
    //

    GUID RMName;

    //
    //  Offset in bytes from the beginning of this structure to a NULL-terminated Unicode
    //  string indicating the path to the RM's transaction manager's log.
    //

    ULONG TmLogPathOffset;

} TXFS_QUERY_RM_INFORMATION,
 *PTXFS_QUERY_RM_INFORMATION;

//
// Structures for FSCTL_TXFS_ROLLFORWARD_REDO
//

#define TXFS_ROLLFORWARD_REDO_FLAG_USE_LAST_REDO_LSN        0x01
#define TXFS_ROLLFORWARD_REDO_FLAG_USE_LAST_VIRTUAL_CLOCK   0x02

#define TXFS_ROLLFORWARD_REDO_VALID_FLAGS                               \
                (TXFS_ROLLFORWARD_REDO_FLAG_USE_LAST_REDO_LSN |         \
                 TXFS_ROLLFORWARD_REDO_FLAG_USE_LAST_VIRTUAL_CLOCK)

typedef struct _TXFS_ROLLFORWARD_REDO_INFORMATION {
    LARGE_INTEGER  LastVirtualClock;
    ULONGLONG LastRedoLsn;
    ULONGLONG HighestRecoveryLsn;
    ULONG Flags;
} TXFS_ROLLFORWARD_REDO_INFORMATION,
 *PTXFS_ROLLFORWARD_REDO_INFORMATION;

//
//  Structures for FSCTL_TXFS_START_RM
//
//  Note that TXFS_START_RM_FLAG_LOG_GROWTH_INCREMENT_NUM_CONTAINERS and
//  TXFS_START_RM_FLAG_LOG_GROWTH_INCREMENT_PERCENT are mutually exclusive.
//  You can specify the log growth amount in number of containers or as a percentage.
//
//  TXFS_START_RM_FLAG_CONTAINER_COUNT_MAX and TXFS_START_RM_FLAG_LOG_NO_CONTAINER_COUNT_MAX
//  are mutually exclusive.
//
//  TXFS_START_RM_FLAG_LOG_CONTAINER_COUNT_MIN and TXFS_START_RM_FLAG_LOG_NO_CONTAINER_COUNT_MIN
//  are mutually exclusive.
//
//  TXFS_START_RM_FLAG_PREFER_CONSISTENCY and TXFS_START_RM_FLAG_PREFER_AVAILABILITY
//  are mutually exclusive.
//
//  Optional parameters will have system-supplied defaults applied if omitted.
//

#define TXFS_START_RM_FLAG_LOG_CONTAINER_COUNT_MAX              0x00000001
#define TXFS_START_RM_FLAG_LOG_CONTAINER_COUNT_MIN              0x00000002
#define TXFS_START_RM_FLAG_LOG_CONTAINER_SIZE                   0x00000004
#define TXFS_START_RM_FLAG_LOG_GROWTH_INCREMENT_NUM_CONTAINERS  0x00000008
#define TXFS_START_RM_FLAG_LOG_GROWTH_INCREMENT_PERCENT         0x00000010
#define TXFS_START_RM_FLAG_LOG_AUTO_SHRINK_PERCENTAGE           0x00000020
#define TXFS_START_RM_FLAG_LOG_NO_CONTAINER_COUNT_MAX           0x00000040
#define TXFS_START_RM_FLAG_LOG_NO_CONTAINER_COUNT_MIN           0x00000080

#define TXFS_START_RM_FLAG_RECOVER_BEST_EFFORT                  0x00000200
#define TXFS_START_RM_FLAG_LOGGING_MODE                         0x00000400
#define TXFS_START_RM_FLAG_PRESERVE_CHANGES                     0x00000800

#define TXFS_START_RM_FLAG_PREFER_CONSISTENCY                   0x00001000
#define TXFS_START_RM_FLAG_PREFER_AVAILABILITY                  0x00002000

#define TXFS_START_RM_VALID_FLAGS                                           \
                (TXFS_START_RM_FLAG_LOG_CONTAINER_COUNT_MAX             |   \
                 TXFS_START_RM_FLAG_LOG_CONTAINER_COUNT_MIN             |   \
                 TXFS_START_RM_FLAG_LOG_CONTAINER_SIZE                  |   \
                 TXFS_START_RM_FLAG_LOG_GROWTH_INCREMENT_NUM_CONTAINERS |   \
                 TXFS_START_RM_FLAG_LOG_GROWTH_INCREMENT_PERCENT        |   \
                 TXFS_START_RM_FLAG_LOG_AUTO_SHRINK_PERCENTAGE          |   \
                 TXFS_START_RM_FLAG_RECOVER_BEST_EFFORT                 |   \
                 TXFS_START_RM_FLAG_LOG_NO_CONTAINER_COUNT_MAX          |   \
                 TXFS_START_RM_FLAG_LOGGING_MODE                        |   \
                 TXFS_START_RM_FLAG_PRESERVE_CHANGES                    |   \
                 TXFS_START_RM_FLAG_PREFER_CONSISTENCY                  |   \
                 TXFS_START_RM_FLAG_PREFER_AVAILABILITY)

typedef struct _TXFS_START_RM_INFORMATION {

    //
    //  TXFS_START_RM_FLAG_* flags.
    //

    ULONG Flags;

    //
    //  RM log container size, in bytes.  This parameter is optional.
    //

    ULONGLONG LogContainerSize;

    //
    //  RM minimum log container count.  This parameter is optional.
    //

    ULONG LogContainerCountMin;

    //
    //  RM maximum log container count.  This parameter is optional.
    //

    ULONG LogContainerCountMax;

    //
    //  RM log growth increment in number of containers or percent, as indicated
    //  by TXFS_START_RM_FLAG_LOG_GROWTH_INCREMENT_* flag.  This parameter is
    //  optional.
    //

    ULONG LogGrowthIncrement;

    //
    //  RM log auto shrink percentage.  This parameter is optional.
    //

    ULONG LogAutoShrinkPercentage;

    //
    //  Offset from the beginning of this structure to the log path for the KTM
    //  instance to be used by this RM.  This must be a two-byte (WCHAR) aligned
    //  value.  This parameter is required.
    //

    ULONG TmLogPathOffset;

    //
    //  Length in bytes of log path for the KTM instance to be used by this RM.
    //  This parameter is required.
    //

    USHORT TmLogPathLength;

    //
    //  Logging mode for this RM.  One of TXFS_LOGGING_MODE_SIMPLE or
    //  TXFS_LOGGING_MODE_FULL (mutually exclusive).  This parameter is optional,
    //  and will default to TXFS_LOGGING_MODE_SIMPLE.
    //

    USHORT LoggingMode;

    //
    //  Length in bytes of the path to the log to be used by the RM.  This parameter
    //  is required.
    //

    USHORT LogPathLength;

    //
    //  Reserved.
    //

    USHORT Reserved;

    //
    //  The path to the log (in Unicode characters) to be used by the RM goes here.
    //  This parameter is required.
    //

    WCHAR LogPath[1];

} TXFS_START_RM_INFORMATION,
 *PTXFS_START_RM_INFORMATION;

//
//  Structures for FSCTL_TXFS_GET_METADATA_INFO
//

typedef struct _TXFS_GET_METADATA_INFO_OUT {

    //
    //  Returns the TxfId of the file referenced by the handle used to call this routine.
    //

    struct {
        LONGLONG LowPart;
        LONGLONG HighPart;
    } TxfFileId;

    //
    //  The GUID of the transaction that has the file locked, if applicable.
    //

    GUID LockingTransaction;

    //
    //  Returns the LSN for the most recent log record we've written for the file.
    //

    ULONGLONG LastLsn;

    //
    //  Transaction state, a TXFS_TRANSACTION_STATE_* value.
    //

    ULONG TransactionState;

} TXFS_GET_METADATA_INFO_OUT, *PTXFS_GET_METADATA_INFO_OUT;

//
//  Structures for FSCTL_TXFS_LIST_TRANSACTION_LOCKED_FILES
//
//  TXFS_LIST_TRANSACTION_LOCKED_FILES_ENTRY_FLAG_CREATED means the reported name was created
//  in the locking transaction.
//
//  TXFS_LIST_TRANSACTION_LOCKED_FILES_ENTRY_FLAG_DELETED means the reported name was deleted
//  in the locking transaction.
//
//  Note that both flags may appear if the name was both created and deleted in the same
//  transaction.  In that case the FileName[] member will contain only "\0", as there is
//  no meaningful name to report.
//

#define TXFS_LIST_TRANSACTION_LOCKED_FILES_ENTRY_FLAG_CREATED   0x00000001
#define TXFS_LIST_TRANSACTION_LOCKED_FILES_ENTRY_FLAG_DELETED   0x00000002

typedef struct _TXFS_LIST_TRANSACTION_LOCKED_FILES_ENTRY {

    //
    //  Offset in bytes from the beginning of the TXFS_LIST_TRANSACTION_LOCKED_FILES
    //  structure to the next TXFS_LIST_TRANSACTION_LOCKED_FILES_ENTRY.
    //

    ULONGLONG Offset;

    //
    //  TXFS_LIST_TRANSACTION_LOCKED_FILES_ENTRY_FLAG_* flags to indicate whether the
    //  current name was deleted or created in the transaction.
    //

    ULONG NameFlags;

    //
    //  NTFS File ID of the file.
    //

    LONGLONG FileId;

    //
    //  Reserved.
    //

    ULONG Reserved1;
    ULONG Reserved2;
    LONGLONG Reserved3;

    //
    //  NULL-terminated Unicode path to this file, relative to RM root.
    //

    WCHAR FileName[1];
} TXFS_LIST_TRANSACTION_LOCKED_FILES_ENTRY, *PTXFS_LIST_TRANSACTION_LOCKED_FILES_ENTRY;


typedef struct _TXFS_LIST_TRANSACTION_LOCKED_FILES {

    //
    //  GUID name of the KTM transaction that files should be enumerated from.
    //

    GUID KtmTransaction;

    //
    //  On output, the number of files involved in the transaction on this RM.
    //

    ULONGLONG NumberOfFiles;

    //
    //  The length of the buffer required to obtain the complete list of files.
    //  This value may change from call to call as the transaction locks more files.
    //

    ULONGLONG BufferSizeRequired;

    //
    //  Offset in bytes from the beginning of this structure to the first
    //  TXFS_LIST_TRANSACTION_LOCKED_FILES_ENTRY.
    //

    ULONGLONG Offset;
} TXFS_LIST_TRANSACTION_LOCKED_FILES, *PTXFS_LIST_TRANSACTION_LOCKED_FILES;

//
//  Structures for FSCTL_TXFS_LIST_TRANSACTIONS
//

typedef struct _TXFS_LIST_TRANSACTIONS_ENTRY {

    //
    //  Transaction GUID.
    //

    GUID TransactionId;

    //
    //  Transaction state, a TXFS_TRANSACTION_STATE_* value.
    //

    ULONG TransactionState;

    //
    //  Reserved fields
    //

    ULONG Reserved1;
    ULONG Reserved2;
    LONGLONG Reserved3;
} TXFS_LIST_TRANSACTIONS_ENTRY, *PTXFS_LIST_TRANSACTIONS_ENTRY;

typedef struct _TXFS_LIST_TRANSACTIONS {

    //
    //  On output, the number of transactions involved in this RM.
    //

    ULONGLONG NumberOfTransactions;

    //
    //  The length of the buffer required to obtain the complete list of
    //  transactions.  Note that this value may change from call to call
    //  as transactions enter and exit the system.
    //

    ULONGLONG BufferSizeRequired;
} TXFS_LIST_TRANSACTIONS, *PTXFS_LIST_TRANSACTIONS;


//
//  Structures for FSCTL_TXFS_READ_BACKUP_INFORMATION
//

#if _MSC_VER >= 1200
#pragma warning(push)
#endif
#pragma warning(disable:4201)       // unnamed struct

typedef struct _TXFS_READ_BACKUP_INFORMATION_OUT {
    union {

        //
        //  Used to return the required buffer size if return code is STATUS_BUFFER_OVERFLOW
        //

        ULONG BufferLength;

        //
        //  On success the data is copied here.
        //

        UCHAR Buffer[1];
    } DUMMYUNIONNAME;
} TXFS_READ_BACKUP_INFORMATION_OUT, *PTXFS_READ_BACKUP_INFORMATION_OUT;

#if _MSC_VER >= 1200
#pragma warning(pop)
#else
#pragma warning( default : 4201 )
#endif

//
//  Structures for FSCTL_TXFS_WRITE_BACKUP_INFORMATION
//

typedef struct _TXFS_WRITE_BACKUP_INFORMATION {

    //
    //  The data returned in the Buffer member of a previous call to
    //  FSCTL_TXFS_READ_BACKUP_INFORMATION goes here.
    //

    UCHAR Buffer[1];
} TXFS_WRITE_BACKUP_INFORMATION, *PTXFS_WRITE_BACKUP_INFORMATION;

//
//  Output structure for FSCTL_TXFS_GET_TRANSACTED_VERSION
//

#define TXFS_TRANSACTED_VERSION_NONTRANSACTED   0xFFFFFFFE
#define TXFS_TRANSACTED_VERSION_UNCOMMITTED     0xFFFFFFFF

typedef struct _TXFS_GET_TRANSACTED_VERSION {

    //
    //  The version that this handle is opened to.  This will be
    //  TXFS_TRANSACTED_VERSION_UNCOMMITTED for nontransacted and
    //  transactional writer handles.
    //

    ULONG ThisBaseVersion;

    //
    //  The most recent committed version available.
    //

    ULONG LatestVersion;

    //
    //  If this is a handle to a miniversion, the ID of the miniversion.
    //  If it is not a handle to a minivers, this field will be 0.
    //

    USHORT ThisMiniVersion;

    //
    //  The first available miniversion.  Unless the miniversions are
    //  visible to the transaction bound to this handle, this field will be zero.
    //

    USHORT FirstMiniVersion;

    //
    //  The latest available miniversion.  Unless the miniversions are
    //  visible to the transaction bound to this handle, this field will be zero.
    //

    USHORT LatestMiniVersion;

} TXFS_GET_TRANSACTED_VERSION, *PTXFS_GET_TRANSACTED_VERSION;

//
//  Structures for FSCTL_TXFS_SAVEPOINT_INFORMATION
//
//  Note that the TXFS_SAVEPOINT_INFORMATION structure is both and in and out structure.
//  The KtmTransaction and ActionCode members are always in-parameters, and the SavepointId
//  member is either an in-parameter, an out-parameter, or not used (see its definition below).
//

//
//  Create a new savepoint.
//

#define TXFS_SAVEPOINT_SET                      0x00000001

//
//  Roll back to a specified savepoint.
//

#define TXFS_SAVEPOINT_ROLLBACK                 0x00000002

//
//  Clear (make unavailable for rollback) the most recently set savepoint
//  that has not yet been cleared.
//

#define TXFS_SAVEPOINT_CLEAR                    0x00000004

//
//  Clear all savepoints from the transaction.
//

#define TXFS_SAVEPOINT_CLEAR_ALL                0x00000010

typedef struct _TXFS_SAVEPOINT_INFORMATION {

    //
    //  Handle to the transaction on which to perform the savepoint operation.
    //

    HANDLE KtmTransaction;

    //
    //  Specifies the savepoint action to take.  A TXFS_SAVEPOINT_* value.
    //

    ULONG ActionCode;

    //
    //  In-parameter for TXFS_ROLLBACK_TO_SAVEPOINT - specifies the savepoint to which
    //  to roll back.
    //
    //  Out-parameter for TXFS_SET_SAVEPOINT - the newly-created savepoint ID will be
    //  returned here.
    //
    //  Not used for TXFS_CLEAR_SAVEPOINT or TXFS_CLEAR_ALL_SAVEPOINTS.
    //

    ULONG SavepointId;

} TXFS_SAVEPOINT_INFORMATION, *PTXFS_SAVEPOINT_INFORMATION;

//
//  Structures for FSCTL_TXFS_CREATE_MINIVERSION
//
//      Only an out parameter is necessary.  That returns the identifier of the new miniversion created.
//

typedef struct _TXFS_CREATE_MINIVERSION_INFO {

    USHORT StructureVersion;

    USHORT StructureLength;

    //
    //  The base version for the newly created miniversion.
    //

    ULONG BaseVersion;

    //
    //  The miniversion that was just created.
    //

    USHORT MiniVersion;

} TXFS_CREATE_MINIVERSION_INFO, *PTXFS_CREATE_MINIVERSION_INFO;

//
//  Structure for FSCTL_TXFS_TRANSACTION_ACTIVE
//

typedef struct _TXFS_TRANSACTION_ACTIVE_INFO {

    //
    //  Whether or not the volume had active transactions when this snapshot was taken.
    //

    BOOLEAN TransactionsActiveAtSnapshot;

} TXFS_TRANSACTION_ACTIVE_INFO, *PTXFS_TRANSACTION_ACTIVE_INFO;

#endif /* _WIN32_WINNT >= 0x0600 */

#if (_WIN32_WINNT >= 0x0601)
//
// Output structure for FSCTL_GET_BOOT_AREA_INFO
//

typedef struct _BOOT_AREA_INFO {

    ULONG               BootSectorCount;  // the count of boot sectors present on the file system
    struct {
        LARGE_INTEGER   Offset;
    } BootSectors[2];                     // variable number of boot sectors.

} BOOT_AREA_INFO, *PBOOT_AREA_INFO;

//
// Output structure for FSCTL_GET_RETRIEVAL_POINTER_BASE
//

typedef struct _RETRIEVAL_POINTER_BASE {

    LARGE_INTEGER       FileAreaOffset; // sector offset to the first allocatable unit on the filesystem
} RETRIEVAL_POINTER_BASE, *PRETRIEVAL_POINTER_BASE;

//
// Structure for FSCTL_SET_PERSISTENT_VOLUME_STATE and FSCTL_GET_PERSISTENT_VOLUME_STATE
// The initial version will be 1.0
//

typedef struct _FILE_FS_PERSISTENT_VOLUME_INFORMATION {

    ULONG VolumeFlags;
    ULONG FlagMask;
    ULONG Version;
    ULONG Reserved;

} FILE_FS_PERSISTENT_VOLUME_INFORMATION, *PFILE_FS_PERSISTENT_VOLUME_INFORMATION;

//
//  Structure for FSCTL_QUERY_FILE_SYSTEM_RECOGNITION
//

typedef struct _FILE_SYSTEM_RECOGNITION_INFORMATION {

    CHAR FileSystem[9];

} FILE_SYSTEM_RECOGNITION_INFORMATION, *PFILE_SYSTEM_RECOGNITION_INFORMATION;

//
//  Structures for FSCTL_REQUEST_OPLOCK
//

#define OPLOCK_LEVEL_CACHE_READ         (0x00000001)
#define OPLOCK_LEVEL_CACHE_HANDLE       (0x00000002)
#define OPLOCK_LEVEL_CACHE_WRITE        (0x00000004)

#define REQUEST_OPLOCK_INPUT_FLAG_REQUEST               (0x00000001)
#define REQUEST_OPLOCK_INPUT_FLAG_ACK                   (0x00000002)
#define REQUEST_OPLOCK_INPUT_FLAG_COMPLETE_ACK_ON_CLOSE (0x00000004)

#define REQUEST_OPLOCK_CURRENT_VERSION          1

typedef struct _REQUEST_OPLOCK_INPUT_BUFFER {

    //
    //  This should be set to REQUEST_OPLOCK_CURRENT_VERSION.
    //

    USHORT StructureVersion;

    USHORT StructureLength;

    //
    //  One or more OPLOCK_LEVEL_CACHE_* values to indicate the desired level of the oplock.
    //

    ULONG RequestedOplockLevel;

    //
    //  REQUEST_OPLOCK_INPUT_FLAG_* flags.
    //

    ULONG Flags;

} REQUEST_OPLOCK_INPUT_BUFFER, *PREQUEST_OPLOCK_INPUT_BUFFER;

#define REQUEST_OPLOCK_OUTPUT_FLAG_ACK_REQUIRED     (0x00000001)
#define REQUEST_OPLOCK_OUTPUT_FLAG_MODES_PROVIDED   (0x00000002)

typedef struct _REQUEST_OPLOCK_OUTPUT_BUFFER {

    //
    //  This should be set to REQUEST_OPLOCK_CURRENT_VERSION.
    //

    USHORT StructureVersion;

    USHORT StructureLength;

    //
    //  One or more OPLOCK_LEVEL_CACHE_* values indicating the level of the oplock that
    //  was just broken.
    //

    ULONG OriginalOplockLevel;

    //
    //  One or more OPLOCK_LEVEL_CACHE_* values indicating the level to which an oplock
    //  is being broken, or an oplock level that may be available for granting, depending
    //  on the operation returning this buffer.
    //

    ULONG NewOplockLevel;

    //
    //  REQUEST_OPLOCK_OUTPUT_FLAG_* flags.
    //

    ULONG Flags;

    //
    //  When REQUEST_OPLOCK_OUTPUT_FLAG_MODES_PROVIDED is set, and when the
    //  OPLOCK_LEVEL_CACHE_HANDLE level is being lost in an oplock break, these fields
    //  contain the access mode and share mode of the request that is causing the break.
    //

    ACCESS_MASK AccessMode;

    USHORT ShareMode;

} REQUEST_OPLOCK_OUTPUT_BUFFER, *PREQUEST_OPLOCK_OUTPUT_BUFFER;

//
//  Structures for FSCTL_SD_GLOBAL_CHANGE
//

//
//  list of operations supported
//

#define SD_GLOBAL_CHANGE_TYPE_MACHINE_SID   1


//
//  Operation specific structures for SD_GLOBAL_CHANGE_TYPE_MACHINE_SID
//
//  This con
//

typedef struct _SD_CHANGE_MACHINE_SID_INPUT {

    //
    //  The current machine SID to change.
    //  This define the offset from the beginning of the SD_GLOBAL_CHANGE_INPUT
    //  structure of where the CurrentMachineSID to replace begins.  This will
    //  be a SID structure.  The length defines the length of the imbedded SID
    //  structure.
    //

    USHORT CurrentMachineSIDOffset;
    USHORT CurrentMachineSIDLength;

    //
    //  The new machine SID value to set inplace of the current machine SID
    //  This define the offset from the beginning of the SD_GLOBAL_CHANGE_INPUT
    //  structure of where the NewMachineSID to set begins.  This will
    //  be a SID structure.  The length defines the length of the imbedded SID
    //  structure.
    //

    USHORT NewMachineSIDOffset;
    USHORT NewMachineSIDLength;

} SD_CHANGE_MACHINE_SID_INPUT, *PSD_CHANGE_MACHINE_SID_INPUT;

typedef struct _SD_CHANGE_MACHINE_SID_OUTPUT {

    //
    //  How many entries were successfully changed in the $Secure stream
    //

    ULONGLONG NumSDChangedSuccess;

    //
    //  How many entires failed the update in the $Secure stream
    //

    ULONGLONG NumSDChangedFail;

    //
    //  How many entires are unused in the current security stream
    //

    ULONGLONG NumSDUnused;

    //
    //  The total number of entries processed in the $Secure stream
    //

    ULONGLONG NumSDTotal;

    //
    //  How many entries were successfully changed in the $MFT file
    //

    ULONGLONG NumMftSDChangedSuccess;

    //
    //  How many entries failed the update in the $MFT file
    //

    ULONGLONG NumMftSDChangedFail;

    //
    //  Total number of entriess process in the $MFT file
    //

    ULONGLONG NumMftSDTotal;

} SD_CHANGE_MACHINE_SID_OUTPUT, *PSD_CHANGE_MACHINE_SID_OUTPUT;

//
//  Generic INPUT & OUTPUT structures for FSCTL_SD_GLOBAL_CHANGE
//

#if _MSC_VER >= 1200
#pragma warning(push)
#endif
#pragma warning(disable:4201)       // unnamed struct

typedef struct _SD_GLOBAL_CHANGE_INPUT
{
    //
    //  Input flags (none currently defined)
    //

    ULONG Flags;

    //
    //  Specifies which type of change we are doing and pics which member
    //  of the below union is in use.
    //

    ULONG ChangeType;

    union {

        SD_CHANGE_MACHINE_SID_INPUT SdChange;
    };

} SD_GLOBAL_CHANGE_INPUT, *PSD_GLOBAL_CHANGE_INPUT;

typedef struct _SD_GLOBAL_CHANGE_OUTPUT
{

    //
    //  Output State Flags (none currently defined)
    //

    ULONG Flags;

    //
    //  Specifies which below union to use
    //

    ULONG ChangeType;

    union {

        SD_CHANGE_MACHINE_SID_OUTPUT SdChange;
    };

} SD_GLOBAL_CHANGE_OUTPUT, *PSD_GLOBAL_CHANGE_OUTPUT;

#if _MSC_VER >= 1200
#pragma warning(pop)
#else
#pragma warning( default : 4201 ) /* nonstandard extension used : nameless struct/union */
#endif

//
//  Flag to indicate the encrypted file is sparse
//

#define ENCRYPTED_DATA_INFO_SPARSE_FILE    1

typedef struct _EXTENDED_ENCRYPTED_DATA_INFO {

    //
    //  This is really a 4 byte character array which
    //  must have the value "EXTD".  We use this
    //  to determine if we should read the extended data
    //  or not.
    //

    ULONG ExtendedCode;

    //
    //  The length of the extended data structure
    //

    ULONG Length;

    //
    //  Encrypted data flags (currently only sparse is defined)
    //

    ULONG Flags;
    ULONG Reserved;

} EXTENDED_ENCRYPTED_DATA_INFO, *PEXTENDED_ENCRYPTED_DATA_INFO;


typedef struct _LOOKUP_STREAM_FROM_CLUSTER_INPUT {

    //
    //  Flags for the operation.  Currently no flags are defined.
    //
    ULONG         Flags;

    //
    //  Number of clusters in the following array of clusters.
    //  The input buffer must be large enough to contain this
    //  number or the operation will fail.
    //
    ULONG         NumberOfClusters;

    //
    //  An array of one or more clusters to look up.
    //
    LARGE_INTEGER Cluster[1];
} LOOKUP_STREAM_FROM_CLUSTER_INPUT, *PLOOKUP_STREAM_FROM_CLUSTER_INPUT;

typedef struct _LOOKUP_STREAM_FROM_CLUSTER_OUTPUT {
    //
    //  Offset from the beginning of this structure to the first entry
    //  returned.  If no entries are returned, this value is zero.
    //
    ULONG         Offset;

    //
    //  Number of matches to the input criteria.  Note that more matches
    //  may be found than entries returned if the buffer is not large
    //  enough.
    //
    ULONG         NumberOfMatches;

    //
    //  Minimum size of the buffer, in bytes, which would be needed to
    //  contain all matching entries to the input criteria.
    //
    ULONG         BufferSizeRequired;
} LOOKUP_STREAM_FROM_CLUSTER_OUTPUT, *PLOOKUP_STREAM_FROM_CLUSTER_OUTPUT;

#define LOOKUP_STREAM_FROM_CLUSTER_ENTRY_FLAG_PAGE_FILE          0x00000001
#define LOOKUP_STREAM_FROM_CLUSTER_ENTRY_FLAG_DENY_DEFRAG_SET    0x00000002
#define LOOKUP_STREAM_FROM_CLUSTER_ENTRY_FLAG_FS_SYSTEM_FILE     0x00000004
#define LOOKUP_STREAM_FROM_CLUSTER_ENTRY_FLAG_TXF_SYSTEM_FILE    0x00000008

#define LOOKUP_STREAM_FROM_CLUSTER_ENTRY_ATTRIBUTE_MASK          0xff000000
#define LOOKUP_STREAM_FROM_CLUSTER_ENTRY_ATTRIBUTE_DATA          0x01000000
#define LOOKUP_STREAM_FROM_CLUSTER_ENTRY_ATTRIBUTE_INDEX         0x02000000
#define LOOKUP_STREAM_FROM_CLUSTER_ENTRY_ATTRIBUTE_SYSTEM        0x03000000

typedef struct _LOOKUP_STREAM_FROM_CLUSTER_ENTRY {
    //
    //  Offset from the beginning of this structure to the next entry
    //  returned.  If there are no more entries, this value is zero.
    //
    ULONG         OffsetToNext;

    //
    //  Flags describing characteristics about this stream.
    //
    ULONG         Flags;

    //
    //  This value is reserved and is currently zero.
    //
    LARGE_INTEGER Reserved;

    //
    //  This is the cluster that this entry refers to.  It will be one
    //  of the clusters passed in the input structure.
    //
    LARGE_INTEGER Cluster;

    //
    //  A NULL-terminated Unicode string containing the path of the
    //  object relative to the root of the volume.  This string
    //  will refer to the attribute or stream represented by the
    //  cluster.
    //
    WCHAR         FileName[1];
} LOOKUP_STREAM_FROM_CLUSTER_ENTRY, *PLOOKUP_STREAM_FROM_CLUSTER_ENTRY;

//
//  This is the structure for the FSCTL_FILE_TYPE_NOTIFICATION operation.
//  Its purpose is to notify the storage stack about the extents of certain
//  types of files.  This is only callable from kernel mode
//

typedef struct _FILE_TYPE_NOTIFICATION_INPUT {

    //
    //  Flags for this operation
    //  FILE_TYPE_NOTIFICATION_FLAG_*
    //

    ULONG Flags;

    //
    //  A count of how many FileTypeID guids are given
    //

    ULONG NumFileTypeIDs;

    //
    //  This is a unique identifer for the type of file notification occuring
    //

    GUID FileTypeID[1];

} FILE_TYPE_NOTIFICATION_INPUT, *PFILE_TYPE_NOTIFICATION_INPUT;

//
//  Flags for the given operation
//

#define FILE_TYPE_NOTIFICATION_FLAG_USAGE_BEGIN     0x00000001      //Set when adding the specified usage on the given file
#define FILE_TYPE_NOTIFICATION_FLAG_USAGE_END       0x00000002      //Set when removing the specified usage on the given file

//
//  These are the globally defined file types
//

DEFINE_GUID( FILE_TYPE_NOTIFICATION_GUID_PAGE_FILE,         0x0d0a64a1, 0x38fc, 0x4db8, 0x9f, 0xe7, 0x3f, 0x43, 0x52, 0xcd, 0x7c, 0x5c );
DEFINE_GUID( FILE_TYPE_NOTIFICATION_GUID_HIBERNATION_FILE,  0xb7624d64, 0xb9a3, 0x4cf8, 0x80, 0x11, 0x5b, 0x86, 0xc9, 0x40, 0xe7, 0xb7 );
DEFINE_GUID( FILE_TYPE_NOTIFICATION_GUID_CRASHDUMP_FILE,    0x9d453eb7, 0xd2a6, 0x4dbd, 0xa2, 0xe3, 0xfb, 0xd0, 0xed, 0x91, 0x09, 0xa9 );
#endif /* _WIN32_WINNT >= 0x0601 */

#endif // _FILESYSTEMFSCTL_

// end_winioctl

//
// Structures for FSCTL_SET_REPARSE_POINT, FSCTL_GET_REPARSE_POINT, and FSCTL_DELETE_REPARSE_POINT
//

//
// The reparse structure is used by layered drivers to store data in a
// reparse point. The constraints on reparse tags are defined below.
// This version of the reparse data buffer is only for Microsoft tags.
//

#if _MSC_VER >= 1200
#pragma warning(push)
#endif
#pragma warning(disable:4201)       // unnamed struct

#define SYMLINK_FLAG_RELATIVE   1

typedef struct _REPARSE_DATA_BUFFER {
    ULONG  ReparseTag;
    USHORT ReparseDataLength;
    USHORT Reserved;
    union {
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            ULONG Flags;
            WCHAR PathBuffer[1];
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
    } DUMMYUNIONNAME;
} REPARSE_DATA_BUFFER, *PREPARSE_DATA_BUFFER;

#if _MSC_VER >= 1200
#pragma warning(pop)
#else
#pragma warning( default : 4201 )
#endif

#define REPARSE_DATA_BUFFER_HEADER_SIZE   FIELD_OFFSET(REPARSE_DATA_BUFFER, GenericReparseBuffer)


// begin_winnt
//
// The reparse GUID structure is used by all 3rd party layered drivers to
// store data in a reparse point. For non-Microsoft tags, The GUID field
// cannot be GUID_NULL.
// The constraints on reparse tags are defined below.
// Microsoft tags can also be used with this format of the reparse point buffer.
//

typedef struct _REPARSE_GUID_DATA_BUFFER {
    ULONG  ReparseTag;
    USHORT ReparseDataLength;
    USHORT Reserved;
    GUID   ReparseGuid;
    struct {
        UCHAR  DataBuffer[1];
    } GenericReparseBuffer;
} REPARSE_GUID_DATA_BUFFER, *PREPARSE_GUID_DATA_BUFFER;

#define REPARSE_GUID_DATA_BUFFER_HEADER_SIZE   FIELD_OFFSET(REPARSE_GUID_DATA_BUFFER, GenericReparseBuffer)



//
// Maximum allowed size of the reparse data.
//

#define MAXIMUM_REPARSE_DATA_BUFFER_SIZE      ( 16 * 1024 )

//
// Predefined reparse tags.
// These tags need to avoid conflicting with IO_REMOUNT defined in ntos\inc\io.h
//

#define IO_REPARSE_TAG_RESERVED_ZERO             (0)
#define IO_REPARSE_TAG_RESERVED_ONE              (1)

//
// The value of the following constant needs to satisfy the following conditions:
//  (1) Be at least as large as the largest of the reserved tags.
//  (2) Be strictly smaller than all the tags in use.
//

#define IO_REPARSE_TAG_RESERVED_RANGE            IO_REPARSE_TAG_RESERVED_ONE

//
// The reparse tags are a ULONG. The 32 bits are laid out as follows:
//
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//  +-+-+-+-+-----------------------+-------------------------------+
//  |M|R|N|R|     Reserved bits     |       Reparse Tag Value       |
//  +-+-+-+-+-----------------------+-------------------------------+
//
// M is the Microsoft bit. When set to 1, it denotes a tag owned by Microsoft.
//   All ISVs must use a tag with a 0 in this position.
//   Note: If a Microsoft tag is used by non-Microsoft software, the
//   behavior is not defined.
//
// R is reserved.  Must be zero for non-Microsoft tags.
//
// N is name surrogate. When set to 1, the file represents another named
//   entity in the system.
//
// The M and N bits are OR-able.
// The following macros check for the M and N bit values:
//

//
// Macro to determine whether a reparse point tag corresponds to a tag
// owned by Microsoft.
//

#define IsReparseTagMicrosoft(_tag) (              \
                           ((_tag) & 0x80000000)   \
                           )

//
// Macro to determine whether a reparse point tag is a name surrogate
//

#define IsReparseTagNameSurrogate(_tag) (          \
                           ((_tag) & 0x20000000)   \
                           )

// end_winnt

//
// The following constant represents the bits that are valid to use in
// reparse tags.
//

#define IO_REPARSE_TAG_VALID_VALUES     (0xF000FFFF)

//
// Macro to determine whether a reparse tag is a valid tag.
//

#define IsReparseTagValid(_tag) (                               \
                  !((_tag) & ~IO_REPARSE_TAG_VALID_VALUES) &&   \
                  ((_tag) > IO_REPARSE_TAG_RESERVED_RANGE)      \
                 )

///////////////////////////////////////////////////////////////////////////////
//
// Microsoft tags for reparse points.
//
///////////////////////////////////////////////////////////////////////////////

#define IO_REPARSE_TAG_MOUNT_POINT              (0xA0000003L)       // winnt
#define IO_REPARSE_TAG_HSM                      (0xC0000004L)       // winnt
#define IO_REPARSE_TAG_DRIVE_EXTENDER           (0x80000005L)
#define IO_REPARSE_TAG_HSM2                     (0x80000006L)       // winnt
#define IO_REPARSE_TAG_SIS                      (0x80000007L)       // winnt
#define IO_REPARSE_TAG_WIM                      (0x80000008L)       // winnt
#define IO_REPARSE_TAG_CSV                      (0x80000009L)       // winnt
#define IO_REPARSE_TAG_DFS                      (0x8000000AL)       // winnt
#define IO_REPARSE_TAG_FILTER_MANAGER           (0x8000000BL)
#define IO_REPARSE_TAG_SYMLINK                  (0xA000000CL)       // winnt
#define IO_REPARSE_TAG_IIS_CACHE                (0xA0000010L)
#define IO_REPARSE_TAG_DFSR                     (0x80000012L)       // winnt



///////////////////////////////////////////////////////////////////////////////
//
// Non-Microsoft tags for reparse points
//
///////////////////////////////////////////////////////////////////////////////

//
// Tag allocated to CONGRUENT, May 2000. Used by IFSTEST
//

#define IO_REPARSE_TAG_IFSTEST_CONGRUENT        (0x00000009L)

//
//  Tag allocated to Moonwalk Univeral for HSM
//  GUID: 257ABE42-5A28-4C8C-AC46-8FEA5619F18F
//

#define IO_REPARSE_TAG_MOONWALK_HSM             (0x0000000AL)

//
//  Tag allocated to Tsinghua Univeristy for Research purposes
//  No released products should use this tag
//  GUID: b86dff51-a31e-4bac-b3cf-e8cfe75c9fc2
//

#define IO_REPARSE_TAG_TSINGHUA_UNIVERSITY_RESEARCH (0x0000000BL)

//
// Tag allocated to ARKIVIO for HSM
//

#define IO_REPARSE_TAG_ARKIVIO                  (0x0000000CL)

//
//  Tag allocated to SOLUTIONSOFT for name surrogate
//

#define IO_REPARSE_TAG_SOLUTIONSOFT             (0x2000000DL)

//
//  Tag allocated to COMMVAULT for HSM
//

#define IO_REPARSE_TAG_COMMVAULT                (0x0000000EL)

//
//  Tag allocated to Overtone Software for HSM
//

#define IO_REPARSE_TAG_OVERTONE                 (0x0000000FL)

//
//  Tag allocated to Symantec (formerly to KVS Inc) for HSM
//  GUID: A49F7BF6-77CA-493c-A0AA-18DBB28D1098
//

#define IO_REPARSE_TAG_SYMANTEC_HSM2            (0x00000010L)

//
//  Tag allocated to Enigma Data for HSM
//

#define IO_REPARSE_TAG_ENIGMA_HSM               (0x00000011L)

//
//  Tag allocated to Symantec for HSM
//  GUID: B99F4235-CF1C-48dd-9E6C-459FA289F8C7
//

#define IO_REPARSE_TAG_SYMANTEC_HSM             (0x00000012L)

//
//  Tag allocated to INTERCOPE for HSM
//  GUID: F204BE2D-AEEB-4728-A31C-C7F4E9BEA758}
//

#define IO_REPARSE_TAG_INTERCOPE_HSM            (0x00000013L)

//
//  Tag allocated to KOM Networks for HSM
//

#define IO_REPARSE_TAG_KOM_NETWORKS_HSM         (0x00000014L)

//
//  Tag allocated to MEMORY_TECH for HSM
//  GUID: E51BA456-046C-43ea-AEC7-DC1A87E1FD49
//

#define IO_REPARSE_TAG_MEMORY_TECH_HSM          (0x00000015L)

//
//  Tag allocated to BridgeHead Software for HSM
//  GUID: EBAFF6E3-F21D-4496-8342-58144B3D2BD0
//

#define IO_REPARSE_TAG_BRIDGEHEAD_HSM           (0x00000016L)

//
//  Tag allocated to OSR for samples reparse point filter
//  GUID: 3740c860-b19b-11d9-9669-0800200c9a66
//

#define IO_REPARSE_TAG_OSR_SAMPLE               (0x20000017L)

//
//  Tag allocated to Global 360 for HSM
//  GUID: C4B51F66-7F00-4c55-9441-8A1B159F209B
//

#define IO_REPARSE_TAG_GLOBAL360_HSM            (0x00000018L)

//
//  Tag allocated to Altiris for HSM
//  GUID: fc1047eb-fb2d-45f2-a2f4-a71c1032fa2dB
//

#define IO_REPARSE_TAG_ALTIRIS_HSM              (0x00000019L)

//
//  Tag allocated to Hermes for HSM
//  GUID: 437E0FD5-FCB4-42fe-877A-C785DA662AC2
//

#define IO_REPARSE_TAG_HERMES_HSM               (0x0000001AL)

//
//  Tag allocated to PointSoft for HSM
//  GUID: 547BC7FD-9604-4deb-AE07-B6514DF5FBC6
//

#define IO_REPARSE_TAG_POINTSOFT_HSM            (0x0000001BL)

//
//  Tag allocated to GRAU Data Storage for HSM
//  GUID: 6662D310-5653-4D10-8C31-F8E166D1A1BD
//

#define IO_REPARSE_TAG_GRAU_DATASTORAGE_HSM     (0x0000001CL)

//
//  Tag allocated to CommVault for HSM
//  GUID: cc38adf3-c583-4efa-b183-72c1671941de
//

#define IO_REPARSE_TAG_COMMVAULT_HSM            (0x0000001DL)


//
//  Tag allocated to Data Storage Group for single instance storage
//  GUID: C1182673-0562-447a-8E40-4F0549FDF817
//

#define IO_REPARSE_TAG_DATASTOR_SIS             (0x0000001EL)


//
//  Tag allocated to Enterprise Data Solutions, Inc. for HSM
//  GUID: EB63DF9D-8874-41cd-999A-A197542CDAFC
//

#define IO_REPARSE_TAG_EDSI_HSM                 (0x0000001FL)


//
//  Tag allocated to HP StorageWorks Reference Information Manager for Files (HSM)
//  GUID: 3B0F6B23-0C2E-4281-9C19-C6AEEBC88CD8
//

#define IO_REPARSE_TAG_HP_HSM                   (0x00000020L)


//
//  Tag allocated to SER Beteiligung Solutions Deutschland GmbH (HSM)
//  GUID: 55B673F0-978E-41c5-9ADB-AF99640BE90E
//

#define IO_REPARSE_TAG_SER_HSM                  (0x00000021L)


//
//  Tag allocated to Double-Take Software (formerly NSI Software, Inc.) for HSM
//  GUID: f7cb0ce8-453a-4ae1-9c56-db41b55f6ed4
//

#define IO_REPARSE_TAG_DOUBLE_TAKE_HSM          (0x00000022L)


//
//  Tag allocated to Beijing Wisdata Systems CO, LTD for HSM
//  GUID: d546500a-2aeb-45f6-9482-f4b1799c3177
//

#define IO_REPARSE_TAG_WISDATA_HSM              (0x00000023L)


//
//  Tag allocated to Mimosa Systems Inc for HSM
//  GUID: 8ddd4144-1a22-404b-8a5a-fcd91c6ee9f3
//

#define IO_REPARSE_TAG_MIMOSA_HSM               (0x00000024L)


//
//  Tag allocated to H&S Heilig und Schubert Software AG for HSM
//  GUID: 77CA30C0-E5EC-43df-9E44-A4910378E284
//

#define IO_REPARSE_TAG_HSAG_HSM                 (0x00000025L)


//
//  Tag allocated to Atempo Inc. (Atempo Digital Archive)  for HSM
//  GUID: 9B64518A-D6A4-495f-8D01-392F38862F0C
//

#define IO_REPARSE_TAG_ADA_HSM                  (0x00000026L)


//
//  Tag allocated to Autonomy Corporation for HSM
//  GUID: EB112A57-10FC-4b42-B590-A61897FDC432
//

#define IO_REPARSE_TAG_AUTN_HSM                 (0x00000027L)


//
//  Tag allocated to Nexsan for HSM
//  GUID: d35eba9a-e722-445d-865f-dde1120acf16
//

#define IO_REPARSE_TAG_NEXSAN_HSM               (0x00000028L)


//
//  Tag allocated to Double-Take for SIS
//  GUID: BDA506C2-F74D-4495-9A8D-44FD8D5B4F42
//

#define IO_REPARSE_TAG_DOUBLE_TAKE_SIS          (0x00000029L)


//
//  Tag allocated to Sony for HSM
//  GUID: E95032E4-FD81-4e15-A8E2-A1F078061C4E
//

#define IO_REPARSE_TAG_SONY_HSM                 (0x0000002AL)


//
//  Tag allocated to Eltan Comm for HSM
//  GUID: E1596D9F-44D8-43f4-A2D6-E9FE8D3E28FB
//

#define IO_REPARSE_TAG_ELTAN_HSM                (0x0000002BL)


//
//  Tag allocated to Utixo LLC for HSM
//  GUID: 5401F960-2F95-46D0-BBA6-052929FE2C32
//

#define IO_REPARSE_TAG_UTIXO_HSM                (0x0000002CL)


//
//  Tag allocated to Quest Software for HSM
//  GUID: D546500A-2AEB-45F6-9482-F4B1799C3177
//

#define IO_REPARSE_TAG_QUEST_HSM                (0x0000002DL)


//
//  Tag allocated to DataGlobal GmbH for HSM
//  GUID: 7A09CA83-B7B1-4614-ADFD-0BD5F4F989C9
//

#define IO_REPARSE_TAG_DATAGLOBAL_HSM           (0x0000002EL)


//
//  Tag allocated to Qi Tech LLC for HSM
//  GUID: C8110B39-A4CE-432E-B58A-FBEAD296DF03
//

#define IO_REPARSE_TAG_QI_TECH_HSM              (0x2000002FL)

//
//  Tag allocated to DataFirst Corporation for HSM
//  GUID: E0E40591-6434-479f-94AC-DECF6DAEFB5C
//

#define IO_REPARSE_TAG_DATAFIRST_HSM            (0x00000030L)

//
//  Tag allocated to C2C Systems for HSM
//  GUID: 6F2F829C-36AE-4E88-A3B6-E2C24377EA1C
//

#define IO_REPARSE_TAG_C2CSYSTEMS_HSM           (0x00000031L)


//
//  Reparse point index keys.
//
//  The index with all the reparse points that exist in a volume at a
//  given time contains entries with keys of the form
//                        <reparse tag, file record id>.
//  The data part of these records is empty.
//

#pragma pack(4)

typedef struct _REPARSE_INDEX_KEY {

    //
    //  The tag of the reparse point.
    //

    ULONG FileReparseTag;

    //
    //  The file record Id where the reparse point is set.
    //

    LARGE_INTEGER FileId;

} REPARSE_INDEX_KEY, *PREPARSE_INDEX_KEY;

#pragma pack()



//
// The following three FSCTLs are placed in this file to facilitate sharing
// between the redirector and the IO subsystem
//
// This FSCTL is used to garner the link tracking information for a file.
// The data structures used for retreving the information are
// LINK_TRACKING_INFORMATION defined further down in this file.
//

#define FSCTL_LMR_GET_LINK_TRACKING_INFORMATION   CTL_CODE(FILE_DEVICE_NETWORK_FILE_SYSTEM,58,METHOD_BUFFERED,FILE_ANY_ACCESS)

//
// This FSCTL is used to update the link tracking information on a server for
// an intra machine/ inter volume move on that server
//

#define FSCTL_LMR_SET_LINK_TRACKING_INFORMATION   CTL_CODE(FILE_DEVICE_NETWORK_FILE_SYSTEM,59,METHOD_BUFFERED,FILE_ANY_ACCESS)

//
// The following IOCTL is used in link tracking implementation. It determines if the
// two file objects passed in are on the same server. This IOCTL is available in
// kernel mode only since it accepts FILE_OBJECT as parameters
//

#define IOCTL_LMR_ARE_FILE_OBJECTS_ON_SAME_SERVER CTL_CODE(FILE_DEVICE_NETWORK_FILE_SYSTEM,60,METHOD_BUFFERED,FILE_ANY_ACCESS)



//
// Named Pipe file control code and structure declarations
//

//
// External named pipe file control operations
//

#define FSCTL_PIPE_ASSIGN_EVENT             CTL_CODE(FILE_DEVICE_NAMED_PIPE, 0, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_PIPE_DISCONNECT               CTL_CODE(FILE_DEVICE_NAMED_PIPE, 1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_PIPE_LISTEN                   CTL_CODE(FILE_DEVICE_NAMED_PIPE, 2, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_PIPE_PEEK                     CTL_CODE(FILE_DEVICE_NAMED_PIPE, 3, METHOD_BUFFERED, FILE_READ_DATA)
#define FSCTL_PIPE_QUERY_EVENT              CTL_CODE(FILE_DEVICE_NAMED_PIPE, 4, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_PIPE_TRANSCEIVE               CTL_CODE(FILE_DEVICE_NAMED_PIPE, 5, METHOD_NEITHER,  FILE_READ_DATA | FILE_WRITE_DATA)
#define FSCTL_PIPE_WAIT                     CTL_CODE(FILE_DEVICE_NAMED_PIPE, 6, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_PIPE_IMPERSONATE              CTL_CODE(FILE_DEVICE_NAMED_PIPE, 7, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_PIPE_SET_CLIENT_PROCESS       CTL_CODE(FILE_DEVICE_NAMED_PIPE, 8, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_PIPE_QUERY_CLIENT_PROCESS     CTL_CODE(FILE_DEVICE_NAMED_PIPE, 9, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_PIPE_GET_PIPE_ATTRIBUTE       CTL_CODE(FILE_DEVICE_NAMED_PIPE, 10, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_PIPE_SET_PIPE_ATTRIBUTE       CTL_CODE(FILE_DEVICE_NAMED_PIPE, 11, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_PIPE_GET_CONNECTION_ATTRIBUTE CTL_CODE(FILE_DEVICE_NAMED_PIPE, 12, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_PIPE_SET_CONNECTION_ATTRIBUTE CTL_CODE(FILE_DEVICE_NAMED_PIPE, 13, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_PIPE_GET_HANDLE_ATTRIBUTE     CTL_CODE(FILE_DEVICE_NAMED_PIPE, 14, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_PIPE_SET_HANDLE_ATTRIBUTE     CTL_CODE(FILE_DEVICE_NAMED_PIPE, 15, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_PIPE_FLUSH                    CTL_CODE(FILE_DEVICE_NAMED_PIPE, 16, METHOD_BUFFERED, FILE_WRITE_DATA)

//
// Internal named pipe file control operations
//

#define FSCTL_PIPE_INTERNAL_READ        CTL_CODE(FILE_DEVICE_NAMED_PIPE, 2045, METHOD_BUFFERED, FILE_READ_DATA)
#define FSCTL_PIPE_INTERNAL_WRITE       CTL_CODE(FILE_DEVICE_NAMED_PIPE, 2046, METHOD_BUFFERED, FILE_WRITE_DATA)
#define FSCTL_PIPE_INTERNAL_TRANSCEIVE  CTL_CODE(FILE_DEVICE_NAMED_PIPE, 2047, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA)
#define FSCTL_PIPE_INTERNAL_READ_OVFLOW CTL_CODE(FILE_DEVICE_NAMED_PIPE, 2048, METHOD_BUFFERED, FILE_READ_DATA)

//
// Define entry types for query event information
//

#define FILE_PIPE_READ_DATA             0x00000000
#define FILE_PIPE_WRITE_SPACE           0x00000001

//
// Named pipe file system control structure declarations
//

// Control structure for FSCTL_PIPE_ASSIGN_EVENT

typedef struct _FILE_PIPE_ASSIGN_EVENT_BUFFER {
     HANDLE EventHandle;
     ULONG KeyValue;
} FILE_PIPE_ASSIGN_EVENT_BUFFER, *PFILE_PIPE_ASSIGN_EVENT_BUFFER;

// Control structure for FSCTL_PIPE_PEEK

typedef struct _FILE_PIPE_PEEK_BUFFER {
     ULONG NamedPipeState;
     ULONG ReadDataAvailable;
     ULONG NumberOfMessages;
     ULONG MessageLength;
     CHAR Data[1];
} FILE_PIPE_PEEK_BUFFER, *PFILE_PIPE_PEEK_BUFFER;

// Control structure for FSCTL_PIPE_QUERY_EVENT

typedef struct _FILE_PIPE_EVENT_BUFFER {
     ULONG NamedPipeState;
     ULONG EntryType;
     ULONG ByteCount;
     ULONG KeyValue;
     ULONG NumberRequests;
} FILE_PIPE_EVENT_BUFFER, *PFILE_PIPE_EVENT_BUFFER;

// Control structure for FSCTL_PIPE_WAIT

typedef struct _FILE_PIPE_WAIT_FOR_BUFFER {
     LARGE_INTEGER Timeout;
     ULONG NameLength;
     BOOLEAN TimeoutSpecified;
     WCHAR Name[1];
} FILE_PIPE_WAIT_FOR_BUFFER, *PFILE_PIPE_WAIT_FOR_BUFFER;

// Control structure for FSCTL_PIPE_SET_CLIENT_PROCESS and FSCTL_PIPE_QUERY_CLIENT_PROCESS

typedef struct _FILE_PIPE_CLIENT_PROCESS_BUFFER {
#if !defined(BUILD_WOW6432)
     PVOID ClientSession;
     PVOID ClientProcess;
#else
     ULONGLONG ClientSession;
     ULONGLONG ClientProcess;
#endif
} FILE_PIPE_CLIENT_PROCESS_BUFFER, *PFILE_PIPE_CLIENT_PROCESS_BUFFER;

// This is an extension to the client process info buffer containing the client
// computer name

#define FILE_PIPE_COMPUTER_NAME_LENGTH 15

typedef struct _FILE_PIPE_CLIENT_PROCESS_BUFFER_EX {
#if !defined(BUILD_WOW6432)
    PVOID ClientSession;
    PVOID ClientProcess;
#else
     ULONGLONG ClientSession;
     ULONGLONG ClientProcess;
#endif
    USHORT ClientComputerNameLength; // in bytes
    WCHAR ClientComputerBuffer[FILE_PIPE_COMPUTER_NAME_LENGTH+1]; // terminated
} FILE_PIPE_CLIENT_PROCESS_BUFFER_EX, *PFILE_PIPE_CLIENT_PROCESS_BUFFER_EX;

//
// Mailslot file control operations.
//

#define FSCTL_MAILSLOT_PEEK             CTL_CODE(FILE_DEVICE_MAILSLOT, 0, METHOD_NEITHER, FILE_READ_DATA) // ntifs

//
// Control structure for FSCTL_LMR_GET_LINK_TRACKING_INFORMATION
//

//
// For links on DFS volumes the volume id and machine id are returned for
// link tracking
//

typedef enum _LINK_TRACKING_INFORMATION_TYPE {
    NtfsLinkTrackingInformation,
    DfsLinkTrackingInformation
} LINK_TRACKING_INFORMATION_TYPE, *PLINK_TRACKING_INFORMATION_TYPE;

typedef struct _LINK_TRACKING_INFORMATION {
    LINK_TRACKING_INFORMATION_TYPE Type;
    UCHAR   VolumeId[16];
} LINK_TRACKING_INFORMATION, *PLINK_TRACKING_INFORMATION;

//
// Control structure for FSCTL_LMR_SET_LINK_TRACKING_INFORMATION
//

typedef struct _REMOTE_LINK_TRACKING_INFORMATION_ {
    PVOID       TargetFileObject;
    ULONG   TargetLinkTrackingInformationLength;
    UCHAR   TargetLinkTrackingInformationBuffer[1];
} REMOTE_LINK_TRACKING_INFORMATION,
 *PREMOTE_LINK_TRACKING_INFORMATION;


#if (_WIN32_WINNT >= 0x0601)

#pragma warning(push)
#pragma warning(disable : 4200)
#pragma warning(disable : 4201)

#ifndef _VIRTUAL_STORAGE_TYPE_DEFINED
#define _VIRTUAL_STORAGE_TYPE_DEFINED
typedef struct _VIRTUAL_STORAGE_TYPE
{
    ULONG DeviceId;
    GUID  VendorId;
} VIRTUAL_STORAGE_TYPE, *PVIRTUAL_STORAGE_TYPE;
#endif

//
//  These structures are used by the FSCTL_QUERY_DEPENDENT_VOLUME
//

typedef struct _STORAGE_QUERY_DEPENDENT_VOLUME_REQUEST {
    ULONG   RequestLevel;
    ULONG   RequestFlags;
} STORAGE_QUERY_DEPENDENT_VOLUME_REQUEST, *PSTORAGE_QUERY_DEPENDENT_VOLUME_REQUEST;

#define QUERY_DEPENDENT_VOLUME_REQUEST_FLAG_HOST_VOLUMES    0x1
#define QUERY_DEPENDENT_VOLUME_REQUEST_FLAG_GUEST_VOLUMES   0x2

typedef struct _STORAGE_QUERY_DEPENDENT_VOLUME_LEV1_ENTRY {
    ULONG   EntryLength;
    ULONG   DependencyTypeFlags;
    ULONG   ProviderSpecificFlags;
    VIRTUAL_STORAGE_TYPE VirtualStorageType;
} STORAGE_QUERY_DEPENDENT_VOLUME_LEV1_ENTRY, *PSTORAGE_QUERY_DEPENDENT_VOLUME_LEV1_ENTRY;

typedef struct _STORAGE_QUERY_DEPENDENT_VOLUME_LEV2_ENTRY {
    ULONG   EntryLength;
    ULONG   DependencyTypeFlags;
    ULONG   ProviderSpecificFlags;
    VIRTUAL_STORAGE_TYPE VirtualStorageType;
    ULONG   AncestorLevel;      // Root parent is 0, every child level after that is incremented
    ULONG   HostVolumeNameOffset;
    ULONG   HostVolumeNameSize;
    ULONG   DependentVolumeNameOffset;
    ULONG   DependentVolumeNameSize;
    ULONG   RelativePathOffset;
    ULONG   RelativePathSize;
    ULONG   DependentDeviceNameOffset;
    ULONG   DependentDeviceNameSize;
} STORAGE_QUERY_DEPENDENT_VOLUME_LEV2_ENTRY, *PSTORAGE_QUERY_DEPENDENT_VOLUME_LEV2_ENTRY;

typedef struct _STORAGE_QUERY_DEPENDENT_VOLUME_RESPONSE {
    ULONG   ResponseLevel;
    ULONG   NumberEntries;
    union {
        STORAGE_QUERY_DEPENDENT_VOLUME_LEV1_ENTRY Lev1Depends[];
        STORAGE_QUERY_DEPENDENT_VOLUME_LEV2_ENTRY Lev2Depends[];
    };
} STORAGE_QUERY_DEPENDENT_VOLUME_RESPONSE, *PSTORAGE_QUERY_DEPENDENT_VOLUME_RESPONSE;

#pragma warning(pop)

#endif  // WinVer >= 0x0601


//
// Object Information Classes
//

typedef enum _OBJECT_INFORMATION_CLASS {
    ObjectBasicInformation = 0,
    ObjectTypeInformation = 2
} OBJECT_INFORMATION_CLASS;

//
//  Public Object Information definitions
//

typedef struct _PUBLIC_OBJECT_BASIC_INFORMATION {
    ULONG Attributes;
    ACCESS_MASK GrantedAccess;
    ULONG HandleCount;
    ULONG PointerCount;

    ULONG Reserved[10];    // reserved for internal use

} PUBLIC_OBJECT_BASIC_INFORMATION, *PPUBLIC_OBJECT_BASIC_INFORMATION;

typedef struct __PUBLIC_OBJECT_TYPE_INFORMATION {

    UNICODE_STRING TypeName;

    ULONG Reserved [22];    // reserved for internal use

} PUBLIC_OBJECT_TYPE_INFORMATION, *PPUBLIC_OBJECT_TYPE_INFORMATION;

#if (NTDDI_VERSION >= NTDDI_NT4)
__drv_maxIRQL(PASSIVE_LEVEL)
__kernel_entry NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryObject (
    __in_opt HANDLE Handle,
    __in OBJECT_INFORMATION_CLASS ObjectInformationClass,
    __out_bcount_opt(ObjectInformationLength) PVOID ObjectInformation,
    __in ULONG ObjectInformationLength,
    __out_opt PULONG ReturnLength
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
__kernel_entry NTSYSCALLAPI
NTSTATUS
NTAPI
NtSetSecurityObject (
    __in HANDLE Handle,
    __in SECURITY_INFORMATION SecurityInformation,
    __in PSECURITY_DESCRIPTOR SecurityDescriptor
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
__kernel_entry NTSYSCALLAPI
NTSTATUS
NTAPI
NtQuerySecurityObject (
    __in HANDLE Handle,
    __in SECURITY_INFORMATION SecurityInformation,
    __out_bcount_opt(Length) PSECURITY_DESCRIPTOR SecurityDescriptor,
    __in ULONG Length,
    __out PULONG LengthNeeded
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
__kernel_entry NTSYSCALLAPI
NTSTATUS
NTAPI
NtClose (
    __in HANDLE Handle
    );
#endif // NTDDI_VERSION >= NTDDI_WIN2K


#if (NTDDI_VERSION >= NTDDI_WINXP)
__checkReturn
__kernel_entry NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreateSection (
    __out PHANDLE SectionHandle,
    __in ACCESS_MASK DesiredAccess,
    __in_opt POBJECT_ATTRIBUTES ObjectAttributes,
    __in_opt PLARGE_INTEGER MaximumSize,
    __in ULONG SectionPageProtection,
    __in ULONG AllocationAttributes,
    __in_opt HANDLE FileHandle
    );
#endif // NTDDI_VERSION >= NTDDI_WINXP


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn
__drv_allocatesMem(Mem)
__kernel_entry NTSYSCALLAPI
NTSTATUS
NTAPI
NtAllocateVirtualMemory (
    __in HANDLE ProcessHandle,
    __inout PVOID *BaseAddress,
    __in ULONG_PTR ZeroBits,
    __inout PSIZE_T RegionSize,
    __in ULONG AllocationType,
    __in ULONG Protect
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__kernel_entry NTSYSCALLAPI
NTSTATUS
NTAPI
NtFreeVirtualMemory (
    __in HANDLE ProcessHandle,
    __inout __drv_freesMem(Mem) PVOID *BaseAddress,
    __inout PSIZE_T RegionSize,
    __in ULONG FreeType
    );
#endif // NTDDI_VERSION >= NTDDI_WIN2K

//
// Data structure used to represent client security context for a thread.
// This data structure is used to support impersonation.
//
//  THE FIELDS OF THIS DATA STRUCTURE SHOULD BE CONSIDERED OPAQUE
//  BY ALL EXCEPT THE SECURITY ROUTINES.
//

typedef struct _SECURITY_CLIENT_CONTEXT {
    SECURITY_QUALITY_OF_SERVICE SecurityQos;
    PACCESS_TOKEN ClientToken;
    BOOLEAN DirectlyAccessClientToken;
    BOOLEAN DirectAccessEffectiveOnly;
    BOOLEAN ServerIsRemote;
    TOKEN_CONTROL ClientTokenControl;
    } SECURITY_CLIENT_CONTEXT, *PSECURITY_CLIENT_CONTEXT;

//
// where
//
//    SecurityQos - is the security quality of service information in effect
//        for this client.  This information is used when directly accessing
//        the client's token.  In this case, the information here over-rides
//        the information in the client's token.  If a copy of the client's
//        token is requested, it must be generated using this information,
//        not the information in the client's token.  In all cases, this
//        information may not provide greater access than the information
//        in the client's token.  In particular, if the client's token is
//        an impersonation token with an impersonation level of
//        "SecurityDelegation", but the information in this field indicates
//        an impersonation level of "SecurityIdentification", then
//        the server may only get a copy of the token with an Identification
//        level of impersonation.
//
//    ClientToken - If the DirectlyAccessClientToken field is FALSE,
//        then this field contains a pointer to a duplicate of the
//        client's token.  Otherwise, this field points directly to
//        the client's token.
//
//    DirectlyAccessClientToken - This boolean flag indicates whether the
//        token pointed to by ClientToken is a copy of the client's token
//        or is a direct reference to the client's token.  A value of TRUE
//        indicates the client's token is directly accessed, FALSE indicates
//        a copy has been made.
//
//    DirectAccessEffectiveOnly - This boolean flag indicates whether the
//        the disabled portions of the token that is currently directly
//        referenced may be enabled.  This field is only valid if the
//        DirectlyAccessClientToken field is TRUE.  In that case, this
//        value supersedes the EffectiveOnly value in the SecurityQos
//        FOR THE CURRENT TOKEN ONLY!  If the client changes to impersonate
//        another client, this value may change.  This value is always
//        minimized by the EffectiveOnly flag in the SecurityQos field.
//
//    ServerIsRemote - If TRUE indicates that the server of the client's
//        request is remote.  This is used for determining the legitimacy
//        of certain levels of impersonation and to determine how to
//        track context.
//
//    ClientTokenControl - If the ServerIsRemote flag is TRUE, and the
//        tracking mode is DYNAMIC, then this field contains a copy of
//        the TOKEN_SOURCE from the client's token to assist in deciding
//        whether the information at the remote server needs to be
//        updated to match the current state of the client's security
//        context.
//
//
//    NOTE: At some point, we may find it worthwhile to keep an array of
//          elements in this data structure, where each element of the
//          array contains {ClientToken, ClientTokenControl} fields.
//          This would allow efficient handling of the case where a client
//          thread was constantly switching between a couple different
//          contexts - presumably impersonating client's of its own.
//
#define NTKERNELAPI DECLSPEC_IMPORT     
#define NTHALAPI DECLSPEC_IMPORT            
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
// Priority increment for completing mailslot I/O.  This is used by the mail-
// slot file system driver when completing an IRP (IoCompleteRequest).
//

#define IO_MAILSLOT_INCREMENT           2

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
// Priority increment used when satisfying a wait on an executive semaphore
// (NtReleaseSemaphore)
//

#define SEMAPHORE_INCREMENT             1



//
// Memory priority definitions.
//

#define SYSTEM_PAGE_PRIORITY_BITS       3
#define SYSTEM_PAGE_PRIORITY_LEVELS     (1 << SYSTEM_PAGE_PRIORITY_BITS)


//
// Miscellaneous type definitions
//
// APC state
//
// N.B. The user APC pending field must be the last member of this structure.
//

typedef struct _KAPC_STATE {
    LIST_ENTRY ApcListHead[MaximumMode];
    struct _KPROCESS *Process;
    BOOLEAN KernelApcInProgress;
    BOOLEAN KernelApcPending;
    BOOLEAN UserApcPending;
} KAPC_STATE, *PKAPC_STATE, *PRKAPC_STATE;

#define KAPC_STATE_ACTUAL_LENGTH                                             \
    (FIELD_OFFSET(KAPC_STATE, UserApcPending) + sizeof(BOOLEAN))

//
// Queue object
//

#define ASSERT_QUEUE(Q) NT_ASSERT(KOBJECT_TYPE(Q) == QueueObject);

// begin_ntosp

typedef struct _KQUEUE {
    DISPATCHER_HEADER Header;
    LIST_ENTRY EntryListHead;       // Object lock
    volatile ULONG CurrentCount;    // Interlocked
    ULONG MaximumCount;
    LIST_ENTRY ThreadListHead;      // Object lock
} KQUEUE, *PKQUEUE, *PRKQUEUE;

// end_ntosp

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
KeInitializeMutant (
    __out PRKMUTANT Mutant,
    __in BOOLEAN InitialOwner
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
VOID
KeQueryOwnerMutant (
    __in PKMUTANT Mutant,
    __out PCLIENT_ID ClientId
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
LONG
KeReadStateMutant (
    __in PRKMUTANT Mutant
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
KeReleaseMutant (
    __inout PRKMUTANT Mutant,
    __in KPRIORITY Increment,
    __in BOOLEAN Abandoned,
    __in BOOLEAN Wait
    );
#endif

//
// Queue Object.
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
KeInitializeQueue (
    __out PRKQUEUE Queue,
    __in ULONG Count
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
LONG
KeReadStateQueue (
    __in PRKQUEUE Queue
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_minIRQL(PASSIVE_LEVEL)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
LONG
KeInsertQueue (
    __inout PRKQUEUE Queue,
    __inout PLIST_ENTRY Entry
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_minIRQL(PASSIVE_LEVEL)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
LONG
KeInsertHeadQueue (
    __inout PRKQUEUE Queue,
    __inout PLIST_ENTRY Entry
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_minIRQL(PASSIVE_LEVEL)
__drv_when((Timeout==NULL || *Timeout!=0), __drv_maxIRQL(APC_LEVEL))
__drv_when((Timeout!=NULL && *Timeout==0), __drv_maxIRQL(DISPATCH_LEVEL))
NTKERNELAPI
PLIST_ENTRY
KeRemoveQueue (
    __inout PRKQUEUE Queue,
    __in KPROCESSOR_MODE WaitMode,
    __in_opt PLARGE_INTEGER Timeout
    );
#endif


#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_minIRQL(PASSIVE_LEVEL)
__drv_when((Timeout==NULL || *Timeout!=0), __drv_maxIRQL(APC_LEVEL))
__drv_when((Timeout!=NULL && *Timeout==0), __drv_maxIRQL(DISPATCH_LEVEL))
NTKERNELAPI
ULONG
KeRemoveQueueEx (
    __inout PKQUEUE Queue,
    __in KPROCESSOR_MODE WaitMode,
    __in BOOLEAN Alertable,
    __in_opt PLARGE_INTEGER Timeout,
    __out_ecount_part(Count, return) PLIST_ENTRY *EntryArray,
    __in ULONG Count
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
PLIST_ENTRY
KeRundownQueue (
    __inout PRKQUEUE Queue
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
KeAttachProcess (
    __inout PRKPROCESS Process
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
KeDetachProcess (
    VOID
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
KeStackAttachProcess (
    __inout PRKPROCESS PROCESS,
    __out PRKAPC_STATE ApcState
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
KeUnstackDetachProcess (
    __in PRKAPC_STATE ApcState
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_minIRQL(PASSIVE_LEVEL)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
UCHAR
KeSetIdealProcessorThread (
    __inout PKTHREAD Thread,
    __in UCHAR Processor
    );
#endif

// begin_ntosp
#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
BOOLEAN
KeSetKernelStackSwapEnable (
    __in BOOLEAN Enable
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WINXP)
__drv_raisesIRQL(DISPATCH_LEVEL)
_DECL_HAL_KE_IMPORT
KIRQL
FASTCALL
KeAcquireQueuedSpinLock (
    __inout __deref __drv_acquiresExclusiveResource(KeQueuedSpinLockType)
    __in KSPIN_LOCK_QUEUE_NUMBER Number
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
_DECL_HAL_KE_IMPORT
VOID
FASTCALL
KeReleaseQueuedSpinLock (
    __inout __deref __drv_releasesExclusiveResource(KeQueuedSpinLockType)
    __in KSPIN_LOCK_QUEUE_NUMBER Number,
    __in KIRQL OldIrql
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
__checkReturn
__drv_valueIs(==1;==0)
_DECL_HAL_KE_IMPORT
LOGICAL
FASTCALL
KeTryToAcquireQueuedSpinLock (
    __in KSPIN_LOCK_QUEUE_NUMBER Number,
    __out __deref __drv_savesIRQL
    PKIRQL OldIrql
    );
#endif

#if defined(_X86_)   

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_raisesIRQL(SYNCH_LEVEL)
__drv_savesIRQL
_DECL_HAL_KE_IMPORT
KIRQL
FASTCALL
KeAcquireSpinLockRaiseToSynch (
    __inout __deref __drv_acquiresExclusiveResource(KeSpinLockType)
    __inout PKSPIN_LOCK SpinLock
    );
#endif

#else 


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_raisesIRQL(SYNCH_LEVEL)
__drv_savesIRQL
NTKERNELAPI
KIRQL
KeAcquireSpinLockRaiseToSynch (
    __inout __deref __drv_acquiresExclusiveResource(KeSpinLockType)
    __inout PKSPIN_LOCK SpinLock
    );
#endif

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


#if (NTDDI_VERSION >= NTDDI_WIN2K)

__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
SIZE_T
ExQueryPoolBlockSize(
    __in PVOID PoolBlock,
    __out PBOOLEAN QuotaCharged
    );

#endif



#if (NTDDI_VERSION >= NTDDI_WINXP)

PSLIST_ENTRY
FASTCALL
InterlockedPushListSList (
    __inout PSLIST_HEADER ListHead,
    __inout __drv_aliasesMem PSLIST_ENTRY List,
    __inout PSLIST_ENTRY ListEnd,
    __in ULONG Count
    );

#endif // NTDDI_VERSION >= NTDDI_WINXP

//
// Define interlocked lookaside list structure and allocation functions.
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)

__drv_maxIRQL(DISPATCH_LEVEL)
VOID
ExAdjustLookasideDepth (
    VOID
    );

#endif


#if !defined(_X86AMD64_)

#if defined(_WIN64)

C_ASSERT(sizeof(ERESOURCE) == 0x68);
C_ASSERT(FIELD_OFFSET(ERESOURCE,ActiveCount) == 0x18);
C_ASSERT(FIELD_OFFSET(ERESOURCE,Flag) == 0x1a);

#else

C_ASSERT(sizeof(ERESOURCE) == 0x38);
C_ASSERT(FIELD_OFFSET(ERESOURCE,ActiveCount) == 0x0c);
C_ASSERT(FIELD_OFFSET(ERESOURCE,Flag) == 0x0e);

#endif

#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)

__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
VOID
ExDisableResourceBoostLite (
    __in PERESOURCE Resource
    );

#endif


#define ExDisableResourceBoost ExDisableResourceBoostLite


//
// Push lock definitions
//


#define EX_PUSH_LOCK ULONG_PTR
#define PEX_PUSH_LOCK PULONG_PTR


VOID
ExInitializePushLock (
    __out PEX_PUSH_LOCK PushLock
    );

//
// Token Flags
//
// Flags that may be defined in the TokenFlags field of the token object,
// or in an ACCESS_STATE structure
//

#define TOKEN_HAS_TRAVERSE_PRIVILEGE    0x0001
#define TOKEN_HAS_BACKUP_PRIVILEGE      0x0002
#define TOKEN_HAS_RESTORE_PRIVILEGE     0x0004
#define TOKEN_WRITE_RESTRICTED          0x0008
#define TOKEN_IS_RESTRICTED             0x0010
#define TOKEN_SESSION_NOT_REFERENCED    0x0020
#define TOKEN_SANDBOX_INERT             0x0040
#define TOKEN_HAS_IMPERSONATE_PRIVILEGE 0x0080
#define SE_BACKUP_PRIVILEGES_CHECKED    0x0100
#define TOKEN_VIRTUALIZE_ALLOWED        0x0200
#define TOKEN_VIRTUALIZE_ENABLED        0x0400
#define TOKEN_IS_FILTERED               0x0800
#define TOKEN_UIACCESS                  0x1000
#define TOKEN_NOT_LOW                   0x2000


typedef struct _SE_EXPORTS {

    //
    // Privilege values
    //

    LUID    SeCreateTokenPrivilege;
    LUID    SeAssignPrimaryTokenPrivilege;
    LUID    SeLockMemoryPrivilege;
    LUID    SeIncreaseQuotaPrivilege;
    LUID    SeUnsolicitedInputPrivilege;
    LUID    SeTcbPrivilege;
    LUID    SeSecurityPrivilege;
    LUID    SeTakeOwnershipPrivilege;
    LUID    SeLoadDriverPrivilege;
    LUID    SeCreatePagefilePrivilege;
    LUID    SeIncreaseBasePriorityPrivilege;
    LUID    SeSystemProfilePrivilege;
    LUID    SeSystemtimePrivilege;
    LUID    SeProfileSingleProcessPrivilege;
    LUID    SeCreatePermanentPrivilege;
    LUID    SeBackupPrivilege;
    LUID    SeRestorePrivilege;
    LUID    SeShutdownPrivilege;
    LUID    SeDebugPrivilege;
    LUID    SeAuditPrivilege;
    LUID    SeSystemEnvironmentPrivilege;
    LUID    SeChangeNotifyPrivilege;
    LUID    SeRemoteShutdownPrivilege;


    //
    // Universally defined Sids
    //


    PSID  SeNullSid;
    PSID  SeWorldSid;
    PSID  SeLocalSid;
    PSID  SeCreatorOwnerSid;
    PSID  SeCreatorGroupSid;


    //
    // Nt defined Sids
    //


    PSID  SeNtAuthoritySid;
    PSID  SeDialupSid;
    PSID  SeNetworkSid;
    PSID  SeBatchSid;
    PSID  SeInteractiveSid;
    PSID  SeLocalSystemSid;
    PSID  SeAliasAdminsSid;
    PSID  SeAliasUsersSid;
    PSID  SeAliasGuestsSid;
    PSID  SeAliasPowerUsersSid;
    PSID  SeAliasAccountOpsSid;
    PSID  SeAliasSystemOpsSid;
    PSID  SeAliasPrintOpsSid;
    PSID  SeAliasBackupOpsSid;

    //
    // New Sids defined for NT5
    //

    PSID  SeAuthenticatedUsersSid;

    PSID  SeRestrictedSid;
    PSID  SeAnonymousLogonSid;

    //
    // New Privileges defined for NT5
    //

    LUID  SeUndockPrivilege;
    LUID  SeSyncAgentPrivilege;
    LUID  SeEnableDelegationPrivilege;

    //
    // New Sids defined for post-Windows 2000

    PSID  SeLocalServiceSid;
    PSID  SeNetworkServiceSid;

    //
    // New Privileges defined for post-Windows 2000
    //

    LUID  SeManageVolumePrivilege;
    LUID  SeImpersonatePrivilege;
    LUID  SeCreateGlobalPrivilege;

    //
    // New Privileges defined for post Windows Server 2003
    //

    LUID  SeTrustedCredManAccessPrivilege;
    LUID  SeRelabelPrivilege;
    LUID  SeIncreaseWorkingSetPrivilege;

    LUID  SeTimeZonePrivilege;
    LUID  SeCreateSymbolicLinkPrivilege;

    //
    // New Sids defined for post Windows Server 2003
    //

    PSID  SeIUserSid;

    //
    // Mandatory Sids, ordered lowest to highest.
    //

    PSID SeUntrustedMandatorySid;
    PSID SeLowMandatorySid;
    PSID SeMediumMandatorySid;
    PSID SeHighMandatorySid;
    PSID SeSystemMandatorySid;

    PSID SeOwnerRightsSid;

} SE_EXPORTS, *PSE_EXPORTS;

///////////////////////////////////////////////////////////////////////////////
//                                                                           //
//              Logon session notification callback routines                 //
//                                                                           //
///////////////////////////////////////////////////////////////////////////////

//
//  These callback routines are used to notify file systems that have
//  registered of logon sessions being terminated, so they can cleanup state
//  associated with this logon session
//

typedef NTSTATUS
(*PSE_LOGON_SESSION_TERMINATED_ROUTINE)(
    __in PLUID LogonId);

//++
//
//  ULONG
//  SeLengthSid(
//      __in PSID Sid
//      );
//
//  Routine Description:
//
//      This routine computes the length of a SID.
//
//  Arguments:
//
//      Sid - Points to the SID whose length is to be returned.
//
//  Return Value:
//
//      The length, in bytes of the SID.
//
//--

#define SeLengthSid( Sid ) \
    (8 + (4 * ((SID *)Sid)->SubAuthorityCount))

//
//VOID
//SeDeleteClientSecurity(
//    __in PSECURITY_CLIENT_CONTEXT ClientContext
//    )
//
///*++
//
//Routine Description:
//
//    This service deletes a client security context block,
//    performing whatever cleanup might be necessary to do so.  In
//    particular, reference to any client token is removed.
//
//Arguments:
//
//    ClientContext - Points to the client security context block to be
//        deleted.
//
//
//Return Value:
//
//
//
//--*/
//--

// begin_ntosp
#define SeDeleteClientSecurity(C)  {                                           \
            if (SeTokenType((C)->ClientToken) == TokenPrimary) {               \
                PsDereferencePrimaryToken( (C)->ClientToken );                 \
            } else {                                                           \
                PsDereferenceImpersonationToken( (C)->ClientToken );           \
            }                                                                  \
        }


//++
//VOID
//SeStopImpersonatingClient()
//
///*++
//
//Routine Description:
//
//    This service is used to stop impersonating a client using an
//    impersonation token.  This service must be called in the context
//    of the server thread which wishes to stop impersonating its
//    client.
//
//
//Arguments:
//
//    None.
//
//Return Value:
//
//    None.
//
//--*/
//--

#define SeStopImpersonatingClient() PsRevertToSelf()


//++
//
//  PACCESS_TOKEN
//  SeQuerySubjectContextToken(
//      __in PSECURITY_SUBJECT_CONTEXT SubjectContext
//      );
//
//  Routine Description:
//
//      This routine returns the effective token from the subject context,
//      either the client token, if present, or the process token.
//
//  Arguments:
//
//      SubjectContext - Context to query
//
//  Return Value:
//
//      This routine returns the PACCESS_TOKEN for the effective token.
//      The pointer may be passed to SeQueryInformationToken.  This routine
//      does not affect the lock status of the token, i.e. the token is not
//      locked.  If the SubjectContext has been locked, the token remains locked,
//      if not, the token remains unlocked.
//
//--

#define SeQuerySubjectContextToken( SubjectContext ) \
        ( ARGUMENT_PRESENT( ((PSECURITY_SUBJECT_CONTEXT) SubjectContext)->ClientToken) ? \
            ((PSECURITY_SUBJECT_CONTEXT) SubjectContext)->ClientToken : \
            ((PSECURITY_SUBJECT_CONTEXT) SubjectContext)->PrimaryToken )


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


NTSTATUS
SeReportSecurityEventWithSubCategory(
    __in ULONG Flags,
    __in PUNICODE_STRING SourceName,
    __in_opt PSID UserSid,
    __in PSE_ADT_PARAMETER_ARRAY AuditParameters,
    __in ULONG AuditSubcategoryId
    );

BOOLEAN
SeAccessCheckFromState (
    __in PSECURITY_DESCRIPTOR SecurityDescriptor,
    __in PTOKEN_ACCESS_INFORMATION PrimaryTokenInformation,
    __in_opt PTOKEN_ACCESS_INFORMATION ClientTokenInformation,
    __in ACCESS_MASK DesiredAccess,
    __in ACCESS_MASK PreviouslyGrantedAccess,
    __deref_opt_out_opt PPRIVILEGE_SET *Privileges,
    __in PGENERIC_MAPPING GenericMapping,
    __in KPROCESSOR_MODE AccessMode,
    __out PACCESS_MASK GrantedAccess,
    __out PNTSTATUS AccessStatus
    );

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
BOOLEAN
SePrivilegeCheck(
    __inout PPRIVILEGE_SET RequiredPrivileges,
    __in PSECURITY_SUBJECT_CONTEXT SubjectSecurityContext,
    __in KPROCESSOR_MODE AccessMode
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
SeFreePrivileges(
    __in PPRIVILEGE_SET Privileges
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
SeOpenObjectAuditAlarm (
    __in PUNICODE_STRING ObjectTypeName,
    __in_opt PVOID Object,
    __in_opt PUNICODE_STRING AbsoluteObjectName,
    __in PSECURITY_DESCRIPTOR SecurityDescriptor,
    __in PACCESS_STATE AccessState,
    __in BOOLEAN ObjectCreated,
    __in BOOLEAN AccessGranted,
    __in KPROCESSOR_MODE AccessMode,
    __out PBOOLEAN GenerateOnClose
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
NTKERNELAPI
VOID
SeOpenObjectAuditAlarmWithTransaction (
    __in PUNICODE_STRING ObjectTypeName,
    __in_opt PVOID Object,
    __in_opt PUNICODE_STRING AbsoluteObjectName,
    __in PSECURITY_DESCRIPTOR SecurityDescriptor,
    __in PACCESS_STATE AccessState,
    __in BOOLEAN ObjectCreated,
    __in BOOLEAN AccessGranted,
    __in KPROCESSOR_MODE AccessMode,
    __in_opt GUID *TransactionId,
    __out PBOOLEAN GenerateOnClose
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
SeOpenObjectForDeleteAuditAlarm (
    __in PUNICODE_STRING ObjectTypeName,
    __in_opt PVOID Object,
    __in_opt PUNICODE_STRING AbsoluteObjectName,
    __in PSECURITY_DESCRIPTOR SecurityDescriptor,
    __in PACCESS_STATE AccessState,
    __in BOOLEAN ObjectCreated,
    __in BOOLEAN AccessGranted,
    __in KPROCESSOR_MODE AccessMode,
    __out PBOOLEAN GenerateOnClose
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
NTKERNELAPI
VOID
SeOpenObjectForDeleteAuditAlarmWithTransaction (
    __in PUNICODE_STRING ObjectTypeName,
    __in_opt PVOID Object,
    __in_opt PUNICODE_STRING AbsoluteObjectName,
    __in PSECURITY_DESCRIPTOR SecurityDescriptor,
    __in PACCESS_STATE AccessState,
    __in BOOLEAN ObjectCreated,
    __in BOOLEAN AccessGranted,
    __in KPROCESSOR_MODE AccessMode,
    __in_opt GUID *TransactionId,
    __out PBOOLEAN GenerateOnClose
    );

NTKERNELAPI
VOID
SeExamineSacl(
    __in PACL Sacl,
    __in PACCESS_TOKEN Token,
    __in ACCESS_MASK DesiredAccess,
    __in BOOLEAN AccessGranted,
    __out PBOOLEAN GenerateAudit,
    __out PBOOLEAN GenerateAlarm
    );

#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
SeDeleteObjectAuditAlarm(
    __in PVOID Object,
    __in HANDLE Handle
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
NTKERNELAPI
VOID
SeDeleteObjectAuditAlarmWithTransaction(
    __in PVOID Object,
    __in HANDLE Handle,
    __in_opt GUID *TransactionId
    );



#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)              
NTKERNELAPI                                     
TOKEN_TYPE                                      
SeTokenType(                                    
    __in PACCESS_TOKEN Token                    
    );                                          
#endif                                          
#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
BOOLEAN
SeTokenIsAdmin(
    __in PACCESS_TOKEN Token
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
BOOLEAN
SeTokenIsRestricted(
    __in PACCESS_TOKEN Token
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA || (NTDDI_VERSION >= NTDDI_WINXPSP2 && NTDDI_VERSION < NTDDI_WS03))
NTKERNELAPI
BOOLEAN
SeTokenIsWriteRestricted(
    __in PACCESS_TOKEN Token
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
NTKERNELAPI
NTSTATUS
SeFilterToken (
    __in PACCESS_TOKEN ExistingToken,
    __in ULONG Flags,
    __in_opt PTOKEN_GROUPS SidsToDisable,
    __in_opt PTOKEN_PRIVILEGES PrivilegesToDelete,
    __in_opt PTOKEN_GROUPS RestrictedSids,
    __deref_out PACCESS_TOKEN * FilteredToken
    );
#endif

// begin_ntosp
#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
SeQueryAuthenticationIdToken(
    __in PACCESS_TOKEN Token,
    __out PLUID AuthenticationId
    );
#endif

// end_ntosp

// begin_ntosp
#if (NTDDI_VERSION >= NTDDI_VISTA)
NTKERNELAPI
VOID
SeQueryTokenIntegrity(
    __in PACCESS_TOKEN Token,
    __inout PSID_AND_ATTRIBUTES IntegritySA
    );
#endif
// end_ntosp

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
SeQuerySessionIdToken(
    __in PACCESS_TOKEN Token,
    __out PULONG SessionId
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
NTKERNELAPI
NTSTATUS
SeSetSessionIdToken(
    __in PACCESS_TOKEN Token,
    __in ULONG SessionId
    );
#endif

// begin_ntosp
#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
SeCreateClientSecurity (
    __in PETHREAD ClientThread,
    __in PSECURITY_QUALITY_OF_SERVICE ClientSecurityQos,
    __in BOOLEAN RemoteSession,
    __out PSECURITY_CLIENT_CONTEXT ClientContext
    );
#endif
// end_ntosp

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
SeImpersonateClient(
    __in PSECURITY_CLIENT_CONTEXT ClientContext,
    __in_opt PETHREAD ServerThread
    );
#endif

// begin_ntosp
#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
SeImpersonateClientEx(
    __in PSECURITY_CLIENT_CONTEXT ClientContext,
    __in_opt PETHREAD ServerThread
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
SeCreateClientSecurityFromSubjectContext (
    __in PSECURITY_SUBJECT_CONTEXT SubjectContext,
    __in PSECURITY_QUALITY_OF_SERVICE ClientSecurityQos,
    __in BOOLEAN ServerIsRemote,
    __out PSECURITY_CLIENT_CONTEXT ClientContext
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
SeQuerySecurityDescriptorInfo (
    __in PSECURITY_INFORMATION SecurityInformation,
    __out_bcount(*Length) PSECURITY_DESCRIPTOR SecurityDescriptor,
    __inout PULONG Length,
    __deref_inout PSECURITY_DESCRIPTOR *ObjectsSecurityDescriptor
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
SeSetSecurityDescriptorInfo (
    __in_opt PVOID Object,
    __in PSECURITY_INFORMATION SecurityInformation,
    __in PSECURITY_DESCRIPTOR ModificationDescriptor,
    __inout PSECURITY_DESCRIPTOR *ObjectsSecurityDescriptor,
    __in POOL_TYPE PoolType,
    __in PGENERIC_MAPPING GenericMapping
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
SeSetSecurityDescriptorInfoEx (
    __in_opt PVOID Object,
    __in PSECURITY_INFORMATION SecurityInformation,
    __in PSECURITY_DESCRIPTOR ModificationDescriptor,
    __inout PSECURITY_DESCRIPTOR *ObjectsSecurityDescriptor,
    __in ULONG AutoInheritFlags,
    __in POOL_TYPE PoolType,
    __in PGENERIC_MAPPING GenericMapping
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
SeAppendPrivileges(
    __inout PACCESS_STATE AccessState,
    __in PPRIVILEGE_SET Privileges
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
NTKERNELAPI
VOID
SeAuditHardLinkCreation(
    __in __in PUNICODE_STRING FileName,
    __in __in PUNICODE_STRING LinkName,
    __in __in BOOLEAN bSuccess
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
NTKERNELAPI
VOID
SeAuditHardLinkCreationWithTransaction(
    __in PUNICODE_STRING FileName,
    __in PUNICODE_STRING LinkName,
    __in BOOLEAN bSuccess,
    __in_opt GUID *TransactionId
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
NTKERNELAPI
VOID
SeAuditTransactionStateChange(
    __in GUID *TransactionId,
    __in GUID *ResourceManagerId,
    __in ULONG NewTransactionState
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
BOOLEAN
SeAuditingFileEvents(
    __in BOOLEAN AccessGranted,
    __in PSECURITY_DESCRIPTOR SecurityDescriptor
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXPSP2)
NTKERNELAPI
BOOLEAN
SeAuditingFileEventsWithContext(
    __in BOOLEAN AccessGranted,
    __in PSECURITY_DESCRIPTOR SecurityDescriptor,
    __in_opt PSECURITY_SUBJECT_CONTEXT SubjectSecurityContext
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
NTKERNELAPI
BOOLEAN
SeAuditingAnyFileEventsWithContext(
     __in PSECURITY_DESCRIPTOR SecurityDescriptor,
    __in_opt PSECURITY_SUBJECT_CONTEXT SubjectSecurityContext
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2KSP3)
NTKERNELAPI
BOOLEAN
SeAuditingHardLinkEvents(
    __in BOOLEAN AccessGranted,
    __in PSECURITY_DESCRIPTOR SecurityDescriptor
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXPSP2)
NTKERNELAPI
BOOLEAN
SeAuditingHardLinkEventsWithContext(
    __in BOOLEAN AccessGranted,
    __in PSECURITY_DESCRIPTOR SecurityDescriptor,
    __in_opt PSECURITY_SUBJECT_CONTEXT SubjectSecurityContext
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
BOOLEAN
SeAuditingFileOrGlobalEvents(
    __in BOOLEAN AccessGranted,
    __in PSECURITY_DESCRIPTOR SecurityDescriptor,
    __in PSECURITY_SUBJECT_CONTEXT SubjectSecurityContext
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
VOID
SeSetAccessStateGenericMapping (
    __inout PACCESS_STATE AccessState,
    __in PGENERIC_MAPPING GenericMapping
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
SeRegisterLogonSessionTerminatedRoutine(
    __in PSE_LOGON_SESSION_TERMINATED_ROUTINE CallbackRoutine
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
SeUnregisterLogonSessionTerminatedRoutine(
    __in PSE_LOGON_SESSION_TERMINATED_ROUTINE CallbackRoutine
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
SeMarkLogonSessionForTerminationNotification(
    __in PLUID LogonId
    );
#endif

// begin_ntosp

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
SeQueryInformationToken (
    __in PACCESS_TOKEN Token,
    __in TOKEN_INFORMATION_CLASS TokenInformationClass,
    __deref_out PVOID *TokenInformation
    );
#endif


NTSTATUS
SeLocateProcessImageName(
    __inout PEPROCESS Process,
    __deref_out PUNICODE_STRING *pImageFileName
    );

//
//  Grants access to SeExports structure
//

extern NTKERNELAPI PSE_EXPORTS SeExports;


#if (NTDDI_VERSION >= NTDDI_WIN7)

NTKERNELAPI
VOID
SeExamineGlobalSacl(
    __in PUNICODE_STRING ObjectType,
    __in PACCESS_TOKEN Token,
    __in ACCESS_MASK DesiredAccess,
    __in BOOLEAN AccessGranted,
    __inout PBOOLEAN GenerateAudit,
    __inout_opt PBOOLEAN GenerateAlarm
);

NTKERNELAPI
VOID
SeMaximumAuditMaskFromGlobalSacl(
    __in_opt PUNICODE_STRING ObjectTypeName,
    __in ACCESS_MASK GrantedAccess,
    __in PACCESS_TOKEN Token,
    __inout PACCESS_MASK AuditMask
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
// Security Support
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
NTSTATUS
PsAssignImpersonationToken(
    __in PETHREAD Thread,
    __in_opt HANDLE Token
    );
#endif

// begin_ntosp

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
PACCESS_TOKEN
PsReferencePrimaryToken (
    __inout PEPROCESS Process
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
VOID
PsDereferencePrimaryToken(
    __in PACCESS_TOKEN PrimaryToken
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
VOID
PsDereferenceImpersonationToken(
    __in PACCESS_TOKEN ImpersonationToken
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
PACCESS_TOKEN
PsReferenceImpersonationToken(
    __inout PETHREAD Thread,
    __out PBOOLEAN CopyOnOpen,
    __out PBOOLEAN EffectiveOnly,
    __out PSECURITY_IMPERSONATION_LEVEL ImpersonationLevel
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
LARGE_INTEGER
PsGetProcessExitTime(
    VOID
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
BOOLEAN
PsIsThreadTerminating(
    __in PETHREAD Thread
    );
#endif

// begin_ntosp

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
NTSTATUS
PsImpersonateClient(
    __inout PETHREAD Thread,
    __in PACCESS_TOKEN Token,
    __in BOOLEAN CopyOnOpen,
    __in BOOLEAN EffectiveOnly,
    __in SECURITY_IMPERSONATION_LEVEL ImpersonationLevel
    );
#endif

// end_ntosp

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
BOOLEAN
PsDisableImpersonation(
    __inout PETHREAD Thread,
    __inout PSE_IMPERSONATION_STATE ImpersonationState
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
VOID
PsRestoreImpersonation(
    __inout PETHREAD Thread,
    __in PSE_IMPERSONATION_STATE ImpersonationState
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
VOID
PsRevertToSelf(
    VOID
    );
#endif


__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
NTSTATUS
PsLookupProcessByProcessId(
    __in HANDLE ProcessId,
    __deref_out PEPROCESS *Process
    );

__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
NTSTATUS
PsLookupThreadByThreadId(
    __in HANDLE ThreadId,
    __deref_out PETHREAD *Thread
    );

//
// Quota Operations
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
PsChargePoolQuota (
    __in PEPROCESS Process,
    __in POOL_TYPE PoolType,
    __in ULONG_PTR Amount
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
NTSTATUS
PsChargeProcessPoolQuota (
    __in PEPROCESS Process,
    __in POOL_TYPE PoolType,
    __in ULONG_PTR Amount
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)

__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
PsReturnPoolQuota(
    __in PEPROCESS Process,
    __in POOL_TYPE PoolType,
    __in ULONG_PTR Amount
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)  
NTKERNELAPI                         
BOOLEAN                             
PsIsSystemThread(                   
    __in PETHREAD Thread            
    );                              
#endif                              

#define IO_OPEN_PAGING_FILE             0x0002
#define IO_OPEN_TARGET_DIRECTORY        0x0004

#define IO_STOP_ON_SYMLINK              0x0008


#define IO_MM_PAGING_FILE               0x0010


//
// Define driver FS notification change routine type.
//

typedef
VOID
DRIVER_FS_NOTIFICATION (
    __in struct _DEVICE_OBJECT *DeviceObject,
    __in BOOLEAN FsActive
    );

typedef DRIVER_FS_NOTIFICATION *PDRIVER_FS_NOTIFICATION;


//
//  Valid values for FS_FILTER_PARAMETERS.AcquireForSectionSynchronization.SyncType
//

typedef enum _FS_FILTER_SECTION_SYNC_TYPE {
    SyncTypeOther = 0,
    SyncTypeCreateSection
} FS_FILTER_SECTION_SYNC_TYPE, *PFS_FILTER_SECTION_SYNC_TYPE;

//
//  Valid values for FS_FILTER_PARAMETERS.NotifyStreamFileObject.NotificationType
//

typedef enum _FS_FILTER_STREAM_FO_NOTIFICATION_TYPE {
    NotifyTypeCreate = 0,
    NotifyTypeRetired
} FS_FILTER_STREAM_FO_NOTIFICATION_TYPE, *PFS_FILTER_STREAM_FO_NOTIFICATION_TYPE;

//
//  Parameters union for the operations that
//  are exposed to the filters through the
//  FsFilterCallbacks registration mechanism.
//

#if _MSC_VER >= 1200
#pragma warning(push)
#pragma warning(disable:4324) // structure was padded due to __declspec(align())
#endif

typedef union _FS_FILTER_PARAMETERS {

    //
    //  AcquireForModifiedPageWriter
    //

    struct {
        PLARGE_INTEGER EndingOffset;
        PERESOURCE *ResourceToRelease;
    } AcquireForModifiedPageWriter;

    //
    //  ReleaseForModifiedPageWriter
    //

    struct {
        PERESOURCE ResourceToRelease;
    } ReleaseForModifiedPageWriter;

    //
    //  AcquireForSectionSynchronization
    //

    struct {
        FS_FILTER_SECTION_SYNC_TYPE SyncType;
        ULONG PageProtection;
    } AcquireForSectionSynchronization;

    //
    //  NotifyStreamFileObjectCreation
    //

    struct {
        FS_FILTER_STREAM_FO_NOTIFICATION_TYPE NotificationType;
        BOOLEAN POINTER_ALIGNMENT SafeToRecurse;
    } NotifyStreamFileObject;

    //
    //  Other
    //

    struct {
        PVOID Argument1;
        PVOID Argument2;
        PVOID Argument3;
        PVOID Argument4;
        PVOID Argument5;
    } Others;

} FS_FILTER_PARAMETERS, *PFS_FILTER_PARAMETERS;

#if _MSC_VER >= 1200
#pragma warning(pop)
#endif

//
//  These are the valid values for the Operation field
//  of the FS_FILTER_CALLBACK_DATA structure.
//

#define FS_FILTER_ACQUIRE_FOR_SECTION_SYNCHRONIZATION      (UCHAR)-1
#define FS_FILTER_RELEASE_FOR_SECTION_SYNCHRONIZATION      (UCHAR)-2
#define FS_FILTER_ACQUIRE_FOR_MOD_WRITE                    (UCHAR)-3
#define FS_FILTER_RELEASE_FOR_MOD_WRITE                    (UCHAR)-4
#define FS_FILTER_ACQUIRE_FOR_CC_FLUSH                     (UCHAR)-5
#define FS_FILTER_RELEASE_FOR_CC_FLUSH                     (UCHAR)-6

typedef struct _FS_FILTER_CALLBACK_DATA {

    ULONG SizeOfFsFilterCallbackData;
    UCHAR Operation;
    UCHAR Reserved;

    struct _DEVICE_OBJECT *DeviceObject;
    struct _FILE_OBJECT *FileObject;

    FS_FILTER_PARAMETERS Parameters;

} FS_FILTER_CALLBACK_DATA, *PFS_FILTER_CALLBACK_DATA;

//
//  Prototype for the callbacks received before an operation
//  is passed to the base file system.
//
//  A filter can fail this operation, but consistant failure
//  will halt system progress.
//

typedef
NTSTATUS
(*PFS_FILTER_CALLBACK) (
    __in PFS_FILTER_CALLBACK_DATA Data,
    __out PVOID *CompletionContext
    );

//
//  Prototype for the completion callback received after an
//  operation is completed.
//

typedef
VOID
(*PFS_FILTER_COMPLETION_CALLBACK) (
    __in PFS_FILTER_CALLBACK_DATA Data,
    __in NTSTATUS OperationStatus,
    __in PVOID CompletionContext
    );

//
//  This is the structure that the file system filter fills in to
//  receive notifications for these locking operations.
//
//  A filter should set the field to NULL for any notification callback
//  it doesn't wish to receive.
//

typedef struct _FS_FILTER_CALLBACKS {

    ULONG SizeOfFsFilterCallbacks;
    ULONG Reserved; //  For alignment

    PFS_FILTER_CALLBACK PreAcquireForSectionSynchronization;
    PFS_FILTER_COMPLETION_CALLBACK PostAcquireForSectionSynchronization;
    PFS_FILTER_CALLBACK PreReleaseForSectionSynchronization;
    PFS_FILTER_COMPLETION_CALLBACK PostReleaseForSectionSynchronization;
    PFS_FILTER_CALLBACK PreAcquireForCcFlush;
    PFS_FILTER_COMPLETION_CALLBACK PostAcquireForCcFlush;
    PFS_FILTER_CALLBACK PreReleaseForCcFlush;
    PFS_FILTER_COMPLETION_CALLBACK PostReleaseForCcFlush;
    PFS_FILTER_CALLBACK PreAcquireForModifiedPageWriter;
    PFS_FILTER_COMPLETION_CALLBACK PostAcquireForModifiedPageWriter;
    PFS_FILTER_CALLBACK PreReleaseForModifiedPageWriter;
    PFS_FILTER_COMPLETION_CALLBACK PostReleaseForModifiedPageWriter;

} FS_FILTER_CALLBACKS, *PFS_FILTER_CALLBACKS;

#if (NTDDI_VERSION >= NTDDI_WINXP)
NTKERNELAPI
NTSTATUS
FsRtlRegisterFileSystemFilterCallbacks (
    __in struct _DRIVER_OBJECT *FilterDriverObject,
    __in PFS_FILTER_CALLBACKS Callbacks
    );
#endif // NTDDI_VERSION >= NTDDI_WINXP

#if (NTDDI_VERSION >= NTDDI_VISTA)
NTKERNELAPI
NTSTATUS
FsRtlNotifyStreamFileObject (
    __in struct _FILE_OBJECT * StreamFileObject,
    __in_opt struct _DEVICE_OBJECT *DeviceObjectHint,
    __in FS_FILTER_STREAM_FO_NOTIFICATION_TYPE NotificationType,
    __in BOOLEAN SafeToRecurse
    );
#endif // NTDDI_VERSION >= NTDDI_VISTA

#define DO_VERIFY_VOLUME                    0x00000002      
#define DO_BUFFERED_IO                      0x00000004      
#define DO_EXCLUSIVE                        0x00000008      
#define DO_DIRECT_IO                        0x00000010      
#define DO_MAP_IO_BUFFER                    0x00000020      
#define DO_DEVICE_HAS_NAME                  0x00000040      
#define DO_DEVICE_INITIALIZING              0x00000080      
#define DO_SYSTEM_BOOT_PARTITION            0x00000100      
#define DO_LONG_TERM_REQUESTS               0x00000200      
#define DO_NEVER_LAST_DEVICE                0x00000400      
#define DO_SHUTDOWN_REGISTERED              0x00000800      
#define DO_BUS_ENUMERATED_DEVICE            0x00001000      
#define DO_POWER_PAGABLE                    0x00002000      
#define DO_POWER_INRUSH                     0x00004000      
#define DO_LOW_PRIORITY_FILESYSTEM          0x00010000      
#define DO_SUPPORTS_TRANSACTIONS            0x00040000      
#define DO_FORCE_NEITHER_IO                 0x00080000      
#define DO_VOLUME_DEVICE_OBJECT             0x00100000      
#define DO_SYSTEM_SYSTEM_PARTITION          0x00200000      
#define DO_SYSTEM_CRITICAL_PARTITION        0x00400000      
#define DO_DISALLOW_EXECUTE                 0x00800000      

//
// The following are global counters used by the I/O system to indicate the
// amount of I/O being performed in the system.  The first three counters
// are just that, counts of operations that have been requested, while the
// last three counters track the amount of data transferred for each type
// of I/O request.
//

extern KSPIN_LOCK IoStatisticsLock;
extern ULONG IoReadOperationCount;
extern ULONG IoWriteOperationCount;
extern ULONG IoOtherOperationCount;
extern LARGE_INTEGER IoReadTransferCount;
extern LARGE_INTEGER IoWriteTransferCount;
extern LARGE_INTEGER IoOtherTransferCount;

//
// It is difficult for cached file systems to properly charge quota
// for the storage that they allocate on behalf of user file handles,
// so the following amount of additional quota is charged against each
// handle as a "best guess" as to the amount of quota the file system
// will allocate on behalf of this handle.
//

//
// These numbers are totally arbitrary, and can be changed if it turns out
// that the file systems actually allocate more (or less) on behalf of
// their file objects.  The non-paged pool charge constant is added to the
// size of a FILE_OBJECT to get the actual charge amount.
//

#define IO_FILE_OBJECT_NON_PAGED_POOL_CHARGE    64
#define IO_FILE_OBJECT_PAGED_POOL_CHARGE        1024



#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
IoAcquireVpbSpinLock(
    __out PKIRQL Irql
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
IoCheckDesiredAccess(
    __inout PACCESS_MASK DesiredAccess,
    __in ACCESS_MASK GrantedAccess
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
IoCheckEaBufferValidity(
    __in  PFILE_FULL_EA_INFORMATION EaBuffer,
    __in  ULONG EaLength,
    __out PULONG ErrorOffset
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
IoCheckFunctionAccess(
    __in ACCESS_MASK GrantedAccess,
    __in UCHAR MajorFunction,
    __in UCHAR MinorFunction,
    __in ULONG IoControlCode,
    __in_opt PVOID Arg1,
    __in_opt PVOID Arg2
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
IoCheckQuerySetFileInformation(
    __in FILE_INFORMATION_CLASS FileInformationClass,
    __in ULONG Length,
    __in BOOLEAN SetOperation
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
IoCheckQuerySetVolumeInformation(
    __in FS_INFORMATION_CLASS FsInformationClass,
    __in ULONG Length,
    __in BOOLEAN SetOperation
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
IoCheckQuotaBufferValidity(
    __in  PFILE_QUOTA_INFORMATION QuotaBuffer,
    __in  ULONG QuotaLength,
    __out PULONG ErrorOffset
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
PFILE_OBJECT
IoCreateStreamFileObject(
    __in_opt PFILE_OBJECT FileObject,
    __in_opt PDEVICE_OBJECT DeviceObject
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
NTKERNELAPI
PFILE_OBJECT
IoCreateStreamFileObjectEx(
    __in_opt  PFILE_OBJECT FileObject,
    __in_opt  PDEVICE_OBJECT DeviceObject,
    __out_opt PHANDLE FileObjectHandle
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
PFILE_OBJECT
IoCreateStreamFileObjectLite(
    __in_opt PFILE_OBJECT FileObject,
    __in_opt PDEVICE_OBJECT DeviceObject
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
BOOLEAN
IoFastQueryNetworkAttributes(
    __in  POBJECT_ATTRIBUTES ObjectAttributes,
    __in  ACCESS_MASK DesiredAccess,
    __in  ULONG OpenOptions,
    __out PIO_STATUS_BLOCK IoStatus,
    __out PFILE_NETWORK_OPEN_INFORMATION Buffer
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
IoPageRead(
    __in  PFILE_OBJECT FileObject,
    __in  PMDL MemoryDescriptorList,
    __in  PLARGE_INTEGER StartingOffset,
    __in  PKEVENT Event,
    __out PIO_STATUS_BLOCK IoStatusBlock
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
PDEVICE_OBJECT
IoGetAttachedDevice(
    __in PDEVICE_OBJECT DeviceObject
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)          // wdm
NTKERNELAPI                                 // wdm
PDEVICE_OBJECT                              // wdm
__drv_maxIRQL(DISPATCH_LEVEL)               // wdm
IoGetAttachedDeviceReference(               // wdm
    __in PDEVICE_OBJECT DeviceObject        // wdm
    );                                      // wdm
#endif                                      // wdm
                                            // wdm
#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
PDEVICE_OBJECT
IoGetBaseFileSystemDeviceObject(
    __in PFILE_OBJECT FileObject
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)          // ntddk
NTKERNELAPI                                 // ntddk ntosp
PCONFIGURATION_INFORMATION                  // ntddk ntosp
__drv_maxIRQL(PASSIVE_LEVEL)                // ntddk ntosp
IoGetConfigurationInformation( VOID );      // ntddk ntosp
#endif                                      // ntddk


#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
ULONG
IoGetRequestorProcessId(
    __in PIRP Irp
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
PEPROCESS
IoGetRequestorProcess(
    __in PIRP Irp
    );
#endif

// begin_wdm

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
PIRP
IoGetTopLevelIrp(
    VOID
    );
#endif


//++
//
// BOOLEAN
// IoIsFileOpenedExclusively(
//     __in PFILE_OBJECT FileObject
//     )
//
// Routine Description:
//
//     This routine is invoked to determine whether the file open represented
//     by the specified file object is opened exclusively.
//
// Arguments:
//
//     FileObject - Pointer to the file object that represents the open instance
//         of the target file to be tested for exclusive access.
//
// Return Value:
//
//     The function value is TRUE if the open instance of the file is exclusive;
//     otherwise FALSE is returned.
//
//--

#define IoIsFileOpenedExclusively( FileObject ) (\
    (BOOLEAN) !((FileObject)->SharedRead || (FileObject)->SharedWrite || (FileObject)->SharedDelete))

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
BOOLEAN
IoIsOperationSynchronous(
    __in PIRP Irp
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
BOOLEAN
IoIsSystemThread(
    __in PETHREAD Thread
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
BOOLEAN
IoIsValidNameGraftingBuffer(
    __in PIRP Irp,
    __in PREPARSE_DATA_BUFFER ReparseBuffer
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WINXP)
NTKERNELAPI
NTSTATUS
IoQueryFileDosDeviceName(
    __in  PFILE_OBJECT FileObject,
    __out POBJECT_NAME_INFORMATION *ObjectNameInformation
    );
#endif

// begin_ntosp
#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
IoQueryFileInformation(
    __in  PFILE_OBJECT FileObject,
    __in  FILE_INFORMATION_CLASS FileInformationClass,
    __in  ULONG Length,
    __out PVOID FileInformation,
    __out PULONG ReturnedLength
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
IoQueryVolumeInformation(
    __in  PFILE_OBJECT FileObject,
    __in  FS_INFORMATION_CLASS FsInformationClass,
    __in  ULONG Length,
    __out PVOID FsInformation,
    __out PULONG ReturnedLength
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
IoQueueThreadIrp(
    __in PIRP Irp
    );
#endif

// end_ntosp

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
IoRegisterFileSystem(
    __in __drv_aliasesMem PDEVICE_OBJECT DeviceObject
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
IoRegisterFsRegistrationChange(
    __in PDRIVER_OBJECT DriverObject,
    __in PDRIVER_FS_NOTIFICATION DriverNotificationRoutine
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
NTKERNELAPI
NTSTATUS
IoRegisterFsRegistrationChangeMountAware(
    __in PDRIVER_OBJECT DriverObject,
    __in PDRIVER_FS_NOTIFICATION DriverNotificationRoutine,
    __in BOOLEAN SynchronizeWithMounts
    );
#endif

#if (NTDDI_VERSION == NTDDI_WIN2K)
//  This API only exists in W2K, it does not exist in any later OS
NTKERNELAPI
NTSTATUS
IoRegisterFsRegistrationChangeEx(
    __in PDRIVER_OBJECT DriverObject,
    __in PDRIVER_FS_NOTIFICATION DriverNotificationRoutine
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
NTKERNELAPI
NTSTATUS
IoEnumerateRegisteredFiltersList(
    __out_bcount_part_opt(DriverObjectListSize,(*ActualNumberDriverObjects)*sizeof(PDRIVER_OBJECT)) PDRIVER_OBJECT *DriverObjectList,
    __in  ULONG  DriverObjectListSize,          //in bytes
    __out PULONG ActualNumberDriverObjects      //in elements
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
NTKERNELAPI
NTSTATUS
IoReplaceFileObjectName (
    __in PFILE_OBJECT FileObject,
    __in_bcount(FileNameLength) PWSTR NewFileName,
    __in USHORT FileNameLength
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
IoReleaseVpbSpinLock(
    __in KIRQL Irql
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
IoSetDeviceToVerify(
    __in PETHREAD Thread,
    __in_opt PDEVICE_OBJECT DeviceObject
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
IoSetInformation(
    __in PFILE_OBJECT FileObject,
    __in FILE_INFORMATION_CLASS FileInformationClass,
    __in ULONG Length,
    __in PVOID FileInformation
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
IoSetTopLevelIrp(
    __in_opt PIRP Irp
    );
#endif


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

// end_wdm end_ntosp
// begin_ntifs

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
IoSynchronousPageWrite(
    __in  PFILE_OBJECT FileObject,
    __in  PMDL MemoryDescriptorList,
    __in  PLARGE_INTEGER StartingOffset,
    __in  PKEVENT Event,
    __out PIO_STATUS_BLOCK IoStatusBlock
    );
#endif

// begin_ntosp

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
PEPROCESS
IoThreadToProcess(
    __in PETHREAD Thread
    );
#endif
// end_ntosp

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
IoUnregisterFileSystem(
    __in PDEVICE_OBJECT DeviceObject
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
IoUnregisterFsRegistrationChange(
    __in PDRIVER_OBJECT DriverObject,
    __in PDRIVER_FS_NOTIFICATION DriverNotificationRoutine
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
IoVerifyVolume(
    __in PDEVICE_OBJECT DeviceObject,
    __in BOOLEAN AllowRawMount
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)              // wdm
NTKERNELAPI                                     // wdm
VOID                                            // wdm
__drv_maxIRQL(DISPATCH_LEVEL)                   // wdm
IoWriteErrorLogEntry(                           // wdm
    __in PVOID ElEntry                          // wdm
    );                                          // wdm
#endif                                          // wdm


#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
IoGetRequestorSessionId(
    __in  PIRP Irp,
    __out PULONG pSessionId
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WINXP)
NTKERNELAPI
NTSTATUS
IoEnumerateDeviceObjectList(
    __in  PDRIVER_OBJECT DriverObject,
    __out_bcount_part_opt(DeviceObjectListSize,(*ActualNumberDeviceObjects)*sizeof(PDEVICE_OBJECT)) PDEVICE_OBJECT *DeviceObjectList,
    __in  ULONG          DeviceObjectListSize,
    __out PULONG         ActualNumberDeviceObjects
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
NTKERNELAPI
PDEVICE_OBJECT
IoGetLowerDeviceObject(
    __in  PDEVICE_OBJECT  DeviceObject
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
NTKERNELAPI
PDEVICE_OBJECT
IoGetDeviceAttachmentBaseRef(
    __in PDEVICE_OBJECT DeviceObject
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
NTKERNELAPI
NTSTATUS
IoGetDiskDeviceObject(
    __in  PDEVICE_OBJECT FileSystemDeviceObject,
    __out PDEVICE_OBJECT *DiskDeviceObject
    );
#endif


//
//  IoPrioirityHint support
//

#if (NTDDI_VERSION >= NTDDI_VISTA)
typedef struct _IO_PRIORITY_INFO {
    ULONG Size;
    ULONG ThreadPriority;
    ULONG PagePriority;
    IO_PRIORITY_HINT IoPriority;
} IO_PRIORITY_INFO, *PIO_PRIORITY_INFO;
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
VOID
FORCEINLINE
IoInitializePriorityInfo(
    __in PIO_PRIORITY_INFO PriorityInfo
    )
{
    PriorityInfo->Size = sizeof(IO_PRIORITY_INFO);
    PriorityInfo->ThreadPriority = 0xffff;
    PriorityInfo->IoPriority = IoPriorityNormal;
    PriorityInfo->PagePriority = 0;
}
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


// Used for queuing work items to be performed at shutdown time.  Same
// rules apply as per Ex work queues.
#if (NTDDI_VERSION >= NTDDI_WINXP)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
NTSTATUS
PoQueueShutdownWorkItem( 
    __inout __drv_aliasesMem PWORK_QUEUE_ITEM WorkItem
    );
#endif

#if defined(_IA64_)                             
                                                
#if (NTDDI_VERSION >= NTDDI_WIN2K)
DECLSPEC_DEPRECATED_DDK                 // Use GetDmaRequirement
__drv_preferredFunction("GetDmaAlignment", "Obsolete")
NTHALAPI
ULONG
HalGetDmaAlignmentRequirement (
    VOID
    );
#endif

#endif                                          
                                                
#if defined(_M_IX86) || defined(_M_AMD64)       
                                                
#define HalGetDmaAlignmentRequirement() 1L      
#endif                                          
                                                

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
BOOLEAN
MmIsRecursiveIoFault (
    VOID
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL (APC_LEVEL)
NTKERNELAPI
BOOLEAN
MmForceSectionClosed (
    __in PSECTION_OBJECT_POINTERS SectionObjectPointer,
    __in BOOLEAN DelayClose
    );
#endif


typedef enum _MMFLUSH_TYPE {
    MmFlushForDelete,
    MmFlushForWrite
} MMFLUSH_TYPE;

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL (APC_LEVEL)
NTKERNELAPI
BOOLEAN
MmFlushImageSection (
    __in PSECTION_OBJECT_POINTERS SectionObjectPointer,
    __in MMFLUSH_TYPE FlushType
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL (APC_LEVEL)
NTKERNELAPI
BOOLEAN
MmCanFileBeTruncated (
    __in PSECTION_OBJECT_POINTERS SectionPointer,
    __in_opt PLARGE_INTEGER NewFileSize
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL (APC_LEVEL)
NTKERNELAPI
BOOLEAN
MmSetAddressRangeModified (
    __in_bcount (Length) PVOID Address,
    __in SIZE_T Length
    );
#endif


//
// Prefetch public interface.
//

typedef struct _READ_LIST {
    PFILE_OBJECT FileObject;
    ULONG NumberOfEntries;
    LOGICAL IsImage;
    FILE_SEGMENT_ELEMENT List[ANYSIZE_ARRAY];
} READ_LIST, *PREAD_LIST;

#if (NTDDI_VERSION >= NTDDI_WINXP)
typedef union _MM_PREFETCH_FLAGS {
    struct {
        ULONG Priority : SYSTEM_PAGE_PRIORITY_BITS;
        ULONG RepurposePriority : SYSTEM_PAGE_PRIORITY_BITS;
    } Flags;
    ULONG AllFlags;

} MM_PREFETCH_FLAGS, *PMM_PREFETCH_FLAGS;

#define MM_PREFETCH_FLAGS_MASK  ((1 << (2*SYSTEM_PAGE_PRIORITY_BITS)) - 1)

__drv_maxIRQL (PASSIVE_LEVEL)
NTKERNELAPI
NTSTATUS
MmPrefetchPages (
    __in ULONG NumberOfLists,
    __in_ecount (NumberOfLists) PREAD_LIST *ReadLists
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
//
//  This routine is used by local file systems to detect  the case where the
//  user has closed the file handles and the section handles, but still has
//  open writable views to the file
//

__drv_maxIRQL (APC_LEVEL)
NTKERNELAPI
ULONG
MmDoesFileHaveUserWritableReferences (
    __in PSECTION_OBJECT_POINTERS SectionPointer
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
ObInsertObject(
    __in PVOID Object,
    __inout_opt PACCESS_STATE PassedAccessState,
    __in_opt ACCESS_MASK DesiredAccess,
    __in ULONG ObjectPointerBias,
    __out_opt PVOID *NewObject,
    __out_opt PHANDLE Handle
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
ObOpenObjectByPointer(
    __in PVOID Object,
    __in ULONG HandleAttributes,
    __in_opt PACCESS_STATE PassedAccessState,
    __in ACCESS_MASK DesiredAccess,
    __in_opt POBJECT_TYPE ObjectType,
    __in KPROCESSOR_MODE AccessMode,
    __out PHANDLE Handle
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
NTKERNELAPI
NTSTATUS
ObOpenObjectByPointerWithTag(
    __in PVOID Object,
    __in ULONG HandleAttributes,
    __in_opt PACCESS_STATE PassedAccessState,
    __in ACCESS_MASK DesiredAccess,
    __in_opt POBJECT_TYPE ObjectType,
    __in KPROCESSOR_MODE AccessMode,
    __in ULONG Tag,
    __out PHANDLE Handle
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
ObMakeTemporaryObject(
    __in PVOID Object
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
ObQueryNameString(
    __in PVOID Object,
    __out_bcount_opt(Length) POBJECT_NAME_INFORMATION ObjectNameInfo,
    __in ULONG Length,
    __out PULONG ReturnLength
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
NTKERNELAPI
BOOLEAN
ObIsKernelHandle (
    __in HANDLE Handle
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
ObQueryObjectAuditingByHandle(
    __in HANDLE Handle,
    __out PBOOLEAN GenerateOnClose
    );
#endif


//
//  The following are globally used definitions for an LBN and a VBN
//

typedef ULONG LBN;
typedef LBN *PLBN;

typedef ULONG VBN;
typedef VBN *PVBN;


//
//  Every file system that uses the cache manager must have FsContext
//  of the file object point to a common fcb header structure.
//

typedef enum _FAST_IO_POSSIBLE {
    FastIoIsNotPossible = 0,
    FastIoIsPossible,
    FastIoIsQuestionable
} FAST_IO_POSSIBLE;


typedef struct _FSRTL_COMMON_FCB_HEADER {

    CSHORT NodeTypeCode;
    CSHORT NodeByteSize;

    //
    //  General flags available to FsRtl.
    //

    UCHAR Flags;

    //
    //  Indicates if fast I/O is possible or if we should be calling
    //  the check for fast I/O routine which is found via the driver
    //  object.
    //

    UCHAR IsFastIoPossible; // really type FAST_IO_POSSIBLE

    //
    //  Second Flags Field
    //

    UCHAR Flags2;

    //
    //  The following reserved field should always be 0
    //

    UCHAR Reserved : 4 ;

    //
    //  Indicates the version of this header
    //

    UCHAR Version : 4 ;

    PERESOURCE Resource;

    PERESOURCE PagingIoResource;

    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER FileSize;
    LARGE_INTEGER ValidDataLength;

} FSRTL_COMMON_FCB_HEADER;
typedef FSRTL_COMMON_FCB_HEADER *PFSRTL_COMMON_FCB_HEADER;


//
//  NodeTypeCode values used ranges
//
//  CDFS                    - 0x0300 - 0x033F
//  CLFS                    - 0x0400 - 0x043F
//  WINFS                   - 0x0440 - 0x047F
//  FASTFAT                 - 0x0500 - 0x053F
//  RAW                     - 0x0600 - 0x063F
//  NTFS                    - 0x0700 - 0x07FF
//  UDFS                    - 0x0900 - 0x093F
//  EXFAT                   - 0x0D00 - 0x0D3F
//                          - 0x8000 - 0xBFFF       reserved for 3rd party file systems
//  WIMFilter               - 0x1000 - 0x103F
//  NCFILTER                - 0x2200 - 0x223F       sample minifilter
//  RDBSS                   - 0xEB00 - 0xECFF
//  NULMRX                  - 0xFF00 - 0xFF3F       sample redirector



//
//  This Fcb header is used for files which support caching
//  of compressed data, and related new support.
//
//  We start out by prefixing this structure with the normal
//  FsRtl header from above, which we have to do two different
//  ways for c++ or c.
//

#ifdef __cplusplus
typedef struct _FSRTL_ADVANCED_FCB_HEADER:FSRTL_COMMON_FCB_HEADER {
#else   // __cplusplus

typedef struct _FSRTL_ADVANCED_FCB_HEADER {

    //
    //  Put in the standard FsRtl header fields
    //

    FSRTL_COMMON_FCB_HEADER DUMMYSTRUCTNAME;

#endif  // __cplusplus

    //
    //  The following two fields are supported only if
    //  Flags2 contains FSRTL_FLAG2_SUPPORTS_FILTER_CONTEXTS
    //

    //
    //  This is a pointer to a Fast Mutex which may be used to
    //  properly synchronize access to the FsRtl header.  The
    //  Fast Mutex must be nonpaged.
    //

    PFAST_MUTEX FastMutex;

    //
    // This is a pointer to a list of stream context structures belonging to
    // filesystem filter drivers that are linked above the filesystem.
    // Each structure is headed by FSRTL_FILTER_CONTEXT.
    //

    LIST_ENTRY FilterContexts;


#if (NTDDI_VERSION >= NTDDI_VISTA)
    //
    //  The following fields are valid only if the Version
    //  field in the FSRTL_COMMON_FCB_HEADER is greater than
    //  or equal to FSRTL_FCB_HEADER_V1
    //  These fields are present in VISTA and beyond
    //

    //
    //  This is a pushlock which is used to properly synchronize access
    //  to the list of stream contexts
    //

    EX_PUSH_LOCK PushLock;

    //
    //  This is a pointer to a blob of information that is
    //  associated with the opened file in the filesystem
    //  corresponding to the structure containing this
    //  FSRTL_ADVANCED_FCB_HEADER.
    //

    PVOID* FileContextSupportPointer;
#endif

} FSRTL_ADVANCED_FCB_HEADER;
typedef FSRTL_ADVANCED_FCB_HEADER *PFSRTL_ADVANCED_FCB_HEADER;

//
//  Define FsRtl common header versions
//

#define FSRTL_FCB_HEADER_V0             (0x00)
#define FSRTL_FCB_HEADER_V1             (0x01)


//
//  Define FsRtl common header flags
//

#define FSRTL_FLAG_FILE_MODIFIED        (0x01)
#define FSRTL_FLAG_FILE_LENGTH_CHANGED  (0x02)
#define FSRTL_FLAG_LIMIT_MODIFIED_PAGES (0x04)

//
//  Following flags determine how the modified page writer should
//  acquire the file.  These flags can't change while either resource
//  is acquired.  If neither of these flags is set then the
//  modified/mapped page writer will attempt to acquire the paging io
//  resource shared.
//

#define FSRTL_FLAG_ACQUIRE_MAIN_RSRC_EX (0x08)
#define FSRTL_FLAG_ACQUIRE_MAIN_RSRC_SH (0x10)

//
//  This flag will be set by the Cache Manager if a view is mapped
//  to a file.
//

#define FSRTL_FLAG_USER_MAPPED_FILE     (0x20)

//  This flag indicates that the file system is using the
//  FSRTL_ADVANCED_FCB_HEADER structure instead of the FSRTL_COMMON_FCB_HEADER
//  structure.
//

#define FSRTL_FLAG_ADVANCED_HEADER      (0x40)

//  This flag determines whether there currently is an Eof advance
//  in progress.  All such advances must be serialized.
//

#define FSRTL_FLAG_EOF_ADVANCE_ACTIVE   (0x80)

//
//  Flag values for Flags2
//
//  All unused bits are reserved and should NOT be modified.
//

//
//  If this flag is set, the Cache Manager will allow modified writing
//  in spite of the value of FsContext2.
//

#define FSRTL_FLAG2_DO_MODIFIED_WRITE        (0x01)

//
//  If this flag is set, the additional fields FilterContexts and FastMutex
//  are supported in FSRTL_COMMON_HEADER, and can be used to associate
//  context for filesystem filters with streams.
//

#define FSRTL_FLAG2_SUPPORTS_FILTER_CONTEXTS  (0x02)

//
//  If this flag is set, the cache manager will flush and purge the cache map when
//  a user first maps a file
//

#define FSRTL_FLAG2_PURGE_WHEN_MAPPED (0x04)

//  If set this represents a PAGING file
//

#define FSRTL_FLAG2_IS_PAGING_FILE (0x08)


// begin_ntosp
//
//
//  The following constants are used to block top level Irp processing when
//  (in either the fast io or cc case) file system resources have been
//  acquired above the file system, or we are in an Fsp thread.
//

#define FSRTL_FSP_TOP_LEVEL_IRP         ((LONG_PTR)0x01)
#define FSRTL_CACHE_TOP_LEVEL_IRP       ((LONG_PTR)0x02)
#define FSRTL_MOD_WRITE_TOP_LEVEL_IRP   ((LONG_PTR)0x03)
#define FSRTL_FAST_IO_TOP_LEVEL_IRP     ((LONG_PTR)0x04)
#define FSRTL_NETWORK1_TOP_LEVEL_IRP    ((LONG_PTR)0x05)
#define FSRTL_NETWORK2_TOP_LEVEL_IRP    ((LONG_PTR)0x06)
#define FSRTL_MAX_TOP_LEVEL_IRP_FLAG    ((LONG_PTR)0xFFFF)

// end_ntosp

//
//  The following structure is used to synchronize Eof extends.
//

typedef struct _EOF_WAIT_BLOCK {

    LIST_ENTRY EofWaitLinks;
    KEVENT Event;

} EOF_WAIT_BLOCK;

typedef EOF_WAIT_BLOCK *PEOF_WAIT_BLOCK;

// begin_ntosp
//
//  Normal uncompressed Copy and Mdl Apis
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
BOOLEAN
FsRtlCopyRead (
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in BOOLEAN Wait,
    __in ULONG LockKey,
    __out_bcount(Length) PVOID Buffer,
    __out PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
BOOLEAN
FsRtlCopyWrite (
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in BOOLEAN Wait,
    __in ULONG LockKey,
    __in_bcount(Length) PVOID Buffer,
    __out PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
BOOLEAN
FsRtlMdlReadDev (
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in ULONG LockKey,
    __deref_out PMDL *MdlChain,
    __out PIO_STATUS_BLOCK IoStatus,
    __in_opt PDEVICE_OBJECT DeviceObject
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
BOOLEAN
FsRtlMdlReadCompleteDev (
    __in PFILE_OBJECT FileObject,
    __in PMDL MdlChain,
    __in_opt PDEVICE_OBJECT DeviceObject
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
BOOLEAN
FsRtlPrepareMdlWriteDev (
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in ULONG LockKey,
    __deref_out PMDL *MdlChain,
    __out PIO_STATUS_BLOCK IoStatus,
    __in PDEVICE_OBJECT DeviceObject
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
BOOLEAN
FsRtlMdlWriteCompleteDev (
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in PMDL MdlChain,
    __in_opt PDEVICE_OBJECT DeviceObject
    );
#endif

//
//  In Irps, compressed reads and writes are  designated by the
//  subfunction IRP_MN_COMPRESSED must be set and the Compressed
//  Data Info buffer must be described by the following structure
//  pointed to by Irp->Tail.Overlay.AuxiliaryBuffer.
//

typedef struct _FSRTL_AUXILIARY_BUFFER {

    //
    //  Buffer description with length.
    //

    PVOID Buffer;
    ULONG Length;

    //
    //  Flags
    //

    ULONG Flags;

    //
    //  Pointer to optional Mdl mapping buffer for file system use
    //

    PMDL Mdl;

} FSRTL_AUXILIARY_BUFFER;
typedef FSRTL_AUXILIARY_BUFFER *PFSRTL_AUXILIARY_BUFFER;

//
//  If this flag is set, the auxiliary buffer structure is
//  deallocated on Irp completion.  The caller has the
//  option in this case of appending this structure to the
//  structure being described, causing it all to be
//  deallocated at once.  If this flag is clear, no deallocate
//  occurs.
//

#define FSRTL_AUXILIARY_FLAG_DEALLOCATE 0x00000001

//
//  The following two routines are called from NtCreateSection to avoid
//  deadlocks with the file systems.
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
VOID
FsRtlAcquireFileExclusive (
    __in PFILE_OBJECT FileObject
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
FsRtlReleaseFile (
    __in PFILE_OBJECT FileObject
    );
#endif

//
//  These routines provide a simple interface for the common operations
//  of query/set file size.
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn
__drv_maxIRQL(PASSIVE_LEVEL)
NTSTATUS
FsRtlGetFileSize(
    __in PFILE_OBJECT FileObject,
    __out PLARGE_INTEGER FileSize
    );
#endif

//
// Determine if there is a complete device failure on an error.
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn
NTKERNELAPI
BOOLEAN
FsRtlIsTotalDeviceFailure(
    __in NTSTATUS Status
    );
#endif

// end_ntddk end_ntosp

//
//  Byte range file lock routines, implemented in FileLock.c
//
//  The file lock info record is used to return enumerated information
//  about a file lock
//

typedef struct _FILE_LOCK_INFO {

    //
    //  A description of the current locked range, and if the lock
    //  is exclusive or shared
    //

    LARGE_INTEGER StartingByte;
    LARGE_INTEGER Length;
    BOOLEAN ExclusiveLock;

    //
    //  The following fields describe the owner of the lock.
    //

    ULONG Key;
    PFILE_OBJECT FileObject;
    PVOID ProcessId;

    //
    //  The following field is used internally by FsRtl
    //

    LARGE_INTEGER EndingByte;

} FILE_LOCK_INFO;
typedef FILE_LOCK_INFO *PFILE_LOCK_INFO;

//
//  The following two procedure prototypes are used by the caller of the
//  file lock package to supply an alternate routine to call when
//  completing an IRP and when unlocking a byte range.  Note that the only
//  utility to us this interface is currently the redirector, all other file
//  system will probably let the IRP complete normally with IoCompleteRequest.
//  The user supplied routine returns any value other than success then the
//  lock package will remove any lock that we just inserted.
//

typedef NTSTATUS (*PCOMPLETE_LOCK_IRP_ROUTINE) (
    __in PVOID Context,
    __in PIRP Irp
    );

typedef VOID (*PUNLOCK_ROUTINE) (
    __in PVOID Context,
    __in PFILE_LOCK_INFO FileLockInfo
    );

//
//  A FILE_LOCK is an opaque structure but we need to declare the size of
//  it here so that users can allocate space for one.
//

typedef struct _FILE_LOCK {

    //
    //  The optional procedure to call to complete a request
    //

    PCOMPLETE_LOCK_IRP_ROUTINE CompleteLockIrpRoutine;

    //
    //  The optional procedure to call when unlocking a byte range
    //

    PUNLOCK_ROUTINE UnlockRoutine;

    //
    //  FastIoIsQuestionable is set to true whenever the filesystem require
    //  additional checking about whether the fast path can be taken.  As an
    //  example Ntfs requires checking for disk space before the writes can
    //  occur.
    //

    BOOLEAN FastIoIsQuestionable;
    BOOLEAN SpareC[3];

    //
    //  FsRtl lock information
    //

    PVOID   LockInformation;

    //
    //  Contains continuation information for FsRtlGetNextFileLock
    //

    FILE_LOCK_INFO  LastReturnedLockInfo;
    PVOID           LastReturnedLock;

    //
    //  Number of lock requests in progress. Used for synchronization purposes
    //  (so far, this only means byte range locks vs. oplocks).
    //

    LONG volatile LockRequestsInProgress;

} FILE_LOCK;
typedef FILE_LOCK *PFILE_LOCK;

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
PFILE_LOCK
FsRtlAllocateFileLock (
    __in_opt PCOMPLETE_LOCK_IRP_ROUTINE CompleteLockIrpRoutine,
    __in_opt PUNLOCK_ROUTINE UnlockRoutine
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
FsRtlFreeFileLock (
    __in PFILE_LOCK FileLock
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
FsRtlInitializeFileLock (
    __in PFILE_LOCK FileLock,
    __in_opt PCOMPLETE_LOCK_IRP_ROUTINE CompleteLockIrpRoutine,
    __in_opt PUNLOCK_ROUTINE UnlockRoutine
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
FsRtlUninitializeFileLock (
    __in PFILE_LOCK FileLock
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
NTSTATUS
FsRtlProcessFileLock (
    __in PFILE_LOCK FileLock,
    __in PIRP Irp,
    __in_opt PVOID Context
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
BOOLEAN
FsRtlCheckLockForReadAccess (
    __in PFILE_LOCK FileLock,
    __in PIRP Irp
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
BOOLEAN
FsRtlCheckLockForWriteAccess (
    __in PFILE_LOCK FileLock,
    __in PIRP Irp
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
BOOLEAN
FsRtlFastCheckLockForRead (
    __in PFILE_LOCK FileLock,
    __in PLARGE_INTEGER StartingByte,
    __in PLARGE_INTEGER Length,
    __in ULONG Key,
    __in PFILE_OBJECT FileObject,
    __in PVOID ProcessId
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
BOOLEAN
FsRtlFastCheckLockForWrite (
    __in PFILE_LOCK FileLock,
    __in PLARGE_INTEGER StartingByte,
    __in PLARGE_INTEGER Length,
    __in ULONG Key,
    __in PVOID FileObject,
    __in PVOID ProcessId
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
PFILE_LOCK_INFO
FsRtlGetNextFileLock (
    __in PFILE_LOCK FileLock,
    __in BOOLEAN Restart
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
BOOLEAN
FsRtlAreThereCurrentOrInProgressFileLocks (
    __in PFILE_LOCK FileLock
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
NTSTATUS
FsRtlFastUnlockSingle (
    __in PFILE_LOCK FileLock,
    __in PFILE_OBJECT FileObject,
    __in LARGE_INTEGER UNALIGNED *FileOffset,
    __in PLARGE_INTEGER Length,
    __in PEPROCESS ProcessId,
    __in ULONG Key,
    __in_opt PVOID Context,
    __in BOOLEAN AlreadySynchronized
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
NTSTATUS
FsRtlFastUnlockAll (
    __in PFILE_LOCK FileLock,
    __in PFILE_OBJECT FileObject,
    __in PEPROCESS ProcessId,
    __in_opt PVOID Context
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
NTSTATUS
FsRtlFastUnlockAllByKey (
    __in PFILE_LOCK FileLock,
    __in PFILE_OBJECT FileObject,
    __in PEPROCESS ProcessId,
    __in ULONG Key,
    __in_opt PVOID Context
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn
__drv_maxIRQL(APC_LEVEL)
__drv_preferredFunction(FsRtlFastLock, "Obsolete")
NTKERNELAPI
BOOLEAN
FsRtlPrivateLock (
    __in PFILE_LOCK FileLock,
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in PLARGE_INTEGER Length,
    __in PEPROCESS ProcessId,
    __in ULONG Key,
    __in BOOLEAN FailImmediately,
    __in BOOLEAN ExclusiveLock,
    __out PIO_STATUS_BLOCK Iosb,
    __in_opt PIRP Irp,
    __in_opt __drv_aliasesMem PVOID Context,
    __in BOOLEAN AlreadySynchronized
    );
#endif

//
//  BOOLEAN
//  FsRtlFastLock (
//      __in PFILE_LOCK FileLock,
//      __in PFILE_OBJECT FileObject,
//      __in PLARGE_INTEGER FileOffset,
//      __in PLARGE_INTEGER Length,
//      __in PEPROCESS ProcessId,
//      __in ULONG Key,
//      __in BOOLEAN FailImmediately,
//      __in BOOLEAN ExclusiveLock,
//      __out PIO_STATUS_BLOCK Iosb,
//      __in PVOID Context OPTIONAL,
//      __in BOOLEAN AlreadySynchronized
//      );
//

#define FsRtlFastLock(A1,A2,A3,A4,A5,A6,A7,A8,A9,A10,A11) ( \
    FsRtlPrivateLock( A1,   /* FileLock            */       \
                      A2,   /* FileObject          */       \
                      A3,   /* FileOffset          */       \
                      A4,   /* Length              */       \
                      A5,   /* ProcessId           */       \
                      A6,   /* Key                 */       \
                      A7,   /* FailImmediately     */       \
                      A8,   /* ExclusiveLock       */       \
                      A9,   /* Iosb                */       \
                      NULL, /* Irp                 */       \
                      A10,  /* Context             */       \
                      A11   /* AlreadySynchronized */ )     \
)

//
//  BOOLEAN
//  FsRtlAreThereCurrentFileLocks (
//      __in PFILE_LOCK FileLock
//      );
//

#define FsRtlAreThereCurrentFileLocks(FL) ( \
    ((FL)->FastIoIsQuestionable))

//
//  These macros are used by file systems to increment or decrement the
//  number of lock requests in progress, in order to prevent races with
//  oplocks etc.
//

#define FsRtlIncrementLockRequestsInProgress(FL) {                           \
    ASSERT( (FL)->LockRequestsInProgress >= 0 );                             \
    (void)                                                                   \
    (InterlockedIncrement((LONG volatile *)&((FL)->LockRequestsInProgress)));\
}

#define FsRtlDecrementLockRequestsInProgress(FL) {                           \
    ASSERT( (FL)->LockRequestsInProgress > 0 );                              \
    (void)                                                                   \
    (InterlockedDecrement((LONG volatile *)&((FL)->LockRequestsInProgress)));\
}



//
//  Filesystem property tunneling, implemented in tunnel.c
//

//
//  Tunnel cache structure
//

typedef struct {

    //
    //  Mutex for cache manipulation
    //

    FAST_MUTEX          Mutex;

    //
    //  Splay Tree of tunneled information keyed by
    //  DirKey ## Name
    //

    PRTL_SPLAY_LINKS    Cache;

    //
    //  Timer queue used to age entries out of the main cache
    //

    LIST_ENTRY          TimerQueue;

    //
    //  Keep track of the number of entries in the cache to prevent
    //  excessive use of memory
    //

    USHORT              NumEntries;

} TUNNEL, *PTUNNEL;

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
FsRtlInitializeTunnelCache (
    __in TUNNEL *Cache
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
FsRtlAddToTunnelCache (
    __in TUNNEL *Cache,
    __in ULONGLONG DirectoryKey,
    __in UNICODE_STRING *ShortName,
    __in UNICODE_STRING *LongName,
    __in BOOLEAN KeyByShortName,
    __in ULONG DataLength,
    __in_bcount(DataLength) VOID *Data
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
BOOLEAN
FsRtlFindInTunnelCache (
    __in TUNNEL *Cache,
    __in ULONGLONG DirectoryKey,
    __in UNICODE_STRING *Name,
    __out UNICODE_STRING *ShortName,
    __out UNICODE_STRING *LongName,
    __inout ULONG  *DataLength,
    __out_bcount_part(*DataLength, *DataLength) VOID *Data
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
FsRtlDeleteKeyFromTunnelCache (
    __in TUNNEL *Cache,
    __in ULONGLONG DirectoryKey
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
FsRtlDeleteTunnelCache (
    __in TUNNEL *Cache
    );
#endif


//
//  Dbcs name support routines, implemented in DbcsName.c
//

//
//  The following enumerated type is used to denote the result of name
//  comparisons
//

typedef enum _FSRTL_COMPARISON_RESULT {
    LessThan = -1,
    EqualTo = 0,
    GreaterThan = 1
} FSRTL_COMPARISON_RESULT;

#ifdef NLS_MB_CODE_PAGE_TAG
#undef NLS_MB_CODE_PAGE_TAG
#endif // NLS_MB_CODE_PAGE_TAG


#define LEGAL_ANSI_CHARACTER_ARRAY        (*FsRtlLegalAnsiCharacterArray) // ntosp
#define NLS_MB_CODE_PAGE_TAG              (*NlsMbOemCodePageTag)
#define NLS_OEM_LEAD_BYTE_INFO            (*NlsOemLeadByteInfo) // ntosp


extern UCHAR const* const LEGAL_ANSI_CHARACTER_ARRAY;
extern PUSHORT NLS_OEM_LEAD_BYTE_INFO;  // Lead byte info. for ACP

//
//  These following bit values are set in the FsRtlLegalDbcsCharacterArray
//

#define FSRTL_FAT_LEGAL         0x01
#define FSRTL_HPFS_LEGAL        0x02
#define FSRTL_NTFS_LEGAL        0x04
#define FSRTL_WILD_CHARACTER    0x08
#define FSRTL_OLE_LEGAL         0x10
#define FSRTL_NTFS_STREAM_LEGAL (FSRTL_NTFS_LEGAL | FSRTL_OLE_LEGAL)

//
//  The following macro is used to determine if an Ansi character is wild.
//

#define FsRtlIsAnsiCharacterWild(C) (                               \
    FsRtlTestAnsiCharacter((C), FALSE, FALSE, FSRTL_WILD_CHARACTER) \
)

//
//  The following macro is used to determine if an Ansi character is Fat legal.
//

#define FsRtlIsAnsiCharacterLegalFat(C,WILD_OK) (                 \
    FsRtlTestAnsiCharacter((C), TRUE, (WILD_OK), FSRTL_FAT_LEGAL) \
)

//
//  The following macro is used to determine if an Ansi character is Hpfs legal.
//

#define FsRtlIsAnsiCharacterLegalHpfs(C,WILD_OK) (                 \
    FsRtlTestAnsiCharacter((C), TRUE, (WILD_OK), FSRTL_HPFS_LEGAL) \
)

//
//  The following macro is used to determine if an Ansi character is Ntfs legal.
//

#define FsRtlIsAnsiCharacterLegalNtfs(C,WILD_OK) (                 \
    FsRtlTestAnsiCharacter((C), TRUE, (WILD_OK), FSRTL_NTFS_LEGAL) \
)

//
//  The following macro is used to determine if an Ansi character is
//  legal in an Ntfs stream name
//

#define FsRtlIsAnsiCharacterLegalNtfsStream(C,WILD_OK) (                    \
    FsRtlTestAnsiCharacter((C), TRUE, (WILD_OK), FSRTL_NTFS_STREAM_LEGAL)   \
)

//
//  The following macro is used to determine if an Ansi character is legal,
//  according to the caller's specification.
//

#define FsRtlIsAnsiCharacterLegal(C,FLAGS) (          \
    FsRtlTestAnsiCharacter((C), TRUE, FALSE, (FLAGS)) \
)

//
//  The following macro is used to test attributes of an Ansi character,
//  according to the caller's specified flags.
//

#define FsRtlTestAnsiCharacter(C, DEFAULT_RET, WILD_OK, FLAGS) (            \
        ((SCHAR)(C) < 0) ? DEFAULT_RET :                                    \
                           FlagOn( LEGAL_ANSI_CHARACTER_ARRAY[(C)],         \
                                   (FLAGS) |                                \
                                   ((WILD_OK) ? FSRTL_WILD_CHARACTER : 0) ) \
)


//
//  The following two macros use global data defined in ntos\rtl\nlsdata.c
//
//  BOOLEAN
//  FsRtlIsLeadDbcsCharacter (
//      __in UCHAR DbcsCharacter
//      );
//
//  /*++
//
//  Routine Description:
//
//      This routine takes the first bytes of a Dbcs character and
//      returns whether it is a lead byte in the system code page.
//
//  Arguments:
//
//      DbcsCharacter - Supplies the input character being examined
//
//  Return Value:
//
//      BOOLEAN - TRUE if the input character is a dbcs lead and
//              FALSE otherwise
//
//  --*/
//
//

#define FsRtlIsLeadDbcsCharacter(DBCS_CHAR) (                      \
    (BOOLEAN)((UCHAR)(DBCS_CHAR) < 0x80 ? FALSE :                  \
              (NLS_MB_CODE_PAGE_TAG &&                             \
               (NLS_OEM_LEAD_BYTE_INFO[(UCHAR)(DBCS_CHAR)] != 0))) \
)

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
FsRtlDissectDbcs (
    __in ANSI_STRING Path,
    __out PANSI_STRING FirstName,
    __out PANSI_STRING RemainingName
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
BOOLEAN
FsRtlDoesDbcsContainWildCards (
    __in PANSI_STRING Name
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
BOOLEAN
FsRtlIsDbcsInExpression (
    __in PANSI_STRING Expression,
    __in PANSI_STRING Name
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
BOOLEAN
FsRtlIsFatDbcsLegal (
    __in ANSI_STRING DbcsName,
    __in BOOLEAN WildCardsPermissible,
    __in BOOLEAN PathNamePermissible,
    __in BOOLEAN LeadingBackslashPermissible
    );
#endif

// end_ntosp

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
BOOLEAN
FsRtlIsHpfsDbcsLegal (
    __in ANSI_STRING DbcsName,
    __in BOOLEAN WildCardsPermissible,
    __in BOOLEAN PathNamePermissible,
    __in BOOLEAN LeadingBackslashPermissible
    );
#endif


//
//  Exception filter routines, implemented in Filter.c
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
FsRtlNormalizeNtstatus (
    __in NTSTATUS Exception,
    __in NTSTATUS GenericException
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn
NTKERNELAPI
BOOLEAN
FsRtlIsNtstatusExpected (
    __in NTSTATUS Exception
    );
#endif

//
//  The following procedures are used to allocate executive pool and raise
//  insufficient resource status if pool isn't currently available.
//

#define FsRtlAllocatePoolWithTag(PoolType, NumberOfBytes, Tag)                \
    ExAllocatePoolWithTag((POOL_TYPE)((PoolType) | POOL_RAISE_IF_ALLOCATION_FAILURE), \
                          NumberOfBytes,                                      \
                          Tag)


#define FsRtlAllocatePoolWithQuotaTag(PoolType, NumberOfBytes, Tag)           \
    ExAllocatePoolWithQuotaTag((POOL_TYPE)((PoolType) | POOL_RAISE_IF_ALLOCATION_FAILURE), \
                               NumberOfBytes,                                 \
                               Tag)

//
//  The following function allocates a resource from the FsRtl pool.
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
__drv_preferredFunction(ExAllocateFromNPagedLookasideList, "The FsRtlAllocateResource routine is obsolete, but is exported to support existing driver binaries. Use ExAllocateFromNPagedLookasideList and ExInitializeResourceLite instead.")
NTKERNELAPI
PERESOURCE
FsRtlAllocateResource (
    VOID
    );
#endif


//
//  Large Integer Mapped Control Blocks routines, implemented in LargeMcb.c
//
//  Originally this structure was truly opaque and code outside largemcb was
//  never allowed to examine or alter the structures.  However, for performance
//  reasons we want to allow ntfs the ability to quickly truncate down the
//  mcb without the overhead of an actual call to largemcb.c.  So to do that we
//  need to export the structure.  This structure is not exact.  The Mapping field
//  is declared here as a pvoid but largemcb.c it is a pointer to mapping pairs.
//

typedef struct _BASE_MCB {
    ULONG MaximumPairCount;
    ULONG PairCount;
    USHORT PoolType;
    USHORT Flags;
    PVOID Mapping;
} BASE_MCB;
typedef BASE_MCB *PBASE_MCB;

typedef struct _LARGE_MCB {
    PKGUARDED_MUTEX GuardedMutex;
    BASE_MCB BaseMcb;
} LARGE_MCB;
typedef LARGE_MCB *PLARGE_MCB;

#define MCB_FLAG_RAISE_ON_ALLOCATION_FAILURE 1

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
FsRtlInitializeLargeMcb (
    __in PLARGE_MCB Mcb,
    __in POOL_TYPE PoolType
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
FsRtlUninitializeLargeMcb (
    __in PLARGE_MCB Mcb
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
FsRtlResetLargeMcb (
    __in PLARGE_MCB Mcb,
    __in BOOLEAN SelfSynchronized
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
FsRtlTruncateLargeMcb (
    __in PLARGE_MCB Mcb,
    __in LONGLONG Vbn
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
BOOLEAN
FsRtlAddLargeMcbEntry (
    __in PLARGE_MCB Mcb,
    __in LONGLONG Vbn,
    __in LONGLONG Lbn,
    __in LONGLONG SectorCount
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
FsRtlRemoveLargeMcbEntry (
    __in PLARGE_MCB Mcb,
    __in LONGLONG Vbn,
    __in LONGLONG SectorCount
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
BOOLEAN
FsRtlLookupLargeMcbEntry (
    __in PLARGE_MCB Mcb,
    __in LONGLONG Vbn,
    __out_opt PLONGLONG Lbn,
    __out_opt PLONGLONG SectorCountFromLbn,
    __out_opt PLONGLONG StartingLbn,
    __out_opt PLONGLONG SectorCountFromStartingLbn,
    __out_opt PULONG Index
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
BOOLEAN
FsRtlLookupLastLargeMcbEntry (
    __in PLARGE_MCB Mcb,
    __out PLONGLONG Vbn,
    __out PLONGLONG Lbn
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
BOOLEAN
FsRtlLookupLastLargeMcbEntryAndIndex (
    __in PLARGE_MCB OpaqueMcb,
    __out PLONGLONG LargeVbn,
    __out PLONGLONG LargeLbn,
    __out PULONG Index
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
ULONG
FsRtlNumberOfRunsInLargeMcb (
    __in PLARGE_MCB Mcb
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
BOOLEAN
FsRtlGetNextLargeMcbEntry (
    __in PLARGE_MCB Mcb,
    __in ULONG RunIndex,
    __out PLONGLONG Vbn,
    __out PLONGLONG Lbn,
    __out PLONGLONG SectorCount
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
BOOLEAN
FsRtlSplitLargeMcb (
    __in PLARGE_MCB Mcb,
    __in LONGLONG Vbn,
    __in LONGLONG Amount
    );
#endif

//
//  Unsynchronzied base mcb functions. There is one of these for every
//  large mcb equivalent function - they are identical other than lack of
//  synchronization
//

#if (NTDDI_VERSION >= NTDDI_WS03)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
FsRtlInitializeBaseMcb (
    __in PBASE_MCB Mcb,
    __in POOL_TYPE PoolType
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_when(!Flags & MCB_FLAG_RAISE_ON_ALLOCATION_FAILURE, __checkReturn)
__drv_maxIRQL(APC_LEVEL)
BOOLEAN
FsRtlInitializeBaseMcbEx (
    __in PBASE_MCB Mcb,
    __in POOL_TYPE PoolType,
    __in USHORT Flags
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WS03)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
FsRtlUninitializeBaseMcb (
    __in PBASE_MCB Mcb
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WS03)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
FsRtlResetBaseMcb (
    __in PBASE_MCB Mcb
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WS03)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
FsRtlTruncateBaseMcb (
    __in PBASE_MCB Mcb,
    __in LONGLONG Vbn
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WS03)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
BOOLEAN
FsRtlAddBaseMcbEntry (
    __in PBASE_MCB Mcb,
    __in LONGLONG Vbn,
    __in LONGLONG Lbn,
    __in LONGLONG SectorCount
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTSTATUS
FsRtlAddBaseMcbEntryEx (
    __in PBASE_MCB Mcb,
    __in LONGLONG Vbn,
    __in LONGLONG Lbn,
    __in LONGLONG SectorCount
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WS03)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
BOOLEAN
FsRtlRemoveBaseMcbEntry (
    __in PBASE_MCB Mcb,
    __in LONGLONG Vbn,
    __in LONGLONG SectorCount
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WS03)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
BOOLEAN
FsRtlLookupBaseMcbEntry (
    __in PBASE_MCB Mcb,
    __in LONGLONG Vbn,
    __out_opt PLONGLONG Lbn,
    __out_opt PLONGLONG SectorCountFromLbn,
    __out_opt PLONGLONG StartingLbn,
    __out_opt PLONGLONG SectorCountFromStartingLbn,
    __out_opt PULONG Index
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WS03)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
BOOLEAN
FsRtlLookupLastBaseMcbEntry (
    __in PBASE_MCB Mcb,
    __out PLONGLONG Vbn,
    __out PLONGLONG Lbn
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WS03)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
BOOLEAN
FsRtlLookupLastBaseMcbEntryAndIndex (
    __in PBASE_MCB OpaqueMcb,
    __inout PLONGLONG LargeVbn,
    __inout PLONGLONG LargeLbn,
    __inout PULONG Index
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WS03)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
ULONG
FsRtlNumberOfRunsInBaseMcb (
    __in PBASE_MCB Mcb
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WS03)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
BOOLEAN
FsRtlGetNextBaseMcbEntry (
    __in PBASE_MCB Mcb,
    __in ULONG RunIndex,
    __out PLONGLONG Vbn,
    __out PLONGLONG Lbn,
    __out PLONGLONG SectorCount
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WS03)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
BOOLEAN
FsRtlSplitBaseMcb (
    __in PBASE_MCB Mcb,
    __in LONGLONG Vbn,
    __in LONGLONG Amount
    );
#endif


//
//  Mapped Control Blocks routines, implemented in Mcb.c
//
//  An MCB is an opaque structure but we need to declare the size of
//  it here so that users can allocate space for one.  Consequently the
//  size computation here must be updated by hand if the MCB changes.
//

typedef struct _MCB {
    LARGE_MCB DummyFieldThatSizesThisStructureCorrectly;
} MCB;
typedef MCB *PMCB;

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
__drv_preferredFunction(FsRtlInitializeLargeMcb, "Obsolete")
NTKERNELAPI
VOID
FsRtlInitializeMcb (
    __in PMCB Mcb,
    __in POOL_TYPE PoolType
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
FsRtlUninitializeMcb (
    __in PMCB Mcb
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
FsRtlTruncateMcb (
    __in PMCB Mcb,
    __in VBN Vbn
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
BOOLEAN
FsRtlAddMcbEntry (
    __in PMCB Mcb,
    __in VBN Vbn,
    __in LBN Lbn,
    __in ULONG SectorCount
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
FsRtlRemoveMcbEntry (
    __in PMCB Mcb,
    __in VBN Vbn,
    __in ULONG SectorCount
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
BOOLEAN
FsRtlLookupMcbEntry (
    __in PMCB Mcb,
    __in VBN Vbn,
    __out PLBN Lbn,
    __out_opt PULONG SectorCount,
    __out PULONG Index
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
BOOLEAN
FsRtlLookupLastMcbEntry (
    __in PMCB Mcb,
    __out PVBN Vbn,
    __out PLBN Lbn
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
ULONG
FsRtlNumberOfRunsInMcb (
    __in PMCB Mcb
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
BOOLEAN
FsRtlGetNextMcbEntry (
    __in PMCB Mcb,
    __in ULONG RunIndex,
    __out PVBN Vbn,
    __out PLBN Lbn,
    __out PULONG SectorCount
    );
#endif


//
//  Fault Tolerance routines, implemented in FaultTol.c
//
//  The routines in this package implement routines that help file
//  systems interact with the FT device drivers.
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
NTSTATUS
FsRtlBalanceReads (
    __in PDEVICE_OBJECT TargetDevice
    );
#endif


//
//  Oplock routines, implemented in Oplock.c
//
//  An OPLOCK is an opaque structure, we declare it as a PVOID and
//  allocate the actual memory only when needed.
//

typedef PVOID OPLOCK, *POPLOCK;

typedef
VOID
(*POPLOCK_WAIT_COMPLETE_ROUTINE) (
    __in PVOID Context,
    __in PIRP Irp
    );

typedef
VOID
(*POPLOCK_FS_PREPOST_IRP) (
    __in PVOID Context,
    __in PIRP Irp
    );

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
FsRtlInitializeOplock (
    __inout POPLOCK Oplock
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
FsRtlUninitializeOplock (
    __inout POPLOCK Oplock
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
NTSTATUS
FsRtlOplockFsctrl (
    __in POPLOCK Oplock,
    __in PIRP Irp,
    __in ULONG OpenCount
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_when(CompletionRoutine != NULL, __checkReturn)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
NTSTATUS
FsRtlCheckOplock (
    __in POPLOCK Oplock,
    __in PIRP Irp,
    __in_opt PVOID Context,
    __in_opt POPLOCK_WAIT_COMPLETE_ROUTINE CompletionRoutine,
    __in_opt POPLOCK_FS_PREPOST_IRP PostIrpRoutine
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTASP1)
//
//  Flags for FsRtlCheckOplockEx.
//

#define OPLOCK_FLAG_COMPLETE_IF_OPLOCKED    0x00000001
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
#define OPLOCK_FLAG_OPLOCK_KEY_CHECK_ONLY   0x00000002
#define OPLOCK_FLAG_BACK_OUT_ATOMIC_OPLOCK  0x00000004
#define OPLOCK_FLAG_IGNORE_OPLOCK_KEYS      0x00000008

//
//  Flags for FsRtlOplockFsctrlEx
//

#define OPLOCK_FSCTRL_FLAG_ALL_KEYS_MATCH   0x00000001
#endif

#if (NTDDI_VERSION >= NTDDI_VISTASP1)
__drv_when(Flags | OPLOCK_FLAG_BACK_OUT_ATOMIC_OPLOCK, __checkReturn)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
NTSTATUS
FsRtlCheckOplockEx (
    __in POPLOCK Oplock,
    __in PIRP Irp,
    __in ULONG Flags,
    __in_opt PVOID Context,
    __in_opt POPLOCK_WAIT_COMPLETE_ROUTINE CompletionRoutine,
    __in_opt POPLOCK_FS_PREPOST_IRP PostIrpRoutine
    );

#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
BOOLEAN
FsRtlOplockIsFastIoPossible (
    __in POPLOCK Oplock
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
BOOLEAN
FsRtlCurrentBatchOplock (
    __in POPLOCK Oplock
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
BOOLEAN
FsRtlCurrentOplock (
    __in POPLOCK Oplock
    );

__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
NTSTATUS
FsRtlOplockBreakToNone (
    __inout POPLOCK Oplock,
    __in_opt PIO_STACK_LOCATION IrpSp,
    __in PIRP Irp,
    __in_opt PVOID Context,
    __in_opt POPLOCK_WAIT_COMPLETE_ROUTINE CompletionRoutine,
    __in_opt POPLOCK_FS_PREPOST_IRP PostIrpRoutine
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
//
// ECP context for an oplock key.
//

typedef struct _OPLOCK_KEY_ECP_CONTEXT {

    //
    //  The caller places a GUID of their own devising here to serve as
    //  the oplock key.
    //

    GUID OplockKey;

    //
    //  This must be set to zero.
    //

    ULONG Reserved;

} OPLOCK_KEY_ECP_CONTEXT, *POPLOCK_KEY_ECP_CONTEXT;

//
//  The GUID used for the OPLOCK_KEY_ECP_CONTEXT structure.
//
//  {48850596-3050-4be7-9863-fec350ce8d7f}
//

DEFINE_GUID( GUID_ECP_OPLOCK_KEY, 0x48850596, 0x3050, 0x4be7, 0x98, 0x63, 0xfe, 0xc3, 0x50, 0xce, 0x8d, 0x7f );

__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
BOOLEAN
FsRtlOplockIsSharedRequest(
    __in PIRP Irp
    );

__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
NTSTATUS
FsRtlOplockBreakH (
    __in POPLOCK Oplock,
    __in PIRP Irp,
    __in ULONG Flags,
    __in_opt PVOID Context,
    __in_opt POPLOCK_WAIT_COMPLETE_ROUTINE CompletionRoutine,
    __in_opt POPLOCK_FS_PREPOST_IRP PostIrpRoutine
    );

__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
BOOLEAN
FsRtlCurrentOplockH (
    __in POPLOCK Oplock
    );

__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
NTSTATUS
FsRtlOplockBreakToNoneEx (
    __inout POPLOCK Oplock,
    __in PIRP Irp,
    __in ULONG Flags,
    __in_opt PVOID Context,
    __in_opt POPLOCK_WAIT_COMPLETE_ROUTINE CompletionRoutine,
    __in_opt POPLOCK_FS_PREPOST_IRP PostIrpRoutine
    );

__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
NTSTATUS
FsRtlOplockFsctrlEx (
    __in POPLOCK Oplock,
    __in PIRP Irp,
    __in ULONG OpenCount,
    __in ULONG Flags
    );

__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
BOOLEAN
FsRtlOplockKeysEqual (
    __in_opt PFILE_OBJECT Fo1,
    __in_opt PFILE_OBJECT Fo2
    );
#endif



//
//  Volume lock/unlock notification routines, implemented in PnP.c
//
//  These routines provide PnP volume lock notification support
//  for all filesystems.
//

#define FSRTL_VOLUME_DISMOUNT           1
#define FSRTL_VOLUME_DISMOUNT_FAILED    2
#define FSRTL_VOLUME_LOCK               3
#define FSRTL_VOLUME_LOCK_FAILED        4
#define FSRTL_VOLUME_UNLOCK             5
#define FSRTL_VOLUME_MOUNT              6
#define FSRTL_VOLUME_NEEDS_CHKDSK       7
#define FSRTL_VOLUME_WORM_NEAR_FULL     8
#define FSRTL_VOLUME_WEARING_OUT        9
#define FSRTL_VOLUME_FORCED_CLOSED      10
#define FSRTL_VOLUME_INFO_MAKE_COMPAT   11
#define FSRTL_VOLUME_PREPARING_EJECT    12
#define FSRTL_VOLUME_CHANGE_SIZE        13
#define FSRTL_VOLUME_BACKGROUND_FORMAT  14

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
NTSTATUS
FsRtlNotifyVolumeEvent (
    __in PFILE_OBJECT FileObject,
    __in ULONG EventCode
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
NTSTATUS
FsRtlNotifyVolumeEventEx (
    __in PFILE_OBJECT FileObject,
    __in ULONG EventCode,
    __in PTARGET_DEVICE_CUSTOM_NOTIFICATION Event
    );
#endif


//
//  Notify Change routines, implemented in Notify.c
//
//  These routines provide Notify Change support for all filesystems.
//  Any of the 'Full' notify routines will support returning the
//  change information into the user's buffer.
//

typedef PVOID PNOTIFY_SYNC;

typedef
BOOLEAN (*PCHECK_FOR_TRAVERSE_ACCESS) (
    __in PVOID NotifyContext,
    __in_opt PVOID TargetContext,
    __in PSECURITY_SUBJECT_CONTEXT SubjectContext
    );

typedef
BOOLEAN (*PFILTER_REPORT_CHANGE) (
    __in PVOID NotifyContext,
    __in PVOID FilterContext
    );

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
FsRtlNotifyInitializeSync (
    __in PNOTIFY_SYNC *NotifySync
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
FsRtlNotifyUninitializeSync (
    __in PNOTIFY_SYNC *NotifySync
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
VOID
FsRtlNotifyFullChangeDirectory (
    __in PNOTIFY_SYNC NotifySync,
    __in PLIST_ENTRY NotifyList,
    __in PVOID FsContext,
    __in PSTRING FullDirectoryName,
    __in BOOLEAN WatchTree,
    __in BOOLEAN IgnoreBuffer,
    __in ULONG CompletionFilter,
    __in_opt PIRP NotifyIrp,
    __in_opt PCHECK_FOR_TRAVERSE_ACCESS TraverseCallback,
    __in_opt PSECURITY_SUBJECT_CONTEXT SubjectContext
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
VOID
FsRtlNotifyFilterChangeDirectory (
    __in PNOTIFY_SYNC NotifySync,
    __in PLIST_ENTRY NotifyList,
    __in PVOID FsContext,
    __in PSTRING FullDirectoryName,
    __in BOOLEAN WatchTree,
    __in BOOLEAN IgnoreBuffer,
    __in ULONG CompletionFilter,
    __in_opt PIRP NotifyIrp,
    __in_opt PCHECK_FOR_TRAVERSE_ACCESS TraverseCallback,
    __in_opt PSECURITY_SUBJECT_CONTEXT SubjectContext,
    __in_opt PFILTER_REPORT_CHANGE FilterCallback
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
VOID
FsRtlNotifyFilterReportChange (
    __in PNOTIFY_SYNC NotifySync,
    __in PLIST_ENTRY NotifyList,
    __in PSTRING FullTargetName,
    __in USHORT TargetNameOffset,
    __in_opt PSTRING StreamName,
    __in_opt PSTRING NormalizedParentName,
    __in ULONG FilterMatch,
    __in ULONG Action,
    __in_opt PVOID TargetContext,
    __in_opt PVOID FilterContext
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
VOID
FsRtlNotifyFullReportChange (
    __in PNOTIFY_SYNC NotifySync,
    __in PLIST_ENTRY NotifyList,
    __in PSTRING FullTargetName,
    __in USHORT TargetNameOffset,
    __in_opt PSTRING StreamName,
    __in_opt PSTRING NormalizedParentName,
    __in ULONG FilterMatch,
    __in ULONG Action,
    __in_opt PVOID TargetContext
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
FsRtlNotifyCleanup (
    __in PNOTIFY_SYNC NotifySync,
    __in PLIST_ENTRY NotifyList,
    __in PVOID FsContext
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
FsRtlNotifyCleanupAll (
    __in PNOTIFY_SYNC NotifySync,
    __in PLIST_ENTRY NotifyList
    );
#endif


//
//  Unicode Name support routines, implemented in Name.c
//
//  The routines here are used to manipulate unicode names
//

//
//  The following macro is used to determine if a character is wild.
//

#define FsRtlIsUnicodeCharacterWild(C) (                                \
      (((C) >= 0x40) ? FALSE : FlagOn( LEGAL_ANSI_CHARACTER_ARRAY[(C)], \
                                       FSRTL_WILD_CHARACTER ) )         \
)

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
VOID
FsRtlDissectName (
    __in UNICODE_STRING Path,
    __out PUNICODE_STRING FirstName,
    __out PUNICODE_STRING RemainingName
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
BOOLEAN
FsRtlDoesNameContainWildCards (
    __in PUNICODE_STRING Name
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
BOOLEAN
FsRtlAreNamesEqual (
    __in PCUNICODE_STRING ConstantNameA,
    __in PCUNICODE_STRING ConstantNameB,
    __in BOOLEAN IgnoreCase,
    __in_ecount_opt(0x10000) PCWCH UpcaseTable
    );
#endif

// begin_ntosp

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
BOOLEAN
FsRtlIsNameInExpression (
    __in PUNICODE_STRING Expression,
    __in PUNICODE_STRING Name,
    __in BOOLEAN IgnoreCase,
    __in_opt PWCH UpcaseTable
    );
#endif

// end_ntosp


//
//  Stack Overflow support routine, implemented in StackOvf.c
//

typedef
VOID
(*PFSRTL_STACK_OVERFLOW_ROUTINE) (
    __in PVOID Context,
    __in PKEVENT Event
    );

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
VOID
FsRtlPostStackOverflow (
    __in PVOID Context,
    __in PKEVENT Event,
    __in PFSRTL_STACK_OVERFLOW_ROUTINE StackOverflowRoutine
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
NTKERNELAPI
VOID
FsRtlPostPagingFileStackOverflow (
    __in PVOID Context,
    __in PKEVENT Event,
    __in PFSRTL_STACK_OVERFLOW_ROUTINE StackOverflowRoutine
    );
#endif


//
// UNC Provider support
//

#if (NTDDI_VERSION >= NTDDI_VISTA)

//
//  Flags passed in to FsRtlRegisterUncProviderEx
//

#define FSRTL_UNC_PROVIDER_FLAGS_MAILSLOTS_SUPPORTED    0x00000001
#define FSRTL_UNC_PROVIDER_FLAGS_CSC_ENABLED            0x00000002
#define FSRTL_UNC_PROVIDER_FLAGS_DOMAIN_SVC_AWARE       0x00000004

__checkReturn
__drv_maxIRQL(PASSIVE_LEVEL)
NTSTATUS
FsRtlRegisterUncProviderEx(
    __out PHANDLE MupHandle,
    __in PUNICODE_STRING RedirDevName,
    __in PDEVICE_OBJECT DeviceObject,
    __in ULONG Flags
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__checkReturn
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
NTSTATUS
FsRtlRegisterUncProvider(
    __out PHANDLE MupHandle,
    __in PUNICODE_STRING RedirectorDeviceName,
    __in BOOLEAN MailslotsSupported
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
VOID
FsRtlDeregisterUncProvider(
    __in HANDLE Handle
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)

__checkReturn
__drv_when(Irp!=NULL, __drv_maxIRQL(PASSIVE_LEVEL))
__drv_when(Irp==NULL, __drv_maxIRQL(APC_LEVEL))
NTKERNELAPI
NTSTATUS
FsRtlCancellableWaitForSingleObject(
    __in PVOID Object,
    __in_opt PLARGE_INTEGER Timeout,
    __in_opt PIRP Irp
    );

__checkReturn
__drv_when(Irp != NULL, __drv_maxIRQL(PASSIVE_LEVEL))
__drv_when(Irp == NULL, __drv_maxIRQL(APC_LEVEL))
NTKERNELAPI
NTSTATUS
FsRtlCancellableWaitForMultipleObjects(
    __in ULONG Count,
    __in_ecount(Count) PVOID ObjectArray[],
    __in WAIT_TYPE WaitType,
    __in_opt PLARGE_INTEGER Timeout,
    __in_opt PKWAIT_BLOCK WaitBlockArray,
    __in_opt PIRP Irp
    );

#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)

//
//  For use by filter drivers to get information on provider corresponding to a given
//  fileobject on the remote filesystem stack. Without this, filters will always end up
//  getting \Device\Mup for providers registering with FsRtlRegisterUncProviderEx().
//


__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
NTSTATUS
FsRtlMupGetProviderInfoFromFileObject(
    __in                        PFILE_OBJECT    pFileObject,
    __in                        ULONG           Level,
    __out_bcount(*pBufferSize)  PVOID           pBuffer,
    __inout                     PULONG          pBufferSize
    );

//
//  Format of output in pBuffer.
//

//
//  Level 1.
//


typedef struct _FSRTL_MUP_PROVIDER_INFO_LEVEL_1 {
    ULONG32         ProviderId;         // ID for quick comparison, stable across provider load/unload.

} FSRTL_MUP_PROVIDER_INFO_LEVEL_1, *PFSRTL_MUP_PROVIDER_INFO_LEVEL_1;

typedef struct _FSRTL_MUP_PROVIDER_INFO_LEVEL_2 {
    ULONG32         ProviderId;         // ID for quick comparison, stable across provider load/unload.
    UNICODE_STRING  ProviderName;       // Device name of provider.

} FSRTL_MUP_PROVIDER_INFO_LEVEL_2, *PFSRTL_MUP_PROVIDER_INFO_LEVEL_2;


__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
NTSTATUS
FsRtlMupGetProviderIdFromName(
    __in    PUNICODE_STRING pProviderName,
    __out   PULONG32        pProviderId
    );


#endif



//
//  File System Filter PerFile Context Support
//

//
//  Filesystem filter drivers use these APIs to associate context
//  with open files (for filesystems that support this).
//

//
//  OwnerId should uniquely identify a particular filter driver
//  (e.g. the address of the driver's device object).
//  InstanceId can be used to distinguish distinct contexts associated
//  by a filter driver with a single file
//

//
//  This structure needs to be embedded within the users context that
//  they want to associate with a given file
//

typedef struct _FSRTL_PER_FILE_CONTEXT {
    //
    //  This is linked into the FileContext list maintained by the
    //  kernel
    //

    LIST_ENTRY Links;

    //
    //  A Unique ID for this filter (ex: address of Driver Object, Device
    //  Object, or Device Extension)
    //

    PVOID OwnerId;

    //
    //  An optional ID to differentiate different contexts for the same
    //  filter.
    //

    PVOID InstanceId;

    //
    //  A callback routine which is called by the underlying file system
    //  when the per-file structure is being torn down.  When this routine is called
    //  the given context has already been removed from the context linked
    //  list.  The callback routine cannot recursively call down into the
    //  filesystem or acquire any of their resources which they might hold
    //  when calling the filesystem outside of the callback.  This must
    //  be defined.
    //

    PFREE_FUNCTION FreeCallback;

} FSRTL_PER_FILE_CONTEXT, *PFSRTL_PER_FILE_CONTEXT;


//
//  This will initialize the given FSRTL_PER_FILE_CONTEXT structure.  This
//  should be used before calling "FsRtlInsertPerFileContext".
//

#define FsRtlInitPerFileContext( _fc, _owner, _inst, _cb)   \
    ((_fc)->OwnerId = (_owner),                               \
     (_fc)->InstanceId = (_inst),                             \
     (_fc)->FreeCallback = (_cb))

//
//  Given a FileObject this will return the FileContext pointer that
//  needs to be passed into the other FsRtl PerFile Context routines.
//  If the file system does not support filter file contexts then
//  NULL is returned
//

#define FsRtlGetPerFileContextPointer(_fo) \
    (FsRtlSupportsPerFileContexts(_fo) ? \
        FsRtlGetPerStreamContextPointer(_fo)->FileContextSupportPointer : \
        NULL)

//
//  This will test to see if PerFile contexts are supported for the given
//  FileObject
//

#define FsRtlSupportsPerFileContexts(_fo)                     \
    ((FsRtlGetPerStreamContextPointer(_fo) != NULL) &&        \
     (FsRtlGetPerStreamContextPointer(_fo)->Version >= FSRTL_FCB_HEADER_V1) &&  \
     (FsRtlGetPerStreamContextPointer(_fo)->FileContextSupportPointer != NULL))


//
//  Associate the context at Ptr with the given file.  The Ptr structure
//  should be filled in by the caller before calling this routine (see
//  FsRtlInitPerFileContext).  If the underlying filesystem does not support
//  filter file contexts, STATUS_INVALID_DEVICE_REQUEST will be returned.
//

__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
NTSTATUS
FsRtlInsertPerFileContext (
    __in PVOID* PerFileContextPointer,
    __in PFSRTL_PER_FILE_CONTEXT Ptr
    );

//
//  Lookup a filter context associated with the file specified.  The first
//  context matching OwnerId (and InstanceId, if present) is returned.  By not
//  specifying InstanceId, a filter driver can search for any context that it
//  has previously associated with a stream.  If no matching context is found,
//  NULL is returned.  If the file system does not support filter contexts,
//  NULL is returned.
//


__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
PFSRTL_PER_FILE_CONTEXT
FsRtlLookupPerFileContext (
    __in PVOID* PerFileContextPointer,
    __in_opt PVOID OwnerId,
    __in_opt PVOID InstanceId
    );


//
//  Normally, contexts should be deleted when the file system notifies the
//  filter that the file is being closed.  There are cases when a filter
//  may want to remove all existing contexts for a specific volume.  This
//  routine should be called at those times.  This routine should NOT be
//  called for the following cases:
//      - Inside your FreeCallback handler - The underlying file system has
//        already removed it from the linked list).
//      - Inside your IRP_CLOSE handler - If you do this then you will not
//        be notified when the stream is torn down.
//
//  This functions identically to FsRtlLookupPerFileContext, except that the
//  returned context has been removed from the list.
//

__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
PFSRTL_PER_FILE_CONTEXT
FsRtlRemovePerFileContext (
    __in PVOID* PerFileContextPointer,
    __in_opt PVOID OwnerId,
    __in_opt PVOID InstanceId
    );


//
//  APIs for file systems to use for initializing and cleaning up
//  the Advaned FCB Header fields for PerStreamContext and
//  PerFileContext support
//

//
//  This will properly initialize the advanced header so that it can be
//  used with PerStream contexts and PerFile contexts.
//  Note:  A fast mutex must be placed in an advanced header.  It is the
//         caller's responsibility to properly create and initialize this
//         mutex before calling this macro.  The mutex field is only set
//         if a non-NULL value is passed in.
//  If the file system supports filter file contexts then it must
//  initialize the FileContextSupportPointer field to point to a PVOID
//  embedded in its per-file structure (FCB). If a NULL is passed in,
//  then the macro assumes that the file system does not support filter
//  file contexts
//

#define FsRtlSetupAdvancedHeaderEx( _advhdr, _fmutx, _fctxptr )                     \
{                                                                                   \
    FsRtlSetupAdvancedHeader( _advhdr, _fmutx );                                    \
    if ((_fctxptr) != NULL) {                                                       \
        (_advhdr)->FileContextSupportPointer = (_fctxptr);                          \
    }                                                                               \
}

//
//  File systems call this API to free any filter contexts still associated
//  with a per-file structure (FCB) that they are tearing down.
//  The FreeCallback routine for each filter context will be called.
//

__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
FsRtlTeardownPerFileContexts (
    __in PVOID* PerFileContextPointer
    );


//
//  File System Filter PerStream Context Support
//

//
//  Filesystem filter drivers use these APIs to associate context
//  with open streams (for filesystems that support this).
//

//
//  OwnerId should uniquely identify a particular filter driver
//  (e.g. the address of the driver's device object).
//  InstanceId can be used to distinguish distinct contexts associated
//  by a filter driver with a single stream (e.g. the address of the
//  PerStream Context structure).
//

//
//  This structure needs to be embedded within the users context that
//  they want to associate with a given stream
//

typedef struct _FSRTL_PER_STREAM_CONTEXT {
    //
    //  This is linked into the StreamContext list inside the
    //  FSRTL_ADVANCED_FCB_HEADER structure.
    //

    LIST_ENTRY Links;

    //
    //  A Unique ID for this filter (ex: address of Driver Object, Device
    //  Object, or Device Extension)
    //

    PVOID OwnerId;

    //
    //  An optional ID to differentiate different contexts for the same
    //  filter.
    //

    PVOID InstanceId;

    //
    //  A callback routine which is called by the underlying file system
    //  when the stream is being torn down.  When this routine is called
    //  the given context has already been removed from the context linked
    //  list.  The callback routine cannot recursively call down into the
    //  filesystem or acquire any of their resources which they might hold
    //  when calling the filesystem outside of the callback.  This must
    //  be defined.
    //

    PFREE_FUNCTION FreeCallback;

} FSRTL_PER_STREAM_CONTEXT, *PFSRTL_PER_STREAM_CONTEXT;


//
//  This will initialize the given FSRTL_PER_STREAM_CONTEXT structure.  This
//  should be used before calling "FsRtlInsertPerStreamContext".
//

#define FsRtlInitPerStreamContext( _fc, _owner, _inst, _cb)   \
    ((_fc)->OwnerId = (_owner),                               \
     (_fc)->InstanceId = (_inst),                             \
     (_fc)->FreeCallback = (_cb))

//
//  Given a FileObject this will return the StreamContext pointer that
//  needs to be passed into the other FsRtl PerStream Context routines.
//

#define FsRtlGetPerStreamContextPointer(_fo) \
    ((PFSRTL_ADVANCED_FCB_HEADER)((_fo)->FsContext))

//
//  This will test to see if PerStream contexts are supported for the given
//  FileObject
//

#define FsRtlSupportsPerStreamContexts(_fo)                     \
    ((NULL != FsRtlGetPerStreamContextPointer(_fo)) &&          \
     FlagOn(FsRtlGetPerStreamContextPointer(_fo)->Flags2,       \
                    FSRTL_FLAG2_SUPPORTS_FILTER_CONTEXTS))

//
//  Associate the context at Ptr with the given stream.  The Ptr structure
//  should be filled in by the caller before calling this routine (see
//  FsRtlInitPerStreamContext).  If the underlying filesystem does not support
//  filter contexts, STATUS_INVALID_DEVICE_REQUEST will be returned.
//

#if (NTDDI_VERSION >= NTDDI_WINXP)
__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
NTSTATUS
FsRtlInsertPerStreamContext (
    __in PFSRTL_ADVANCED_FCB_HEADER PerStreamContext,
    __in PFSRTL_PER_STREAM_CONTEXT Ptr
    );
#endif

//
//  Lookup a filter context associated with the stream specified.  The first
//  context matching OwnerId (and InstanceId, if present) is returned.  By not
//  specifying InstanceId, a filter driver can search for any context that it
//  has previously associated with a stream.  If no matching context is found,
//  NULL is returned.  If the file system does not support filter contexts,
//  NULL is returned.
//

#if (NTDDI_VERSION >= NTDDI_WINXP)
__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
PFSRTL_PER_STREAM_CONTEXT
FsRtlLookupPerStreamContextInternal (
    __in PFSRTL_ADVANCED_FCB_HEADER StreamContext,
    __in_opt PVOID OwnerId,
    __in_opt PVOID InstanceId
    );
#endif

#define FsRtlLookupPerStreamContext(_sc, _oid, _iid)                          \
 (((NULL != (_sc)) &&                                                         \
   FlagOn((_sc)->Flags2,FSRTL_FLAG2_SUPPORTS_FILTER_CONTEXTS) &&              \
   !IsListEmpty(&(_sc)->FilterContexts)) ?                                    \
        FsRtlLookupPerStreamContextInternal((_sc), (_oid), (_iid)) :          \
        NULL)

//
//  Normally, contexts should be deleted when the file system notifies the
//  filter that the stream is being closed.  There are cases when a filter
//  may want to remove all existing contexts for a specific volume.  This
//  routine should be called at those times.  This routine should NOT be
//  called for the following cases:
//      - Inside your FreeCallback handler - The underlying file system has
//        already removed it from the linked list).
//      - Inside your IRP_CLOSE handler - If you do this then you will not
//        be notified when the stream is torn down.
//
//  This functions identically to FsRtlLookupPerStreamContext, except that the
//  returned context has been removed from the list.
//

#if (NTDDI_VERSION >= NTDDI_WINXP)
__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
PFSRTL_PER_STREAM_CONTEXT
FsRtlRemovePerStreamContext (
    __in PFSRTL_ADVANCED_FCB_HEADER StreamContext,
    __in_opt PVOID OwnerId,
    __in_opt PVOID InstanceId
    );
#endif


//
//  APIs for file systems to use for initializing and cleaning up
//  the Advaned FCB Header fields for PerStreamContext support
//

//
//  This will properly initialize the advanced header so that it can be
//  used with PerStream contexts.
//  Note:  A fast mutex must be placed in an advanced header.  It is the
//         caller's responsibility to properly create and initialize this
//         mutex before calling this macro.  The mutex field is only set
//         if a non-NULL value is passed in.
//

__drv_maxIRQL(APC_LEVEL)
VOID
FORCEINLINE
FsRtlSetupAdvancedHeader(
    __in PVOID AdvHdr,
    __in PFAST_MUTEX FMutex )

/*
    The AdvHdr parameter should have a type of PFSRTL_ADVANCED_FCB_HEADER but
    I had to make it a PVOID because there are cases where this routine is
    called where a different type is passed in (where the advanced header
    is at the front of this other type).  This routine used to be a macro and
    I changed it to an INLINE so we could put the NTDDI_VERSION conditional into
    it.  To maintain compatiblity I made the AdvHdr parameter a PVOID and cast
    it to the correct type internally.
*/

{
    PFSRTL_ADVANCED_FCB_HEADER localAdvHdr = (PFSRTL_ADVANCED_FCB_HEADER)AdvHdr;

    localAdvHdr->Flags |= FSRTL_FLAG_ADVANCED_HEADER;
    localAdvHdr->Flags2 |= FSRTL_FLAG2_SUPPORTS_FILTER_CONTEXTS;

#if (NTDDI_VERSION >= NTDDI_VISTA)
    localAdvHdr->Version = FSRTL_FCB_HEADER_V1;
#else
    localAdvHdr->Version = FSRTL_FCB_HEADER_V0;
#endif

    InitializeListHead( &localAdvHdr->FilterContexts );

    if (FMutex != NULL) {

        localAdvHdr->FastMutex = FMutex;
    }

#if (NTDDI_VERSION >= NTDDI_VISTA)

//
//  API not avaialble down level
//  We want to support a driver compiled to the last version running downlevel,
//  so continue to use use the direct init of the push lock and not call
//  ExInitializePushLock.
//

    *((PULONG_PTR)(&localAdvHdr->PushLock)) = 0;
    /*ExInitializePushLock( &localAdvHdr->PushLock ); API not avaialble down level*/

    localAdvHdr->FileContextSupportPointer = NULL;
#endif
}


//
// File systems call this API to free any filter contexts still associated
// with an FSRTL_COMMON_FCB_HEADER that they are tearing down.
// The FreeCallback routine for each filter context will be called.
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
FsRtlTeardownPerStreamContexts (
    __in PFSRTL_ADVANCED_FCB_HEADER AdvancedHeader
    );

//
//  Function pointer to above routine for modules that need to dynamically import
//

typedef VOID (*PFN_FSRTLTEARDOWNPERSTREAMCONTEXTS) (__in PFSRTL_ADVANCED_FCB_HEADER AdvancedHeader);
#endif

//
//  File System Filter PerFileObject Context Support
//

//
//  Filesystem filter drivers use these APIs to associate context
//  with individual open files.  For now these are only supported on file
//  objects with a FileObject extension which are only created by using
//  IoCreateFileSpecifyDeviceObjectHint.
//

//
//  OwnerId should uniquely identify a particular filter driver
//  (e.g. the address of the driver's device object).
//  InstanceId can be used to distinguish distinct contexts associated
//  by a filter driver with a single stream (e.g. the address of the
//  fileobject).
//

//
//  This structure needs to be embedded within the users context that
//  they want to associate with a given stream
//

typedef struct _FSRTL_PER_FILEOBJECT_CONTEXT {
    //
    //  This is linked into the File Object
    //

    LIST_ENTRY Links;

    //
    //  A Unique ID for this filter (ex: address of Driver Object, Device
    //  Object, or Device Extension)
    //

    PVOID OwnerId;

    //
    //  An optional ID to differentiate different contexts for the same
    //  filter.
    //

    PVOID InstanceId;

} FSRTL_PER_FILEOBJECT_CONTEXT, *PFSRTL_PER_FILEOBJECT_CONTEXT;


//
//  This will initialize the given FSRTL_PER_FILEOBJECT_CONTEXT structure.  This
//  should be used before calling "FsRtlInsertPerFileObjectContext".
//

#define FsRtlInitPerFileObjectContext( _fc, _owner, _inst )         \
    ((_fc)->OwnerId = (_owner),                                     \
     (_fc)->InstanceId = (_inst))                                   \

//
//  Associate the context at Ptr with the given FileObject.  The Ptr
//  structure should be filled in by the caller before calling this
//  routine (see FsRtlInitPerFileObjectContext).  If this file object does not
//  support filter contexts, STATUS_INVALID_DEVICE_REQUEST will be returned.
//

__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
NTSTATUS
FsRtlInsertPerFileObjectContext (
    __in PFILE_OBJECT FileObject,
    __in PFSRTL_PER_FILEOBJECT_CONTEXT Ptr
    );

//
//  Lookup a filter context associated with the FileObject specified.  The first
//  context matching OwnerId (and InstanceId, if present) is returned.  By not
//  specifying InstanceId, a filter driver can search for any context that it
//  has previously associated with a stream.  If no matching context is found,
//  NULL is returned.  If the FileObject does not support contexts,
//  NULL is returned.
//

__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
PFSRTL_PER_FILEOBJECT_CONTEXT
FsRtlLookupPerFileObjectContext (
    __in PFILE_OBJECT FileObject,
    __in_opt PVOID OwnerId,
    __in_opt PVOID InstanceId
    );

//
//  Normally, contexts should be deleted when the IoManager notifies the
//  filter that the FileObject is being freed.  There are cases when a filter
//  may want to remove all existing contexts for a specific volume.  This
//  routine should be called at those times.  This routine should NOT be
//  called for the following case:
//      - Inside your FreeCallback handler - The IoManager has already removed
//        it from the linked list.
//
//  This functions identically to FsRtlLookupPerFileObjectContext, except that
//  the returned context has been removed from the list.
//

__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
PFSRTL_PER_FILEOBJECT_CONTEXT
FsRtlRemovePerFileObjectContext (
    __in PFILE_OBJECT FileObject,
    __in_opt PVOID OwnerId,
    __in_opt PVOID InstanceId
    );

//++
//
//  VOID
//  FsRtlCompleteRequest (
//      __in PIRP Irp,
//      __in NTSTATUS Status
//      );
//
//  Routine Description:
//
//      This routine is used to complete an IRP with the indicated
//      status.  It does the necessary raise and lower of IRQL.
//
//  Arguments:
//
//      Irp - Supplies a pointer to the Irp to complete
//
//      Status - Supplies the completion status for the Irp
//
//  Return Value:
//
//      None.
//
//--

#define FsRtlCompleteRequest(IRP,STATUS) {         \
    (IRP)->IoStatus.Status = (STATUS);             \
    IoCompleteRequest( (IRP), IO_DISK_INCREMENT ); \
}


//++
//
//  VOID
//  FsRtlEnterFileSystem (
//      );
//
//  Routine Description:
//
//      This routine is used when entering a file system (e.g., through its
//      Fsd entry point).  It ensures that the file system cannot be suspended
//      while running and thus block other file I/O requests.  Upon exit
//      the file system must call FsRtlExitFileSystem.
//
//  Arguments:
//
//  Return Value:
//
//      None.
//
//--

#define FsRtlEnterFileSystem() { \
    KeEnterCriticalRegion();     \
}

//++
//
//  VOID
//  FsRtlExitFileSystem (
//      );
//
//  Routine Description:
//
//      This routine is used when exiting a file system (e.g., through its
//      Fsd entry point).
//
//  Arguments:
//
//  Return Value:
//
//      None.
//
//--

#define FsRtlExitFileSystem() { \
    KeLeaveCriticalRegion();    \
}

#if (NTDDI_VERSION >= NTDDI_WINXP)
NTKERNELAPI
VOID
FsRtlIncrementCcFastReadNotPossible(
    VOID
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
NTKERNELAPI
VOID
FsRtlIncrementCcFastReadWait(
    VOID
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
NTKERNELAPI
VOID
FsRtlIncrementCcFastReadNoWait(
    VOID
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
NTKERNELAPI
VOID
FsRtlIncrementCcFastReadResourceMiss(
    VOID
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
NTKERNELAPI
VOID
FsRtlIncrementCcFastMdlReadWait(
    VOID
    );
#endif

//
//  Returns TRUE if the given fileObject represents a paging file, returns
//  FALSE otherwise.
//

#if (NTDDI_VERSION >= NTDDI_WINXP)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
LOGICAL
FsRtlIsPagingFile (
    __in PFILE_OBJECT FileObject
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
//
//  This routine is available on:
//  * Windows 2000 SP4 plus URP
//  * Windows XP SP2 plus QFE ?
//  * Windows Server 2003 SP1
//
__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
NTSTATUS
FsRtlCreateSectionForDataScan(
    __out PHANDLE SectionHandle,
    __deref_out PVOID *SectionObject,
    __out_opt PLARGE_INTEGER SectionFileSize,
    __in PFILE_OBJECT FileObject,
    __in ACCESS_MASK DesiredAccess,
    __in_opt POBJECT_ATTRIBUTES ObjectAttributes,
    __in_opt PLARGE_INTEGER MaximumSize,
    __in ULONG SectionPageProtection,
    __in ULONG AllocationAttributes,
    __in ULONG Flags
    );
#endif

//
// Reparse Routines
//

#if (NTDDI_VERSION >= NTDDI_VISTA)
__checkReturn
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
NTSTATUS
FsRtlValidateReparsePointBuffer (
    __in ULONG BufferLength,
    __in_bcount(BufferLength) PREPARSE_DATA_BUFFER ReparseBuffer
);

__checkReturn
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
NTSTATUS
FsRtlRemoveDotsFromPath(
    __inout_bcount(PathLength) PWSTR OriginalString,
    __in USHORT PathLength,
    __out USHORT *NewLength
);
#endif

// begin_ntosp
//////////////////////////////////////////////////////////////////////////
//
//              Extra Create Parameter Support routines
//
//  These routines are used when processing a create IRP to allow passing
//  extra information up and down the file system stack.  This is used by
//  file system filters, Client Side Encryption, Transactions etc.
//
//////////////////////////////////////////////////////////////////////////

#if (NTDDI_VERSION >= NTDDI_VISTA)
typedef struct _ECP_LIST ECP_LIST;
typedef struct _ECP_LIST *PECP_LIST;
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
typedef struct _ECP_HEADER ECP_HEADER;
typedef struct _ECP_HEADER *PECP_HEADER;
#endif

//
//  Prototype for the ECP cleanup routine callback
//

#if (NTDDI_VERSION >= NTDDI_VISTA)
typedef VOID
(*PFSRTL_EXTRA_CREATE_PARAMETER_CLEANUP_CALLBACK) (
    __inout PVOID EcpContext,
    __in LPCGUID EcpType
    );
#endif



//
//  Basic ECP functions
//

//
//  Flags used by FsRtlAllocateExtraCreateParameterList
//

#if (NTDDI_VERSION >= NTDDI_VISTA)
typedef ULONG FSRTL_ALLOCATE_ECPLIST_FLAGS;

    //
    //  Charge this memory against the quota of the current process
    //

    #define FSRTL_ALLOCATE_ECPLIST_FLAG_CHARGE_QUOTA    0x00000001
#endif


#if (NTDDI_VERSION >= NTDDI_VISTA)
__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
NTSTATUS
FsRtlAllocateExtraCreateParameterList (
    __in FSRTL_ALLOCATE_ECPLIST_FLAGS Flags,
    __deref_out PECP_LIST *EcpList
    );
#endif


#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
FsRtlFreeExtraCreateParameterList (
    __in PECP_LIST EcpList
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
NTKERNELAPI
NTSTATUS
FsRtlInitializeExtraCreateParameterList (
    __inout PECP_LIST EcpList
    );
#endif

//
//  Flags used by FsRtlAllocateExtraCreateParameter
//            and FsRtlAllocateExtraCreateParameterFromLookasideList
//

#if (NTDDI_VERSION >= NTDDI_VISTA)
typedef ULONG FSRTL_ALLOCATE_ECP_FLAGS;

    //
    //  If set charage quota against the current process for this
    //  allocation.  This flag is ignored if using a lookaside list
    //

    #define FSRTL_ALLOCATE_ECP_FLAG_CHARGE_QUOTA    0x00000001

    //
    //  If set allocate the ECP from non-paged pool
    //  Else use paged pool
    //

    #define FSRTL_ALLOCATE_ECP_FLAG_NONPAGED_POOL   0x00000002
#endif


#if (NTDDI_VERSION >= NTDDI_VISTA)
__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
NTSTATUS
FsRtlAllocateExtraCreateParameter (
    __in LPCGUID EcpType,
    __in ULONG SizeOfContext,
    __in FSRTL_ALLOCATE_ECP_FLAGS Flags,
    __in_opt PFSRTL_EXTRA_CREATE_PARAMETER_CLEANUP_CALLBACK CleanupCallback,
    __in ULONG PoolTag,
    __deref_out_bcount(SizeOfContext) PVOID *EcpContext
    );
#endif


#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
FsRtlFreeExtraCreateParameter (
    __in PVOID EcpContext
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
NTKERNELAPI
VOID
FsRtlInitializeExtraCreateParameter(
    __in PECP_HEADER Ecp,
    __in ULONG EcpFlags,
    __in_opt PFSRTL_EXTRA_CREATE_PARAMETER_CLEANUP_CALLBACK CleanupCallback,
    __in ULONG TotalSize,
    __in LPCGUID EcpType,
    __in_opt PVOID ListAllocatedFrom
    );
#endif

//
//  Flags used by FsRtlInitExtraCreateParameterLookasideList
//

#if (NTDDI_VERSION >= NTDDI_VISTA)
typedef ULONG FSRTL_ECP_LOOKASIDE_FLAGS;

    //
    //  If set this is a NON-PAGED lookaside list
    //  ELSE this is a PAGED lookaside list
    //

    #define FSRTL_ECP_LOOKASIDE_FLAG_NONPAGED_POOL 0x00000002
#endif


#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_when(Flags|FSRTL_ECP_LOOKASIDE_FLAG_NONPAGED_POOL, __drv_maxIRQL(DISPATCH_LEVEL))
__drv_when(!(Flags|FSRTL_ECP_LOOKASIDE_FLAG_NONPAGED_POOL), __drv_maxIRQL(APC_LEVEL))
NTKERNELAPI
VOID
FsRtlInitExtraCreateParameterLookasideList (
    __inout PVOID Lookaside,
    __in FSRTL_ECP_LOOKASIDE_FLAGS Flags,
    __in SIZE_T Size,
    __in ULONG Tag
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_when(Flags|FSRTL_ECP_LOOKASIDE_FLAG_NONPAGED_POOL, __drv_maxIRQL(DISPATCH_LEVEL))
__drv_when(!(Flags|FSRTL_ECP_LOOKASIDE_FLAG_NONPAGED_POOL), __drv_maxIRQL(APC_LEVEL))
VOID
FsRtlDeleteExtraCreateParameterLookasideList (
    __inout PVOID Lookaside,
    __in FSRTL_ECP_LOOKASIDE_FLAGS Flags
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
NTSTATUS
FsRtlAllocateExtraCreateParameterFromLookasideList (
    __in LPCGUID EcpType,
    __in_bound ULONG SizeOfContext,
    __in FSRTL_ALLOCATE_ECP_FLAGS Flags,
    __in_opt PFSRTL_EXTRA_CREATE_PARAMETER_CLEANUP_CALLBACK CleanupCallback,
    __inout PVOID LookasideList,
    __deref_out PVOID *EcpContext
    );
#endif


#if (NTDDI_VERSION >= NTDDI_VISTA)
__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
NTSTATUS
FsRtlInsertExtraCreateParameter (
    __inout PECP_LIST EcpList,
    __inout PVOID EcpContext
    );
#endif


#if (NTDDI_VERSION >= NTDDI_VISTA)
__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
NTSTATUS
FsRtlFindExtraCreateParameter (
    __in PECP_LIST EcpList,
    __in LPCGUID EcpType,
    __deref_opt_out PVOID *EcpContext,
    __out_opt ULONG *EcpContextSize
    );
#endif


#if (NTDDI_VERSION >= NTDDI_VISTA)
__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
NTSTATUS
FsRtlRemoveExtraCreateParameter (
    __inout PECP_LIST EcpList,
    __in LPCGUID EcpType,
    __deref_out PVOID *EcpContext,
    __out_opt ULONG *EcpContextSize
    );
#endif

//
//  Functions to get and set Extra Create Parameters into/out of a create IRP
//


#if (NTDDI_VERSION >= NTDDI_VISTA)
__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
NTSTATUS
FsRtlGetEcpListFromIrp (
    __in PIRP Irp,
    __deref_out_opt PECP_LIST *EcpList
    );
#endif


#if (NTDDI_VERSION >= NTDDI_VISTA)
__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
NTSTATUS
FsRtlSetEcpListIntoIrp (
    __inout PIRP Irp,
    __in PECP_LIST EcpList
    );
#endif


//
//   Additional functions used for full functionality
//


#if (NTDDI_VERSION >= NTDDI_VISTA)
__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
NTSTATUS
FsRtlGetNextExtraCreateParameter (
    __in PECP_LIST EcpList,
    __in_opt PVOID CurrentEcpContext,
    __out_opt LPGUID NextEcpType,
    __deref_opt_out PVOID *NextEcpContext,
    __out_opt ULONG *NextEcpContextSize
    );
#endif


#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
VOID
FsRtlAcknowledgeEcp (
    __in PVOID EcpContext
    );
#endif


#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
BOOLEAN
FsRtlIsEcpAcknowledged (
    __in PVOID EcpContext
    );
#endif


#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
BOOLEAN
FsRtlIsEcpFromUserMode (
    __in PVOID EcpContext
    );
#endif

// end_ntosp

//////////////////////////////////////////////////////////////////////////////
//
//      This contains public ECP definitions
//
//////////////////////////////////////////////////////////////////////////////

#if (NTDDI_VERSION >= NTDDI_VISTA)

//
// Start of NETWORK_OPEN_ECP_CONTEXT structures and definitions.
// This ECP can be used as a way to pass extra information at create time
// to network redirectors.
//

typedef enum {

    NetworkOpenLocationAny,         // No restrictions.
    NetworkOpenLocationRemote,      // Restrict to remote only.
    NetworkOpenLocationLoopback     // Restrict to local-machine only.

} NETWORK_OPEN_LOCATION_QUALIFIER;


typedef enum {

    NetworkOpenIntegrityAny,        // No restrictions on signing/encryption etc.
    NetworkOpenIntegrityNone,       // No signing/encryption.
    NetworkOpenIntegritySigned,     // Signed end to end.
    NetworkOpenIntegrityEncrypted,  // encrypted end-end.
    NetworkOpenIntegrityMaximum     // Best available.

} NETWORK_OPEN_INTEGRITY_QUALIFIER;




//
// ECP context for network create parameters.
//


#if (NTDDI_VERSION >= NTDDI_WIN7)

// 
// Below we have the structures and definitions for Win7
//
 
// in flags.

#define NETWORK_OPEN_ECP_IN_FLAG_DISABLE_HANDLE_COLLAPSING 0x1
#define NETWORK_OPEN_ECP_IN_FLAG_DISABLE_HANDLE_DURABILITY 0x2
#define NETWORK_OPEN_ECP_IN_FLAG_FORCE_BUFFERED_SYNCHRONOUS_IO_HACK 0x80000000

typedef struct _NETWORK_OPEN_ECP_CONTEXT {

    USHORT Size;        // Must be set to the size of this structure.
    USHORT Reserved;    // Must be set to zero.

    struct {

        //
        // Pre-create restrictions
        //

        struct {

            NETWORK_OPEN_LOCATION_QUALIFIER Location;
            NETWORK_OPEN_INTEGRITY_QUALIFIER Integrity;
            ULONG Flags;

        } in;

        //
        // Post create information returned to the caller.
        //

        struct {

            NETWORK_OPEN_LOCATION_QUALIFIER Location;
            NETWORK_OPEN_INTEGRITY_QUALIFIER Integrity;
            ULONG Flags;

        } out;

    } DUMMYSTRUCTNAME;

} NETWORK_OPEN_ECP_CONTEXT, *PNETWORK_OPEN_ECP_CONTEXT;

//
// This version of the NETWORK_OPEN_ECP_CONTEXT was used on
// Windows Vista. Drivers interpreting "Network ECP Contexts" on 
// Vista OSes should use this version.
//

typedef struct _NETWORK_OPEN_ECP_CONTEXT_V0 {

    USHORT Size;        // Must be set to the size of this structure.
    USHORT Reserved;    // Must be set to zero.

    struct {

        //
        // Pre-create restrictions
        //

        struct {

            NETWORK_OPEN_LOCATION_QUALIFIER Location;
            NETWORK_OPEN_INTEGRITY_QUALIFIER Integrity;

        } in;

        //
        // Post create information returned to the caller.
        //

        struct {

            NETWORK_OPEN_LOCATION_QUALIFIER Location;
            NETWORK_OPEN_INTEGRITY_QUALIFIER Integrity;

        } out;

    } DUMMYSTRUCTNAME;

} NETWORK_OPEN_ECP_CONTEXT_V0, *PNETWORK_OPEN_ECP_CONTEXT_V0;

#elif (NTDDI_VERSION >= NTDDI_VISTA)

//
// Here is the definition of Network Open ECP for native Vista Drivers.
//

typedef struct _NETWORK_OPEN_ECP_CONTEXT {

    USHORT Size;        // Must be set to the size of this structure.
    USHORT Reserved;    // Must be set to zero.

    struct {

        //
        // Pre-create restrictions
        //

        struct {

            NETWORK_OPEN_LOCATION_QUALIFIER Location;
            NETWORK_OPEN_INTEGRITY_QUALIFIER Integrity;

        } in;

        //
        // Post create information returned to the caller.
        //

        struct {

            NETWORK_OPEN_LOCATION_QUALIFIER Location;
            NETWORK_OPEN_INTEGRITY_QUALIFIER Integrity;

        } out;

    } DUMMYSTRUCTNAME;

} NETWORK_OPEN_ECP_CONTEXT, *PNETWORK_OPEN_ECP_CONTEXT;
#endif

//
//  The GUID used for the NETWORK_OPEN_ECP_CONTEXT structure
//

DEFINE_GUID( GUID_ECP_NETWORK_OPEN_CONTEXT, 0xc584edbf, 0x00df, 0x4d28, 0xb8, 0x84, 0x35, 0xba, 0xca, 0x89, 0x11, 0xe8 );

//
// End NETWORK_OPEN_ECP_CONTEXT definitions
//

#endif //(NTDDI_VERSION >= NTDDI_VISTA)

#if (NTDDI_VERSION >= NTDDI_VISTA)

//
// Start of PREFETCH_OPEN_ECP_CONTEXT structures and definitions.
// This ECP is used to communicate the fact that a given open request is done
// by the prefetcher.
//

//
// ECP structure for prefetcher opens.
//

typedef struct _PREFETCH_OPEN_ECP_CONTEXT {

    PVOID Context;      // Opaque context associated with the open.

} PREFETCH_OPEN_ECP_CONTEXT, *PPREFETCH_OPEN_ECP_CONTEXT;

//
//  The GUID used for the PREFETCH_OPEN_ECP_CONTEXT structure
//

DEFINE_GUID( GUID_ECP_PREFETCH_OPEN, 0xe1777b21, 0x847e, 0x4837, 0xaa, 0x45, 0x64, 0x16, 0x1d, 0x28, 0x6, 0x55 );

//
// End PREFETCH_OPEN_ECP_CONTEXT definitions
//

#endif


#if (NTDDI_VERSION >= NTDDI_WIN7)
//
//  The type GUID and structure for NFS (Network File System) extra create parameters
//
//
// {f326d30c-e5f8-4fe7-ab74-f5a3196d92db}
//

typedef struct sockaddr_storage *PSOCKADDR_STORAGE_NFS;


DEFINE_GUID (GUID_ECP_NFS_OPEN,
             0xf326d30c,
             0xe5f8,
             0x4fe7,
             0xab, 0x74, 0xf5, 0xa3, 0x19, 0x6d, 0x92, 0xdb);


typedef struct _NFS_OPEN_ECP_CONTEXT {

    //
    //  Export alias (share name) for the create with type PUNICODE_STRING. This is a
    //  hint and may be a name, NULL or zero length string
    //
    PUNICODE_STRING             ExportAlias;


    //
    // Socket address of client
    //
    PSOCKADDR_STORAGE_NFS       ClientSocketAddress;

} NFS_OPEN_ECP_CONTEXT, *PNFS_OPEN_ECP_CONTEXT, **PPNFS_OPEN_ECP_CONTEXT;

//
// ECP context for SRV create parameters.
//

//
// The GUID used for the SRV_OPEN_ECP_CONTEXT structure
// {BEBFAEBC-AABF-489d-9D2C-E9E361102853}
//
//typedef struct sockaddr_storage *PSOCKADDR_STORAGE_SMB;

DEFINE_GUID( GUID_ECP_SRV_OPEN,
             0xbebfaebc,
             0xaabf,
             0x489d,
             0x9d, 0x2c, 0xe9, 0xe3, 0x61, 0x10, 0x28, 0x53 );

typedef struct _SRV_OPEN_ECP_CONTEXT {

    //
    //  Share name for the create with type PUNICODE_STRING
    //

    PUNICODE_STRING ShareName;

    //
    // Socket address of client
    //

    PSOCKADDR_STORAGE_NFS SocketAddress;

    //
    //  Oplock state of open (for SMB/SMB2 oplock breaking logic)
    //

    BOOLEAN OplockBlockState;
    BOOLEAN OplockAppState;
    BOOLEAN OplockFinalState;

} SRV_OPEN_ECP_CONTEXT, *PSRV_OPEN_ECP_CONTEXT;

//
// End SRV_OPEN_ECP_CONTEXT definitions
//

#endif //(NTDDI_VERSION >= NTDDI_WIN7)



//
//  This routine allows the caller to change the referenced file object that
//  is pointed to by either:
//  - One of Mm's image control areas for this stream
//  - Mm's data control area for this stream
//  - Cc's shared cache map for this stream
//

#if (NTDDI_VERSION >= NTDDI_VISTA)
typedef enum _FSRTL_CHANGE_BACKING_TYPE {

    ChangeDataControlArea,
    ChangeImageControlArea,
    ChangeSharedCacheMap

} FSRTL_CHANGE_BACKING_TYPE, *PFSRTL_CHANGE_BACKING_TYPE;

__checkReturn
__drv_maxIRQL(PASSIVE_LEVEL)
NTKERNELAPI
NTSTATUS
FsRtlChangeBackingFileObject (
    __in_opt PFILE_OBJECT CurrentFileObject,
    __in PFILE_OBJECT NewFileObject,
    __in FSRTL_CHANGE_BACKING_TYPE ChangeBackingType,
    __in ULONG Flags                //reserved, must be zero
    );

#endif

//
// Flags for FsRtlLogCcFlushError
//

#define FSRTL_CC_FLUSH_ERROR_FLAG_NO_HARD_ERROR  0x1
#define FSRTL_CC_FLUSH_ERROR_FLAG_NO_LOG_ENTRY   0x2

#if (NTDDI_VERSION >= NTDDI_VISTA)

__checkReturn
__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
NTSTATUS
FsRtlLogCcFlushError(
    __in PUNICODE_STRING FileName,
    __in PDEVICE_OBJECT DeviceObject,
    __in PSECTION_OBJECT_POINTERS SectionObjectPointer,
    __in NTSTATUS FlushError,
    __in ULONG Flags
    );

#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)

//
//  Routine to query whether volume startup application such as autochk
//  have completed.
//

__drv_maxIRQL(APC_LEVEL)
NTKERNELAPI
BOOLEAN
FsRtlAreVolumeStartupApplicationsComplete(
    VOID
    );

#endif

// begin_ntosp

#if (NTDDI_VERSION > NTDDI_VISTA)

//
//  Routine to query maximum depth of virtual disk layering support.
//

NTKERNELAPI
ULONG
FsRtlQueryMaximumVirtualDiskNestingLevel (
    VOID
    );

//
//  Routine to query virtual disk info for a given disk or volume object
//

NTKERNELAPI
NTSTATUS
FsRtlGetVirtualDiskNestingLevel (
    __in PDEVICE_OBJECT DeviceObject,
    __out PULONG NestingLevel,
    __out_opt PULONG NestingFlags
    );

//
//  Current possible values for NestingFlags.
//

#define FSRTL_VIRTDISK_FULLY_ALLOCATED  0x00000001
#define FSRTL_VIRTDISK_NO_DRIVE_LETTER  0x00000002

#endif

//
//  Define two constants describing the view size (and alignment)
//  that the Cache Manager uses to map files.
//

#define VACB_MAPPING_GRANULARITY         (0x40000)
#define VACB_OFFSET_SHIFT                (18)

//
// Public portion of BCB
//

typedef struct _PUBLIC_BCB {

    //
    // Type and size of this record
    //
    // NOTE: The first four fields must be the same as the BCB in cc.h.
    //

    CSHORT NodeTypeCode;
    CSHORT NodeByteSize;

    //
    // Description of range of file which is currently mapped.
    //

    ULONG MappedLength;
    LARGE_INTEGER MappedFileOffset;
} PUBLIC_BCB, *PPUBLIC_BCB;

//
//  File Sizes structure.
//

typedef struct _CC_FILE_SIZES {

    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER FileSize;
    LARGE_INTEGER ValidDataLength;

} CC_FILE_SIZES, *PCC_FILE_SIZES;

//
// Define a Cache Manager callback structure.  These routines are required
// by the Lazy Writer, so that it can acquire resources in the right order
// to avoid deadlocks.  Note that otherwise you would have most FS requests
// acquiring FS resources first and caching structures second, while the
// Lazy Writer needs to acquire its own resources first, and then FS
// structures later as it calls the file system.
//

//
// First define the procedure pointer typedefs
//

//
// This routine is called by the Lazy Writer prior to doing a write,
// since this will require some file system resources associated with
// this cached file. The context parameter supplied is whatever the FS
// passed as the LazyWriteContext parameter when is called
// CcInitializeCacheMap.
//

typedef
BOOLEAN (*PACQUIRE_FOR_LAZY_WRITE) (
     __in PVOID Context,
     __in BOOLEAN Wait
     );

//
// This routine releases the Context acquired above.
//

typedef
VOID (*PRELEASE_FROM_LAZY_WRITE) (
     __in PVOID Context
     );

//
// This routine is called by the Lazy Writer prior to doing a readahead.
//

typedef
BOOLEAN (*PACQUIRE_FOR_READ_AHEAD) (
     __in PVOID Context,
     __in BOOLEAN Wait
     );

//
// This routine releases the Context acquired above.
//

typedef
VOID (*PRELEASE_FROM_READ_AHEAD) (
     __in PVOID Context
     );

typedef struct _CACHE_MANAGER_CALLBACKS {

    PACQUIRE_FOR_LAZY_WRITE AcquireForLazyWrite;
    PRELEASE_FROM_LAZY_WRITE ReleaseFromLazyWrite;
    PACQUIRE_FOR_READ_AHEAD AcquireForReadAhead;
    PRELEASE_FROM_READ_AHEAD ReleaseFromReadAhead;

} CACHE_MANAGER_CALLBACKS, *PCACHE_MANAGER_CALLBACKS;

//
//  This structure is passed into CcUninitializeCacheMap
//  if the caller wants to know when the cache map is deleted.
//

typedef struct _CACHE_UNINITIALIZE_EVENT {
    struct _CACHE_UNINITIALIZE_EVENT *Next;
    KEVENT Event;
} CACHE_UNINITIALIZE_EVENT, *PCACHE_UNINITIALIZE_EVENT;

//
// Callback routine for retrieving dirty pages from Cache Manager.
//

typedef
VOID (*PDIRTY_PAGE_ROUTINE) (
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in PLARGE_INTEGER OldestLsn,
    __in PLARGE_INTEGER NewestLsn,
    __in PVOID Context1,
    __in PVOID Context2
    );

//
// Callback routine for doing log file flushes to Lsn.
//

typedef
VOID (*PFLUSH_TO_LSN) (
    __in PVOID LogHandle,
    __in LARGE_INTEGER Lsn
    );

//
// Macro to test whether a file is cached or not.
//

#define CcIsFileCached(FO) (                                                         \
    ((FO)->SectionObjectPointer != NULL) &&                                          \
    (((PSECTION_OBJECT_POINTERS)(FO)->SectionObjectPointer)->SharedCacheMap != NULL) \
)

extern ULONG CcFastMdlReadWait;

//
// The following routines are intended for use by File Systems Only.
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
CcInitializeCacheMap (
    __in PFILE_OBJECT FileObject,
    __in PCC_FILE_SIZES FileSizes,
    __in BOOLEAN PinAccess,
    __in PCACHE_MANAGER_CALLBACKS Callbacks,
    __in PVOID LazyWriteContext
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
BOOLEAN
CcUninitializeCacheMap (
    __in PFILE_OBJECT FileObject,
    __in_opt PLARGE_INTEGER TruncateSize,
    __in_opt PCACHE_UNINITIALIZE_EVENT UninitializeEvent
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
CcSetFileSizes (
    __in PFILE_OBJECT FileObject,
    __in PCC_FILE_SIZES FileSizes
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
NTKERNELAPI
NTSTATUS
CcSetFileSizesEx (
    __in PFILE_OBJECT FileObject,
    __in PCC_FILE_SIZES FileSizes
    );
#endif

#define CcGetFileSizePointer(FO) (                                     \
    ((PLARGE_INTEGER)((FO)->SectionObjectPointer->SharedCacheMap) + 1) \
)

//
//  Flags for CcPurgeCacheSection
//

//
//  UNINITIALIZE_CACHE_MAPS - All private cache maps will be uninitialized
//     before purging the data.  This pattern may be specified as TRUE.
//

#define UNINITIALIZE_CACHE_MAPS          (1)

//
//  DO_NOT_RETRY_PURGE - CcPurgeCacheSection will not retry purging the file
//     on purge failure even if Mm says the file can be truncated.  The return
//     value will specify whether or not the purge succeeded.
//

#define DO_NOT_RETRY_PURGE               (2)

//
//  DO_NOT_PURGE_DIRTY_PAGES - Instructs CcPurgeCacheSection to fail any
//      purge requests that would cause the caller to throw away dirty data. This
//      flag should be used when initiating a coherency flush/purge to ensure that
//      the file system does not throw away data generated in the gap between a
//      flush and purge.
//

#define DO_NOT_PURGE_DIRTY_PAGES         (0x4)

#if (NTDDI_VERSION >= NTDDI_VISTA)
NTKERNELAPI
BOOLEAN
CcPurgeCacheSection (
    __in PSECTION_OBJECT_POINTERS SectionObjectPointer,
    __in_opt PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in ULONG Flags
    );

#elif (NTDDI_VERSION >= NTDDI_WIN2K)

NTKERNELAPI
BOOLEAN
CcPurgeCacheSection (
    __in PSECTION_OBJECT_POINTERS SectionObjectPointer,
    __in_opt PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in BOOLEAN UninitializeCacheMaps
    );
#endif

#define CC_FLUSH_AND_PURGE_NO_PURGE     (0x1)

#if (NTDDI_VERSION >= NTDDI_WIN7)
NTKERNELAPI
VOID
CcCoherencyFlushAndPurgeCache (
    __in PSECTION_OBJECT_POINTERS SectionObjectPointer,
    __in_opt PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __out PIO_STATUS_BLOCK IoStatus,
    __in_opt ULONG Flags
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
CcSetDirtyPageThreshold (
    __in PFILE_OBJECT FileObject,
    __in ULONG DirtyPageThreshold
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
CcFlushCache (
    __in PSECTION_OBJECT_POINTERS SectionObjectPointer,
    __in_opt PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __out_opt PIO_STATUS_BLOCK IoStatus
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
LARGE_INTEGER
CcGetFlushedValidData (
    __in PSECTION_OBJECT_POINTERS SectionObjectPointer,
    __in BOOLEAN BcbListHeld
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
BOOLEAN
CcZeroData (
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER StartOffset,
    __in PLARGE_INTEGER EndOffset,
    __in BOOLEAN Wait
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
PVOID
CcRemapBcb (
    __in PVOID Bcb
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
CcRepinBcb (
    __in PVOID Bcb
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
CcUnpinRepinnedBcb (
    __in PVOID Bcb,
    __in BOOLEAN WriteThrough,
    __out PIO_STATUS_BLOCK IoStatus
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
PFILE_OBJECT
CcGetFileObjectFromSectionPtrs (
    __in PSECTION_OBJECT_POINTERS SectionObjectPointer
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
NTKERNELAPI
PFILE_OBJECT
CcGetFileObjectFromSectionPtrsRef (
    __in PSECTION_OBJECT_POINTERS SectionObjectPointer
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
PFILE_OBJECT
CcGetFileObjectFromBcb (
    __in PVOID Bcb
    );
#endif


//
// These routines are implemented to support write throttling.
//

//
//  BOOLEAN
//  CcCopyWriteWontFlush (
//      IN PFILE_OBJECT FileObject,
//      IN PLARGE_INTEGER FileOffset,
//      IN ULONG Length
//      );
//

#if (NTDDI_VERSION >= NTDDI_WIN7)
NTKERNELAPI
BOOLEAN 
CcCopyWriteWontFlush (
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length 
    );
#else
#define CcCopyWriteWontFlush(FO,FOFF,LEN) ((LEN) <= 0X1000000)
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
BOOLEAN
CcCanIWrite (
    __in PFILE_OBJECT FileObject,
    __in ULONG BytesToWrite,
    __in BOOLEAN Wait,
    __in UCHAR Retrying
    );
#endif

typedef
VOID (*PCC_POST_DEFERRED_WRITE) (
    __in PVOID Context1,
    __in PVOID Context2
    );

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
CcDeferWrite (
    __in PFILE_OBJECT FileObject,
    __in PCC_POST_DEFERRED_WRITE PostRoutine,
    __in PVOID Context1,
    __in PVOID Context2,
    __in ULONG BytesToWrite,
    __in BOOLEAN Retrying
    );
#endif

//
// The following routines provide a data copy interface to the cache, and
// are intended for use by File Servers and File Systems.
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
BOOLEAN
CcCopyRead (
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in BOOLEAN Wait,
    __out_bcount(Length) PVOID Buffer,
    __out PIO_STATUS_BLOCK IoStatus
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
CcFastCopyRead (
    __in PFILE_OBJECT FileObject,
    __in ULONG FileOffset,
    __in ULONG Length,
    __in ULONG PageCount,
    __out_bcount(Length) PVOID Buffer,
    __out PIO_STATUS_BLOCK IoStatus
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
BOOLEAN
CcCopyWrite (
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in BOOLEAN Wait,
    __in_bcount(Length) PVOID Buffer
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
CcFastCopyWrite (
    __in PFILE_OBJECT FileObject,
    __in ULONG FileOffset,
    __in ULONG Length,
    __in_bcount(Length) PVOID Buffer
    );
#endif

//
//  The following routines provide an Mdl interface for transfers to and
//  from the cache, and are primarily intended for File Servers.
//
//  NOBODY SHOULD BE CALLING THESE MDL ROUTINES DIRECTLY, USE FSRTL AND
//  FASTIO INTERFACES.
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
CcMdlRead (
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __out PMDL *MdlChain,
    __out PIO_STATUS_BLOCK IoStatus
    );
#endif

//
//  This routine is now a wrapper for FastIo if present or CcMdlReadComplete2
//
#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
CcMdlReadComplete (
    __in PFILE_OBJECT FileObject,
    __in PMDL MdlChain
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
CcPrepareMdlWrite (
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __out PMDL *MdlChain,
    __out PIO_STATUS_BLOCK IoStatus
    );
#endif
//
//  This routine is now a wrapper for FastIo if present or CcMdlWriteComplete2
//
#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
CcMdlWriteComplete (
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in PMDL MdlChain
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
NTKERNELAPI
VOID
CcMdlWriteAbort (
    __in PFILE_OBJECT FileObject,
    __in PMDL MdlChain
    );
#endif // NTDDI_VERSION >= NTDDI_WINXP

//
// Common ReadAhead call for Copy Read and Mdl Read.
//
// ReadAhead should always be invoked by calling the CcReadAhead macro,
// which tests first to see if the read is large enough to warrant read
// ahead.  Measurements have shown that, calling the read ahead routine
// actually decreases performance for small reads, such as issued by
// many compilers and linkers.  Compilers simply want all of the include
// files to stay in memory after being read the first time.
//

#define CcReadAhead(FO,FOFF,LEN) {                       \
    if ((LEN) >= 256) {                                  \
        CcScheduleReadAhead((FO),(FOFF),(LEN));          \
    }                                                    \
}

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
CcScheduleReadAhead (
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length
    );
#endif

//
//  The following routine allows a caller to wait for the next batch
//  of lazy writer work to complete.  In particular, this provides a
//  mechanism for a caller to be sure that all avaliable lazy closes
//  at the time of this call have issued.
//
#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
CcWaitForCurrentLazyWriterActivity (
    VOID
    );
#endif

//
// This routine changes the read ahead granularity for a file, which is
// PAGE_SIZE by default.
//
#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
CcSetReadAheadGranularity (
    __in PFILE_OBJECT FileObject,
    __in ULONG Granularity
    );
#endif

//
// The following routines provide direct access data which is pinned in the
// cache, and is primarily intended for use by File Systems.  In particular,
// this mode of access is ideal for dealing with volume structures.
//

//
//  Flags for pinning
//
//  Note: The flags for pinning and the flags for mapping cannot overlap unless
//     the flag has the same meaning.
//

//
//  Synchronous Wait - normally specified.  This pattern may be specified as TRUE.
//

#define PIN_WAIT                         (1)

//
//  Acquire metadata Bcb exclusive (default is shared, Lazy Writer uses exclusive).
//
//  Must be set with PIN_WAIT.
//

#define PIN_EXCLUSIVE                    (2)

//
//  Acquire metadata Bcb but do not fault data in.  Default is to fault the data in.
//  This unusual flag is only used by Ntfs for cache coherency synchronization between
//  compressed and uncompressed streams for the same compressed file.
//
//  Must be set with PIN_WAIT.
//

#define PIN_NO_READ                      (4)

//
//  This option may be used to pin data only if the Bcb already exists.  If the Bcb
//  does not already exist - the pin is unsuccessful and no Bcb is returned.  This routine
//  provides a way to see if data is already pinned (and possibly dirty) in the cache,
//  without forcing a fault if the data is not there.
//

#define PIN_IF_BCB                       (8)

//
//  If this option is specified, the caller is responsible for tracking the
//  dirty ranges and calling MmSetAddressRangeModified on these ranges before
//  they are flushed.  Ranges should only be pinned via this manner if the
//  entire range will be written or purged (one or the other must occur).
//

#define PIN_CALLER_TRACKS_DIRTY_DATA      (32)

//
//  If this option is specified, Cc will used reserved views to map the data
//  requested if Mm has no views to give Cc at the time of mapping the data.
//  This flag should only be used for critical data, like file system metadata
//  or other data critical to the file system remaining consistent.  This is
//  a best effort attempt to ensure that we have enough kernel VA space for
//  critical system mappings, but once they are all gone, the call will fail
//  with insufficient resources.
//
//

#define PIN_HIGH_PRIORITY                 (64)

//
//  Flags for mapping
//

//
//  Synchronous Wait - normally specified.  This pattern may be specified as TRUE.
//

#define MAP_WAIT                          (1)

//
//  Acquire metadata Bcb but do not fault data in.  Default is to fault the data in.
//  This should not overlap with any of the PIN_ flags so they can be passed down to
//  CcPinFileData
//

#define MAP_NO_READ                       (16)

//
//  If this option is specified, Cc will used reserved views to map the data
//  requested if Mm has no views to give Cc at the time of mapping the data.
//  This flag should only be used for critical data, like file system metadata
//  or other data critical to the file system remaining consistent.  This is
//  a best effort attempt to ensure that we have enough kernel VA space for
//  critical system mappings, but once they are all gone, the call will fail
//  with insufficient resources.
//
//

#define MAP_HIGH_PRIORITY                 (64)


#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
BOOLEAN
CcPinRead (
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in ULONG Flags,
    __deref_out PVOID *Bcb,
    __deref_out_bcount(Length) PVOID *Buffer
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
NTKERNELAPI
BOOLEAN
CcMapData (
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in ULONG Flags,
    __deref_out PVOID *Bcb,
    __deref_out_bcount(Length) PVOID *Buffer
    );
#elif (NTDDI_VERSION >= NTDDI_WIN2K)

NTKERNELAPI
BOOLEAN
CcMapData (
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in BOOLEAN Wait,
    __deref_out PVOID *Bcb,
    __deref_out_bcount(Length) PVOID *Buffer
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
BOOLEAN
CcPinMappedData (
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in ULONG Flags,
    __deref_inout PVOID *Bcb
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
BOOLEAN
CcPreparePinWrite (
    __in PFILE_OBJECT FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in BOOLEAN Zero,
    __in ULONG Flags,
    __deref_out PVOID *Bcb,
    __deref_out_bcount(Length) PVOID *Buffer
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
CcSetDirtyPinnedData (
    __in PVOID BcbVoid,
    __in_opt PLARGE_INTEGER Lsn
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
CcUnpinData (
    __in PVOID Bcb
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
CcSetBcbOwnerPointer (
    __in PVOID Bcb,
    __in PVOID OwnerPointer
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
CcUnpinDataForThread (
    __in PVOID Bcb,
    __in ERESOURCE_THREAD ResourceThreadId
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
CcSetAdditionalCacheAttributes (
    __in PFILE_OBJECT FileObject,
    __in BOOLEAN DisableReadAhead,
    __in BOOLEAN DisableWriteBehind
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
NTKERNELAPI
VOID
CcSetParallelFlushFile (
    __in PFILE_OBJECT FileObject,
    __in BOOLEAN EnableParallelFlush
    );
#endif // NTDDI_VERSION >= NTDDI_VISTA

#if (NTDDI_VERSION >= NTDDI_WINXP)
NTKERNELAPI
VOID
CcSetLogHandleForFile (
    __in PFILE_OBJECT FileObject,
    __in PVOID LogHandle,
    __in PFLUSH_TO_LSN FlushToLsnRoutine
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
NTKERNELAPI
LARGE_INTEGER
CcGetDirtyPages (
    __in PVOID LogHandle,
    __in PDIRTY_PAGE_ROUTINE DirtyPageRoutine,
    __in PVOID Context1,
    __in PVOID Context2
    );
#endif // NTDDI_VERSION >= NTDDI_WINXP

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
BOOLEAN
CcIsThereDirtyData (
    __in PVPB Vpb
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
NTKERNELAPI
BOOLEAN
CcIsThereDirtyDataEx (
    __in PVPB Vpb,
    __in_opt PULONG NumberOfDirtyPages
    );
#endif

#ifndef __SSPI_H__
#define __SSPI_H__
#define ISSP_LEVEL  32          
#define ISSP_MODE   0           

#if defined(_NO_KSECDD_IMPORT_)

#define KSECDDDECLSPEC

#else

#define KSECDDDECLSPEC __declspec(dllimport)

#endif

typedef WCHAR SEC_WCHAR;
typedef CHAR SEC_CHAR;

#ifndef __SECSTATUS_DEFINED__
typedef LONG SECURITY_STATUS;
#define __SECSTATUS_DEFINED__
#endif

#define SEC_TEXT TEXT
#define SEC_FAR
#define SEC_ENTRY __stdcall


#ifndef __SECHANDLE_DEFINED__
typedef struct _SecHandle
{
    ULONG_PTR dwLower ;
    ULONG_PTR dwUpper ;
} SecHandle, * PSecHandle ;

#define __SECHANDLE_DEFINED__
#endif // __SECHANDLE_DEFINED__

#define SecInvalidateHandle( x )    \
            ((PSecHandle) (x))->dwLower = ((PSecHandle) (x))->dwUpper = ((ULONG_PTR) ((INT_PTR)-1)) ;

#define SecIsValidHandle( x ) \
            ( ( ((PSecHandle) (x))->dwLower != ((ULONG_PTR) ((INT_PTR) -1 ))) && \
              ( ((PSecHandle) (x))->dwUpper != ((ULONG_PTR) ((INT_PTR) -1 ))) )

//
// pseudo handle value: the handle has already been deleted
//

#define SEC_DELETED_HANDLE  ((ULONG_PTR) (-2))

typedef SecHandle CredHandle;
typedef PSecHandle PCredHandle;

typedef SecHandle CtxtHandle;
typedef PSecHandle PCtxtHandle;

typedef LARGE_INTEGER _SECURITY_INTEGER, SECURITY_INTEGER, *PSECURITY_INTEGER; 
typedef SECURITY_INTEGER TimeStamp;                 
typedef SECURITY_INTEGER * PTimeStamp;      
typedef UNICODE_STRING SECURITY_STRING, *PSECURITY_STRING;  

//
// SecPkgInfo structure
//
//  Provides general information about a security provider
//

typedef struct _SecPkgInfoW
{
    unsigned long fCapabilities;        // Capability bitmask
    unsigned short wVersion;            // Version of driver
    unsigned short wRPCID;              // ID for RPC Runtime
    unsigned long cbMaxToken;           // Size of authentication token (max)
#ifdef MIDL_PASS
    [string]
#endif
    SEC_WCHAR * Name;           // Text name

#ifdef MIDL_PASS
    [string]
#endif
    SEC_WCHAR * Comment;        // Comment
} SecPkgInfoW, * PSecPkgInfoW;

#  define SecPkgInfo SecPkgInfoW        
#  define PSecPkgInfo PSecPkgInfoW      

//
//  Security Package Capabilities
//
#define SECPKG_FLAG_INTEGRITY                   0x00000001  // Supports integrity on messages
#define SECPKG_FLAG_PRIVACY                     0x00000002  // Supports privacy (confidentiality)
#define SECPKG_FLAG_TOKEN_ONLY                  0x00000004  // Only security token needed
#define SECPKG_FLAG_DATAGRAM                    0x00000008  // Datagram RPC support
#define SECPKG_FLAG_CONNECTION                  0x00000010  // Connection oriented RPC support
#define SECPKG_FLAG_MULTI_REQUIRED              0x00000020  // Full 3-leg required for re-auth.
#define SECPKG_FLAG_CLIENT_ONLY                 0x00000040  // Server side functionality not available
#define SECPKG_FLAG_EXTENDED_ERROR              0x00000080  // Supports extended error msgs
#define SECPKG_FLAG_IMPERSONATION               0x00000100  // Supports impersonation
#define SECPKG_FLAG_ACCEPT_WIN32_NAME           0x00000200  // Accepts Win32 names
#define SECPKG_FLAG_STREAM                      0x00000400  // Supports stream semantics
#define SECPKG_FLAG_NEGOTIABLE                  0x00000800  // Can be used by the negotiate package
#define SECPKG_FLAG_GSS_COMPATIBLE              0x00001000  // GSS Compatibility Available
#define SECPKG_FLAG_LOGON                       0x00002000  // Supports common LsaLogonUser
#define SECPKG_FLAG_ASCII_BUFFERS               0x00004000  // Token Buffers are in ASCII
#define SECPKG_FLAG_FRAGMENT                    0x00008000  // Package can fragment to fit
#define SECPKG_FLAG_MUTUAL_AUTH                 0x00010000  // Package can perform mutual authentication
#define SECPKG_FLAG_DELEGATION                  0x00020000  // Package can delegate
#define SECPKG_FLAG_READONLY_WITH_CHECKSUM      0x00040000  // Package can delegate
#define SECPKG_FLAG_RESTRICTED_TOKENS           0x00080000  // Package supports restricted callers
#define SECPKG_FLAG_NEGO_EXTENDER               0x00100000  // this package extends SPNEGO, there is at most one
#define SECPKG_FLAG_NEGOTIABLE2                 0x00200000  // this package is negotiated under the NegoExtender

#define SECPKG_ID_NONE      0xFFFF


//
// SecBuffer
//
//  Generic memory descriptors for buffers passed in to the security
//  API
//

typedef struct _SecBuffer {
    unsigned long cbBuffer;             // Size of the buffer, in bytes
    unsigned long BufferType;           // Type of the buffer (below)
#ifdef MIDL_PASS
    [size_is(cbBuffer)] char * pvBuffer;                         // Pointer to the buffer
#else
    __field_bcount(cbBuffer) void SEC_FAR * pvBuffer;            // Pointer to the buffer
#endif
} SecBuffer, * PSecBuffer;

typedef struct _SecBufferDesc {
    unsigned long ulVersion;            // Version number
    unsigned long cBuffers;             // Number of buffers
#ifdef MIDL_PASS
    [size_is(cBuffers)]
#endif
    __field_ecount(cBuffers) PSecBuffer pBuffers;                // Pointer to array of buffers
} SecBufferDesc, SEC_FAR * PSecBufferDesc;

#define SECBUFFER_VERSION           0

#define SECBUFFER_EMPTY             0   // Undefined, replaced by provider
#define SECBUFFER_DATA              1   // Packet data
#define SECBUFFER_TOKEN             2   // Security token
#define SECBUFFER_PKG_PARAMS        3   // Package specific parameters
#define SECBUFFER_MISSING           4   // Missing Data indicator
#define SECBUFFER_EXTRA             5   // Extra data
#define SECBUFFER_STREAM_TRAILER    6   // Security Trailer
#define SECBUFFER_STREAM_HEADER     7   // Security Header
#define SECBUFFER_NEGOTIATION_INFO  8   // Hints from the negotiation pkg
#define SECBUFFER_PADDING           9   // non-data padding
#define SECBUFFER_STREAM            10  // whole encrypted message
#define SECBUFFER_MECHLIST          11
#define SECBUFFER_MECHLIST_SIGNATURE 12
#define SECBUFFER_TARGET            13  // obsolete
#define SECBUFFER_CHANNEL_BINDINGS  14
#define SECBUFFER_CHANGE_PASS_RESPONSE 15
#define SECBUFFER_TARGET_HOST       16
#define SECBUFFER_ALERT             17

#define SECBUFFER_ATTRMASK                      0xF0000000
#define SECBUFFER_READONLY                      0x80000000  // Buffer is read-only, no checksum
#define SECBUFFER_READONLY_WITH_CHECKSUM        0x10000000  // Buffer is read-only, and checksummed
#define SECBUFFER_RESERVED                      0x60000000  // Flags reserved to security system


typedef struct _SEC_NEGOTIATION_INFO {
    unsigned long       Size;           // Size of this structure
    unsigned long       NameLength;     // Length of name hint
    SEC_WCHAR * Name;           // Name hint
    void *      Reserved;       // Reserved
} SEC_NEGOTIATION_INFO, * PSEC_NEGOTIATION_INFO ;

typedef struct _SEC_CHANNEL_BINDINGS {
    unsigned long  dwInitiatorAddrType;
    unsigned long  cbInitiatorLength;
    unsigned long  dwInitiatorOffset;
    unsigned long  dwAcceptorAddrType;
    unsigned long  cbAcceptorLength;
    unsigned long  dwAcceptorOffset;
    unsigned long  cbApplicationDataLength;
    unsigned long  dwApplicationDataOffset;
} SEC_CHANNEL_BINDINGS, * PSEC_CHANNEL_BINDINGS ;


//
//  Data Representation Constant:
//
#define SECURITY_NATIVE_DREP        0x00000010
#define SECURITY_NETWORK_DREP       0x00000000

//
//  Credential Use Flags
//
#define SECPKG_CRED_INBOUND         0x00000001
#define SECPKG_CRED_OUTBOUND        0x00000002
#define SECPKG_CRED_BOTH            0x00000003
#define SECPKG_CRED_DEFAULT         0x00000004
#define SECPKG_CRED_RESERVED        0xF0000000

//
//  SSP SHOULD prompt the user for credentials/consent, independent
//  of whether credentials to be used are the 'logged on' credentials
//  or retrieved from credman.
//
//  An SSP may choose not to prompt, however, in circumstances determined
//  by the SSP.
//

#define SECPKG_CRED_AUTOLOGON_RESTRICTED    0x00000010

//
// auth will always fail, ISC() is called to process policy data only
//

#define SECPKG_CRED_PROCESS_POLICY_ONLY     0x00000020

//
//  InitializeSecurityContext Requirement and return flags:
//

#define ISC_REQ_DELEGATE                0x00000001
#define ISC_REQ_MUTUAL_AUTH             0x00000002
#define ISC_REQ_REPLAY_DETECT           0x00000004
#define ISC_REQ_SEQUENCE_DETECT         0x00000008
#define ISC_REQ_CONFIDENTIALITY         0x00000010
#define ISC_REQ_USE_SESSION_KEY         0x00000020
#define ISC_REQ_PROMPT_FOR_CREDS        0x00000040
#define ISC_REQ_USE_SUPPLIED_CREDS      0x00000080
#define ISC_REQ_ALLOCATE_MEMORY         0x00000100
#define ISC_REQ_USE_DCE_STYLE           0x00000200
#define ISC_REQ_DATAGRAM                0x00000400
#define ISC_REQ_CONNECTION              0x00000800
#define ISC_REQ_CALL_LEVEL              0x00001000
#define ISC_REQ_FRAGMENT_SUPPLIED       0x00002000
#define ISC_REQ_EXTENDED_ERROR          0x00004000
#define ISC_REQ_STREAM                  0x00008000
#define ISC_REQ_INTEGRITY               0x00010000
#define ISC_REQ_IDENTIFY                0x00020000
#define ISC_REQ_NULL_SESSION            0x00040000
#define ISC_REQ_MANUAL_CRED_VALIDATION  0x00080000
#define ISC_REQ_RESERVED1               0x00100000
#define ISC_REQ_FRAGMENT_TO_FIT         0x00200000
// This exists only in Windows Vista and greater
#define ISC_REQ_FORWARD_CREDENTIALS     0x00400000
#define ISC_REQ_NO_INTEGRITY            0x00800000 // honored only by SPNEGO
#define ISC_REQ_USE_HTTP_STYLE          0x01000000

#define ISC_RET_DELEGATE                0x00000001
#define ISC_RET_MUTUAL_AUTH             0x00000002
#define ISC_RET_REPLAY_DETECT           0x00000004
#define ISC_RET_SEQUENCE_DETECT         0x00000008
#define ISC_RET_CONFIDENTIALITY         0x00000010
#define ISC_RET_USE_SESSION_KEY         0x00000020
#define ISC_RET_USED_COLLECTED_CREDS    0x00000040
#define ISC_RET_USED_SUPPLIED_CREDS     0x00000080
#define ISC_RET_ALLOCATED_MEMORY        0x00000100
#define ISC_RET_USED_DCE_STYLE          0x00000200
#define ISC_RET_DATAGRAM                0x00000400
#define ISC_RET_CONNECTION              0x00000800
#define ISC_RET_INTERMEDIATE_RETURN     0x00001000
#define ISC_RET_CALL_LEVEL              0x00002000
#define ISC_RET_EXTENDED_ERROR          0x00004000
#define ISC_RET_STREAM                  0x00008000
#define ISC_RET_INTEGRITY               0x00010000
#define ISC_RET_IDENTIFY                0x00020000
#define ISC_RET_NULL_SESSION            0x00040000
#define ISC_RET_MANUAL_CRED_VALIDATION  0x00080000
#define ISC_RET_RESERVED1               0x00100000
#define ISC_RET_FRAGMENT_ONLY           0x00200000
// This exists only in Windows Vista and greater
#define ISC_RET_FORWARD_CREDENTIALS     0x00400000

#define ISC_RET_USED_HTTP_STYLE         0x01000000
#define ISC_RET_NO_ADDITIONAL_TOKEN     0x02000000  // *INTERNAL*
#define ISC_RET_REAUTHENTICATION        0x08000000  // *INTERNAL*

#define ASC_REQ_DELEGATE                0x00000001
#define ASC_REQ_MUTUAL_AUTH             0x00000002
#define ASC_REQ_REPLAY_DETECT           0x00000004
#define ASC_REQ_SEQUENCE_DETECT         0x00000008
#define ASC_REQ_CONFIDENTIALITY         0x00000010
#define ASC_REQ_USE_SESSION_KEY         0x00000020
#define ASC_REQ_ALLOCATE_MEMORY         0x00000100
#define ASC_REQ_USE_DCE_STYLE           0x00000200
#define ASC_REQ_DATAGRAM                0x00000400
#define ASC_REQ_CONNECTION              0x00000800
#define ASC_REQ_CALL_LEVEL              0x00001000
#define ASC_REQ_EXTENDED_ERROR          0x00008000
#define ASC_REQ_STREAM                  0x00010000
#define ASC_REQ_INTEGRITY               0x00020000
#define ASC_REQ_LICENSING               0x00040000
#define ASC_REQ_IDENTIFY                0x00080000
#define ASC_REQ_ALLOW_NULL_SESSION      0x00100000
#define ASC_REQ_ALLOW_NON_USER_LOGONS   0x00200000
#define ASC_REQ_ALLOW_CONTEXT_REPLAY    0x00400000
#define ASC_REQ_FRAGMENT_TO_FIT         0x00800000
#define ASC_REQ_FRAGMENT_SUPPLIED       0x00002000
#define ASC_REQ_NO_TOKEN                0x01000000
#define ASC_REQ_PROXY_BINDINGS          0x04000000
//      SSP_RET_REAUTHENTICATION        0x08000000  // *INTERNAL*
#define ASC_REQ_ALLOW_MISSING_BINDINGS  0x10000000

#define ASC_RET_DELEGATE                0x00000001
#define ASC_RET_MUTUAL_AUTH             0x00000002
#define ASC_RET_REPLAY_DETECT           0x00000004
#define ASC_RET_SEQUENCE_DETECT         0x00000008
#define ASC_RET_CONFIDENTIALITY         0x00000010
#define ASC_RET_USE_SESSION_KEY         0x00000020
#define ASC_RET_ALLOCATED_MEMORY        0x00000100
#define ASC_RET_USED_DCE_STYLE          0x00000200
#define ASC_RET_DATAGRAM                0x00000400
#define ASC_RET_CONNECTION              0x00000800
#define ASC_RET_CALL_LEVEL              0x00002000 // skipped 1000 to be like ISC_
#define ASC_RET_THIRD_LEG_FAILED        0x00004000
#define ASC_RET_EXTENDED_ERROR          0x00008000
#define ASC_RET_STREAM                  0x00010000
#define ASC_RET_INTEGRITY               0x00020000
#define ASC_RET_LICENSING               0x00040000
#define ASC_RET_IDENTIFY                0x00080000
#define ASC_RET_NULL_SESSION            0x00100000
#define ASC_RET_ALLOW_NON_USER_LOGONS   0x00200000
#define ASC_RET_ALLOW_CONTEXT_REPLAY    0x00400000  // deprecated - don't use this flag!!!
#define ASC_RET_FRAGMENT_ONLY           0x00800000
#define ASC_RET_NO_TOKEN                0x01000000
#define ASC_RET_NO_ADDITIONAL_TOKEN     0x02000000  // *INTERNAL*
#define ASC_RET_NO_PROXY_BINDINGS       0x04000000
//      SSP_RET_REAUTHENTICATION        0x08000000  // *INTERNAL*
#define ASC_RET_MISSING_BINDINGS        0x10000000

//
//  Security Credentials Attributes:
//

#define SECPKG_CRED_ATTR_NAMES        1
#define SECPKG_CRED_ATTR_SSI_PROVIDER 2

typedef struct _SecPkgCredentials_NamesW
{
#ifdef MIDL_PASS
    [string]
#endif
    SEC_WCHAR * sUserName;

} SecPkgCredentials_NamesW, * PSecPkgCredentials_NamesW;

#  define SecPkgCredentials_Names SecPkgCredentials_NamesW      
#  define PSecPkgCredentials_Names PSecPkgCredentials_NamesW    

#if NTDDI_VERSION > NTDDI_WS03
typedef struct _SecPkgCredentials_SSIProviderW
{
    SEC_WCHAR * sProviderName;
    unsigned long       ProviderInfoLength;
    char *      ProviderInfo;
} SecPkgCredentials_SSIProviderW, * PSecPkgCredentials_SSIProviderW;
#endif // End W2k3SP1 and greater
#  define SecPkgCredentials_SSIProvider SecPkgCredentials_SSIProviderW      
#  define PSecPkgCredentials_SSIProvider PSecPkgCredentials_SSIProviderW    

//
//  Security Context Attributes:
//

#define SECPKG_ATTR_SIZES           0
#define SECPKG_ATTR_NAMES           1
#define SECPKG_ATTR_LIFESPAN        2
#define SECPKG_ATTR_DCE_INFO        3
#define SECPKG_ATTR_STREAM_SIZES    4
#define SECPKG_ATTR_KEY_INFO        5
#define SECPKG_ATTR_AUTHORITY       6
#define SECPKG_ATTR_PROTO_INFO      7
#define SECPKG_ATTR_PASSWORD_EXPIRY 8
#define SECPKG_ATTR_SESSION_KEY     9
#define SECPKG_ATTR_PACKAGE_INFO    10
#define SECPKG_ATTR_USER_FLAGS      11
#define SECPKG_ATTR_NEGOTIATION_INFO 12
#define SECPKG_ATTR_NATIVE_NAMES    13
#define SECPKG_ATTR_FLAGS           14
// These attributes exist only in Win XP and greater
#define SECPKG_ATTR_USE_VALIDATED   15
#define SECPKG_ATTR_CREDENTIAL_NAME 16
#define SECPKG_ATTR_TARGET_INFORMATION 17
#define SECPKG_ATTR_ACCESS_TOKEN    18
// These attributes exist only in Win2K3 and greater
#define SECPKG_ATTR_TARGET          19
#define SECPKG_ATTR_AUTHENTICATION_ID  20
// These attributes exist only in Win2K3SP1 and greater
#define SECPKG_ATTR_LOGOFF_TIME     21
//
// win7 or greater
//
#define SECPKG_ATTR_NEGO_KEYS         22
#define SECPKG_ATTR_PROMPTING_NEEDED  24
#define SECPKG_ATTR_UNIQUE_BINDINGS   25
#define SECPKG_ATTR_ENDPOINT_BINDINGS 26
#define SECPKG_ATTR_CLIENT_SPECIFIED_TARGET 27

#define SECPKG_ATTR_LAST_CLIENT_TOKEN_STATUS 30
#define SECPKG_ATTR_NEGO_PKG_INFO        31 // contains nego info of packages
#define SECPKG_ATTR_NEGO_STATUS          32 // contains the last error
#define SECPKG_ATTR_CONTEXT_DELETED      33 // a context has been deleted

#define SECPKG_ATTR_SUBJECT_SECURITY_ATTRIBUTES 128

typedef struct _SecPkgContext_SubjectAttributes { 
    void* AttributeInfo; // contains a PAUTHZ_SECURITY_ATTRIBUTES_INFORMATION structure
} SecPkgContext_SubjectAttributes, *PSecPkgContext_SubjectAttributes;

#define SECPKG_ATTR_NEGO_INFO_FLAG_NO_KERBEROS 0x1
#define SECPKG_ATTR_NEGO_INFO_FLAG_NO_NTLM     0x2

//
// types of credentials, used by SECPKG_ATTR_PROMPTING_NEEDED
//

typedef enum _SECPKG_CRED_CLASS {
    SecPkgCredClass_None = 0,  // no creds
    SecPkgCredClass_Ephemeral = 10,  // logon creds
    SecPkgCredClass_PersistedGeneric = 20, // saved creds, not target specific
    SecPkgCredClass_PersistedSpecific = 30, // saved creds, target specific
    SecPkgCredClass_Explicit = 40, // explicitly supplied creds
} SECPKG_CRED_CLASS, * PSECPKG_CRED_CLASS;

typedef struct _SecPkgContext_CredInfo {
    SECPKG_CRED_CLASS CredClass;
    unsigned long IsPromptingNeeded;
} SecPkgContext_CredInfo, *PSecPkgContext_CredInfo;

typedef struct _SecPkgContext_NegoPackageInfo
{
    unsigned long PackageMask;
} SecPkgContext_NegoPackageInfo, * PSecPkgContext_NegoPackageInfo;

typedef struct _SecPkgContext_NegoStatus
{
    unsigned long LastStatus;
} SecPkgContext_NegoStatus, * PSecPkgContext_NegoStatus;

typedef struct _SecPkgContext_Sizes
{
    unsigned long cbMaxToken;
    unsigned long cbMaxSignature;
    unsigned long cbBlockSize;
    unsigned long cbSecurityTrailer;
} SecPkgContext_Sizes, * PSecPkgContext_Sizes;

typedef struct _SecPkgContext_StreamSizes
{
    unsigned long   cbHeader;
    unsigned long   cbTrailer;
    unsigned long   cbMaximumMessage;
    unsigned long   cBuffers;
    unsigned long   cbBlockSize;
} SecPkgContext_StreamSizes, * PSecPkgContext_StreamSizes;

typedef struct _SecPkgContext_NamesW
{
    SEC_WCHAR * sUserName;
} SecPkgContext_NamesW, * PSecPkgContext_NamesW;

#  define SecPkgContext_Names SecPkgContext_NamesW          
#  define PSecPkgContext_Names PSecPkgContext_NamesW        

typedef struct _SecPkgContext_Lifespan
{
    TimeStamp tsStart;
    TimeStamp tsExpiry;
} SecPkgContext_Lifespan, * PSecPkgContext_Lifespan;

typedef struct _SecPkgContext_DceInfo
{
    unsigned long AuthzSvc;
    void * pPac;
} SecPkgContext_DceInfo, * PSecPkgContext_DceInfo;


typedef struct _SecPkgContext_KeyInfoW
{
    SEC_WCHAR * sSignatureAlgorithmName;
    SEC_WCHAR * sEncryptAlgorithmName;
    unsigned long       KeySize;
    unsigned long       SignatureAlgorithm;
    unsigned long       EncryptAlgorithm;
} SecPkgContext_KeyInfoW, * PSecPkgContext_KeyInfoW;

#define SecPkgContext_KeyInfo   SecPkgContext_KeyInfoW      
#define PSecPkgContext_KeyInfo  PSecPkgContext_KeyInfoW     

typedef struct _SecPkgContext_AuthorityW
{
    SEC_WCHAR * sAuthorityName;
} SecPkgContext_AuthorityW, * PSecPkgContext_AuthorityW;

#define SecPkgContext_Authority SecPkgContext_AuthorityW        
#define PSecPkgContext_Authority    PSecPkgContext_AuthorityW   

typedef struct _SecPkgContext_ProtoInfoW
{
    SEC_WCHAR * sProtocolName;
    unsigned long majorVersion;
    unsigned long minorVersion;
} SecPkgContext_ProtoInfoW, * PSecPkgContext_ProtoInfoW;

#define SecPkgContext_ProtoInfo   SecPkgContext_ProtoInfoW      
#define PSecPkgContext_ProtoInfo  PSecPkgContext_ProtoInfoW     

typedef struct _SecPkgContext_PasswordExpiry
{
    TimeStamp tsPasswordExpires;
} SecPkgContext_PasswordExpiry, * PSecPkgContext_PasswordExpiry;

#if NTDDI_VERSION > NTDDI_WS03
typedef struct _SecPkgContext_LogoffTime
{
    TimeStamp tsLogoffTime;
} SecPkgContext_LogoffTime, * PSecPkgContext_LogoffTime;
#endif // Greater than Windows Server 2003 RTM (SP1 and greater contains this)

typedef struct _SecPkgContext_SessionKey
{
    unsigned long SessionKeyLength;
    __field_bcount(SessionKeyLength) unsigned char * SessionKey;
} SecPkgContext_SessionKey, *PSecPkgContext_SessionKey;

// used by nego2
typedef struct _SecPkgContext_NegoKeys
{
  unsigned long KeyType;
  unsigned short KeyLength;
  __field_bcount(KeyLength) unsigned char* KeyValue;
  unsigned long  VerifyKeyType;
  unsigned short VerifyKeyLength;
  __field_bcount(VerifyKeyLength) unsigned char* VerifyKeyValue;
} SecPkgContext_NegoKeys, * PSecPkgContext_NegoKeys;

typedef struct _SecPkgContext_PackageInfoW
{
    PSecPkgInfoW PackageInfo;
} SecPkgContext_PackageInfoW, * PSecPkgContext_PackageInfoW;


typedef struct _SecPkgContext_UserFlags
{
    unsigned long UserFlags;
} SecPkgContext_UserFlags, * PSecPkgContext_UserFlags;

typedef struct _SecPkgContext_Flags
{
    unsigned long Flags;
} SecPkgContext_Flags, * PSecPkgContext_Flags;

#define SecPkgContext_PackageInfo   SecPkgContext_PackageInfoW      
#define PSecPkgContext_PackageInfo  PSecPkgContext_PackageInfoW     
typedef struct _SecPkgContext_NegotiationInfoW
{
    PSecPkgInfoW    PackageInfo ;
    unsigned long   NegotiationState ;
} SecPkgContext_NegotiationInfoW, * PSecPkgContext_NegotiationInfoW ;

#  define SecPkgContext_NativeNames SecPkgContext_NativeNamesW          
#  define PSecPkgContext_NativeNames PSecPkgContext_NativeNamesW        

#if OSVER(NTDDI_VERSION) > NTDDI_WIN2K

typedef struct _SecPkgContext_CredentialNameW
{
    unsigned long CredentialType;
    SEC_WCHAR *sCredentialName;
} SecPkgContext_CredentialNameW, * PSecPkgContext_CredentialNameW;

#endif // Later than win2k
#  define SecPkgContext_CredentialName SecPkgContext_CredentialNameW          
#  define PSecPkgContext_CredentialName PSecPkgContext_CredentialNameW        

typedef void
(SEC_ENTRY * SEC_GET_KEY_FN) (
    void * Arg,                 // Argument passed in
    void * Principal,           // Principal ID
    unsigned long KeyVer,               // Key Version
    void * * Key,       // Returned ptr to key
    SECURITY_STATUS * Status    // returned status
    );

//
// Flags for ExportSecurityContext
//

#define SECPKG_CONTEXT_EXPORT_RESET_NEW         0x00000001      // New context is reset to initial state
#define SECPKG_CONTEXT_EXPORT_DELETE_OLD        0x00000002      // Old context is deleted during export
// This is only valid in W2K3SP1 and greater
#define SECPKG_CONTEXT_EXPORT_TO_KERNEL         0x00000004      // Context is to be transferred to the kernel


KSECDDDECLSPEC
SECURITY_STATUS SEC_ENTRY
AcquireCredentialsHandleW(
#if ISSP_MODE == 0     // For Kernel mode
    __in_opt  PSECURITY_STRING pPrincipal,
    __in      PSECURITY_STRING pPackage,
#else
    __in_opt  LPWSTR pszPrincipal,                // Name of principal
    __in      LPWSTR pszPackage,                  // Name of package
#endif
    __in      unsigned long fCredentialUse,       // Flags indicating use
    __in_opt  void * pvLogonId,           // Pointer to logon ID
    __in_opt  void * pAuthData,           // Package specific data
    __in_opt  SEC_GET_KEY_FN pGetKeyFn,           // Pointer to GetKey() func
    __in_opt  void * pvGetKeyArgument,    // Value to pass to GetKey()
    __out     PCredHandle phCredential,           // (out) Cred Handle
    __out_opt PTimeStamp ptsExpiry                // (out) Lifetime (optional)
    );

typedef SECURITY_STATUS
(SEC_ENTRY * ACQUIRE_CREDENTIALS_HANDLE_FN_W)(
#if ISSP_MODE == 0
    PSECURITY_STRING,
    PSECURITY_STRING,
#else
    SEC_WCHAR *,
    SEC_WCHAR *,
#endif
    unsigned long,
    void *,
    void *,
    SEC_GET_KEY_FN,
    void *,
    PCredHandle,
    PTimeStamp);

#  define AcquireCredentialsHandle AcquireCredentialsHandleW            
#  define ACQUIRE_CREDENTIALS_HANDLE_FN ACQUIRE_CREDENTIALS_HANDLE_FN_W 

KSECDDDECLSPEC
SECURITY_STATUS SEC_ENTRY
FreeCredentialsHandle(
    __in PCredHandle phCredential            // Handle to free
    );

typedef SECURITY_STATUS
(SEC_ENTRY * FREE_CREDENTIALS_HANDLE_FN)(
    PCredHandle );

KSECDDDECLSPEC
SECURITY_STATUS SEC_ENTRY
AddCredentialsW(
    __in      PCredHandle hCredentials,
#if ISSP_MODE == 0      // For Kernel mode
    __in_opt  PSECURITY_STRING pPrincipal,
    __in      PSECURITY_STRING pPackage,
#else
    __in_opt  LPWSTR pszPrincipal,                // Name of principal
    __in      LPWSTR pszPackage,                  // Name of package
#endif
    __in      unsigned long fCredentialUse,       // Flags indicating use
    __in_opt  void * pAuthData,           // Package specific data
    __in_opt  SEC_GET_KEY_FN pGetKeyFn,           // Pointer to GetKey() func
    __in_opt  void * pvGetKeyArgument,    // Value to pass to GetKey()
    __out_opt PTimeStamp ptsExpiry                // (out) Lifetime (optional)
    );

typedef SECURITY_STATUS
(SEC_ENTRY * ADD_CREDENTIALS_FN_W)(
    PCredHandle,
#if ISSP_MODE == 0
    PSECURITY_STRING,
    PSECURITY_STRING,
#else
    SEC_WCHAR *,
    SEC_WCHAR *,
#endif
    unsigned long,
    void *,
    SEC_GET_KEY_FN,
    void *,
    PTimeStamp);

SECURITY_STATUS SEC_ENTRY
AddCredentialsA(
    __in PCredHandle hCredentials,
    __in_opt LPSTR pszPrincipal,             // Name of principal
    __in LPSTR pszPackage,                   // Name of package
    __in unsigned long fCredentialUse,       // Flags indicating use
    __in_opt void * pAuthData,           // Package specific data
    __in_opt SEC_GET_KEY_FN pGetKeyFn,           // Pointer to GetKey() func
    __in_opt void * pvGetKeyArgument,    // Value to pass to GetKey()
    __out_opt PTimeStamp ptsExpiry                // (out) Lifetime (optional)
    );

typedef SECURITY_STATUS
(SEC_ENTRY * ADD_CREDENTIALS_FN_A)(
    PCredHandle,
    SEC_CHAR *,
    SEC_CHAR *,
    unsigned long,
    void *,
    SEC_GET_KEY_FN,
    void *,
    PTimeStamp);

#ifdef UNICODE
#define AddCredentials  AddCredentialsW
#define ADD_CREDENTIALS_FN  ADD_CREDENTIALS_FN_W
#else
#define AddCredentials  AddCredentialsA
#define ADD_CREDENTIALS_FN ADD_CREDENTIALS_FN_A
#endif

////////////////////////////////////////////////////////////////////////
///
/// Password Change Functions
///
////////////////////////////////////////////////////////////////////////

#if ISSP_MODE != 0

SECURITY_STATUS SEC_ENTRY
ChangeAccountPasswordW(
    __in    SEC_WCHAR *  pszPackageName,
    __in    SEC_WCHAR *  pszDomainName,
    __in    SEC_WCHAR *  pszAccountName,
    __in    SEC_WCHAR *  pszOldPassword,
    __in    SEC_WCHAR *  pszNewPassword,
    __in    BOOLEAN              bImpersonating,
    __in    unsigned long        dwReserved,
    __inout PSecBufferDesc       pOutput
    );

typedef SECURITY_STATUS
(SEC_ENTRY * CHANGE_PASSWORD_FN_W)(
    SEC_WCHAR *,
    SEC_WCHAR *,
    SEC_WCHAR *,
    SEC_WCHAR *,
    SEC_WCHAR *,
    BOOLEAN,
    unsigned long,
    PSecBufferDesc
    );



SECURITY_STATUS SEC_ENTRY
ChangeAccountPasswordA(
    __in    SEC_CHAR *  pszPackageName,
    __in    SEC_CHAR *  pszDomainName,
    __in    SEC_CHAR *  pszAccountName,
    __in    SEC_CHAR *  pszOldPassword,
    __in    SEC_CHAR *  pszNewPassword,
    __in    BOOLEAN             bImpersonating,
    __in    unsigned long       dwReserved,
    __inout PSecBufferDesc      pOutput
    );

typedef SECURITY_STATUS
(SEC_ENTRY * CHANGE_PASSWORD_FN_A)(
    SEC_CHAR *,
    SEC_CHAR *,
    SEC_CHAR *,
    SEC_CHAR *,
    SEC_CHAR *,
    BOOLEAN,
    unsigned long,
    PSecBufferDesc
    );

#ifdef UNICODE
#  define ChangeAccountPassword ChangeAccountPasswordW
#  define CHANGE_PASSWORD_FN CHANGE_PASSWORD_FN_W
#else
#  define ChangeAccountPassword ChangeAccountPasswordA
#  define CHANGE_PASSWORD_FN CHANGE_PASSWORD_FN_A
#endif // !UNICODE

#endif // ISSP_MODE


////////////////////////////////////////////////////////////////////////
///
/// Context Management Functions
///
////////////////////////////////////////////////////////////////////////

KSECDDDECLSPEC
SECURITY_STATUS SEC_ENTRY
InitializeSecurityContextW(
    __in_opt    PCredHandle phCredential,               // Cred to base context
    __in_opt    PCtxtHandle phContext,                  // Existing context (OPT)
#if ISSP_MODE == 0
    __in_opt PSECURITY_STRING pTargetName,
#else
    __in_opt SEC_WCHAR * pszTargetName,         // Name of target
#endif
    __in        unsigned long fContextReq,              // Context Requirements
    __in        unsigned long Reserved1,                // Reserved, MBZ
    __in        unsigned long TargetDataRep,            // Data rep of target
    __in_opt    PSecBufferDesc pInput,                  // Input Buffers
    __in        unsigned long Reserved2,                // Reserved, MBZ
    __inout_opt PCtxtHandle phNewContext,               // (out) New Context handle
    __inout_opt PSecBufferDesc pOutput,                 // (inout) Output Buffers
    __out       unsigned long * pfContextAttr,  // (out) Context attrs
    __out_opt   PTimeStamp ptsExpiry                    // (out) Life span (OPT)
    );

typedef SECURITY_STATUS
(SEC_ENTRY * INITIALIZE_SECURITY_CONTEXT_FN_W)(
    PCredHandle,
    PCtxtHandle,
#if ISSP_MODE == 0
    PSECURITY_STRING,
#else
    SEC_WCHAR *,
#endif
    unsigned long,
    unsigned long,
    unsigned long,
    PSecBufferDesc,
    unsigned long,
    PCtxtHandle,
    PSecBufferDesc,
    unsigned long *,
    PTimeStamp);

#  define InitializeSecurityContext InitializeSecurityContextW              
#  define INITIALIZE_SECURITY_CONTEXT_FN INITIALIZE_SECURITY_CONTEXT_FN_W   

KSECDDDECLSPEC
SECURITY_STATUS SEC_ENTRY
AcceptSecurityContext(
    __in_opt  PCredHandle phCredential,               // Cred to base context
    __in_opt  PCtxtHandle phContext,                  // Existing context (OPT)
    __in_opt  PSecBufferDesc pInput,                  // Input buffer
    __in      unsigned long fContextReq,              // Context Requirements
    __in      unsigned long TargetDataRep,            // Target Data Rep
    __in_opt  PCtxtHandle phNewContext,               // (out) New context handle
    __in_opt  PSecBufferDesc pOutput,                 // (inout) Output buffers
    __out     unsigned long * pfContextAttr,  // (out) Context attributes
    __out_opt PTimeStamp ptsExpiry                    // (out) Life span (OPT)
    );

typedef SECURITY_STATUS
(SEC_ENTRY * ACCEPT_SECURITY_CONTEXT_FN)(
    PCredHandle,
    PCtxtHandle,
    PSecBufferDesc,
    unsigned long,
    unsigned long,
    PCtxtHandle,
    PSecBufferDesc,
    unsigned long *,
    PTimeStamp);



SECURITY_STATUS SEC_ENTRY
CompleteAuthToken(
    __in PCtxtHandle phContext,              // Context to complete
    __in PSecBufferDesc pToken               // Token to complete
    );

typedef SECURITY_STATUS
(SEC_ENTRY * COMPLETE_AUTH_TOKEN_FN)(
    PCtxtHandle,
    PSecBufferDesc);

KSECDDDECLSPEC
SECURITY_STATUS SEC_ENTRY
ImpersonateSecurityContext(
    __in PCtxtHandle phContext               // Context to impersonate
    );

typedef SECURITY_STATUS
(SEC_ENTRY * IMPERSONATE_SECURITY_CONTEXT_FN)(
    PCtxtHandle);


KSECDDDECLSPEC
SECURITY_STATUS SEC_ENTRY
RevertSecurityContext(
    __in PCtxtHandle phContext               // Context from which to re
    );

typedef SECURITY_STATUS
(SEC_ENTRY * REVERT_SECURITY_CONTEXT_FN)(
    PCtxtHandle);


KSECDDDECLSPEC
SECURITY_STATUS SEC_ENTRY
QuerySecurityContextToken(
    __in  PCtxtHandle phContext,
    __out void * * Token
    );

typedef SECURITY_STATUS
(SEC_ENTRY * QUERY_SECURITY_CONTEXT_TOKEN_FN)(
    PCtxtHandle, void * *);


KSECDDDECLSPEC
SECURITY_STATUS SEC_ENTRY
DeleteSecurityContext(
    __in PCtxtHandle phContext               // Context to delete
    );

typedef SECURITY_STATUS
(SEC_ENTRY * DELETE_SECURITY_CONTEXT_FN)(
    PCtxtHandle);


KSECDDDECLSPEC
SECURITY_STATUS SEC_ENTRY
ApplyControlToken(
    __in PCtxtHandle phContext,              // Context to modify
    __in PSecBufferDesc pInput               // Input token to apply
    );

typedef SECURITY_STATUS
(SEC_ENTRY * APPLY_CONTROL_TOKEN_FN)(
    PCtxtHandle, PSecBufferDesc);


KSECDDDECLSPEC
SECURITY_STATUS SEC_ENTRY
QueryContextAttributesW(
    __in  PCtxtHandle phContext,              // Context to query
    __in  unsigned long ulAttribute,          // Attribute to query
    __out void * pBuffer              // Buffer for attributes
    );

typedef SECURITY_STATUS
(SEC_ENTRY * QUERY_CONTEXT_ATTRIBUTES_FN_W)(
    PCtxtHandle,
    unsigned long,
    void *);

#  define QueryContextAttributes QueryContextAttributesW            
#  define QUERY_CONTEXT_ATTRIBUTES_FN QUERY_CONTEXT_ATTRIBUTES_FN_W 

#if (OSVER(NTDDI_VERSION) > NTDDI_WIN2K)

SECURITY_STATUS SEC_ENTRY
SetContextAttributesW(
    __in PCtxtHandle phContext,                   // Context to Set
    __in unsigned long ulAttribute,               // Attribute to Set
    __in_bcount(cbBuffer) void * pBuffer, // Buffer for attributes
    __in unsigned long cbBuffer                   // Size (in bytes) of Buffer
    );

typedef SECURITY_STATUS
(SEC_ENTRY * SET_CONTEXT_ATTRIBUTES_FN_W)(
    PCtxtHandle,
    unsigned long,
    void *,
    unsigned long );

#endif // Greater than w2k

#  define SetContextAttributes SetContextAttributesW            
#  define SET_CONTEXT_ATTRIBUTES_FN SET_CONTEXT_ATTRIBUTES_FN_W 

KSECDDDECLSPEC
SECURITY_STATUS SEC_ENTRY
QueryCredentialsAttributesW(
    __in    PCredHandle phCredential,           // Credential to query
    __in    unsigned long ulAttribute,          // Attribute to query
    __inout void * pBuffer              // Buffer for attributes
    );

typedef SECURITY_STATUS
(SEC_ENTRY * QUERY_CREDENTIALS_ATTRIBUTES_FN_W)(
    PCredHandle,
    unsigned long,
    void *);

#  define QueryCredentialsAttributes QueryCredentialsAttributesW            
#  define QUERY_CREDENTIALS_ATTRIBUTES_FN QUERY_CREDENTIALS_ATTRIBUTES_FN_W 

#if NTDDI_VERSION > NTDDI_WS03

KSECDDDECLSPEC
SECURITY_STATUS SEC_ENTRY
SetCredentialsAttributesW(
    __in PCredHandle phCredential,                // Credential to Set
    __in unsigned long ulAttribute,               // Attribute to Set
    __in_bcount(cbBuffer) void * pBuffer, // Buffer for attributes
    __in unsigned long cbBuffer                   // Size (in bytes) of Buffer
    );

typedef SECURITY_STATUS
(SEC_ENTRY * SET_CREDENTIALS_ATTRIBUTES_FN_W)(
    PCredHandle,
    unsigned long,
    void *,
    unsigned long );

#endif // For W2k3SP1 and greater

#  define SetCredentialsAttributes SetCredentialsAttributesW            
#  define SET_CREDENTIALS_ATTRIBUTES_FN SET_CREDENTIALS_ATTRIBUTES_FN_W 

SECURITY_STATUS SEC_ENTRY
FreeContextBuffer(
    __inout PVOID pvContextBuffer      // buffer to free
    );

typedef SECURITY_STATUS
(SEC_ENTRY * FREE_CONTEXT_BUFFER_FN)(
    __inout PVOID
    );

///////////////////////////////////////////////////////////////////
////
////    Message Support API
////
//////////////////////////////////////////////////////////////////

KSECDDDECLSPEC
SECURITY_STATUS SEC_ENTRY
MakeSignature(
    __in PCtxtHandle phContext,              // Context to use
    __in unsigned long fQOP,                 // Quality of Protection
    __in PSecBufferDesc pMessage,            // Message to sign
    __in unsigned long MessageSeqNo          // Message Sequence Num.
    );

typedef SECURITY_STATUS
(SEC_ENTRY * MAKE_SIGNATURE_FN)(
    PCtxtHandle,
    unsigned long,
    PSecBufferDesc,
    unsigned long);


KSECDDDECLSPEC
SECURITY_STATUS SEC_ENTRY
VerifySignature(
    __in  PCtxtHandle phContext,              // Context to use
    __in  PSecBufferDesc pMessage,            // Message to verify
    __in  unsigned long MessageSeqNo,         // Sequence Num.
    __out unsigned long * pfQOP       // QOP used
    );

typedef SECURITY_STATUS
(SEC_ENTRY * VERIFY_SIGNATURE_FN)(
    PCtxtHandle,
    PSecBufferDesc,
    unsigned long,
    unsigned long *);

// This only exists win Win2k3 and Greater
#define SECQOP_WRAP_NO_ENCRYPT      0x80000001
#define SECQOP_WRAP_OOB_DATA        0x40000000

SECURITY_STATUS SEC_ENTRY
EncryptMessage( __in    PCtxtHandle         phContext,
                __in    unsigned long       fQOP,
                __inout PSecBufferDesc      pMessage,
                __in    unsigned long       MessageSeqNo);

typedef SECURITY_STATUS
(SEC_ENTRY * ENCRYPT_MESSAGE_FN)(
    PCtxtHandle, unsigned long, PSecBufferDesc, unsigned long);


SECURITY_STATUS SEC_ENTRY
DecryptMessage( __in      PCtxtHandle         phContext,
                __inout   PSecBufferDesc      pMessage,
                __in      unsigned long       MessageSeqNo,
                __out_opt unsigned long *     pfQOP);


typedef SECURITY_STATUS
(SEC_ENTRY * DECRYPT_MESSAGE_FN)(
    PCtxtHandle, PSecBufferDesc, unsigned long,
    unsigned long *);


///////////////////////////////////////////////////////////////////////////
////
////    Misc.
////
///////////////////////////////////////////////////////////////////////////

KSECDDDECLSPEC
SECURITY_STATUS SEC_ENTRY
EnumerateSecurityPackagesW(
    __out       unsigned long * pcPackages,     // Receives num. packages
    __deref_out PSecPkgInfoW  * ppPackageInfo    // Receives array of info
    );

typedef SECURITY_STATUS
(SEC_ENTRY * ENUMERATE_SECURITY_PACKAGES_FN_W)(
    unsigned long *,
    PSecPkgInfoW *);

#  define EnumerateSecurityPackages EnumerateSecurityPackagesW              
#  define ENUMERATE_SECURITY_PACKAGES_FN ENUMERATE_SECURITY_PACKAGES_FN_W   

KSECDDDECLSPEC
SECURITY_STATUS SEC_ENTRY
QuerySecurityPackageInfoW(
#if ISSP_MODE == 0
    __in        PSECURITY_STRING pPackageName,
#else
    __in        LPWSTR pszPackageName,          // Name of package
#endif
    __deref_out PSecPkgInfoW *ppPackageInfo     // Receives package info
    );

typedef SECURITY_STATUS
(SEC_ENTRY * QUERY_SECURITY_PACKAGE_INFO_FN_W)(
#if ISSP_MODE == 0
    PSECURITY_STRING,
#else
    SEC_WCHAR *,
#endif
    PSecPkgInfoW *);

#  define QuerySecurityPackageInfo QuerySecurityPackageInfoW                
#  define QUERY_SECURITY_PACKAGE_INFO_FN QUERY_SECURITY_PACKAGE_INFO_FN_W   

///////////////////////////////////////////////////////////////////////////
////
////    Context export/import
////
///////////////////////////////////////////////////////////////////////////


KSECDDDECLSPEC
SECURITY_STATUS SEC_ENTRY
ExportSecurityContext(
    __in  PCtxtHandle          phContext,             // (in) context to export
    __in  ULONG                fFlags,                // (in) option flags
    __out PSecBuffer           pPackedContext,        // (out) marshalled context
    __out void * * pToken             // (out, optional) token handle for impersonation
    );

typedef SECURITY_STATUS
(SEC_ENTRY * EXPORT_SECURITY_CONTEXT_FN)(
    PCtxtHandle,
    ULONG,
    PSecBuffer,
    void * *
    );

KSECDDDECLSPEC
SECURITY_STATUS SEC_ENTRY
ImportSecurityContextW(
#if ISSP_MODE == 0
    __in  PSECURITY_STRING     pszPackage,
#else
    __in  LPWSTR               pszPackage,
#endif
    __in  PSecBuffer           pPackedContext,        // (in) marshalled context
    __in  void *               Token,                 // (in, optional) handle to token for context
    __out PCtxtHandle          phContext              // (out) new context handle
    );

typedef SECURITY_STATUS
(SEC_ENTRY * IMPORT_SECURITY_CONTEXT_FN_W)(
#if ISSP_MODE == 0
    PSECURITY_STRING,
#else
    SEC_WCHAR *,
#endif
    PSecBuffer,
    VOID *,
    PCtxtHandle
    );

#  define ImportSecurityContext ImportSecurityContextW              
#  define IMPORT_SECURITY_CONTEXT_FN IMPORT_SECURITY_CONTEXT_FN_W   

#if ISSP_MODE == 0
KSECDDDECLSPEC
NTSTATUS
NTAPI
SecMakeSPN(
    IN PUNICODE_STRING ServiceClass,
    IN PUNICODE_STRING ServiceName,
    IN PUNICODE_STRING InstanceName OPTIONAL,
    IN USHORT InstancePort OPTIONAL,
    IN PUNICODE_STRING Referrer OPTIONAL,
    IN OUT PUNICODE_STRING Spn,
    OUT PULONG Length OPTIONAL,
    IN BOOLEAN Allocate
    );

#if OSVER(NTDDI_VERSION) > NTDD_WIN2K

KSECDDDECLSPEC
NTSTATUS
NTAPI
SecMakeSPNEx(
    IN PUNICODE_STRING ServiceClass,
    IN PUNICODE_STRING ServiceName,
    IN PUNICODE_STRING InstanceName OPTIONAL,
    IN USHORT InstancePort OPTIONAL,
    IN PUNICODE_STRING Referrer OPTIONAL,
    IN PUNICODE_STRING TargetInfo OPTIONAL,
    IN OUT PUNICODE_STRING Spn,
    OUT PULONG Length OPTIONAL,
    IN BOOLEAN Allocate
    );

#if OSVER(NTDDI_VERSION) > NTDDI_WS03

KSECDDDECLSPEC
NTSTATUS
NTAPI
SecMakeSPNEx2(
    IN PUNICODE_STRING ServiceClass,
    IN PUNICODE_STRING ServiceName,
    IN PUNICODE_STRING InstanceName OPTIONAL,
    IN USHORT InstancePort OPTIONAL,
    IN PUNICODE_STRING Referrer OPTIONAL,
    IN PUNICODE_STRING InTargetInfo OPTIONAL,
    IN OUT PUNICODE_STRING Spn,
    OUT PULONG TotalSize OPTIONAL,
    IN BOOLEAN Allocate,
    IN BOOLEAN IsTargetInfoMarshaled
    );

#endif // Windows Vista and greater

KSECDDDECLSPEC
NTSTATUS
SEC_ENTRY
SecLookupAccountSid(
    __in      PSID Sid,
    __out     PULONG NameSize,
    __inout   PUNICODE_STRING NameBuffer,
    __out     PULONG DomainSize OPTIONAL,
    __out_opt PUNICODE_STRING DomainBuffer OPTIONAL,
    __out     PSID_NAME_USE NameUse
    );

KSECDDDECLSPEC
NTSTATUS
SEC_ENTRY
SecLookupAccountName(
    __in        PUNICODE_STRING Name,
    __inout     PULONG SidSize,
    __out       PSID Sid,
    __out       PSID_NAME_USE NameUse,
    __out       PULONG DomainSize OPTIONAL,
    __inout_opt PUNICODE_STRING ReferencedDomain OPTIONAL
    );

#endif // Greater than W2k

#if OSVER(NTDDI_VERSION) > NTDDI_WINXP

KSECDDDECLSPEC
NTSTATUS
SEC_ENTRY
SecLookupWellKnownSid(
    __in        WELL_KNOWN_SID_TYPE SidType,
    __out       PSID Sid,
    __in        ULONG SidBufferSize,
    __inout_opt PULONG SidSize OPTIONAL
    );

#endif // Greater than XP


#endif

#define SECURITY_ENTRYPOINTW SEC_TEXT("InitSecurityInterfaceW")     
#    define SECURITY_ENTRYPOINT SECURITY_ENTRYPOINTW                

#define FreeCredentialHandle FreeCredentialsHandle

typedef struct _SECURITY_FUNCTION_TABLE_W {
    unsigned long                       dwVersion;
    ENUMERATE_SECURITY_PACKAGES_FN_W    EnumerateSecurityPackagesW;
    QUERY_CREDENTIALS_ATTRIBUTES_FN_W   QueryCredentialsAttributesW;
    ACQUIRE_CREDENTIALS_HANDLE_FN_W     AcquireCredentialsHandleW;
    FREE_CREDENTIALS_HANDLE_FN          FreeCredentialsHandle;
    void *                      Reserved2;
    INITIALIZE_SECURITY_CONTEXT_FN_W    InitializeSecurityContextW;
    ACCEPT_SECURITY_CONTEXT_FN          AcceptSecurityContext;
    COMPLETE_AUTH_TOKEN_FN              CompleteAuthToken;
    DELETE_SECURITY_CONTEXT_FN          DeleteSecurityContext;
    APPLY_CONTROL_TOKEN_FN              ApplyControlToken;
    QUERY_CONTEXT_ATTRIBUTES_FN_W       QueryContextAttributesW;
    IMPERSONATE_SECURITY_CONTEXT_FN     ImpersonateSecurityContext;
    REVERT_SECURITY_CONTEXT_FN          RevertSecurityContext;
    MAKE_SIGNATURE_FN                   MakeSignature;
    VERIFY_SIGNATURE_FN                 VerifySignature;
    FREE_CONTEXT_BUFFER_FN              FreeContextBuffer;
    QUERY_SECURITY_PACKAGE_INFO_FN_W    QuerySecurityPackageInfoW;
    void *                      Reserved3;
    void *                      Reserved4;
    EXPORT_SECURITY_CONTEXT_FN          ExportSecurityContext;
    IMPORT_SECURITY_CONTEXT_FN_W        ImportSecurityContextW;
    ADD_CREDENTIALS_FN_W                AddCredentialsW ;
    void *                      Reserved8;
    QUERY_SECURITY_CONTEXT_TOKEN_FN     QuerySecurityContextToken;
    ENCRYPT_MESSAGE_FN                  EncryptMessage;
    DECRYPT_MESSAGE_FN                  DecryptMessage;
#if OSVER(NTDDI_VERSION) > NTDDI_WIN2K
    // Fields below this are available in OSes after w2k
    SET_CONTEXT_ATTRIBUTES_FN_W         SetContextAttributesW;
#endif // greater thean 2K

#if NTDDI_VERSION > NTDDI_WS03SP1
    // Fields below this are available in OSes after W2k3SP1
    SET_CREDENTIALS_ATTRIBUTES_FN_W     SetCredentialsAttributesW;
#endif
#if ISSP_MODE != 0
    CHANGE_PASSWORD_FN_W                ChangeAccountPasswordW;
#else
    void *                      Reserved9;
#endif
} SecurityFunctionTableW, * PSecurityFunctionTableW;

#  define SecurityFunctionTable SecurityFunctionTableW      
#  define PSecurityFunctionTable PSecurityFunctionTableW    
#define SECURITY_SUPPORT_PROVIDER_INTERFACE_VERSION     1   
#define SECURITY_SUPPORT_PROVIDER_INTERFACE_VERSION_2   2   
#define SECURITY_SUPPORT_PROVIDER_INTERFACE_VERSION_3   3   
#define SECURITY_SUPPORT_PROVIDER_INTERFACE_VERSION_4   4   

KSECDDDECLSPEC
PSecurityFunctionTableW SEC_ENTRY
InitSecurityInterfaceW(
    void
    );

typedef PSecurityFunctionTableW
(SEC_ENTRY * INIT_SECURITY_INTERFACE_W)(void);

#  define InitSecurityInterface InitSecurityInterfaceW          
#  define INIT_SECURITY_INTERFACE INIT_SECURITY_INTERFACE_W     

#ifndef _AUTH_IDENTITY_EX2_DEFINED
#define _AUTH_IDENTITY_EX2_DEFINED

#define SEC_WINNT_AUTH_IDENTITY_VERSION_2 0x201

typedef struct _SEC_WINNT_AUTH_IDENTITY_EX2 {
   unsigned long Version; // contains SEC_WINNT_AUTH_IDENTITY_VERSION_2
   unsigned short cbHeaderLength;
   unsigned long cbStructureLength;
   unsigned long UserOffset;                // Non-NULL terminated string, unicode only
   unsigned short UserLength;               // # of bytes (NOT WCHARs), not including NULL.
   unsigned long DomainOffset;              // Non-NULL terminated string, unicode only
   unsigned short DomainLength;             // # of bytes (NOT WCHARs), not including NULL.
   unsigned long PackedCredentialsOffset;   // Non-NULL terminated string, unicode only
   unsigned short PackedCredentialsLength;  // # of bytes (NOT WCHARs), not including NULL.
   unsigned long Flags;
   unsigned long PackageListOffset;         // Non-NULL terminated string, unicode only
   unsigned short PackageListLength;
} SEC_WINNT_AUTH_IDENTITY_EX2, *PSEC_WINNT_AUTH_IDENTITY_EX2;

#endif // _AUTH_IDENTITY_EX2_DEFINED

#ifndef _AUTH_IDENTITY_DEFINED
#define _AUTH_IDENTITY_DEFINED

//
// This was not defined in NTIFS.h for windows 2000 however
// this struct has always been there and are safe to use
// in windows 2000 and above.
//

#define SEC_WINNT_AUTH_IDENTITY_ANSI    0x1
#define SEC_WINNT_AUTH_IDENTITY_UNICODE 0x2

typedef struct _SEC_WINNT_AUTH_IDENTITY_W {
  unsigned short *User;         //  Non-NULL terminated string.
  unsigned long UserLength;     //  # of characters (NOT bytes), not including NULL.
  unsigned short *Domain;       //  Non-NULL terminated string.
  unsigned long DomainLength;   //  # of characters (NOT bytes), not including NULL.
  unsigned short *Password;     //  Non-NULL terminated string.
  unsigned long PasswordLength; //  # of characters (NOT bytes), not including NULL.
  unsigned long Flags;
} SEC_WINNT_AUTH_IDENTITY_W, *PSEC_WINNT_AUTH_IDENTITY_W;

#define SEC_WINNT_AUTH_IDENTITY SEC_WINNT_AUTH_IDENTITY_W       
#define PSEC_WINNT_AUTH_IDENTITY PSEC_WINNT_AUTH_IDENTITY_W     
#define _SEC_WINNT_AUTH_IDENTITY _SEC_WINNT_AUTH_IDENTITY_W     

#endif //_AUTH_IDENTITY_DEFINED                                 // ntifs

//
// This is the combined authentication identity structure that may be
// used with the negotiate package, NTLM, Kerberos, or SCHANNEL
//

#ifndef SEC_WINNT_AUTH_IDENTITY_VERSION
#define SEC_WINNT_AUTH_IDENTITY_VERSION 0x200

typedef struct _SEC_WINNT_AUTH_IDENTITY_EXW {
    unsigned long Version;
    unsigned long Length;
    unsigned short *User;           //  Non-NULL terminated string.
    unsigned long UserLength;       //  # of characters (NOT bytes), not including NULL.
    unsigned short *Domain;         //  Non-NULL terminated string.
    unsigned long DomainLength;     //  # of characters (NOT bytes), not including NULL.
    unsigned short *Password;       //  Non-NULL terminated string.
    unsigned long PasswordLength;   //  # of characters (NOT bytes), not including NULL.
    unsigned long Flags;
    unsigned short *PackageList;
    unsigned long PackageListLength;
} SEC_WINNT_AUTH_IDENTITY_EXW, *PSEC_WINNT_AUTH_IDENTITY_EXW;

#define SEC_WINNT_AUTH_IDENTITY_EX  SEC_WINNT_AUTH_IDENTITY_EXW    
#define PSEC_WINNT_AUTH_IDENTITY_EX PSEC_WINNT_AUTH_IDENTITY_EXW   

#endif // SEC_WINNT_AUTH_IDENTITY_VERSION


typedef PVOID PSEC_WINNT_AUTH_IDENTITY_OPAQUE; // the credential structure is opaque


#if (NTDDI_VERSION >= NTDDI_WIN7)                                 
//
//  Convert the _OPAQUE structure passed in to the
//  3 tuple <username, domainname, 'password'>.
//
//  Note: The 'strings' returned need not necessarily be
//  in user recognisable form. The purpose of this API
//  is to 'flatten' the _OPAQUE structure into the 3 tuple.
//  User recognisable <username, domainname> can always be
//  obtained by passing NULL to the pszPackedCredentialsString
//  parameter.
//
// zero out the pszPackedCredentialsString then
// free the returned memory using SspiLocalFree()
//

SECURITY_STATUS
SEC_ENTRY
SspiEncodeAuthIdentityAsStrings(
    __in PSEC_WINNT_AUTH_IDENTITY_OPAQUE pAuthIdentity,
    __deref_out_opt PCWSTR* ppszUserName,
    __deref_out_opt PCWSTR* ppszDomainName,
    __deref_opt_out_opt PCWSTR* ppszPackedCredentialsString
    );

SECURITY_STATUS
SEC_ENTRY
SspiValidateAuthIdentity(
    __in PSEC_WINNT_AUTH_IDENTITY_OPAQUE AuthData
    );

//
// free the returned memory using SspiFreeAuthIdentity()
//

SECURITY_STATUS
SEC_ENTRY
SspiCopyAuthIdentity(
    __in PSEC_WINNT_AUTH_IDENTITY_OPAQUE AuthData,
    __deref_out PSEC_WINNT_AUTH_IDENTITY_OPAQUE* AuthDataCopy
    );

//
// use only for the memory returned by SspiCopyAuthIdentity().
// Internally calls SspiZeroAuthIdentity().
//

VOID
SEC_ENTRY
SspiFreeAuthIdentity(
    __in_opt PSEC_WINNT_AUTH_IDENTITY_OPAQUE AuthData
    );

VOID
SEC_ENTRY
SspiZeroAuthIdentity(
    __in_opt PSEC_WINNT_AUTH_IDENTITY_OPAQUE AuthData
    );

VOID
SEC_ENTRY
SspiLocalFree(
    __in_opt PVOID DataBuffer
    );

//
// call SspiFreeAuthIdentity to free the returned AuthIdentity 
// which zeroes out the credentials blob before freeing it
//

SECURITY_STATUS
SEC_ENTRY
SspiEncodeStringsAsAuthIdentity(
    __in_opt PCWSTR pszUserName,
    __in_opt PCWSTR pszDomainName,
    __in_opt PCWSTR pszPackedCredentialsString,
    __deref_out PSEC_WINNT_AUTH_IDENTITY_OPAQUE* ppAuthIdentity
    );

SECURITY_STATUS
SEC_ENTRY
SspiCompareAuthIdentities(
    __in_opt PSEC_WINNT_AUTH_IDENTITY_OPAQUE AuthIdentity1,
    __in_opt PSEC_WINNT_AUTH_IDENTITY_OPAQUE AuthIdentity2,
    __out_opt PBOOLEAN SameSuppliedUser,
    __out_opt PBOOLEAN SameSuppliedIdentity
    );

//
// zero out the returned AuthIdentityByteArray then
// free the returned memory using SspiLocalFree()
//

SECURITY_STATUS
SEC_ENTRY
SspiMarshalAuthIdentity(
    __in PSEC_WINNT_AUTH_IDENTITY_OPAQUE AuthIdentity,
    __out unsigned long* AuthIdentityLength,
    __deref_out_bcount(*AuthIdentityLength) char** AuthIdentityByteArray
    );

//
// free the returned auth identity using SspiFreeAuthIdentity()
//

SECURITY_STATUS
SEC_ENTRY
SspiUnmarshalAuthIdentity(
    __in unsigned long AuthIdentityLength,
    __in_bcount(AuthIdentityLength) char* AuthIdentityByteArray,
    __deref_out PSEC_WINNT_AUTH_IDENTITY_OPAQUE* ppAuthIdentity
    );

BOOLEAN
SEC_ENTRY
SspiIsPromptingNeeded(
    __in unsigned long ErrorOrNtStatus
    );

SECURITY_STATUS
SEC_ENTRY
SspiGetTargetHostName(
    __in PCWSTR pszTargetName,
    __deref_out PWSTR* pszHostName
    );

SECURITY_STATUS
SEC_ENTRY
SspiExcludePackage(
    __in_opt PSEC_WINNT_AUTH_IDENTITY_OPAQUE AuthIdentity,
    __in PCWSTR pszPackageName,
    __deref_out PSEC_WINNT_AUTH_IDENTITY_OPAQUE* ppNewAuthIdentity
    );

//
// Common types used by negotiable security packages
//
// These are defined after W2K
//

#define SEC_WINNT_AUTH_IDENTITY_MARSHALLED      0x4     // all data is in one buffer
#define SEC_WINNT_AUTH_IDENTITY_ONLY            0x8     // these credentials are for identity only - no PAC needed

#endif // NTDDI_VERSION
#endif // __SSPI_H__

#ifndef SECURITY_USER_DATA_DEFINED
#define SECURITY_USER_DATA_DEFINED

typedef struct _SECURITY_USER_DATA {
    SECURITY_STRING UserName;           // User name
    SECURITY_STRING LogonDomainName;    // Domain the user logged on to
    SECURITY_STRING LogonServer;        // Server that logged the user on
    PSID            pSid;               // SID of user
} SECURITY_USER_DATA, *PSECURITY_USER_DATA;

typedef SECURITY_USER_DATA SecurityUserData, * PSecurityUserData;


#define UNDERSTANDS_LONG_NAMES  1
#define NO_LONG_NAMES           2

#endif // SECURITY_USER_DATA_DEFINED

NTSTATUS SEC_ENTRY
GetSecurityUserInfo(
    __in_opt    PLUID LogonId,
    __in        ULONG Flags,
    __deref_out PSecurityUserData * UserInformation
    );

NTSTATUS SEC_ENTRY
MapSecurityError( __in SECURITY_STATUS SecStatus );

#define DD_MUP_DEVICE_NAME L"\\Device\\Mup"    


//
// The actual prefix resolution IOCTL issued by MUP to
// redirectors to determine who is responsible for a
// \\server\share prefix.
//

//
// For use with legacy providers, which register with
// FsRtlRegisterUncProvider().
//

#define IOCTL_REDIR_QUERY_PATH              CTL_CODE(FILE_DEVICE_NETWORK_FILE_SYSTEM, 99, METHOD_NEITHER, FILE_ANY_ACCESS)

//
// For use by redirectors conforming to the Vista redirector model.
// These register with FsRtlRegisterUncProviderEx().
//

#define IOCTL_REDIR_QUERY_PATH_EX       CTL_CODE(FILE_DEVICE_NETWORK_FILE_SYSTEM, 100, METHOD_NEITHER, FILE_ANY_ACCESS)

//
// Used by MUP prefix resolution.
// For use with legacy providers, which register with
// FsRtlRegisterUncProvider().
//

typedef struct _QUERY_PATH_REQUEST {
    ULONG                   PathNameLength;
    PIO_SECURITY_CONTEXT    SecurityContext;
    WCHAR                   FilePathName[1];
} QUERY_PATH_REQUEST, *PQUERY_PATH_REQUEST;

//
// Used by MUP prefix resolution.
// Issued to providers which register with FsRtlRegisterUncProviderEx()
// These are providers conforming to the Vista redirector model.
//

typedef struct _QUERY_PATH_REQUEST_EX {
    PIO_SECURITY_CONTEXT    pSecurityContext;
    ULONG                   EaLength;
    PVOID                   pEaBuffer;

    //
    // Pointer to filename will be passed to provider.
    // Providers MUST NOT modify this string.
    //

    UNICODE_STRING          PathName;

    //
    // Pointer to optional domain service name.  Only providers which
    // register as FSRTL_UNC_PROVIDER_FLAGS_DOMAIN_SVC_AWARE will see
    // domain service names.
    //
    // This consumes 2 of the 5 ULONG_PTRs initially reserved in the
    // _EX query.  New as of Windows 7.
    //

    UNICODE_STRING          DomainServiceName;

    //
    // Reserved 
    // 

    ULONG_PTR               Reserved[ 3 ];
} QUERY_PATH_REQUEST_EX, *PQUERY_PATH_REQUEST_EX;

typedef struct _QUERY_PATH_RESPONSE {
    ULONG LengthAccepted;
} QUERY_PATH_RESPONSE, *PQUERY_PATH_RESPONSE;

#ifndef _WNNC_
#define _WNNC_

//
// Network types
//

#define     WNNC_NET_MSNET       0x00010000
#define     WNNC_NET_SMB         0x00020000
#define     WNNC_NET_NETWARE     0x00030000
#define     WNNC_NET_VINES       0x00040000
#define     WNNC_NET_10NET       0x00050000
#define     WNNC_NET_LOCUS       0x00060000
#define     WNNC_NET_SUN_PC_NFS  0x00070000
#define     WNNC_NET_LANSTEP     0x00080000
#define     WNNC_NET_9TILES      0x00090000
#define     WNNC_NET_LANTASTIC   0x000A0000
#define     WNNC_NET_AS400       0x000B0000
#define     WNNC_NET_FTP_NFS     0x000C0000
#define     WNNC_NET_PATHWORKS   0x000D0000
#define     WNNC_NET_LIFENET     0x000E0000
#define     WNNC_NET_POWERLAN    0x000F0000
#define     WNNC_NET_BWNFS       0x00100000
#define     WNNC_NET_COGENT      0x00110000
#define     WNNC_NET_FARALLON    0x00120000
#define     WNNC_NET_APPLETALK   0x00130000
#define     WNNC_NET_INTERGRAPH  0x00140000
#define     WNNC_NET_SYMFONET    0x00150000
#define     WNNC_NET_CLEARCASE   0x00160000
#define     WNNC_NET_FRONTIER    0x00170000
#define     WNNC_NET_BMC         0x00180000
#define     WNNC_NET_DCE         0x00190000
#define     WNNC_NET_AVID        0x001A0000
#define     WNNC_NET_DOCUSPACE   0x001B0000
#define     WNNC_NET_MANGOSOFT   0x001C0000
#define     WNNC_NET_SERNET      0x001D0000
#define     WNNC_NET_RIVERFRONT1 0X001E0000
#define     WNNC_NET_RIVERFRONT2 0x001F0000
#define     WNNC_NET_DECORB      0x00200000
#define     WNNC_NET_PROTSTOR    0x00210000
#define     WNNC_NET_FJ_REDIR    0x00220000
#define     WNNC_NET_DISTINCT    0x00230000
#define     WNNC_NET_TWINS       0x00240000
#define     WNNC_NET_RDR2SAMPLE  0x00250000
#define     WNNC_NET_CSC         0x00260000
#define     WNNC_NET_3IN1        0x00270000
#define     WNNC_NET_EXTENDNET   0x00290000
#define     WNNC_NET_STAC        0x002A0000
#define     WNNC_NET_FOXBAT      0x002B0000
#define     WNNC_NET_YAHOO       0x002C0000
#define     WNNC_NET_EXIFS       0x002D0000
#define     WNNC_NET_DAV         0x002E0000
#define     WNNC_NET_KNOWARE     0x002F0000
#define     WNNC_NET_OBJECT_DIRE 0x00300000
#define     WNNC_NET_MASFAX      0x00310000
#define     WNNC_NET_HOB_NFS     0x00320000
#define     WNNC_NET_SHIVA       0x00330000
#define     WNNC_NET_IBMAL       0x00340000
#define     WNNC_NET_LOCK        0x00350000
#define     WNNC_NET_TERMSRV     0x00360000
#define     WNNC_NET_SRT         0x00370000
#define     WNNC_NET_QUINCY      0x00380000
#define     WNNC_NET_OPENAFS     0x00390000
#define     WNNC_NET_AVID1       0X003A0000
#define     WNNC_NET_DFS         0x003B0000
#define     WNNC_NET_KWNP        0x003C0000
#define     WNNC_NET_ZENWORKS    0x003D0000
#define     WNNC_NET_DRIVEONWEB  0x003E0000
#define     WNNC_NET_VMWARE      0x003F0000
#define     WNNC_NET_RSFX        0x00400000
#define     WNNC_NET_MFILES      0x00410000
#define     WNNC_NET_MS_NFS      0x00420000
#define     WNNC_NET_GOOGLE      0x00430000

#define     WNNC_CRED_MANAGER   0xFFFF0000

//
// Network type aliases
//

#define     WNNC_NET_LANMAN      WNNC_NET_SMB


#endif  // _WNNC_
#define VOLSNAPCONTROLTYPE                              0x00000053 // 'S'
#define IOCTL_VOLSNAP_FLUSH_AND_HOLD_WRITES             CTL_CODE(VOLSNAPCONTROLTYPE, 0, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS) 

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwQueryObject(
    __in_opt HANDLE Handle,
    __in OBJECT_INFORMATION_CLASS ObjectInformationClass,
    __out_bcount_opt(ObjectInformationLength) PVOID ObjectInformation,
    __in ULONG ObjectInformationLength,
    __out_opt PULONG ReturnLength
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwNotifyChangeKey(
    __in HANDLE KeyHandle,
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

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwCreateEvent (
    __out PHANDLE EventHandle,
    __in ACCESS_MASK DesiredAccess,
    __in_opt POBJECT_ATTRIBUTES ObjectAttributes,
    __in EVENT_TYPE EventType,
    __in BOOLEAN InitialState
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwDeleteFile(
    __in POBJECT_ATTRIBUTES ObjectAttributes
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwDeviceIoControlFile(
    __in HANDLE FileHandle,
    __in_opt HANDLE Event,
    __in_opt PIO_APC_ROUTINE ApcRoutine,
    __in_opt PVOID ApcContext,
    __out PIO_STATUS_BLOCK IoStatusBlock,
    __in ULONG IoControlCode,
    __in_bcount_opt(InputBufferLength) PVOID InputBuffer,
    __in ULONG InputBufferLength,
    __out_bcount_opt(OutputBufferLength) PVOID OutputBuffer,
    __in ULONG OutputBufferLength
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwQueryDirectoryFile(
    __in HANDLE FileHandle,
    __in_opt HANDLE Event,
    __in_opt PIO_APC_ROUTINE ApcRoutine,
    __in_opt PVOID ApcContext,
    __out PIO_STATUS_BLOCK IoStatusBlock,
    __out_bcount(Length) PVOID FileInformation,
    __in ULONG Length,
    __in FILE_INFORMATION_CLASS FileInformationClass,
    __in BOOLEAN ReturnSingleEntry,
    __in_opt PUNICODE_STRING FileName,
    __in BOOLEAN RestartScan
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwQueryVolumeInformationFile(
    __in HANDLE FileHandle,
    __out PIO_STATUS_BLOCK IoStatusBlock,
    __out_bcount(Length) PVOID FsInformation,
    __in ULONG Length,
    __in FS_INFORMATION_CLASS FsInformationClass
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwSetVolumeInformationFile(
    __in HANDLE FileHandle,
    __out PIO_STATUS_BLOCK IoStatusBlock,
    __in_bcount(Length) PVOID FsInformation,
    __in ULONG Length,
    __in FS_INFORMATION_CLASS FsInformationClass
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwFsControlFile(
    __in HANDLE FileHandle,
    __in_opt HANDLE Event,
    __in_opt PIO_APC_ROUTINE ApcRoutine,
    __in_opt PVOID ApcContext,
    __out PIO_STATUS_BLOCK IoStatusBlock,
    __in ULONG FsControlCode,
    __in_bcount_opt(InputBufferLength) PVOID InputBuffer,
    __in ULONG InputBufferLength,
    __out_bcount_opt(OutputBufferLength) PVOID OutputBuffer,
    __in ULONG OutputBufferLength
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwDuplicateObject(
    __in HANDLE SourceProcessHandle,
    __in HANDLE SourceHandle,
    __in_opt HANDLE TargetProcessHandle,
    __out_opt PHANDLE TargetHandle,
    __in ACCESS_MASK DesiredAccess,
    __in ULONG HandleAttributes,
    __in ULONG Options
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwOpenDirectoryObject(
    __out PHANDLE DirectoryHandle,
    __in ACCESS_MASK DesiredAccess,
    __in POBJECT_ATTRIBUTES ObjectAttributes
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
__drv_when(return==0, __drv_allocatesMem(Region))
NTSYSAPI
NTSTATUS
NTAPI
ZwAllocateVirtualMemory(
    __in HANDLE ProcessHandle,
    __inout PVOID *BaseAddress,
    __in ULONG_PTR ZeroBits,
    __inout PSIZE_T RegionSize,
    __in ULONG AllocationType,
    __in ULONG Protect
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
__drv_when(return==0, __drv_freesMem(Region))
NTSYSAPI
NTSTATUS
NTAPI
ZwFreeVirtualMemory(
    __in HANDLE ProcessHandle,
    __inout PVOID *BaseAddress,
    __inout PSIZE_T RegionSize,
    __in ULONG FreeType
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_when(Timeout == NULL, __drv_maxIRQL(APC_LEVEL))
__drv_when(Timeout->QuadPart != 0, __drv_maxIRQL(APC_LEVEL))
__drv_when(Timeout->QuadPart == 0, __drv_maxIRQL(DISPATCH_LEVEL))
NTSYSAPI
NTSTATUS
NTAPI
ZwWaitForSingleObject(
    __in HANDLE Handle,
    __in BOOLEAN Alertable,
    __in_opt PLARGE_INTEGER Timeout
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(DISPATCH_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwSetEvent (
    __in HANDLE EventHandle,
    __out_opt PLONG PreviousState
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(APC_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwFlushVirtualMemory(
    __in HANDLE ProcessHandle,
    __inout PVOID *BaseAddress,
    __inout PSIZE_T RegionSize,
    __out PIO_STATUS_BLOCK IoStatus
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwOpenProcessTokenEx(
    __in HANDLE ProcessHandle,
    __in ACCESS_MASK DesiredAccess,
    __in ULONG HandleAttributes,
    __out PHANDLE TokenHandle
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwOpenThreadTokenEx(
    __in HANDLE ThreadHandle,
    __in ACCESS_MASK DesiredAccess,
    __in BOOLEAN OpenAsSelf,
    __in ULONG HandleAttributes,
    __out PHANDLE TokenHandle
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwQueryInformationToken (
    __in HANDLE TokenHandle,
    __in TOKEN_INFORMATION_CLASS TokenInformationClass,
    __out_bcount_part_opt(TokenInformationLength,*ReturnLength) PVOID TokenInformation,
    __in ULONG TokenInformationLength,
    __out PULONG ReturnLength
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwSetInformationToken (
    __in HANDLE TokenHandle,
    __in TOKEN_INFORMATION_CLASS TokenInformationClass,
    __in_bcount(TokenInformationLength) PVOID TokenInformation,
    __in ULONG TokenInformationLength
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwSetSecurityObject(
    __in HANDLE Handle,
    __in SECURITY_INFORMATION SecurityInformation,
    __in PSECURITY_DESCRIPTOR SecurityDescriptor
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySecurityObject(
    __in HANDLE Handle,
    __in SECURITY_INFORMATION SecurityInformation,
    __out_bcount_part(Length,*LengthNeeded) PSECURITY_DESCRIPTOR SecurityDescriptor,
    __in ULONG Length,
    __out PULONG LengthNeeded
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwLockFile(
    __in HANDLE FileHandle,
    __in_opt HANDLE Event,
    __in_opt PIO_APC_ROUTINE ApcRoutine,
    __in_opt PVOID ApcContext,
    __out PIO_STATUS_BLOCK IoStatusBlock,
    __in PLARGE_INTEGER ByteOffset,
    __in PLARGE_INTEGER Length,
    __in ULONG Key,
    __in BOOLEAN FailImmediately,
    __in BOOLEAN ExclusiveLock
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwUnlockFile(
    __in HANDLE FileHandle,
    __out PIO_STATUS_BLOCK IoStatusBlock,
    __in PLARGE_INTEGER ByteOffset,
    __in PLARGE_INTEGER Length,
    __in ULONG Key
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwQueryQuotaInformationFile(
    __in HANDLE FileHandle,
    __out PIO_STATUS_BLOCK IoStatusBlock,
    __out_bcount(Length) PVOID Buffer,
    __in ULONG Length,
    __in BOOLEAN ReturnSingleEntry,
    __in_bcount_opt(SidListLength) PVOID SidList,
    __in ULONG SidListLength,
    __in_opt PSID StartSid,
    __in BOOLEAN RestartScan
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwSetQuotaInformationFile(
    __in HANDLE FileHandle,
    __out PIO_STATUS_BLOCK IoStatusBlock,
    __in_bcount(Length) PVOID Buffer,
    __in ULONG Length
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
ZwFlushBuffersFile(
    __in HANDLE FileHandle,
    __out PIO_STATUS_BLOCK IoStatusBlock
    );
#endif

__drv_maxIRQL(PASSIVE_LEVEL)
NTSTATUS
ZwQueryEaFile (
    __in HANDLE FileHandle,
    __out PIO_STATUS_BLOCK IoStatusBlock,
    __out_bcount(Length) PVOID Buffer,
    __in ULONG Length,
    __in BOOLEAN ReturnSingleEntry,
    __in_bcount_opt(EaListLength) PVOID EaList,
    __in ULONG EaListLength,
    __in_opt PULONG EaIndex,
    __in BOOLEAN RestartScan
    );

__drv_maxIRQL(PASSIVE_LEVEL)
NTSTATUS
ZwSetEaFile (
    __in HANDLE FileHandle,
    __out PIO_STATUS_BLOCK IoStatusBlock,
    __in_bcount(Length) PVOID Buffer,
    __in ULONG Length
    );

__drv_maxIRQL(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwDuplicateToken(
    __in HANDLE ExistingTokenHandle,
    __in ACCESS_MASK DesiredAccess,
    __in POBJECT_ATTRIBUTES ObjectAttributes,
    __in BOOLEAN EffectiveOnly,
    __in TOKEN_TYPE TokenType,
    __out PHANDLE NewTokenHandle
    );



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

#endif // _NTIFS_

