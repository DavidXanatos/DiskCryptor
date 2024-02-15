
/*++

Copyright (c) Microsoft Corporation. All rights reserved.

Module Name:

    ata.h

Abstract:

    Defines the structures used by ATA port and the miniport drivers.

Authors:

Revision History:

--*/

#ifndef _NTATA_
#define _NTATA_

#if _MSC_VER >= 1200
#pragma warning(push)
#endif

#pragma warning(disable:4214) // bit field types other than int

//
// IDENTIFY device data (response to 0xEC)
//
#pragma pack(push, id_device_data, 1)
typedef struct _IDENTIFY_DEVICE_DATA {

    struct {
        USHORT Reserved1 : 1;
        USHORT Retired3 : 1;
        USHORT ResponseIncomplete : 1;
        USHORT Retired2 : 3;
        USHORT FixedDevice : 1;
        USHORT RemovableMedia : 1;
        USHORT Retired1 : 7;
        USHORT DeviceType : 1;            
    } GeneralConfiguration;                     // word 0

    USHORT NumCylinders;                        // word 1
    USHORT ReservedWord2;
    USHORT NumHeads;                            // word 3 
    USHORT Retired1[2];   
    USHORT NumSectorsPerTrack;                  // word 6
    USHORT VendorUnique1[3]; 
    UCHAR  SerialNumber[20];                    // word 10-19
    USHORT Retired2[2];  
    USHORT Obsolete1;    
    UCHAR  FirmwareRevision[8];                 // word 23-26 
    UCHAR  ModelNumber[40];                     // word 27-46
    UCHAR  MaximumBlockTransfer;                // word 47
    UCHAR  VendorUnique2;      
    USHORT ReservedWord48;

    struct {
        UCHAR ReservedByte49;
        UCHAR DmaSupported : 1;
        UCHAR LbaSupported : 1;
        UCHAR IordyDisable : 1;
        UCHAR IordySupported : 1;
        UCHAR Reserved1 : 1;
        UCHAR StandybyTimerSupport : 1;
        UCHAR Reserved2 : 2;
        USHORT ReservedWord50;
    }Capabilities;                              // word 49-50        

    USHORT ObsoleteWords51[2]; 

    USHORT TranslationFieldsValid:3;            // word 53

    USHORT Reserved3:13;

    USHORT NumberOfCurrentCylinders;            // word 54
    USHORT NumberOfCurrentHeads;                // word 55
    USHORT CurrentSectorsPerTrack;              // word 56
    ULONG  CurrentSectorCapacity;               // word 57
    UCHAR  CurrentMultiSectorSetting;           // word 58
    UCHAR  MultiSectorSettingValid : 1;

    UCHAR  ReservedByte59 : 7;

    ULONG  UserAddressableSectors;              // word 60-61

    USHORT ObsoleteWord62;

    USHORT MultiWordDMASupport : 8;             // word 63 
    USHORT MultiWordDMAActive : 8;
    USHORT AdvancedPIOModes : 8; 
    USHORT ReservedByte64 : 8;
    USHORT MinimumMWXferCycleTime;  
    USHORT RecommendedMWXferCycleTime; 
    USHORT MinimumPIOCycleTime;      
    USHORT MinimumPIOCycleTimeIORDY; 

    USHORT ReservedWords69[6]; 

    USHORT QueueDepth : 5;

    USHORT ReservedWord75 : 11;
    USHORT ReservedWords76[4];
    USHORT MajorRevision; 
    USHORT MinorRevision;

    struct {
        
        //
        // Word 82
        //
        USHORT SmartCommands : 1;
        USHORT SecurityMode : 1;
        USHORT RemovableMediaFeature : 1;
        USHORT PowerManagement : 1;
        USHORT Reserved1 : 1;
        USHORT WriteCache : 1;
        USHORT LookAhead : 1;
        USHORT ReleaseInterrupt : 1;
        USHORT ServiceInterrupt : 1;
        USHORT DeviceReset : 1;
        USHORT HostProtectedArea : 1;
        USHORT Obsolete1 : 1;
        USHORT WriteBuffer : 1;
        USHORT ReadBuffer : 1;
        USHORT Nop : 1;
        USHORT Obsolete2 : 1;

        //
        // Word 83
        //
        USHORT DownloadMicrocode : 1;
        USHORT DmaQueued : 1;
        USHORT Cfa : 1;
        USHORT AdvancedPm : 1;
        USHORT Msn : 1;
        USHORT PowerUpInStandby : 1;
        USHORT ManualPowerUp : 1;
        USHORT Reserved2 : 1;
        USHORT SetMax : 1;
        USHORT Acoustics : 1;
        USHORT BigLba : 1;
        USHORT DeviceConfigOverlay : 1;
        USHORT FlushCache : 1;
        USHORT FlushCacheExt : 1;
        USHORT Resrved3 : 2;

        //
        // Word 84
        //
        USHORT SmartErrorLog : 1;
        USHORT SmartSelfTest : 1;
        USHORT MediaSerialNumber : 1;
        USHORT MediaCardPassThrough : 1;
        USHORT StreamingFeature : 1;
        USHORT GpLogging : 1;
        USHORT WriteFua : 1;
        USHORT WriteQueuedFua : 1;
        USHORT WWN64Bit : 1;
        USHORT URGReadStream : 1;
        USHORT URGWriteStream : 1;
        USHORT ReservedForTechReport : 2;
        USHORT IdleWithUnloadFeature : 1;
        USHORT Reserved4 : 2;

    }CommandSetSupport;                        

    struct {

        //
        // Word 85
        //
        USHORT SmartCommands : 1;
        USHORT SecurityMode : 1;
        USHORT RemovableMediaFeature : 1;
        USHORT PowerManagement : 1;
        USHORT Reserved1 : 1;
        USHORT WriteCache : 1;
        USHORT LookAhead : 1;
        USHORT ReleaseInterrupt : 1;
        USHORT ServiceInterrupt : 1;
        USHORT DeviceReset : 1;
        USHORT HostProtectedArea : 1;
        USHORT Obsolete1 : 1;
        USHORT WriteBuffer : 1;
        USHORT ReadBuffer : 1;
        USHORT Nop : 1;
        USHORT Obsolete2 : 1;

        //
        // Word 86
        //
        USHORT DownloadMicrocode : 1;
        USHORT DmaQueued : 1;
        USHORT Cfa : 1;
        USHORT AdvancedPm : 1;
        USHORT Msn : 1;
        USHORT PowerUpInStandby : 1;
        USHORT ManualPowerUp : 1;
        USHORT Reserved2 : 1;
        USHORT SetMax : 1;
        USHORT Acoustics : 1;
        USHORT BigLba : 1;
        USHORT DeviceConfigOverlay : 1;
        USHORT FlushCache : 1;
        USHORT FlushCacheExt : 1;
        USHORT Resrved3 : 2;

        //
        // Word 87
        //
        USHORT SmartErrorLog : 1;
        USHORT SmartSelfTest : 1;
        USHORT MediaSerialNumber : 1;
        USHORT MediaCardPassThrough : 1;
        USHORT StreamingFeature : 1;
        USHORT GpLogging : 1;
        USHORT WriteFua : 1;
        USHORT WriteQueuedFua : 1;
        USHORT WWN64Bit : 1;
        USHORT URGReadStream : 1;
        USHORT URGWriteStream : 1;
        USHORT ReservedForTechReport : 2;
        USHORT IdleWithUnloadFeature : 1;
        USHORT Reserved4 : 2;

    }CommandSetActive;                          

    USHORT UltraDMASupport : 8;                 // word 88
    USHORT UltraDMAActive  : 8; 

    USHORT ReservedWord89[4];
    USHORT HardwareResetResult;
    USHORT CurrentAcousticValue : 8;
    USHORT RecommendedAcousticValue : 8;
    USHORT ReservedWord95[5];

    ULONG  Max48BitLBA[2];                      // word 100-103

    USHORT StreamingTransferTime;
        USHORT ReservedWord105;
        struct { 
                USHORT LogicalSectorsPerPhysicalSector : 4;
                USHORT Reserved0 : 8;
                USHORT LogicalSectorLongerThan256Words : 1;
                USHORT MultipleLogicalSectorsPerPhysicalSector : 1;
                USHORT Reserved1 : 2;
        } PhysicalLogicalSectorSize;                            // word 106

        USHORT InterSeekDelay;                                          //word 107
        USHORT WorldWideName[4];                                        //words 108-111
        USHORT ReservedForWorldWideName128[4];          //words 112-115
        USHORT ReservedForTlcTechnicalReport;           //word 116
        USHORT WordsPerLogicalSector[2];                        //words 117-118
        
        struct {
                USHORT ReservedForDrqTechnicalReport : 1;
                USHORT WriteReadVerifySupported : 1;
                USHORT Reserved0 : 11;
                USHORT Reserved1 : 2;
        }CommandSetSupportExt;                                                  //word 119

        struct {
                USHORT ReservedForDrqTechnicalReport : 1;
                USHORT WriteReadVerifyEnabled : 1;
                USHORT Reserved0 : 11;
                USHORT Reserved1 : 2;
        }CommandSetActiveExt;                                                   //word 120
                
        USHORT ReservedForExpandedSupportandActive[6];
        
        USHORT MsnSupport : 2;                                                  //word 127
        USHORT ReservedWord127 : 14;

        struct {                                                                                //word 128
                USHORT SecuritySupported : 1;
                USHORT SecurityEnabled : 1;
                USHORT SecurityLocked : 1;
                USHORT SecurityFrozen : 1;
                USHORT SecurityCountExpired : 1;
                USHORT EnhancedSecurityEraseSupported : 1;
                USHORT Reserved0 : 2;
                USHORT SecurityLevel : 1;
                USHORT Reserved1 : 7;
        } SecurityStatus;

    USHORT ReservedWord129[31];
    
    struct {                                                                            //word 160
        USHORT MaximumCurrentInMA : 12;
        USHORT CfaPowerMode1Disabled : 1;
        USHORT CfaPowerMode1Required : 1;
        USHORT Reserved0 : 1;
        USHORT Word160Supported : 1;
    } CfaPowerMode1;

    USHORT ReservedForCfaWord161[8];                //Words 161-168

    struct {                                        //Word 169
        USHORT SupportsTrim : 1;
        USHORT Reserved0    : 15;                        
    } DataSetManagementFeature;

    USHORT ReservedForCfaWord170[6];                //Words 170-175

    USHORT CurrentMediaSerialNumber[30];            //Words 176-205
    
    USHORT ReservedWord206;                         //Word 206
    USHORT ReservedWord207[2];                      //Words 207-208
    
    struct {                                        //Word 209
        USHORT AlignmentOfLogicalWithinPhysical: 14;
        USHORT Word209Supported: 1;
        USHORT Reserved0: 1;                        
    } BlockAlignment;
    
    
    USHORT WriteReadVerifySectorCountMode3Only[2]; //Words 210-211
    USHORT WriteReadVerifySectorCountMode2Only[2]; //Words 212-213
    
    struct {
        USHORT NVCachePowerModeEnabled: 1;
        USHORT Reserved0: 3;
        USHORT NVCacheFeatureSetEnabled: 1;
        USHORT Reserved1: 3;
        USHORT NVCachePowerModeVersion: 4;
        USHORT NVCacheFeatureSetVersion: 4;
    } NVCacheCapabilities;                  //Word 214
    USHORT NVCacheSizeLSW;                  //Word 215
    USHORT NVCacheSizeMSW;                  //Word 216
    USHORT NominalMediaRotationRate;        //Word 217; value 0001h means non-rotating media.
    USHORT ReservedWord218;                 //Word 218
    struct {
        UCHAR NVCacheEstimatedTimeToSpinUpInSeconds;
        UCHAR Reserved;
    } NVCacheOptions;                       //Word 219
    
    USHORT ReservedWord220[35];             //Words 220-254
    
    USHORT Signature : 8;                   //Word 255
    USHORT CheckSum : 8;
        
} IDENTIFY_DEVICE_DATA, *PIDENTIFY_DEVICE_DATA;
#pragma pack (pop, id_device_data)

//
// identify packet data (response to 0xA1)
//
#pragma pack (push, id_packet_data, 1)
typedef struct _IDENTIFY_PACKET_DATA {

    struct {
        USHORT PacketType : 2;
        USHORT Reserved1 : 3;
        USHORT DrqDelay : 2;
        USHORT RemovableMedia : 1;
        USHORT CommandPacketType : 5;
        USHORT Reserved2 : 1;
        USHORT DeviceType : 2;
    }GeneralConfiguration;

    USHORT ResevedWord1;
    USHORT UniqueConfiguration;
    USHORT ReservedWords3[7];
    USHORT SerialNumber[10];
    USHORT ReservedWords20[3];
    USHORT FirmwareRevision[4];
    USHORT ModelNumber[20];
    USHORT ReservedWords47[2];

    struct {
        USHORT VendorSpecific : 8;
        USHORT DmaSupported : 1;
        USHORT LbaSupported : 1;
        USHORT IordyDisabled : 1;
        USHORT IordySupported : 1;
        USHORT Obsolete : 1;
        USHORT OverlapSupported : 1;
        USHORT QueuedCommandsSupported : 1;
        USHORT InterleavedDmaSupported : 1;
    } Capabilities;

    USHORT ReservedWord50;
    USHORT ObsoleteWords51[2];

    USHORT TranslationFieldsValid:3;   

    USHORT Reserved3:13;

    USHORT ReservedWords54[9];

    USHORT MultiWordDMASupport : 8;             // word 63 
    USHORT MultiWordDMAActive : 8;
    USHORT AdvancedPIOModes : 8; 
    USHORT ReservedByte64 : 8;
    USHORT MinimumMWXferCycleTime;  
    USHORT RecommendedMWXferCycleTime; 
    USHORT MinimumPIOCycleTime;      
    USHORT MinimumPIOCycleTimeIORDY; 

    USHORT ReservedWords69[2]; 

    USHORT BusReleaseDelay;
    USHORT ServiceCommandDelay;

    USHORT ReservedWords73[2];

    USHORT QueueDepth : 5;

    USHORT ReservedWord75 : 11;
    USHORT ReservedWords76[4];
    USHORT MajorRevision; 
    USHORT MinorRevision;

    struct {
        USHORT SmartCommands : 1;
        USHORT SecurityMode : 1;
        USHORT RemovableMedia : 1;
        USHORT PowerManagement : 1;
        USHORT PacketCommands : 1;
        USHORT WriteCache : 1;
        USHORT LookAhead : 1;
        USHORT ReleaseInterrupt : 1;
        USHORT ServiceInterrupt : 1;
        USHORT DeviceReset : 1;
        USHORT HostProtectedArea : 1;
        USHORT Obsolete1 : 1;
        USHORT WriteBuffer : 1;
        USHORT ReadBuffer : 1;
        USHORT Nop : 1;
        USHORT Obsolete2 : 1;
        USHORT DownloadMicrocode : 1;
        USHORT Reserved1 : 3;
        USHORT Msn : 1;
        USHORT PowerUpInStandby : 1;
        USHORT ManualPowerUp : 1;
        USHORT Reserved2 : 1;
        USHORT SetMax : 1;
        USHORT Reserved3 : 7;
    } CommandSetSupport;

    USHORT ReservedWord84;

    struct {
        USHORT SmartCommands : 1;
        USHORT SecurityMode : 1;
        USHORT RemovableMedia : 1;
        USHORT PowerManagement : 1;
        USHORT PacketCommands : 1;
        USHORT WriteCache : 1;
        USHORT LookAhead : 1;
        USHORT ReleaseInterrupt : 1;
        USHORT ServiceInterrupt : 1;
        USHORT DeviceReset : 1;
        USHORT HostProtectedArea : 1;
        USHORT Obsolete1 : 1;
        USHORT WriteBuffer : 1;
        USHORT ReadBuffer : 1;
        USHORT Nop : 1;
        USHORT Obsolete2 : 1;
        USHORT DownloadMicrocode : 1;
        USHORT Reserved1 : 3;
        USHORT Msn : 1;
        USHORT PowerUpInStandby : 1;
        USHORT ManualPowerUp : 1;
        USHORT Reserved2 : 1;
        USHORT SetMax : 1;
        USHORT Reserved : 7;
    } CommandSetActive;

    USHORT ReservedWord87;

    USHORT UltraDMASupport : 8;                 // word 88
    USHORT UltraDMAActive  : 8; 

    USHORT ReservedWords89[4];
    USHORT HardwareResetResult;
    USHORT ReservedWords94[32];

    USHORT AtapiZeroByteCount;

    USHORT MsnSupport : 2;

    USHORT ReservedWord127 : 14;
    USHORT SecurityStatus;
    USHORT ReservedWord129[126];
    USHORT Signature : 8;
    USHORT CheckSum : 8;

} IDENTIFY_PACKET_DATA, *PIDENTIFY_PACKET_DATA;
#pragma pack (pop, id_packet_data)

//
// Register FIS
//
#pragma pack (push, regfis, 1)
typedef struct _REGISTER_FIS {

    //
    // dword 0
    //
    UCHAR FisType;
    UCHAR Reserved0 : 7;
    UCHAR CmdReg : 1;
    UCHAR Command;
    UCHAR Features;

    //
    // dword 1
    //
    UCHAR SectorNumber;
    UCHAR CylinderLow;
    UCHAR CylinderHigh;
    UCHAR DeviceHead;

    //
    // dword 2
    //
    UCHAR SectorNumberExp;
    UCHAR CylinderLowExp;
    UCHAR CylinderHighExp;
    UCHAR FeaturesExp;

    //
    // dword 3
    //
    UCHAR SectorCount;
    UCHAR SectorCountExp;
    UCHAR Reserved2;
    UCHAR Control;

    //
    // dword 4
    //
    ULONG Reserved3;
        
}REGISTER_FIS, *PREGISTER_FIS;
#pragma pack (pop, regfis)

//
// ATAPI specific scsiops
//
#define ATAPI_MODE_SENSE        0x5A
#define ATAPI_MODE_SELECT       0x55
#define ATAPI_LS120_FORMAT_UNIT 0x24

//
// IDE driveSelect register bit for LBA mode
//
#define IDE_LBA_MODE   (1 << 6)

//
// IDE drive control definitions
//
#define IDE_DC_DISABLE_INTERRUPTS    0x02
#define IDE_DC_RESET_CONTROLLER      0x04
#define IDE_DC_REENABLE_CONTROLLER   0x00

//
// IDE status definitions
//
#define IDE_STATUS_ERROR             0x01
#define IDE_STATUS_INDEX             0x02
#define IDE_STATUS_CORRECTED_ERROR   0x04
#define IDE_STATUS_DRQ               0x08
#define IDE_STATUS_DSC               0x10
#define IDE_STATUS_DRDY              0x40
#define IDE_STATUS_IDLE              0x50
#define IDE_STATUS_BUSY              0x80

//
// IDE error definitions
//
#define IDE_ERROR_BAD_BLOCK          0x80
#define IDE_ERROR_CRC_ERROR          IDE_ERROR_BAD_BLOCK
#define IDE_ERROR_DATA_ERROR         0x40
#define IDE_ERROR_MEDIA_CHANGE       0x20
#define IDE_ERROR_ID_NOT_FOUND       0x10
#define IDE_ERROR_MEDIA_CHANGE_REQ   0x08
#define IDE_ERROR_COMMAND_ABORTED    0x04
#define IDE_ERROR_END_OF_MEDIA       0x02
#define IDE_ERROR_ILLEGAL_LENGTH     0x01
#define IDE_ERROR_ADDRESS_NOT_FOUND  IDE_ERROR_ILLEGAL_LENGTH


//
// IDE command definitions
//
#define IDE_COMMAND_NOP                         0x00
#define IDE_COMMAND_DATA_SET_MANAGEMENT         0x06
#define IDE_COMMAND_ATAPI_RESET                 0x08
#define IDE_COMMAND_READ                        0x20
#define IDE_COMMAND_READ_EXT                    0x24
#define IDE_COMMAND_READ_DMA_EXT                0x25
#define IDE_COMMAND_READ_DMA_QUEUED_EXT         0x26
#define IDE_COMMAND_READ_MULTIPLE_EXT           0x29
#define IDE_COMMAND_WRITE                       0x30
#define IDE_COMMAND_WRITE_EXT                   0x34
#define IDE_COMMAND_WRITE_DMA_EXT               0x35
#define IDE_COMMAND_WRITE_DMA_QUEUED_EXT        0x36
#define IDE_COMMAND_WRITE_MULTIPLE_EXT          0x39
#define IDE_COMMAND_WRITE_DMA_FUA_EXT           0x3D
#define IDE_COMMAND_WRITE_DMA_QUEUED_FUA_EXT    0x3E
#define IDE_COMMAND_VERIFY                      0x40
#define IDE_COMMAND_VERIFY_EXT                  0x42
#define IDE_COMMAND_EXECUTE_DEVICE_DIAGNOSTIC   0x90
#define IDE_COMMAND_SET_DRIVE_PARAMETERS        0x91
#define IDE_COMMAND_ATAPI_PACKET                0xA0
#define IDE_COMMAND_ATAPI_IDENTIFY              0xA1
#define IDE_COMMAND_SMART                       0xB0
#define IDE_COMMAND_READ_MULTIPLE               0xC4
#define IDE_COMMAND_WRITE_MULTIPLE              0xC5
#define IDE_COMMAND_SET_MULTIPLE                0xC6
#define IDE_COMMAND_READ_DMA                    0xC8
#define IDE_COMMAND_WRITE_DMA                   0xCA
#define IDE_COMMAND_WRITE_DMA_QUEUED            0xCC
#define IDE_COMMAND_WRITE_MULTIPLE_FUA_EXT      0xCE
#define IDE_COMMAND_GET_MEDIA_STATUS            0xDA
#define IDE_COMMAND_DOOR_LOCK                   0xDE
#define IDE_COMMAND_DOOR_UNLOCK                 0xDF
#define IDE_COMMAND_STANDBY_IMMEDIATE           0xE0
#define IDE_COMMAND_IDLE_IMMEDIATE              0xE1
#define IDE_COMMAND_CHECK_POWER                 0xE5
#define IDE_COMMAND_SLEEP                       0xE6
#define IDE_COMMAND_FLUSH_CACHE                 0xE7
#define IDE_COMMAND_FLUSH_CACHE_EXT             0xEA
#define IDE_COMMAND_IDENTIFY                    0xEC
#define IDE_COMMAND_MEDIA_EJECT                 0xED
#define IDE_COMMAND_SET_FEATURE                 0xEF
#define IDE_COMMAND_SECURITY_FREEZE_LOCK        0xF5
#define IDE_COMMAND_NOT_VALID                   0xFF

//
// IDE Set Transfer Mode
//
#define IDE_SET_DEFAULT_PIO_MODE(mode)      ((UCHAR) 1)     // disable I/O Ready
#define IDE_SET_ADVANCE_PIO_MODE(mode)      ((UCHAR) ((1 << 3) | (mode)))
#define IDE_SET_SWDMA_MODE(mode)            ((UCHAR) ((1 << 4) | (mode)))
#define IDE_SET_MWDMA_MODE(mode)            ((UCHAR) ((1 << 5) | (mode)))
#define IDE_SET_UDMA_MODE(mode)             ((UCHAR) ((1 << 6) | (mode)))

//
// Set features parameter list
//
#define IDE_FEATURE_ENABLE_WRITE_CACHE          0x2
#define IDE_FEATURE_SET_TRANSFER_MODE           0x3
#define IDE_FEATURE_ENABLE_SATA_FEATURE         0x10
#define IDE_FEATURE_DISABLE_MSN                 0x31
#define IDE_FEATURE_DISABLE_REVERT_TO_POWER_ON  0x66
#define IDE_FEATURE_DISABLE_WRITE_CACHE         0x82
#define IDE_FEATURE_DISABLE_SATA_FEATURE        0x90
#define IDE_FEATURE_ENABLE_MSN                  0x95

//
// SATA Features Sector Count parameter list
//

#define IDE_SATA_FEATURE_NON_ZERO_DMA_BUFFER_OFFSET         0x1
#define IDE_SATA_FEATURE_DMA_SETUP_FIS_AUTO_ACTIVATE        0x2
#define IDE_SATA_FEATURE_DEVICE_INITIATED_POWER_MANAGEMENT  0x3
#define IDE_SATA_FEATURE_GUARANTEED_IN_ORDER_DELIVERY       0x4
#define IDE_SATA_FEATURE_ASYNCHRONOUS_NOTIFICATION          0x5
#define IDE_SATA_FEATURE_SOFTWARE_SETTINGS_PRESERVATION     0x6

//
// SMART sub command list
//
#define IDE_SMART_READ_ATTRIBUTES               0xD0
#define IDE_SMART_READ_THRESHOLDS               0xD1
#define IDE_SMART_ENABLE_DISABLE_AUTOSAVE       0xD2
#define IDE_SMART_SAVE_ATTRIBUTE_VALUES         0xD3
#define IDE_SMART_EXECUTE_OFFLINE_DIAGS         0xD4
#define IDE_SMART_READ_LOG                      0xD5
#define IDE_SMART_WRITE_LOG                     0xD6
#define IDE_SMART_ENABLE                        0xD8
#define IDE_SMART_DISABLE                       0xD9
#define IDE_SMART_RETURN_STATUS                 0xDA
#define IDE_SMART_ENABLE_DISABLE_AUTO_OFFLINE   0xDB

//
// Features for IDE_COMMAND_DATA_SET_MANAGEMENT
//
#define IDE_DSM_FEATURE_TRIM                  0x0001    //bit 0 of WORD

#if _MSC_VER >= 1200
#pragma warning(pop)
#else
#pragma warning(default:4214)
#endif

#endif

