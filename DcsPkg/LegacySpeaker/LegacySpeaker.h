/** @file
  TODO: Brief Description of UEFI Driver LegacySpeaker
  
  TODO: Detailed Description of UEFI Driver LegacySpeaker

  TODO: Copyright for UEFI Driver LegacySpeaker
  
  TODO: License for UEFI Driver LegacySpeaker

**/

#ifndef __EFI_LEGACY_SPEAKER_H__
#define __EFI_LEGACY_SPEAKER_H__

#include <Uefi.h>

//
// Libraries
//
#include <Library/UefiBootServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BaseLib.h>
#include <Library/UefiLib.h>
#include <Library/DevicePathLib.h>
#include <Library/DebugLib.h>

//
// UEFI Driver Model Protocols
//
#include <Protocol/ComponentName2.h>
#include <Protocol/ComponentName.h>

//
// Consumed Protocols
//

//
// Produced Protocols
//
#include <Protocol/Speaker.h>


//
// Protocol instances
//
extern EFI_COMPONENT_NAME2_PROTOCOL  gLegacySpeakerComponentName2;
extern EFI_COMPONENT_NAME_PROTOCOL  gLegacySpeakerComponentName;
extern EFI_SPEAKER_IF_PROTOCOL gEfiSpeakerInterfaceProtocol;

//
// Include files with function prototypes
//
#include "ComponentName.h"

//
// Speaker Related Port Information
//
#define EFI_TIMER_COUNTER_PORT            0x40
#define EFI_TIMER_CONTROL_PORT            0x43
#define EFI_TIMER_2_PORT                  0x42
#define EFI_SPEAKER_CONTROL_PORT          0x61

#define EFI_SPEAKER_OFF_MASK              0xFC

#define EFI_DEFAULT_BEEP_FREQUENCY        0x500

//
// Default Intervals/Beep Duration
//
#define EFI_DEFAULT_LONG_BEEP_DURATION    0x70000
#define EFI_DEFAULT_SHORT_BEEP_DURATION   0x50000
#define EFI_DEFAULT_BEEP_TIME_INTERVAL    0x20000


EFI_STATUS
EFIAPI
ProgramToneFrequency(
	IN  EFI_SPEAKER_IF_PROTOCOL           * This,
	IN  UINT16                            Frequency
	);


EFI_STATUS
EFIAPI
GenerateBeepTone(
	IN  EFI_SPEAKER_IF_PROTOCOL           * This,
	IN  UINTN                             NumberOfBeeps,
	IN  UINTN                             BeepDuration,
	IN  UINTN                             TimeInterval
	);

EFI_STATUS
TurnOnSpeaker(
	);

EFI_STATUS
TurnOffSpeaker(
	);

#endif
