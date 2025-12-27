/** @file
  TODO: Brief Description of UEFI Driver LegacySpeaker
  
  TODO: Detailed Description of UEFI Driver LegacySpeaker

  TODO: Copyright for UEFI Driver LegacySpeaker
  
  TODO: License for UEFI Driver LegacySpeaker

**/

#include "LegacySpeaker.h"
#include <Library/IoLib.h>

//////////////////////////////////////////////////////////////////////////
// Speaker
//////////////////////////////////////////////////////////////////////////
/**

  This function will enable the speaker to generate beep

  @retval EFI_STATUS

**/
EFI_STATUS
TurnOnSpeaker (
  )
{
  UINT8                   Data;
  Data = IoRead8 (EFI_SPEAKER_CONTROL_PORT);
  Data |= 0x03;
  IoWrite8(EFI_SPEAKER_CONTROL_PORT, Data);
  return EFI_SUCCESS;
}

/**

  This function will stop beep from speaker.

  @retval Status

**/
EFI_STATUS
TurnOffSpeaker (
  )
{
  UINT8                   Data;

  Data = IoRead8 (EFI_SPEAKER_CONTROL_PORT);
  Data &= 0xFC;
  IoWrite8(EFI_SPEAKER_CONTROL_PORT, Data);
  return EFI_SUCCESS;
}

/**
  Generate beep sound based upon number of beeps and duration of the beep

  @param NumberOfBeeps     Number of beeps which user want to produce
  @param BeepDuration      Duration for speaker gate need to be enabled
  @param TimeInterval      Interval between each beep

  @retval      Does not return if the reset takes place.
               EFI_INVALID_PARAMETER   If ResetType is invalid.

**/
EFI_STATUS
OutputBeep (
  IN     UINTN                              NumberOfBeep,
  IN     UINTN                              BeepDuration,
  IN     UINTN                              TimeInterval
  )
{
  UINTN           Num;

  for (Num=0; Num < NumberOfBeep; Num++) {
    TurnOnSpeaker ();
    //
    // wait some time,at least 120us
    //
    gBS->Stall (BeepDuration);
    TurnOffSpeaker();
    gBS->Stall (TimeInterval);
  }

  return EFI_SUCCESS;
}

/**
  This function will program the speaker tone frequency. The value should be with 64k
  boundary since it takes only 16 bit value which gets programmed in two step IO operation

  @param  Frequency     A value which should be 16 bit only.

  @retval EFI_SUCESS

**/
EFI_STATUS
EFIAPI    
ProgramToneFrequency (
  IN EFI_SPEAKER_IF_PROTOCOL            * This,
  IN  UINT16                            Frequency
  )
{
  UINT8                   Data;

  Data = 0xB6;
  IoWrite8(EFI_TIMER_CONTROL_PORT, Data);

  Data = (UINT8)(Frequency & 0x00FF);
  IoWrite8(EFI_TIMER_2_PORT, Data);
  Data = (UINT8)((Frequency & 0xFF00) >> 8);
  IoWrite8(EFI_TIMER_2_PORT, Data);
  return EFI_SUCCESS;
}

/**
  This function will generate the beep for specified duration.

  @param NumberOfBeeps     Number of beeps which user want to produce
  @param BeepDuration      Duration for speaker gate need to be enabled
  @param TimeInterval      Interval between each beep

  @retval EFI_STATUS

**/
EFI_STATUS
EFIAPI
GenerateBeepTone (
  IN EFI_SPEAKER_IF_PROTOCOL            * This,
  IN  UINTN                             NumberOfBeeps,
  IN  UINTN                             BeepDuration,
  IN  UINTN                             TimeInterval
  )
{

  if ((NumberOfBeeps == 1) && (BeepDuration == 0) && (TimeInterval == 0)) {
    TurnOnSpeaker ();
    return EFI_SUCCESS;
  }

  if ((NumberOfBeeps == 0) && (BeepDuration == 0) && (TimeInterval == 0)) {
    TurnOffSpeaker ();
    return EFI_SUCCESS;
  }

  if (BeepDuration == 0) {
    BeepDuration = EFI_DEFAULT_SHORT_BEEP_DURATION;
  }

  if (TimeInterval == 0) {
    TimeInterval = EFI_DEFAULT_BEEP_TIME_INTERVAL;
  }

  OutputBeep (NumberOfBeeps, BeepDuration, TimeInterval);
  return EFI_SUCCESS;
}

GUID gEfiSpeakerInterfaceProtocolGuid = EFI_SPEAKER_INTERFACE_PROTOCOL_GUID;
EFI_SPEAKER_IF_PROTOCOL gEfiSpeakerInterfaceProtocol = {
	ProgramToneFrequency,
	GenerateBeepTone
};

//////////////////////////////////////////////////////////////////////////
// Driver
//////////////////////////////////////////////////////////////////////////

/**
  Unloads an image.

  @param  ImageHandle           Handle that identifies the image to be unloaded.

  @retval EFI_SUCCESS           The image has been unloaded.
  @retval EFI_INVALID_PARAMETER ImageHandle is not a valid image handle.

**/
EFI_STATUS 
EFIAPI
LegacySpeakerUnload (
  IN EFI_HANDLE  ImageHandle
  )
{
  EFI_STATUS  Status;

  Status = EFI_SUCCESS;
  //
  // Uninstall Driver Supported EFI Version Protocol onto ImageHandle
  //
  Status = gBS->UninstallMultipleProtocolInterfaces(
	  ImageHandle,
	  &gEfiSpeakerInterfaceProtocolGuid, &gEfiSpeakerInterfaceProtocol,
	  NULL
	  );

  if (EFI_ERROR(Status)) {
	  return Status;
  }
  // Clean up
  return EFI_SUCCESS;
}

/**
  This is the declaration of an EFI image entry point. This entry point is
  the same for UEFI Applications, UEFI OS Loaders, and UEFI Drivers including
  both device drivers and bus drivers.

  @param  ImageHandle           The firmware allocated handle for the UEFI image.
  @param  SystemTable           A pointer to the EFI System Table.

  @retval EFI_SUCCESS           The operation completed successfully.
  @retval Others                An unexpected error occurred.
**/
EFI_STATUS
EFIAPI
LegacySpeakerDriverEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;

  Status = EFI_SUCCESS;

  //
  // Install Speaker protocol onto ImageHandle
  //
  Status = gBS->InstallMultipleProtocolInterfaces(
	  &ImageHandle,
	  &gEfiSpeakerInterfaceProtocolGuid, &gEfiSpeakerInterfaceProtocol,
	  NULL
	  );
  ASSERT_EFI_ERROR(Status);
//  gEfiSpeakerInterfaceProtocol.SetSpeakerToneFrequency(&gEfiSpeakerInterfaceProtocol, 0x500);
//  gEfiSpeakerInterfaceProtocol.GenerateBeep(&gEfiSpeakerInterfaceProtocol, 2, 200000, 200000);

  return Status;
}

