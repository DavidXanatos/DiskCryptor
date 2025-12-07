[Setup]
AppName=DiskCryptor
AppVerName=DiskCryptor 1.2
AppId=DiskCryptor
AppVersion=1.2.1
AppPublisher=http://diskcryptor.org/
AppPublisherURL=http://diskcryptor.org/
AppMutex=DISKCRYPTOR_MUTEX
DefaultDirName={pf}\dcrypt
DefaultGroupName=DiskCryptor
UninstallDisplayIcon={app}\dcrypt.exe
OutputBaseFilename=dcrypt_setup_1.2_beta_3
Compression=lzma
ArchitecturesAllowed=x86 x64
ArchitecturesInstallIn64BitMode=x64
AllowNoIcons=yes
AlwaysRestart=yes
LicenseFile=..\DCrypt\license.txt
;WizardImageFile=WizardImage0.bmp
;WizardSmallImageFile=WizardSmallImage0.bmp

[Files]
Source: "..\DCrypt\Bin\Release_i386\dccon.exe"; DestDir: "{app}"; DestName: "dccon.exe"; Check: "not Is64BitInstallMode"; MinVersion: 0.0,5.0; Flags: ignoreversion; 
Source: "..\DCrypt\Bin\Release_i386\dcinst.exe"; DestDir: "{app}"; DestName: "dcinst.exe"; Check: "not Is64BitInstallMode"; MinVersion: 0.0,5.0; Flags: ignoreversion;
Source: "..\DCrypt\Bin\Release_i386\dcrypt.exe"; DestDir: "{app}"; DestName: "dcrypt.exe"; Check: "not Is64BitInstallMode"; MinVersion: 0.0,5.0; Flags: ignoreversion;
Source: "..\DCrypt\Bin\Build_i386\dcrypt.sys"; DestDir: "{app}"; DestName: "dcrypt.sys"; Check: "not Is64BitInstallMode"; MinVersion: 0.0,5.0; Flags: ignoreversion;
Source: "..\DCrypt\Bin\Release_i386\dcapi.dll"; DestDir: "{app}"; DestName: "dcapi.dll"; Check: "not Is64BitInstallMode"; MinVersion: 0.0,5.0; Flags: ignoreversion;
;Source: "..\DCrypt\Bin\Release_i386\dcrypt.pdb"; DestDir: "{app}"; DestName: "dcrypt.pdb"; Check: "not Is64BitInstallMode"; MinVersion: 0.0,5.0; Flags: ignoreversion;
;Source: "..\DCrypt\Bin\Build_i386\shim_ia32.zip"; DestDir: "{app}"; DestName: "shim_ia32.zip"; Check: "not Is64BitInstallMode"; MinVersion: 0.0,5.0; Flags: ignoreversion; 

Source: "..\DCrypt\Bin\Release_amd64\dccon.exe"; DestDir: "{app}"; DestName: "dccon.exe"; Check: "Is64BitInstallMode"; MinVersion: 0.0,5.0; Flags: ignoreversion;
Source: "..\DCrypt\Bin\Release_amd64\dcinst.exe"; DestDir: "{app}"; DestName: "dcinst.exe"; Check: "Is64BitInstallMode"; MinVersion: 0.0,5.0; Flags: ignoreversion; 
Source: "..\DCrypt\Bin\Release_amd64\dcrypt.exe"; DestDir: "{app}"; DestName: "dcrypt.exe"; Check: "Is64BitInstallMode"; MinVersion: 0.0,5.0; Flags: ignoreversion;
Source: "..\DCrypt\Bin\Build_amd64\dcrypt.sys"; DestDir: "{app}"; DestName: "dcrypt.sys"; Check: "Is64BitInstallMode"; MinVersion: 0.0,5.0; Flags: ignoreversion;
Source: "..\DCrypt\Bin\Release_amd64\dcapi.dll"; DestDir: "{app}"; DestName: "dcapi.dll"; Check: "Is64BitInstallMode"; MinVersion: 0.0,5.0; Flags: ignoreversion; 
;Source: "..\DCrypt\Bin\Release_amd64\dcrypt.pdb"; DestDir: "{app}"; DestName: "dcrypt.pdb"; Check: "Is64BitInstallMode"; MinVersion: 0.0,5.0; Flags: ignoreversion; 
;Source: "..\DCrypt\Bin\Build_amd64\shim_x64.zip"; DestDir: "{app}"; DestName: "shim_x64.zip"; Check: "Is64BitInstallMode"; MinVersion: 0.0,5.0; Flags: ignoreversion; 

Source: "..\DCrypt\license.txt"; DestDir: "{app}"; MinVersion: 0.0,5.0; Flags: ignoreversion; 
Source: "..\DCrypt\changes.txt"; DestDir: "{app}"; MinVersion: 0.0,5.0; Flags: ignoreversion; 
Source: "..\DCrypt\PostOOBE.cmd"; DestDir: "{app}"; MinVersion: 0.0,5.0; Flags: ignoreversion; 
Source: "..\DCrypt\dcrypt.inf"; DestDir: "{app}"; MinVersion: 0.0,5.0; Flags: ignoreversion; 

[Icons]
Name: "{group}\DiskCryptor"; Filename: "{app}\dcrypt.exe"; MinVersion: 0.0,5.0; 
Name: "{group}\License"; Filename: "{app}\license.txt"; MinVersion: 0.0,5.0; 
Name: "{group}\Uninstall DiskCryptor"; Filename: "{uninstallexe}"; MinVersion: 0.0,5.0; 
Name: "{userdesktop}\DiskCryptor"; Filename: "{app}\dcrypt.exe"; Tasks: desktopicon; MinVersion: 0.0,5.0; 

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop icon"; MinVersion: 0.0,5.0; 
Name: "modifypath"; Description: "&Add application directory to system path"; Flags: unchecked; MinVersion: 0.0,5.0; 

[CustomMessages]

[Languages]


[Code]
#include "environment.iss"

function InitializeSetup(): Boolean;
var
  Version: TWindowsVersion;
  DeleteFlag: Cardinal;
  ExecRet: Integer;
  DrvVersion: Cardinal;
begin

  SuppressibleMsgBox('This is a BETA release, use it at your own risk!'#13#10'This tool is provided on an "as is" basis, with no warranty of any kind, express or implied.', mbError, MB_OK);

  GetWindowsVersionEx(Version);

  // is not NT or is old nt or is windows 2000 (5.0)
  if (Version.NTPlatform = False) or (Version.Major < 5) or ((Version.Major = 5) and (Version.Minor = 0)) then
  begin
    SuppressibleMsgBox('DiskCryptor requires Windows XP SP2 or later.', mbError, MB_OK, MB_OK);
    Result := False;
    exit;
  end;

  // its windows xp (5.1) but service pack is too old
  if (Version.Major = 5) and (Version.Minor = 1) and (Version.Build < 2) then
  begin
    SuppressibleMsgBox('When running on Windows XP, Service Pack 2 is required.', mbError, MB_OK, MB_OK);
    Result := False;
    exit;
  end;

  // its windows server (5.2) but service pack is too old
  if (Version.Major = 5) and (Version.Minor = 2) and (Version.Build < 1) then
  begin
    SuppressibleMsgBox('When running on Windows 2003, Service Pack 1 is required.', mbError, MB_OK, MB_OK);
    Result := False;
    exit;
  end;

  // if we are uninstalling the driver right now, query for a reboot
  if RegQueryDWordValue(HKEY_LOCAL_MACHINE, 'SYSTEM\CurrentControlSet\Services\dcrypt', 'DeleteFlag', DeleteFlag) then
  begin
    if (DeleteFlag <> 0) then
    begin
      if MsgBox('You must restart your computer before installing DiskCryptor.'#13#10'Do you want to restart your computer now?', mbConfirmation, MB_YESNO) = IDYES then
      begin
        Exec(ExpandConstant('{sys}\shutdown.exe'), '/r /t 0', '', SW_SHOW, ewWaitUntilTerminated, ExecRet);
      end;
      Result := False;
      exit;
    end;
  end;

  // check is a version is already installed
  if RegQueryDWordValue(HKEY_LOCAL_MACHINE, 'SYSTEM\CurrentControlSet\Services\dcrypt\config', 'sysBuild', DrvVersion) then
  begin
    if (DrvVersion > 848) then
    begin
      MsgBox('A newer version of DiskCryptor is installed.'#13#10'Downgrade is not supported, please use latest version of DiskCryptor.', mbError, MB_OK);
      Result := False;
      exit;
    end
    //else
    //begin
    //  if MsgBox('Current version of DiskCryptor is already installed.'#13#10'You want to repair installation?', mbConfirmation, MB_YESNO) <> IDYES then
    //  begin
    //    Result := False;
    //    exit;
    //  end;
    //end;
  end;

  Result := True;
end;

function InitializeUninstall(): Boolean;
var
  ExecRet: Integer;
begin

  if (Exec(ExpandConstant('{app}\dcinst.exe'), '-isenc', '', SW_HIDE, ewWaitUntilTerminated, ExecRet) = False) and (ExecRet = 51) then // ST_ENCRYPTED
  begin
    MsgBox('DiskCryptor cannot be uninstalled, because system boot device is encrypted.'#13#10'Please decrypt this device and try again.', mbError, MB_OK);
    Result := False;
    exit;
  end;

  Result := True;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ExecRet: Integer;
begin

  // after the installation
  if (CurStep <> ssPostInstall) then  
    exit;
 
  // add to path
  if IsTaskSelected('modifypath') then
    EnvAddPath(ExpandConstant('{app}'));

  // install the driver
  if (Exec(ExpandConstant('{app}\dcinst.exe'), '-setup', '', SW_HIDE, ewWaitUntilTerminated, ExecRet) = False) or (ExecRet <> 0) then
    MsgBox('Error occurred when installing driver (error code: ' + IntToStr(ExecRet) + ' ).', mbError, MB_OK);
 
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ExecRet: Integer;
begin
  
  // before the uninstallation
  if (CurUninstallStep <> usUninstall) then
    exit;
  
  // remove from path 
  EnvRemovePath(ExpandConstant('{app}'));
  
  // remove from autostart
  RegDeleteValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'DiskCryptor');
  RegDeleteValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce', 'DiskCryptor');

  // uninstall the driver
  if (Exec(ExpandConstant('{app}\dcinst.exe'), '-unins', '', SW_HIDE, ewWaitUntilTerminated, ExecRet) = False) or (ExecRet <> 0) then
    MsgBox('Error occurred when removing driver (error code: ' + IntToStr(ExecRet) + ' ).', mbError, MB_OK);

  // check if bootloader is installed
  if (Exec(ExpandConstant('{app}\dcinst.exe'), '-isboot', '', SW_HIDE, ewWaitUntilTerminated, ExecRet) = True) and (ExecRet = 0) then
  begin
    if MsgBox('Uninstall DiskCryptor bootloader from your HDD?', mbConfirmation, MB_YESNO) = IDYES then
    begin
      // uninstall the bootloader
      if (Exec(ExpandConstant('{app}\dcinst.exe'), '-unldr', '', SW_HIDE, ewWaitUntilTerminated, ExecRet) = False) or (ExecRet <> 0) then
        MsgBox('Error occurred when removing bootloader (error code: ' + IntToStr(ExecRet) + ' ).', mbError, MB_OK);
    end;
  end;

end;

