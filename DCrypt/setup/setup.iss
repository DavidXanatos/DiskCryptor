#include '..\_include_\version.h'

[Setup]
AppName=DiskCryptor
AppVerName=DiskCryptor {#DC_PRODUCT_VER}
AppPublisher=http://diskcryptor.net/
AppPublisherURL=http://diskcryptor.net/
AppVersion={#DC_PRODUCT_VER}
ArchitecturesAllowed=x86 x64
ArchitecturesInstallIn64BitMode=x64
Compression=lzma/ultra
SolidCompression=yes
MergeDuplicateFiles=yes
AllowCancelDuringInstall=no
AllowNoIcons=yes
AllowUNCPath=no
LicenseFile=..\license.txt
PrivilegesRequired=admin
OutputDir=..\Bin
OutputBaseFilename=dcrypt_setup
VersionInfoVersion={#DC_FILE_VER}
VersionInfoCompany=http://diskcryptor.net/
VersionInfoCopyright=ntldr <ntldr@diskcryptor.net>
DefaultDirName={pf}\dcrypt
UninstallDisplayIcon={app}\dcrypt.exe
DefaultGroupName=DiskCryptor
UsePreviousTasks=yes
ChangesEnvironment=yes
AlwaysRestart=yes
AppMutex=DISKCRYPTOR_MUTEX
SignedUninstaller=yes

[Tasks]
Name: desktopicon; Description: "Create a &desktop icon";
Name: modifypath; Description: "&Add application directory to system path"; Flags: unchecked

[Files]
; x86 files
Source: "..\Bin\Release_i386\*.exe"; DestDir: "{app}"; Check: not Is64BitInstallMode
Source: "..\Bin\Release_i386\*.sys"; DestDir: "{app}"; Check: not Is64BitInstallMode
Source: "..\Bin\Release_i386\*.dll"; DestDir: "{app}"; Check: not Is64BitInstallMode
Source: "..\Bin\Release_i386\*.pdb"; DestDir: "{app}"; Check: not Is64BitInstallMode
; x64 files
Source: "..\Bin\Release_amd64\*.exe"; DestDir: "{app}"; Check: Is64BitInstallMode
Source: "..\Bin\Release_amd64\*.sys"; DestDir: "{app}"; Check: Is64BitInstallMode
Source: "..\Bin\Release_amd64\*.dll"; DestDir: "{app}"; Check: Is64BitInstallMode
Source: "..\Bin\Release_amd64\*.pdb"; DestDir: "{app}"; Check: Is64BitInstallMode
; misc files
Source: "..\license.txt"; DestDir: "{app}"
Source: "..\changes.txt"; DestDir: "{app}"

[Icons]
Name: "{group}\DiskCryptor"; Filename: "{app}\dcrypt.exe"
Name: "{group}\License"; Filename: "{app}\license.txt"
Name: "{group}\Uninstall DiskCryptor"; Filename: "{uninstallexe}"
Name: "{userdesktop}\DiskCryptor"; Filename: "{app}\dcrypt.exe"; Tasks: desktopicon

[Code]

const
 DC_BUILD = {#DC_DRIVER_VER};
 
var
 repair: boolean;

function InitializeSetup(): Boolean;
var
 succs: boolean;
 value: dword;
 resl: integer;
 vers: TWindowsVersion;
begin
 Result := true;
 repair := false;
 
 GetWindowsVersionEx(vers);
 if (not vers.NTPlatform) or (vers.Major < 5) or ((vers.Major = 5) and (vers.Minor = 0)) then begin
  SuppressibleMsgBox('DiskCryptor requires Windows XP SP2 or later.', mbCriticalError, MB_OK, MB_OK);
  Result := false; Exit;
 end;
 
 if (vers.Major = 5) and (vers.Minor = 1) and (vers.ServicePackMajor < 2) then begin
  SuppressibleMsgBox('When running on Windows XP, Service Pack 2 is required.', mbCriticalError, MB_OK, MB_OK);
  Result := false; Exit;
 end;
 if (vers.Major = 5) and (vers.Minor = 2) and (vers.ServicePackMajor < 1) then begin
  SuppressibleMsgBox('When running on Windows 2003, Service Pack 1 is required.', mbCriticalError, MB_OK, MB_OK);
  Result := false; Exit;
 end;
 
 succs := RegQueryDwordValue(HKEY_LOCAL_MACHINE, 'SYSTEM\CurrentControlSet\Services\dcrypt', 'DeleteFlag', value);
 if succs and (value <> 0) then begin
  if MsgBox('You must restart your computer before installing DiskCryptor.'#13#10+
             'Do you want to restart your computer now?', mbConfirmation, MB_YESNO) = IDYES then
   Exec(ExpandConstant('{sys}\shutdown.exe'), '/r /t 0', '', SW_HIDE, ewWaitUntilTerminated, resl);
  Result := false; Exit;
 end;
 succs := RegQueryDwordValue(HKEY_LOCAL_MACHINE, 'SYSTEM\CurrentControlSet\Services\dcrypt\config', 'sysBuild', value);
 if succs and (value > DC_BUILD) then begin
  MsgBox('A newer version of DiskCryptor is installed.'#13#10+
         'Downgrade is not supported, please use latest version of DiskCryptor.', mbError, MB_OK);
  Result := false;
 end;
 if succs and (value = DC_BUILD) then begin
  if MsgBox('Current version of DiskCryptor is already installed.'#13#10+
            'You want to repair installation?', mbConfirmation, MB_YESNO) = IDYES then begin
    repair := true;
    Result := true;
  end else Result := false;
 end;
end;

function InitializeUninstall(): Boolean;
var
 error: integer;
begin
 Result := true;
 if not Exec(ExpandConstant('{app}\dcinst.exe'), '-isenc', '', SW_SHOW, ewWaitUntilTerminated, error) then error := 0;
 if error = 51 { ST_ENCRYPTED } then begin
  MsgBox('DiskCryptor can not be uninstalled, because system boot device is encrypted.'#13#10+
         'Please decrypt this device and try again.', mbError, MB_OK);
  Result := false;
 end;
end;

procedure modpath();
var
 oldpath:	string;
 pathitm: string;
 newpath: string;
 mydir: string;
 i: integer;
begin
 mydir   := ExpandConstant('{app}');
 newpath := '';
 RegQueryStringValue(HKEY_LOCAL_MACHINE, 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment', 'Path', oldpath);
 oldpath := oldpath + ';';
 while (Pos(';', oldpath) > 0) do begin
  pathitm := Copy(oldpath, 0, Pos(';', oldpath)-1);
  oldpath := Copy(oldpath, Pos(';', oldpath)+1, Length(oldpath));
  i := i + 1;
  if pathitm = mydir then continue;
  newpath := newpath + pathitm + ';';
 end;
 if not IsUninstaller then begin
  newpath := newpath + mydir;
 end else begin
  newpath := Copy(newpath, 0, Length(newpath)-1);
 end;
 RegWriteStringValue(HKEY_LOCAL_MACHINE, 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment', 'Path', newpath);
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
 succs: boolean;
 error: integer;
begin
	if CurStep = ssPostInstall then begin
    if IsTaskSelected('modifypath') then modpath();
    succs := Exec(ExpandConstant('{app}\dcinst.exe'), '-setup', '', SW_SHOW, ewWaitUntilTerminated, error);
    if ((not succs) or (error <> 0)) and (not repair) then begin
      MsgBox('Error occurred when installing driver (error code: ' + IntToStr(error) + ' ).', mbError, MB_OK);
    end;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
 succs: boolean;
 error: integer;
begin
 if (CurUninstallStep = usUninstall) then begin
   modpath();
   RegDeleteValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'DiskCryptor');
   RegDeleteValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce', 'DiskCryptor');
   succs := Exec(ExpandConstant('{app}\dcinst.exe'), '-unins', '', SW_SHOW, ewWaitUntilTerminated, error);
   if (not succs) or (error <> 0) then begin
     MsgBox('Error occurred when removing driver (error code: ' + IntToStr(error) + ' ).', mbError, MB_OK);
   end;
   succs := Exec(ExpandConstant('{app}\dcinst.exe'), '-isboot', '', SW_SHOW, ewWaitUntilTerminated, error);
   if succs and (error = 0) then begin
    if MsgBox('Uninstall DiskCryptor bootloader from you HDD?', mbConfirmation, MB_YESNO) = IDYES then begin
      succs := Exec(ExpandConstant('{app}\dcinst.exe'), '-unldr', '', SW_SHOW, ewWaitUntilTerminated, error);
      if (not succs) or (error <> 0) then begin
        MsgBox('Error occurred when removing bootloader (error code: ' + IntToStr(error) + ' ).', mbError, MB_OK);
      end;
    end;
   end;
 end;
end;

