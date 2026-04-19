; =============================================================
; Artemis -- by Arkitexe
; Inno Setup installer script
;
; To compile this script into a Setup.exe:
;   1. Install Inno Setup (free): https://jrsoftware.org/isdl.php
;   2. First build the app exe:  build_exe.bat
;      -> produces dist\Artemis.exe
;   3. Then run:  build_installer.bat
;      -> produces installer\Artemis_Setup_Beta.exe
;
; Your friend then runs Artemis_Setup_Beta.exe -- no Python or
; other dependencies needed. It installs to Program Files,
; creates Start Menu + Desktop shortcuts, and registers an
; uninstall entry under Add/Remove Programs.
; =============================================================

#define AppName        "Artemis"
#define AppVersion     "15.0.0"
#define AppPublisher   "Arkitexe"
#define AppExeName     "Artemis.exe"
#define AppDescription "Halo Infinite match server detector"

[Setup]
AppId={{A5D7E3C9-7F1B-4A82-9C4B-ARTEMIS-V15-GRT}}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL=
AppSupportURL=
AppUpdatesURL=

; Install location: Program Files\Artemis
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}

; Write uninstaller
UninstallDisplayName={#AppName}
UninstallDisplayIcon={app}\{#AppExeName}

; Installer polish
WizardStyle=modern
SetupIconFile=resources\artemis_icon.ico
OutputDir=installer
OutputBaseFilename=Artemis_Setup_Beta
Compression=lzma2/max
SolidCompression=yes

; Require admin so we can install to Program Files AND so the WinDivert
; driver can register on first launch of Artemis.exe. Inno will prompt UAC.
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible

; Nice installer wizard images (optional -- comment out if not present)
WizardImageFile=resources\installer_banner.bmp
WizardSmallImageFile=resources\installer_small.bmp

; License box shown during install -- the text in LICENSE.txt
LicenseFile=LICENSE.txt

; Don't show the "ready to install" page (one less click for the friend)
DisableReadyPage=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: checkedonce

[Files]
; The main exe (PyInstaller output)
Source: "dist\Artemis.exe"; DestDir: "{app}"; Flags: ignoreversion

; Bundled icon so the uninstaller + shortcuts can reference it outside the exe
Source: "resources\artemis_icon.ico"; DestDir: "{app}"; Flags: ignoreversion

; README for the user to find after install
Source: "README.txt"; DestDir: "{app}"; Flags: ignoreversion isreadme

[Icons]
; Start Menu shortcut (always created)
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExeName}"; \
    IconFilename: "{app}\artemis_icon.ico"; \
    Comment: "{#AppDescription}"

; Uninstall shortcut in Start Menu
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"

; Desktop shortcut (optional per checkbox)
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; \
    IconFilename: "{app}\artemis_icon.ico"; \
    Tasks: desktopicon; \
    Comment: "{#AppDescription}"

[Run]
; Offer to launch Artemis at end of install. runascurrentuser is important:
; without it, the launch would inherit the installer's elevated token and
; every subsequent exit/relaunch would re-prompt UAC.
Filename: "{app}\{#AppExeName}"; \
    Description: "Launch {#AppName} now"; \
    Flags: postinstall nowait skipifsilent runascurrentuser

[UninstallDelete]
; Clean up anything the app created in its install dir (e.g. crash dumps)
Type: filesandordirs; Name: "{app}\logs"

; NOTE: we deliberately do NOT delete the Desktop\Artemis Logs folder on
; uninstall. Those are the user's match history and are valuable. If the
; user wants them gone they can delete manually.

[Code]
// On uninstall, remind user their logs are preserved on the Desktop.
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
  begin
    MsgBox('Artemis has been uninstalled.' + #13#10#13#10 +
           'Your match history in "Artemis Logs" on your Desktop ' +
           'was preserved. You can delete that folder manually if ' +
           'you no longer need it.',
           mbInformation, MB_OK);
  end;
end;
