; ─────────────────────────────────────────────────────────────────────────────
; Davenlab Security Remediation Tool — Script de Inno Setup
; Genera un instalador .exe profesional para Windows
;
; Requisitos:
;   - Inno Setup 6+: https://jrsoftware.org/isinfo.php
;   - Haber compilado el .exe con PyInstaller antes de correr esto
; ─────────────────────────────────────────────────────────────────────────────

#define MyAppName      "Davenlab Security Remediation Tool"
#define MyAppVersion   "1.0"
#define MyAppPublisher "Davenlab"
#define MyAppExeName   "DavenlabSecurityTool.exe"
#define MyAppURL       "https://github.com/TU_USUARIO/Davenlab-Security-Remediation-Tool"

[Setup]
AppId={{A3F7B2C1-D4E5-4F6A-8B9C-0D1E2F3A4B5C}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\DavenlabSecurityTool
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
; Solicitar permisos de Administrador para la instalación
PrivilegesRequired=admin
OutputDir=installer_output
OutputBaseFilename=Davenlab_Security_Tool_v1.0_Setup
SetupIconFile=assets\icon.ico
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
; Mostrar licencia durante la instalación
LicenseFile=LICENSE

[Languages]
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"

[Tasks]
Name: "desktopicon";    Description: "Crear acceso directo en el Escritorio"; GroupDescription: "Íconos adicionales:"
Name: "startmenuicon";  Description: "Crear acceso directo en el Menú Inicio"; GroupDescription: "Íconos adicionales:"; Flags: checkedonce

[Files]
; El ejecutable compilado por PyInstaller
Source: "dist\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion

; La carpeta de logs (vacía, para que el usuario la encuentre al abrir la app)
Source: "logs\.gitkeep";        DestDir: "{app}\logs"; DestName: ".gitkeep"; Flags: ignoreversion

; El ícono para el acceso directo
Source: "assets\icon.ico";      DestDir: "{app}\assets"; Flags: ignoreversion

[Icons]
; Acceso directo en el Menú Inicio
Name: "{group}\{#MyAppName}";   Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\assets\icon.ico"
Name: "{group}\Desinstalar";    Filename: "{uninstallexe}"

; Acceso directo en el Escritorio (si el usuario lo eligió)
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\assets\icon.ico"; Tasks: desktopicon

[Run]
; Ofrecer lanzar la app al finalizar la instalación
Filename: "{app}\{#MyAppExeName}"; Description: "Iniciar {#MyAppName}"; \
  Flags: nowait postinstall skipifsilent runascurrentuser
