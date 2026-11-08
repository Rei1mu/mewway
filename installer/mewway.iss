; mewwway 安装包脚本（Inno Setup 6）。
; 由 .github/workflows/release.yml 调用 iscc，用 /D 传入版本号与架构。
;
; 架构处理沿用 teambition-agent-orchestrator 的成熟做法：
;   不依赖 OutputArchitectures（需 6.4+，CI 版本行为不稳），改用
;   ArchitecturesAllowed + ArchitecturesInstallIn64BitMode 配合矩阵里的 InnoArch，
;   每个架构单独编出一个安装器（x64 / arm64 各一个）。
;
; 中文语言文件 ChineseSimplified.isl 随仓库走（installer/ 下），不依赖 CI 环境。

#ifndef AppVersion
  #define AppVersion "0.1.0"
#endif
#ifndef TargetArch
  #define TargetArch "x64"
#endif
#ifndef InnoArch
  #define InnoArch "x64compatible"
#endif
#ifndef SrcExe
  #define SrcExe "..\target\release\mewway.exe"
#endif
#ifndef OutDir
  #define OutDir "..\dist"
#endif

[Setup]
; AppId 固定不变，升级时才能覆盖安装而不是装成两份。
AppId=c0cabde7-0c88-429a-8d9d-bd2f6060bfd0
AppName=mewway
AppVerName=mewway {#AppVersion}
AppVersion={#AppVersion}
AppPublisher=mewway
AppPublisherURL=https://github.com/Rei1mu/mewway
; 系统级代理工具通常需要管理员权限（设置系统代理 / 绑定特权端口）。
DefaultDirName={autopf}\mewway
DefaultGroupName=mewway
PrivilegesRequired=admin
OutputDir={#OutDir}
OutputBaseFilename=mewway-{#AppVersion}-{#TargetArch}-setup
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed={#InnoArch}
ArchitecturesInstallIn64BitMode={#InnoArch}
UninstallDisplayIcon={app}\mewway.exe
MinVersion=10.0

[Languages]
; 中文放第一个 = 安装界面默认中文；英文留给非中文用户。
Name: "zh"; MessagesFile: "ChineseSimplified.isl"
Name: "en"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "{#SrcExe}"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\mewway"; Filename: "{app}\mewway.exe"
Name: "{autodesktop}\mewway"; Filename: "{app}\mewway.exe"; Tasks: desktopicon

[Tasks]
Name: desktopicon; Description: "创建桌面快捷方式"; GroupDescription: "附加选项:"

[Run]
Filename: "{app}\mewway.exe"; Description: "启动 mewwway"; Flags: nowait postinstall skipifsilent
