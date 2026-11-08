; mewwway 安装脚本（Inno Setup 6.4+）
;
; 通过 ISCC 命令行参数化，CI 中每个架构单独编译出一个原生安装器：
;   /DArch=x64|arm64       安装器自身架构（对应 OutputArchitectures，决定 setup.exe 是 x64 还是 arm64 原生）
;   /DVersion=<semver>     版本号（取自 git tag，例如 0.1.0）
;   /DExePath=<path>       要打包的可执行文件 mewwway.exe 的绝对/相对路径
;
; 用法示例：
;   iscc installer/mewway.iss /DArch=x64 /DVersion=0.1.0 /DExePath=target/x86_64-pc-windows-msvc/release/mewway.exe /Odist
;
; 注意：OutputArchitectures=arm64 需要 Inno Setup 6.4.0 及以上。

[Setup]
; 固定 GUID 标识本应用，保证升级/卸载正确关联（请勿随意更改）
AppId=c0cabde7-0c88-429a-8d9d-bd2f6060bfd0
AppName=mewway
AppVersion={#Version}
AppPublisher=mewway
AppCopyright=Copyright (C) 2026 mewwway
DefaultDirName={autopf}\mewway
DefaultGroupName=mewway
; 单架构安装器：打包对应架构的 mewwway.exe，并以 64 位模式安装到 Program Files。
; 注：setup.exe 自身位数由 Inno Setup 版本决定；本 CI 用的 6.x(<6.4) 出的是 x64 载体，
; 在 ARM64 机器上以模拟方式运行，但安装进去的 mewwway.exe 是原生 ARM64 二进制。
ArchitecturesInstallIn64BitMode={#Arch}
OutputBaseFilename=mewway-{#Version}-{#Arch}-setup
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
; 系统级代理工具通常需要管理员权限（设置系统代理 / 绑定特权端口）
PrivilegesRequired=admin
UninstallDisplayName=mewway {#Version} ({#Arch})
CreateAppDir=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "chinesesimplified"; MessagesFile: "compiler:Languages\ChineseSimplified.isl"

[Files]
Source: "{#ExePath}"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\mewway"; Filename: "{app}\mewway.exe"
Name: "{autodesktop}\mewway"; Filename: "{app}\mewway.exe"; Tasks: desktopicon

[Tasks]
Name: desktopicon; Description: "创建桌面快捷方式"; GroupDescription: "附加图标:"

[Run]
Filename: "{app}\mewway.exe"; Description: "启动 mewwway"; Flags: nowait postinstall skipifsilent
