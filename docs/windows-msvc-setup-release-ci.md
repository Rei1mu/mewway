# Windows MSVC 双架构 Setup 发布 CI（通用模板）

> 适用：Rust/cargo 项目（其他 MSVC 构建同理），要发 Windows 版，且需要 **x64 + arm64 两个原生安装器**（`setup.exe`），自动构建并发布到 GitHub Release。
> 本地开发不需要 setup，直接 `cargo run` 即可。
> 这是踩了一圈坑后收敛出来的稳定范式（参考 `teambition-agent-orchestrator` 的成熟做法）。

## 仓库里要放的文件

```
.github/workflows/release.yml      # CI 工作流
installer/<app>.iss                # Inno Setup 脚本（参数化）
installer/ChineseSimplified.isl   # ⚠️ 必须随仓库提交，CI 环境的 InnoSetup 不带中文语言包
```

> 不需要中文安装界面：删掉 `[Languages]` 里的 `zh` 行，并去掉 `ChineseSimplified.isl` 即可。

## 1) `.github/workflows/release.yml`

```yaml
name: release

# 打 v* tag 自动出两个安装包；手动触发只构建、不上传 Release。
on:
  push:
    tags: ["v*"]
  workflow_dispatch:

permissions:
  contents: write

jobs:
  build:
    name: build ${{ matrix.arch }}
    runs-on: windows-latest
    strategy:
      fail-fast: false
      matrix:
        include:
          # x64 用本机工具链；arm64 在 x64 runner 上交叉编译（VS 自带 ARM64 工具）。
          # 不用 windows-11-arm runner：私有仓库拿不到，公开仓库也常排队。
          - target: x86_64-pc-windows-msvc
            arch: x64
            inno: x64compatible
          - target: aarch64-pc-windows-msvc
            arch: arm64
            inno: arm64
    steps:
      - uses: actions/checkout@v4

      - uses: dtolnay/rust-toolchain@stable
        with:
          targets: ${{ matrix.target }}

      - uses: Swatinem/rust-cache@v2
        with:
          key: ${{ matrix.target }}

      - name: 取版本号
        id: ver
        shell: pwsh
        run: |
          if ($env:GITHUB_REF_TYPE -eq 'tag') {
            $v = $env:GITHUB_REF_NAME -replace '^v', ''
          } else {
            $m = Select-String -Path Cargo.toml -Pattern '^version\s*=\s*"([^"]+)"' | Select-Object -First 1
            $v = $m.Matches[0].Groups[1].Value
          }
          "version=$v" >> $env:GITHUB_OUTPUT

      - name: 编译
        run: cargo build --release --locked --target ${{ matrix.target }}

      - name: 装 Inno Setup
        run: choco install innosetup --no-progress -y

      - name: 打 setup.exe
        shell: pwsh
        run: |
          iscc "/DAppVersion=${{ steps.ver.outputs.version }}" `
               "/DTargetArch=${{ matrix.arch }}" `
               "/DInnoArch=${{ matrix.inno }}" `
               "/DSrcExe=..\target\${{ matrix.target }}\release\<app>.exe" `
               "installer\<app>.iss"

      - uses: actions/upload-artifact@v4
        with:
          name: setup-${{ matrix.arch }}
          path: dist/*.exe
          if-no-files-found: error

  release:
    needs: build
    if: startsWith(github.ref, 'refs/tags/v')
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with:
          path: dist
          merge-multiple: true

      - uses: softprops/action-gh-release@v2
        with:
          files: dist/*.exe
          fail_on_unmatched_files: true
          generate_release_notes: true
```

把上面所有的 `<app>` 换成你的二进制名（如 `mewway`）。

## 2) `installer/<app>.iss`

用 `#ifndef` 给默认值，CI 用 `/D` 覆盖，所以这份脚本可直接复用到任意项目，只改默认值即可。

```iss
; <app> 安装包脚本（Inno Setup 6）。
; 由 release.yml 调用 iscc，用 /D 传入版本号与架构。
; 架构处理：不用 OutputArchitectures（需 6.4+，CI 版本不稳），
; 改用 ArchitecturesAllowed + ArchitecturesInstallIn64BitMode 配合矩阵里的 InnoArch。

#ifndef AppName
  #define AppName "MyApp"          ; ← 改成你的应用名
#endif
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
  #define SrcExe "..\target\release\MyApp.exe"   ; ← 改成你的 exe（相对本脚本目录）
#endif
#ifndef OutDir
  #define OutDir "..\dist"
#endif

[Setup]
; AppId 固定不变，升级时才能覆盖安装而不是装成两份。每个 app 必须用不同 GUID！
; 生成： python3 -c "import uuid;print(uuid.uuid4())"  —— 注意 AppId 不要加花括号。
AppId=00000000-0000-0000-0000-000000000000
AppName={#AppName}
AppVerName={#AppName} {#AppVersion}
AppVersion={#AppVersion}
AppPublisher={#AppName}
; 系统级/需要管理员权限的工具有 PrivilegesRequired=admin；
; 普通用户态 CLI 工具可用 PrivilegesRequired=lowest + DefaultDirName={%USERPROFILE}\<app>
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
PrivilegesRequired=admin
OutputDir={#OutDir}
OutputBaseFilename={#AppName}-{#AppVersion}-{#TargetArch}-setup
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed={#InnoArch}
ArchitecturesInstallIn64BitMode={#InnoArch}
UninstallDisplayIcon={app}\{#AppName}.exe
MinVersion=10.0

[Languages]
; 中文放第一个 = 安装界面默认中文；英文留给非中文用户。
; ChineseSimplified.isl 随仓库走，不依赖 CI 环境（见文件开头说明）。
Name: "zh"; MessagesFile: "ChineseSimplified.isl"
Name: "en"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "{#SrcExe}"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppName}.exe"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppName}.exe"; Tasks: desktopicon

[Tasks]
Name: desktopicon; Description: "创建桌面快捷方式"; GroupDescription: "附加选项:"

[Run]
Filename: "{app}\{#AppName}.exe"; Description: "启动 {#AppName}"; Flags: nowait postinstall skipifsilent
```

## 3) 把 `ChineseSimplified.isl` 放进 `installer/`

从任意一个已带该文件的仓库复制（如 `Rei1mu/teambition-agent-orchestrator/installer/ChineseSimplified.isl`），提交到你的 `installer/` 目录。

**不要**写 `MessagesFile: "compiler:Languages\ChineseSimplified.isl"` —— CI 的 InnoSetup 安装里没有这个文件，会报 `Couldn't open include file`。把 `.isl` 随仓库提交、`.iss` 里直接写 `MessagesFile: "ChineseSimplified.isl"`（相对脚本目录）即可。

## ⚠️ 踩坑清单（别再走弯路）

1. **别用 `OutputArchitectures`**：需要 Inno Setup ≥ 6.4，而 `choco install innosetup` 装上后版本行为不一致，会报 `Unrecognized [Setup] section directive "OutputArchitectures"`。改用 `ArchitecturesAllowed={#InnoArch}` + `ArchitecturesInstallIn64BitMode={#InnoArch}`，矩阵里 x64 传 `x64compatible`、arm64 传 `arm64`。两个 setup 各自只装对应架构，完全满足「双架构安装器」。
2. **中文语言包必须随仓库提交**：见上。否则编译阶段直接 `Couldn't open include file`。
3. **exe 路径相对 `.iss` 所在目录解析**：用 `..\target\${{ matrix.target }}\release\<app>.exe`（iscc 从仓库根调用脚本），不要写绝对路径或相对仓库根的路径 —— InnoSetup 会按脚本目录解析 `Source`。
4. **`choco install innosetup` 后 `iscc` 在下一步即可用**：GitHub Actions 会把 choco 装的工具加进 PATH，无需手动加。
5. **`AppId` 每个项目用独立 GUID**：复用同一个 GUID 会让不同 app 互相覆盖卸载项；且 AppId 不要加花括号。
6. **arm64 交叉编译在本机 Windows 跑不起来**（缺 ARM64 MSVC lib），所以 arm64 一定放在 `windows-latest` runner 上交叉编译，不要本机编。

## 发布

```bash
git tag v0.1.0 && git push origin v0.1.0
```

触发后：两个 build job 各出一个 `setup.exe` → `release` job 下载合并 → 发布到 `v0.1.0` Release，资产正好是 `<app>-0.1.0-x64-setup.exe` 和 `<app>-0.1.0-arm64-setup.exe`。

> 想重发某个版本：先删掉 GitHub 上该 Release（连同其资产）和远端 tag，再把 tag 指到对应 commit 重新推送即可重新触发。
