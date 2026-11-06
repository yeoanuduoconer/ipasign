# ipasign

**iOS IPA 重签名工具** —— 纯 Python 签名引擎 + 交互式终端界面。

不用 Xcode，不用 macOS，不用第三方签名服务：证书、描述文件、Mach-O 签名、IPA 打包、设备安装全部在本地完成。

```
┌───────────────────────────────── ipasign  iOS 签名工具 ─────────────────────────────────┐
│ 版本      1.0.0                                                                          │
│ 证书库    0 套 (空)                                                                      │
│ 登录      未登录                                                                         │
│ 设备      iPad (6) (26.5)                                                                │
│ 配置目录  C:\Users\you\.ipasign                                                          │
└──────────────────────────────────────────────────────────────────────────────────────────┘
  1  Apple ID 登录（申请开发者会话）        6  证书库管理
  2  申请证书 + 描述文件（证书工厂）        7  设备与驱动信息
  3  签名 IPA                               8  自动续签（到期自动重签重装）
  4  安装到设备                             9  关于 / 路径
  5  签名体检（doctor）                     0  退出
```

菜单项是**自包含**的：没登录就直接点「2」，它会先引导你登录再继续；证书库为空时点「3」，它会先帮你申请一套证书。

## 功能一览

| 能力 | 说明 |
| --- | --- |
| 重签名 | 解析 / 重建 Mach-O 代码签名：CodeDirectory、requirements、CMS、DER entitlements |
| 资源封印 | 生成 `_CodeSignature/CodeResources`，嵌套 bundle 一并纳入 |
| IPA 打包 | 解包 → 逐层签名（appex / framework / dylib）→ 重打包 |
| 证书工厂 | 自己的 Apple ID 登录，自动申请开发证书 + App ID + 描述文件 |
| 设备证明 | 自动 provision ADI v3（Apple 设备身份），不依赖任何第三方 anisette 服务 |
| 装机 | 通过 `pymobiledevice3` 安装到 USB 或 Wi-Fi 连接的设备 |
| 自动续签 | 到期前自动重新申请描述文件 → 重签 → 重装，可守护循环 |
| 体检 | 证书链、有效期、Bundle ID 覆盖、设备 UDID、团队一致性逐项检查 |
| 证书库 | 多套身份集中管理，`renew` 一键重签 |
| 双引擎 | 默认自研 `native` 引擎，需要时可切到外部 `zsign` |

## 安装

### 安装（需要 Python 3.10+）

```bash
pip install .          # 或安装发布包：pip install ipasign
```

装完直接就是命令，任意目录可用（pip 会把启动器放进 Python 的 Scripts 目录，
该目录在 PATH 里）：

```powershell
ipasign
```

**原生登录库已经打包在 wheel 里**（`ipasign/native/win-x64/`），所以登录、
申请证书开箱即用，不需要编译任何东西。

装机功能额外装一个依赖：

```bash
pip install ".[device]"      # 或发布后：pip install "ipasign[device]"
```

开发时用可编辑安装，改代码立即生效：

```bash
pip install -e ".[all]"
```

**唯一的系统级前提**：如果要「插线装到 iPhone/iPad」，Windows 需要 Apple 的
USB 驱动（iTunes 或「Apple Devices」应用，装一次即可）。这是设备驱动，
任何装机工具都绕不开；**签名、登录、申请证书、自动续签完全不需要它**。
macOS 自带该驱动。

卸载：`pip uninstall ipasign`。

### 从源码安装

```bash
# 基础功能（签名 / 校验 / 证书库 / TUI）
pip install -e .

# 需要装机功能时
pip install -e ".[device]"

# 开发者：测试
pip install -e ".[all]"
```

要求 Python 3.10+，无系统级依赖。Windows / macOS / Linux 均可运行。

### 让「登录 / 证书工厂」生效

自动申请证书需要本地编译的 `apple_auth_client`（MIT 协议，基于 [apple-auth](https://github.com/apple-auth/apple-auth) 的 GrandSlam 实现）：

```bash
git clone https://github.com/apple-auth/apple-auth
cmake -S apple-auth -B apple-auth-client -G "Visual Studio 17 2022" -A x64 \
      -DAPPLE_AUTH_WITH_CLIENT=ON -DAPPLE_AUTH_WITH_CURL=ON \
      -DAPPLE_AUTH_BUILD_EXAMPLES=OFF -DBUILD_SHARED_LIBS=ON
cmake --build apple-auth-client --config Release
```

**Windows x64 已经内置**（`ipasign/native/win-x64/`），无需编译即可使用登录与证书申请。
其他平台（macOS / Linux / Windows ARM64）需要自行编译一次。编译后让 `ipasign` 找到它，
按以下顺序查找：

1. **环境变量**（最直接）

   ```powershell
   $env:APPLE_AUTH_LIBRARY = "D:\builds\apple-auth-client\Release\apple_auth_client.dll"
   ```

2. **用户数据目录**（推荐，之后无需再配）

   ```
   ~/.ipasign/native/apple_auth_client.dll     ← 客户端（登录、申请证书）
   ~/.ipasign/native/apple_auth.dll            ← 核心（ADI / OTP）
   ```

   Windows 上是 `C:\Users\<你>\.ipasign\native\`。把 DLL 和它依赖的
   `libcurl.dll`、`plist-2.0.dll`、`z.dll` 一起放进去。

3. **开发布局**：库放在仓库同级目录（`apple-auth-client/Release/`）也会被自动找到。

所有路径都由 `ipasign/paths.py` 统一解析，代码里没有写死任何绝对路径。
额外的环境变量：`IPASIGN_HOME`（改数据目录）、`IPASIGN_NATIVE_DIR`（额外搜索目录）、
`IPASIGN_APPLE_AUTH_DLL`（核心库路径）、`IPASIGN_ZSIGN`（zsign 路径）。

> 只做「签名」不需要它；只有「登录 Apple ID / 自动申请证书」需要。

## 快速开始

### 交互式界面（推荐）

```bash
ipasign
```

无参数启动 TUI，按数字选择操作。所有输入都在本机终端完成，密码用 `getpass` 读取，不落盘。

### 命令行

```bash
# 1. 登录一次（密码 + 验证码都在终端输入）
ipasign login --account you@example.com

# 2. 申请证书 + 描述文件（Bundle ID 直接从 IPA 里读，不用自己填）
ipasign issue --ipa 原版.ipa --udid 00008110-0011223344556677

# 3. 签名（用申请产生的证书库条目）
ipasign renew <条目名> 原版.ipa -o 已签名.ipa -p <p12密码>

# 4. 或直接用 p12 + 描述文件签名
ipasign sign 原版.ipa -o 已签名.ipa -c id.p12 -m profile.mobileprovision -p <p12密码>

# 5. 签名并安装到设备
ipasign renew <条目名> 原版.ipa -o 已签名.ipa -p <p12密码> --install
```

## 命令参考

| 命令 | 作用 |
| --- | --- |
| `ipasign` | 交互式终端界面 |
| `ipasign tui` | 同上（显式） |
| `ipasign login --account <Apple ID> [--fresh]` | 登录 Apple ID，换取开发者会话并列出团队 |
| `ipasign issue --ipa <ipa>` | 从 IPA 自动读取 Bundle ID 并申请证书 / App ID / 描述文件 |
| `ipasign issue --bundle-id <id>` | 手动指定 Bundle ID 申请 |
| `ipasign issue ... --reuse <条目>` | 复用已有证书，只申请新描述文件（免费账号必用） |
| `ipasign sign <ipa>` | 用指定 p12 + 描述文件重签名（`--engine zsign` 走后备引擎） |
| `ipasign renew <条目> <ipa>` | 从证书库取身份并重签，可 `--install`（p12 密码自动读取） |
| `ipasign install <ipa> [--udid <udid>] [--wifi]` | 安装到设备 |
| `ipasign verify <ipa>` | 校验签名结构（CodeDirectory / CMS / 资源封印） |
| `ipasign doctor <ipa> --vault <条目>` | 签名体检 |
| `ipasign vault list/import/show/rm` | 证书库管理 |
| `ipasign devices [--wifi]` | 列出已连接设备 |
| `ipasign selfcheck` | 检查运行依赖、路径、原生库、设备 |
| `ipasign watch add/list/rm/run/start` | 自动续签任务管理 |
| `ipasign info <ipa>` | 查看 IPA 基本信息 |
| `ipasign profile <file>` | 查看描述文件 |
| `ipasign identity <p12>` | 查看证书与证书链 |
| `ipasign fetch-certs` | 缓存 Apple WWDR 中间证书 |

## 目录结构

```
ipasign/
├── app.py              # 入口：无参数进 TUI，有参数走 CLI
├── tui.py              # rich 终端界面
├── cli.py              # argparse 命令
├── device.py           # pymobiledevice3 装机（USB / Wi-Fi）
├── watch.py            # 自动续签任务与守护循环
├── core/               # 签名引擎（与 Apple 服务无关，可独立使用）
│   ├── macho.py        #   Mach-O 解析与代码签名重建
│   ├── cms.py          #   CMS/PKCS#7 签名与校验
│   ├── der.py          #   极简 DER 编解码
│   ├── derplist.py     #   DER 形式的 entitlements（slot 7）
│   ├── bundle.py       #   逐层签名编排
│   ├── resources.py    #   _CodeSignature/CodeResources
│   ├── ipa.py          #   IPA 解包 / 打包
│   ├── profile.py      #   描述文件解析与 entitlements 推导
│   ├── pki.py          #   证书链、p12、WWDR
│   ├── vault.py        #   本地证书库
│   ├── verify.py       #   签名自检
│   ├── doctor.py       #   体检
│   └── errors.py       #   异常类型
└── apple/              # 与 Apple 服务交互
    ├── auth.py         #   GrandSlam 登录（调用原生客户端）
    ├── developer.py    #   developerservices2（QH65B2）
    ├── issue.py        #   证书工厂：CSR → 证书 → App ID → 描述文件
    └── anisette/       #   设备证明（ADI）
        ├── adi.py      #     ADI 容器解析
        ├── native.py   #     apple_auth.dll 的 ctypes 绑定
        └── provision.py#     自建 ADI v3（SPIM → CPIM → PTM）
```

更细的协议说明见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)。

## 工作原理

**签名**（`core/macho.py`）：解析 `LC_CODE_SIGNATURE`，按页计算 SHA-256，重建 CodeDirectory v0x20400，写入 requirements、XML entitlements、DER entitlements（iOS 15+）、CMS（含 Apple hash-agility 属性），最后把签名区按 16 字节对齐。签名产物与 `zsign` 逐字段一致，iOS 26 实测可安装运行。

**证书工厂**（`apple/issue.py`）：登录后拿到 Xcode 应用令牌，调用开发者接口：`addDevice` → `submitDevelopmentCSR` → `addAppId` → `downloadTeamProvisioningProfile`。私钥全程本地生成，只有 CSR 和公钥离开本机。

**设备证明**（`apple/anisette/`）：向 Apple 申请 SPIM → 用本机硬件指纹生成 CPIM → 换取 PTM/信任密钥 → 落地 `adi.pb`。之后每次请求用它生成 `X-Apple-I-MD` 一次性口令。

## 引擎选择

默认使用自研的 `native` 引擎（纯 Python，逐字段与 zsign 对齐，已在 iOS 26 真机验证）。需要时也可以调用外部 zsign：

```bash
ipasign sign app.ipa -o out.ipa -c id.p12 -m profile.mobileprovision --engine zsign
ipasign renew <条目> app.ipa -o out.ipa -p <密码> --engine zsign --install
```

zsign 是独立的 GPLv3 程序，**本项目不打包它**：自行下载后设置 `IPASIGN_ZSIGN` 指向可执行文件即可。

## 已验证

下列开源 App 用本工具（
ative 引擎）重签后，在 iOS 26.5 的 iPad 上实测安装成功：

| App | 结构特点 |
| --- | --- |
| [Dolphin iOS](https://github.com/OatmealDome/dolphin-ios) | 多架构（fat）framework + 独立 dylib |
| [SideStore](https://github.com/SideStore/SideStore) | framework + App Extension（widget） |
| [iNDS](https://github.com/iNDS-Team/iNDS) | 主程序为 arm + arm64 多架构 |
| [Termoso](https://github.com/termoso/termoso) | 完全未签名（无 LC_CODE_SIGNATURE） |

## 使用须知

- **免费 Apple ID**：证书同时只能有 **1 张**（`maxActive: 1`），描述文件 **7 天**到期。换 App 时用 `--reuse` 复用证书，只重新拉描述文件。
- **自动复用**：同一个 Bundle ID 重复签时，工具会复用已有的 App ID 和证书（不会重复创建、不消耗配额）；Apple 报「证书名额已满」时会自动回退到证书库里的证书。
- **开发者模式**：iOS 16+ 首次运行开发签名的 App，需要在 `设置 → 隐私与安全性 → 开发者模式` 打开并重启。
- **信任证书**：首次安装后在 `设置 → 通用 → VPN与设备管理` 里信任你的开发者证书。
- **Wi-Fi 安装**：先用数据线连一次，在 iTunes（Windows）/ Finder（macOS）里勾选「通过 Wi-Fi 同步」，之后 ipasign devices --wifi 能看到设备，ipasign install --wifi 就能无线安装。
- **自动续签**：ipasign watch add app.ipa --vault <条目> --udid <UDID>，之后 ipasign watch run（检查一次）或 ipasign watch start（前台守护循环；要常驻请用 Windows 任务计划程序 / systemd timer / cron 定时调 watch run）。任务存在 ~/.ipasign/renewals.json，**默认不保存 p12 密码**（运行时提示；加 --save-password 才会明文保存）。
- **限流**：Apple 对登录和证书申请有频率限制，HTTP 503 时等 30–60 分钟或换网络。
- **只签你有权处理的 App**：本工具不绕过 App Store 的 DRM，也不为盗版内容提供便利。

## 安全与隐私

- Apple ID 密码只在本地 `getpass` 中读取，**不写入磁盘、不记录日志**。
- 落盘的只有：`adi.pb`（设备身份）、`account-session.plist`（登录会话）、证书库里的 p12 与描述文件。
- 所有配置在 `~/.ipasign/`，删除该目录即可完全重置。
- 工具自己签发的证书条目，其 p12 密码是**自动生成的随机值**，保存在 `~/.ipasign/identities/<条目>/meta.json`（本机明文，只有本用户可读）。这样签名时无需再输入。
- 你**导入**的 p12 不会被记录密码，使用时仍需提供。

## 开发

```bash
pip install -e ".[all]"
pytest            # 62 个测试
```

签名引擎与 Apple 服务层解耦：`ipasign.core` 不依赖网络，可单独用于批量签名。

## 许可证

MIT。
