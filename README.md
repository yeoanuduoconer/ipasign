# ipasign

跨平台的 iOS IPA 重签名工具：**纯 Python 实现** Mach-O 代码签名、CMS(PKCS#7) 签名与
资源封印，Windows / macOS / Linux 都能直接运行，附带命令行和图形界面。

> 仅用于你拥有或已获授权修改的应用（自有 App 重签、企业内部分发、调试装机）。
> 本工具不破解 DRM，也不能让 App Store 上加密的应用“重签一下就能跑”。

## 它做什么

一次 `ipasign sign` 会完成这些事：

| 步骤 | 说明 |
| --- | --- |
| 解析 IPA | 读取 `Payload/*.app`，保留符号链接与可执行权限 |
| 解析描述文件 | 团队 ID、App ID（含通配）、权限、设备列表、有效期、允许的证书 |
| 校验匹配 | 证书 ↔ 描述文件 ↔ Bundle ID 三方校验，不匹配时给出明确原因 |
| 改写 Bundle ID | 描述文件是显式 App ID 时自动对齐（可用 `--bundle-id` 指定） |
| 签名嵌套组件 | `Frameworks/*.framework`、`PlugIns/*.appex`、Watch App、散落 dylib，由内向外逐层重签 |
| 生成 CodeDirectory | 分页 SHA256、special slots（Info.plist / Requirements / CodeResources / Entitlements） |
| 生成 CMS 签名 | SHA256 + RSA，含 Apple hash-agility 属性，自动补全 WWDR 中间证书 |
| 生成资源封印 | `_CodeSignature/CodeResources`（files / files2 / rules） |
| 重新打包 | 输出可直接安装的 IPA |

同时提供 `info`、`verify`、`profile`、`identity` 等诊断命令。

## 环境要求

- Python 3.9+（开发环境为 3.11）
- 依赖：`cryptography`（唯一第三方依赖，用于 PKCS#12、X.509、RSA）
- 系统：Windows 10/11、macOS、Linux（GUI 需要 Tk，Python 官方安装包自带）

## 安装

```powershell
git clone <repo> ipasign
cd ipasign
python -m pip install -e ".[device]"   # device 可选：装到手机用
# 可选：预先下载 Apple WWDR 中间证书到 ~/.ipasign/certs
ipasign fetch-certs
```

安装后可直接使用 `ipasign` 命令，或 `python -m ipasign`。

## 准备材料

1. **IPA**：必须是**已解密**的包。App Store / iTunes 下载的包带有 FairPlay 加密，
   工具会检测 `LC_ENCRYPTION_INFO` 并直接报错（见“常见问题”）。
2. **证书 `.p12`**：包含私钥和开发者证书，导出时设置密码。
   - Apple Developer 后台 → Certificates → 选择证书 → Download（`.cer`）→ 双击导入钥匙串 →
     在“钥匙串访问”中导出为 `.p12`。
   - 从 Xcode 的 `Manage Certificates` 也可以直接导出。
3. **描述文件 `.mobileprovision`**：Apple Developer 后台 → Profiles，
   确认它包含上面那张证书、包含目标设备（或使用 Ad Hoc / App Store 类型）。

## 命令行

### 查看 IPA

```powershell
ipasign info app.ipa
```

```
应用        : Demo.app
Bundle ID   : com.example.demo
名称/版本   : Demo / 1.0 (1)
最低系统    : 14.0
主程序      : Demo [arm64]
签名        : 未签名
嵌套组件    :
  - Frameworks/DemoKit.framework (framework)
  - PlugIns/Widget.appex (appex)
```

### 重签名

```powershell
ipasign sign app.ipa `
  -c cert.p12 -p 证书密码 `
  -m profile.mobileprovision `
  -o app-signed.ipa
```

输出摘要：

```
描述文件: Test Profile (TEAM123456.*)
签名证书: Apple Development: Tester (ABCD1234) (team TEAM123456)
signed framework: com.example.demo.kit
signed appex: com.example.demo.widget
signed app: com.example.demo
[完成] 已输出: app-signed.ipa
  Bundle ID : com.example.demo
  Team ID   : TEAM123456
  已签名    : 3 个 Mach-O 文件
```

常用参数：

| 参数 | 说明 |
| --- | --- |
| `-o, --output` | 输出路径，默认 `<输入>-signed.ipa` |
| `-c / -p` | p12 路径 / 密码；不给密码则交互输入 |
| `-m, --profile` | 描述文件 |
| `-b, --bundle-id` | 指定新的 Bundle ID |
| `-e, --entitlements` | 用自定义 entitlements plist 覆盖描述文件推导结果 |
| `--chain FILE` | 手动指定中间证书（可重复） |
| `--no-download` | 禁止自动下载 Apple 中间证书 |
| `--adhoc` | 只做 ad-hoc 签名（越狱设备 / 自签测试） |
| `--engine zsign` | 改用 zsign 引擎（需 `--zsign` 指定可执行文件或放入 `~/.ipasign/bin`） |
| `--json` | 机器可读输出 |

### 校验签名

```powershell
ipasign verify app-signed.ipa
ipasign verify app-signed.ipa -c cert.p12 -p 密码 -m profile.mobileprovision
```

逐个 Mach-O 校验：CodeDirectory 页哈希、CMS 签名、主程序标识与 Bundle ID 一致性、
entitlements 与描述文件的授权范围、描述文件有效期与证书列表。

### 安装到手机

```powershell
ipasign devices                                  # 列出已连接的 iPhone / iPad
ipasign install app-signed.ipa                   # 装到唯一连接的那台设备
ipasign install app-signed.ipa --udid <UDID> --verify
```

依赖 `pymobiledevice3`（`pip install -e ".[device]"`）与 Apple 的设备驱动
（iTunes 或 Apple Devices，负责 Apple Mobile Device Service）。手机要解锁并点「信任」。
`--verify` 会在安装前先做一遍签名结构校验，避免装上去才发现证书不匹配。

### 证书库与续签

把一套 p12 + 描述文件存进本地证书库（`~/.ipasign/identities`），之后就不用每次写一长串参数：

```powershell
ipasign vault import corp cert.p12 -m profile.mobileprovision -p 密码
ipasign vault list
ipasign vault show corp -p 密码          # 包含证书链/有效期/匹配性自检
ipasign renew corp app.ipa -o app-renewed.ipa -p 密码 --install
ipasign doctor app.ipa --vault corp -p 密码 --device
```

- `vault` 只复制证书和描述文件，**密码不会落盘**，每次用时再输入；
- `renew` 会检查描述文件是否过期，然后重签并可选择直接装机——适合 7 天/1 年到期前跑一次；
- `doctor` 是签名前的体检：证书是否过期、链是否完整、描述文件是否覆盖这个 Bundle ID、
  证书是否在描述文件名单里、团队是否一致、手机 UDID 是否在设备列表里。

### 其他诊断命令

```powershell
ipasign profile profile.mobileprovision    # 描述文件详情（团队/AppID/设备/证书/权限）
ipasign identity cert.p12 -p 密码          # 证书详情与证书链（缺中间证书会提示）
ipasign fetch-certs                        # 下载 Apple WWDR 中间证书到本地缓存
```

## 图形界面

```powershell
ipasign gui
```

或双击仓库根目录的 `run-gui.cmd`。界面里依次选择 IPA、p12、描述文件，填密码，
点“开始签名”即可；右侧日志实时显示每个组件的签名过程，另有“校验现有 IPA”按钮。

## 工作原理

iOS 的代码签名数据附在每个 Mach-O 文件末尾，由 `LC_CODE_SIGNATURE` 指向，结构是一个
SuperBlob：

```
SuperBlob
├── CodeDirectory      # 分页 SHA256 + 特殊槽（Info.plist / 资源 / 权限 ...）
├── Requirements       # 指定需求（identifier "..." and anchor apple generic）
├── Entitlements       # XML plist，iOS 用它决定 App 能做什么
└── CMS (PKCS#7)       # 对 CodeDirectory 的签名，证书链到 Apple Root
```

签名时按 **由内向外** 的顺序处理：先签 framework / appex / dylib，再签宿主 App；
每个 bundle 的 `_CodeSignature/CodeResources` 对该 bundle 内除主程序、`Info.plist`
之外的所有文件做 SHA1/SHA256 封印。

更多格式细节、与 Apple `codesign` 的差异见 [docs/format.md](docs/format.md)。

### 兼容性说明

- 实现方式与开源工具 [zsign](https://github.com/zhlynn/zsign) 逐字段对照验证：
  CodeDirectory 布局、superblob 偏移、requirements、CMS 签名属性（含
  `1.2.840.113635.100.9.1/9.2` 两个 hash-agility 属性）均一致。
- 生成的 CMS 用 OpenSSL `cms -verify` 可独立验证通过。
- 未生成 **DER entitlements**（`CSSLOT_DER_ENTITLEMENTS`，slot 7）：iOS 15+ 仍接受
  仅 XML entitlements 的签名，主流重签工具也如此。
- Requirements 使用 `identifier "..." and anchor apple generic` 的简化形式；
  这不影响 iOS 安装与启动，但与 `codesign -d` 打印出的完整 DR 略有差异。

## 常见问题

**安装报 0xE8008015 / 0xE8008016 / 0xE8008017**
证书与描述文件不匹配（`0xE8008016`），或描述文件没有包含该设备 UDID（`0xE8008015`），
或 entitlements 超出描述文件授权范围。先用 `ipasign verify` 看具体是哪一项。

**提示“签名证书不在描述文件证书列表中”**
描述文件生成时没有勾选这张证书，去 Apple Developer 后台编辑 Profile 并重新下载。
工具仍会完成签名，但 iOS 会拒绝安装。

**提示“证书链中没有中间证书”**
iOS 要求 CMS 里带 Apple WWDR 中间证书。运行 `ipasign fetch-certs` 自动下载，或用
`--chain AppleWWDRCAG4.cer` 手动指定；Windows 证书库里已安装的中间证书也会被自动使用。

**提示“主程序仍处于加密状态”**
这是 App Store 下载的原包（FairPlay 加密），必须先用其他方式拿到解密后的 IPA。
本工具不提供、也不协助 DRM 解密。

**免费 Apple ID 的证书只能用 7 天**
需要每 7 天重签一次；这是 Apple 的限制，任何重签工具都一样。也可用 Sideloadly 等工具
配合本工具链使用。

**描述文件是显式 App ID，和 App 的 Bundle ID 不一致**
工具会自动把 Bundle ID 改成描述文件授权的那一个（并同步改写插件 Bundle ID），
也可以用 `-b` 显式指定。

**带扩展（appex）的 App 签名后打不开扩展**
如果描述文件是显式 App ID（不是 `*` 通配），扩展需要它自己的描述文件。此时工具会给出警告
并移除旧的嵌入描述文件；最稳妥的做法是使用通配 App ID 的描述文件。

**在越狱设备上测试**
用 `--adhoc` 可生成不带 CMS 的 ad-hoc 签名，配合 `ldid`/越狱环境使用。

## 限制与路线图

- [x] 完整 Mach-O 重签（thin / fat、arm64 / arm64e / x86_64）
- [x] 嵌套 bundle、资源封印、entitlements、requirements、CMS
- [x] CLI + GUI、校验与诊断
- [x] 设备通道：列出设备、把 IPA 直接装进手机（`devices` / `install`）
- [x] 证书库、签名前体检、一键续签（`vault` / `doctor` / `renew`）
- [ ] Apple ID 自动登录并申请免费 7 天证书（协议已打通到 GSA `init`，Apple 对所有请求统一返回 `-80045`，疑似对新客户端/环境的硬性限制）
- [ ] dylib 注入、图标替换（可先用 `--engine zsign`）
- [ ] DER entitlements（slot 7）
- [ ] 多描述文件（为扩展单独指定 profile）

## 开发与测试

```powershell
python -m pip install -e ".[dev]"
python -m pytest -q
```

测试全部使用**合成样本**：程序化生成 Mach-O、自签名证书、CMS 包装的描述文件与 IPA，
无需真实 Apple 账号即可跑通“解包 → 重签 → 打包 → 校验”。

代码结构：

```
ipasign/
├── der.py          # 极简 DER 编解码
├── cms.py          # CMS SignedData 构建与校验
├── macho.py        # Mach-O 解析、CodeDirectory、SuperBlob、重签
├── resources.py    # _CodeSignature/CodeResources
├── profile.py      # .mobileprovision 解析与 entitlements 推导
├── pki.py          # p12、证书链、WWDR 自动补全
├── bundle.py       # bundle 级签名编排
├── ipa.py          # IPA 解包/打包（符号链接、权限）
├── verify.py       # 签名校验
├── cli.py          # 命令行
├── gui.py          # Tkinter 界面
└── zsign_engine.py # zsign 备用引擎
```

## 免责声明

本项目仅供学习、研究与合法用途。使用者必须确保对所处理的应用拥有合法授权，
并自行承担因使用本工具产生的全部责任。请勿用于分发盗版应用或规避 Apple 的
安全机制。
