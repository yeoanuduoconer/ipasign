# 架构与协议笔记

本文记录 ipasign 各层做什么、以及其中涉及的 Apple 协议细节，方便二次开发。

## 分层

```
┌───────────────────────────────┐
│  app.py  →  tui.py / cli.py   │  交互层：只负责输入输出与编排
├───────────────────────────────┤
│  apple/   auth · developer ·  │  服务层：所有需要联网的 Apple 交互
│           issue · anisette    │
├───────────────────────────────┤
│  core/    macho · cms · bundle│  引擎层：纯计算，不联网，可独立复用
│           ipa · pki · vault   │
├───────────────────────────────┤
│  device.py (pymobiledevice3)  │  设备层：安装 / 查询
└───────────────────────────────┘
```

`core/` 不 import `apple/`，所以批量签名脚本可以只装 `cryptography` 跑起来。

## 一、Mach-O 代码签名

iOS 可执行文件的签名是「附加在文件末尾的一块数据」，由 `LC_CODE_SIGNATURE`
指向：

```
SuperBlob (0xFADE0CC0)
├── 0x0000 CodeDirectory (0xFADE0C02, version 0x20400)
├── 0x0002 Requirements    (0xFADE0C01)
├── 0x0005 Entitlements    (0xFADE7171, XML plist)
├── 0x0007 DER entitlements(0xFADE7172, Apple DER plist)
└── 0x10000 CMS            (BlobWrapper 0xFADE0B01)
```

**CodeDirectory** 是核心：它保存

- `codeLimit`：参与哈希的字节数（= 签名起始偏移）
- 每 4096 字节一个 SHA-256（`nCode` 个）
- 特殊槽位（`nSpecial`）：Info.plist、Requirements、CodeResources、XML/DER entitlements
- `teamID`、`execSegBase/Limit/Flags`

生成顺序（`core/macho.py::sign_macho`）：

1. 解析 load commands，找到 `LC_CODE_SIGNATURE` 与 `__LINKEDIT`
2. 截断旧签名，把签名区放在 16 字节对齐的位置
3. 构造 CodeDirectory → SuperBlob → 计算 CMS
4. 因为 `datasize`/`__LINKEDIT.filesize` 写在被哈希的头部里，需要**迭代收敛**（一般 2 轮）

### 几个容易踩的坑

| 坑 | 现象 | 处理 |
| --- | --- | --- |
| 签名区没按 16 字节对齐 | iOS `0xe8008019` 签名无效 | `_pad_signature()` 补零 |
| 缺 DER entitlements（slot 7） | iOS 26 `0xE8008029` 签名版本不支持 | `core/derplist.py` 生成 |
| 资源封印漏掉嵌套文件 | 安装时校验失败 | `resources.py` 只排除根 `_CodeSignature` |
| `execSegFlags` 被重置 | 某些 App 行为异常 | 保留原签名的 flags |

### DER entitlements 格式

Apple 用一套精简的 DER 编码，逐字节对照 `zsign` 输出确认：

```
70 <len>            根（APPLICATION 16）
  02 01 01          INTEGER 1，版本
  b0 <len>          字典（CONTEXT 16）
    30 <len>        每个键值对是一个 SEQUENCE
      0c <len> key  UTF8String
      <value>       0c 字符串 / 01 布尔 / 02 整数 / 30 数组 / b0 嵌套字典
```

键按字节序升序排列。`core/derplist.py::encode_entitlements` 的输出与 zsign
逐字节一致（有测试固定这个向量）。

## 二、CMS / PKCS#7

`core/cms.py` 手写 DER 生成 CMS：

- `SignedData` + `SignerInfo`（版本 1）
- 摘要算法 SHA-256，签名算法 `rsaEncryption`
- 签名属性：`contentType`、`messageDigest`、`signingTime`，外加 Apple 的两个
  hash-agility 属性：
  - `1.2.840.113635.100.9.1`（cdhash，八位组）
  - `1.2.840.113635.100.9.2`（cdhash 的 plist 包装）
- 证书链按 叶子 → WWDR G3 → Apple Root CA 顺序放入

校验用 `verify_detached_cms`（自实现）或 `openssl cms -verify`。

## 三、证书工厂（开发者接口）

协议 `QH65B2`，端点：

```
POST https://developerservices2.apple.com/services/QH65B2/<action>.action?clientId=XABBG36SBA
Content-Type: text/x-xml-plist
```

请求体是 plist，公共字段：

```
clientId        XABBG36SBA
protocolVersion QH65B2
requestId       大写 UUID
userLocale      en_US
teamId          团队 ID
```

用到的 action：

| action | 作用 | 关键字段 |
| --- | --- | --- |
| `listTeams` | 列团队 | — |
| `ios/listDevices` | 列设备 | — |
| `ios/addDevice` | 注册设备 | `deviceNumber`(UDID)、`deviceName` |
| `ios/listAllDevelopmentCerts` | 列证书 | — |
| `ios/submitDevelopmentCSR` | 申请证书 | `csrContent` = **base64(DER)** |
| `ios/revokeDevelopmentCert` | 吊销 | `certificateId`、`serialNumber` |
| `ios/addAppId` | 注册 App ID | `identifier`、`name` |
| `ios/downloadTeamProvisioningProfile` | 取描述文件 | `appIdId` |

响应可能是 **plist 也可能是 JSON**（错误时），解析器两种都支持。
`resultCode` 非 0 即失败：`3250` CSR 格式错、`7460` 证书数量到上限、
`35` 缺少必填参数。

> 免费账号每个类型 `maxActive: 1`，所以换 App 时复用证书、只重新下载描述文件
> （`ipasign issue --reuse`）。

### 申请证书时私钥的保护

CSR 生成后先把私钥写到 `~/.ipasign/pending-key.pem`，签发成功再删除。
原因是：Apple 一旦签了 CSR 就占用了一个证书名额，如果此时进程崩溃，私钥丢失
会导致这张证书永远不可用（只能吊销重来）。

## 四、GrandSlam 登录

登录走 Apple 的 SRP-6a：

1. `init`：发送 `A2k`（客户端公钥）、`ps`（支持的预处理）、`cpd`（设备数据）
2. 服务端返回 `s`（盐）、`B`（服务端公钥）、`i`（迭代次数）、`c`（挑战）
3. `complete`：发送 `M1`（客户端证明）、`c`
4. 服务端返回会话令牌（`GsIdmsToken`、`sk`、`t` 等）

ipasign 不在 Python 里重写这套流程，而是调用本地编译的 `apple_auth_client`
（MIT），因为其中还包含 2FA、可信设备、应用令牌交换等大量边界处理。

**应用令牌**（`o=apptokens`，`app=com.apple.gs.xcode.auth`）是调用开发者接口的
前提，交换时用 `sk` 对 `"apptokens" + dsid + app` 做 HMAC-SHA256 作为
`checksum`。这一步的挑战值是一次性的：拿到 503 后必须重新登录。

## 五、设备证明（ADI v3）

Apple 要求每个请求带上 `X-Apple-I-MD`（一次性口令），它由 ADI 文件和设备指纹
派生。ADI 文件结构：

```
4B  版本（3）
4B  prefix 长度
NB  prefix
16B IV
NB  AES 密文（16 的倍数）
20B 认证标签
```

密文的密钥来自「硬件指纹 + prefix」经过一套自定义 MD5 扩散（319 字节状态、
128 字节表、1276 步混合），所以 **ADI 与生成它的机器绑定**。这部分用原生库
（`apple_auth.dll`）实现，Python 只是 ctypes 调用。

自建 ADI 的流程（`apple/anisette/provision.py`）：

```
GET  /grandslam/GsService2/lookup                → midStartProvisioning / midFinishProvisioning
POST midStartProvisioning  {Header:{}, Request:{}}            → Response.spim
     cpim = aauth_provisioning_begin(spim, 硬件指纹) → aauth_provisioning_request()
POST midFinishProvisioning {Request:{cpim: b64}}             → Response.ptm / tk / RINFO
     aauth_provisioning_finish(ptm, tk) → 导出 adi.pb
```

请求头必须带：

```
X-Mme-Device-Id   稳定的设备 UUID（服务端把实体绑在它上面）
X-Apple-I-MD-LU   稳定的十六进制串（大写，非 UUID 格式）
X-MMe-Client-Info Windows 平台的是 <PC> <Windows;6.2(0,0);9200> <com.apple.AuthKitWin/1 ...>
Content-Type     application/x-www-form-urlencoded（即使 body 是 plist）
```

平台不匹配会得到 `-29003 environment mismatch`，缺少设备 ID 会得到
`-29000 EntityNotAvailable`。

## 六、安装

`device.py` 调用 `pymobiledevice3 apps install`，安装后用
`pymobiledevice3 apps list` 确认 bundle id 真的出现了（iOS 有时会"报告成功"
但实际丢弃），并重试 5 次以避开列表刷新延迟。

## 测试

```
tests/fixtures.py     合成 Mach-O、自签证书、CMS、描述文件
tests/test_macho.py   签名结构与自校验
tests/test_derplist.py DER entitlements 与 zsign 参考向量逐字节对比
tests/test_bundle.py  端到端签名一个合成 IPA
tests/test_cli.py     命令行
tests/test_adi.py     ADI 容器解析
tests/test_pki.py     证书链
tests/test_profile.py 描述文件
tests/test_vault.py   证书库
```


## 七、自动续签

ipasign/watch.py 是一个很薄的调度层：

`
renewals.json            # 任务：ipa / 证书库条目 / 设备 / 间隔
   ↓ run_once(threshold)
profile 到期时间 ≤ 阈值？
   ↓ 是
issue(reuse=条目)        # 重新拉描述文件（复用同一张证书）
   ↓
sign_ipa(原 IPA → 新 IPA)
   ↓
install_ipa(udid, wifi)
   ↓
记录 last_run / last_result / last_error
`

关键点：

- **只刷描述文件，不重发证书**——证书一年有效，描述文件 7 天到期，重发证书会消耗免费账号唯一的名额。
- 到期时间从证书库的 meta.profile_expires 读取，没有元数据时退回解析描述文件本身。
- 密码默认不落盘；--save-password 才会写进任务文件（明文，仅限本机可信环境）。
- watch start 是前台循环，需要常驻时用系统计划任务（Windows 任务计划程序 / systemd timer / cron）调 watch run。

## 八、Wi-Fi 安装

安装走的是经典 lockdown + installation_proxy，不需要 iOS 17+ 的 RSD 隧道；
usbmuxd 负责按 UDID 把连接路由到 USB 或网络设备。

因此 Wi-Fi 的前提是设备**已经配对过 Wi-Fi 同步**：

1. 数据线连一次，在 iTunes（Windows）/ Finder（macOS）勾选「通过 Wi-Fi 同步」
2. 手机与电脑同一局域网，手机解锁
3. pymobiledevice3 usbmux list --network 能看到设备

list_devices(wifi=...) 用 DeviceInfo.transport（usb / wifi）过滤，
install_ipa(..., wifi=True) 找不到网络设备时会给出上面的指引。

## 九、踩坑记录：0xe8008019 与 cdhash 截断

现象：自研签名在 iOS 26 上被拒（`0xe8008019`），而同一份内容的 zsign 签名可以安装，
且我们的 CMS 用 OpenSSL 校验是通过的。

定位方法：保留 zsign 的 CodeDirectory、只把 CMS 换成我们生成的 —— 仍然失败，
于是范围缩小到 CMS。逐属性对比后发现 Apple 的 hash-agility 属性
（`1.2.840.113635.100.9.1`，内容是 `{cdhashes: [<data>]}` 的 XML plist）里：

- zsign：`SHA-256(CodeDirectory)` 的**前 20 字节**
- 我们：完整的 32 字节

Apple 的 cdhash 本身就是截断到 20 字节的 SHA-256，iOS 用它和实际 CD 比对，
多出来的 12 字节让整个签名被判无效。

修复：生成该 plist 时写入 `cdhash[:20]`；`1.2.840.113635.100.9.2`（DER 形式）
仍保留完整 32 字节 SHA-256，与 codesign/zsign 一致。回归测试见 `tests/test_cms.py`。
