# iOS 代码签名格式与 ipasign 的实现

本文记录 ipasign 生成的签名结构，便于排查问题或二次开发。字段定义来自 Apple 的
`cs_blobs.h`、`codesign` 的实际输出，以及 zsign 的对照验证。

## 1. Mach-O 与 LC_CODE_SIGNATURE

签名数据附在每个 Mach-O 文件的末尾，由 `LC_CODE_SIGNATURE`（`0x1D`）指向：

```c
struct linkedit_data_command {
    uint32_t cmd;        // 0x1D
    uint32_t cmdsize;    // 16
    uint32_t dataoff;    // 签名在文件中的偏移
    uint32_t datasize;   // 签名长度
};
```

关键约束：

- `dataoff` 必须 ≥ `__LINKEDIT.fileoff + __LINKEDIT.filesize` 的起始位置，实际就是
  `__LINKEDIT` 末尾；
- `CodeDirectory.codeLimit` 等于 `dataoff`，即“被签名区域的长度”；
- 修改 `datasize` 或 `__LINKEDIT` 的 `filesize/vmsize` 会改变被哈希的头部字节，
  因此实现采用**两轮收敛**：先用占位长度算一遍得到签名长度，写入真实长度后再算一遍。

Universal（fat）二进制逐个架构切片独立签名，每个切片有自己的 `LC_CODE_SIGNATURE`
和 CodeDirectory，最后按原对齐方式重排 fat 头。

## 2. SuperBlob

整个签名区是一个大端序 SuperBlob：

```
uint32 magic   = 0xFADE0CC0
uint32 length
uint32 count
BlobIndex index[count]   // { uint32 type; uint32 offset; }
blobs...
```

ipasign 写入的槽位：

| type | 名称 | 内容 |
| --- | --- | --- |
| `0x0000` | CodeDirectory | 见下节 |
| `0x0002` | Requirements | 需求集合（见 §5） |
| `0x0005` | Entitlements | `0xFADE7171` + XML plist |
| `0x10000` | CMS | `0xFADE0B01` BlobWrapper + PKCS#7 DER |

> 注意 CMS 外面还有一层 `CSMAGIC_BLOBWRAPPER`（`0xFADE0B01`），这是 Apple 的格式，
> zsign 同样如此；解析时必须先剥掉 8 字节头。

## 3. CodeDirectory

版本 `0x20400`，大端序，头部固定 88 字节：

```c
struct CodeDirectory {
    uint32_t magic;          // 0xFADE0C02
    uint32_t length;
    uint32_t version;        // 0x20400
    uint32_t flags;          // 0 = 正常签名, 0x2 = ad-hoc
    uint32_t hashOffset;     // 第一个 code slot 的偏移
    uint32_t identOffset;
    uint32_t nSpecialSlots;
    uint32_t nCodeSlots;
    uint32_t codeLimit;      // 被签名区域长度（= dataoff）
    uint8_t  hashSize;       // 32
    uint8_t  hashType;       // 2 = SHA256
    uint8_t  platform;       // 0
    uint8_t  pageSize;       // 12 => 4096 字节
    uint32_t spare2;
    uint32_t scatterOffset;
    uint32_t teamOffset;
    uint32_t spare3;
    uint64_t codeLimit64;    // 0（使用 codeLimit）
    uint64_t execSegBase;
    uint64_t execSegLimit;
    uint64_t execSegFlags;
};
```

布局顺序：

```
[header 88B][identifier\0][team\0][special slots（倒序）][code slots]
```

- **code slots**：把 `[0, codeLimit)` 按 4096 字节分页，每页 SHA256；
- **special slots**：存放在 `hashOffset` 之前，**倒序排列**——slot 1 紧贴 code slots，
  slot n 在最远处。ipasign 生成时按 `n..1` 顺序写入，解析时按 `index+1` 还原。

| slot | 含义 | 何时使用 |
| --- | --- | --- |
| -1 | `Info.plist` 的 SHA256 | bundle 主程序 |
| -2 | Requirements blob 的 SHA256 | 总是 |
| -3 | `_CodeSignature/CodeResources` 的 SHA256 | 有资源的 bundle |
| -5 | Entitlements blob 的 SHA256 | App / appex |
| -7 | DER entitlements（未实现） | — |

`execSegBase/Limit` 取 `__TEXT` 的文件偏移与大小；只有 `MH_EXECUTE` 时
`execSegFlags = 1`（`CS_EXECSEG_MAIN_BINARY`）。

## 4. Entitlements

```
uint32 magic   = 0xFADE7171
uint32 length
XML plist bytes
```

内容由描述文件的 `Entitlements` 推导：

- `$(AppIdentifierPrefix)` / `$(TeamIdentifierPrefix)` 展开为 `TEAMID.`；
- `$(CFBundleIdentifier)` 展开为实际 Bundle ID；
- `application-identifier` 强制写成 `TEAMID.<bundle id>`；
- `com.apple.developer.team-identifier` 强制写成 `TEAMID`；
- `keychain-access-groups` 中等于 `TEAMID.*` 的项改成具体 Bundle ID。

## 5. Requirements

```
SuperBlob 0xFADE0C01
└── BlobIndex { type = 3 (designated), offset = 20 }
    └── Requirement 0xFADE0C00 { length, kind = 1, expression... }
```

需求表达式是**前缀记法**的字节码。ipasign 生成：

```
and( ident("com.example.demo"), anchor_apple_generic )
```

即：`identifier "com.example.demo" and anchor apple generic`。
Apple 的 `codesign` 还会附加 `certificate leaf[subject.CN] = "..."` 与
`certificate 1[field.1.2.840.113635.100.6.2.x]` 两个条件，本工具使用其子集，
对安装与启动没有影响。

## 6. CMS / PKCS#7

对 **CodeDirectory 的原始字节**做分离式签名（detached），结构：

```
ContentInfo
└── SignedData (version 1)
    ├── digestAlgorithms        SET { sha256 }
    ├── encapContentInfo        SEQUENCE { id-data }        # 无 eContent
    ├── certificates  [0]       leaf + WWDR 中间证书(+ 根)
    └── signerInfos             SET { SignerInfo }
```

SignerInfo 的签名属性（signedAttrs）：

| OID | 内容 |
| --- | --- |
| `1.2.840.113549.1.9.3` | contentType = data |
| `1.2.840.113549.1.9.5` | signingTime（UTC） |
| `1.2.840.113549.1.9.4` | messageDigest = SHA256(CodeDirectory) |
| `1.2.840.113635.100.9.2` | hash agility v2：`SEQUENCE { sha256 OID, OCTET STRING(cdhash) }` |
| `1.2.840.113635.100.9.1` | cdhashes：XML plist `{cdhashes: [<data>]}` |

签名算法使用 `rsaEncryption (1.2.840.113549.1.1.1)`（与 OpenSSL / codesign 一致），
摘要算法 `sha256 (2.16.840.1.101.3.4.2.1)`。最后把 SET(0x31) 的首字节换成
隐式标签 0xA0 放进 SignerInfo。

**证书链**：iOS 要求 CMS 内含 Apple WWDR 中间证书，否则无法链到 Apple Root 而拒绝安装。
`ipasign.pki.ensure_chain` 依次从 p12、`--chain`、`~/.ipasign/certs`、Windows 证书库、
Apple PKI 下载中查找与 leaf 的 issuer 名称完全一致的那一张。

## 7. CodeResources

`_CodeSignature/CodeResources` 是 plist：

```
{
  files:  { path: {hash: SHA1} },              # 旧格式
  files2: { path: {hash2: SHA256} },           # 新格式
  rules:  {...},                               # 旧规则
  rules2: {...}                                # 新规则（^.*、Info.plist omit 等）
}
```

排除项：主程序、`Info.plist`、`_CodeSignature/*`、`.DS_Store`、`PkgInfo`，
以及嵌套 bundle 内部的文件（它们有自己的 CodeResources）。

符号链接记录为 `{symlink: target}`。空文件也会被记录。

## 8. 重签流程

1. 解包 IPA（记录符号链接与权限位）；
2. 解析 `Info.plist`，确定 Bundle ID 并校验描述文件覆盖范围；
3. 如有必要改写 Bundle ID（含插件前缀）；
4. 深度优先遍历嵌套 bundle，由内向外逐个：
   - 写入 `embedded.mobileprovision`（主 App 与覆盖该 ID 的扩展）；
   - 生成 `_CodeSignature/CodeResources`；
   - 生成 entitlements、requirements、CMS，重写 Mach-O；
5. 签名散落的 dylib（无 Info.plist，只有 CodeDirectory + CMS）；
6. 打包 IPA。

## 9. 与 Apple codesign 的差异

| 项目 | codesign | ipasign |
| --- | --- | --- |
| DER entitlements (slot 7) | 生成 | 不生成 |
| 指定需求 | 含 CN / 证书扩展条件 | 仅 `identifier + anchor apple generic` |
| 签名区预留空间 | 可能预留 | 紧贴（下次重签会重新分配） |
| CodeResources 规则细节 | 固定但复杂 | 标准规则子集，iOS 不校验资源封印内容 |
| 资源封印 | 严格 | 完整 files/files2，但嵌套 bundle 整体跳过 |

iOS 安装与启动只检查：CMS 链、CodeDirectory 的 cdhash、entitlements 是否被描述文件授权、
以及 App ID 是否匹配。以上差异不影响这些检查。
