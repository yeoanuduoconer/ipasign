# 变更记录

格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循语义化版本。

## [1.0.0] - 2026-11-07

首个可用版本。

### 功能

- **签名引擎**：纯 Python 重建 Mach-O 代码签名（CodeDirectory、requirements、
  CMS/PKCS#7、DER entitlements），不依赖 zsign 等外部工具
- **资源封印**：生成 `_CodeSignature/CodeResources`，嵌套 bundle（appex、
  framework、dylib）逐层签名
- **证书工厂**：用自己的 Apple ID 登录，自动申请开发证书、App ID、描述文件
  （自动注册设备、复用证书与 App ID）
- **设备证明**：内置 ADI v3 支持，不依赖第三方 anisette 服务
- **装机**：通过 pymobiledevice3 安装到 USB / Wi-Fi 连接的设备
- **自动续签**：到期前自动重新申请描述文件 → 重签 → 重装，可守护循环
- **交互界面**：rich TUI，菜单项自包含（缺登录/缺证书会就地引导）
- **双引擎**：默认 native，可用 `--engine zsign` 切到外部 zsign

### 修复（开发过程中的关键问题）

- `0xe8008019`：CMS 的 9.1 属性里 `cdhashes` 必须是 `sha256(CodeDirectory)` 的
  前 20 字节，而非完整 32 字节
- `0xE8008029`：iOS 26 要求 DER 形式的 entitlements（slot 7）
- 签名区按 16 字节对齐；dylib 的 CodeDirectory 标识符取 `LC_ID_DYLIB` 的 basename
- 嵌套文件必须纳入父级 `CodeResources`；`files2` 条目需同时带 SHA-1 与 SHA-256

### 已知限制

- 免费 Apple ID：同时只能有 1 张开发证书，描述文件 7 天有效，App ID 每周约 10 个
- 内置原生库目前只提供 Windows x64；其他平台需自行编译
- 插线安装需要 Apple 移动设备驱动（系统级，无法绕过）
