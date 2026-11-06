# 安全策略

## 报告问题

如果你发现安全问题（例如私钥泄漏、签名校验绕过、凭据被写入磁盘），请不要开公开
issue，直接通过 GitHub 的 **Security → Report a vulnerability** 私下报告。

请包含：复现步骤、受影响版本、你的环境（操作系统 / Python 版本）。

## 这个工具会接触哪些敏感数据

| 数据 | 存放位置 | 说明 |
| --- | --- | --- |
| Apple ID 密码 | **不保存** | 仅由 `getpass` 在终端读取，用于当次登录 |
| 双重认证验证码 | **不保存** | 同上，仅在内存中使用 |
| 账号会话令牌 | 数据目录 `apple-auth-device-mac/account-session.plist` | 登录成功后由 Apple 返回 |
| 设备身份（ADI） | 数据目录 `apple-auth-device-mac/adi.pb` | 申请证书时的设备证明，含设备标识 |
| 开发证书私钥 | 数据目录 `identities/<条目>/identity.p12` | 加密存储，密码见下 |
| p12 密码 | 数据目录 `identities/<条目>/meta.json` | 工具生成的身份会明文记录在本机，便于免交互签名 |
| 描述文件 | 数据目录 `identities/<条目>/profile.mobileprovision` | 含 Team ID、App ID、设备 UDID |

数据目录默认位置：

- 源码目录运行 → `<项目目录>/.ipasign`
- pip 安装 → `~/.ipasign`
- 可用环境变量 `IPASIGN_HOME` 覆盖

## 分享前的检查

**提交 issue 或分享项目前**：

- 不要包含 `.ipasign/` 目录（`.gitignore` 已排除）
- 不要上传 `*.p12`、`*.mobileprovision`、签名后的 `*.ipa`（里面嵌着描述文件）
- 日志里的 `selfcheck` 输出含本机路径，粘贴前请自行删减

## 我们不做什么

- 不上传任何数据到第三方服务；所有网络请求只发往 Apple 官方域名
  （`gsa.apple.com`、`developerservices2.apple.com`、`idmsa.apple.com` 等）
- 不内置遥测、不收集使用统计
- 不绕过 Apple 的证书与描述文件校验
