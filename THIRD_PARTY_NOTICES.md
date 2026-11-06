# 第三方组件与许可证

ipasign 本身以 MIT 许可证发布。仓库中包含的第三方代码与二进制如下。

## 内置二进制（`ipasign/native/win-x64/`）

| 组件 | 许可证 | 项目地址 |
| --- | --- | --- |
| apple-auth（`apple_auth_client.dll`、`apple_auth.dll`） | MIT | https://github.com/apple-auth/apple-auth |
| curl（`libcurl.dll`） | curl License（MIT 风格） | https://curl.se/docs/copyright.html |
| libplist（`plist-2.0.dll`） | LGPL-2.1 | https://github.com/libimobiledevice/libplist |
| zlib（`z.dll`） | zlib License | https://zlib.net/zlib_license.html |
| mbedTLS（静态链接进 apple-auth） | Apache-2.0 | https://www.trustedfirmware.org/projects/mbed-tls/ |
| nlohmann/json（静态链接进 apple-auth） | MIT | https://github.com/nlohmann/json |

- 二进制来源与校验和见 `ipasign/native/README.md`，可用 `sha256sum` 核对。
- libplist 以动态库形式链接，用户可自行替换 `plist-2.0.dll`（LGPL 要求）。
- 所有二进制均可从源码重新编译，步骤见 `ipasign/native/README.md`。

## 内置 Python 代码（`ipasign/vendor/apple_auth/`）

| 组件 | 许可证 | 说明 |
| --- | --- | --- |
| apple-auth Python bindings | MIT | 完整许可证文本见 `ipasign/vendor/apple-auth.LICENSE` |

## 运行时依赖（由 pip 安装，不随仓库分发）

| 组件 | 许可证 |
| --- | --- |
| cryptography | Apache-2.0 / BSD-3-Clause |
| requests | Apache-2.0 |
| rich | MIT |
| pymobiledevice3（可选，装机用） | LGPL-3.0 |
