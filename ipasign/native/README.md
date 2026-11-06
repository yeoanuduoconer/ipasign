# 内置原生库（Windows x64）

这些 DLL 让「登录 Apple ID / 申请证书」开箱即用，**不需要用户自己编译**。

## 来源

从 [apple-auth](https://github.com/apple-auth/apple-auth)（MIT）源码编译：

```bash
git clone https://github.com/apple-auth/apple-auth
cmake -S apple-auth -B apple-auth-client -G "Visual Studio 17 2022" -A x64 \
      -DCMAKE_TOOLCHAIN_FILE=<vcpkg>/scripts/buildsystems/vcpkg.cmake \
      -DAPPLE_AUTH_WITH_CLIENT=ON -DAPPLE_AUTH_WITH_CURL=ON \
      -DAPPLE_AUTH_BUILD_EXAMPLES=OFF -DBUILD_SHARED_LIBS=ON
cmake --build apple-auth-client --config Release
```

| 文件 | 作用 | 来源 |
| --- | --- | --- |
| `apple_auth_client.dll` | GrandSlam 登录、2FA、开发者会话 | apple-auth |
| `apple_auth.dll` | ADI 解析、OTP 生成、provisioning | apple-auth |
| `libcurl.dll` | HTTPS 传输 | curl |
| `plist-2.0.dll` | plist 编解码 | libplist |
| `z.dll` | 压缩 | zlib |

## 校验和

```
bf634ecb99a761c0787b73ef3fc54ee67d7a182d012ccb3b7b3e1d28b3c8b5ae  apple_auth_client.dll
f93b6d13bd5423cefafabcac0c7ce4a9a5b0bb7024084679250602ef50945e0e  apple_auth.dll
20439c85e9acb13c47a4b2a163ce8024b16f290ea095827f3403267048f13322  libcurl.dll
014100c7712545afb230012b23a431a5ad7b019a673adbe63070192e8bbd6f3f  plist-2.0.dll
d3f6e896c197f561e2b78692983d211cf13d92413f24a0cfd7714c0f4133c466  z.dll
```

## 覆盖与替换

优先级（`ipasign/paths.py`）：

```
1. 环境变量 APPLE_AUTH_LIBRARY / IPASIGN_NATIVE_DIR
2. ~/.ipasign/native/           ← 用户自己编译的新版本放这里
3. 本目录（内置）
4. 仓库同级开发目录
5. 平台数据目录
```

想用自己编译的版本，放到 `~/.ipasign/native/` 即可覆盖内置版本。

## 其他平台

目前只内置了 **Windows x64**。macOS / Linux / Windows ARM64 需要自行编译，
放到 `~/.ipasign/native/`（文件名：`libapple_auth_client.so`、
`libapple_auth_client.dylib` 等，`ipasign/paths.py` 会按平台查找）。
