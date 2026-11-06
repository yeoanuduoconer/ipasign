# Bundled native libraries (Windows x64)

These DLLs make "sign in with an Apple ID / issue a certificate" work out of the
box — **no local build required**.

## Provenance

Built from the [apple-auth](https://github.com/apple-auth/apple-auth) source (MIT):

```bash
git clone https://github.com/apple-auth/apple-auth
cmake -S apple-auth -B apple-auth-client -G "Visual Studio 17 2022" -A x64 \
      -DCMAKE_TOOLCHAIN_FILE=<vcpkg>/scripts/buildsystems/vcpkg.cmake \
      -DAPPLE_AUTH_WITH_CLIENT=ON -DAPPLE_AUTH_WITH_CURL=ON \
      -DAPPLE_AUTH_BUILD_EXAMPLES=OFF -DBUILD_SHARED_LIBS=ON
cmake --build apple-auth-client --config Release
```

| File | Purpose | Origin |
| --- | --- | --- |
| `apple_auth_client.dll` | GrandSlam sign-in, 2FA, developer session | apple-auth |
| `apple_auth.dll` | ADI parsing, OTP generation, provisioning | apple-auth |
| `libcurl.dll` | HTTPS transport | curl |
| `plist-2.0.dll` | plist encoding/decoding | libplist |
| `z.dll` | compression | zlib |

## Checksums

```
bf634ecb99a761c0787b73ef3fc54ee67d7a182d012ccb3b7b3e1d28b3c8b5ae  apple_auth_client.dll
f93b6d13bd5423cefafabcac0c7ce4a9a5b0bb7024084679250602ef50945e0e  apple_auth.dll
20439c85e9acb13c47a4b2a163ce8024b16f290ea095827f3403267048f13322  libcurl.dll
014100c7712545afb230012b23a431a5ad7b019a673adbe63070192e8bbd6f3f  plist-2.0.dll
d3f6e896c197f561e2b78692983d211cf13d92413f24a0cfd7714c0f4133c466  z.dll
```

## Overriding the bundled build

Search order (`ipasign/paths.py`):

```
1. environment: APPLE_AUTH_LIBRARY / IPASIGN_NATIVE_DIR
2. ~/.ipasign/native/           <- put a locally built version here
3. this directory (bundled)
4. a development build next to the checkout
5. the platform application-data directory
```

A locally built copy in `~/.ipasign/native/` takes precedence over the bundled one.

## Other platforms

Only **Windows x64** is bundled. macOS / Linux / Windows ARM64 need a local
build, placed in `~/.ipasign/native/` (file names: `libapple_auth_client.so`,
`libapple_auth_client.dylib`, and so on; `ipasign/paths.py` resolves per platform).
