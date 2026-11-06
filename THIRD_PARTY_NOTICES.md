# Third-party components and licenses

ipasign itself is released under the MIT license. The third-party code and
binaries included in this repository are listed below.

## Bundled binaries (`ipasign/native/win-x64/`)

| Component | License | Project |
| --- | --- | --- |
| apple-auth (`apple_auth_client.dll`, `apple_auth.dll`) | MIT | https://github.com/apple-auth/apple-auth |
| curl (`libcurl.dll`) | curl License (MIT-style) | https://curl.se/docs/copyright.html |
| libplist (`plist-2.0.dll`) | LGPL-2.1 | https://github.com/libimobiledevice/libplist |
| zlib (`z.dll`) | zlib License | https://zlib.net/zlib_license.html |
| mbedTLS (statically linked into apple-auth) | Apache-2.0 | https://www.trustedfirmware.org/projects/mbed-tls/ |
| nlohmann/json (statically linked into apple-auth) | MIT | https://github.com/nlohmann/json |

- Provenance and checksums are listed in `ipasign/native/README.md`; verify them
  with `sha256sum`.
- libplist is linked dynamically, so `plist-2.0.dll` can be replaced by the user
  (an LGPL requirement).
- Every binary can be rebuilt from source; the steps are in
  `ipasign/native/README.md`.

## Bundled Python code (`ipasign/vendor/apple_auth/`)

| Component | License | Notes |
| --- | --- | --- |
| apple-auth Python bindings | MIT | Full license text in `ipasign/vendor/apple-auth.LICENSE` |

## Runtime dependencies (installed by pip, not vendored)

| Component | License |
| --- | --- |
| cryptography | Apache-2.0 / BSD-3-Clause |
| requests | Apache-2.0 |
| rich | MIT |
| pymobiledevice3 (optional, for installing to a device) | LGPL-3.0 |
