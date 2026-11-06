# Changelog

The format follows [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/), and version numbers follow Semantic Versioning.

## [1.0.0] - 2026-11-07

First usable release.

### Features

- **Signing engine**: rebuilds Mach-O code signing in pure Python (CodeDirectory, requirements,
  CMS/PKCS#7, DER entitlements), with no dependency on zsign or other external tools
- **Resource sealing**: generates `_CodeSignature/CodeResources`; nested bundles (appex,
  framework, dylib) are signed layer by layer
- **Certificate factory**: sign in with your own Apple ID and automatically request development
  certificates, App IDs, and provisioning profiles (registering devices and reusing certificates and App IDs automatically)
- **Device attestation**: built-in ADI v3 support, with no dependency on third-party anisette services
- **Installation**: install to devices connected over USB / Wi-Fi through pymobiledevice3
- **Automatic renewal**: before expiry, automatically request the provisioning profile again → re-sign → reinstall; can run as a daemon loop
- **Interactive interface**: rich TUI with self-contained menu items (it guides you in place when sign-in or a certificate is missing)
- **Dual engines**: native by default; switch to the external zsign with `--engine zsign`

### Fixes (key issues during development)

- `0xe8008019`: the `cdhashes` in the CMS 9.1 attribute must be the first 20 bytes of
  `sha256(CodeDirectory)`, not the full 32 bytes
- `0xE8008029`: iOS 26 requires entitlements in DER form (slot 7)
- The signing area is aligned to 16 bytes; a dylib's CodeDirectory identifier takes the basename of `LC_ID_DYLIB`
- Nested files must be included in the parent `CodeResources`; `files2` entries must carry both SHA-1 and SHA-256

### Known limitations

- Free Apple ID: only 1 development certificate at a time, provisioning profiles are valid for 7 days, and roughly 10 App IDs per week
- The bundled native library currently ships for Windows x64 only; other platforms must build it themselves
- Wired installation requires the Apple mobile device driver (system-level, cannot be bypassed)
