# ipasign

**iOS IPA re-signing toolkit** — a pure-Python signing engine with an interactive terminal UI.

No Xcode, no macOS, no third-party signing service: certificates, provisioning profiles, Mach-O code signing, IPA packaging and device installation all happen locally.

**English** | [简体中文](README.zh-CN.md)

```
+------------------------ ipasign  iOS signing tool -------------------------+
| Version   1.0.0                                                            |
| Vault     0 identities (empty)                                             |
| Account   not signed in                                                    |
| Device    none detected                                                    |
| Data dir  <data dir>                                                       |
+----------------------------------------------------------------------------+
  1       Apple ID sign-in (developer session)  
  2       Issue certificate + profile           
  3       Sign an IPA                           
  4       Install to device                     
  5       Check a signed IPA (doctor)           
  6       Manage the vault                      
  7       Devices and drivers                   
  8       Auto-renew (re-sign and reinstall)    
  9       About / paths                         
  0       Quit                                  
```

Menu items are **self-sufficient**: pick `2` without signing in and it walks you through sign-in first; pick `3` with an empty vault and it offers to issue a certificate.

## Features

| Capability | Notes |
| --- | --- |
| Re-signing | Parses and rebuilds the Mach-O code signature: CodeDirectory, requirements, CMS, DER entitlements |
| Resource seal | Generates `_CodeSignature/CodeResources`, nested bundles included |
| IPA packaging | Unpack → sign every layer (appex / framework / dylib) → repack |
| Certificate factory | Signs in with your own Apple ID; issues a development certificate, App ID and profile |
| Device attestation | Provisions ADI v3 locally; no third-party anisette service |
| Installation | Installs over USB or Wi-Fi through `pymobiledevice3` |
| Auto-renew | Re-issues the profile before expiry, re-signs and reinstalls on a loop |
| Doctor | Checks the chain, validity, Bundle ID coverage, device UDID and team consistency |
| Vault | Keeps several identities, one command to re-sign |
| Two engines | `native` (default, pure Python) or an external `zsign` |

## Install

Requires **Python 3.10+**. The native sign-in libraries ship inside the wheel
(`ipasign/native/win-x64/`), so sign-in and certificate issuing work out of the box.

```bash
pip install .            # or, once published: pip install ipasign
ipasign                  # works from any directory
```

Optional extras:

```bash
pip install ".[device]"  # adds pymobiledevice3 for installing to a device
pip install -e ".[all]"  # development: editable install with test dependencies
```

The only system-level requirement is Apple's USB driver (iTunes or the
**Apple Devices** app) on Windows, and only for installing over a cable.
macOS ships that driver. **Signing, sign-in, issuing and auto-renew do not need it.**

Uninstall with `pip uninstall ipasign`.

### Building the native libraries on other platforms

Windows x64 is bundled. For macOS, Linux or Windows ARM64, build
[apple-auth](https://github.com/apple-auth/apple-auth) once:

```bash
git clone https://github.com/apple-auth/apple-auth
cmake -S apple-auth -B apple-auth-client -G "Visual Studio 17 2022" -A x64 \
      -DAPPLE_AUTH_WITH_CLIENT=ON -DAPPLE_AUTH_WITH_CURL=ON \
      -DAPPLE_AUTH_BUILD_EXAMPLES=OFF -DBUILD_SHARED_LIBS=ON
cmake --build apple-auth-client --config Release
```

Then let ipasign find the result, in this order:

1. `APPLE_AUTH_LIBRARY` — full path to `apple_auth_client.dll`
2. `<data dir>/native/` — copy the DLL plus `libcurl`, `plist-2.0` and `z`
3. the source checkout (development layout)
4. the platform application-data directory
5. `PATH`

All locations are resolved by `ipasign/paths.py`; no absolute path is hard-coded.
Other environment variables: `IPASIGN_HOME`, `IPASIGN_NATIVE_DIR`,
`IPASIGN_APPLE_AUTH_DLL`, `IPASIGN_ZSIGN`, `IPASIGN_LANG`.

## Quick start

### Interactive UI (recommended)

```bash
ipasign
```

The first start asks for the interface language (English or 简体中文) and remembers
the choice; it can be changed later in **About**. Passwords and 2FA codes are read
with `getpass` and never written to disk.

### Command line

```bash
# 1. sign in once (password and 2FA code are entered in the terminal)
ipasign login --account you@example.com

# 2. issue a certificate + profile (the Bundle ID is read from the IPA)
ipasign issue --ipa app.ipa --udid 00008110-0011223344556677

# 3. sign with the vault entry that was just created
ipasign renew <entry> app.ipa -o app-signed.ipa

# 4. or sign directly with a p12 and a profile
ipasign sign app.ipa -o app-signed.ipa -c id.p12 -m profile.mobileprovision -p <password>

# 5. sign and install
ipasign renew <entry> app.ipa -o app-signed.ipa --install
```

## Command reference

| Command | Purpose |
| --- | --- |
| `ipasign` | Interactive terminal UI |
| `ipasign tui` | Same, explicitly |
| `ipasign login --account <Apple ID> [--fresh]` | Sign in, obtain a developer session and list teams |
| `ipasign issue --ipa <ipa>` | Read the Bundle ID from the IPA and issue certificate / App ID / profile |
| `ipasign issue --bundle-id <id>` | Issue with an explicit Bundle ID |
| `ipasign issue ... --reuse <entry>` | Reuse a certificate, issue only a new profile (needed on free accounts) |
| `ipasign sign <ipa>` | Re-sign with a given p12 + profile (`--engine zsign` for the fallback) |
| `ipasign renew <entry> <ipa>` | Take the identity from the vault and re-sign; `--install` also installs |
| `ipasign install <ipa> [--udid <udid>] [--wifi]` | Install to a device |
| `ipasign verify <ipa>` | Validate the signature structure (CodeDirectory / CMS / resource seal) |
| `ipasign doctor <ipa> --vault <entry>` | Full signing check |
| `ipasign vault list/import/show/rm` | Manage the vault |
| `ipasign devices [--wifi]` | List connected devices |
| `ipasign selfcheck` | Check dependencies, paths, native libraries and devices |
| `ipasign watch add/list/rm/run/start` | Manage auto-renew jobs |
| `ipasign info <ipa>` | Show basic IPA information |
| `ipasign profile <file>` | Show a provisioning profile |
| `ipasign identity <p12>` | Show a certificate and its chain |
| `ipasign fetch-certs` | Cache Apple's WWDR intermediate certificates |

Add `--lang en` / `--lang zh` to any command to pick the interface language.

## Project layout

```
ipasign/
├── app.py              # entry point: no arguments -> TUI, arguments -> CLI
├── tui.py              # rich terminal interface (i18n via i18n.py)
├── i18n.py             # English + Chinese message catalog
├── cli.py              # argparse commands
├── paths.py            # every path is resolved here
├── device.py           # installation through pymobiledevice3 (USB / Wi-Fi)
├── watch.py            # auto-renew jobs and the daemon loop
├── core/               # signing engine (no Apple services, usable standalone)
│   ├── macho.py        #   Mach-O parsing and signature rebuilding
│   ├── cms.py          #   CMS/PKCS#7 signing and verification
│   ├── der.py          #   minimal DER encoder/decoder
│   ├── derplist.py     #   entitlements as DER (slot 7)
│   ├── bundle.py       #   layer-by-layer signing orchestration
│   ├── resources.py    #   _CodeSignature/CodeResources
│   ├── ipa.py          #   IPA unpack / pack
│   ├── profile.py      #   profile parsing and entitlement derivation
│   ├── pki.py          #   chains, p12, WWDR
│   ├── vault.py        #   local identity store
│   ├── verify.py       #   signature self-check
│   ├── doctor.py       #   the doctor checks
│   └── errors.py       #   exception types
└── apple/              # Apple service integration
    ├── auth.py         #   GrandSlam sign-in (drives the native client)
    ├── developer.py    #   developerservices2 (QH65B2)
    ├── issue.py        #   certificate factory: CSR -> cert -> App ID -> profile
    └── anisette/       #   device attestation (ADI)
        ├── adi.py      #     ADI container parsing
        ├── native.py   #     ctypes bindings to apple_auth.dll
        └── provision.py#     local ADI v3 provisioning (SPIM -> CPIM -> PTM)
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the protocol details.

## How it works

**Signing** (`core/macho.py`): parses `LC_CODE_SIGNATURE`, hashes every page,
rebuilds CodeDirectory v0x20400, writes requirements, XML entitlements, DER
entitlements (iOS 15+) and the CMS blob (including Apple's hash-agility
attributes), then aligns the signature area to 16 bytes. The output is
field-for-field identical to `zsign` and installs on iOS 26.

**Certificate factory** (`apple/issue.py`): after sign-in the Xcode application
token is used against the developer API: `addDevice` -> `submitDevelopmentCSR` ->
`addAppId` -> `downloadTeamProvisioningProfile`. The private key never leaves the
machine; only the CSR and the public key are sent.

**Device attestation** (`apple/anisette/`): requests SPIM from Apple, derives
CPIM from local hardware fingerprints, exchanges it for PTM/trust keys and
stores `adi.pb`; each later request uses it to compute the one-time
`X-Apple-I-MD` header.

## Engines

The default `native` engine is pure Python, matches zsign field by field and is
verified on real iOS 26 hardware. An external zsign binary can be used instead:

```bash
ipasign sign app.ipa -o out.ipa -c id.p12 -m profile.mobileprovision --engine zsign
ipasign renew <entry> app.ipa -o out.ipa --engine zsign --install
```

zsign is a separate GPLv3 program and is **not bundled**: download it and point
`IPASIGN_ZSIGN` at the executable.

## Verified

The following open-source apps were re-signed with the native engine and
installed successfully on an iPad running iOS 26.5:

| App | Structural trait |
| --- | --- |
| [Dolphin iOS](https://github.com/OatmealDome/dolphin-ios) | fat frameworks plus a loose dylib |
| [SideStore](https://github.com/SideStore/SideStore) | framework plus an app extension |
| [iNDS](https://github.com/iNDS-Team/iNDS) | main binary is arm + arm64 |
| [Termoso](https://github.com/termoso/termoso) | completely unsigned (no `LC_CODE_SIGNATURE`) |

## Notes

- **Free Apple IDs** allow **one** active certificate (`maxActive: 1`) and
  profiles expire after **7 days**. Use `--reuse` to keep the certificate and
  only fetch a new profile when switching apps.
- **Automatic reuse**: signing the same Bundle ID again reuses the existing App
  ID and certificate; if Apple reports the certificate limit, the tool falls
  back to the certificate already in the vault.
- **Developer Mode**: iOS 16+ requires `Settings > Privacy & Security >
  Developer Mode` to be enabled once, followed by a reboot.
- **Trusting the certificate**: after the first install, trust your development
  certificate in `Settings > General > VPN & Device Management`.
- **Wi-Fi installation**: connect once over USB, enable *Sync over Wi-Fi* in
  iTunes/Finder, then `ipasign devices --wifi` and `ipasign install --wifi`.
- **Auto-renew**: `ipasign watch add app.ipa --vault <entry> --udid <UDID>`,
  then `ipasign watch run` (one check) or `ipasign watch start` (foreground
  daemon; use Task Scheduler / systemd timer / cron for something permanent).
  Jobs live in `<data dir>/renewals.json`; the p12 password is not stored unless
  `--save-password` is given.
- **Rate limits**: Apple throttles sign-ins and certificate requests; on HTTP
  503 wait 30-60 minutes or switch networks.
- **Only sign what you are allowed to**: this tool does not bypass App Store
  DRM and is not meant to facilitate piracy.

## Security and privacy

- The Apple ID password is read with `getpass` and is **never written to disk or
  logged**.
- Only these files are written: `adi.pb` (device identity),
  `account-session.plist` (session), and the p12/profile pairs in the vault.
- Configuration lives in **`<project>/.ipasign/`** when running from a source
  checkout, and in `~/.ipasign/` for a pip-installed copy. Override with
  `IPASIGN_HOME`. Temporary unpacking happens in `<data dir>/tmp/` and is
  cleaned up automatically.
- The p12 password for factory-issued identities is a generated random value
  stored in `<data dir>/identities/<entry>/meta.json` (plain text, readable by
  the current user only), so signing needs no prompt.
- Imported p12 files never have their password recorded.

## Development

```bash
pip install -e ".[all]"
pytest
```

The signing engine is decoupled from Apple services: `ipasign.core` does not
touch the network and can be used standalone for batch signing.

## License

MIT.
