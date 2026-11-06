"""Command line interface for ipasign."""

from __future__ import annotations

from ipasign import paths

import argparse
import getpass
import json
import plistlib
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

from . import __version__, device
from ipasign.core import bundle, ipa, macho, vault
from ipasign.core import doctor as doctor_mod
from ipasign.core.bundle import SignOptions
from ipasign.core.errors import IpasignError
from ipasign.core.pki import (
    SigningIdentity,
    describe_chain,
    ensure_chain,
    load_certificate,
    load_identity,
)
from ipasign.core.profile import ProvisioningProfile
from ipasign.core.verify import verify_ipa


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _log_factory(quiet: bool, verbose: bool):
    def log(message: str) -> None:
        if quiet:
            return
        prefix = "  " if verbose else ""
        print(prefix + message, file=sys.stderr)

    return log


def _load_identity(
    p12: str,
    password: Optional[str],
    chains: List[str],
    *,
    allow_download: bool = True,
    log=print,
) -> SigningIdentity:
    extra = [load_certificate(path) for path in chains]
    try:
        identity = load_identity(p12, password, extra)
    except IpasignError as exc:
        if password is None and "password" in str(exc).lower():
            password = getpass.getpass("p12 password: ")
            identity = load_identity(p12, password, extra)
        else:
            raise
    return ensure_chain(identity, extra, allow_download=allow_download, log=log)


def _open_ipa(path: Path):
    workdir = Path(tempfile.mkdtemp(prefix="ipasign-cli-", dir=str(paths.temp_dir())))
    contents = ipa.extract_ipa(path, workdir)
    return workdir, contents


def _collect_info(contents: ipa.IpaContents) -> dict:
    app = contents.app_path
    info = plistlib.loads((app / "Info.plist").read_bytes())
    executable = bundle.resolve_executable(app, info)
    signatures = []
    architectures: List[str] = []
    encrypted = False
    try:
        executable_bytes = executable.read_bytes()
        architectures = [
            macho.cpu_name(item.cputype)
            for item in macho.split_slices(executable_bytes).slices
        ]
        encrypted = macho.is_encrypted(executable_bytes)
    except Exception:  # noqa: BLE001 - not a Mach-O
        architectures = []
    try:
        signatures = macho.read_signatures(executable.read_bytes())
    except Exception:  # noqa: BLE001 - unsigned / unparsable binary
        signatures = []
    nested = []
    for item in bundle.nested_bundles(app):
        nested.append(
            {
                "path": item.relative_to(app).as_posix(),
                "type": item.suffix.lower().lstrip("."),
            }
        )
    embedded_profile = None
    profile_path = app / "embedded.mobileprovision"
    if profile_path.is_file():
        try:
            embedded_profile = ProvisioningProfile.parse(
                profile_path.read_bytes()
            ).describe()
        except Exception:  # noqa: BLE001
            embedded_profile = {"error": "cannot parse embedded profile"}
    main_signature = signatures[0] if signatures else None
    return {
        "app": app.name,
        "bundle_id": info.get("CFBundleIdentifier"),
        "name": info.get("CFBundleName") or info.get("CFBundleDisplayName"),
        "version": info.get("CFBundleShortVersionString"),
        "build": info.get("CFBundleVersion"),
        "minimum_os": info.get("MinimumOSVersion"),
        "executable": executable.name,
        "architectures": architectures,
        "encrypted": encrypted,
        "signed": main_signature is not None,
        "signature": {
            "identifier": main_signature.code_directory.identifier,
            "team_id": main_signature.code_directory.team_id,
            "cms": main_signature.cms_blob is not None,
            "flags": main_signature.code_directory.flags,
        }
        if main_signature
        else None,
        "nested": nested,
        "profile": embedded_profile,
        "payload_size": sum(
            path.stat().st_size for path in app.rglob("*") if path.is_file()
        ),
    }


def _print_info(info: dict) -> None:
    print(f"App         : {info['app']}")
    print(f"Bundle ID   : {info['bundle_id']}")
    print(f"Name/Version: {info['name']} / {info['version']} ({info['build']})")
    print(f"Min OS      : {info['minimum_os']}")
    print(f"Executable  : {info['executable']} [{', '.join(info['architectures']) or 'unknown'}]")
    if info.get("encrypted"):
        print("Encrypted   : yes (App Store DRM; it will not run after re-signing)")
    size = info["payload_size"]
    size_text = f"{size / 1024 / 1024:.1f} MB" if size >= 1024 * 1024 else f"{size / 1024:.0f} KB"
    print(f"Size        : {size_text}")
    if info["signature"]:
        signature = info["signature"]
        print(
            f"Signature   : {signature['identifier']} "
            f"(team {signature['team_id'] or 'unknown'}, "
            f"{'CMS' if signature['cms'] else 'ad-hoc'})"
        )
    else:
        print("Signature   : unsigned")
    if info["nested"]:
        print("Nested      :")
        for item in info["nested"]:
            print(f"  - {item['path']} ({item['type']})")
    profile = info["profile"]
    if profile and "error" not in profile:
        print(
            f"Profile     : {profile['name']} / {profile['application_identifier']} / "
            f"{'expired' if profile['expired'] else 'valid until ' + str(profile['expires'])[:10]}"
        )


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_sign(args: argparse.Namespace) -> int:
    log = _log_factory(args.quiet, args.verbose)
    input_ipa = Path(args.input)
    if not input_ipa.is_file():
        raise IpasignError(f"IPA file not found: {input_ipa}")
    output_ipa = Path(args.output) if args.output else input_ipa.with_name(
        f"{input_ipa.stem}-signed.ipa"
    )
    if output_ipa.exists() and not args.force:
        raise IpasignError(
            f"output file already exists: {output_ipa} (add --force to overwrite)"
        )


    profile = None
    identity = None
    if args.engine == "zsign" and not args.adhoc:
        from .core.zsign_backend import bundle_id_for_profile, sign_with_zsign

        zsign_profile = ProvisioningProfile.load(args.profile)
        sign_with_zsign(
            input_ipa,
            output_ipa,
            p12=args.p12,
            profile=args.profile,
            password=args.password,
            bundle_id=args.bundle_id or bundle_id_for_profile(zsign_profile),
            log=log,
        )
        print(f"[done] {output_ipa} (zsign engine)")
        return 0

    if not args.adhoc:
        if not args.p12:
            raise IpasignError("a signing certificate is required: pass -c/--p12")
        if not args.profile:
            raise IpasignError("a provisioning profile is required: pass -m/--profile")
        profile = ProvisioningProfile.load(args.profile)
        log(f"Profile: {profile.name} ({profile.application_identifier})")
        identity = _load_identity(
            args.p12,
            args.password,
            args.chain or [],
            allow_download=not args.no_download,
            log=log,
        )
        log(f"Signing certificate: {identity.common_name} (team {identity.team_id})")
        if len(identity.certificates) < 2:
            log("Hint: the chain has no intermediate certificate; iOS may reject the install")

    options = SignOptions(
        bundle_id=args.bundle_id,
        entitlements_file=args.entitlements,
        ad_hoc=args.adhoc,
        rewrite_bundle_id=not args.no_rewrite_bundle_id,
        verbose=args.verbose,
    )
    report = bundle.sign_ipa(
        input_ipa,
        output_ipa,
        identity=identity,
        profile=profile,
        options=options,
        log=log,
        keep_workdir=args.keep_workdir,
    )

    if args.json:
        print(
            json.dumps(
                {
                    "output": str(output_ipa),
                    "bundle_id": report.bundle_id,
                    "team_id": report.team_id,
                    "profile": report.profile_name,
                    "steps": [step.__dict__ for step in report.steps],
                    "warnings": report.warnings,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0

    print(f"[done] Wrote: {output_ipa}")
    print(f"  Bundle ID : {report.bundle_id}")
    print(f"  Team ID   : {report.team_id or 'unknown'}")
    print(f"  Profile   : {report.profile_name or 'none (ad-hoc)'}")
    print(f"  Signed    : {len(report.steps)} Mach-O files")
    for warning in report.warnings:
        print(f"  [warning] {warning}")
    return 0


def cmd_info(args: argparse.Namespace) -> int:
    input_ipa = Path(args.input)
    if not input_ipa.is_file():
        raise IpasignError(f"IPA file not found: {input_ipa}")
    workdir, contents = _open_ipa(input_ipa)
    try:
        info = _collect_info(contents)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    if args.json:
        print(json.dumps(info, ensure_ascii=False, indent=2, default=str))
    else:
        _print_info(info)
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    identity = None
    if args.p12:
        identity = _load_identity(
            args.p12, args.password, args.chain or [], allow_download=True, log=lambda m: None
        )
    profile = ProvisioningProfile.load(args.profile) if args.profile else None
    report = verify_ipa(args.input, identity=identity, profile=profile)

    if args.json:
        print(
            json.dumps(
                {
                    "ok": report.ok,
                    "bundle_id": report.bundle_id,
                    "problems": report.all_problems(),
                    "checks": [check.__dict__ for check in report.checks],
                },
                ensure_ascii=False,
                indent=2,
                default=str,
            )
        )
        return 0 if report.ok else 1

    print(f"Verify: {args.input}")
    for check in report.checks:
        status = "OK " if not check.problems else "ERR"
        cms = "CMS" if check.cms_ok else "no CMS"
        print(
            f"  [{status}] {check.path:45} {check.identifier or '-':40} "
            f"{','.join(check.architectures) or '-':10} {cms}"
        )
        for problem in check.problems:
            print(f"        - {problem}")
    problems = report.all_problems()
    if problems:
        print(f"Result: {len(problems)} problem(s) found")
        return 1
    print("Result: signature structure verified")
    return 0


def cmd_devices(args: argparse.Namespace) -> int:
    if not device.library_available():
        raise IpasignError(
            "pymobiledevice3 is missing; cannot talk to the phone. Install it with:\n"
            "  python -m pip install pymobiledevice3"
        )
    devices = device.list_devices(wifi=True if getattr(args, "wifi", False) else None)
    if args.json:
        print(json.dumps([item.__dict__ for item in devices], ensure_ascii=False, indent=2))
        return 0 if devices else 1
    if not devices:
        if getattr(args, "wifi", False):
            print(
                "No Wi-Fi device found. Connect the cable once and enable "
                "'Sync over Wi-Fi' in iTunes/Finder."
            )
            return 1
        print("No device detected. Please make sure:")
        print("  1) the phone is connected to the computer with a cable;")
        print("  2) the phone is unlocked and you tapped Trust in the prompt;")
        print("  3) iTunes / Apple Devices is installed (it provides the Apple Mobile Device Service).")
        return 1
    for item in devices:
        marker = "" if item.paired else "  [unpaired]"
        print(f"{item.udid}  {item.label()}  [{item.transport}]{marker}")
        if item.extra.get("pairing_error"):
            print(f"    Pairing failed: {item.extra['pairing_error'][:160]}")
    return 0


def cmd_install(args: argparse.Namespace) -> int:
    log = _log_factory(False, args.verbose)
    ipa_path = Path(args.ipa)
    if not ipa_path.is_file():
        raise IpasignError(f"IPA file not found: {ipa_path}")

    if args.verify:
        log("Verifying the signature before install ...")
        report = verify_ipa(ipa_path)
        if not report.ok:
            for problem in report.all_problems()[:10]:
                print(f"  [problem] {problem}")
            raise IpasignError(
                "signature verification failed; install aborted (add --no-verify to skip)"
            )

    udid = device.install_ipa(
        ipa_path,
        udid=args.udid,
        developer=args.developer,
        wifi=getattr(args, "wifi", False),
        log=log,
    )
    print(f"[done] Installed on device {udid}")
    print(
        "If the icon is greyed out, trust the certificate in Settings → General → "
        "VPN & Device Management."
    )
    return 0


def cmd_vault(args: argparse.Namespace) -> int:
    action = getattr(args, "action", None)
    if action == "list":
        items = vault.list_all()
        if args.json:
            print(json.dumps([item.meta for item in items], ensure_ascii=False, indent=2))
            return 0
        if not items:
            print("The vault is empty. Import one first:")
            print("  ipasign vault import <name> cert.p12 -m profile.mobileprovision -p <password>")
            return 0
        for item in items:
            print(f"{item.name:20} {item.summary()}")
        return 0

    if action == "import":
        stored = vault.save(
            args.name, args.p12, args.profile, args.password, overwrite=args.force
        )
        print(f"[done] Stored in the vault: {stored.name}")
        print(f"  p12     : {stored.p12_path}")
        if stored.profile_path:
            print(f"  Profile : {stored.profile_path}")
        print(f"  Team    : {stored.meta.get('team_id') or 'unknown'}")
        print(f"  Expires : {str(stored.meta.get('profile_expires') or stored.meta.get('leaf_expires'))[:10]}")
        return 0

    if action == "show":
        item = vault.load(args.name)
        password = args.password or vault.password_of(item)
        if not password:
            password = getpass.getpass("p12 password: ")
        identity = load_identity(item.p12_path, password)
        profile = (
            ProvisioningProfile.load(item.profile_path) if item.profile_path else None
        )
        checks = doctor_mod.run_checks(
            identity=identity, profile=profile, allow_expired_profile=True
        )
        if args.json:
            payload = {
                "meta": item.meta,
                "identity": identity.describe(),
                "profile": profile.describe() if profile else None,
                "checks": [check.__dict__ for check in checks],
            }
            print(json.dumps(payload, ensure_ascii=False, indent=2, default=str))
            return 0
        print(f"Vault entry: {item.name}")
        for key, value in item.meta.items():
            print(f"  {key:18}: {value}")
        for check in checks:
            print("  " + check.line())
        return 0

    if action == "rm":
        vault.remove(args.name)
        print(f"[done] Removed {args.name} from the vault")
        return 0
    raise IpasignError("unknown vault action")


def cmd_doctor(args: argparse.Namespace) -> int:
    identity = None
    profile = None
    if args.vault:
        item = vault.load(args.vault)
        password = args.password or vault.password_of(item)
        if not password:
            password = getpass.getpass("p12 password: ")
        identity = load_identity(item.p12_path, password)
        identity = ensure_chain(identity, allow_download=False, log=lambda m: None)
        if item.profile_path:
            profile = ProvisioningProfile.load(item.profile_path)
    else:
        if args.p12:
            identity = _load_identity(
                args.p12, args.password, args.chain or [], allow_download=False,
                log=lambda m: None,
            )
        if args.profile:
            profile = ProvisioningProfile.load(args.profile)

    devices = device.list_devices() if args.device else None
    checks = doctor_mod.run_checks(
        ipa_path=args.ipa, identity=identity, profile=profile, devices=devices
    )
    if args.json:
        print(json.dumps([check.__dict__ for check in checks], ensure_ascii=False, indent=2))
        return 0 if doctor_mod.all_ok(checks) else 1
    for check in checks:
        print(check.line())
    print(
        "Result: "
        + ("all checks passed" if doctor_mod.all_ok(checks) else "problems found; fix the FAIL items above")
    )
    return 0 if doctor_mod.all_ok(checks) else 1


def cmd_renew(args: argparse.Namespace) -> int:
    log = _log_factory(False, args.verbose)
    item = vault.load(args.name)
    if item.profile_path is None:
        raise IpasignError(
            f"certificate {item.name!r} has no provisioning profile; cannot renew"
        )
    password = args.password or vault.password_of(item)
    if not password:
        password = getpass.getpass("p12 password: ")
    identity = load_identity(item.p12_path, password)
    identity = ensure_chain(identity, allow_download=True, log=log)
    profile = ProvisioningProfile.load(item.profile_path)
    if profile.is_expired():
        raise IpasignError(
            f"the profile expired on {profile.expiration:%Y-%m-%d}; "
            "regenerate it before renewing"
        )
    output = Path(args.output) if args.output else Path(args.ipa).with_name(
        f"{Path(args.ipa).stem}-renewed.ipa"
    )
    if getattr(args, "engine", "native") == "zsign":
        from .core.zsign_backend import sign_with_zsign

        from .core.zsign_backend import bundle_id_for_profile

        sign_with_zsign(
            args.ipa,
            output,
            p12=item.p12_path,
            profile=item.profile_path,
            password=password,
            bundle_id=args.bundle_id or bundle_id_for_profile(profile),
            log=log,
        )
        print(
            f"[done] {output} (zsign engine, expires {profile.expiration:%Y-%m-%d})"
        )
        if args.install:
            log("Installing to the device ...")
            udid = device.install_ipa(output, udid=args.udid, log=log)
            print(f"[done] Installed on {udid}")
        return 0
    report = bundle.sign_ipa(
        args.ipa, output, identity=identity, profile=profile,
        options=SignOptions(bundle_id=args.bundle_id), log=log,
    )
    print(f"[done] {output}  ({report.bundle_id}, expires {profile.expiration:%Y-%m-%d})")
    if args.install:
        log("Installing to the device ...")
        udid = device.install_ipa(output, udid=args.udid, log=log)
        print(f"[done] Installed on {udid}")
    return 0


def cmd_profile(args: argparse.Namespace) -> int:
    profile = ProvisioningProfile.load(args.profile)
    data = profile.describe()
    data["team_ids"] = profile.team_ids
    data["devices"] = profile.devices[:20]
    data["entitlements_full"] = profile.entitlements
    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2, default=str))
        return 0
    print(f"Name        : {data['name']}")
    print(f"UUID        : {data['uuid']}")
    print(f"Team        : {', '.join(data['team_ids']) or '-'}")
    print(f"App ID      : {data['application_identifier']} ({'wildcard' if data['wildcard'] else 'explicit'})")
    print(f"Expires     : {data['expires'] or '-'} {'[expired]' if data['expired'] else ''}")
    print(f"Devices     : {data['device_count']}")
    print(f"Platforms   : {', '.join(data['platforms'])}")
    print(f"Certificates: {data['certificate_count']}")
    for subject in data["certificates"]:
        print(f"  - {subject}")
    print("Entitlements: " + ", ".join(data["entitlements"]))
    return 0


def cmd_identity(args: argparse.Namespace) -> int:
    identity = _load_identity(
        args.p12,
        args.password,
        args.chain or [],
        allow_download=not args.no_download,
        log=print,
    )
    data = identity.describe()
    data["chain"] = describe_chain(identity)
    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2, default=str))
        return 0
    print(f"Certificate : {data['common_name']}")
    print(f"Team        : {data['team_id']}")
    print(f"Validity    : {data['not_before'][:10]} ~ {data['not_after'][:10]}")
    print(f"SHA256      : {data['sha256']}")
    print("Chain       :")
    for item in data["chain"]:
        marker = " (expired)" if item["expired"] else ""
        print(f"  [{item['index']}] {item['role']:12} {item['subject']}{marker}")
    if len(data["chain"]) < 2:
        print(
            "Hint: the intermediate certificate is missing; iOS will reject the install. "
            "Run `ipasign fetch-certs`"
        )
    return 0


def cmd_login(args: argparse.Namespace) -> int:
    """Log in through the native apple-auth client and list developer teams."""
    from ipasign.apple import auth as apple_auth_bridge

    try:
        library = apple_auth_bridge.library_path()
    except apple_auth_bridge.AppleAuthUnavailable as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 1

    print(f"[..] Native client: {library}")
    print(f"[..] Device identity dir: {apple_auth_bridge.STATE_DIR}")
    try:
        device = apple_auth_bridge.open_device()
        session = None if args.fresh else device.session
        if session is not None:
            print("[..] Reusing the saved sign-in session (--fresh forces a new sign-in)")
        else:
            print("     The first run provisions ADI automatically (takes a few seconds)")
            device, session = apple_auth_bridge.login(args.account, args.password)
    except Exception as exc:  # noqa: BLE001 - native errors
        message = str(exc)
        if "503" in message:
            print(
                "[error] Apple rate limit (HTTP 503): too many requests from this IP in a "
                "short time.\n"
                "        Wait 30-60 minutes, or switch networks (phone hotspot / proxy) "
                "to clear it immediately.",
                file=sys.stderr,
            )
        elif "-22406" in message or "-20101" in message or "-20102" in message:
            print("[error] Incorrect Apple ID or password.", file=sys.stderr)
        else:
            print(f"[error] Sign-in failed: {message}", file=sys.stderr)
        return 1

    print("[done] Signed in")
    try:
        headers = apple_auth_bridge.developer_headers(device, session)
    except Exception as exc:  # noqa: BLE001
        print(f"[error] Cannot obtain a developer session: {exc}", file=sys.stderr)
        return 1

    teams = _fetch_developer_teams(headers)
    if teams:
        print("[done] Developer teams:")
        for team in teams:
            print(
                f"  {team.get('name', '?')}  teamId={team.get('teamId', '?')}  "
                f"type={team.get('type', '?')}"
            )
    else:
        print("[!] No team list returned (the account may not have joined the Developer Program)")
    return 0


def _fetch_developer_teams(headers: Dict[str, str]) -> List[Dict]:
    import plistlib
    import uuid

    import requests

    bundle = paths.ca_bundle()
    body = {
        "clientId": "XABBG36SBA",
        "protocolVersion": "QH65B2",
        "requestId": str(uuid.uuid4()).upper(),
        "userLocale": "en_US",
    }
    response = requests.post(
        "https://developerservices2.apple.com/services/QH65B2/listTeams.action?clientId=XABBG36SBA",
        data=plistlib.dumps(body),
        headers={**headers, "Content-Type": "text/x-xml-plist"},
        verify=str(bundle) if bundle is not None else True,
        timeout=40,
    )
    if response.status_code != 200:
        print(f"[!] listTeams HTTP {response.status_code}", file=sys.stderr)
        return []
    try:
        payload = plistlib.loads(response.content)
    except Exception:  # noqa: BLE001
        return []
    return payload.get("teams", []) or []


def cmd_issue(args: argparse.Namespace) -> int:
    """Issue a certificate + provisioning profile through the developer portal."""
    from ipasign.apple.issue import issue

    bundle_id = args.bundle_id
    app_name = args.app_name
    if not bundle_id:
        if not args.ipa:
            raise IpasignError(
                "pass --bundle-id, or --ipa to read the Bundle ID from an IPA"
            )
        from ipasign.core.doctor import ipa_bundle_info

        info = ipa_bundle_info(args.ipa)
        bundle_id = info["bundle_id"]
        if not app_name:
            app_name = info["name"] or bundle_id.rsplit(".", 1)[-1]
        print(f"[..] Detected from the IPA: {app_name}  {bundle_id}")
    if not app_name:
        app_name = "ipasign app"

    try:
        result = issue(
            bundle_id=bundle_id,
            app_name=app_name,
            device_udid=args.udid,
            vault_name=args.name,
            reuse=args.reuse,
            password=args.password,
            allow_revoke=args.revoke_old,
        )
    except Exception as exc:  # noqa: BLE001 - remote + native errors
        print(f"[error] Issuing failed: {exc}", file=sys.stderr)
        return 1
    print(f"  Team       : {result['team_id']}")
    print(f"  Cert ID    : {result['certificate_id']}")
    print(f"  App ID     : {result['app_id_id']} ({result['bundle_id']})")
    print(f"  Profile    : {result['profile_app_id']}")
    print(f"  Vault entry: {result['name']}")
    print("  Password   : generated and stored in the vault; used automatically when signing")
    return 0


def cmd_tui(args: argparse.Namespace) -> int:
    from .tui import main as tui_main

    return tui_main()


def cmd_watch(args: argparse.Namespace) -> int:
    from . import watch

    action = args.action
    if action == "add":
        job = watch.add_job(
            args.ipa,
            args.vault,
            udid=args.udid,
            output=args.output,
            password=args.password if args.save_password else None,
            wifi=args.wifi,
            interval_hours=args.interval_hours,
            job_id=args.id,
        )
        print(f"[done] Renewal job added: {job.id}")
        print(f"  {job.describe()}")
        print(f"  Output: {job.output_path()}")
        if args.password and not args.save_password:
            print("  Hint: password not stored; watch run/start will prompt for it")
        return 0
    if action == "list":
        jobs = watch.load_jobs()
        if not jobs:
            print("No renewal jobs yet. Add one with `ipasign watch add <ipa> --vault <entry>`.")
            return 0
        for job in jobs:
            print(f"{job.describe()}")
            print(f"    Last run: {job.last_run or '-'}  Result: {job.last_result or '-'}")
            if job.last_error:
                print(f"    Error: {job.last_error[:120]}")
        return 0
    if action == "rm":
        if watch.remove_job(args.id):
            print(f"[done] Deleted {args.id}")
            return 0
        print(f"[error] No such job: {args.id}", file=sys.stderr)
        return 1
    if action == "run":
        results = watch.run_once(
            threshold_hours=args.threshold_hours, force=args.force, log=_log_factory(False, False)
        )
        if not results:
            print("No renewal jobs yet.")
            return 0
        for job_id, result in results.items():
            print(f"  {job_id}: {result}")
        return 0 if all(not str(v).startswith("failed") for v in results.values()) else 1
    if action == "start":
        watch.run_forever(
            interval_minutes=args.interval_minutes,
            threshold_hours=args.threshold_hours,
            log=_log_factory(False, False),
        )
        return 0
    raise IpasignError(f"unknown action: {action}")


def cmd_selfcheck(args: argparse.Namespace) -> int:
    """Print what this build can do and where it looks for things."""
    from . import paths

    print(f"Version     : {__version__}")
    print(f"Mode        : {'single-file executable' if paths.frozen() else 'source / pip install'}")
    print(f"Data dir    : {paths.data_dir()}")
    print(f"Platform    : {paths.platform_tag()}")

    try:
        from .apple import auth

        library = auth.library_path()
        print(f"Auth client : {library}")
    except Exception as error:  # noqa: BLE001
        print(f"Auth client : unavailable ({error})")

    try:
        from .apple.anisette import native

        print(f"Auth core   : {native.find_library()}")
    except Exception as error:  # noqa: BLE001
        print(f"Auth core   : unavailable ({error})")

    from .core import zsign_backend

    print(f"zsign       : {zsign_backend.find_zsign() or 'not installed (optional)'}")

    try:
        from .device import list_devices

        devices = list_devices()
        names = ", ".join(f"{d.name} ({d.transport})" for d in devices) or "none connected"
        print(f"Devices     : {names}")
    except Exception as error:  # noqa: BLE001
        print(f"Devices     : unavailable ({error})")

    entries = vault.list_all()
    print(f"Vault       : {len(entries)} entries" + (": " + ", ".join(e.name for e in entries) if entries else ""))
    return 0


def cmd_fetch_certs(args: argparse.Namespace) -> int:
    from ipasign.core.pki import cert_cache_dir, download_apple_certificates

    files = download_apple_certificates(force=args.force, log=print)
    print(f"Cached {len(files)} certificates in {cert_cache_dir()}")
    return 0



# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ipasign",
        description="iOS IPA re-signing tool (cross-platform, pure-Python signing engine)",
    )
    parser.add_argument("--version", action="version", version=f"ipasign {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    sign = subparsers.add_parser("sign", help="re-sign an IPA")
    sign.add_argument("input", help="input IPA path")
    sign.add_argument("-o", "--output", help="output IPA path (default <input>-signed.ipa)")
    sign.add_argument("-c", "--p12", help="signing certificate .p12/.pfx")
    sign.add_argument("-p", "--password", help="p12 password (prompted when omitted)")
    sign.add_argument("-m", "--profile", help="provisioning profile .mobileprovision")
    sign.add_argument(
        "-b", "--bundle-id",
        help="override the Bundle ID (kept by default, then corrected to the profile)",
    )
    sign.add_argument("-e", "--entitlements", help="use a custom entitlements plist")
    sign.add_argument("--chain", action="append", help="extra intermediate certificate (repeatable)")
    sign.add_argument(
        "--no-download", action="store_true",
        help="do not download Apple intermediate certificates automatically",
    )
    sign.add_argument(
        "--no-rewrite-bundle-id", action="store_true",
        help="never rewrite the Bundle ID automatically",
    )
    sign.add_argument(
        "--adhoc", "--ad-hoc", action="store_true",
        help="ad-hoc signing only (jailbroken devices)",
    )
    sign.add_argument(
        "--engine", choices=["native", "zsign"], default="native",
        help="signing engine (zsign needs the external IPASIGN_ZSIGN executable)",
    )
    sign.add_argument("--keep-workdir", help="keep the extracted workdir (for debugging)")
    sign.add_argument("--force", action="store_true", help="overwrite an existing output file")
    sign.add_argument("--json", action="store_true", help="print the result as JSON")
    sign.add_argument("-q", "--quiet", action="store_true")
    sign.add_argument("-v", "--verbose", action="store_true")
    sign.set_defaults(func=cmd_sign)

    info = subparsers.add_parser("info", help="show basic IPA information")
    info.add_argument("input")
    info.add_argument("--json", action="store_true")
    info.set_defaults(func=cmd_info)

    verify = subparsers.add_parser("verify", help="verify the IPA signature structure")
    verify.add_argument("input")
    verify.add_argument("-c", "--p12", help="signing certificate to compare against")
    verify.add_argument("-p", "--password")
    verify.add_argument("-m", "--profile", help="provisioning profile to compare against")
    verify.add_argument("--chain", action="append")
    verify.add_argument("--json", action="store_true")
    verify.set_defaults(func=cmd_verify)

    vault_parser = subparsers.add_parser(
        "vault", help="local identity vault (p12 + provisioning profile)"
    )
    vault_sub = vault_parser.add_subparsers(dest="action", required=True)
    p = vault_sub.add_parser("list", help="list the vault")
    p.add_argument("--json", action="store_true")
    p = vault_sub.add_parser("import", help="import a certificate and profile pair")
    p.add_argument("name")
    p.add_argument("p12")
    p.add_argument("-m", "--profile")
    p.add_argument("-p", "--password")
    p.add_argument("--force", action="store_true")
    p = vault_sub.add_parser("show", help="show one entry's details and self-check")
    p.add_argument("name")
    p.add_argument("-p", "--password")
    p.add_argument("--json", action="store_true")
    p = vault_sub.add_parser("rm", help="delete from the vault")
    p.add_argument("name")
    vault_parser.set_defaults(func=cmd_vault)

    doctor_parser = subparsers.add_parser(
        "doctor",
        help="pre-flight checks: do the certificate / profile / device / IPA match?",
    )
    doctor_parser.add_argument("ipa", nargs="?")
    doctor_parser.add_argument("--vault", help="use a vault entry")
    doctor_parser.add_argument("-c", "--p12")
    doctor_parser.add_argument("-p", "--password")
    doctor_parser.add_argument("-m", "--profile")
    doctor_parser.add_argument("--chain", action="append")
    doctor_parser.add_argument(
        "--device", action="store_true",
        help="also check whether connected devices are listed in the profile",
    )
    doctor_parser.add_argument("--json", action="store_true")
    doctor_parser.set_defaults(func=cmd_doctor)

    renew_parser = subparsers.add_parser(
        "renew", help="re-sign with a vault identity (optionally install right away)"
    )
    renew_parser.add_argument("name")
    renew_parser.add_argument("ipa")
    renew_parser.add_argument("-o", "--output")
    renew_parser.add_argument(
        "-p", "--password",
        help="p12 password (tool-generated entries use the stored password)",
    )
    renew_parser.add_argument("-b", "--bundle-id")
    renew_parser.add_argument("--install", action="store_true")
    renew_parser.add_argument("--udid")
    renew_parser.add_argument("-v", "--verbose", action="store_true")
    renew_parser.add_argument(
        "--engine", choices=["native", "zsign"], default="native",
        help="signing engine (zsign needs an external executable)",
    )
    renew_parser.set_defaults(func=cmd_renew)

    devices = subparsers.add_parser("devices", help="list connected iPhone / iPad devices")
    devices.add_argument("--json", action="store_true")
    devices.add_argument("--wifi", action="store_true", help="only show devices connected over Wi-Fi")
    devices.set_defaults(func=cmd_devices)

    install = subparsers.add_parser("install", help="install a signed IPA on a device")
    install.add_argument("ipa")
    install.add_argument("--udid", help="target device UDID (required when several are connected)")
    install.add_argument("--developer", action="store_true", help="install as a developer package")
    install.add_argument(
        "--wifi", action="store_true",
        help="install over Wi-Fi (requires prior Wi-Fi sync pairing)",
    )
    install.add_argument(
        "--verify", dest="verify", action="store_true",
        help="verify the signature structure before installing",
    )
    install.add_argument(
        "--no-verify", dest="verify", action="store_false",
        help="skip the pre-install verification",
    )
    install.add_argument("-v", "--verbose", action="store_true")
    install.set_defaults(func=cmd_install, verify=False)

    profile = subparsers.add_parser("profile", help="show the contents of a provisioning profile")
    profile.add_argument("profile")
    profile.add_argument("--json", action="store_true")
    profile.set_defaults(func=cmd_profile)

    identity = subparsers.add_parser("identity", help="show the signing certificate and its chain")
    identity.add_argument("p12")
    identity.add_argument("-p", "--password")
    identity.add_argument("--chain", action="append")
    identity.add_argument("--no-download", action="store_true")
    identity.add_argument("--json", action="store_true")
    identity.set_defaults(func=cmd_identity)

    tui = subparsers.add_parser("tui", help="start the interactive terminal UI")
    tui.set_defaults(func=cmd_tui)

    watch_parser = subparsers.add_parser(
        "watch", help="auto-renew: re-sign and reinstall before the profile expires"
    )
    watch_sub = watch_parser.add_subparsers(dest="action", required=True)

    p = watch_sub.add_parser("add", help="add a renewal job")
    p.add_argument("ipa")
    p.add_argument("--vault", required=True, help="vault entry name")
    p.add_argument("--udid", help="target device (auto-selected at run time when omitted)")
    p.add_argument(
        "--output", help="output path after re-signing (default <name>-renewed.ipa)"
    )
    p.add_argument("--password", help="p12 password (only stored together with --save-password)")
    p.add_argument(
        "--save-password", action="store_true",
        help="store the p12 password in the job file (plain text)",
    )
    p.add_argument("--wifi", action="store_true", help="install over Wi-Fi after renewing")
    p.add_argument("--interval-hours", type=float, default=24.0)
    p.add_argument("--id", help="job name (random by default)")
    p.set_defaults(func=cmd_watch)

    p = watch_sub.add_parser("list", help="list renewal jobs")
    p.set_defaults(func=cmd_watch)

    p = watch_sub.add_parser("rm", help="delete a renewal job")
    p.add_argument("id")
    p.set_defaults(func=cmd_watch)

    p = watch_sub.add_parser("run", help="check and renew once, right now")
    p.add_argument("--force", action="store_true", help="ignore the expiry and renew anyway")
    p.add_argument("--threshold-hours", type=float, default=24.0)
    p.set_defaults(func=cmd_watch)

    p = watch_sub.add_parser("start", help="start the daemon loop that checks periodically")
    p.add_argument("--interval-minutes", type=float, default=60.0)
    p.add_argument("--threshold-hours", type=float, default=24.0)
    p.set_defaults(func=cmd_watch)

    selfcheck = subparsers.add_parser("selfcheck", help="check runtime dependencies and paths")
    selfcheck.set_defaults(func=cmd_selfcheck)

    fetch = subparsers.add_parser(
        "fetch-certs", help="download and cache the Apple WWDR intermediate certificates"
    )
    fetch.add_argument("--force", action="store_true")
    fetch.set_defaults(func=cmd_fetch_certs)

    issue = subparsers.add_parser(
        "issue", help="issue a certificate + profile automatically and store them in the vault"
    )
    issue.add_argument("--bundle-id", help="the app's Bundle ID (or read it from --ipa)")
    issue.add_argument("--ipa", help="read the Bundle ID from this IPA")
    issue.add_argument(
        "--app-name", help="name shown in the developer portal (defaults to the IPA's name)"
    )
    issue.add_argument("--udid", help="also register the device with this UDID")
    issue.add_argument("--name", help="vault entry name (generated by default)")
    issue.add_argument(
        "--reuse", help="reuse a vault certificate and only request a new profile "
        "(recommended for free accounts)",
    )
    issue.add_argument(
        "--revoke-old", action="store_true",
        help="when the certificate slots are full and the key is not here, revoke the old "
        "certificate and request again",
    )
    issue.add_argument("--password", default="ipasign", help="password for the generated p12")
    issue.set_defaults(func=cmd_issue)

    login = subparsers.add_parser(
        "login", help="sign in with an Apple ID to issue certificates and profiles"
    )
    login.add_argument("--account", required=True, help="Apple ID email")
    login.add_argument("--password", help="prompt for it locally when omitted (recommended)")
    login.add_argument("--fresh", action="store_true", help="ignore the saved session and sign in again")
    login.set_defaults(func=cmd_login)


    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 2
    try:
        return int(args.func(args))
    except IpasignError as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n[interrupted]", file=sys.stderr)
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
