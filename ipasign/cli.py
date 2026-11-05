"""Command line interface for ipasign."""

from __future__ import annotations

import argparse
import getpass
import json
import plistlib
import shutil
import sys
import tempfile
from pathlib import Path
from typing import List, Optional

from . import __version__, bundle, device, ipa, macho
from .bundle import SignOptions
from .errors import IpasignError
from .pki import (
    SigningIdentity,
    describe_chain,
    ensure_chain,
    load_certificate,
    load_identity,
)
from .profile import ProvisioningProfile
from .verify import verify_ipa
from .zsign_engine import find_zsign, sign_with_zsign


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
            password = getpass.getpass("p12 密码: ")
            identity = load_identity(p12, password, extra)
        else:
            raise
    return ensure_chain(identity, extra, allow_download=allow_download, log=log)


def _open_ipa(path: Path):
    workdir = Path(tempfile.mkdtemp(prefix="ipasign-cli-"))
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
    print(f"应用        : {info['app']}")
    print(f"Bundle ID   : {info['bundle_id']}")
    print(f"名称/版本   : {info['name']} / {info['version']} ({info['build']})")
    print(f"最低系统    : {info['minimum_os']}")
    print(f"主程序      : {info['executable']} [{', '.join(info['architectures']) or '未知'}]")
    if info.get("encrypted"):
        print("加密状态    : 已加密（App Store DRM，重签后无法直接运行）")
    size = info["payload_size"]
    size_text = f"{size / 1024 / 1024:.1f} MB" if size >= 1024 * 1024 else f"{size / 1024:.0f} KB"
    print(f"大小        : {size_text}")
    if info["signature"]:
        signature = info["signature"]
        print(
            f"签名        : {signature['identifier']} "
            f"(team {signature['team_id'] or '未知'}, "
            f"{'CMS' if signature['cms'] else 'ad-hoc'})"
        )
    else:
        print("签名        : 未签名")
    if info["nested"]:
        print("嵌套组件    :")
        for item in info["nested"]:
            print(f"  - {item['path']} ({item['type']})")
    profile = info["profile"]
    if profile and "error" not in profile:
        print(
            f"描述文件    : {profile['name']} / {profile['application_identifier']} / "
            f"{'已过期' if profile['expired'] else '有效期至 ' + str(profile['expires'])[:10]}"
        )


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_sign(args: argparse.Namespace) -> int:
    log = _log_factory(args.quiet, args.verbose)
    input_ipa = Path(args.input)
    if not input_ipa.is_file():
        raise IpasignError(f"找不到 IPA 文件: {input_ipa}")
    output_ipa = Path(args.output) if args.output else input_ipa.with_name(
        f"{input_ipa.stem}-signed.ipa"
    )
    if output_ipa.exists() and not args.force:
        raise IpasignError(f"输出文件已存在: {output_ipa}（加 --force 覆盖）")

    if args.engine == "zsign":
        sign_with_zsign(
            input_ipa,
            output_ipa,
            p12=Path(args.p12) if args.p12 else None,
            password=args.password,
            profile=Path(args.profile) if args.profile else None,
            bundle_id=args.bundle_id,
            entitlements=Path(args.entitlements) if args.entitlements else None,
            ad_hoc=args.adhoc,
            zsign=args.zsign,
            log=log,
        )
        print(f"[完成] 已输出: {output_ipa}")
        return 0

    profile = None
    identity = None
    if not args.adhoc:
        if not args.p12:
            raise IpasignError("需要 -c/--p12 指定签名证书")
        if not args.profile:
            raise IpasignError("需要 -m/--profile 指定描述文件")
        profile = ProvisioningProfile.load(args.profile)
        log(f"描述文件: {profile.name} ({profile.application_identifier})")
        identity = _load_identity(
            args.p12,
            args.password,
            args.chain or [],
            allow_download=not args.no_download,
            log=log,
        )
        log(f"签名证书: {identity.common_name} (team {identity.team_id})")
        if len(identity.certificates) < 2:
            log("提示: 证书链中没有中间证书，iOS 可能拒绝安装")

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

    print(f"[完成] 已输出: {output_ipa}")
    print(f"  Bundle ID : {report.bundle_id}")
    print(f"  Team ID   : {report.team_id or '未知'}")
    print(f"  描述文件  : {report.profile_name or '无（ad-hoc）'}")
    print(f"  已签名    : {len(report.steps)} 个 Mach-O 文件")
    for warning in report.warnings:
        print(f"  [警告] {warning}")
    return 0


def cmd_info(args: argparse.Namespace) -> int:
    input_ipa = Path(args.input)
    if not input_ipa.is_file():
        raise IpasignError(f"找不到 IPA 文件: {input_ipa}")
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

    print(f"校验: {args.input}")
    for check in report.checks:
        status = "OK " if not check.problems else "ERR"
        cms = "CMS" if check.cms_ok else "无CMS"
        print(
            f"  [{status}] {check.path:45} {check.identifier or '-':40} "
            f"{','.join(check.architectures) or '-':10} {cms}"
        )
        for problem in check.problems:
            print(f"        - {problem}")
    problems = report.all_problems()
    if problems:
        print(f"结果: 发现 {len(problems)} 个问题")
        return 1
    print("结果: 签名结构校验通过")
    return 0


def cmd_devices(args: argparse.Namespace) -> int:
    if not device.library_available():
        raise IpasignError(
            "缺少 pymobiledevice3，无法与手机通信。安装：\n"
            "  python -m pip install pymobiledevice3"
        )
    devices = device.list_devices()
    if args.json:
        print(json.dumps([item.__dict__ for item in devices], ensure_ascii=False, indent=2))
        return 0 if devices else 1
    if not devices:
        print("没有检测到设备。请确认：")
        print("  1) 手机用数据线连上电脑；")
        print("  2) 手机解锁，并在弹窗里点「信任」；")
        print("  3) iTunes / Apple Devices 已安装（提供 Apple Mobile Device Service）。")
        return 1
    for item in devices:
        marker = "" if item.paired else "  [未配对]"
        print(f"{item.udid}  {item.label()}  [{item.connection or 'USB'}]{marker}")
        if item.extra.get("pairing_error"):
            print(f"    配对失败: {item.extra['pairing_error'][:160]}")
    return 0


def cmd_install(args: argparse.Namespace) -> int:
    log = _log_factory(False, args.verbose)
    ipa_path = Path(args.ipa)
    if not ipa_path.is_file():
        raise IpasignError(f"找不到 IPA 文件: {ipa_path}")

    if args.verify:
        log("安装前校验签名 ...")
        report = verify_ipa(ipa_path)
        if not report.ok:
            for problem in report.all_problems()[:10]:
                print(f"  [问题] {problem}")
            raise IpasignError("签名校验未通过，已中止安装（加 --no-verify 可跳过）")

    udid = device.install_ipa(
        ipa_path, udid=args.udid, developer=args.developer, log=log
    )
    print(f"[完成] 已安装到设备 {udid}")
    print("如果图标是灰色的，去 设置 → 通用 → VPN与设备管理 里信任对应证书。")
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
    print(f"名称        : {data['name']}")
    print(f"UUID        : {data['uuid']}")
    print(f"Team        : {', '.join(data['team_ids']) or '-'}")
    print(f"App ID      : {data['application_identifier']} ({'通配' if data['wildcard'] else '显式'})")
    print(f"到期时间    : {data['expires'] or '-'} {'[已过期]' if data['expired'] else ''}")
    print(f"设备数量    : {data['device_count']}")
    print(f"平台        : {', '.join(data['platforms'])}")
    print(f"证书数量    : {data['certificate_count']}")
    for subject in data["certificates"]:
        print(f"  - {subject}")
    print("权限        : " + ", ".join(data["entitlements"]))
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
    print(f"证书        : {data['common_name']}")
    print(f"Team        : {data['team_id']}")
    print(f"有效期      : {data['not_before'][:10]} ~ {data['not_after'][:10]}")
    print(f"SHA256      : {data['sha256']}")
    print("证书链      :")
    for item in data["chain"]:
        marker = " (已过期)" if item["expired"] else ""
        print(f"  [{item['index']}] {item['role']:12} {item['subject']}{marker}")
    if len(data["chain"]) < 2:
        print("提示: 缺少中间证书，iOS 会拒绝安装；可运行 `ipasign fetch-certs`")
    return 0


def cmd_fetch_certs(args: argparse.Namespace) -> int:
    from .pki import cert_cache_dir, download_apple_certificates

    files = download_apple_certificates(force=args.force, log=print)
    print(f"已缓存 {len(files)} 个证书到 {cert_cache_dir()}")
    return 0


def cmd_gui(args: argparse.Namespace) -> int:
    from .gui import main as gui_main

    return gui_main()


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ipasign",
        description="iOS IPA 重签名工具（跨平台，纯 Python 签名引擎）",
    )
    parser.add_argument("--version", action="version", version=f"ipasign {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    sign = subparsers.add_parser("sign", help="对 IPA 重新签名")
    sign.add_argument("input", help="输入 IPA 路径")
    sign.add_argument("-o", "--output", help="输出 IPA 路径（默认 <输入>-signed.ipa）")
    sign.add_argument("-c", "--p12", help="签名证书 .p12/.pfx")
    sign.add_argument("-p", "--password", help="p12 密码（不填则交互输入）")
    sign.add_argument("-m", "--profile", help="描述文件 .mobileprovision")
    sign.add_argument("-b", "--bundle-id", help="修改 Bundle ID（默认沿用并将按描述文件校正）")
    sign.add_argument("-e", "--entitlements", help="使用自定义 entitlements plist")
    sign.add_argument("--chain", action="append", help="附加中间证书（可重复）")
    sign.add_argument("--no-download", action="store_true", help="不要自动下载 Apple 中间证书")
    sign.add_argument("--no-rewrite-bundle-id", action="store_true", help="禁止自动改写 Bundle ID")
    sign.add_argument("--adhoc", "--ad-hoc", action="store_true", help="仅做 ad-hoc 签名（越狱设备）")
    sign.add_argument("--engine", choices=["native", "zsign"], default="native", help="签名引擎")
    sign.add_argument("--zsign", help="zsign 可执行文件路径")
    sign.add_argument("--keep-workdir", help="保留解包目录（调试用）")
    sign.add_argument("--force", action="store_true", help="覆盖已存在的输出文件")
    sign.add_argument("--json", action="store_true", help="以 JSON 输出结果")
    sign.add_argument("-q", "--quiet", action="store_true")
    sign.add_argument("-v", "--verbose", action="store_true")
    sign.set_defaults(func=cmd_sign)

    info = subparsers.add_parser("info", help="查看 IPA 基本信息")
    info.add_argument("input")
    info.add_argument("--json", action="store_true")
    info.set_defaults(func=cmd_info)

    verify = subparsers.add_parser("verify", help="校验 IPA 签名结构")
    verify.add_argument("input")
    verify.add_argument("-c", "--p12", help="用于比对的签名证书")
    verify.add_argument("-p", "--password")
    verify.add_argument("-m", "--profile", help="用于比对的描述文件")
    verify.add_argument("--chain", action="append")
    verify.add_argument("--json", action="store_true")
    verify.set_defaults(func=cmd_verify)

    devices = subparsers.add_parser("devices", help="列出已连接的 iPhone / iPad")
    devices.add_argument("--json", action="store_true")
    devices.set_defaults(func=cmd_devices)

    install = subparsers.add_parser("install", help="把已签名的 IPA 安装到设备")
    install.add_argument("ipa")
    install.add_argument("--udid", help="目标设备 UDID（连接多台设备时必填）")
    install.add_argument("--developer", action="store_true", help="作为开发者包安装")
    install.add_argument("--verify", dest="verify", action="store_true", help="安装前校验签名结构")
    install.add_argument("--no-verify", dest="verify", action="store_false", help="跳过安装前校验")
    install.add_argument("-v", "--verbose", action="store_true")
    install.set_defaults(func=cmd_install, verify=False)

    profile = subparsers.add_parser("profile", help="查看描述文件内容")
    profile.add_argument("profile")
    profile.add_argument("--json", action="store_true")
    profile.set_defaults(func=cmd_profile)

    identity = subparsers.add_parser("identity", help="查看签名证书与证书链")
    identity.add_argument("p12")
    identity.add_argument("-p", "--password")
    identity.add_argument("--chain", action="append")
    identity.add_argument("--no-download", action="store_true")
    identity.add_argument("--json", action="store_true")
    identity.set_defaults(func=cmd_identity)

    fetch = subparsers.add_parser("fetch-certs", help="下载并缓存 Apple WWDR 中间证书")
    fetch.add_argument("--force", action="store_true")
    fetch.set_defaults(func=cmd_fetch_certs)

    gui = subparsers.add_parser("gui", help="启动图形界面")
    gui.set_defaults(func=cmd_gui)

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
        print(f"[错误] {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n[中断]", file=sys.stderr)
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
