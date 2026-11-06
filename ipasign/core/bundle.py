"""High-level bundle re-signing.

The entry point :func:`sign_app` walks a ``.app`` bundle, re-signs every
Mach-O file inside it from the leaves up (nested frameworks and extensions
first, then the host app), refreshes ``_CodeSignature/CodeResources`` and
embeds the provisioning profile.
"""

from __future__ import annotations

import os
import plistlib
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from ipasign.core import macho, resources
from ipasign.core.errors import BundleError, IdentityError
from ipasign.core.ipa import IpaContents, extract_ipa, pack_ipa
from ipasign.core.pki import SigningIdentity
from ipasign.core.profile import ProvisioningProfile, entitlements_to_xml

BUNDLE_SUFFIXES = (".app", ".appex", ".framework", ".bundle", ".xpc", ".plugin")
EXTENSION_SUFFIXES = (".appex",)


@dataclass
class SignOptions:
    """User-tunable behaviour of a signing run."""

    bundle_id: Optional[str] = None
    entitlements_file: Optional[str] = None
    ad_hoc: bool = False
    rewrite_bundle_id: bool = True
    embed_profile: bool = True
    sign_nested: bool = True
    verbose: bool = False


@dataclass
class SignStep:
    path: str
    identifier: str
    kind: str
    architectures: List[str] = field(default_factory=list)
    entitlements: List[str] = field(default_factory=list)


@dataclass
class BundleReport:
    app_path: Path
    bundle_id: str
    team_id: str
    profile_name: str = ""
    steps: List[SignStep] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def summary(self) -> str:
        lines = [
            f"bundle id : {self.bundle_id}",
            f"team id   : {self.team_id or 'unknown'}",
            f"profile   : {self.profile_name or 'none'}",
            f"signed    : {len(self.steps)} Mach-O file(s)",
        ]
        for warning in self.warnings:
            lines.append(f"warning   : {warning}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Property list helpers
# ---------------------------------------------------------------------------

def _read_plist(path: Path) -> "tuple[dict, bytes, int]":
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise BundleError(f"cannot read {path}: {exc}") from exc
    fmt = plistlib.FMT_BINARY if raw.startswith(b"bplist00") else plistlib.FMT_XML
    try:
        data = plistlib.loads(raw)
    except Exception as exc:  # noqa: BLE001
        raise BundleError(f"invalid property list at {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise BundleError(f"property list at {path} is not a dictionary")
    return data, raw, fmt


def _write_plist(path: Path, data: dict, fmt: int) -> bytes:
    blob = plistlib.dumps(data, fmt=fmt, sort_keys=False)
    path.write_bytes(blob)
    return blob


def _write_binary(path: Path, data: bytes) -> None:
    mode = None
    try:
        mode = path.stat().st_mode
    except OSError:
        pass
    path.write_bytes(data)
    if mode is not None and os.name != "nt":
        try:
            os.chmod(path, mode)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Bundle inspection
# ---------------------------------------------------------------------------

def resolve_executable(root: Path, info: Dict) -> Path:
    """Locate the main executable referenced by ``CFBundleExecutable``."""
    name = info.get("CFBundleExecutable")
    candidates: List[Path] = []
    if name:
        candidates.append(root / str(name))
        candidates.append(root / "Versions" / "Current" / str(name))
    # Framework style layout: Versions/<letter>/<name>
    versions = root / "Versions"
    if versions.is_dir():
        for child in sorted(versions.iterdir()):
            if child.is_dir() and name:
                candidates.append(child / str(name))
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    if name:
        raise BundleError(f"executable {name!r} not found in {root}")
    raise BundleError(f"bundle has no CFBundleExecutable: {root}")


def _nested_bundles(root: Path) -> List[Path]:
    """All bundles nested inside *root*, deepest first."""
    found: List[Path] = []
    root = Path(root)
    for folder, dirs, _files in os.walk(root, followlinks=False):
        folder_path = Path(folder)
        if folder_path == root:
            continue
        for name in list(dirs):
            candidate = folder_path / name
            if candidate.suffix.lower() in BUNDLE_SUFFIXES and (candidate / "Info.plist").is_file():
                found.append(candidate)
    found.sort(key=lambda path: len(path.parts), reverse=True)
    return found


def nested_bundles(root: "str | Path") -> List[Path]:
    """Public wrapper around the nested-bundle discovery (deepest first)."""
    return _nested_bundles(Path(root))


def _is_nested_path(path: Path, nested: Sequence[Path]) -> bool:
    for bundle in nested:
        try:
            path.relative_to(bundle)
            return True
        except ValueError:
            continue
    return False


def _loose_binaries(root: Path, nested: Sequence[Path], executable: Path) -> List[Path]:
    """Mach-O files that are not the bundle executable and not inside a bundle."""
    out: List[Path] = []
    exe_resolved = executable.resolve()
    for folder, dirs, files in os.walk(root, followlinks=False):
        folder_path = Path(folder)
        dirs[:] = [
            name for name in dirs
            if name != resources.CODE_SIGNATURE_DIR
            and not _is_nested_path(folder_path / name, nested)
        ]
        for name in files:
            path = folder_path / name
            if path.is_symlink() or path.resolve() == exe_resolved:
                continue
            try:
                with path.open("rb") as handle:
                    magic = handle.read(4)
            except OSError:
                continue
            if macho.is_macho(magic):
                out.append(path)
    out.sort()
    return out


def _clean_signature_dir(root: Path) -> None:
    target = root / resources.CODE_SIGNATURE_DIR
    if target.is_dir():
        shutil.rmtree(target, ignore_errors=True)


# ---------------------------------------------------------------------------
# Bundle id rewriting
# ---------------------------------------------------------------------------

def _rewrite_identifier(bundle_id: str, old: str, new: str) -> str:
    if bundle_id == old:
        return new
    if bundle_id.startswith(old + "."):
        return new + bundle_id[len(old):]
    return bundle_id


def _apply_bundle_id(app_path: Path, old: str, new: str, warnings: List[str]) -> None:
    """Rewrite the app identifier, and any plugin identifiers under it."""
    for folder, _dirs, files in os.walk(app_path):
        if "Info.plist" not in files:
            continue
        plist_path = Path(folder) / "Info.plist"
        if plist_path == app_path / "Info.plist":
            continue
        try:
            info, _raw, fmt = _read_plist(plist_path)
        except BundleError:
            continue
        current = info.get("CFBundleIdentifier")
        if not isinstance(current, str):
            continue
        updated = _rewrite_identifier(current, old, new)
        if updated != current:
            info["CFBundleIdentifier"] = updated
            _write_plist(plist_path, info, fmt)
            if updated != current:
                warnings.append(f"rewrote nested bundle id {current} -> {updated}")


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------

def _entitlements_for(
    profile: Optional[ProvisioningProfile],
    identity: SigningIdentity,
    bundle_id: str,
    options: SignOptions,
    warnings: List[str],
) -> Optional[Dict]:
    if profile is None:
        return None
    if options.entitlements_file:
        data, _raw, _fmt = _read_plist(Path(options.entitlements_file))
        data.setdefault("application-identifier", f"{identity.team_id}.{bundle_id}")
        data.setdefault("com.apple.developer.team-identifier", identity.team_id)
        return data
    return profile.entitlements_for(bundle_id, team_id=identity.team_id or None)


def _sign_binary(
    path: Path,
    *,
    identifier: str,
    identity: Optional[SigningIdentity],
    entitlements: Optional[Dict],
    info_plist: Optional[bytes],
    resource_dir: Optional[bytes],
    options: SignOptions,
) -> List[str]:
    data = path.read_bytes()
    if not macho.is_macho(data):
        raise BundleError(f"not a Mach-O file: {path}")
    params = macho.SignParameters(
        identifier=identifier,
        key=identity.key if identity else None,
        certificates=list(identity.certificates) if identity else [],
        team_id=identity.team_id if identity else "",
        entitlements=entitlements_to_xml(entitlements) if entitlements is not None else None,
        info_plist=info_plist,
        resource_dir=resource_dir,
        ad_hoc=options.ad_hoc or identity is None,
    )
    signed = macho.sign_macho(data, params)
    _write_binary(path, signed)
    return [macho.cpu_name(slice_.cputype) for slice_ in macho.split_slices(signed).slices]


def _sign_bundle_contents(
    root: Path,
    *,
    identity: Optional[SigningIdentity],
    profile: Optional[ProvisioningProfile],
    entitlements: Optional[Dict],
    options: SignOptions,
    report: BundleReport,
    embed_profile: bool,
    kind: str,
) -> None:
    info_path = root / "Info.plist"
    info, info_raw, _fmt = _read_plist(info_path)
    identifier = str(info.get("CFBundleIdentifier") or root.stem)
    executable = resolve_executable(root, info)

    _clean_signature_dir(root)
    if embed_profile and profile is not None and options.embed_profile:
        (root / "embedded.mobileprovision").write_bytes(profile.raw)

    # Seal nested bundles' files as well: iOS's installer validates the whole
    # resource envelope, and omitting nested code makes it report an invalid
    # signature (0xe8008019).  zsign does the same.
    code_resources, _entries = resources.build_code_resources(
        root, executable=executable
    )
    signature_dir = root / resources.CODE_SIGNATURE_DIR
    signature_dir.mkdir(parents=True, exist_ok=True)
    (signature_dir / resources.CODE_RESOURCES_NAME).write_bytes(code_resources)

    architectures = _sign_binary(
        executable,
        identifier=identifier,
        identity=identity,
        entitlements=entitlements,
        info_plist=info_raw,
        resource_dir=code_resources,
        options=options,
    )
    report.steps.append(
        SignStep(
            path=str(root),
            identifier=identifier,
            kind=kind,
            architectures=architectures,
            entitlements=sorted(entitlements) if entitlements else [],
        )
    )


def sign_app(
    app_path: "str | Path",
    identity: Optional[SigningIdentity],
    profile: Optional[ProvisioningProfile] = None,
    options: Optional[SignOptions] = None,
    *,
    log=lambda message: None,
) -> BundleReport:
    """Re-sign every Mach-O file inside *app_path*."""
    app_path = Path(app_path)
    options = options or SignOptions()
    if not (app_path / "Info.plist").is_file():
        raise BundleError(f"not an app bundle (no Info.plist): {app_path}")

    info, _raw, fmt = _read_plist(app_path / "Info.plist")
    original_id = str(info.get("CFBundleIdentifier") or "")
    if not original_id:
        raise BundleError("Info.plist has no CFBundleIdentifier")

    main_executable = resolve_executable(app_path, info)
    if macho.is_encrypted(main_executable.read_bytes()):
        raise BundleError(
            "主程序仍处于加密状态（App Store 下载的 IPA 带 FairPlay DRM），"
            "重签后无法运行；请改用已解密的 IPA"
        )

    team_id = identity.team_id if identity else (profile.app_id_prefix if profile else "")
    report = BundleReport(
        app_path=app_path,
        bundle_id=original_id,
        team_id=team_id,
        profile_name=profile.name if profile else "",
    )

    target_id = options.bundle_id or original_id
    if profile is not None and not profile.supports_bundle_id(target_id):
        suggestion = profile.suggested_bundle_id()
        if options.bundle_id:
            raise BundleError(
                f"profile {profile.name!r} does not authorise bundle id {options.bundle_id!r} "
                f"(it authorises {profile.application_identifier!r})"
            )
        if suggestion and options.rewrite_bundle_id:
            report.warnings.append(
                f"profile authorises {suggestion!r}; rewriting bundle id {target_id!r} -> {suggestion!r}"
            )
            target_id = suggestion
        else:
            raise BundleError(
                f"profile {profile.name!r} authorises {profile.application_identifier!r}, "
                f"which cannot cover {target_id!r}"
            )

    if identity is not None and profile is not None:
        if identity.team_id and not profile.team_matches(identity.team_id):
            raise BundleError(
                f"certificate team {identity.team_id!r} does not match profile team "
                f"{profile.team_id!r}"
            )
        if not profile.has_certificate(identity.leaf):
            report.warnings.append(
                "the signing certificate is not listed in the profile; "
                "iOS will reject the install unless the profile is regenerated"
            )

    report.bundle_id = target_id
    if target_id != original_id:
        info["CFBundleIdentifier"] = target_id
        _write_plist(app_path / "Info.plist", info, fmt)
        _apply_bundle_id(app_path, original_id, target_id, report.warnings)
        log(f"bundle id: {original_id} -> {target_id}")

    if profile is not None and profile.is_expired():
        report.warnings.append(
            f"provisioning profile expired on {profile.expiration:%Y-%m-%d}"
        )

    # Re-read after possible rewrite so the embedded Info.plist slot matches.
    info, _raw, _fmt = _read_plist(app_path / "Info.plist")

    if options.sign_nested:
        for bundle in _nested_bundles(app_path):
            nested_info, _n_raw, _n_fmt = _read_plist(bundle / "Info.plist")
            nested_id = str(nested_info.get("CFBundleIdentifier") or bundle.stem)
            kind = bundle.suffix.lower()
            entitlements = {}  # zsign emits an empty entitlements blob for frameworks
            embed_nested = False
            if kind in (".appex", ".app"):
                stale = bundle / "embedded.mobileprovision"
                if profile is not None:
                    if profile.supports_bundle_id(nested_id):
                        entitlements = _entitlements_for(
                            profile, identity, nested_id, options, report.warnings
                        )
                        embed_nested = True
                    else:
                        report.warnings.append(
                            f"{nested_id}: 描述文件不覆盖该 Bundle ID，扩展可能无法启动；"
                            "建议使用通配 App ID 的描述文件，或为该扩展单独准备描述文件"
                        )
                if stale.is_file() and not embed_nested:
                    stale.unlink()
                    report.warnings.append(
                        f"{nested_id}: 已移除与新描述文件不匹配的旧 embedded.mobileprovision"
                    )
            _sign_bundle_contents(
                bundle,
                identity=identity,
                profile=profile,
                entitlements=entitlements,
                options=options,
                report=report,
                embed_profile=embed_nested,
                kind=kind.lstrip("."),
            )
            log(f"signed {kind.lstrip('.')}: {nested_id}")

        executable = resolve_executable(app_path, info)
        for binary in _loose_binaries(app_path, _nested_bundles(app_path), executable):
            rel = binary.relative_to(app_path).as_posix()
            # codesign uses the basename of LC_ID_DYLIB; a path with slashes is
            # rejected by iOS (0xe8008019).
            try:
                install_name = macho.dylib_identifier(binary.read_bytes()) or rel
            except OSError:
                install_name = rel
            identifier = install_name.rsplit("/", 1)[-1]
            architectures = _sign_binary(
                binary,
                identifier=identifier,
                identity=identity,
                entitlements={},
                info_plist=None,
                resource_dir=None,
                options=options,
            )
            report.steps.append(
                SignStep(path=str(binary), identifier=identifier, kind="dylib",
                         architectures=architectures)
            )

    main_entitlements = _entitlements_for(profile, identity, target_id, options, report.warnings)
    _sign_bundle_contents(
        app_path,
        identity=identity,
        profile=profile,
        entitlements=main_entitlements,
        options=options,
        report=report,
        embed_profile=True,
        kind="app",
    )
    log(f"signed app: {target_id}")
    return report


# ---------------------------------------------------------------------------
# IPA level
# ---------------------------------------------------------------------------

def sign_ipa(
    input_ipa: "str | Path",
    output_ipa: "str | Path",
    *,
    identity: Optional[SigningIdentity],
    profile: Optional[ProvisioningProfile] = None,
    options: Optional[SignOptions] = None,
    log=lambda message: None,
    keep_workdir: Optional["str | Path"] = None,
) -> BundleReport:
    """Extract, re-sign and repack an IPA."""
    options = options or SignOptions()
    input_ipa = Path(input_ipa)
    output_ipa = Path(output_ipa)
    if input_ipa.resolve() == output_ipa.resolve():
        raise BundleError("input and output IPA must be different files")

    if keep_workdir:
        workdir = Path(keep_workdir)
    else:
        # Unpack next to the output file: a large IPA explodes to several GB
        # and the user's system drive is often the smallest one.  Fall back to
        # the system temp directory when that location is not writable.
        try:
            workdir = Path(
                tempfile.mkdtemp(prefix=".ipasign-work-", dir=str(Path(output_ipa).parent))
            )
        except OSError:
            workdir = Path(tempfile.mkdtemp(prefix="ipasign-"))
    try:
        log(f"unpacking {input_ipa.name} ...")
        contents = extract_ipa(input_ipa, workdir)
        apps = contents.app_bundles
        if len(apps) > 1:
            log(f"warning: {len(apps)} app bundles found; signing {apps[0].name}")
        report = sign_app(
            contents.app_path, identity, profile, options, log=log
        )
        log(f"packing {output_ipa.name} ...")
        pack_ipa(contents, output_ipa)
        return report
    finally:
        if keep_workdir is None:
            shutil.rmtree(workdir, ignore_errors=True)
