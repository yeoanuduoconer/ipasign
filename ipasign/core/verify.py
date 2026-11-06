"""Signature verification for IPA files and app bundles.

Verification is structural: every Mach-O file must carry a signature, the
CodeDirectory page hashes must match the file, the CMS envelope must verify
against its CodeDirectory and the identifiers must agree with ``Info.plist``.
"""

from __future__ import annotations

import plistlib
import shutil
import tempfile

from ipasign import paths
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from cryptography import x509

from ipasign.core import macho
from ipasign.core.cms import verify_detached_cms
from ipasign.core.errors import IpasignError, SignatureError
from ipasign.core.ipa import extract_ipa
from ipasign.core.pki import SigningIdentity
from ipasign.core.profile import ProvisioningProfile


@dataclass
class SignatureCheck:
    path: str
    identifier: str
    team_id: str
    architectures: List[str] = field(default_factory=list)
    signed: bool = False
    cms_ok: bool = False
    signer: str = ""
    entitlements: Optional[Dict] = None
    problems: List[str] = field(default_factory=list)


@dataclass
class VerificationReport:
    source: Path
    bundle_id: str = ""
    checks: List[SignatureCheck] = field(default_factory=list)
    problems: List[str] = field(default_factory=list)
    profile: Optional[Dict] = None
    ad_hoc: bool = False

    @property
    def ok(self) -> bool:
        return not self.problems and all(not check.problems for check in self.checks)

    def all_problems(self) -> List[str]:
        out = list(self.problems)
        for check in self.checks:
            out.extend(f"{check.path}: {problem}" for problem in check.problems)
        return out


def _walk_macho(root: Path):
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        try:
            with path.open("rb") as handle:
                magic = handle.read(4)
        except OSError:
            continue
        if macho.is_macho(magic):
            yield path


def verify_bundle(
    app_path: Path,
    *,
    identity: Optional[SigningIdentity] = None,
    profile: Optional[ProvisioningProfile] = None,
) -> VerificationReport:
    report = VerificationReport(source=app_path)
    info_path = app_path / "Info.plist"
    if not info_path.is_file():
        report.problems.append("missing Info.plist")
        return report
    info = plistlib.loads(info_path.read_bytes())
    report.bundle_id = str(info.get("CFBundleIdentifier", ""))

    for path in _walk_macho(app_path):
        rel = path.relative_to(app_path).as_posix()
        check = SignatureCheck(path=rel, identifier="", team_id="")
        data = path.read_bytes()
        try:
            signatures = macho.read_signatures(data)
        except SignatureError as exc:
            check.problems.append(f"cannot parse the signature: {exc}")
            report.checks.append(check)
            continue
        if not signatures:
            check.problems.append("unsigned")
            report.checks.append(check)
            continue
        check.signed = True
        for index, signature in enumerate(signatures):
            cd = signature.code_directory
            check.architectures.append(macho.cpu_name(signature.cputype))
            if index == 0:
                check.identifier = cd.identifier
                check.team_id = cd.team_id
            prefix = f"[{macho.cpu_name(signature.cputype)}] " if len(signatures) > 1 else ""
            check.problems.extend(prefix + problem for problem in macho.verify_slice_hashes(data, signature))
            if signature.cms_blob:
                try:
                    verified = verify_detached_cms(signature.cms_blob, cd.raw)
                    check.cms_ok = True
                    if not check.signer:
                        check.signer = verified.certificate.subject.rfc4514_string()
                except Exception as exc:  # noqa: BLE001
                    check.problems.append(f"CMS verification failed: {exc}")
            else:
                check.problems.append("missing CMS signature (ad-hoc)")
            if signature.entitlements:
                try:
                    check.entitlements = plistlib.loads(signature.entitlements)
                except Exception:  # noqa: BLE001
                    pass
        report.checks.append(check)

    # Identifier consistency with Info.plist.
    main_check = next(
        (check for check in report.checks if check.path == str(info.get("CFBundleExecutable"))),
        None,
    )
    if main_check and main_check.identifier:
        if main_check.identifier != report.bundle_id:
            report.problems.append(
                f"main executable signing identifier {main_check.identifier!r} does not "
                f"match Bundle ID {report.bundle_id!r}"
            )
    elif main_check is not None:
        report.problems.append("the main executable has no readable signing identifier")

    entitlements = main_check.entitlements if main_check else None
    if entitlements:
        appid = entitlements.get("application-identifier")
        if not appid:
            report.problems.append(
                "the main executable lacks the application-identifier entitlement"
            )
        elif profile is not None and not str(appid).endswith("." + report.bundle_id):
            report.problems.append(
                f"application-identifier {appid!r} does not match Bundle ID "
                f"{report.bundle_id!r}"
            )

    embedded = app_path / "embedded.mobileprovision"
    if profile is None and embedded.is_file():
        try:
            profile = ProvisioningProfile.parse(embedded.read_bytes())
        except Exception as exc:  # noqa: BLE001
            report.problems.append(f"embedded profile is corrupt: {exc}")
    if profile is not None:
        report.profile = profile.describe()
        if profile.is_expired():
            report.problems.append("the provisioning profile has expired")
        if not profile.supports_bundle_id(report.bundle_id):
            report.problems.append(
                f"the profile does not cover Bundle ID {report.bundle_id!r} "
                f"({profile.application_identifier})"
            )
        if entitlements:
            granted = profile.entitlements
            requested = set(entitlements.keys())
            missing = sorted(
                key for key in requested
                if key not in granted and key not in ("application-identifier",
                                                      "com.apple.developer.team-identifier")
            )
            if missing:
                report.problems.append("entitlements not granted by the profile: " + ", ".join(missing))
        if identity is not None and not profile.has_certificate(identity.leaf):
            report.problems.append(
                "the signing certificate is not in the profile's certificate list"
            )

    if not any(check.signed for check in report.checks):
        report.problems.append("no signed Mach-O files")
    return report


def verify_ipa(
    ipa_path: "str | Path",
    *,
    identity: Optional[SigningIdentity] = None,
    profile: Optional[ProvisioningProfile] = None,
) -> VerificationReport:
    ipa_path = Path(ipa_path)
    workdir = Path(tempfile.mkdtemp(prefix="ipasign-verify-", dir=str(paths.temp_dir())))
    try:
        contents = extract_ipa(ipa_path, workdir)
        report = verify_bundle(contents.app_path, identity=identity, profile=profile)
        report.source = ipa_path
        return report
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
