"""Pre-flight checks: will this identity + profile + device accept this IPA?

Everything here is local knowledge (no Apple server involved): certificate
expiry, chain completeness, profile coverage, team consistency and device
registration.  Catching these before an install saves a lot of 0xE800xxxx
guessing on the device.
"""

from __future__ import annotations

import datetime as dt
import plistlib
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from ipasign.core.errors import IpasignError
from ipasign.core.pki import SigningIdentity
from ipasign.core.profile import ProvisioningProfile


@dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""

    def line(self) -> str:
        mark = "OK  " if self.ok else "FAIL"
        return f"[{mark}] {self.name}" + (f": {self.detail}" if self.detail else "")


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def ipa_bundle_id(ipa_path: "str | Path") -> str:
    path = Path(ipa_path)
    if not path.is_file():
        raise IpasignError(f"找不到 IPA: {path}")
    try:
        with zipfile.ZipFile(path) as archive:
            for name in archive.namelist():
                if (
                    name.startswith("Payload/")
                    and name.count("/") == 2
                    and name.endswith("/Info.plist")
                ):
                    info = plistlib.loads(archive.read(name))
                    return str(info.get("CFBundleIdentifier") or "")
    except zipfile.BadZipFile as exc:
        raise IpasignError(f"不是合法的 IPA: {exc}") from exc
    raise IpasignError("IPA 里找不到 Payload/*.app/Info.plist")


def run_checks(
    *,
    ipa_path: Optional["str | Path"] = None,
    identity: Optional[SigningIdentity] = None,
    profile: Optional[ProvisioningProfile] = None,
    devices: Optional[list] = None,
    allow_expired_profile: bool = False,
) -> List[Check]:
    checks: List[Check] = []
    now = _utcnow()

    bundle_id = None
    if ipa_path is not None:
        bundle_id = ipa_bundle_id(ipa_path)
        checks.append(Check("IPA Bundle ID", bool(bundle_id), bundle_id or "读取失败"))

    if identity is not None:
        leaf = identity.leaf
        expired = leaf.not_valid_after_utc <= now
        checks.append(
            Check(
                "证书有效期",
                not expired,
                f"{leaf.not_valid_after_utc:%Y-%m-%d} 到期"
                + ("（已过期）" if expired else ""),
            )
        )
        has_issuer = len(identity.certificates) > 1
        self_signed = leaf.issuer == leaf.subject
        if self_signed:
            checks.append(
                Check(
                    "证书链",
                    False,
                    "自签名证书，iOS 不会信任（只能用于越狱设备或本地测试）",
                )
            )
        else:
            checks.append(
                Check(
                    "证书链",
                    has_issuer,
                    "含中间证书"
                    if has_issuer
                    else "缺少 WWDR 中间证书，iOS 会拒绝安装（ipasign fetch-certs）",
                )
            )

    if profile is not None:
        expired = profile.is_expired()
        checks.append(
            Check(
                "描述文件有效期",
                (not expired) or allow_expired_profile,
                (profile.expiration.strftime("%Y-%m-%d") if profile.expiration else "无到期时间")
                + ("（已过期）" if expired else ""),
            )
        )
        if bundle_id:
            covered = profile.supports_bundle_id(bundle_id)
            checks.append(
                Check(
                    "描述文件覆盖 Bundle ID",
                    covered,
                    f"{bundle_id} vs {profile.application_identifier}",
                )
            )
        if identity is not None:
            checks.append(
                Check(
                    "证书在描述文件名单内",
                    profile.has_certificate(identity.leaf),
                    "证书不在 DeveloperCertificates 里，iOS 会拒绝安装"
                    if not profile.has_certificate(identity.leaf)
                    else "",
                )
            )
            team_ok = profile.team_matches(identity.team_id) if identity.team_id else True
            checks.append(
                Check(
                    "团队一致",
                    team_ok,
                    f"证书 {identity.team_id} vs 描述文件 {profile.team_id}",
                )
            )
        devices_in_profile = profile.devices
        if devices and devices_in_profile:
            for device in devices:
                udid = getattr(device, "udid", "")
                checks.append(
                    Check(
                        f"设备 {udid} 已注册",
                        udid in devices_in_profile,
                        f"描述文件里有 {len(devices_in_profile)} 台设备",
                    )
                )

    return checks


def ipa_bundle_info(ipa_path: "str | Path") -> dict:
    """Return ``{bundle_id, name, version}`` read from the IPA's Info.plist."""
    path = Path(ipa_path)
    if not path.is_file():
        raise IpasignError(f"找不到 IPA: {path}")
    try:
        with zipfile.ZipFile(path) as archive:
            for name in archive.namelist():
                if (
                    name.startswith("Payload/")
                    and name.count("/") == 2
                    and name.endswith("/Info.plist")
                ):
                    info = plistlib.loads(archive.read(name))
                    return {
                        "bundle_id": str(info.get("CFBundleIdentifier") or ""),
                        "name": str(
                            info.get("CFBundleDisplayName")
                            or info.get("CFBundleName")
                            or ""
                        ),
                        "version": str(info.get("CFBundleShortVersionString") or ""),
                    }
    except zipfile.BadZipFile as exc:
        raise IpasignError(f"不是合法的 IPA: {exc}") from exc
    raise IpasignError("IPA 里找不到 Payload/*.app/Info.plist")


def all_ok(checks: List[Check]) -> bool:
    return all(check.ok for check in checks)
