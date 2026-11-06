"""Local identity vault: store a certificate + provisioning profile pair.

A re-signing workflow usually has one long-lived identity (a company cert, a
paid developer account, a friend's export) and many IPAs.  Keeping the
``.p12`` and ``.mobileprovision`` in a known place under ``~/.ipasign`` makes
``ipasign renew`` and ``ipasign doctor`` one-liners instead of long command
lines with passwords.

Passwords are never written to disk by this module.
"""

from __future__ import annotations

from ipasign import paths

import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from ipasign.core.errors import IpasignError


def vault_root() -> Path:
    root = paths.data_dir() / "identities"
    root.mkdir(parents=True, exist_ok=True)
    return root


@dataclass
class StoredIdentity:
    name: str
    directory: Path
    p12_path: Path
    profile_path: Optional[Path] = None
    meta: dict = field(default_factory=dict)

    @property
    def exists(self) -> bool:
        return self.p12_path.is_file()

    def summary(self) -> str:
        bits = [self.name]
        if self.meta.get("team_id"):
            bits.append(f"team {self.meta['team_id']}")
        if self.meta.get("profile_app_id"):
            bits.append(str(self.meta["profile_app_id"]))
        if self.meta.get("profile_expires"):
            bits.append(f"到期 {str(self.meta['profile_expires'])[:10]}")
        return "  ".join(bits)


def _safe_name(name: str) -> str:
    name = name.strip()
    if not name or name in (".", "..") or any(ch in name for ch in '/\\:*?"<>|'):
        raise IpasignError("证书库名字不能为空，也不能包含路径分隔符")
    cleaned = "".join(ch for ch in name if ch.isalnum() or ch in "-_.")
    if cleaned != name:
        raise IpasignError("证书库名字只能包含字母、数字、中文、- _ .")
    return cleaned


def save(
    name: str,
    p12_path: "str | Path",
    profile_path: Optional["str | Path"] = None,
    password: Optional[str] = None,
    overwrite: bool = False,
    store_password: bool = False,
) -> StoredIdentity:
    """Copy an identity into the vault and record its metadata."""
    from ipasign.core.pki import load_identity
    from ipasign.core.profile import ProvisioningProfile

    safe = _safe_name(name)
    directory = vault_root() / safe
    if directory.exists() and not overwrite:
        raise IpasignError(f"证书库里已经有 {safe!r} 了（加 --force 覆盖）")
    directory.mkdir(parents=True, exist_ok=True)

    p12_source = Path(p12_path)
    if not p12_source.is_file():
        raise IpasignError(f"找不到 p12: {p12_source}")
    identity = load_identity(p12_source, password)
    target_p12 = directory / "identity.p12"
    shutil.copyfile(p12_source, target_p12)

    meta = {
        "name": safe,
        # Only identities created by the certificate factory keep their
        # (randomly generated) container password here; imported p12 files do
        # not, because that password belongs to the user.
        **({"p12_password": password} if store_password and password else {}),
        "team_id": identity.team_id,
        "common_name": identity.common_name,
        "serial": hex(identity.leaf.serial_number),
        "leaf_expires": identity.leaf.not_valid_after_utc.isoformat(),
        "chain_length": len(identity.certificates),
    }

    target_profile = None
    if profile_path:
        profile_source = Path(profile_path)
        if not profile_source.is_file():
            raise IpasignError(f"找不到描述文件: {profile_source}")
        profile = ProvisioningProfile.load(profile_source)
        target_profile = directory / "profile.mobileprovision"
        shutil.copyfile(profile_source, target_profile)
        meta.update(
            {
                "profile_name": profile.name,
                "profile_uuid": profile.uuid,
                "profile_app_id": profile.application_identifier,
                "profile_expires": profile.expiration.isoformat() if profile.expiration else None,
            }
        )

    (directory / "meta.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return StoredIdentity(safe, directory, target_p12, target_profile, meta)


def load(name: str) -> StoredIdentity:
    safe = _safe_name(name)
    directory = vault_root() / safe
    if not directory.is_dir():
        raise IpasignError(f"证书库里没有 {safe!r}（ipasign vault list 查看已有的）")
    p12_path = directory / "identity.p12"
    if not p12_path.is_file():
        raise IpasignError(f"证书 {safe!r} 的 p12 文件丢失了: {p12_path}")
    profile_path = directory / "profile.mobileprovision"
    meta_file = directory / "meta.json"
    meta = {}
    if meta_file.is_file():
        try:
            meta = json.loads(meta_file.read_text(encoding="utf-8"))
        except ValueError:
            meta = {}
    return StoredIdentity(
        name=safe,
        directory=directory,
        p12_path=p12_path,
        profile_path=profile_path if profile_path.is_file() else None,
        meta=meta,
    )


def list_all() -> List[StoredIdentity]:
    root = vault_root()
    items: List[StoredIdentity] = []
    for directory in sorted(root.iterdir()):
        if not directory.is_dir():
            continue
        try:
            items.append(load(directory.name))
        except IpasignError:
            continue
    return items


def remove(name: str) -> None:
    safe = _safe_name(name)
    directory = vault_root() / safe
    if not directory.is_dir():
        raise IpasignError(f"证书库里没有 {safe!r}")
    shutil.rmtree(directory)


def password_of(entry: StoredIdentity) -> Optional[str]:
    """Container password recorded for factory-issued identities."""
    return entry.meta.get("p12_password")
