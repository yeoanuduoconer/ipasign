"""Issue a fresh development identity (certificate + provisioning profile).

This is the "certificate factory": everything is produced locally except the
two Apple signatures (the certificate and the profile), which the developer
portal hands back through :class:`ipasign.developer.DeveloperClient`.
"""

from __future__ import annotations

import base64
import tempfile
from pathlib import Path
from typing import Dict, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    pkcs12,
)
from cryptography.x509.oid import NameOID

from . import apple_auth_bridge, vault
from .developer import DeveloperClient
from .pki import SigningIdentity, ensure_chain, load_identity


def _find_cert_content(payload):
    """Apple nests the issued certificate a couple of levels deep."""
    if isinstance(payload, dict):
        for key in ("certContent", "certificateContent"):
            value = payload.get(key)
            if isinstance(value, str) and len(value) > 200:
                return value
        for value in payload.values():
            found = _find_cert_content(value)
            if found:
                return found
    elif isinstance(payload, (list, tuple)):
        for item in payload:
            found = _find_cert_content(item)
            if found:
                return found
    return None


def _generate_csr(key: rsa.RSAPrivateKey) -> bytes:
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "iPhone Developer"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ipasign"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        ]
    )
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.DER)
    )


def issue(
    *,
    bundle_id: str,
    app_name: str,
    device_udid: Optional[str] = None,
    device_name: str = "ipasign",
    vault_name: Optional[str] = None,
    reuse: Optional[str] = None,
    password: str = "ipasign",
    log=print,
) -> Dict:
    """Create a certificate + profile for ``bundle_id`` and store them."""
    device = apple_auth_bridge.open_device()
    if device.session is None:
        raise RuntimeError("尚未登录，请先运行: ipasign login --account <Apple ID>")
    headers = apple_auth_bridge.developer_headers(device, device.session)
    client = DeveloperClient(headers)

    teams = client.list_teams()
    if not teams:
        raise RuntimeError("该 Apple ID 没有开发者团队")
    team = teams[0]
    team_id = team["teamId"]
    log(f"[..] 团队: {team.get('name')} ({team_id})")

    if device_udid:
        known = {d.get("deviceNumber") for d in client.list_devices(team_id)}
        if device_udid not in known:
            log(f"[..] 注册设备 {device_udid}")
            client.add_device(team_id, device_udid, device_name)
        else:
            log(f"[..] 设备已注册: {device_udid}")

    key_stash = Path.home() / ".ipasign" / "pending-key.pem"
    if reuse:
        # Free accounts may hold only one development certificate, so a new
        # bundle id reuses the existing key/certificate and only fetches a
        # fresh profile.
        stored = vault.load(reuse)
        reused = load_identity(stored.p12_path, password)
        key, leaf = reused.key, reused.leaf
        log(f"[..] 复用证书: {leaf.subject.rfc4514_string()}")
    else:
        before = {c["certificateId"] for c in client.list_certificates(team_id)}
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if not reuse:
        # Persist immediately: a crash after Apple signs the CSR would otherwise
        # leave an unusable certificate (private key lost) and burn the slot.
        key_stash.parent.mkdir(parents=True, exist_ok=True)
        key_stash.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        csr = _generate_csr(key)
        log("[..] 提交 CSR，申请开发证书")
        client.submit_csr(team_id, csr)
        fresh = [
            c for c in client.list_certificates(team_id)
            if c.get("certificateId") not in before
        ]
        if not fresh:
            raise RuntimeError("Apple 没有返回新证书")
        cert_info = fresh[0]
        content = cert_info.get("certContent") or _find_cert_content(cert_info)
        if not content:
            raise RuntimeError("证书列表里没有 certContent")
        leaf = x509.load_der_x509_certificate(
            content if isinstance(content, (bytes, bytearray)) else base64.b64decode(content)
        )
        log(f"[..] 证书签发成功: {leaf.subject.rfc4514_string()}")

    identity = ensure_chain(
        SigningIdentity(key=key, certificates=[leaf]), allow_download=True, log=log
    )

    log(f"[..] 注册 App ID {bundle_id}")
    app_id = client.add_app_id(team_id, bundle_id, app_name)
    log(f"[..] App ID: {app_id['appIdId']}")

    log("[..] 下载描述文件")
    profile_bytes = client.download_profile(team_id, app_id["appIdId"])

    name = vault_name or f"{team_id}-{app_id['appIdId']}".lower()
    p12 = pkcs12.serialize_key_and_certificates(
        b"ipasign",
        key,
        identity.certificates[0],
        cas=identity.certificates[1:] or None,
        encryption_algorithm=BestAvailableEncryption(password.encode()),
    )

    with tempfile.TemporaryDirectory() as tmp:
        p12_path = Path(tmp) / "identity.p12"
        profile_path = Path(tmp) / "profile.mobileprovision"
        p12_path.write_bytes(p12)
        profile_path.write_bytes(profile_bytes)
        entry = vault.save(
            name=name,
            p12_path=p12_path,
            profile_path=profile_path,
            password=password,
            overwrite=True,
        )

    key_stash.unlink(missing_ok=True)
    log(f"[完成] 已存入证书库: {name}")
    return {
        "name": name,
        "team_id": team_id,
        "certificate_id": None if reuse else cert_info.get("certificateId"),
        "app_id_id": app_id["appIdId"],
        "bundle_id": bundle_id,
        "profile_size": len(profile_bytes),
        "profile_app_id": entry.meta.get("profile_app_id"),
    }
