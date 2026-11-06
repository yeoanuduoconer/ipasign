"""Issue a fresh development identity (certificate + provisioning profile).

This is the "certificate factory": everything is produced locally except the
two Apple signatures (the certificate and the profile), which the developer
portal hands back through :class:`ipasign.apple.developer.DeveloperClient`.

Free Apple IDs are limited to **one** development certificate and a small
number of new App IDs per week, so this module deliberately reuses whatever it
can:

* an existing App ID with the same identifier (instead of creating a duplicate)
* an existing certificate from the local vault (``--reuse``, or automatically
  when Apple answers ``7460 Maximum number of certificates generated``)
"""

from __future__ import annotations

from ipasign import paths

import base64
import secrets
import tempfile
from pathlib import Path
from typing import Dict, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    pkcs12,
)
from cryptography.x509.oid import NameOID

from ipasign.apple import auth as apple_auth_bridge
from ipasign.apple.developer import DeveloperClient, DeveloperError
from ipasign.core import vault
from ipasign.core.pki import SigningIdentity, ensure_chain, load_identity

CERT_LIMIT_CODE = 7460  # "Maximum number of certificates generated"


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


def _vault_identity_for_team(team_id: str, password: str):
    """Latest vault entry that belongs to *team_id* (used when the slot is full)."""
    best = None
    for entry in vault.list_all():
        if entry.meta.get("team_id") != team_id or not entry.p12_path.is_file():
            continue
        stamp = entry.meta.get("leaf_expires") or ""
        if best is None or stamp > best[0]:
            best = (stamp, entry)
    if best is None:
        return None, None
    entry = best[1]
    return entry, load_identity(entry.p12_path, password)


def _obtain_identity(
    client: DeveloperClient,
    team_id: str,
    *,
    reuse: Optional[str],
    password: str,
    log,
    allow_revoke: bool = False,
) -> Tuple[SigningIdentity, Optional[dict], bool]:
    """Return ``(identity, cert_info, reused)``.

    ``reuse`` may name a vault entry; otherwise a new certificate is requested
    and, if the account has no free slot, the newest vault identity is used.
    """
    if reuse:
        stored = vault.load(reuse)
        identity = load_identity(stored.p12_path, password)
        log(f"[..] Reusing certificate: {identity.leaf.subject.rfc4514_string()}")
        return identity, None, True

    before = {c["certificateId"] for c in client.list_certificates(team_id)}
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    # Persist immediately: a crash after Apple signs the CSR would otherwise
    # leave an unusable certificate (private key lost) and burn the only slot.
    key_stash = paths.ensure_data_dir() / "pending-key.pem"
    key_stash.parent.mkdir(parents=True, exist_ok=True)
    key_stash.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )

    csr = _generate_csr(key)
    try:
        log("[..] Submitting the CSR to request a development certificate")
        client.submit_csr(team_id, csr)
    except DeveloperError as error:
        if error.payload.get("resultCode") != CERT_LIMIT_CODE:
            raise
        entry, identity = _vault_identity_for_team(team_id, password)
        if identity is not None:
            key_stash.unlink(missing_ok=True)
            log(f"[..] Certificate limit reached; using the vault certificate: {entry.name}")
            return identity, None, True
        if allow_revoke:
            revoked = revoke_all_certificates(client, team_id, log=log)
            log(f"[..] Revoked {revoked} old certificate(s); submitting the request again")
            client.submit_csr(team_id, csr)
        else:
            key_stash.unlink(missing_ok=True)
            raise RuntimeError(
                "Certificate limit reached (a free Apple ID can hold only 1 development "
                "certificate). The old certificate in the account has no matching private "
                "key here; revoke it and retry."
            ) from error

    fresh = [
        c for c in client.list_certificates(team_id)
        if c.get("certificateId") not in before
    ]
    if not fresh:
        raise RuntimeError("Apple did not return a new certificate")
    cert_info = fresh[0]
    content = cert_info.get("certContent") or _find_cert_content(cert_info)
    if not content:
        raise RuntimeError("the certificate list has no certContent")
    leaf = x509.load_der_x509_certificate(
        content if isinstance(content, (bytes, bytearray)) else base64.b64decode(content)
    )
    key_stash.unlink(missing_ok=True)
    log(f"[..] Certificate issued: {leaf.subject.rfc4514_string()}")
    identity = ensure_chain(
        SigningIdentity(key=key, certificates=[leaf]), allow_download=True, log=log
    )
    return identity, cert_info, False


def revoke_all_certificates(client: DeveloperClient, team_id: str, log=print) -> int:
    """Revoke every development certificate of the team.

    Needed when the account still holds a certificate whose private key is not
    on this machine (fresh install, cleaned vault): the free tier allows only
    one active certificate, so a new CSR is rejected until it is gone.
    """
    certificates = client.list_certificates(team_id)
    for certificate in certificates:
        log(f"[..] Revoking old certificate {certificate.get('certificateId')}")
        client.revoke_certificate(
            team_id, certificate["certificateId"], certificate["serialNumber"]
        )
    return len(certificates)

def _ensure_app_id(
    client: DeveloperClient, team_id: str, bundle_id: str, app_name: str, log
) -> dict:
    """Reuse the App ID when it already exists (free accounts have a quota)."""
    for existing in client.list_app_ids(team_id):
        if existing.get("identifier") == bundle_id:
            log(f"[..] Reusing App ID: {existing.get('appIdId')}")
            return existing
    log(f"[..] Registering App ID {bundle_id}")
    app_id = client.add_app_id(team_id, bundle_id, app_name)
    log(f"[..] App ID: {app_id['appIdId']}")
    return app_id


def issue(
    *,
    bundle_id: str,
    app_name: str,
    device_udid: Optional[str] = None,
    device_name: str = "ipasign",
    vault_name: Optional[str] = None,
    reuse: Optional[str] = None,
    password: Optional[str] = None,
    allow_revoke: bool = False,
    log=print,
) -> Dict:
    """Create (or reuse) a certificate + profile for ``bundle_id``."""
    device = apple_auth_bridge.open_device()
    if device.session is None:
        raise RuntimeError(
            "not signed in yet; run `ipasign login --account <Apple ID>` first"
        )
    headers = apple_auth_bridge.developer_headers(device, device.session)
    client = DeveloperClient(headers)

    teams = client.list_teams()
    if not teams:
        raise RuntimeError("this Apple ID has no developer team")
    team = teams[0]
    team_id = team["teamId"]
    log(f"[..] Team: {team.get('name')} ({team_id})")

    if device_udid:
        known = {d.get("deviceNumber") for d in client.list_devices(team_id)}
        if device_udid not in known:
            log(f"[..] Registering device {device_udid}")
            client.add_device(team_id, device_udid, device_name)
        else:
            log(f"[..] Device already registered: {device_udid}")

    identity, cert_info, _reused = _obtain_identity(
        client,
        team_id,
        reuse=reuse,
        password=password,
        log=log,
        allow_revoke=allow_revoke,
    )

    app_id = _ensure_app_id(client, team_id, bundle_id, app_name, log)

    log("[..] Downloading the provisioning profile")
    profile_bytes = client.download_profile(team_id, app_id["appIdId"])

    if not password:
        password = secrets.token_urlsafe(18)
    name = vault_name or f"{team_id}-{app_id['appIdId']}".lower()
    p12 = pkcs12.serialize_key_and_certificates(
        b"ipasign",
        identity.key,
        identity.certificates[0],
        cas=identity.certificates[1:] or None,
        encryption_algorithm=BestAvailableEncryption(password.encode()),
    )

    with tempfile.TemporaryDirectory(dir=str(paths.temp_dir())) as tmp:
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
            store_password=True,
        )

    log(f"[done] Stored in the vault: {name}")
    return {
        "name": name,
        "team_id": team_id,
        "certificate_id": cert_info.get("certificateId") if cert_info else None,
        "app_id_id": app_id["appIdId"],
        "bundle_id": bundle_id,
        "profile_size": len(profile_bytes),
        "profile_app_id": entry.meta.get("profile_app_id"),
    }
