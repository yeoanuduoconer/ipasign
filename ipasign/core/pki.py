"""Signing identity handling: PKCS#12 bundles, certificate chains, team IDs.

A ``.p12`` exported from Keychain Access usually contains the leaf
certificate and its private key, sometimes the intermediate CA as well.
iOS needs the *Apple Worldwide Developer Relations* intermediate inside the
CMS envelope to build a chain up to Apple's root, so this module can pull it
from a few places: the p12 itself, an explicit ``--chain`` file, a ``certs/``
folder next to the tool, or the Windows certificate store.
"""

from __future__ import annotations

from ipasign import paths

import base64
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from ipasign.core.errors import IdentityError

WWDR_NAME_HINTS = (
    "Worldwide Developer Relations",
    "Apple Development",
    "Apple Distribution",
    "Apple Worldwide",
)


@dataclass
class SigningIdentity:
    """A private key plus its certificate chain (leaf first)."""

    key: object
    certificates: List[x509.Certificate] = field(default_factory=list)

    # -- properties -----------------------------------------------------
    @property
    def leaf(self) -> x509.Certificate:
        return self.certificates[0]

    @property
    def common_name(self) -> str:
        values = self.leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return values[0].value if values else ""

    @property
    def organization(self) -> str:
        values = self.leaf.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        return values[0].value if values else ""

    @property
    def team_id(self) -> str:
        """Best-effort team identifier from the certificate subject."""
        values = self.leaf.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
        if values and values[0].value:
            return values[0].value
        match = re.search(r"\(([A-Z0-9]{6,12})\)\s*$", self.common_name)
        if match:
            return match.group(1)
        return ""

    @property
    def fingerprint_sha256(self) -> str:
        return self.leaf.fingerprint(hashes.SHA256()).hex()

    def describe(self) -> dict:
        return {
            "common_name": self.common_name,
            "organization": self.organization,
            "team_id": self.team_id,
            "serial": hex(self.leaf.serial_number),
            "not_before": self.leaf.not_valid_before_utc.isoformat(),
            "not_after": self.leaf.not_valid_after_utc.isoformat(),
            "sha256": self.fingerprint_sha256,
            "chain_length": len(self.certificates),
        }

    def chain_with(self, extra: Sequence[x509.Certificate]) -> "SigningIdentity":
        seen = {c.fingerprint(hashes.SHA256()) for c in self.certificates}
        merged = list(self.certificates)
        for cert in extra:
            digest = cert.fingerprint(hashes.SHA256())
            if digest not in seen:
                merged.append(cert)
                seen.add(digest)
        return SigningIdentity(key=self.key, certificates=merged)


def load_identity(
    p12_path: os.PathLike | str,
    password: Optional[str] = None,
    extra_chain: Iterable[x509.Certificate] = (),
) -> SigningIdentity:
    """Load a ``.p12`` / ``.pfx`` file into a :class:`SigningIdentity`."""
    path = Path(p12_path)
    if not path.is_file():
        raise IdentityError(f"p12 file not found: {path}")
    data = path.read_bytes()
    secret = None if password is None else password.encode("utf-8")
    try:
        key, cert, additional = pkcs12.load_key_and_certificates(data, secret)
    except ValueError as exc:
        hint = "wrong password" if secret else "the file may be password protected"
        raise IdentityError(f"cannot open p12 ({hint}): {exc}") from exc
    if key is None:
        raise IdentityError("p12 does not contain a private key")
    if cert is None:
        raise IdentityError("p12 does not contain a leaf certificate")
    identity = SigningIdentity(
        key=key, certificates=[cert] + list(additional or []),
    )
    extra = list(extra_chain)
    if extra:
        identity = identity.chain_with(extra)
    return identity


# ---------------------------------------------------------------------------
# Certificates
# ---------------------------------------------------------------------------

def load_certificate(path: os.PathLike | str) -> x509.Certificate:
    data = Path(path).read_bytes()
    if b"-----BEGIN" in data:
        return x509.load_pem_x509_certificate(data)
    return x509.load_der_x509_certificate(data)


def load_certificates(paths: Iterable[os.PathLike | str]) -> List[x509.Certificate]:
    return [load_certificate(path) for path in paths]


def find_wwdr_certificates(search_dirs: Iterable[os.PathLike | str] = ()) -> List[x509.Certificate]:
    """Look for the Apple WWDR intermediate in well-known locations."""
    found: List[x509.Certificate] = []
    seen = set()

    def _add(cert: x509.Certificate) -> None:
        digest = cert.fingerprint(hashes.SHA256())
        if digest not in seen and any(h in cert.subject.rfc4514_string() for h in WWDR_NAME_HINTS):
            seen.add(digest)
            found.append(cert)

    roots = [Path(d) for d in search_dirs]
    for root in roots:
        if not root.is_dir():
            continue
        for pattern in ("*.cer", "*.crt", "*.pem", "*.der"):
            for file in sorted(root.glob(pattern)):
                try:
                    _add(load_certificate(file))
                except Exception:  # noqa: BLE001 - best effort scanning
                    continue

    if sys.platform == "win32" and not found:
        for cert in _windows_store_lookup():
            _add(cert)
    return found


def _windows_store_lookup() -> List[x509.Certificate]:
    """Best-effort lookup of Apple intermediates in the Windows cert store."""
    script = (
        "$ErrorActionPreference='SilentlyContinue';"
        "$stores=@('Cert:\\CurrentUser\\CA','Cert:\\CurrentUser\\Root',"
        "'Cert:\\LocalMachine\\CA','Cert:\\LocalMachine\\Root');"
        "$seen=@{};"
        "foreach($s in $stores){"
        " Get-ChildItem $s | Where-Object { $_.Subject -like '*Worldwide Developer Relations*' } |"
        " ForEach-Object { if(-not $seen[$_.Thumbprint]){ $seen[$_.Thumbprint]=1;"
        " [Convert]::ToBase64String($_.RawData) } } }"
    )
    try:
        completed = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=20,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError):
        return []
    certificates: List[x509.Certificate] = []
    for line in completed.stdout.splitlines():
        line = line.strip()
        if len(line) < 40:
            continue
        try:
            certificates.append(x509.load_der_x509_certificate(base64.b64decode(line)))
        except Exception:  # noqa: BLE001 - ignore individual parse failures
            continue
    return certificates


def default_chain_dirs() -> List[Path]:
    """Directories searched automatically for intermediate certificates."""
    here = Path(__file__).resolve().parent.parent
    candidates = [here / "certs", paths.data_dir() / "certs"]
    return [path for path in candidates if path.is_dir()]


# ---------------------------------------------------------------------------
# Apple chain completion
# ---------------------------------------------------------------------------

APPLE_CERTIFICATE_URLS: Dict[str, str] = {
    "AppleWWDRCAG2.cer": "https://www.apple.com/certificateauthority/AppleWWDRCAG2.cer",
    "AppleWWDRCAG3.cer": "https://www.apple.com/certificateauthority/AppleWWDRCAG3.cer",
    "AppleWWDRCAG4.cer": "https://www.apple.com/certificateauthority/AppleWWDRCAG4.cer",
    "AppleWWDRCAG5.cer": "https://www.apple.com/certificateauthority/AppleWWDRCAG5.cer",
    "AppleWWDRCAG6.cer": "https://www.apple.com/certificateauthority/AppleWWDRCAG6.cer",
    "AppleIncRootCertificate.cer": "https://www.apple.com/appleca/AppleIncRootCertificate.cer",
    "AppleRootCA-G2.cer": "https://www.apple.com/certificateauthority/AppleRootCA-G2.cer",
    "AppleRootCA-G3.cer": "https://www.apple.com/certificateauthority/AppleRootCA-G3.cer",
}


def cert_cache_dir(create: bool = True) -> Path:
    directory = paths.data_dir() / "certs"
    if create:
        directory.mkdir(parents=True, exist_ok=True)
    return directory


def download_apple_certificates(force: bool = False, log=print) -> List[Path]:
    """Download Apple's WWDR intermediates and roots into the cache."""
    import urllib.request

    directory = cert_cache_dir()
    saved: List[Path] = []
    for name, url in APPLE_CERTIFICATE_URLS.items():
        target = directory / name
        if target.is_file() and not force:
            saved.append(target)
            continue
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "ipasign/0.1"})
            with urllib.request.urlopen(request, timeout=20) as response:
                data = response.read()
            x509.load_der_x509_certificate(data)  # validate before caching
            target.write_bytes(data)
            saved.append(target)
            log(f"downloaded {name}")
        except Exception as exc:  # noqa: BLE001 - network is best effort
            log(f"could not download {name}: {exc}")
    return saved


def load_certificate_cache() -> List[x509.Certificate]:
    directory = cert_cache_dir(create=False)
    if not directory.is_dir():
        return []
    certificates = []
    for file in sorted(directory.glob("*")):
        if file.suffix.lower() not in (".cer", ".crt", ".der", ".pem"):
            continue
        try:
            certificates.append(load_certificate(file))
        except Exception:  # noqa: BLE001
            continue
    return certificates


def _is_currently_valid(cert: x509.Certificate, now=None) -> bool:
    moment = now or _utcnow()
    try:
        return cert.not_valid_before_utc <= moment <= cert.not_valid_after_utc
    except AttributeError:  # pragma: no cover - old cryptography
        return cert.not_valid_before <= moment.replace(tzinfo=None) <= cert.not_valid_after


def _utcnow():
    import datetime as _dt

    return _dt.datetime.now(_dt.timezone.utc)


def ensure_chain(
    identity: SigningIdentity,
    extra: Iterable[x509.Certificate] = (),
    *,
    allow_download: bool = True,
    log=print,
) -> SigningIdentity:
    """Complete *identity*'s chain up to Apple's root when possible.

    iOS requires the Apple WWDR intermediate inside the CMS envelope; a p12
    exported from Keychain usually contains only the leaf certificate.  The
    missing link is looked up in the local cache, in *extra*, in Apple's public
    PKI (downloaded once) and finally in the Windows certificate store.
    """
    certificates = list(identity.certificates)
    pool: List[x509.Certificate] = list(extra) + load_certificate_cache()

    def subjects() -> set:
        return {cert.subject.public_bytes() for cert in certificates}

    def find_issuer(cert: x509.Certificate) -> Optional[x509.Certificate]:
        wanted = cert.issuer.public_bytes()
        matches = [
            candidate
            for candidate in pool
            if candidate.subject.public_bytes() == wanted
            and candidate.fingerprint(hashes.SHA256())
            != cert.fingerprint(hashes.SHA256())
        ]
        if not matches:
            return None
        # Prefer a certificate that is currently valid.
        matches.sort(key=lambda candidate: not _is_currently_valid(candidate))
        return matches[0]

    looked_up_store = False
    downloaded = False
    for _ in range(4):
        current = certificates[-1]
        if current.issuer == current.subject:  # self-signed root, chain complete
            break
        issuer = find_issuer(current)
        if (
            issuer is None
            and len(certificates) == 1
            and not looked_up_store
            and sys.platform == "win32"
        ):
            looked_up_store = True
            pool.extend(_windows_store_lookup())
            issuer = find_issuer(current)
        if issuer is None and allow_download and not downloaded:
            downloaded = True
            if download_apple_certificates(log=lambda message: None):
                pool.extend(load_certificate_cache())
                issuer = find_issuer(current)
        if issuer is None:
            break
        if issuer.subject.public_bytes() in subjects():
            break
        certificates.append(issuer)

    if len(certificates) < 2:
        log(
            "未能自动补全 Apple 中间证书；iOS 会拒绝安装。"
            "请用 --chain 指定 AppleWWDRCA*.cer，或运行 `ipasign fetch-certs`"
        )

    return SigningIdentity(key=identity.key, certificates=certificates)


def describe_chain(identity: SigningIdentity) -> List[Dict[str, str]]:
    out = []
    for index, cert in enumerate(identity.certificates):
        out.append(
            {
                "index": index,
                "role": "leaf" if index == 0 else "intermediate",
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "not_after": cert.not_valid_after_utc.isoformat(),
                "expired": not _is_currently_valid(cert),
            }
        )
    return out
