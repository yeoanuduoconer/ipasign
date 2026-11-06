"""Tests for signing identity handling and chain completion."""

from __future__ import annotations

import datetime as dt

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from ipasign.core import pki
from ipasign.core.errors import IdentityError

from . import fixtures


def test_load_p12_with_password(tmp_path):
    key, cert = fixtures.make_identity()
    path = tmp_path / "id.p12"
    path.write_bytes(fixtures.make_p12(key, cert, password="secret"))

    identity = pki.load_identity(path, "secret")
    assert identity.team_id == "TEAM123456"
    assert identity.common_name.startswith("Apple Development")
    assert identity.certificates[0].fingerprint(hashes.SHA256()) == cert.fingerprint(hashes.SHA256())

    with pytest.raises(IdentityError):
        pki.load_identity(path, "wrong")


def test_load_p12_missing_file():
    with pytest.raises(IdentityError):
        pki.load_identity("does/not/exist.p12")


def _make_ca_and_leaf():
    now = dt.datetime.now(dt.timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Apple Inc."),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "G4"),
        x509.NameAttribute(
            NameOID.COMMON_NAME, "Apple Worldwide Developer Relations Certification Authority"
        ),
    ])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name).issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Apple Development: X")]))
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=365))
        .sign(ca_key, hashes.SHA256())
    )
    return leaf_key, leaf, ca


def test_ensure_chain_finds_cached_intermediate(tmp_path, monkeypatch):
    leaf_key, leaf, ca = _make_ca_and_leaf()
    cache = tmp_path / "certs"
    cache.mkdir()
    (cache / "AppleWWDRCAG4.cer").write_bytes(
        ca.public_bytes(serialization.Encoding.DER)
    )
    monkeypatch.setattr(pki, "cert_cache_dir", lambda create=True: cache)

    identity = pki.SigningIdentity(key=leaf_key, certificates=[leaf])
    completed = pki.ensure_chain(identity, allow_download=False, log=lambda message: None)
    assert len(completed.certificates) == 2
    assert completed.certificates[1].fingerprint(hashes.SHA256()) == ca.fingerprint(hashes.SHA256())


def test_ensure_chain_reports_missing_intermediate(capsys):
    leaf_key, leaf, _ca = _make_ca_and_leaf()
    messages = []
    identity = pki.SigningIdentity(key=leaf_key, certificates=[leaf])
    completed = pki.ensure_chain(identity, allow_download=False, log=messages.append)
    assert len(completed.certificates) == 1
    assert messages and "--chain" in messages[0]
