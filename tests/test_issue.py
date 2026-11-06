"""Tests for the certificate factory (no network involved)."""

from __future__ import annotations

import types

import pytest
from cryptography.hazmat.primitives import serialization

from ipasign.apple import issue as issue_mod
from ipasign.apple.developer import DeveloperError
from ipasign.core import vault
from ipasign.core.pki import SigningIdentity

from . import fixtures

KEY, CERT = fixtures.make_identity()
CERT_DER = CERT.public_bytes(serialization.Encoding.DER)


class FakeClient:
    """Minimal stand-in for DeveloperClient."""

    def __init__(self, *, app_ids=None, certs=None, submit_error=None):
        self._app_ids = list(app_ids or [])
        self._certs = list(certs or [])
        self.submit_error = submit_error
        self.added_app_ids = []
        self.submitted = []
        self.profile_requests = []

    def list_teams(self):
        return [{"name": "Team", "teamId": "TEAM123456", "type": "Individual"}]

    def list_devices(self, team_id):
        return [{"deviceNumber": "00008110-AAAABBBB", "name": "iPad"}]

    def list_certificates(self, team_id):
        return list(self._certs)

    def list_app_ids(self, team_id):
        return list(self._app_ids)

    def add_device(self, team_id, udid, name):
        return {"deviceNumber": udid}

    def submit_csr(self, team_id, csr):
        if self.submit_error is not None:
            raise self.submit_error
        self.submitted.append(csr)
        self._certs.append({"certificateId": "NEWCERT", "certContent": CERT_DER})
        return {"resultCode": 0}

    def add_app_id(self, team_id, identifier, name):
        record = {"appIdId": "NEWAPPID", "identifier": identifier, "name": name}
        self.added_app_ids.append(record)
        self._app_ids.append(record)
        return record

    def download_profile(self, team_id, app_id_id):
        self.profile_requests.append(app_id_id)
        return b"PROFILE-" + app_id_id.encode()


def _install_fakes(monkeypatch, client, tmp_path):
    monkeypatch.setattr(issue_mod, "DeveloperClient", lambda headers: client)
    monkeypatch.setattr(
        issue_mod.apple_auth_bridge,
        "open_device",
        lambda *a, **k: types.SimpleNamespace(session=object()),
    )
    monkeypatch.setattr(
        issue_mod.apple_auth_bridge, "developer_headers", lambda device, session: {}
    )
    monkeypatch.setattr(issue_mod, "ensure_chain", lambda identity, **k: identity)
    # Deterministic key so the fake certificate matches the request.
    monkeypatch.setattr(issue_mod.rsa, "generate_private_key", lambda **kwargs: KEY)
    monkeypatch.setattr(vault, "vault_root", lambda: tmp_path / "identities")
    monkeypatch.setattr(issue_mod.vault, "list_all", lambda: [])
    monkeypatch.setattr(
        vault,
        "save",
        lambda **kwargs: types.SimpleNamespace(meta={"profile_app_id": "TEAM123456.demo"}),
    )


def test_reuses_existing_app_id(monkeypatch, tmp_path):
    client = FakeClient(
        app_ids=[{"appIdId": "EXISTING", "identifier": "com.example.demo"}]
    )
    _install_fakes(monkeypatch, client, tmp_path)

    result = issue_mod.issue(
        bundle_id="com.example.demo", app_name="Demo", log=lambda *_: None
    )

    assert client.added_app_ids == []  # no duplicate App ID created
    assert client.profile_requests == ["EXISTING"]
    assert result["app_id_id"] == "EXISTING"


def test_creates_app_id_when_missing(monkeypatch, tmp_path):
    client = FakeClient()
    _install_fakes(monkeypatch, client, tmp_path)

    result = issue_mod.issue(
        bundle_id="com.example.new", app_name="New", log=lambda *_: None
    )

    assert [a["identifier"] for a in client.added_app_ids] == ["com.example.new"]
    assert result["app_id_id"] == "NEWAPPID"
    assert result["certificate_id"] == "NEWCERT"


def test_certificate_limit_falls_back_to_vault(monkeypatch, tmp_path):
    client = FakeClient(
        submit_error=DeveloperError(
            "ios/submitDevelopmentCSR",
            {"resultCode": 7460, "resultString": "Maximum number of certificates generated"},
        )
    )
    _install_fakes(monkeypatch, client, tmp_path)

    identity = SigningIdentity(key=KEY, certificates=[CERT])
    stored = types.SimpleNamespace(
        name="existing",
        p12_path=tmp_path / "identity.p12",
        meta={"team_id": "TEAM123456", "leaf_expires": "2027-01-01"},
    )
    stored.p12_path.write_bytes(b"unused")
    monkeypatch.setattr(issue_mod.vault, "list_all", lambda: [stored])
    monkeypatch.setattr(issue_mod, "load_identity", lambda path, password: identity)

    result = issue_mod.issue(
        bundle_id="com.example.demo", app_name="Demo", log=lambda *_: None
    )

    assert result["certificate_id"] is None
    assert client.added_app_ids  # profile still issued
    assert client.profile_requests


def test_certificate_limit_without_vault_raises(monkeypatch, tmp_path):
    client = FakeClient(
        submit_error=DeveloperError("ios/submitDevelopmentCSR", {"resultCode": 7460})
    )
    _install_fakes(monkeypatch, client, tmp_path)

    with pytest.raises(RuntimeError, match="证书名额已满"):
        issue_mod.issue(
            bundle_id="com.example.demo", app_name="Demo", log=lambda *_: None
        )


def test_reuse_skips_csr(monkeypatch, tmp_path):
    client = FakeClient()
    _install_fakes(monkeypatch, client, tmp_path)

    identity = SigningIdentity(key=KEY, certificates=[CERT])
    stored = types.SimpleNamespace(name="vaulted", p12_path=tmp_path / "v.p12", meta={})
    stored.p12_path.write_bytes(b"unused")
    monkeypatch.setattr(issue_mod.vault, "load", lambda name: stored)
    monkeypatch.setattr(issue_mod, "load_identity", lambda path, password: identity)

    result = issue_mod.issue(
        bundle_id="com.example.demo",
        app_name="Demo",
        reuse="vaulted",
        log=lambda *_: None,
    )

    assert client.submitted == []  # no new certificate requested
    assert result["certificate_id"] is None


def test_verify_falls_back_when_ca_bundle_missing(monkeypatch, tmp_path):
    """No ca-bundle.pem must not crash requests verification."""
    monkeypatch.setenv("IPASIGN_HOME", str(tmp_path))
    from ipasign.apple import developer

    assert developer._verify() is True
