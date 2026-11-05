"""Tests for the identity vault, the doctor and renew."""

from __future__ import annotations

import json
import plistlib
import zipfile

import pytest

from ipasign import doctor, vault
from ipasign.errors import IpasignError
from ipasign.pki import SigningIdentity
from ipasign.profile import ProvisioningProfile

from . import fixtures


@pytest.fixture()
def isolated_vault(tmp_path, monkeypatch):
    root = tmp_path / "identities"
    root.mkdir()
    monkeypatch.setattr(vault, "vault_root", lambda: root)
    return root


def _identity_files(tmp_path, app_id="TEAM123456.*"):
    key, cert = fixtures.make_identity()
    p12 = tmp_path / "id.p12"
    p12.write_bytes(fixtures.make_p12(key, cert, password="secret"))
    profile_path = tmp_path / "profile.mobileprovision"
    profile_path.write_bytes(fixtures.make_profile(certificates=[cert], app_id=app_id))
    return key, cert, p12, profile_path


def test_vault_import_list_show_remove(isolated_vault, tmp_path):
    key, cert, p12, profile_path = _identity_files(tmp_path)
    stored = vault.save("corp", p12, profile_path, "secret")
    assert stored.p12_path.is_file()
    assert stored.profile_path.is_file()
    assert stored.meta["team_id"] == "TEAM123456"
    assert stored.meta["profile_app_id"] == "TEAM123456.*"

    items = vault.list_all()
    assert [item.name for item in items] == ["corp"]

    loaded = vault.load("corp")
    assert loaded.p12_path.read_bytes() == p12.read_bytes()

    vault.remove("corp")
    assert vault.list_all() == []


def test_vault_rejects_duplicates_without_force(isolated_vault, tmp_path):
    _key, _cert, p12, profile_path = _identity_files(tmp_path)
    vault.save("corp", p12, profile_path, "secret")
    with pytest.raises(IpasignError):
        vault.save("corp", p12, profile_path, "secret")
    vault.save("corp", p12, profile_path, "secret", overwrite=True)


def test_vault_rejects_unsafe_names(isolated_vault, tmp_path):
    _key, _cert, p12, _profile = _identity_files(tmp_path)
    with pytest.raises(IpasignError):
        vault.save("../evil", p12, None, "secret")


def test_doctor_detects_self_signed_and_expired_profile(tmp_path):
    key, cert, _p12, _profile_path = _identity_files(tmp_path)
    identity = SigningIdentity(key=key, certificates=[cert])

    _key2, cert2 = fixtures.make_identity()
    expired = ProvisioningProfile.parse(
        fixtures.make_profile(certificates=[cert2], expires_days=-3)
    )
    checks = doctor.run_checks(identity=identity, profile=expired)
    by_name = {check.name: check for check in checks}
    assert not by_name["证书链"].ok
    assert not by_name["描述文件有效期"].ok


def test_doctor_flags_bundle_id_mismatch(tmp_path):
    key, cert, _p12, _profile_path = _identity_files(tmp_path)
    identity = SigningIdentity(key=key, certificates=[cert])
    profile = ProvisioningProfile.parse(
        fixtures.make_profile(certificates=[cert], app_id="TEAM123456.com.allowed.app")
    )
    app = fixtures.make_app_dir(str(tmp_path / "src"), bundle_id="com.other.app")
    ipa = fixtures.make_ipa(app, str(tmp_path / "x.ipa"))

    checks = doctor.run_checks(ipa_path=ipa, identity=identity, profile=profile)
    by_name = {check.name: check for check in checks}
    assert not by_name["描述文件覆盖 Bundle ID"].ok
    assert doctor.all_ok(checks) is False


def test_doctor_passes_for_matching_identity(tmp_path):
    key, cert, _p12, profile_path = _identity_files(tmp_path)
    identity = SigningIdentity(key=key, certificates=[cert])
    profile = ProvisioningProfile.load(profile_path)
    app = fixtures.make_app_dir(str(tmp_path / "src"), bundle_id="com.example.demo")
    ipa = fixtures.make_ipa(app, str(tmp_path / "x.ipa"))

    checks = doctor.run_checks(ipa_path=ipa, identity=identity, profile=profile)
    by_name = {check.name: check for check in checks}
    assert by_name["描述文件覆盖 Bundle ID"].ok
    assert by_name["证书在描述文件名单内"].ok
    assert by_name["团队一致"].ok


def test_ipa_bundle_id_reads_payload(tmp_path):
    app = fixtures.make_app_dir(str(tmp_path / "src"), bundle_id="com.example.demo")
    ipa = fixtures.make_ipa(app, str(tmp_path / "x.ipa"))
    assert doctor.ipa_bundle_id(ipa) == "com.example.demo"


def test_ipa_bundle_id_rejects_non_zip(tmp_path):
    target = tmp_path / "bad.ipa"
    target.write_bytes(b"not a zip")
    with pytest.raises(IpasignError):
        doctor.ipa_bundle_id(target)
