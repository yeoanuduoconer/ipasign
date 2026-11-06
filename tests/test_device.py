"""Tests for the device layer (no real hardware required)."""

from __future__ import annotations

import pytest

from ipasign import device


def test_library_available_returns_bool():
    assert isinstance(device.library_available(), bool)


def test_list_devices_requires_library(monkeypatch):
    monkeypatch.setattr(device, "library_available", lambda: False)
    with pytest.raises(device.DeviceError):
        device.list_devices()


def test_install_rejects_missing_file(tmp_path):
    with pytest.raises(device.DeviceError):
        device.install_ipa(tmp_path / "missing.ipa")


def test_install_rejects_wrong_extension(tmp_path):
    target = tmp_path / "note.txt"
    target.write_text("hi")
    with pytest.raises(device.DeviceError):
        device.install_ipa(target)


def test_friendly_error_translates_known_failures():
    message = device.friendly_error("ERROR: ApplicationVerificationFailed")
    assert "证书" in message or "描述文件" in message


def test_friendly_error_passes_unknown_text():
    assert device.friendly_error("some random error") == "some random error"

def _make_ipa(tmp_path, bundle_id="com.example.demo", team="TEAM123456"):
    """Minimal IPA with Info.plist + embedded profile (enough for metadata)."""
    import plistlib
    import zipfile

    from tests import fixtures

    _key, cert = fixtures.make_identity()
    profile = fixtures.make_profile(certificates=[cert], app_id=f"{team}.*")
    path = tmp_path / "sample.ipa"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("Payload/Demo.app/Info.plist", plistlib.dumps({"CFBundleIdentifier": bundle_id}))
        archive.writestr("Payload/Demo.app/embedded.mobileprovision", profile)
    return path


def test_ipa_metadata_reads_bundle_and_team(tmp_path):
    ipa = _make_ipa(tmp_path)
    bundle_id, team = device._ipa_metadata(ipa)
    assert bundle_id == "com.example.demo"
    assert team == "TEAM123456"


def test_confirm_installed_detects_foreign_signer(tmp_path, monkeypatch):
    import pytest as _pytest

    ipa = _make_ipa(tmp_path)
    monkeypatch.setattr(
        device,
        "_list_apps",
        lambda udid: {
            "com.example.demo": {
                "Entitlements": {"com.apple.developer.team-identifier": "OTHERTEAM"},
                "SignerIdentity": "Apple iPhone OS Application Signing",
            }
        },
    )
    with _pytest.raises(device.DeviceError) as excinfo:
        device._confirm_installed(ipa, "UDID")
    assert "另外一个签名方" in str(excinfo.value) or "另一个签名方" in str(excinfo.value)


def test_confirm_installed_accepts_matching_signer(tmp_path, monkeypatch):
    ipa = _make_ipa(tmp_path)
    monkeypatch.setattr(
        device,
        "_list_apps",
        lambda udid: {
            "com.example.demo": {
                "Entitlements": {"com.apple.developer.team-identifier": "TEAM123456"}
            }
        },
    )
    device._confirm_installed(ipa, "UDID")
