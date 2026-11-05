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
