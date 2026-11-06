"""Device transport classification and Wi-Fi helpers."""

from __future__ import annotations

from ipasign.device import DeviceInfo


def test_transport_usb():
    info = DeviceInfo(udid="u", connection="USB")
    assert info.transport == "usb"
    assert info.is_wifi is False


def test_transport_network():
    for value in ("Network", "WiFi", "WLAN", "network"):
        info = DeviceInfo(udid="u", connection=value)
        assert info.transport == "wifi"
        assert info.is_wifi is True


def test_transport_unknown():
    info = DeviceInfo(udid="u")
    assert info.transport == "unknown"
    assert info.is_wifi is False


def test_label_contains_identity():
    info = DeviceInfo(udid="u", name="iPad", product_type="iPad15,3", ios_version="26.5")
    assert "iPad" in info.label() and "26.5" in info.label()
