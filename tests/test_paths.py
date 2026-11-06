"""Path resolution tests: nothing may depend on a machine-specific location."""

from __future__ import annotations

from pathlib import Path

from ipasign import paths


def test_data_dir_defaults_to_home(monkeypatch):
    monkeypatch.delenv("IPASIGN_HOME", raising=False)
    assert paths.data_dir() == Path.home() / ".ipasign"


def test_data_dir_honours_override(monkeypatch, tmp_path):
    monkeypatch.setenv("IPASIGN_HOME", str(tmp_path / "custom"))
    assert paths.data_dir() == tmp_path / "custom"
    assert paths.ensure_data_dir().is_dir()


def test_find_native_prefers_env_dir(monkeypatch, tmp_path):
    library = tmp_path / "lib" / "apple_auth.dll"
    library.parent.mkdir(parents=True)
    library.write_bytes(b"dll")
    monkeypatch.setenv("IPASIGN_NATIVE_DIR", str(library.parent))
    assert paths.find_native("apple_auth.dll") == library


def test_find_native_uses_data_dir(monkeypatch, tmp_path):
    library = tmp_path / "native" / "apple_auth_client.dll"
    library.parent.mkdir(parents=True)
    library.write_bytes(b"dll")
    monkeypatch.setenv("IPASIGN_HOME", str(tmp_path))
    monkeypatch.delenv("IPASIGN_NATIVE_DIR", raising=False)
    assert paths.find_native("apple_auth_client.dll") == library


def test_find_native_returns_none_when_absent(monkeypatch, tmp_path):
    monkeypatch.setenv("IPASIGN_HOME", str(tmp_path))
    monkeypatch.delenv("IPASIGN_NATIVE_DIR", raising=False)
    assert paths.find_native("definitely-missing.dll") is None


def test_find_tool_uses_data_dir(monkeypatch, tmp_path):
    tool = tmp_path / "tools" / "zsign.exe"
    tool.parent.mkdir(parents=True)
    tool.write_bytes(b"exe")
    monkeypatch.setenv("IPASIGN_HOME", str(tmp_path))
    assert paths.find_tool("zsign.exe") == tool


def test_ca_bundle_only_when_present(monkeypatch, tmp_path):
    monkeypatch.setenv("IPASIGN_HOME", str(tmp_path))
    assert paths.ca_bundle() is None
    bundle = tmp_path / "ca-bundle.pem"
    bundle.write_text("cert")
    assert paths.ca_bundle() == bundle


def test_zsign_env_override(monkeypatch, tmp_path):
    from ipasign.core import zsign_backend

    tool = tmp_path / "zsign.exe"
    tool.write_bytes(b"exe")
    monkeypatch.setenv("IPASIGN_ZSIGN", str(tool))
    assert zsign_backend.find_zsign() == tool


def test_auth_library_env_override(monkeypatch, tmp_path):
    from ipasign.apple import auth

    library = tmp_path / "apple_auth_client.dll"
    library.write_bytes(b"dll")
    monkeypatch.setenv("APPLE_AUTH_LIBRARY", str(library))
    assert auth.library_path() == library
