"""Path resolution tests: nothing may depend on a machine-specific location."""

from __future__ import annotations

from pathlib import Path

from ipasign import paths


def test_data_dir_prefers_checkout(monkeypatch):
    """A source checkout keeps everything inside the project folder."""
    monkeypatch.delenv("IPASIGN_HOME", raising=False)
    root = paths.project_root()
    if root is None:  # installed copy: falls back to the home directory
        assert paths.data_dir() == Path.home() / ".ipasign"
    else:
        assert paths.data_dir() == root / ".ipasign"


def test_temp_dir_lives_inside_data_dir(monkeypatch, tmp_path):
    monkeypatch.setenv("IPASIGN_HOME", str(tmp_path / "data"))
    temp = paths.temp_dir()
    assert temp.is_dir()
    assert paths.data_dir() in temp.parents


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


def test_platform_tag_shape():
    tag = paths.platform_tag()
    assert tag.startswith(("win-", "macos-", "linux-"))
    assert tag.endswith(("x64", "arm64"))


def test_bundled_dirs_are_inside_package():
    package_dir = Path(paths.__file__).resolve().parent
    for directory in paths.bundled_native_dirs():
        assert package_dir in directory.parents


def test_find_native_falls_back_to_bundled(monkeypatch, tmp_path):
    monkeypatch.setenv("IPASIGN_HOME", str(tmp_path))
    monkeypatch.delenv("IPASIGN_NATIVE_DIR", raising=False)
    found = paths.find_native("apple_auth_client.dll")
    if found is None:
        # platform without a bundled build (macOS/Linux CI): nothing to assert
        return
    assert "native" in str(found)


def test_bundled_libraries_load(monkeypatch, tmp_path):
    """The shipped DLLs must be loadable without a user install."""
    monkeypatch.setenv("IPASIGN_HOME", str(tmp_path))
    monkeypatch.delenv("APPLE_AUTH_LIBRARY", raising=False)
    from ipasign.apple import auth

    try:
        library = auth.library_path()
    except auth.AppleAuthUnavailable:
        return  # no bundled build for this platform
    import ctypes

    ctypes.CDLL(str(library))  # raises OSError if dependencies are missing
