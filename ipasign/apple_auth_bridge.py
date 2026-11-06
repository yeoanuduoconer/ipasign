"""Apple ID login through the locally built ``apple_auth_client`` library.

``apple-auth`` (MIT) ships a complete GrandSlam client: provisioning, SRP,
2FA, trusted-device handling and the developer-portal session.  Re-implementing
that in Python is what produced ``-22409``; driving the native client is the
supported path.

The password is read locally by ``getpass`` inside the native wrapper and is
never written to disk or logged.  Only the resulting account session is saved,
under ``~/.ipasign/apple-auth-device``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Optional

STATE_DIR = Path.home() / ".ipasign" / "apple-auth-device-mac"
LIBRARY_CANDIDATES = (
    Path(r"E:\tools\ipasign\apple-auth-client\Release\apple_auth_client.dll"),
    Path(r"E:\tools\ipasign\apple-auth-build\Release\apple_auth_client.dll"),
)
SOURCE_DIR = Path(r"E:\tools\ipasign\apple-auth-src")


class AppleAuthUnavailable(RuntimeError):
    """The native client library or its Python bindings are missing."""


def library_path() -> Path:
    explicit = os.environ.get("APPLE_AUTH_LIBRARY")
    if explicit:
        path = Path(explicit)
        if path.is_file():
            return path
        raise AppleAuthUnavailable(f"APPLE_AUTH_LIBRARY not found: {path}")
    for candidate in LIBRARY_CANDIDATES:
        if candidate.is_file():
            return candidate
    raise AppleAuthUnavailable(
        "apple_auth_client.dll not found; build apple-auth with "
        "APPLE_AUTH_WITH_CLIENT=ON or set APPLE_AUTH_LIBRARY"
    )


def _import_device():
    library = library_path()
    os.environ["APPLE_AUTH_LIBRARY"] = str(library)
    python_dir = SOURCE_DIR / "python"
    if python_dir.is_dir() and str(python_dir) not in sys.path:
        sys.path.insert(0, str(python_dir))
    try:
        from apple_auth import Device  # noqa: PLC0415
    except ImportError as error:  # pragma: no cover - environment dependent
        raise AppleAuthUnavailable(
            f"apple_auth Python package unavailable ({error}); "
            "it lives in <apple-auth>/python"
        ) from error
    return Device


def open_device(state: "str | Path | None" = None):
    """Open (and provision on first use) a Mac device identity.

    Xcode's application token (com.apple.gs.xcode.auth) matches a macOS device
    profile; a Windows identity is rejected with -80046.
    """
    Device = _import_device()
    target = Path(state) if state else STATE_DIR
    return Device.mac(str(target))


def login(email: str, password: Optional[str] = None, state=None):
    """Log in, prompting for password and 2FA locally when not supplied."""
    device = open_device(state)
    session = device.login(email=email, password=password)
    return device, session


def developer_headers(device, session) -> dict:
    return device.developer_headers(device.developer_session(session))


def describe_session(session) -> dict:
    data = {}
    for name in ("dsid", "gs_token", "status", "account_name"):
        value = getattr(session, name, None)
        if value:
            data[name] = str(value)[:12] + "..." if name == "gs_token" else str(value)
    return data
