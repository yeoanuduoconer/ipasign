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

from ipasign import paths

STATE_DIR = paths.data_dir() / "apple-auth-device-mac"


class AppleAuthUnavailable(RuntimeError):
    """The native client library or its Python bindings are missing."""


def library_path() -> Path:
    explicit = os.environ.get("APPLE_AUTH_LIBRARY")
    if explicit:
        path = Path(explicit).expanduser()
        if path.is_file():
            return path
        raise AppleAuthUnavailable(f"APPLE_AUTH_LIBRARY not found: {path}")
    found = paths.find_native(
        "apple_auth_client.dll",
        "libapple_auth_client.so",
        "libapple_auth_client.dylib",
    )
    if found is not None:
        return found
    raise AppleAuthUnavailable(
        "找不到 apple-auth 原生客户端（apple_auth_client.dll）。\n"
        "编译方法见 README，然后把库文件放到 ~/.ipasign/native/，"
        "或设置环境变量 APPLE_AUTH_LIBRARY 指向它。"
    )


def _import_device():
    library = library_path()
    os.environ["APPLE_AUTH_LIBRARY"] = str(library)
    # Vendored MIT bindings ship with ipasign; an upstream checkout is only a
    # development fallback.
    try:
        from ipasign.vendor.apple_auth import Device  # noqa: PLC0415

        return Device
    except ImportError:
        # Optional development fallback: an upstream apple-auth checkout.
        source = os.environ.get("IPASIGN_APPLE_AUTH_SOURCE")
        if source:
            python_dir = Path(source).expanduser() / "python"
            if python_dir.is_dir() and str(python_dir) not in sys.path:
                sys.path.insert(0, str(python_dir))
        try:
            from apple_auth import Device  # noqa: PLC0415
        except ImportError as error:  # pragma: no cover - environment dependent
            raise AppleAuthUnavailable(
                f"apple_auth bindings unavailable ({error})"
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
