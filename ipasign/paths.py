"""Filesystem locations, resolved per user and per platform.

Nothing in ipasign may hard-code a machine-specific path.  Everything the tool
needs to locate lives here, with a predictable search order:

user data (``~/.ipasign`` by default, ``IPASIGN_HOME`` overrides it)
    vault, device identity (ADI), account session, renewal jobs

native libraries (``apple_auth.dll`` / ``apple_auth_client.dll``)
    1. explicit environment variable
    2. ``<data>/native/``
    3. next to the package (development checkout)
    4. platform application-data directory
    5. the system PATH

external tools (``zsign``)
    1. explicit environment variable
    2. ``<data>/tools/``
    3. the system PATH

Environment variables
    IPASIGN_HOME            override the data directory
    IPASIGN_NATIVE_DIR      extra directory searched for the native libraries
    APPLE_AUTH_LIBRARY      full path to ``apple_auth_client.dll``
    IPASIGN_APPLE_AUTH_DLL  full path to the core ``apple_auth.dll``
    IPASIGN_ZSIGN           full path to the ``zsign`` executable
"""

from __future__ import annotations

import os
import platform
import shutil
import sys
from pathlib import Path
from typing import Iterable, List, Optional

APP_NAME = "ipasign"


def project_root() -> Optional[Path]:
    """The source checkout containing this package, if any.

    Everything ipasign produces lives inside the checkout (``<project>/.ipasign``)
    so a project folder is fully self-contained.  An installed copy has no
    checkout, so it falls back to the per-user directory.
    """
    if frozen():
        return None
    candidate = Path(__file__).resolve().parent.parent
    if (candidate / "pyproject.toml").is_file():
        return candidate
    return None


def data_dir() -> Path:
    """Where ipasign keeps vault, sessions and jobs (created on demand).

    Order: ``IPASIGN_HOME`` → the source checkout → the user home directory.
    """
    override = os.environ.get("IPASIGN_HOME")
    if override:
        return Path(override).expanduser()
    root = project_root()
    if root is not None:
        return root / f".{APP_NAME}"
    return Path.home() / f".{APP_NAME}"


def temp_dir() -> Path:
    """Scratch space for staging files, inside the data directory."""
    path = ensure_data_dir() / "tmp"
    path.mkdir(parents=True, exist_ok=True)
    return path


def ensure_data_dir() -> Path:
    path = data_dir()
    path.mkdir(parents=True, exist_ok=True)
    return path


def _platform_data_dirs() -> List[Path]:
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        return [Path(base) / APP_NAME / "native"] if base else []
    if sys.platform == "darwin":
        return [Path.home() / "Library" / "Application Support" / APP_NAME / "native"]
    base = os.environ.get("XDG_DATA_HOME")
    root = Path(base) if base else Path.home() / ".local" / "share"
    return [root / APP_NAME / "native"]


def _package_neighbours() -> List[Path]:
    """Development layouts: the native build sitting next to the checkout."""
    package = Path(__file__).resolve().parent          # .../ipasign
    project = package.parent                            # repo root
    candidates: List[Path] = []
    if frozen():
        return []
    for root in (project, project.parent, package):
        candidates.extend(
            [
                root / "native",
                root / "apple-auth-client" / "Release",
                root / "apple-auth-build" / "Release",
                root / ".ipasign" / "native",
            ]
        )
    return candidates


def platform_tag() -> str:
    """``win-x64`` / ``macos-arm64`` / ``linux-x64`` …"""
    machine = platform.machine().lower()
    arch = "arm64" if machine in ("arm64", "aarch64") else "x64"
    if sys.platform == "win32":
        return f"win-{arch}"
    if sys.platform == "darwin":
        return f"macos-{arch}"
    return f"linux-{arch}"


def frozen() -> bool:
    """True inside a PyInstaller executable."""
    return bool(getattr(sys, "frozen", False))


def _bundle_root() -> Path:
    """Where data files live: the package dir, or the frozen bundle root."""
    if frozen():
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).resolve().parent))
    return Path(__file__).resolve().parent


def bundled_native_dirs() -> List[Path]:
    """Native libraries shipped inside the package (no build required)."""
    if frozen():
        base = _bundle_root() / "ipasign" / "native"
    else:
        base = _bundle_root() / "native"
    return [base / platform_tag(), base]



def native_dirs() -> List[Path]:
    """Directories searched for the apple-auth native libraries.

    Order: explicit override, per-user install, bundled build (works out of
    the box), development layouts, platform application data.
    """
    dirs: List[Path] = []
    extra = os.environ.get("IPASIGN_NATIVE_DIR")
    if extra:
        dirs.append(Path(extra).expanduser())
    dirs.append(data_dir() / "native")
    dirs.extend(bundled_native_dirs())
    dirs.extend(_package_neighbours())
    dirs.extend(_platform_data_dirs())
    # de-duplicate while keeping the order
    seen, result = set(), []
    for directory in dirs:
        key = str(directory).lower()
        if key not in seen:
            seen.add(key)
            result.append(directory)
    return result


def find_native(*names: str) -> Optional[Path]:
    """Locate one of *names* in :func:`native_dirs`."""
    for directory in native_dirs():
        for name in names:
            candidate = directory / name
            if candidate.is_file():
                return candidate
    return None


def which(program: str) -> Optional[Path]:
    found = shutil.which(program)
    return Path(found) if found else None


def tool_dirs() -> Iterable[Path]:
    yield data_dir() / "tools"
    yield data_dir() / "bin"


def find_tool(*names: str) -> Optional[Path]:
    for directory in tool_dirs():
        for name in names:
            candidate = directory / name
            if candidate.is_file():
                return candidate
    for name in names:
        found = which(name)
        if found:
            return found
    return None


def ca_bundle() -> Optional[Path]:
    """Optional combined CA bundle (Apple's legacy root, corporate proxies)."""
    candidate = data_dir() / "ca-bundle.pem"
    return candidate if candidate.is_file() else None
