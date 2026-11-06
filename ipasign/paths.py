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
import shutil
import sys
from pathlib import Path
from typing import Iterable, List, Optional

APP_NAME = "ipasign"


def data_dir() -> Path:
    """Where ipasign keeps vault, sessions and jobs (created on demand)."""
    override = os.environ.get("IPASIGN_HOME")
    if override:
        return Path(override).expanduser()
    return Path.home() / f".{APP_NAME}"


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


def native_dirs() -> List[Path]:
    """Directories searched for the apple-auth native libraries."""
    dirs: List[Path] = []
    extra = os.environ.get("IPASIGN_NATIVE_DIR")
    if extra:
        dirs.append(Path(extra).expanduser())
    dirs.append(data_dir() / "native")
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
