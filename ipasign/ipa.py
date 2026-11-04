"""IPA (zip) unpacking and repacking.

IPAs are ordinary zip archives with a ``Payload/`` folder at the root.  Two
details need care:

* symlinks inside frameworks are stored as zip entries with the Unix
  ``S_IFLNK`` mode bits; on Windows they cannot be materialised, so they are
  recorded and recreated during repacking instead;
* executable bits must survive the round trip.
"""

from __future__ import annotations

import os
import shutil
import stat
import time
import unicodedata
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .errors import BundleError


@dataclass
class IpaContents:
    """An extracted IPA, ready for signing."""

    workdir: Path
    payload_dir: Path
    app_path: Path
    symlinks: Dict[str, str] = field(default_factory=dict)
    modes: Dict[str, int] = field(default_factory=dict)

    @property
    def app_bundles(self) -> List[Path]:
        return [
            entry
            for entry in sorted(self.payload_dir.iterdir())
            if entry.is_dir() and entry.suffix == ".app"
        ]


def _safe_name(name: str) -> str:
    name = unicodedata.normalize("NFC", name.replace("\\", "/"))
    while name.startswith("./"):
        name = name[2:]
    name = name.lstrip("/")
    parts = [part for part in name.split("/") if part not in ("", ".")]
    if any(part == ".." for part in parts):
        raise BundleError(f"unsafe path in archive: {name!r}")
    return "/".join(parts)


def extract_ipa(ipa_path: "str | Path", workdir: "str | Path") -> IpaContents:
    """Extract *ipa_path* into *workdir* (which must not exist yet or be empty)."""
    ipa_path = Path(ipa_path)
    workdir = Path(workdir)
    if not ipa_path.is_file():
        raise BundleError(f"IPA not found: {ipa_path}")
    if workdir.exists() and any(workdir.iterdir()):
        raise BundleError(f"working directory is not empty: {workdir}")
    workdir.mkdir(parents=True, exist_ok=True)

    symlinks: Dict[str, str] = {}
    modes: Dict[str, int] = {}
    try:
        archive = zipfile.ZipFile(ipa_path, "r")
    except zipfile.BadZipFile as exc:
        raise BundleError(f"not a valid zip/IPA file: {exc}") from exc

    with archive:
        names = archive.namelist()
        if not any(name.startswith("Payload/") for name in names):
            raise BundleError("archive has no Payload/ folder; is this really an IPA?")
        for info in archive.infolist():
            name = _safe_name(info.filename)
            if not name or name.startswith("__MACOSX/"):
                continue
            mode = (info.external_attr >> 16) & 0xFFFF
            target = workdir / name
            if info.is_dir() or info.filename.endswith("/"):
                target.mkdir(parents=True, exist_ok=True)
                modes[name] = stat.S_IFDIR | 0o755
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            if stat.S_ISLNK(mode):
                link_target = archive.read(info).decode("utf-8", "surrogateescape")
                symlinks[name] = link_target
                modes[name] = stat.S_IFLNK | 0o755
                continue
            with archive.open(info, "r") as source, open(target, "wb") as sink:
                shutil.copyfileobj(source, sink, length=1024 * 1024)
            file_mode = mode & 0o777 or 0o644
            modes[name] = stat.S_IFREG | file_mode
            try:
                os.chmod(target, file_mode | 0o600)
            except OSError:
                pass

    payload_dir = workdir / "Payload"
    if not payload_dir.is_dir():
        raise BundleError("archive has no Payload/ folder")
    apps = [
        entry
        for entry in sorted(payload_dir.iterdir())
        if entry.is_dir() and entry.suffix == ".app"
    ]
    if not apps:
        raise BundleError("no .app bundle found inside Payload/")
    if len(apps) > 1:
        # Multi-app archives are unusual; sign the first one but keep the rest.
        apps.sort(key=lambda path: path.name)
    return IpaContents(
        workdir=workdir,
        payload_dir=payload_dir,
        app_path=apps[0],
        symlinks=symlinks,
        modes=modes,
    )


def _zip_mode(path: Path, rel: str, modes: Dict[str, int]) -> int:
    mode = modes.get(rel)
    if mode is not None:
        return mode & 0o7777
    if path.is_dir():
        return 0o755
    return 0o644


def pack_ipa(contents: IpaContents, out_path: "str | Path") -> Path:
    """Pack the signed tree back into an IPA at *out_path*."""
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    base = contents.workdir
    stamp = time.localtime()[:6]

    with zipfile.ZipFile(
        out_path, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True, compresslevel=6
    ) as archive:
        for folder, dirs, files in os.walk(contents.payload_dir):
            dirs.sort()
            folder_path = Path(folder)
            rel_dir = folder_path.relative_to(base).as_posix()
            info = zipfile.ZipInfo(rel_dir + "/", date_time=stamp)
            info.create_system = 3
            info.external_attr = (stat.S_IFDIR | 0o755) << 16 | 0x10
            info.compress_type = zipfile.ZIP_STORED
            archive.writestr(info, b"")
            for name in sorted(files):
                file_path = folder_path / name
                rel = file_path.relative_to(base).as_posix()
                if file_path.is_symlink():
                    continue  # handled below from the recorded map
                self_mode = _zip_mode(file_path, rel, contents.modes)
                info = zipfile.ZipInfo(rel, date_time=stamp)
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | self_mode) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                with archive.open(info, "w") as sink, open(file_path, "rb") as source:
                    shutil.copyfileobj(source, sink, length=1024 * 1024)

        for rel, target in sorted(contents.symlinks.items()):
            info = zipfile.ZipInfo(rel, date_time=stamp)
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o755) << 16
            info.compress_type = zipfile.ZIP_STORED
            archive.writestr(info, target.encode("utf-8", "surrogateescape"))

    return out_path
