"""``_CodeSignature/CodeResources`` generation.

The resource envelope seals every file inside a bundle (excluding the main
executable and ``Info.plist``, which are sealed through dedicated
CodeDirectory slots).  iOS itself does not re-verify the envelope on device,
but macOS tools (``codesign --verify``) and application thinning do, so the
format is produced faithfully.
"""

from __future__ import annotations

import hashlib
import os
import plistlib
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence

CODE_RESOURCES_NAME = "CodeResources"
CODE_SIGNATURE_DIR = "_CodeSignature"

# Apple's stock rule set for bundles without nested code specialities.
_STANDARD_RULES: Dict[str, object] = {
    "^.*": True,
    "^.*\\.lproj/": {"optional": True, "weight": 1000},
    "^.*\\.lproj/locversion.plist$": {"omit": True, "weight": 1100},
    "^Base\\.lproj/": {"weight": 1010},
    "^version.plist$": True,
    "^Info\\.plist$": {"omit": True, "weight": 20},
    "^PkgInfo$": {"omit": True, "weight": 20},
    "^_MASReceipt/": {"omit": True},
    "^.*\\.dSYM($|/)": {"weight": 11},
    "^(.*/)?\\.DS_Store$": {"omit": True, "weight": 2000},
    "^\\.git($|/)": {"omit": True, "weight": 20},
    "^\\.svn($|/)": {"omit": True, "weight": 20},
    "^CVS($|/)": {"omit": True, "weight": 20},
}


@dataclass
class ResourceEntry:
    path: str
    size: int
    sha1: Optional[bytes] = None
    sha256: Optional[bytes] = None
    symlink: Optional[str] = None


def _hash_file(path: Path) -> tuple[int, bytes, bytes]:
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return size, sha1.digest(), sha256.digest()


def collect_resources(
    root: Path,
    *,
    executable: Optional[Path] = None,
    skip_dirs: Iterable[Path] = (),
    skip_files: Iterable[Path] = (),
) -> List[ResourceEntry]:
    """Walk *root* and return the sealed file list (POSIX relative paths)."""
    root = Path(root)
    skip_dir_set = {Path(path).resolve() for path in skip_dirs}
    skip_file_set = {Path(path).resolve() for path in skip_files}
    if executable is not None:
        skip_file_set.add(Path(executable).resolve())

    entries: List[ResourceEntry] = []
    for folder, dirs, files in os.walk(root, followlinks=False):
        folder_path = Path(folder)
        kept = []
        for name in dirs:
            child = folder_path / name
            # Only the bundle's own _CodeSignature is excluded; nested bundles
            # keep theirs, and the parent seals those files too (zsign does
            # the same, and iOS validates the full envelope).
            if child.name in ("__MACOSX", ".git", ".svn", "CVS"):
                continue
            if child.name == CODE_SIGNATURE_DIR and folder_path == root:
                continue
            if os.path.islink(child):
                rel = child.relative_to(root).as_posix()
                entries.append(
                    ResourceEntry(path=rel, size=0, symlink=os.readlink(child))
                )
                continue
            if child.resolve() in skip_dir_set:
                continue
            kept.append(name)
        dirs[:] = sorted(kept)

        for name in sorted(files):
            child = folder_path / name
            resolved = child.resolve()
            if resolved in skip_file_set:
                continue
            # Apple's rules only omit the bundle's own Info.plist / PkgInfo,
            # not same-named resources in subdirectories.
            if folder_path == root and name in ("Info.plist", "PkgInfo"):
                continue
            if name in (".DS_Store", "._.DS_Store"):
                continue
            rel = child.relative_to(root).as_posix()
            if child.is_symlink():
                entries.append(ResourceEntry(path=rel, size=0, symlink=os.readlink(child)))
                continue
            size, sha1, sha256 = _hash_file(child)
            entries.append(ResourceEntry(path=rel, size=size, sha1=sha1, sha256=sha256))
    entries.sort(key=lambda item: item.path)
    return entries


def render_code_resources(entries: Sequence[ResourceEntry]) -> bytes:
    """Serialise the resource envelope as the plist ``codesign`` writes."""
    files: Dict[str, object] = {}
    files2: Dict[str, object] = {}
    for entry in entries:
        if entry.symlink is not None:
            files[entry.path] = {"symlink": entry.symlink}
            files2[entry.path] = {"symlink": entry.symlink}
            continue
        record: Dict[str, object] = {}
        if entry.sha1 is not None:
            record["hash"] = entry.sha1
        if entry.sha256 is not None:
            record["hash2"] = entry.sha256
        files[entry.path] = {"hash": entry.sha1} if entry.sha1 else record
        files2[entry.path] = {"hash2": entry.sha256} if entry.sha256 else record

    payload = {
        "files": files,
        "files2": files2,
        "rules": dict(_STANDARD_RULES),
        "rules2": dict(_STANDARD_RULES),
    }
    return plistlib.dumps(payload, fmt=plistlib.FMT_XML, sort_keys=True)


def build_code_resources(
    root: Path,
    *,
    executable: Optional[Path] = None,
    skip_dirs: Iterable[Path] = (),
) -> tuple[bytes, List[ResourceEntry]]:
    entries = collect_resources(root, executable=executable, skip_dirs=skip_dirs)
    return render_code_resources(entries), entries
