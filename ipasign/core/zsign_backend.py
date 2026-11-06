"""Optional zsign backend.

Our own signing engine is the default, but some app bundles (currently seen
with Fat/universal frameworks plus loose dylibs) are still rejected by iOS
with ``0xe8008019`` even though the signature verifies locally and with
OpenSSL.  Until that gap is closed, users can switch to ``zsign`` — an
independent GPLv3 implementation — for those packages.

zsign is *not* bundled: point ``IPASIGN_ZSIGN`` at the executable, or drop it
next to the other tools.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Optional

from ipasign import paths
from ipasign.core.errors import IpasignError




def find_zsign() -> Optional[Path]:
    explicit = os.environ.get("IPASIGN_ZSIGN")
    if explicit:
        path = Path(explicit)
        return path if path.is_file() else None
    return paths.find_tool("zsign.exe", "zsign")


def bundle_id_for_profile(profile) -> Optional[str]:
    """Bundle id implied by an explicit App ID profile (None for wildcards)."""
    app_id = getattr(profile, "application_identifier", "") or ""
    if not app_id or app_id.endswith(".*"):
        return None
    teams = getattr(profile, "team_ids", None) or []
    team = teams[0] if teams else ""
    if team and app_id.startswith(team + "."):
        return app_id[len(team) + 1:]
    return app_id


def sign_with_zsign(
    input_ipa: "str | Path",
    output_ipa: "str | Path",
    *,
    p12: "str | Path",
    profile: "str | Path",
    password: Optional[str] = None,
    bundle_id: Optional[str] = None,
    log=print,
) -> Path:
    """Re-sign *input_ipa* with zsign and return the output path."""
    binary = find_zsign()
    if binary is None:
        raise IpasignError(
            "没有找到 zsign。下载 zsign 后设置 IPASIGN_ZSIGN 指向它，"
            "例如：\n  set IPASIGN_ZSIGN=D:\\tools\\zsign.exe"
        )
    command = [
        str(binary),
        "-k", str(p12),
        "-m", str(profile),
        "-o", str(output_ipa),
    ]
    if password:
        command += ["-p", password]
    if bundle_id:
        command += ["-b", bundle_id]
    command.append(str(input_ipa))

    log(f"zsign: {binary}")
    process = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    for line in (process.stdout or "").splitlines():
        log(line)
    if process.returncode != 0 or not Path(output_ipa).is_file():
        detail = (process.stderr or process.stdout or "").strip()[-600:]
        raise IpasignError(f"zsign 签名失败：{detail}")
    return Path(output_ipa)
