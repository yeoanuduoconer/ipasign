"""Optional fallback engine that drives the ``zsign`` command line tool.

The native engine is self-contained; this backend exists for the rare app
whose binaries cannot be rewritten natively (for example code without a
``LC_CODE_SIGNATURE`` load command and no header room to add one).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

from .errors import IpasignError


def find_zsign(explicit: Optional[str] = None) -> Optional[str]:
    """Locate a ``zsign`` executable."""
    candidates: List[Optional[str]] = [
        explicit,
        os.environ.get("ZSIGN"),
        shutil.which("zsign"),
        shutil.which("zsign.exe"),
    ]
    suffix = ".exe" if sys.platform == "win32" else ""
    candidates.append(str(Path.home() / ".ipasign" / "bin" / f"zsign{suffix}"))
    candidates.append(str(Path(__file__).resolve().parent.parent / "bin" / f"zsign{suffix}"))
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return str(candidate)
    return None


def sign_with_zsign(
    input_ipa: Path,
    output_ipa: Path,
    *,
    p12: Optional[Path] = None,
    password: Optional[str] = None,
    profile: Optional[Path] = None,
    bundle_id: Optional[str] = None,
    entitlements: Optional[Path] = None,
    ad_hoc: bool = False,
    zsign: Optional[str] = None,
    log=print,
) -> None:
    executable = find_zsign(zsign)
    if executable is None:
        raise IpasignError(
            "找不到 zsign 可执行文件；请用 --zsign 指定路径，或从 "
            "https://github.com/zhlynn/zsign/releases 下载后放入 ~/.ipasign/bin/"
        )

    command = [executable, "-o", str(output_ipa), "-z", "9"]
    if ad_hoc:
        command.append("-a")
    else:
        if not p12 or not profile:
            raise IpasignError("zsign 引擎需要 p12 与描述文件")
        command += ["-k", str(p12), "-m", str(profile)]
        if password:
            command += ["-p", password]
    if bundle_id:
        command += ["-b", bundle_id]
    if entitlements:
        command += ["-e", str(entitlements)]
    command.append(str(input_ipa))

    log("调用 zsign: " + " ".join(command))
    process = subprocess.run(
        command, capture_output=True, text=True,
        encoding="utf-8", errors="replace",
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    for line in (process.stdout or "").splitlines():
        log(line)
    if process.returncode != 0:
        detail = (process.stderr or process.stdout or "").strip()
        raise IpasignError(f"zsign 执行失败 (exit {process.returncode}): {detail}")
    if not output_ipa.is_file():
        raise IpasignError("zsign 未生成输出文件")
