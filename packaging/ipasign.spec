# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec: a single-file ipasign executable.

Build with::

    pyinstaller --noconfirm --clean packaging/ipasign.spec

The result is ``dist/ipasign.exe`` (Windows) or ``dist/ipasign`` (macOS/Linux)
and needs no Python, no compiler and no pip on the target machine.
"""

from pathlib import Path

from PyInstaller.utils.hooks import collect_all

ROOT = Path(SPECPATH).parent          # noqa: F821 - provided by PyInstaller

datas = [(str(ROOT / "ipasign" / "native"), "ipasign/native")]
binaries = []
hiddenimports = []

# pymobiledevice3 pulls in a lot of dynamic imports; collect it wholesale.
for package in ("pymobiledevice3",):
    pkg_datas, pkg_binaries, pkg_hidden = collect_all(package)
    datas += pkg_datas
    binaries += pkg_binaries
    hiddenimports += pkg_hidden

hiddenimports += [
    "ipasign.vendor.apple_auth",
    "ipasign.vendor.apple_auth.device",
    "ipasign.vendor.apple_auth.native",
    "ipasign.vendor.apple_auth.models",
    "ipasign.vendor.apple_auth.crypto",
    "ipasign.tui",
    "ipasign.apple.anisette.provision",
    "ipasign.core.zsign_backend",
]

a = Analysis(  # noqa: F821
    [str(ROOT / "packaging" / "entry.py")],
    pathex=[str(ROOT)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "numpy", "pandas", "PyQt5", "PySide6"],
    noarchive=False,
)

pyz = PYZ(a.pure)  # noqa: F821

exe = EXE(  # noqa: F821
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="ipasign",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
