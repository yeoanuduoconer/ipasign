"""Device discovery and IPA installation.

The heavy lifting is delegated to `pymobiledevice3`, which speaks the same
usbmux/lockdown/installation_proxy protocols as libimobiledevice.  On Windows
it talks to Apple's *Apple Mobile Device Service*, so iTunes (or the Apple
Devices app) must be installed and the phone must be unlocked and trusted.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import time
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from ipasign.core.errors import IpasignError


class DeviceError(IpasignError):
    """Raised when no device is reachable or installation fails."""


@dataclass
class DeviceInfo:
    udid: str
    name: str = ""
    product_type: str = ""
    ios_version: str = ""
    connection: str = ""
    paired: bool = False
    extra: dict = field(default_factory=dict)

    def label(self) -> str:
        bits = [self.name or "未命名设备", self.product_type or "?", f"iOS {self.ios_version or '?'}"]
        return " / ".join(bits)


def library_available() -> bool:
    import importlib.util

    return importlib.util.find_spec("pymobiledevice3") is not None


def _require_library() -> None:
    if not library_available():
        raise DeviceError(
            "缺少 pymobiledevice3，无法与手机通信。安装：\n"
            "  python -m pip install pymobiledevice3"
        )


def _cli(*args: str, timeout: int = 120) -> subprocess.CompletedProcess:
    command = [sys.executable, "-m", "pymobiledevice3", *args]
    return subprocess.run(
        command, capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=timeout, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


def list_devices() -> List[DeviceInfo]:
    """Return every device visible over USB or Wi-Fi (empty list when none)."""
    _require_library()
    try:
        return asyncio.run(_list_devices_async())
    except Exception:  # noqa: BLE001 - older/newer API shapes, fall back to the CLI
        return _list_via_cli()


async def _list_devices_async() -> List[DeviceInfo]:
    from pymobiledevice3.lockdown import create_using_usbmux
    from pymobiledevice3.usbmux import list_devices as mux_list

    entries = await mux_list()
    devices: List[DeviceInfo] = []
    for entry in entries:
        serial = str(getattr(entry, "serial", "") or "")
        if not serial:
            continue
        connection = getattr(entry, "connection_type", "") or ""
        if hasattr(connection, "name"):
            connection = connection.name
        info = DeviceInfo(udid=serial, connection=str(connection))
        try:
            client = await create_using_usbmux(serial=serial)
            info.name = str(await client.get_value(key="DeviceName") or "")
            info.product_type = str(await client.get_value(key="ProductType") or "")
            info.ios_version = str(await client.get_value(key="ProductVersion") or "")
            info.paired = True
        except Exception as exc:  # noqa: BLE001 - untrusted / locked device
            info.extra["pairing_error"] = str(exc)
        devices.append(info)
    return devices


def _list_via_cli() -> List[DeviceInfo]:
    process = _cli("usbmux", "list")
    if process.returncode != 0:
        return []
    try:
        payload = json.loads(process.stdout or "[]")
    except json.JSONDecodeError:
        return []
    devices = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        devices.append(
            DeviceInfo(
                udid=str(item.get("serial") or item.get("udid") or ""),
                connection=str(item.get("connection_type") or ""),
            )
        )
    return [device for device in devices if device.udid]


_FRIENDLY_ERRORS = {
    "could not connect": "连不上手机：检查数据线、解锁屏幕、在手机上点「信任此电脑」",
    "pairing": "设备未配对：解锁手机，点「信任此电脑」，然后重试",
    "invalid host id": "配对记录失效：在手机上「设置 → 通用 → 传输或还原 → 还原位置与隐私」后重新信任",
    "applicationverificationfailed": "iOS 拒绝了这个签名：证书/描述文件不匹配，或设备未注册",
    "device is locked": "手机处于锁屏状态，解锁后重试",
    "no device": "没有检测到设备：用数据线连接手机并解锁",
}


def friendly_error(message: str) -> str:
    lowered = message.lower()
    for needle, hint in _FRIENDLY_ERRORS.items():
        if needle in lowered:
            return f"{hint}\n原始信息：{message.strip()[:400]}"
    return message.strip()[:600]


def install_ipa(
    ipa_path: "str | Path",
    *,
    udid: Optional[str] = None,
    developer: bool = False,
    log=lambda message: None,
) -> str:
    """Install *ipa_path* on a connected device; returns the target UDID."""
    _require_library()
    path = Path(ipa_path)
    if not path.is_file():
        raise DeviceError(f"找不到 IPA：{path}")
    if path.suffix.lower() not in (".ipa", ".app"):
        raise DeviceError("只支持 .ipa 或 .app")

    devices = list_devices()
    if not devices:
        raise DeviceError(
            "没有检测到设备。请确认：\n"
            "  1) 手机用数据线连上电脑；\n"
            "  2) 手机解锁，并在弹窗里点「信任」；\n"
            "  3) iTunes / Apple Devices 已安装（提供 Apple Mobile Device Service）。"
        )
    if udid is None:
        if len(devices) > 1:
            raise DeviceError(
                "检测到多台设备，请用 --udid 指定：\n"
                + "\n".join(f"  {device.udid}  {device.label()}" for device in devices)
            )
        udid = devices[0].udid
    target = next((device for device in devices if device.udid == udid), None)
    if target is not None:
        log(f"目标设备: {target.label()} ({target.udid})")

    command = [sys.executable, "-m", "pymobiledevice3", "apps", "install", str(path)]
    if udid:
        command += ["--udid", udid]
    if developer:
        command.append("--developer")
    log("上传并安装中（大文件需要几分钟）...")
    process = subprocess.run(
        command, capture_output=True, text=True, encoding="utf-8", errors="replace",
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    for line in (process.stdout or "").splitlines():
        log(line)
    if process.returncode != 0:
        detail = (process.stderr or process.stdout or "").strip()
        # pymobiledevice3 prints progress lines before the actual failure; keep
        # the last error-looking line so the message is not truncated mid-way.
        interesting = [
            line for line in detail.splitlines()
            if "ERROR" in line or "Error Domain" in line or "error:" in line
        ]
        if interesting:
            detail = interesting[-1]
        raise DeviceError(friendly_error(detail))

    _confirm_installed(path, udid, log=log)
    return udid


# ---------------------------------------------------------------------------
# Post-install confirmation
# ---------------------------------------------------------------------------

def _ipa_metadata(path: Path) -> "tuple[str, str]":
    """Read the IPA's bundle id and signing team without extracting it."""
    import plistlib
    import zipfile

    from ipasign.core.profile import ProvisioningProfile

    if path.suffix.lower() != ".ipa":
        return "", ""
    bundle_id = ""
    team_id = ""
    try:
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            info_name = next(
                (
                    name
                    for name in names
                    if name.startswith("Payload/")
                    and name.count("/") == 2
                    and name.endswith("/Info.plist")
                ),
                None,
            )
            if info_name is None:
                return "", ""
            info = plistlib.loads(archive.read(info_name))
            bundle_id = str(info.get("CFBundleIdentifier") or "")
            profile_name = info_name[: -len("Info.plist")] + "embedded.mobileprovision"
            if profile_name in names:
                team_id = ProvisioningProfile.parse(archive.read(profile_name)).team_id
    except Exception:  # noqa: BLE001 - best effort only
        return bundle_id, team_id
    return bundle_id, team_id


def _installed_app(udid: str, bundle_id: str) -> "dict | None":
    process = subprocess.run(
        [sys.executable, "-m", "pymobiledevice3", "apps", "list", "--udid", udid],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if process.returncode != 0:
        return None
    try:
        payload = json.loads(process.stdout[process.stdout.find("{"):])
    except (ValueError, json.JSONDecodeError):
        return None
    return payload.get(bundle_id)


def _confirm_installed(path: Path, udid: str, log=lambda message: None) -> None:
    """Verify the app really landed, and explain the common silent failures.

    ``installation_proxy`` can return success while iOS keeps an existing app
    with the same bundle id (for example the App Store build), which looks
    like "installed" but nothing changes on the home screen.
    """
    if path.suffix.lower() != ".ipa":
        return
    bundle_id, expected_team = _ipa_metadata(path)
    if not bundle_id:
        return
    app = None
    for _ in range(5):
        app = _installed_app(udid, bundle_id)
        if app is not None:
            break
        time.sleep(2)
    if app is None:
        raise DeviceError(
            f"系统报告安装完成，但设备上查不到 {bundle_id}。\n"
            "常见原因：签名校验未通过（证书与描述文件不匹配 / 证书被吊销）、"
            "或设备存储空间不足。"
        )
    installed_team = str(
        (app.get("Entitlements") or {}).get("com.apple.developer.team-identifier", "")
    )
    if expected_team and installed_team and expected_team != installed_team:
        signer = app.get("SignerIdentity", "未知")
        raise DeviceError(
            f"设备上的 {bundle_id} 属于另一个签名方（team {installed_team}，{signer}），"
            "本次安装没有覆盖它。\n"
            "这通常意味着设备上已经装了同 Bundle ID 的 App Store 版本；"
            "要安装当前这个包，需要先卸载设备上的同名 App。"
        )
    log(f"确认已安装: {bundle_id}")


def restart_device(udid: str, log=lambda message: None) -> None:
    """Reboot the device (useful after installing a developer app)."""
    process = _cli("diagnostics", "restart", "--udid", udid, timeout=60)
    if process.returncode != 0:
        raise DeviceError(friendly_error(process.stderr or process.stdout))
