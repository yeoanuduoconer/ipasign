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
        bits = [self.name or "Unnamed device", self.product_type or "?", f"iOS {self.ios_version or '?'}"]
        return " / ".join(bits)

    @property
    def transport(self) -> str:
        """`usb` / `wifi` / `unknown`, normalised from usbmuxd."""
        value = (self.connection or "").lower()
        if "usb" in value:
            return "usb"
        if "network" in value or "wifi" in value or "wlan" in value:
            return "wifi"
        return "unknown"

    @property
    def is_wifi(self) -> bool:
        return self.transport == "wifi"


def library_available() -> bool:
    import importlib.util

    return importlib.util.find_spec("pymobiledevice3") is not None


def _require_library() -> None:
    if not library_available():
        raise DeviceError(
            "pymobiledevice3 is missing; cannot talk to the phone. Install it with:\n"
            "  python -m pip install pymobiledevice3"
        )


def _cli(*args: str, timeout: int = 120) -> subprocess.CompletedProcess:
    command = [sys.executable, "-m", "pymobiledevice3", *args]
    return subprocess.run(
        command, capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=timeout, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


def list_devices(wifi: Optional[bool] = None) -> List[DeviceInfo]:
    """Devices visible to usbmuxd (USB and Wi-Fi).

    `wifi=True` keeps network devices only, `wifi=False` USB only;
    `None` returns both.
    """
    _require_library()
    try:
        devices = asyncio.run(_list_devices_async())
    except Exception:  # noqa: BLE001 - older/newer API shapes, fall back to the CLI
        devices = _list_via_cli()
    if wifi is True:
        return [device for device in devices if device.is_wifi]
    if wifi is False:
        return [device for device in devices if not device.is_wifi]
    return devices


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


def _list_via_cli(network_only: bool = False) -> List[DeviceInfo]:
    args = ["usbmux", "list"] + (["--network"] if network_only else [])
    process = _cli(*args)
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
    "could not connect": (
        "cannot reach the phone: check the cable, unlock the screen and tap "
        "'Trust This Computer' on the phone"
    ),
    "pairing": (
        "the device is not paired: unlock the phone, tap 'Trust This Computer', "
        "then retry"
    ),
    "invalid host id": (
        "the pairing record is stale: on the phone go to Settings → General → "
        "Transfer or Reset → Reset Location & Privacy, then trust again"
    ),
    "applicationverificationfailed": (
        "iOS rejected the signature: certificate/profile mismatch, or the device "
        "is not registered"
    ),
    "device is locked": "the phone is locked; unlock it and retry",
    "no device": "no device detected: connect the phone with a cable and unlock it",
}


def friendly_error(message: str) -> str:
    lowered = message.lower()
    for needle, hint in _FRIENDLY_ERRORS.items():
        if needle in lowered:
            return f"{hint}\nOriginal message: {message.strip()[:400]}"
    return message.strip()[:600]


def install_ipa(
    ipa_path: "str | Path",
    *,
    udid: Optional[str] = None,
    developer: bool = False,
    wifi: bool = False,
    log=lambda message: None,
) -> str:
    """Install *ipa_path* on a connected device; returns the target UDID.

    With `wifi=True` the device must already be paired for Wi-Fi sync, i.e.
    usbmuxd has to list it as a network device; the transfer itself then goes
    over the air with no cable attached.
    """
    _require_library()
    path = Path(ipa_path)
    if not path.is_file():
        raise DeviceError(f"IPA not found: {path}")
    if path.suffix.lower() not in (".ipa", ".app"):
        raise DeviceError("only .ipa or .app is supported")

    devices = list_devices(wifi=True if wifi else None)
    if not devices and wifi:
        raise DeviceError(
            "No device reachable over Wi-Fi.\n"
            "  1) Connect the cable once and enable 'Sync over Wi-Fi' in iTunes (Windows) or Finder (macOS);\n"
            "  2) Keep the phone unlocked on the same network as the computer;\n"
            "  3) Unplug the cable; `ipasign devices --wifi` should now list it."
        )
    if not devices:
        raise DeviceError(
            "No device detected. Please make sure:\n"
            "  1) the phone is connected to the computer with a cable;\n"
            "  2) the phone is unlocked and you tapped Trust in the prompt;\n"
            "  3) iTunes / Apple Devices is installed (it provides the Apple Mobile Device Service)."
        )
    if udid is None:
        if len(devices) > 1:
            raise DeviceError(
                "Multiple devices detected; pick one with --udid:\n"
                + "\n".join(f"  {device.udid}  {device.label()}" for device in devices)
            )
        udid = devices[0].udid
    target = next((device for device in devices if device.udid == udid), None)
    if target is not None:
        log(f"Target device: {target.label()} ({target.udid}, {target.transport})")

    log("Uploading and installing (large apps take a few minutes)...")
    api_error = None
    try:
        asyncio.run(_install_async(path, udid, developer))
    except Exception as error:  # noqa: BLE001
        api_error = error

    if api_error is not None and not getattr(sys, "frozen", False):
        # Source checkout: retry through the CLI, which reports progress.
        command = [sys.executable, "-m", "pymobiledevice3", "apps", "install", str(path)]
        if udid:
            command += ["--udid", udid]
        if developer:
            command.append("--developer")
        process = subprocess.run(
            command, capture_output=True, text=True, encoding="utf-8", errors="replace",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        for line in (process.stdout or "").splitlines():
            log(line)
        if process.returncode != 0:
            detail = (process.stderr or process.stdout or "").strip()
            interesting = [
                line for line in detail.splitlines()
                if "ERROR" in line or "Error Domain" in line or "error:" in line
            ]
            if interesting:
                detail = interesting[-1]
            raise DeviceError(friendly_error(detail))
    elif api_error is not None:
        raise DeviceError(friendly_error(str(api_error)))

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


async def _install_async(path: Path, udid: str, developer: bool) -> None:
    from pymobiledevice3.lockdown import create_using_usbmux
    from pymobiledevice3.services.installation_proxy import InstallationProxyService

    client = await create_using_usbmux(serial=udid)
    service = InstallationProxyService(client)
    try:
        await service.install_from_local(str(path), developer=developer)
    finally:
        await service.close()


async def _list_apps_async(udid: str) -> dict:
    from pymobiledevice3.lockdown import create_using_usbmux
    from pymobiledevice3.services.installation_proxy import InstallationProxyService

    client = await create_using_usbmux(serial=udid)
    service = InstallationProxyService(client)
    try:
        return await service.get_apps()
    finally:
        await service.close()

def _list_apps(udid: str) -> "dict | None":
    """Return the installed-app dictionary, or None when the query failed.

    The query fails while the device is locked or busy installing, which must
    not be confused with "the app is not installed".
    """
    try:
        return asyncio.run(_list_apps_async(udid))
    except Exception:  # noqa: BLE001 - fall back to the CLI in a source checkout
        pass
    if getattr(sys, "frozen", False):
        return None
    try:
        process = subprocess.run(
            [sys.executable, "-m", "pymobiledevice3", "apps", "list", "--udid", udid],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=60,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except subprocess.TimeoutExpired:
        return None
    if process.returncode != 0:
        return None
    try:
        return json.loads(process.stdout[process.stdout.find("{"):])
    except (ValueError, json.JSONDecodeError):
        return None


def _installed_app(udid: str, bundle_id: str) -> "dict | None":
    payload = _list_apps(udid)
    if payload is None:
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
    listed = False
    for attempt in range(10):
        payload = _list_apps(udid)
        if payload is not None:
            listed = True
            app = payload.get(bundle_id)
            if app is not None:
                break
        if attempt == 0:
            log("Waiting for the device to refresh its app list ...")
        time.sleep(2)
    if app is None:
        if not listed:
            raise DeviceError(
                "The install was submitted, but reading the device's app list failed "
                "(usually because the phone is locked or busy).\n"
                "Unlock the phone and run `ipasign devices` to confirm, or run the install again."
            )
        raise DeviceError(
            f"The system reported success, but {bundle_id} is not on the device.\n"
            "Common causes: the signature was rejected (certificate/profile mismatch, "
            "or a revoked certificate), or the device is out of storage."
        )
    installed_team = str(
        (app.get("Entitlements") or {}).get("com.apple.developer.team-identifier", "")
    )
    if expected_team and installed_team and expected_team != installed_team:
        signer = app.get("SignerIdentity", "unknown")
        raise DeviceError(
            f"The {bundle_id} on the device belongs to a different signer "
            f"(team {installed_team}, {signer}); this install did not replace it.\n"
            "This usually means the App Store build with the same Bundle ID is already "
            "installed; uninstall that app before installing this package."
        )
    log(f"Confirmed installed: {bundle_id}")


def restart_device(udid: str, log=lambda message: None) -> None:
    """Reboot the device (useful after installing a developer app)."""
    process = _cli("diagnostics", "restart", "--udid", udid, timeout=60)
    if process.returncode != 0:
        raise DeviceError(friendly_error(process.stderr or process.stdout))
