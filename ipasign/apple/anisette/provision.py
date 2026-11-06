"""Provision a fresh ADI (device attestation identity) for this machine.

Flow (reverse engineered from the MIT ``Provision`` client and confirmed
against Apple's live service)::

    GET  https://gsa.apple.com/grandslam/GsService2/lookup
         -> urls.midStartProvisioning / urls.midFinishProvisioning
    POST midStartProvisioning  {Header:{}, Request:{}}
         -> Response.spim  (base64 challenge)
    POST midFinishProvisioning {Header:{}, Request:{cpim: <base64>}}
         -> Response.ptm, Response.tk, Response["X-Apple-I-MD-RINFO"]

``aauth_provisioning_*`` in the native library turns (hw id, spim) into the
CPIM and (ptm, tk) back into an ADI profile.  The result is an ``adi.pb``
bound to *this* machine's hardware digest, which is exactly what the OTP
generator needs.
"""

from __future__ import annotations

from ipasign import paths

import base64
import datetime as _dt
import secrets
import http.cookiejar
import json
import plistlib
import ssl
import time
import urllib.request
import uuid
from pathlib import Path
from typing import Optional

from .native import AnisetteError, _Native, find_library

URL_BAG = "https://gsa.apple.com/grandslam/GsService2/lookup"
STATE_DIR = paths.data_dir() / "anisette"
ADI_PATH = STATE_DIR / "adi.pb"
INFO_PATH = STATE_DIR / "info.json"

CLIENT_INFO = "<PC> <Windows;6.2(0,0);9200> <com.apple.AuthKitWin/1 (com.apple.iCloud/1)>"
DEFAULT_CA = paths.data_dir() / "ca-bundle.pem"


class ProvisioningError(RuntimeError):
    """Raised when Apple rejects a provisioning step."""


def _ssl_context() -> ssl.SSLContext:
    # Apple's GSA chain terminates in the legacy Apple Root CA, which certifi
    # does not ship; our own combined bundle does.
    if DEFAULT_CA.is_file():
        return ssl.create_default_context(cafile=str(DEFAULT_CA))
    return ssl.create_default_context()


_LOCAL_UUID: Optional[str] = None


def local_user_uuid() -> str:
    """Stable per-machine value for X-Apple-I-MD-LU.

    The ADI is bound to the value used while provisioning, so it must survive
    process restarts; a fresh UUID makes GrandSlam answer -22409.
    """
    global _LOCAL_UUID
    if _LOCAL_UUID is None:
        path = STATE_DIR / "local-uuid.txt"
        if path.is_file():
            stored = path.read_text(encoding="utf-8").strip()
            if stored:
                _LOCAL_UUID = stored
                return _LOCAL_UUID
        _LOCAL_UUID = secrets.token_hex(20).upper()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(_LOCAL_UUID, encoding="utf-8")
    return _LOCAL_UUID


def device_id() -> str:
    """Stable X-Mme-Device-Id; Apple binds the provisioning entity to it."""
    path = STATE_DIR / "device-id.txt"
    if path.is_file():
        value = path.read_text(encoding="utf-8").strip()
        if value:
            return value
    value = str(uuid.uuid4()).upper()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")
    return value


def _headers() -> dict:
    return {
        # AuthKit really sends this even though the body is a plist.
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "*/*",
        "Connection": "keep-alive",
        "User-Agent": "iCloud/7.4",
        "X-Mme-Device-Id": device_id(),
        "X-Apple-I-Client-Time": _dt.datetime.now(_dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "X-Apple-Client-App-Name": "Setup",
        "X-MMe-Client-Info": CLIENT_INFO,
        "X-Apple-I-MD-LU": local_user_uuid(),
    }


_OPENER: Optional[urllib.request.OpenerDirector] = None


def _opener() -> urllib.request.OpenerDirector:
    # The start/finish exchange is stateful: Apple scopes the CPIM to the
    # session cookie handed out by startMachineProvisioning.
    global _OPENER
    if _OPENER is None:
        jar = http.cookiejar.CookieJar()
        _OPENER = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(jar),
            urllib.request.HTTPSHandler(context=_ssl_context()),
        )
    return _OPENER


def _request(url: str, payload: Optional[dict], log=print) -> dict:
    body = plistlib.dumps(payload, fmt=plistlib.FMT_XML) if payload else b""
    request = urllib.request.Request(url, data=body or None, headers=_headers())
    log(f"  -> {url}")
    try:
        response = _opener().open(request, timeout=60)
    except urllib.error.HTTPError as error:
        detail = error.read()[:600]
        raise ProvisioningError(
            f"HTTP {error.code} from {url}: {detail!r}"
        ) from error
    with response:
        raw = response.read()
        status = response.status
    if status != 200:
        raise ProvisioningError(f"HTTP {status} from {url}")
    if not raw:
        return {}
    try:
        return plistlib.loads(raw)
    except Exception as error:  # noqa: BLE001
        raise ProvisioningError(
            f"expected a plist from {url}, got {len(raw)} bytes"
        ) from error


def fetch_url_bag(log=print) -> dict:
    plist = _request(URL_BAG, None, log=log)
    urls = plist.get("urls") or {}
    if "midStartProvisioning" not in urls or "midFinishProvisioning" not in urls:
        raise ProvisioningError("GSA url bag is missing the mid provisioning endpoints")
    return urls


def provision(adi_path: Path = ADI_PATH, log=print) -> dict:
    """Provision a new ADI bound to this machine and write it to ``adi_path``."""
    native = _Native(find_library())
    hardware = native.hardware_id()
    log(f"hardware id: {hardware.hex()}")

    urls = fetch_url_bag(log=log)

    log("starting provisioning")
    start = _request(urls["midStartProvisioning"], {"Header": {}, "Request": {}}, log=log)
    try:
        spim = base64.b64decode(start["Response"]["spim"])
    except (KeyError, TypeError) as error:
        raise ProvisioningError(f"unexpected start response: {start}") from error
    log(f"spim: {len(spim)} bytes")

    session = native.provisioning_begin(spim, hardware, int(time.time()))
    try:
        cpim = native.provisioning_request(session)
        log(f"cpim: {len(cpim)} bytes")
        end = _request(
            urls["midFinishProvisioning"],
            {"Header": {}, "Request": {"cpim": base64.b64encode(cpim).decode()}},
            log=log,
        )
        response = end.get("Response") or {}
        if "ptm" not in response or "tk" not in response:
            raise ProvisioningError(f"unexpected finish response: {end}")
        ptm = base64.b64decode(response["ptm"])
        trust_key = base64.b64decode(response["tk"])
        log(f"ptm: {len(ptm)} bytes, trust key: {len(trust_key)} bytes")

        profile = native.provisioning_finish(session, ptm, trust_key)
        try:
            adi = native.export_profile(profile, hardware)
            machine_id = base64.b64encode(native.machine_id(profile)).decode()
        finally:
            native.free(profile)
    finally:
        native.lib.aauth_provisioning_free(session)

    adi_path.parent.mkdir(parents=True, exist_ok=True)
    adi_path.write_bytes(adi)
    info = {
        "hardware_id": hardware.hex(),
        "machine_id": machine_id,
        "routing_info": int(response.get("X-Apple-I-MD-RINFO", 0)),
        "adi_size": len(adi),
        "provisioned_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
    }
    INFO_PATH.write_text(json.dumps(info, indent=2), encoding="utf-8")
    log(f"ADI written: {adi_path} ({len(adi)} bytes), RINFO={info['routing_info']}")
    return info


if __name__ == "__main__":  # pragma: no cover - manual diagnostic
    print(json.dumps(provision(), indent=2))

