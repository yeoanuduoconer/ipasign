"""GrandSlam init check using our own provisioned ADI (no anisette server).

    python tools/gsa_native_check.py you@example.com

Exit codes: 0 accepted, 2 local anisette missing, 3 rejected, 4 HTTP 503.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import plistlib
import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT))

import appleid_probe as probe  # noqa: E402
import srp  # noqa: E402
from ipasign.anisette.native import AnisetteProfile, default_adi  # noqa: E402
from ipasign.anisette.provision import (  # noqa: E402
    CLIENT_INFO,
    INFO_PATH,
    device_id,
    local_user_uuid,
)

ENDPOINT = "https://gsa.apple.com/grandslam/GsService2"


def anisette_headers() -> dict:
    info = json.loads(INFO_PATH.read_text(encoding="utf-8")) if INFO_PATH.is_file() else {}
    adi = ROOT / ".adi-placeholder"
    adi_path = default_adi()
    own = Path.home() / ".ipasign" / "anisette" / "adi.pb"
    if own.is_file():
        adi_path = own
    elif adi_path is None:
        raise SystemExit("no ADI available")
    with AnisetteProfile(adi_path) as profile:
        otp = profile.otp_base64()
        machine = profile.machine_id_base64
    now = _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return {
        "X-Apple-I-MD": otp,
        "X-Apple-I-MD-M": machine,
        "X-Apple-I-MD-LU": local_user_uuid(),
        "X-Apple-I-MD-RINFO": info.get("routing_info", 50660608),
        "X-Mme-Device-Id": device_id(),
        "X-Apple-I-Client-Time": now,
        "X-Apple-Locale": "en_US",
        "X-Apple-I-TimeZone": "GMT",
        "X-Apple-I-SRL-NO": "W00000000001",
        "X-MMe-Client-Info": CLIENT_INFO,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("apple_id")
    args = parser.parse_args()

    anisette = anisette_headers()
    cpd = probe.client_provided_data(anisette)
    srp.no_username_in_x(True)
    user = srp.User(args.apple_id, b"", hash_alg=srp.SHA256, ng_type=srp.NG_2048)
    _, a_public = user.start_authentication()

    session = requests.Session()
    session.verify = probe.ca_bundle()
    body = {
        "Header": {"Version": "1.0.1"},
        "Request": {"A2k": a_public, "ps": ["s2k", "s2k_fo"], "cpd": cpd, "u": args.apple_id, "o": "init"},
    }
    response = session.post(
        ENDPOINT,
        data=plistlib.dumps(body),
        headers={
            "Content-Type": "text/x-xml-plist",
            "Accept": "*/*",
            "User-Agent": "iCloud/7.4",
            "X-MMe-Client-Info": CLIENT_INFO,
            "X-Mme-Device-Id": anisette["X-Mme-Device-Id"],
        },
        timeout=40,
    )
    print("HTTP", response.status_code)
    if response.status_code == 503:
        print("[!] 503，Apple 限流")
        return 4
    if response.status_code != 200:
        print(response.content[:400])
        return 3

    payload = plistlib.loads(response.content)
    reply = payload.get("Response", {})
    status = reply.get("Status", {})
    print("Status:", {"ec": status.get("ec"), "em": status.get("em")})
    print("keys:", sorted(reply.keys()))
    if reply.get("s") and reply.get("B") and reply.get("c"):
        print("[OK] Apple 接受了我们自己的 OTP，返回 SRP 挑战。")
        return 0
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
