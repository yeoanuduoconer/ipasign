"""Try GSA init with different client-info strings to isolate -22409."""

import datetime as dt
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
from ipasign.anisette.native import AnisetteProfile  # noqa: E402
from ipasign.anisette.provision import INFO_PATH, device_id, local_user_uuid  # noqa: E402

ACCOUNT = "you@example.com"
ADI = Path.home() / ".ipasign" / "anisette" / "adi.pb"

MAC = "<MacBookPro15,2> <macOS;26.3;25D125> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>"
WIN = "<PC> <Windows;6.2(0,0);9200> <com.apple.AuthKitWin/1 (com.apple.iCloud/1)>"


def attempt(client_info: str, user_agent: str, ser_no: str | None) -> None:
    with AnisetteProfile(ADI) as profile:
        otp = profile.otp_base64()
        machine = profile.machine_id_base64
    info = json.loads(INFO_PATH.read_text(encoding="utf-8"))
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    anisette = {
        "X-Apple-I-MD": otp,
        "X-Apple-I-MD-M": machine,
        "X-Apple-I-MD-LU": local_user_uuid(),
        "X-Apple-I-MD-RINFO": info["routing_info"],
        "X-Mme-Device-Id": device_id(),
        "X-Apple-I-Client-Time": now,
        "X-Apple-Locale": "en_US",
        "X-Apple-I-TimeZone": "GMT",
        "X-MMe-Client-Info": client_info,
        "X-Apple-I-SRL-NO": ser_no,
    }
    cpd = probe.client_provided_data(anisette)
    srp.no_username_in_x(True)
    user = srp.User(ACCOUNT, b"", hash_alg=srp.SHA256, ng_type=srp.NG_2048)
    _, public = user.start_authentication()
    session = requests.Session()
    session.verify = probe.ca_bundle()
    body = {
        "Header": {"Version": "1.0.1"},
        "Request": {
            "A2k": public,
            "ps": ["s2k", "s2k_fo"],
            "cpd": cpd,
            "u": ACCOUNT,
            "o": "init",
        },
    }
    response = session.post(
        "https://gsa.apple.com/grandslam/GsService2",
        data=plistlib.dumps(body),
        headers={
            "Content-Type": "text/x-xml-plist",
            "Accept": "*/*",
            "User-Agent": user_agent,
            "X-MMe-Client-Info": client_info,
            "X-Mme-Device-Id": anisette["X-Mme-Device-Id"],
        },
        timeout=40,
    )
    reply = plistlib.loads(response.content).get("Response", {})
    status = reply.get("Status", {})
    label = client_info[:34]
    print(
        f"  {label:36} ser={str(ser_no):14} ec={status.get('ec')} "
        f"em={str(status.get('em'))[:40]} challenge={bool(reply.get('s'))}"
    )


if __name__ == "__main__":
    attempts = [
        (WIN, "iCloud/7.4", None),
        (WIN, "iCloud/7.4", "W00000000001"),
        (MAC, "Xcode", None),
        (MAC, "Xcode", "C02X00000000"),
    ]
    for client_info, user_agent, serial in attempts:
        try:
            attempt(client_info, user_agent, serial)
        except Exception as error:  # noqa: BLE001
            print("  error:", error)
