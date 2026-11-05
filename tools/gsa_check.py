"""One-shot GrandSlam init check against the *local* anisette server.

Run it after the IP has cooled down:

    python tools/gsa_check.py you@example.com

It performs exactly one request (init), so it will not burn through Apple's
rate limit.  Exit codes:

    0  Apple accepted the request (s/B/i returned)
    2  local anisette server unreachable
    3  Apple returned an error status
    4  Apple returned HTTP 503 (IP still blocked, wait longer)
"""

from __future__ import annotations

import argparse
import plistlib
import sys

import requests

sys.path.insert(0, __file__.rsplit("\\", 1)[0])
import appleid_probe as probe  # noqa: E402
import srp  # noqa: E402

ENDPOINT = "https://gsa.apple.com/grandslam/GsService2"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("apple_id")
    parser.add_argument("--anisette", default="http://127.0.0.1:6969")
    args = parser.parse_args()

    try:
        anisette = probe.fetch_anisette(args.anisette)
    except Exception as exc:  # noqa: BLE001
        print(f"[!] 本地 anisette 服务不可用: {exc}")
        print(r"    先运行 E:\tools\ipasign\anisette\start-anisette.cmd")
        return 2

    cpd = probe.client_provided_data(anisette)
    srp.no_username_in_x(True)
    user = srp.User(args.apple_id, b"", hash_alg=srp.SHA256, ng_type=srp.NG_2048)
    _, a_public = user.start_authentication()

    session = requests.Session()
    session.verify = probe.ca_bundle()
    body = {
        "Header": {"Version": "1.0.1"},
        "Request": {
            "A2k": a_public,
            "ps": ["s2k", "s2k_fo"],
            "cpd": cpd,
            "u": args.apple_id,
            "o": "init",
        },
    }
    response = session.post(
        ENDPOINT,
        data=plistlib.dumps(body),
        headers={
            "Content-Type": "text/x-xml-plist",
            "Accept": "*/*",
            "X-MMe-Client-Info": anisette.get("X-MMe-Client-Info", ""),
            "User-Agent": "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0",
        },
        timeout=40,
    )
    print("HTTP", response.status_code, "| device:", anisette["X-Mme-Device-Id"])
    if response.status_code == 503:
        print("[!] Apple 仍在 503 限流，等 30-60 分钟再试，或换手机热点。")
        return 4
    if response.status_code != 200:
        print(response.content[:400])
        return 3

    payload = plistlib.loads(response.content)
    reply = payload.get("Response", {})
    status = reply.get("Status", {})
    message = status.get("em")
    if isinstance(message, bytes):
        message = message.decode("utf-8", "replace")
    print("Status:", {"ec": status.get("ec"), "em": message})
    print("Response keys:", sorted(reply.keys()))
    if reply.get("s") and reply.get("B") and reply.get("c"):
        print("[OK] Apple 接受了请求，返回了 SRP 挑战（s/B/c）。")
        return 0
    print("[!] Apple 拒绝了请求。")
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
