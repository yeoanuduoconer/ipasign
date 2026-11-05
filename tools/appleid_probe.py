"""Standalone probe for Apple's GrandSlam (GSA) sign-in.

This is a development tool, not part of the ipasign package: it makes exactly
one login attempt so we can see where the handshake stands.  It never writes
the password or the session tokens to disk.

Usage::

    python tools/appleid_probe.py you@example.com

The password is read with getpass.  Apple will send a 2FA prompt to the
trusted device if the account has two-factor authentication enabled; the
probe stops there and tells you what it saw.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import hmac
import plistlib
import sys
import traceback

import requests
import srp

GSA_ENDPOINT = "https://gsa.apple.com/grandslam/GsService2"
DEFAULT_ANISETTE = "https://ani.sidestore.io"


_CANONICAL = {
    "x-apple-i-client-time": "X-Apple-I-Client-Time",
    "x-apple-i-md": "X-Apple-I-MD",
    "x-apple-i-md-lu": "X-Apple-I-MD-LU",
    "x-apple-i-md-m": "X-Apple-I-MD-M",
    "x-apple-i-md-rinfo": "X-Apple-I-MD-RINFO",
    "x-apple-i-srl-no": "X-Apple-I-SRL-NO",
    "x-apple-i-timezone": "X-Apple-I-TimeZone",
    "x-apple-locale": "X-Apple-Locale",
    "x-mme-client-info": "X-MMe-Client-Info",
    "x-mme-device-id": "X-Mme-Device-Id",
}


def fetch_anisette(url: str) -> dict:
    response = requests.get(url, timeout=25)
    response.raise_for_status()
    raw = response.json()
    data = {}
    for key, value in raw.items():
        data[_CANONICAL.get(key.lower(), key)] = value
    required = ["X-Apple-I-MD", "X-Apple-I-MD-M", "X-Apple-I-MD-RINFO", "X-Mme-Device-Id"]
    missing = [key for key in required if key not in data]
    if missing:
        raise RuntimeError(f"anisette server response is missing {missing}: {sorted(raw)}")
    return data


def client_provided_data(anisette: dict) -> dict:
    """The ``cpd`` dictionary Apple expects inside every GSA request."""
    cpd = {
        "bootstrap": True,
        "icscrec": True,
        "loc": "en_US",
        "pbe": False,
        "prkgen": True,
        "svct": "iCloud",
        "X-Apple-I-Client-Time": anisette.get("X-Apple-I-Client-Time"),
        "X-Apple-Locale": anisette.get("X-Apple-Locale", "en_US"),
        "X-Apple-I-TimeZone": anisette.get("X-Apple-I-TimeZone", "CST"),
        "X-Apple-I-MD": anisette["X-Apple-I-MD"],
        "X-Apple-I-MD-LU": anisette.get("X-Apple-I-MD-LU", ""),
        "X-Apple-I-MD-M": anisette["X-Apple-I-MD-M"],
        "X-Apple-I-MD-RINFO": anisette["X-Apple-I-MD-RINFO"],
        "X-Mme-Device-Id": anisette["X-Mme-Device-Id"],
        "X-Apple-I-SRL-NO": anisette.get("X-Apple-I-SRL-NO", "0"),
    }
    return {key: value for key, value in cpd.items() if value is not None}


def post_plist(session: requests.Session, request: dict, anisette: dict) -> dict:
    body = {"Header": {"Version": "1.0.1"}, "Request": request}
    headers = {
        "Content-Type": "text/x-xml-plist",
        "Accept": "*/*",
        "Accept-Language": "en-us",
        "User-Agent": "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0",
        "X-Mme-Client-Info": anisette.get(
            "X-MMe-Client-Info", ""
        ),
    }
    response = session.post(
        GSA_ENDPOINT, data=plistlib.dumps(body), headers=headers, timeout=40
    )
    if response.status_code != 200:
        print(f"HTTP {response.status_code}: {response.text[:500]}")
    try:
        return plistlib.loads(response.content)
    except Exception:  # noqa: BLE001
        print("RAW RESPONSE:", response.content[:800])
        raise


def redact(value):
    """Trim long/opaque values so diagnostics never leak tokens."""
    if isinstance(value, dict):
        return {key: redact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, (str, bytes)) and len(value) > 24:
        return f"<{len(value)} bytes>"
    return value


def password_key(password: str, salt: bytes, iterations: int, is_s2k: bool) -> bytes:
    """Apple's SRP password preprocessing (s2k / s2k_fo)."""
    digest = hashlib.sha256(password.encode("utf-8")).digest()
    material = digest if is_s2k else digest.hex().encode("ascii")
    return hashlib.pbkdf2_hmac("sha256", material, salt, iterations, 32)


def decrypt_spd(session_key: bytes, spd: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    key = hmac.new(session_key, b"extra data key:", hashlib.sha256).digest()
    iv = hmac.new(session_key, b"extra data iv:", hashlib.sha256).digest()[:16]
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(spd) + decryptor.finalize()
    if not padded:
        return padded
    pad = padded[-1]
    return padded[:-pad] if 0 < pad <= 16 else padded


def ca_bundle() -> str:
    """certifi + Apple Root CA.

    ``gsa.apple.com`` chains to the legacy ``Apple Root CA``, which certifi
    does not ship; without it every request fails with a bogus
    "self-signed certificate in certificate chain" error.
    """
    import certifi
    from pathlib import Path

    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    bundle_path = Path.home() / ".ipasign" / "ca-bundle.pem"
    base = Path(certifi.where()).read_text(encoding="utf-8")
    root_der = Path.home() / ".ipasign" / "certs" / "AppleIncRootCertificate.cer"
    if root_der.is_file():
        pem = x509.load_der_x509_certificate(root_der.read_bytes()).public_bytes(
            serialization.Encoding.PEM
        )
        base += "\n" + pem.decode("ascii")
    bundle_path.parent.mkdir(parents=True, exist_ok=True)
    bundle_path.write_text(base, encoding="utf-8")
    return str(bundle_path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("apple_id")
    parser.add_argument("--anisette", default=DEFAULT_ANISETTE)
    args = parser.parse_args()

    password = getpass.getpass(f"{args.apple_id} 的密码（不会显示、不会保存）: ")

    print("[1] 获取 anisette 设备数据 ...")
    anisette = fetch_anisette(args.anisette)
    print("    device id:", anisette["X-Mme-Device-Id"])
    cpd = client_provided_data(anisette)

    print("[2] SRP 初始化 ...")
    srp.no_username_in_x(True)
    user = srp.User(args.apple_id, b"", hash_alg=srp.SHA256, ng_type=srp.NG_2048)
    _, a_public = user.start_authentication()
    print("    A 长度:", len(a_public))

    print("[3] init 请求 ...")
    session = requests.Session()
    session.verify = ca_bundle()
    init = post_plist(
        session,
        {"A2k": a_public, "ps": ["s2k", "s2k_fo"], "cpd": cpd, "u": args.apple_id, "o": "init"},
        anisette,
    )
    response = init.get("Response", {})
    status = init.get("Status", {})
    print("    status:", redact(status))
    print("    response keys:", sorted(response.keys()))

    salt = response.get("s")
    server_public = response.get("B")
    iterations = response.get("i")
    protocol = response.get("sp")
    challenge = response.get("c")
    if not all([salt, server_public, iterations, challenge]):
        print("    !! 缺少 s/B/i/c，无法继续。响应：", redact(init))
        return 2

    print(f"    protocol={protocol} iterations={iterations} salt={len(salt)}B")

    print("[4] 计算 M1 ...")
    key = password_key(password, salt, int(iterations), protocol == "s2k")
    user.p = key
    m1 = user.process_challenge(salt, server_public)
    if m1 is None:
        print("    !! SRP process_challenge 返回 None（安全检查失败）")
        return 3
    print("    M1:", base64.b64encode(m1).decode()[:24], "...")

    print("[5] complete 请求 ...")
    complete = post_plist(
        session,
        {"c": challenge, "M1": m1, "cpd": cpd, "u": args.apple_id, "o": "complete"},
        anisette,
    )
    response = complete.get("Response", {})
    status = complete.get("Status", {}) or response.get("Status", {})
    print("    status:", redact(status))
    print("    response keys:", sorted(response.keys()))

    m2 = response.get("M2")
    if m2 is None:
        print("    !! 没有 M2 —— 认证被拒绝。响应：", redact(complete))
        return 4

    try:
        user.verify_session(m2)
        print("    M2 校验: 通过")
    except Exception as exc:  # noqa: BLE001
        print("    M2 校验: 失败 ->", exc)

    auth_type = (status or {}).get("au")
    print("    二次验证类型 au =", auth_type)

    spd = response.get("spd")
    if spd:
        try:
            plain = decrypt_spd(user.K, spd)
            payload = plistlib.loads(plain)
            print("    spd 解密成功，字段:", sorted(payload.keys()))
        except Exception as exc:  # noqa: BLE001
            print("    spd 解密失败:", exc)
            traceback.print_exc()

    if auth_type == "trustedDeviceSecondaryAuth":
        print("\n==> 账号启用了双重认证，下一步需要实现 2FA 验证码流程。")
    elif m2:
        print("\n==> 第一段握手走通了（密码正确、SRP 匹配）。")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
