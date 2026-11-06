"""Try CSR encodings until Apple accepts one."""

import base64
import json
import os
import plistlib
import sys
import uuid
from pathlib import Path

os.environ["APPLE_AUTH_LIBRARY"] = r"E:\tools\ipasign\apple-auth-client\Release\apple_auth_client.dll"
sys.path.insert(0, r"E:\tools\ipasign\apple-auth-src\python")
sys.path.insert(0, r"C:\Users\you\source\repos\ipasign")

import requests  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from ipasign import apple_auth_bridge  # noqa: E402
from ipasign.developer import BASE, CLIENT_ID, PROTOCOL  # noqa: E402

TEAM = "TEAM123456"
device = apple_auth_bridge.open_device()
headers = apple_auth_bridge.developer_headers(device, device.session)


def make_csr(subject):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
    return builder.sign(key, hashes.SHA256())


def submit(label, csr_content, extra=None):
    body = {
        "clientId": CLIENT_ID,
        "protocolVersion": PROTOCOL,
        "requestId": str(uuid.uuid4()).upper(),
        "userLocale": "en_US",
        "teamId": TEAM,
        "csrContent": csr_content,
        "machineId": str(uuid.uuid4()).upper(),
        "machineName": "ipasign",
    }
    body.update(extra or {})
    response = requests.post(
        f"{BASE}/ios/submitDevelopmentCSR.action?clientId={CLIENT_ID}",
        data=plistlib.dumps(body),
        headers={**headers, "Content-Type": "text/x-xml-plist"},
        timeout=60,
        verify=str(Path.home() / ".ipasign" / "ca-bundle.pem"),
    )
    text = response.content.decode("utf-8", "replace")
    try:
        payload = json.loads(text)
        code, message = payload.get("resultCode"), payload.get("resultString")
    except Exception:  # noqa: BLE001
        code, message = "?", text[:80]
    print(f"  {label:34} HTTP {response.status_code} code={code} msg={message}")
    return code == 0


cn_only = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "iPhone Developer")])
full = x509.Name(
    [
        x509.NameAttribute(NameOID.COMMON_NAME, "iPhone Developer"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ipasign"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    ]
)
team_cn = x509.Name(
    [x509.NameAttribute(NameOID.COMMON_NAME, f"iPhone Developer: {TEAM}")]
)

for label, subject in (("cn-only", cn_only), ("full", full), ("team-cn", team_cn)):
    csr = make_csr(subject)
    pem = csr.public_bytes(serialization.Encoding.PEM)
    der = csr.public_bytes(serialization.Encoding.DER)
    submit(f"{label} b64(pem)", base64.b64encode(pem).decode())
    submit(f"{label} b64(der)", base64.b64encode(der).decode())
    submit(f"{label} raw pem", pem.decode())
