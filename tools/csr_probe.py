"""Dump the raw response of a developer-portal action."""

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

device = apple_auth_bridge.open_device()
headers = apple_auth_bridge.developer_headers(device, device.session)

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
csr = (
    x509.CertificateSigningRequestBuilder()
    .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "iPhone Developer")]))
    .sign(key, hashes.SHA256())
    .public_bytes(serialization.Encoding.PEM)
)

body = {
    "clientId": CLIENT_ID,
    "protocolVersion": PROTOCOL,
    "requestId": str(uuid.uuid4()).upper(),
    "userLocale": "en_US",
    "teamId": "TEAM123456",
    "csrContent": __import__("base64").b64encode(csr).decode(),
    "machineId": str(uuid.uuid4()).upper(),
    "machineName": "ipasign",
}
response = requests.post(
    f"{BASE}/ios/submitDevelopmentCSR.action?clientId={CLIENT_ID}",
    data=plistlib.dumps(body),
    headers={**headers, "Content-Type": "text/x-xml-plist"},
    timeout=60,
    verify=str(Path.home() / ".ipasign" / "ca-bundle.pem"),
)
print("HTTP", response.status_code, "| content-type:", response.headers.get("content-type"))
print("len:", len(response.content))
print(response.content[:600])
