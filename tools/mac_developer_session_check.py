"""Try the developer-session exchange with a macOS device profile.

Reuses the saved account session (no password needed) but swaps the device
identity to macOS, which is what Xcode-shaped app-token requests expect.
"""

import os
import shutil
import sys
from pathlib import Path

os.environ["APPLE_AUTH_LIBRARY"] = r"E:\tools\ipasign\apple-auth-client\Release\apple_auth_client.dll"
sys.path.insert(0, r"E:\tools\ipasign\apple-auth-src\python")

from apple_auth import Device  # noqa: E402

SRC = Path.home() / ".ipasign" / "apple-auth-device"
DST = Path.home() / ".ipasign" / "apple-auth-mac"

DST.mkdir(parents=True, exist_ok=True)
for name in ("account-session.plist",):
    source = SRC / name
    if source.is_file():
        shutil.copy2(source, DST / name)
        print("copied", name)

device = Device.mac(str(DST))
print("platform:", device.info.platform)
print("session:", "yes" if device.session is not None else "no")
if device.session is None:
    raise SystemExit("no saved session loaded")

try:
    headers = device.developer_headers(device.developer_session(device.session))
    print("developer headers ok:", sorted(headers)[:6])
except Exception as error:  # noqa: BLE001
    print("developer session error:", type(error).__name__, str(error)[:200])
