"""Smoke-test apple-auth's own client with a wrong password.

If the server answers "invalid credentials" the anisette/provisioning layer is
fine and only our hand-rolled GSA request is lacking something.
"""

import os
import sys
from pathlib import Path

os.environ["APPLE_AUTH_LIBRARY"] = r"E:\tools\ipasign\apple-auth-client\Release\apple_auth_client.dll"
sys.path.insert(0, r"E:\tools\ipasign\apple-auth-src\python")

from apple_auth import Device  # noqa: E402

STATE = Path.home() / ".ipasign" / "apple-auth-device"

device = Device.windows(str(STATE))
print("state:", device.state)
print("info:", device.info)
print("provisioned session:", device.session)

print("fresh headers:", {k: (v[:18] + "..." if len(v) > 18 else v) for k, v in device.headers().items()})

try:
    device.login(email="you@example.com", password="definitely-wrong")
    print("login unexpectedly succeeded?")
except Exception as error:  # noqa: BLE001
    print("login error:", type(error).__name__, str(error)[:300])
