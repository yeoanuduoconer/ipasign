"""Read-only probe of the developer portal using the saved session."""

import os
import sys
from pathlib import Path

os.environ["APPLE_AUTH_LIBRARY"] = r"E:\tools\ipasign\apple-auth-client\Release\apple_auth_client.dll"
sys.path.insert(0, r"E:\tools\ipasign\apple-auth-src\python")
sys.path.insert(0, r"C:\Users\you\source\repos\ipasign")

from ipasign import apple_auth_bridge  # noqa: E402
from ipasign.developer import DeveloperClient  # noqa: E402

device = apple_auth_bridge.open_device()
print("session:", "yes" if device.session is not None else "no")
headers = apple_auth_bridge.developer_headers(device, device.session)
client = DeveloperClient(headers)

teams = client.list_teams()
print("teams:", [(t.get("name"), t.get("teamId"), t.get("type")) for t in teams])
team = teams[0]["teamId"]

devices = client.list_devices(team)
print("devices:", [(d.get("name"), d.get("deviceNumber"), d.get("status")) for d in devices])

certs = client.list_certificates(team)
print("certificates:", [(c.get("name"), c.get("certificateId"), c.get("status")) for c in certs])

apps = client.list_app_ids(team)
print("app ids:", [(a.get("name"), a.get("identifier"), a.get("appIdId")) for a in apps])
