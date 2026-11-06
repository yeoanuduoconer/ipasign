"""Apple Developer Portal (developerservices2, protocol QH65B2) client.

Authentication comes from :mod:`ipasign.apple_auth_bridge`: the Xcode
application token (``com.apple.gs.xcode.auth``) is turned into the
``X-Apple-GS-Token`` / ``X-Apple-I-Identity-Id`` header pair plus fresh
anisette headers.

Every action posts a plist built from a common envelope
(``clientId``/``protocolVersion``/``requestId``/``teamId``) and returns the
decoded response plist.
"""

from __future__ import annotations

from ipasign import paths

import base64
import plistlib
import uuid
from typing import Dict, List, Optional

import requests

BASE = "https://developerservices2.apple.com/services/QH65B2"
CLIENT_ID = "XABBG36SBA"
PROTOCOL = "QH65B2"

CA_BUNDLE = None  # filled by _verify()


class DeveloperError(RuntimeError):
    """Apple rejected a developer-portal action."""

    def __init__(self, action: str, payload: dict):
        self.action = action
        self.payload = payload
        status = payload.get("userString") or payload.get("resultString") or ""
        code = payload.get("resultCode")
        super().__init__(f"{action}: {status or 'failed'} (resultCode={code})")


def _verify():
    """requests ``verify`` value: the optional CA bundle, else system roots."""
    bundle = paths.ca_bundle()
    return str(bundle) if bundle is not None else True


class DeveloperClient:
    def __init__(self, headers: Dict[str, str], timeout: int = 60):
        self.headers = dict(headers)
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = _verify()

    # -- plumbing -----------------------------------------------------

    def _post(self, action: str, fields: Optional[dict] = None) -> dict:
        body = {
            "clientId": CLIENT_ID,
            "protocolVersion": PROTOCOL,
            "requestId": str(uuid.uuid4()).upper(),
            "userLocale": "en_US",
        }
        body.update(fields or {})
        response = self.session.post(
            f"{BASE}/{action}.action?clientId={CLIENT_ID}",
            data=plistlib.dumps(body),
            headers={**self.headers, "Content-Type": "text/x-xml-plist"},
            timeout=self.timeout,
        )
        if response.status_code != 200:
            raise DeveloperError(action, {"resultCode": response.status_code,
                                          "resultString": f"HTTP {response.status_code}"})
        content_type = response.headers.get("content-type", "")
        try:
            if "json" in content_type:
                payload = response.json()
            else:
                payload = plistlib.loads(response.content)
        except Exception as error:  # noqa: BLE001
            raise DeveloperError(
                action, {"resultString": f"unparsable response: {error}"}
            ) from error
        if payload.get("resultCode") not in (0, None):
            raise DeveloperError(action, payload)
        return payload

    # -- read-only ----------------------------------------------------

    def list_teams(self) -> List[dict]:
        return self._post("listTeams").get("teams", []) or []

    def list_devices(self, team_id: str) -> List[dict]:
        return self._post("ios/listDevices", {"teamId": team_id}).get("devices", []) or []

    def list_certificates(self, team_id: str) -> List[dict]:
        payload = self._post(
            "ios/listAllDevelopmentCerts", {"teamId": team_id}
        )
        return payload.get("certificates", []) or []

    def list_app_ids(self, team_id: str) -> List[dict]:
        return self._post("ios/listAppIds", {"teamId": team_id}).get("appIds", []) or []

    # -- writes -------------------------------------------------------

    def add_device(self, team_id: str, udid: str, name: str = "ipasign") -> dict:
        payload = self._post(
            "ios/addDevice",
            {"teamId": team_id, "deviceNumber": udid, "deviceName": name},
        )
        return payload.get("device", payload)

    def submit_csr(self, team_id: str, csr_pem: bytes) -> dict:
        payload = self._post(
            "ios/submitDevelopmentCSR",
            {
                "teamId": team_id,
                "csrContent": base64.b64encode(csr_pem).decode(),
                "machineId": str(uuid.uuid4()).upper(),
                "machineName": "ipasign",
            },
        )
        # resultCode == 0 means the certificate exists; its content is read
        # back through listAllDevelopmentCerts (the response shape differs
        # between portal versions).
        return payload

    def revoke_certificate(
        self, team_id: str, certificate_id: str, serial_number: str
    ) -> dict:
        return self._post(
            "ios/revokeDevelopmentCert",
            {
                "teamId": team_id,
                "certificateId": certificate_id,
                "serialNumber": serial_number,
            },
        )

    def add_app_id(self, team_id: str, identifier: str, name: str) -> dict:
        payload = self._post(
            "ios/addAppId",
            {"teamId": team_id, "identifier": identifier, "name": name},
        )
        app_id = payload.get("appId") or {}
        if not app_id.get("appIdId"):
            raise DeveloperError("ios/addAppId", payload)
        return app_id

    def download_profile(self, team_id: str, app_id_id: str) -> bytes:
        payload = self._post(
            "ios/downloadTeamProvisioningProfile",
            {"teamId": team_id, "appIdId": app_id_id},
        )
        profile = (payload.get("provisioningProfile") or {}).get("encodedProfile")
        if not profile:
            raise DeveloperError("ios/downloadTeamProvisioningProfile", payload)
        return profile
