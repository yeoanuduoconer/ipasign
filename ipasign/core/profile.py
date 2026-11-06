"""Provisioning profile (``.mobileprovision``) parsing and entitlement synthesis.

A profile is a CMS-signed plist.  The interesting parts for re-signing are:

* which team and app identifier it authorises,
* which entitlements it grants (the app may only claim those),
* which certificates may sign for it,
* whether it has expired.
"""

from __future__ import annotations

import copy
import datetime as dt
import plistlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from ipasign.core import cms
from ipasign.core.errors import ProfileError

_PARAM = re.compile(r"\$[({](AppIdentifierPrefix|TeamIdentifierPrefix|CFBundleIdentifier|BundleIdentifier)[)}]")


def _as_datetime(value: Any) -> Optional[dt.datetime]:
    if isinstance(value, dt.datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=dt.timezone.utc)
        return value.astimezone(dt.timezone.utc)
    return None


@dataclass
class ProvisioningProfile:
    """Parsed representation of a ``.mobileprovision`` file."""

    raw: bytes
    payload: Dict[str, Any] = field(default_factory=dict)

    # -- construction ---------------------------------------------------
    @classmethod
    def parse(cls, raw: bytes) -> "ProvisioningProfile":
        if not raw:
            raise ProfileError("empty provisioning profile")
        try:
            content = cms.extract_detached_content(raw)
        except Exception as exc:  # noqa: BLE001 - re-raised with context
            raise ProfileError(f"cannot read profile envelope: {exc}") from exc
        try:
            payload = plistlib.loads(content)
        except Exception as exc:  # noqa: BLE001
            raise ProfileError(f"profile payload is not a property list: {exc}") from exc
        if not isinstance(payload, dict):
            raise ProfileError("profile payload is not a dictionary")
        return cls(raw=raw, payload=payload)

    @classmethod
    def load(cls, path: "str | Path") -> "ProvisioningProfile":
        file = Path(path)
        if not file.is_file():
            raise ProfileError(f"provisioning profile not found: {file}")
        return cls.parse(file.read_bytes())

    # -- basic fields ---------------------------------------------------
    @property
    def name(self) -> str:
        return str(self.payload.get("Name", ""))

    @property
    def uuid(self) -> str:
        return str(self.payload.get("UUID", ""))

    @property
    def team_ids(self) -> List[str]:
        value = self.payload.get("TeamIdentifier") or []
        return [str(item) for item in value]

    @property
    def team_id(self) -> str:
        teams = self.team_ids
        if teams:
            return teams[0]
        prefix = self.payload.get("ApplicationIdentifierPrefix") or []
        return str(prefix[0]) if prefix else ""

    @property
    def app_id_prefix(self) -> str:
        prefix = self.payload.get("ApplicationIdentifierPrefix") or []
        return str(prefix[0]) if prefix else self.team_id

    @property
    def entitlements(self) -> Dict[str, Any]:
        value = self.payload.get("Entitlements")
        if not isinstance(value, dict):
            raise ProfileError("profile has no Entitlements dictionary")
        return value

    @property
    def expiration(self) -> Optional[dt.datetime]:
        return _as_datetime(self.payload.get("ExpirationDate"))

    @property
    def creation(self) -> Optional[dt.datetime]:
        return _as_datetime(self.payload.get("CreationDate"))

    @property
    def devices(self) -> List[str]:
        value = self.payload.get("ProvisionedDevices") or []
        return [str(item) for item in value]

    @property
    def provisions_all_devices(self) -> bool:
        return bool(self.payload.get("ProvisionsAllDevices"))

    @property
    def platforms(self) -> List[str]:
        value = self.payload.get("Platform") or []
        return [str(item) for item in value]

    @property
    def developer_certificates(self) -> List[bytes]:
        return [bytes(item) for item in (self.payload.get("DeveloperCertificates") or [])]

    @property
    def application_identifier(self) -> str:
        return str(self.entitlements.get("application-identifier", ""))

    @property
    def is_wildcard(self) -> bool:
        return self.application_identifier.endswith("*")

    # -- queries --------------------------------------------------------
    def supports_bundle_id(self, bundle_id: str) -> bool:
        pattern = self.application_identifier
        if not pattern:
            return False
        prefix = f"{self.app_id_prefix}."
        if pattern.startswith(prefix):
            pattern = pattern[len(prefix):]
        elif pattern.startswith(f"{self.team_id}."):
            pattern = pattern[len(self.team_id) + 1:]
        if pattern.endswith("*"):
            return bundle_id.startswith(pattern[:-1])
        return bundle_id == pattern

    def suggested_bundle_id(self) -> Optional[str]:
        """For explicit (non-wildcard) profiles, the bundle id it authorises."""
        if self.is_wildcard:
            return None
        pattern = self.application_identifier
        for prefix in (f"{self.app_id_prefix}.", f"{self.team_id}."):
            if pattern.startswith(prefix):
                return pattern[len(prefix):]
        return pattern or None

    def has_certificate(self, certificate: x509.Certificate) -> bool:
        target = certificate.public_bytes(serialization.Encoding.DER)
        return any(target == item for item in self.developer_certificates)

    def certificate_summaries(self) -> List[str]:
        out = []
        for item in self.developer_certificates:
            try:
                cert = x509.load_der_x509_certificate(item)
            except Exception:  # noqa: BLE001
                continue
            out.append(cert.subject.rfc4514_string())
        return out

    def is_expired(self, now: Optional[dt.datetime] = None) -> bool:
        expiry = self.expiration
        if expiry is None:
            return False
        moment = now or dt.datetime.now(dt.timezone.utc)
        return expiry <= moment

    def team_matches(self, team_id: str) -> bool:
        teams = set(self.team_ids)
        prefix = self.payload.get("ApplicationIdentifierPrefix") or []
        teams.update(str(item) for item in prefix)
        return not teams or team_id in teams

    # -- entitlement synthesis -----------------------------------------
    def entitlements_for(
        self,
        bundle_id: str,
        *,
        team_id: Optional[str] = None,
        include_team_identifier: bool = True,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Build the entitlement dictionary to embed for *bundle_id*.

        The profile's own entitlements are the upper bound of what may be
        claimed; wildcard placeholders are expanded and the application
        identifier is rewritten to the concrete bundle identifier.
        """
        team = team_id or self.team_id
        entitlements = copy.deepcopy(self.entitlements)

        def resolve(value: Any) -> Any:
            if isinstance(value, str):
                def repl(match: "re.Match[str]") -> str:
                    key = match.group(1)
                    if key in ("AppIdentifierPrefix", "TeamIdentifierPrefix"):
                        return team + "."
                    return bundle_id
                return _PARAM.sub(repl, value)
            if isinstance(value, list):
                return [resolve(item) for item in value]
            if isinstance(value, dict):
                return {key: resolve(item) for key, item in value.items()}
            return value

        entitlements = resolve(entitlements)
        entitlements["application-identifier"] = f"{team}.{bundle_id}"
        if include_team_identifier:
            entitlements["com.apple.developer.team-identifier"] = team

        # Keep the profile's keychain groups verbatim (including the
        # "TEAM.*" wildcard): iOS authorises entitlements against the profile
        # and zsign does the same; rewriting them to a concrete group is what
        # makes iOS reject the signature on device.

        if extra:
            entitlements.update(extra)
        return entitlements

    def describe(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "uuid": self.uuid,
            "team_id": self.team_id,
            "app_id_prefix": self.app_id_prefix,
            "application_identifier": self.application_identifier,
            "wildcard": self.is_wildcard,
            "platforms": self.platforms,
            "created": self.creation.isoformat() if self.creation else None,
            "expires": self.expiration.isoformat() if self.expiration else None,
            "expired": self.is_expired(),
            "device_count": len(self.devices),
            "provisions_all_devices": self.provisions_all_devices,
            "certificate_count": len(self.developer_certificates),
            "certificates": self.certificate_summaries(),
            "entitlements": sorted(self.entitlements.keys()),
        }


def entitlements_to_xml(entitlements: Dict[str, Any]) -> bytes:
    """Serialise entitlements as the XML plist iOS expects in the blob."""
    return plistlib.dumps(entitlements, fmt=plistlib.FMT_XML, sort_keys=True)
