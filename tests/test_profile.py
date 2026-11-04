"""Tests for provisioning profile parsing and entitlement synthesis."""

from __future__ import annotations

import datetime as dt

import pytest

from ipasign.errors import ProfileError
from ipasign.profile import ProvisioningProfile, entitlements_to_xml

from . import fixtures


def test_parse_profile_fields():
    key, cert = fixtures.make_identity()
    raw = fixtures.make_profile(certificates=[cert])
    profile = ProvisioningProfile.parse(raw)
    assert profile.name == "Test Profile"
    assert profile.team_id == "TEAM123456"
    assert profile.app_id_prefix == "TEAM123456"
    assert profile.application_identifier == "TEAM123456.*"
    assert profile.is_wildcard
    assert profile.has_certificate(cert)
    assert not profile.is_expired()
    assert profile.expiration is not None and profile.expiration.tzinfo is not None


def test_wildcard_matching():
    _key, cert = fixtures.make_identity()
    wildcard = ProvisioningProfile.parse(fixtures.make_profile(certificates=[cert]))
    assert wildcard.supports_bundle_id("com.example.demo")
    assert wildcard.supports_bundle_id("com.example.demo.widget")
    # A team-wide wildcard authorises any bundle id of that team.
    assert wildcard.supports_bundle_id("org.other.app")

    explicit = ProvisioningProfile.parse(
        fixtures.make_profile(certificates=[cert], app_id="TEAM123456.com.example.demo")
    )
    assert explicit.supports_bundle_id("com.example.demo")
    assert not explicit.supports_bundle_id("com.example.demo.widget")
    assert explicit.suggested_bundle_id() == "com.example.demo"


def test_entitlements_for_rewrites_application_identifier():
    _key, cert = fixtures.make_identity()
    profile = ProvisioningProfile.parse(fixtures.make_profile(certificates=[cert]))
    entitlements = profile.entitlements_for("com.example.demo")
    assert entitlements["application-identifier"] == "TEAM123456.com.example.demo"
    assert entitlements["com.apple.developer.team-identifier"] == "TEAM123456"
    assert entitlements["keychain-access-groups"] == ["TEAM123456.com.example.demo"]
    assert entitlements["get-task-allow"] is True


def test_entitlements_substitute_placeholders():
    _key, cert = fixtures.make_identity()
    raw = fixtures.make_profile(
        certificates=[cert],
        entitlements={
            "application-identifier": "$(AppIdentifierPrefix)$(CFBundleIdentifier)",
            "com.apple.developer.team-identifier": "$(TeamIdentifierPrefix)",
            "aps-environment": "development",
        },
    )
    profile = ProvisioningProfile.parse(raw)
    entitlements = profile.entitlements_for("com.demo.app")
    assert entitlements["application-identifier"] == "TEAM123456.com.demo.app"
    assert entitlements["com.apple.developer.team-identifier"] == "TEAM123456"


def test_expired_profile():
    _key, cert = fixtures.make_identity()
    profile = ProvisioningProfile.parse(
        fixtures.make_profile(certificates=[cert], expires_days=-5)
    )
    assert profile.is_expired()
    assert profile.describe()["expired"] is True


def test_invalid_profile_raises():
    with pytest.raises(ProfileError):
        ProvisioningProfile.parse(b"not a profile")


def test_entitlements_xml_roundtrip():
    import plistlib

    data = {"application-identifier": "TEAM.com.x", "get-task-allow": True}
    xml = entitlements_to_xml(data)
    assert plistlib.loads(xml) == data
