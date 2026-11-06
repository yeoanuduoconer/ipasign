"""zsign fallback backend helpers."""

from __future__ import annotations

import types

from ipasign.core import zsign_backend


def test_bundle_id_for_explicit_profile():
    profile = types.SimpleNamespace(
        application_identifier="TEAM123456.com.example.app",
        team_ids=["TEAM123456"],
    )
    assert zsign_backend.bundle_id_for_profile(profile) == "com.example.app"


def test_bundle_id_for_wildcard_is_none():
    profile = types.SimpleNamespace(application_identifier="TEAM123456.*", team_ids=["TEAM123456"])
    assert zsign_backend.bundle_id_for_profile(profile) is None


def test_bundle_id_without_team_prefix():
    profile = types.SimpleNamespace(application_identifier="com.example.other", team_ids=[])
    assert zsign_backend.bundle_id_for_profile(profile) == "com.example.other"


def test_bundle_id_missing():
    profile = types.SimpleNamespace(application_identifier="", team_ids=[])
    assert zsign_backend.bundle_id_for_profile(profile) is None
