"""Tests for the DER entitlements encoder (slot 7)."""

from __future__ import annotations

import binascii
import hashlib

import pytest

from ipasign import macho
from ipasign.derplist import encode_entitlements
from ipasign.macho import SignParameters, read_signatures, sign_macho

from . import fixtures

# Reference blob produced by zsign for exactly these entitlements.
REFERENCE_ENTITLEMENTS = {
    "application-identifier": "TEAM123456.*",
    "com.apple.developer.team-identifier": "TEAM123456",
    "get-task-allow": True,
    "keychain-access-groups": ["TEAM123456.*"],
}
REFERENCE_HEX = (
    "7081a0020101b0819a30260c166170706c69636174696f6e2d6964656e7469666965720c0c"
    "5445414d3132333435362e2a30310c23636f6d2e6170706c652e646576656c6f7065722e7465"
    "616d2d6964656e7469666965720c0a5445414d31323334353630130c0e6765742d7461736b"
    "2d616c6c6f770101ff30280c166b6579636861696e2d6163636573732d67726f757073300e0c"
    "0c5445414d3132333435362e2a"
)


def test_encoder_matches_reference_bytes():
    encoded = encode_entitlements(REFERENCE_ENTITLEMENTS)
    assert encoded == binascii.unhexlify(REFERENCE_HEX)


def test_encoder_handles_nested_values():
    payload = {
        "a-string": "hello",
        "a-bool": False,
        "a-number": 7,
        "a-list": ["x", 1, True],
        "a-dict": {"inner": "value"},
    }
    encoded = encode_entitlements(payload)
    assert encoded.startswith(b"\x70")
    # Every top-level key is present as a UTF8String in the blob.
    for key in payload:
        assert key.encode() in encoded


def test_encoder_sorts_keys():
    first = encode_entitlements({"b": "1", "a": "2"})
    second = encode_entitlements({"a": "2", "b": "1"})
    assert first == second


def test_encoder_rejects_unsupported_values():
    with pytest.raises(TypeError):
        encode_entitlements({"weird": object()})


def test_signed_binary_carries_der_entitlements():
    key, cert = fixtures.make_identity()
    ents = b"""<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>get-task-allow</key><true/>
</dict></plist>
"""
    params = SignParameters(
        identifier="com.example.demo",
        key=key,
        certificates=[cert],
        team_id="TEAM123456",
        entitlements=ents,
        info_plist=b"<plist/>",
        resource_dir=b"<plist/>",
    )
    signed = sign_macho(fixtures.make_macho(), params)
    signature = read_signatures(signed)[0]
    assert macho.CSSLOT_DER_ENTITLEMENTS in signature.blobs
    der_blob = signature.blobs[macho.CSSLOT_DER_ENTITLEMENTS]
    assert der_blob[:4] == b"\xfa\xde\x71\x72"  # CSMAGIC_EMBEDDED_DER_ENTITLEMENTS
    cd = signature.code_directory
    assert cd.n_special == 7
    assert cd.special_slots[7] == hashlib.sha256(der_blob).digest()
