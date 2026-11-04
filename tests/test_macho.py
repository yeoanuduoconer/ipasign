"""Tests for the Mach-O code-signing engine."""

from __future__ import annotations

import hashlib

import pytest
from cryptography.hazmat.primitives import hashes

from ipasign import macho
from ipasign.cms import verify_detached_cms
from ipasign.macho import (
    SignParameters,
    parse_slice_layout,
    read_signatures,
    sign_macho,
    split_slices,
    verify_slice_hashes,
)

from . import fixtures

ENTS = b"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>application-identifier</key><string>TEAM123456.com.example.demo</string>
<key>com.apple.developer.team-identifier</key><string>TEAM123456</string>
<key>get-task-allow</key><true/>
</dict></plist>
"""


def _params(key, cert) -> SignParameters:
    return SignParameters(
        identifier="com.example.demo",
        key=key,
        certificates=[cert],
        team_id="TEAM123456",
        entitlements=ENTS,
        info_plist=b"<plist>info</plist>",
        resource_dir=b"<plist>resources</plist>",
    )


def test_sign_thin_macho_roundtrip():
    key, cert = fixtures.make_identity()
    binary = fixtures.make_macho()
    signed = sign_macho(binary, _params(key, cert))

    assert len(signed) > len(binary)
    layout = parse_slice_layout(signed)
    assert layout.code_sig is not None
    start = layout.code_sig.dataoff
    assert start == 0x5000  # the LC placeholder position; trailing slack is dropped
    assert layout.code_sig.datasize == len(signed) - start

    signatures = read_signatures(signed)
    assert len(signatures) == 1
    signature = signatures[0]
    cd = signature.code_directory
    assert cd.identifier == "com.example.demo"
    assert cd.team_id == "TEAM123456"
    assert cd.n_special == 5
    assert cd.code_limit == start
    assert cd.flags == 0
    assert signature.entitlements == ENTS

    assert verify_slice_hashes(signed, signature) == []

    verified = verify_detached_cms(signature.cms_blob, cd.raw)
    assert verified.certificate.fingerprint(hashes.SHA256()) == cert.fingerprint(hashes.SHA256())

    # The __LINKEDIT segment must now cover the appended signature.
    linkedit = layout.linkedit
    assert linkedit.filesize == layout.code_sig.datasize
    assert linkedit.vmsize >= linkedit.filesize


def test_resign_is_stable_and_valid():
    key, cert = fixtures.make_identity()
    once = sign_macho(fixtures.make_macho(), _params(key, cert))
    twice = sign_macho(once, _params(key, cert))
    assert abs(len(twice) - len(once)) < 64
    signature = read_signatures(twice)[0]
    assert verify_slice_hashes(twice, signature) == []
    verify_detached_cms(signature.cms_blob, signature.code_directory.raw)


def test_fat_binary_roundtrip():
    key, cert = fixtures.make_identity()
    fat = fixtures.make_fat(
        (fixtures.CPU_ARM64, 0, fixtures.make_macho()),
        (fixtures.CPU_ARM64, 0x80000002, fixtures.make_macho(text_size=0x2000)),
    )
    signed = sign_macho(fat, _params(key, cert))
    image = split_slices(signed)
    assert image.is_fat and len(image.slices) == 2
    signatures = read_signatures(signed)
    assert len(signatures) == 2
    for signature in signatures:
        assert signature.code_directory.identifier == "com.example.demo"
    assert verify_slice_hashes(signed, signatures[0]) == []
    assert verify_slice_hashes(signed, signatures[1]) == []


def test_adds_missing_signature_load_command():
    key, cert = fixtures.make_identity()
    binary = fixtures.make_macho(with_code_signature=False)
    signed = sign_macho(binary, _params(key, cert))
    layout = parse_slice_layout(signed)
    assert layout.code_sig is not None and layout.code_sig.datasize > 0
    signature = read_signatures(signed)[0]
    assert verify_slice_hashes(signed, signature) == []


def test_verify_detects_tampering():
    key, cert = fixtures.make_identity()
    signed = bytearray(sign_macho(fixtures.make_macho(), _params(key, cert)))
    signed[0x100] ^= 0xFF  # flip a byte inside __TEXT
    signature = read_signatures(bytes(signed))[0]
    problems = verify_slice_hashes(bytes(signed), signature)
    assert problems and "page 0 hash mismatch" in problems[0]


def test_ad_hoc_signature_has_no_cms():
    binary = fixtures.make_macho()
    params = SignParameters(identifier="com.example.demo", ad_hoc=True)
    signed = sign_macho(binary, params)
    signature = read_signatures(signed)[0]
    assert signature.cms_blob is None
    assert signature.code_directory.flags & macho.CS_ADHOC
    assert verify_slice_hashes(signed, signature) == []


def test_special_slots_hash_expected_values():
    key, cert = fixtures.make_identity()
    params = _params(key, cert)
    signed = sign_macho(fixtures.make_macho(), params)
    cd = read_signatures(signed)[0].code_directory
    assert cd.special_slots[macho.CSSLOT_INFOSLOT] == hashlib.sha256(params.info_plist).digest()
    assert cd.special_slots[macho.CSSLOT_RESOURCEDIR] == hashlib.sha256(params.resource_dir).digest()
    ent_blob = macho.entitlements_blob(ENTS)
    assert cd.special_slots[macho.CSSLOT_ENTITLEMENTS] == hashlib.sha256(ent_blob).digest()

def test_encrypted_flag_is_parsed():
    from ipasign import macho as _macho

    assert _macho.is_encrypted(fixtures.make_macho(encrypted=True))
    assert not _macho.is_encrypted(fixtures.make_macho())
