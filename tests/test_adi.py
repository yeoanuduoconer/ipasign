"""Tests for the ADI v3 envelope parser."""

from __future__ import annotations

import struct

import pytest

from ipasign.apple.anisette import adi


def make_state_file(version: int = 3, prefix: bytes = b"0123456789abcdef", blocks: int = 4) -> bytes:
    iv = bytes(range(16))
    ciphertext = bytes(blocks * 16)
    tag = bytes(20)
    return (
        struct.pack(">II", version, len(prefix))
        + prefix
        + iv
        + ciphertext
        + tag
    )


def test_parse_v3_envelope():
    data = make_state_file()
    state = adi.parse_state_file(data)
    assert state.version == 3
    assert state.prefix == b"0123456789abcdef"
    assert state.iv == bytes(range(16))
    assert len(state.ciphertext) == 64
    assert state.tag == bytes(20)
    assert state.body_size == 64


def test_parse_v1_envelope_is_accepted():
    state = adi.parse_state_file(make_state_file(version=1))
    assert state.version == 1


def test_rejects_unknown_version():
    with pytest.raises(adi.AdiError):
        adi.parse_state_file(make_state_file(version=2))


def test_rejects_truncated_file():
    with pytest.raises(adi.AdiError):
        adi.parse_state_file(b"\x00\x00\x00\x03")


def test_rejects_prefix_overflow():
    data = bytearray(make_state_file())
    struct.pack_into(">I", data, 4, 10_000)
    with pytest.raises(adi.AdiError):
        adi.parse_state_file(bytes(data))


def test_rejects_unaligned_ciphertext():
    data = make_state_file()[:-20] + b"x" * 8 + b"\x00" * 20  # +8 bytes inside ciphertext
    with pytest.raises(adi.AdiError):
        adi.parse_state_file(data)


def test_describe_reports_prefix_words():
    info = adi.describe_file(data=make_state_file())
    assert info["version"] == 3
    assert info["prefix_size"] == 16
    assert len(info["prefix_words"]) == 4


def test_parse_real_adi_if_present():
    """Optional: validate against Sideloadly's provisioned v3 file."""
    from pathlib import Path

    candidate = Path.home() / "AppData/Local/Sideloadly"
    files = sorted(candidate.glob("*/adi.pb")) if candidate.is_dir() else []
    if not files:
        pytest.skip("no provisioned ADI on this machine")
    state = adi.load_state_file(files[0])
    assert state.version in (1, 3)
    assert len(state.iv) == 16
    assert len(state.tag) == 20
