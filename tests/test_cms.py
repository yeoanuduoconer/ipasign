"""CMS structure tests (Apple hash-agility attributes)."""

from __future__ import annotations

import base64
import hashlib
import plistlib

from ipasign.core import cms, der

from . import fixtures


def _agility_attrs(blob: bytes):
    """Return (v2_value, plist_bytes) from a CMS blob."""
    info = der.parse_one(blob)
    signed = info.iter_children()[1].iter_children()[0]
    parts = signed.iter_children()
    signer = parts[-1].iter_children()[0]
    attrs = signer.iter_children()[3]
    v2 = None
    plist = None
    for attr in attrs.iter_children():
        oid = attr.iter_children()[0].as_oid()
        value = attr.iter_children()[1].iter_children()[0]
        if oid == cms.OID_HASH_AGILITY_V2:
            v2 = value
        elif oid == cms.OID_CDHASHES:
            plist = value.value
    return v2, plist


def test_cdhash_plist_uses_truncated_digest():
    key, cert = fixtures.make_identity()
    cd = b"fake code directory bytes"
    cdhash = hashlib.sha256(cd).digest()

    blob = cms.build_detached_cms(cd, key, [cert], cdhash=cdhash)
    v2, plist = _agility_attrs(blob)

    assert plist is not None and v2 is not None
    payload = plistlib.loads(plist)
    # Apple's flexibility plist carries the 20-byte truncated cdhash; a full
    # 32-byte value makes iOS reject the signature (0xe8008019).
    assert payload["cdhashes"] == [cdhash[:20]]

    # The v2 attribute still carries the full SHA-256 digest.
    seq = v2.iter_children()
    assert seq[0].as_oid() == cms.OID_SHA256
    assert seq[1].value == cdhash


def test_cms_without_cdhash_has_no_agility_attrs():
    key, cert = fixtures.make_identity()
    blob = cms.build_detached_cms(b"payload", key, [cert])
    v2, plist = _agility_attrs(blob)
    assert v2 is None and plist is None
