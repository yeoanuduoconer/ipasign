"""DER-encoded property lists (Apple's entitlements slot format).

Since iOS 15 the code signature carries entitlements twice: the classic XML
blob (slot 5) and a DER blob (slot 7).  Xcode, codesign and zsign all emit
both, and iOS 26 rejects signatures that only have the XML one with
``0xE8008029`` ("code signature version is no longer supported").

The wire format, derived from a reference signature::

    70 <len>                      application 16: root
      02 01 01                    INTEGER 1 (format version)
      b0 <len>                    context 16: dictionary
        30 <len>                  SEQUENCE per entry
          0c <len> key            UTF8String
          <value>                 any of the value encodings below

Values: UTF8String (0x0c), BOOLEAN (0x01), INTEGER (0x02), OCTET STRING
(0x04), SEQUENCE (0x30) for arrays and a nested ``b0`` dictionary.
Entries are keyed in ascending byte order, which is what the reference
output does.
"""

from __future__ import annotations

from typing import Any

from . import der

ROOT_TAG = 0x70  # APPLICATION 16, constructed
DICTIONARY_TAG = 0xB0  # context 16, constructed


def _encode_value(value: Any) -> bytes:
    if isinstance(value, bool):
        return der.boolean(value)
    if isinstance(value, int):
        return der.integer(value)
    if isinstance(value, str):
        return der.utf8_string(value)
    if isinstance(value, (bytes, bytearray)):
        return der.octet_string(bytes(value))
    if isinstance(value, (list, tuple)):
        return der.sequence(*(_encode_value(item) for item in value))
    if isinstance(value, dict):
        return _encode_dictionary(value)
    raise TypeError(f"cannot DER-encode {type(value).__name__}")


def _encode_dictionary(mapping: dict) -> bytes:
    entries = b"".join(
        der.sequence(der.utf8_string(str(key)), _encode_value(value))
        for key, value in sorted(mapping.items(), key=lambda item: str(item[0]))
    )
    return der.tlv(DICTIONARY_TAG, entries)


def encode_entitlements(entitlements: dict) -> bytes:
    """Encode an entitlements dictionary the way codesign stores slot 7."""
    body = der.integer(1) + _encode_dictionary(entitlements)
    return der.tlv(ROOT_TAG, body)
