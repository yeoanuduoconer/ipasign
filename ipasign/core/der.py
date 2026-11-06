"""A tiny DER (ASN.1) encoder/decoder.

ipasign needs ASN.1 for exactly two things:

* building the CMS/PKCS#7 ``SignedData`` blob that carries the RSA signature
  over the CodeDirectory, and
* reading the CMS envelope that wraps a ``.mobileprovision`` file.

Rather than depend on an ASN.1 library, this module implements the small
subset required.  The encoder is deliberately dumb (no schema), which keeps
the CMS builder explicit and auditable, and the decoder is a generic TLV
tree parser good enough to navigate CMS structures.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Union

from ipasign.core.errors import IpasignError


class DERError(IpasignError):
    """Malformed DER input or an impossible encoding request."""


# ---------------------------------------------------------------------------
# Encoding
# ---------------------------------------------------------------------------

def encode_length(length: int) -> bytes:
    if length < 0:
        raise DERError(f"negative length: {length}")
    if length < 0x80:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + encode_length(len(content)) + content


def sequence(*items: bytes) -> bytes:
    return tlv(0x30, b"".join(items))


def set_of(*items: bytes, sorted_: bool = True) -> bytes:
    body = b"".join(sorted(items) if sorted_ else items)
    return tlv(0x31, body)


def null() -> bytes:
    return b"\x05\x00"


def integer(value: int) -> bytes:
    if value < 0:
        raise DERError("negative INTEGER not supported")
    if value == 0:
        raw = b"\x00"
    else:
        raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
        if raw[0] & 0x80:
            raw = b"\x00" + raw
    return tlv(0x02, raw)


def boolean(value: bool) -> bytes:
    return tlv(0x01, b"\xff" if value else b"\x00")


def octet_string(data: bytes) -> bytes:
    return tlv(0x04, data)


def bit_string(data: bytes, unused_bits: int = 0) -> bytes:
    return tlv(0x03, bytes([unused_bits]) + data)


def utf8_string(value: str) -> bytes:
    return tlv(0x0C, value.encode("utf-8"))


def utc_time(value: _dt.datetime) -> bytes:
    if value.tzinfo is not None:
        value = value.astimezone(_dt.timezone.utc)
    return tlv(0x17, value.strftime("%y%m%d%H%M%SZ").encode("ascii"))


def generalized_time(value: _dt.datetime) -> bytes:
    if value.tzinfo is not None:
        value = value.astimezone(_dt.timezone.utc)
    return tlv(0x18, value.strftime("%Y%m%d%H%M%SZ").encode("ascii"))


def oid(dotted: str) -> bytes:
    """Encode a dotted OID string, e.g. ``"1.2.840.113549.1.7.2"``."""
    try:
        parts = [int(p) for p in dotted.split(".")]
    except ValueError as exc:  # pragma: no cover - defensive
        raise DERError(f"bad OID {dotted!r}") from exc
    if len(parts) < 2:
        raise DERError(f"bad OID {dotted!r}")
    body = bytearray()
    body += _base128(40 * parts[0] + parts[1])
    for part in parts[2:]:
        body += _base128(part)
    return tlv(0x06, bytes(body))


def _base128(value: int) -> bytes:
    if value < 0:
        raise DERError("negative OID component")
    chunk = [value & 0x7F]
    value >>= 7
    while value:
        chunk.append((value & 0x7F) | 0x80)
        value >>= 7
    return bytes(reversed(chunk))


def context(tag_number: int, content: bytes, constructed: bool = True) -> bytes:
    """Context-specific tag, explicit when *constructed* is true."""
    base = 0xA0 if constructed else 0x80
    if tag_number > 30:
        raise DERError("high-tag-number form not supported")
    return tlv(base | tag_number, content)


def raw_tag(tag_byte: int, content: bytes) -> bytes:
    """Escape hatch: encode *content* with an arbitrary single-byte tag."""
    return tlv(tag_byte, content)


# ---------------------------------------------------------------------------
# Decoding
# ---------------------------------------------------------------------------

@dataclass
class Node:
    """One decoded TLV element."""

    tag: int
    value: bytes
    raw: bytes
    children: Optional[List["Node"]] = field(default=None)

    # -- predicates -----------------------------------------------------
    @property
    def constructed(self) -> bool:
        return bool(self.tag & 0x20)

    @property
    def class_name(self) -> str:
        cls = self.tag & 0xC0
        return {0x00: "universal", 0x40: "application", 0x80: "context", 0xC0: "private"}[cls]

    @property
    def number(self) -> int:
        return self.tag & 0x1F

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Node(tag=0x{self.tag:02x}, len={len(self.value)})"

    # -- accessors ------------------------------------------------------
    def iter_children(self) -> List["Node"]:
        return self.children or []

    def find(self, tag: Union[int, str], nth: int = 0) -> Optional["Node"]:
        """First child with *tag*.

        *tag* may be an integer tag byte or a dotted OID string.
        """
        matches = self.find_all(tag)
        if len(matches) > nth:
            return matches[nth]
        return None

    def find_all(self, tag: Union[int, str]) -> List["Node"]:
        if isinstance(tag, str):
            body = _oid_body(tag)
            return [
                child
                for child in self.iter_children()
                if child.tag == 0x06 and child.value == body
            ]
        return [child for child in self.iter_children() if child.tag == tag]

    def as_int(self) -> int:
        if self.tag != 0x02:
            raise DERError(f"INTEGER expected, got tag 0x{self.tag:02x}")
        return int.from_bytes(self.value, "big", signed=True)

    def as_oid(self) -> str:
        if self.tag != 0x06:
            raise DERError(f"OID expected, got tag 0x{self.tag:02x}")
        return decode_oid(self.value)

    def as_string(self) -> str:
        try:
            return self.value.decode("utf-8")
        except UnicodeDecodeError:  # pragma: no cover
            return self.value.decode("latin-1")


def _oid_body(dotted: str) -> bytes:
    """Return the body bytes of an OID (without tag/length)."""
    return oid(dotted)[2:]


def decode_oid(body: bytes) -> str:
    if not body:
        raise DERError("empty OID")
    parts: List[int] = []
    value = 0
    for byte in body:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(value)
            value = 0
    if value:  # pragma: no cover - malformed
        raise DERError("truncated OID")
    first = parts[0]
    if first < 40:
        head = [0, first]
    elif first < 80:
        head = [1, first - 40]
    else:
        head = [2, first - 80]
    return ".".join(str(p) for p in head + parts[1:])


def parse(data: bytes, offset: int = 0) -> "tuple[Node, int]":
    """Parse one element starting at *offset*; return ``(node, end_offset)``."""
    if offset >= len(data):
        raise DERError("unexpected end of data")
    start = offset
    tag = data[offset]
    offset += 1
    if tag & 0x1F == 0x1F:
        raise DERError("high-tag-number form not supported")
    if offset >= len(data):
        raise DERError("unexpected end of data")
    first = data[offset]
    offset += 1
    if first < 0x80:
        length = first
    elif first == 0x80:
        raise DERError("indefinite lengths are not valid DER")
    else:
        count = first & 0x7F
        if offset + count > len(data):
            raise DERError("truncated length")
        length = int.from_bytes(data[offset:offset + count], "big")
        offset += count
    end = offset + length
    if end > len(data):
        raise DERError("truncated content")
    value = data[offset:end]
    children: Optional[List[Node]] = None
    if tag & 0x20:
        children = []
        cursor = offset
        while cursor < end:
            child, cursor = parse(data, cursor)
            children.append(child)
        if cursor != end:
            raise DERError("constructed element length mismatch")
    return Node(tag=tag, value=value, raw=data[start:end], children=children), end


def parse_all(data: bytes) -> List[Node]:
    nodes: List[Node] = []
    offset = 0
    while offset < len(data):
        node, offset = parse(data, offset)
        nodes.append(node)
    return nodes


def parse_one(data: bytes) -> Node:
    node, end = parse(data, 0)
    if end != len(data):
        # Tolerate trailing bytes (CMS is sometimes padded) but only zeros.
        if data[end:].strip(b"\x00"):
            raise DERError(f"{len(data) - end} trailing bytes after DER structure")
    return node


# Convenience re-exports ---------------------------------------------------

__all__ = [
    "DERError",
    "Node",
    "boolean",
    "bit_string",
    "context",
    "decode_oid",
    "encode_length",
    "generalized_time",
    "integer",
    "null",
    "octet_string",
    "oid",
    "parse",
    "parse_all",
    "parse_one",
    "raw_tag",
    "sequence",
    "set_of",
    "tlv",
    "utc_time",
    "utf8_string",
]
