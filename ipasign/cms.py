"""CMS / PKCS#7 SignedData support.

Two operations are implemented:

``build_detached_cms``
    Wrap the CodeDirectory blob in a detached ``SignedData`` structure and
    RSA-sign it with the developer certificate.  This is the *entire* purpose
    of CMS inside an iOS code signature.

``extract_detached_content``
    Read the payload of a ``.mobileprovision`` file, which is itself a
    ``SignedData`` structure whose content is the plist describing the
    profile (team, app id, entitlements, devices, certificates ...).
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import plistlib
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

from . import der
from .errors import SignatureError

# -- OIDs ------------------------------------------------------------------
OID_DATA = "1.2.840.113549.1.7.1"
OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_SIGNING_TIME = "1.2.840.113549.1.9.5"
OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
OID_SHA1 = "1.3.14.3.2.26"
OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OID_SHA384 = "2.16.840.1.101.3.4.2.2"
OID_SHA512 = "2.16.840.1.101.3.4.2.3"
OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2"
# Apple's "hash agility" attributes: the CD hashes are carried in the signed
# attributes so verifiers do not have to re-hash the CMS content.
OID_CDHASHES = "1.2.840.113635.100.9.1"
OID_HASH_AGILITY_V2 = "1.2.840.113635.100.9.2"

_DIGESTS = {
    OID_SHA1: (hashes.SHA1, hashlib.sha1),
    OID_SHA256: (hashes.SHA256, hashlib.sha256),
    OID_SHA384: (hashes.SHA384, hashlib.sha384),
    OID_SHA512: (hashes.SHA512, hashlib.sha512),
}


# ---------------------------------------------------------------------------
# Building
# ---------------------------------------------------------------------------

def _algorithm_identifier(dotted: str, with_null: bool = False) -> bytes:
    parts = [der.oid(dotted)]
    if with_null:
        parts.append(der.null())
    return der.sequence(*parts)


def _signer_identifier(cert: x509.Certificate) -> bytes:
    issuer = cert.issuer.public_bytes()
    return der.sequence(issuer, der.integer(cert.serial_number))


def _sign_attrs(attrs_der: bytes, key) -> bytes:
    if isinstance(key, rsa.RSAPrivateKey):
        return key.sign(attrs_der, padding.PKCS1v15(), hashes.SHA256())
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return key.sign(attrs_der, ec.ECDSA(hashes.SHA256()))
    if isinstance(key, ed25519.Ed25519PrivateKey):  # pragma: no cover - not used by Apple
        return key.sign(attrs_der)
    raise SignatureError(f"unsupported private key type: {type(key).__name__}")


def _signature_algorithm(key) -> bytes:
    if isinstance(key, rsa.RSAPrivateKey):
        # OpenSSL (and therefore codesign-compatible tooling) emits the generic
        # rsaEncryption OID in SignerInfo when using PKCS#7 v1.5 semantics.
        return _algorithm_identifier(OID_RSA_ENCRYPTION, with_null=True)
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return _algorithm_identifier(OID_ECDSA_SHA256)
    if isinstance(key, ed25519.Ed25519PrivateKey):  # pragma: no cover
        return _algorithm_identifier("1.3.101.112")
    raise SignatureError(f"unsupported private key type: {type(key).__name__}")


def build_detached_cms(
    content: bytes,
    key,
    certificates: Sequence[x509.Certificate],
    *,
    signing_time: Optional[_dt.datetime] = None,
    cdhash: Optional[bytes] = None,
) -> bytes:
    """Return a DER encoded detached ``SignedData`` over *content*.

    The returned blob is what belongs in slot ``CSSLOT_SIGNATURESLOT`` of an
    embedded signature SuperBlob.

    When *cdhash* is given, Apple's hash-agility attributes are added exactly
    like ``codesign`` and ``zsign`` do; iOS can then verify the CodeDirectory
    hash without re-hashing the CMS payload.
    """
    if not certificates:
        raise SignatureError("at least one certificate is required to build CMS")

    digest = hashlib.sha256(content).digest()
    message_digest_attr = der.sequence(
        der.oid(OID_MESSAGE_DIGEST), der.set_of(der.octet_string(digest))
    )
    content_type_attr = der.sequence(
        der.oid(OID_CONTENT_TYPE), der.set_of(der.oid(OID_DATA))
    )
    attrs = [content_type_attr]
    if signing_time is not None:
        attrs.append(
            der.sequence(
                der.oid(OID_SIGNING_TIME), der.set_of(der.utc_time(signing_time))
            )
        )
    attrs.append(message_digest_attr)

    if cdhash:
        attrs.append(
            der.sequence(
                der.oid(OID_HASH_AGILITY_V2),
                der.set_of(
                    der.sequence(der.oid(OID_SHA256), der.octet_string(cdhash))
                ),
            )
        )
        plist_payload = plistlib.dumps({"cdhashes": [cdhash]}, fmt=plistlib.FMT_XML)
        attrs.append(
            der.sequence(
                der.oid(OID_CDHASHES), der.set_of(der.octet_string(plist_payload))
            )
        )

    attrs_der = der.set_of(*attrs)          # tag 0x31 — this is what gets signed
    signature = _sign_attrs(attrs_der, key)

    # Inside SignerInfo the same bytes appear with an implicit [0] tag.
    signed_attrs_field = b"\xa0" + attrs_der[1:]

    signer_info = der.sequence(
        der.integer(1),
        _signer_identifier(certificates[0]),
        _algorithm_identifier(OID_SHA256),
        signed_attrs_field,
        _signature_algorithm(key),
        der.octet_string(signature),
    )

    cert_bodies = b"".join(
        c.public_bytes(serialization.Encoding.DER) for c in certificates
    )
    signed_data = der.sequence(
        der.integer(1),
        der.set_of(_algorithm_identifier(OID_SHA256)),
        der.sequence(der.oid(OID_DATA)),                     # detached content
        der.raw_tag(0xA0, cert_bodies),                      # [0] IMPLICIT certificates
        der.set_of(signer_info),
    )
    return der.sequence(der.oid(OID_SIGNED_DATA), der.context(0, signed_data))


# ---------------------------------------------------------------------------
# Parsing (provisioning profiles)
# ---------------------------------------------------------------------------

def _first_child(node: der.Node, tag: int) -> Optional[der.Node]:
    for child in node.iter_children():
        if child.tag == tag:
            return child
    return None


def extract_detached_content(blob: bytes) -> bytes:
    """Return the eContent of a CMS ``SignedData`` structure.

    Used for ``.mobileprovision`` files.  Falls back to scanning for the
    embedded XML plist when the envelope is unusual (some profiles are signed
    with tools that produce quirky structures).
    """
    try:
        info = der.parse_one(blob)
        if info.tag != 0x30:
            raise der.DERError("ContentInfo is not a SEQUENCE")
        children = info.iter_children()
        if len(children) < 2:
            raise der.DERError("truncated ContentInfo")
        explicit = children[1]
        signed_data = explicit.iter_children()[0] if explicit.iter_children() else None
        if signed_data is None:
            raise der.DERError("missing SignedData")
        encap = signed_data.iter_children()[2]
        if encap.tag != 0x30:
            raise der.DERError("missing EncapsulatedContentInfo")
        payload = None
        for child in encap.iter_children():
            if child.tag == 0x04:
                payload = child.value
                break
            if child.tag == 0xA0:
                inner = child.iter_children()
                if inner:
                    payload = b"".join(c.value for c in inner if c.tag == 0x04)
                    break
        if payload:
            return payload
        raise der.DERError("no eContent")
    except der.DERError:
        start = blob.find(b"<?xml")
        end = blob.find(b"</plist>")
        if start != -1 and end != -1:
            return blob[start:end + len(b"</plist>")]
        raise SignatureError("cannot extract content from CMS envelope")


@dataclass
class VerifiedCms:
    certificate: x509.Certificate
    certificates: List[x509.Certificate]
    signing_time: Optional[_dt.datetime]
    digest_oid: str


def verify_detached_cms(signature: bytes, content: bytes) -> VerifiedCms:
    """Verify a detached CMS signature and return the signing certificate.

    This validates the *mathematical* signature only — trust anchoring against
    Apple's root is reported separately by :mod:`ipasign.verify`.
    """
    info = der.parse_one(signature)
    children = info.iter_children()
    if len(children) < 2 or children[0].as_oid() != OID_SIGNED_DATA:
        raise SignatureError("not a CMS SignedData structure")
    signed_data = children[1].iter_children()[0]

    cert_nodes = []
    signer_infos = None
    for child in signed_data.iter_children():
        if child.tag == 0xA0:  # certificates
            cert_nodes = child.iter_children()
        elif child.tag == 0x31:  # signerInfos (last SET)
            signer_infos = child
    if signer_infos is None or not signer_infos.iter_children():
        raise SignatureError("CMS envelope has no SignerInfo")

    certificates = [
        x509.load_der_x509_certificate(node.raw) for node in cert_nodes if node.tag == 0x30
    ]
    signer_info = signer_infos.iter_children()[0]
    si_children = signer_info.iter_children()
    if len(si_children) < 6:
        raise SignatureError("truncated SignerInfo")

    sid = si_children[1]
    if sid.tag != 0x30 or len(sid.iter_children()) < 2:
        raise SignatureError("unsupported SignerIdentifier (expected IssuerAndSerialNumber)")
    issued_by = sid.iter_children()[0].raw
    serial = sid.iter_children()[1].as_int()

    digest_alg = si_children[2].iter_children()[0].as_oid()
    signed_attrs = si_children[3]
    sig_alg = si_children[4].iter_children()[0].as_oid()
    sig_value = si_children[5].value

    if digest_alg not in _DIGESTS:
        raise SignatureError(f"unsupported CMS digest algorithm {digest_alg}")
    hasher = _DIGESTS[digest_alg][1]

    # messageDigest signed attribute must equal the digest of the content.
    message_digest = None
    signing_time = None
    for attr in signed_attrs.iter_children():
        attr_children = attr.iter_children()
        if len(attr_children) != 2:
            continue
        attr_type = attr_children[0].as_oid()
        values = attr_children[1].iter_children()
        if attr_type == OID_MESSAGE_DIGEST and values:
            message_digest = values[0].value
        elif attr_type == OID_SIGNING_TIME and values:
            signing_time = _parse_asn1_time(values[0])
    if message_digest is None:
        raise SignatureError("CMS signature lacks messageDigest attribute")
    if message_digest != hasher(content).digest():
        raise SignatureError("CMS digest does not match the signed content")

    leaf = None
    for cert in certificates:
        if cert.issuer.public_bytes() == issued_by and cert.serial_number == serial:
            leaf = cert
            break
    if leaf is None:
        raise SignatureError("signing certificate not present in CMS envelope")

    attrs_der = b"\x31" + signed_attrs.raw[1:]
    public_key = leaf.public_key()
    hash_alg = _DIGESTS[digest_alg][0]()
    if isinstance(public_key, rsa.RSAPublicKey):
        public_key.verify(sig_value, attrs_der, padding.PKCS1v15(), hash_alg)
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key.verify(sig_value, attrs_der, ec.ECDSA(hash_alg))
    elif isinstance(public_key, ed25519.Ed25519PublicKey):  # pragma: no cover
        public_key.verify(sig_value, attrs_der)
    else:  # pragma: no cover
        raise SignatureError(f"unsupported public key type {type(public_key).__name__}")

    return VerifiedCms(
        certificate=leaf,
        certificates=certificates,
        signing_time=signing_time,
        digest_oid=digest_alg,
    )


def _parse_asn1_time(node: der.Node) -> Optional[_dt.datetime]:
    try:
        text = node.value.decode("ascii")
    except UnicodeDecodeError:  # pragma: no cover
        return None
    if node.tag == 0x17:  # UTCTime YYMMDDHHMMSSZ
        year = int(text[0:2])
        year += 2000 if year < 50 else 1900
        return _dt.datetime(
            year, int(text[2:4]), int(text[4:6]), int(text[6:8]), int(text[8:10]),
            int(text[10:12]), tzinfo=_dt.timezone.utc,
        )
    if node.tag == 0x18:  # GeneralizedTime YYYYMMDDHHMMSSZ
        return _dt.datetime(
            int(text[0:4]), int(text[4:6]), int(text[6:8]), int(text[8:10]),
            int(text[10:12]), int(text[12:14]), tzinfo=_dt.timezone.utc,
        )
    return None


def certificate_chain_der(certificates: Iterable[x509.Certificate]) -> List[bytes]:
    return [c.public_bytes(serialization.Encoding.DER) for c in certificates]
