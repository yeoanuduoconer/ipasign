"""Synthetic fixtures: Mach-O images, identities, provisioning profiles, IPAs.

Everything here is generated from scratch so the test suite never needs a real
Apple developer account, a real IPA or macOS.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import io
import os
import plistlib
import random
import struct
import zipfile
from pathlib import Path
from typing import Dict, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from ipasign import cms, der

CPU_ARM64 = 0x0100000C
CPU_ARM = 12
CPU_X86_64 = 0x01000007

MH_EXECUTE = 0x2
MH_DYLIB = 0x6

LC_SEGMENT_64 = 0x19
LC_CODE_SIGNATURE = 0x1D


# ---------------------------------------------------------------------------
# Mach-O
# ---------------------------------------------------------------------------

def _segment64(name: str, vmaddr: int, vmsize: int, fileoff: int, filesize: int,
               maxprot: int = 5, initprot: int = 5) -> bytes:
    return struct.pack(
        "<II16sQQQQiiII", LC_SEGMENT_64, 72, name.encode("latin-1"),
        vmaddr, vmsize, fileoff, filesize, maxprot, initprot, 0, 0,
    )


def make_macho(
    *,
    cputype: int = CPU_ARM64,
    cpusubtype: int = 0,
    filetype: int = MH_EXECUTE,
    with_code_signature: bool = True,
    text_size: int = 0x4000,
    data_size: int = 0x1000,
    pad: int = 0x20,
    encrypted: bool = False,
) -> bytes:
    """Build a small but structurally valid 64-bit Mach-O with a signature hole."""
    data_off = text_size
    linkedit_off = data_off + data_size

    segments = [
        _segment64("__PAGEZERO", 0, 0x100000000, 0, 0, 0, 0),
        _segment64("__TEXT", 0x100000000, text_size, 0, text_size),
        _segment64("__DATA", 0x100000000 + text_size, data_size, data_off, data_size, 3, 3),
        _segment64("__LINKEDIT", 0x100000000 + text_size + data_size, 0x4000,
                   linkedit_off, 0, 1, 1),
    ]
    commands = list(segments)
    if encrypted:
        commands.append(struct.pack("<IIIIII", 0x2C, 24, data_off, data_size, 1, 0))
    if with_code_signature:
        commands.append(struct.pack("<IIII", LC_CODE_SIGNATURE, 16, linkedit_off, 0))

    sizeofcmds = sum(len(cmd) for cmd in commands)
    header = struct.pack(
        "<IIIIIIII", 0xFEEDFACF, cputype, cpusubtype, filetype,
        len(commands), sizeofcmds, 0x00200085, 0,
    )
    blob = bytearray(header + b"".join(commands))
    blob += b"\x00" * (text_size - len(blob))
    blob += b"\xaa" * data_size          # a little cargo-culted __DATA
    blob += b"\x00" * pad                # __LINKEDIT slack before the signature
    return bytes(blob)


def make_fat(*slices: Tuple[int, int, bytes], align_exp: int = 14) -> bytes:
    """Wrap thin Mach-O images into a universal binary."""
    count = len(slices)
    header_len = 8 + 20 * count
    offsets = []
    cursor = 1 << align_exp
    for _, _, data in slices:
        cursor = (cursor + (1 << align_exp) - 1) & ~((1 << align_exp) - 1)
        offsets.append(cursor)
        cursor += len(data)
    out = bytearray(cursor)
    struct.pack_into(">II", out, 0, 0xCAFEBABE, count)
    for index, ((cpu, sub, data), offset) in enumerate(zip(slices, offsets)):
        struct.pack_into(">IIIII", out, 8 + index * 20, cpu, sub, offset, len(data), align_exp)
        out[offset:offset + len(data)] = data
    return bytes(out)


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------

def make_identity(
    cn: str = "Apple Development: Tester (ABCD1234)",
    team: str = "TEAM123456",
    org: str = "Test Corp",
    key_size: int = 2048,
):
    """Return ``(private_key, certificate)`` for a self-signed developer cert."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, team),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def make_p12(key, cert, chain=None, password: str = "test") -> bytes:
    return pkcs12.serialize_key_and_certificates(
        name=b"identity",
        key=key,
        cert=cert,
        cas=list(chain or []),
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode()),
    )


# ---------------------------------------------------------------------------
# Provisioning profile
# ---------------------------------------------------------------------------

def make_profile(
    *,
    name: str = "Test Profile",
    team: str = "TEAM123456",
    app_id: str = "TEAM123456.*",
    entitlements: Optional[Dict] = None,
    certificates=(),
    devices=None,
    uuid: str = "00000000-0000-0000-0000-000000000000",
    expires_days: int = 365,
    signer=None,
) -> bytes:
    """Build a CMS-wrapped ``.mobileprovision`` payload."""
    now = dt.datetime.now(dt.timezone.utc)
    if entitlements is None:
        entitlements = {
            "application-identifier": app_id,
            "com.apple.developer.team-identifier": team,
            "get-task-allow": True,
            "keychain-access-groups": [app_id],
        }
    payload = {
        "AppIDName": name,
        "ApplicationIdentifierPrefix": [team],
        "CreationDate": now - dt.timedelta(days=1),
        "ExpirationDate": now + dt.timedelta(days=expires_days),
        "Name": name,
        "Platform": ["iOS"],
        "ProvisionedDevices": list(devices) if devices else None,
        "TeamIdentifier": [team],
        "TeamName": "Test Corp",
        "TimeToLive": 365,
        "UUID": uuid,
        "Version": 1,
        "Entitlements": entitlements,
        "DeveloperCertificates": [
            c.public_bytes(serialization.Encoding.DER) for c in certificates
        ],
    }
    if payload["ProvisionedDevices"] is None:
        del payload["ProvisionedDevices"]
    raw = plistlib.dumps(payload, fmt=plistlib.FMT_XML)

    if signer is None:
        signer = make_identity()
    key, cert = signer
    # Attached CMS: [0] EXPLICIT OCTET STRING as eContent.
    digest = hashlib.sha256(raw).digest()
    attrs = der.set_of(
        der.sequence(der.oid(cms.OID_CONTENT_TYPE), der.set_of(der.oid(cms.OID_DATA))),
        der.sequence(der.oid(cms.OID_MESSAGE_DIGEST), der.set_of(der.octet_string(digest))),
    )
    signature = key.sign(attrs, padding.PKCS1v15(), hashes.SHA256())
    signer_info = der.sequence(
        der.integer(1),
        der.sequence(cert.issuer.public_bytes(), der.integer(cert.serial_number)),
        der.sequence(der.oid(cms.OID_SHA256)),
        b"\xa0" + attrs[1:],
        der.sequence(der.oid(cms.OID_RSA_ENCRYPTION), der.null()),
        der.octet_string(signature),
    )
    signed_data = der.sequence(
        der.integer(1),
        der.set_of(der.sequence(der.oid(cms.OID_SHA256))),
        der.sequence(der.oid(cms.OID_DATA), der.context(0, der.octet_string(raw))),
        der.raw_tag(0xA0, cert.public_bytes(serialization.Encoding.DER)),
        der.set_of(signer_info),
    )
    return der.sequence(der.oid(cms.OID_SIGNED_DATA), der.context(0, signed_data))


# ---------------------------------------------------------------------------
# App bundle / IPA
# ---------------------------------------------------------------------------

def make_app_dir(
    root: str,
    *,
    bundle_id: str = "com.example.demo",
    executable_name: str = "Demo",
    with_extension: bool = True,
    with_framework: bool = True,
    resources: Optional[Dict[str, bytes]] = None,
    filetype: int = MH_EXECUTE,
    encrypted: bool = False,
) -> str:
    """Create ``Payload/Demo.app`` under *root*; return the ``.app`` path."""
    app = os.path.join(root, "Payload", executable_name + ".app")
    os.makedirs(app, exist_ok=True)

    info = {
        "CFBundleIdentifier": bundle_id,
        "CFBundleExecutable": executable_name,
        "CFBundleName": executable_name,
        "CFBundlePackageType": "APPL",
        "CFBundleShortVersionString": "1.0",
        "CFBundleVersion": "1",
        "MinimumOSVersion": "14.0",
        "UIDeviceFamily": [1, 2],
    }
    with open(os.path.join(app, "Info.plist"), "wb") as handle:
        plistlib.dump(info, handle, fmt=plistlib.FMT_BINARY)

    with open(os.path.join(app, executable_name), "wb") as handle:
        handle.write(make_macho(filetype=filetype, encrypted=encrypted))

    os.makedirs(os.path.join(app, "Base.lproj"), exist_ok=True)
    with open(os.path.join(app, "Base.lproj", "Main.storyboardc"), "wb") as handle:
        handle.write(b"storyboard")
    with open(os.path.join(app, "Assets.car"), "wb") as handle:
        handle.write(os.urandom(1024))
    with open(os.path.join(app, "PkgInfo"), "wb") as handle:
        handle.write(b"APPL????")

    for name, payload in (resources or {}).items():
        target = os.path.join(app, name)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "wb") as handle:
            handle.write(payload)

    if with_framework:
        fw = os.path.join(app, "Frameworks", "DemoKit.framework")
        os.makedirs(fw, exist_ok=True)
        fw_info = {
            "CFBundleIdentifier": bundle_id + ".kit",
            "CFBundleExecutable": "DemoKit",
            "CFBundlePackageType": "FMWK",
            "CFBundleVersion": "1",
        }
        with open(os.path.join(fw, "Info.plist"), "wb") as handle:
            plistlib.dump(fw_info, handle, fmt=plistlib.FMT_BINARY)
        with open(os.path.join(fw, "DemoKit"), "wb") as handle:
            handle.write(make_macho(filetype=MH_DYLIB, text_size=0x2000, data_size=0x1000))

    if with_extension:
        appex = os.path.join(app, "PlugIns", "Widget.appex")
        os.makedirs(appex, exist_ok=True)
        appex_info = {
            "CFBundleIdentifier": bundle_id + ".widget",
            "CFBundleExecutable": "Widget",
            "CFBundlePackageType": "XPC!",
            "CFBundleVersion": "1",
        }
        with open(os.path.join(appex, "Info.plist"), "wb") as handle:
            plistlib.dump(appex_info, handle, fmt=plistlib.FMT_BINARY)
        with open(os.path.join(appex, "Widget"), "wb") as handle:
            handle.write(make_macho(text_size=0x2000, data_size=0x1000))
        with open(os.path.join(appex, "widget.json"), "wb") as handle:
            handle.write(b'{"kind": "test"}')

    return app


def make_ipa(app_dir: str, out_path: str) -> str:
    """Zip the ``Payload`` folder around *app_dir* into an IPA.

    Executable-looking files get the ``0755`` bit, as Xcode produces them.
    """
    import stat as _stat

    payload_root = os.path.dirname(app_dir)  # .../Payload
    base = os.path.dirname(payload_root)
    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for folder, dirs, files in os.walk(payload_root):
            dirs.sort()
            folder_path = Path(folder)
            rel_dir = folder_path.relative_to(base).as_posix()
            zi = zipfile.ZipInfo(rel_dir + "/")
            zi.create_system = 3
            zi.external_attr = ((_stat.S_IFDIR | 0o755) << 16) | 0x10
            archive.writestr(zi, b"")
            for name in sorted(files):
                full = folder_path / name
                rel = full.relative_to(base).as_posix()
                executable = "." not in name or name.endswith((".dylib", ".so"))
                mode = 0o755 if executable else 0o644
                zi = zipfile.ZipInfo(rel)
                zi.create_system = 3
                zi.external_attr = (_stat.S_IFREG | mode) << 16
                archive.writestr(zi, full.read_bytes())
    return out_path
