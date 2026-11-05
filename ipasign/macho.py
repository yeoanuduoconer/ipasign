"""Mach-O parsing and iOS code-signature generation.

This module implements the on-disk format described in Apple's
``cs_blobs.h``: an embedded signature is a *SuperBlob* made of a
``CodeDirectory``, a (possibly empty) requirement set, the entitlements
blob and a CMS signature over the CodeDirectory.

The signing entry point is :func:`sign_macho`, which takes a thin or
universal Mach-O image and returns a new image with a fresh signature
appended at its end.  The implementation is deliberately allocation-light
and preserves everything the original binary had (load commands, segments,
padding), only rewriting the ``LC_CODE_SIGNATURE`` and ``__LINKEDIT``
fields that must change.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from . import cms, der
from .errors import MachOError, SignatureError

# -- Mach-O magics ---------------------------------------------------------
FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF
MH_MAGIC = 0xFEEDFACE
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM = 0xCEFAEDFE
MH_CIGAM_64 = 0xCFFAEDFE

# -- load commands ---------------------------------------------------------
LC_SEGMENT = 0x1
LC_SEGMENT_64 = 0x19
LC_CODE_SIGNATURE = 0x1D
LC_ENCRYPTION_INFO = 0x21
LC_ENCRYPTION_INFO_64 = 0x2C

# -- file types ------------------------------------------------------------
MH_OBJECT = 0x1
MH_EXECUTE = 0x2
MH_DYLIB = 0x6
MH_BUNDLE = 0x8
MH_DYLIB_STUB = 0x9
MH_DSYM = 0xA

# -- CodeDirectory / SuperBlob magics --------------------------------------
CSMAGIC_REQUIREMENT = 0xFADE0C00
CSMAGIC_REQUIREMENTS = 0xFADE0C01
CSMAGIC_CODEDIRECTORY = 0xFADE0C02
CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xFADE7171
CSMAGIC_EMBEDDED_DER_ENTITLEMENTS = 0xFADE7172
CSMAGIC_BLOBWRAPPER = 0xFADE0B01

CSSLOT_CODEDIRECTORY = 0
CSSLOT_INFOSLOT = 1
CSSLOT_REQUIREMENTS = 2
CSSLOT_RESOURCEDIR = 3
CSSLOT_APPLICATION = 4
CSSLOT_ENTITLEMENTS = 5
CSSLOT_DER_ENTITLEMENTS = 7
CSSLOT_ALTERNATE_CODEDIRECTORIES = 0x1000
CSSLOT_SIGNATURESLOT = 0x10000

# -- CodeDirectory constants -----------------------------------------------
CD_VERSION = 0x20400
HASH_SHA1 = 1
HASH_SHA256 = 2
PAGE_SIZE_LOG2 = 12
CS_ADHOC = 0x00000002
CS_REQUIRE_LV = 0x00002000
CS_EXECSEG_MAIN_BINARY = 0x1

_CPU_NAMES = {
    7: "x86",
    0x01000007: "x86_64",
    12: "arm",
    0x0100000C: "arm64",
    0x0200000C: "arm64_32",
}

_endian_fmt = {"<": "little", ">": "big"}


def cpu_name(cputype: int) -> str:
    return _CPU_NAMES.get(cputype, f"cpu{cputype:#x}")


def align(value: int, alignment: int) -> int:
    if alignment <= 1:
        return value
    return (value + alignment - 1) & ~(alignment - 1)


def is_macho(data: bytes) -> bool:
    if len(data) < 4:
        return False
    be = int.from_bytes(data[:4], "big")
    if be in (FAT_MAGIC, FAT_MAGIC_64):
        return True
    le = int.from_bytes(data[:4], "little")
    return le in (MH_MAGIC, MH_MAGIC_64, MH_CIGAM, MH_CIGAM_64)


def is_encrypted(data: bytes) -> bool:
    """True when any slice carries a non-zero ``cryptid`` (App Store DRM)."""
    try:
        image = split_slices(data)
    except MachOError:
        return False
    for slice_ in image.slices:
        try:
            if parse_slice_layout(slice_.data).encrypted:
                return True
        except MachOError:
            continue
    return False


# ---------------------------------------------------------------------------
# Layout model
# ---------------------------------------------------------------------------

@dataclass
class Segment:
    name: str
    vmaddr: int
    vmsize: int
    fileoff: int
    filesize: int
    cmd_off: int
    vmsize_off: int
    filesize_off: int


@dataclass
class CodeSignatureLC:
    cmd_off: int
    dataoff: int
    datasize: int
    dataoff_off: int
    datasize_off: int


@dataclass
class SliceLayout:
    endian: str
    is64: bool
    cputype: int
    cpusubtype: int
    filetype: int
    header_size: int
    ncmds: int
    sizeofcmds: int
    ncmds_off: int
    sizeofcmds_off: int
    segments: Dict[str, Segment]
    code_sig: Optional[CodeSignatureLC]
    encrypted: bool = False

    @property
    def text(self) -> Optional[Segment]:
        return self.segments.get("__TEXT")

    @property
    def linkedit(self) -> Optional[Segment]:
        return self.segments.get("__LINKEDIT")


def _u32(data: bytes, off: int, endian: str) -> int:
    return struct.unpack_from(endian + "I", data, off)[0]


def _u64(data: bytes, off: int, endian: str) -> int:
    return struct.unpack_from(endian + "Q", data, off)[0]


def _put32(buf: bytearray, off: int, value: int, endian: str) -> None:
    struct.pack_into(endian + "I", buf, off, value & 0xFFFFFFFF)


def _put64(buf: bytearray, off: int, value: int, endian: str) -> None:
    struct.pack_into(endian + "Q", buf, off, value & 0xFFFFFFFFFFFFFFFF)


def parse_slice_layout(data: bytes) -> SliceLayout:
    """Parse the header / load commands of one thin Mach-O slice."""
    if len(data) < 32:
        raise MachOError("file too small to be Mach-O")
    magic_le = int.from_bytes(data[:4], "little")
    if magic_le in (MH_MAGIC, MH_MAGIC_64):
        endian = "<"
    elif magic_le in (MH_CIGAM, MH_CIGAM_64):
        endian = ">"
    else:
        raise MachOError(f"not a Mach-O slice (magic {data[:4].hex()})")
    is64 = magic_le in (MH_MAGIC_64, MH_CIGAM_64)
    cputype = _u32(data, 4, endian)
    cpusubtype = _u32(data, 8, endian)
    filetype = _u32(data, 12, endian)
    ncmds = _u32(data, 16, endian)
    sizeofcmds = _u32(data, 20, endian)
    header_size = 32 if is64 else 28
    if header_size + sizeofcmds > len(data):
        raise MachOError("load commands exceed file size")

    segments: Dict[str, Segment] = {}
    code_sig: Optional[CodeSignatureLC] = None
    encrypted = False
    offset = header_size
    for _ in range(ncmds):
        if offset + 8 > len(data):
            raise MachOError("truncated load command")
        cmd = _u32(data, offset, endian)
        cmdsize = _u32(data, offset + 4, endian)
        if cmdsize < 8 or offset + cmdsize > len(data):
            raise MachOError("invalid load command size")
        if cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64) and cmdsize >= 20:
            if _u32(data, offset + 16, endian) != 0:
                encrypted = True
        if cmd in (LC_SEGMENT, LC_SEGMENT_64):
            raw_name = data[offset + 8:offset + 24]
            name = raw_name.split(b"\x00")[0].decode("latin-1")
            if is64:
                vmaddr = _u64(data, offset + 24, endian)
                vmsize = _u64(data, offset + 32, endian)
                fileoff = _u64(data, offset + 40, endian)
                filesize = _u64(data, offset + 48, endian)
                vmsize_off, filesize_off = offset + 32, offset + 48
            else:
                vmaddr = _u32(data, offset + 24, endian)
                vmsize = _u32(data, offset + 28, endian)
                fileoff = _u32(data, offset + 32, endian)
                filesize = _u32(data, offset + 36, endian)
                vmsize_off, filesize_off = offset + 28, offset + 36
            segments[name] = Segment(
                name=name, vmaddr=vmaddr, vmsize=vmsize, fileoff=fileoff,
                filesize=filesize, cmd_off=offset, vmsize_off=vmsize_off,
                filesize_off=filesize_off,
            )
        elif cmd == LC_CODE_SIGNATURE:
            if cmdsize < 16:
                raise MachOError("truncated LC_CODE_SIGNATURE")
            code_sig = CodeSignatureLC(
                cmd_off=offset,
                dataoff=_u32(data, offset + 8, endian),
                datasize=_u32(data, offset + 12, endian),
                dataoff_off=offset + 8,
                datasize_off=offset + 12,
            )
        offset += cmdsize

    return SliceLayout(
        endian=endian, is64=is64, cputype=cputype, cpusubtype=cpusubtype,
        filetype=filetype, header_size=header_size, ncmds=ncmds,
        sizeofcmds=sizeofcmds, ncmds_off=16, sizeofcmds_off=20,
        segments=segments, code_sig=code_sig, encrypted=encrypted,
    )


@dataclass
class Slice:
    cputype: int
    cpusubtype: int
    align: int
    offset: int
    size: int
    data: bytes


@dataclass
class MachOImage:
    slices: List[Slice]
    is_fat: bool
    fat_is64: bool = False


def split_slices(data: bytes) -> MachOImage:
    """Split a (possibly universal) Mach-O image into slices."""
    if len(data) < 8:
        raise MachOError("file too small to be Mach-O")
    magic = int.from_bytes(data[:4], "big")
    if magic in (FAT_MAGIC, FAT_MAGIC_64):
        fat64 = magic == FAT_MAGIC_64
        nfat = int.from_bytes(data[4:8], "big")
        if nfat == 0 or nfat > 64:
            raise MachOError(f"implausible fat architecture count: {nfat}")
        slices: List[Slice] = []
        entry = 32 if fat64 else 20
        for index in range(nfat):
            base = 8 + index * entry
            if base + entry > len(data):
                raise MachOError("truncated fat header")
            cputype, cpusubtype = struct.unpack_from(">II", data, base)
            if fat64:
                offset, size = struct.unpack_from(">QQ", data, base + 8)
                align_exp = struct.unpack_from(">I", data, base + 24)[0]
            else:
                offset, size, align_exp = struct.unpack_from(">III", data, base + 8)
            if offset + size > len(data):
                raise MachOError("fat slice exceeds file size")
            slices.append(
                Slice(
                    cputype=cputype, cpusubtype=cpusubtype,
                    align=align_exp or 0, offset=offset, size=size,
                    data=data[offset:offset + size],
                )
            )
        return MachOImage(slices=slices, is_fat=True, fat_is64=fat64)

    layout = parse_slice_layout(data)
    return MachOImage(
        slices=[
            Slice(
                cputype=layout.cputype, cpusubtype=layout.cpusubtype,
                align=0, offset=0, size=len(data), data=data,
            )
        ],
        is_fat=False,
    )


# ---------------------------------------------------------------------------
# Blob builders
# ---------------------------------------------------------------------------

def empty_requirements() -> bytes:
    """A structurally valid, empty requirement set."""
    return struct.pack(">III", CSMAGIC_REQUIREMENTS, 12, 0)


# -- requirement expression opcodes (libsecurity_codesigning/reqdumper) -----
OP_FALSE = 0
OP_TRUE = 1
OP_IDENT = 2
OP_AND = 6
OP_OR = 7
OP_NOT = 9
OP_APPLE_GENERIC_ANCHOR = 15
REQ_TYPE_DESIGNATED = 3


def designated_requirement(identifier: str) -> bytes:
    """``identifier "X" and anchor apple generic`` as a requirement set.

    This is a subset of what ``codesign`` emits (which also pins the leaf
    certificate's CN and Apple's certificate extensions).  The subset is a
    valid designated requirement and is satisfied by any Apple-issued
    developer certificate, which is what re-signed apps need.
    """
    encoded = identifier.encode("utf-8")
    expression = b"".join(
        [
            struct.pack(">I", OP_AND),
            struct.pack(">I", OP_IDENT),
            struct.pack(">I", len(encoded)),
            encoded,
            struct.pack(">I", OP_APPLE_GENERIC_ANCHOR),
        ]
    )
    requirement = struct.pack(
        ">III", CSMAGIC_REQUIREMENT, 12 + len(expression), 1
    ) + expression
    return (
        struct.pack(">III", CSMAGIC_REQUIREMENTS, 20 + len(requirement), 1)
        + struct.pack(">II", REQ_TYPE_DESIGNATED, 20)
        + requirement
    )


def entitlements_blob(xml: bytes) -> bytes:
    return struct.pack(">II", CSMAGIC_EMBEDDED_ENTITLEMENTS, 8 + len(xml)) + xml


def der_entitlements_blob(payload: bytes) -> bytes:
    """Wrap a DER plist in the embedded-DER-entitlements blob header."""
    return (
        struct.pack(">II", CSMAGIC_EMBEDDED_DER_ENTITLEMENTS, 8 + len(payload))
        + payload
    )


def blob_wrapper(payload: bytes) -> bytes:
    """Wrap a CMS payload the way Apple (and zsign) store the signature slot."""
    return struct.pack(">II", CSMAGIC_BLOBWRAPPER, 8 + len(payload)) + payload


def unwrap_blob(blob: bytes) -> bytes:
    """Strip a BlobWrapper header if present, otherwise return *blob*."""
    if len(blob) >= 8:
        magic, length = struct.unpack_from(">II", blob, 0)
        if magic == CSMAGIC_BLOBWRAPPER and 8 <= length <= len(blob):
            return blob[8:length]
    return blob


def build_code_directory(
    code_hashes: Sequence[bytes],
    special_slots: Dict[int, bytes],
    *,
    identifier: str,
    team_id: str = "",
    code_limit: int,
    flags: int = 0,
    exec_seg: Tuple[int, int, int] = (0, 0, 0),
    hash_type: int = HASH_SHA256,
    page_size: int = PAGE_SIZE_LOG2,
    platform: int = 0,
    version: int = CD_VERSION,
) -> bytes:
    """Assemble a CodeDirectory blob (big-endian, as Apple writes it)."""
    hash_size = {HASH_SHA1: 20, HASH_SHA256: 32}.get(hash_type)
    if hash_size is None:
        raise SignatureError(f"unsupported hash type {hash_type}")
    for index, digest in enumerate(code_hashes):
        if len(digest) != hash_size:
            raise SignatureError(f"code hash {index} has wrong length")

    ident = identifier.encode("utf-8") + b"\x00"
    team = team_id.encode("utf-8") + b"\x00" if team_id else b""
    n_special = max(special_slots) if special_slots else 0
    for slot, digest in special_slots.items():
        if len(digest) != hash_size:
            raise SignatureError(f"special slot {slot} has wrong length")
    n_code = len(code_hashes)

    header_len = 88
    ident_off = header_len
    team_off = ident_off + len(ident) if team else 0
    special_area = b"".join(
        special_slots.get(slot, b"\x00" * hash_size)
        for slot in range(n_special, 0, -1)
    )
    hash_off = header_len + len(ident) + len(team) + len(special_area)
    length = hash_off + n_code * hash_size

    header = struct.pack(
        ">9I4B4I4Q",
        CSMAGIC_CODEDIRECTORY,
        length,
        version,
        flags,
        hash_off,
        ident_off,
        n_special,
        n_code,
        code_limit,
        hash_size,
        hash_type,
        platform,
        page_size,
        0,          # spare2
        0,          # scatterOffset
        team_off,
        0,          # spare3
        0,          # codeLimit64 (0 == use codeLimit)
        exec_seg[0],
        exec_seg[1],
        exec_seg[2],
    )
    if len(header) != header_len:
        raise SignatureError("internal: CodeDirectory header size mismatch")
    return header + ident + team + special_area + b"".join(code_hashes)


def _pad_signature(blob: bytes, alignment: int = 16) -> bytes:
    """Pad the embedded signature area to a 16-byte boundary.

    Apple's codesign (and zsign) reserve an aligned signature area; iOS 26
    rejects unaligned blobs with ``0xe8008019`` ("does not have a valid
    signature").  The padding sits *after* the SuperBlob, outside
    ``codeLimit``, so it is not hashed and ``length`` stays exact.
    """
    remainder = len(blob) % alignment
    if not remainder:
        return blob
    return blob + b"\x00" * (alignment - remainder)


def build_superblob(blobs: Sequence[Tuple[int, bytes]]) -> bytes:
    """Wrap ``(type, blob)`` pairs into a SuperBlob, ordered by type."""
    ordered = sorted(blobs, key=lambda item: item[0])
    count = len(ordered)
    header_len = 12 + 8 * count
    offsets = []
    cursor = header_len
    for _, blob in ordered:
        offsets.append(cursor)
        cursor += len(blob)
    index = b"".join(
        struct.pack(">II", slot_type, offset)
        for (slot_type, _), offset in zip(ordered, offsets)
    )
    header = struct.pack(">III", CSMAGIC_EMBEDDED_SIGNATURE, cursor, count)
    return header + index + b"".join(blob for _, blob in ordered)


def parse_superblob(data: bytes) -> Dict[int, bytes]:
    """Parse an embedded signature SuperBlob into ``{slot: blob}``."""
    if len(data) < 12:
        raise SignatureError("signature blob too small")
    magic, length, count = struct.unpack_from(">III", data, 0)
    if magic != CSMAGIC_EMBEDDED_SIGNATURE:
        raise SignatureError(f"unexpected signature magic {magic:#x}")
    if length > len(data):
        raise SignatureError("signature length exceeds available data")
    out: Dict[int, bytes] = {}
    for index in range(count):
        slot, offset = struct.unpack_from(">II", data, 12 + index * 8)
        if offset > length:
            raise SignatureError(f"blob offset {offset} outside signature")
        blob_len = struct.unpack_from(">I", data, offset + 4)[0]
        out[slot] = data[offset:offset + blob_len]
    return out


@dataclass
class CodeDirectory:
    version: int
    flags: int
    hash_type: int
    hash_size: int
    page_size: int
    identifier: str
    team_id: str
    code_limit: int
    n_special: int
    n_code: int
    special_slots: Dict[int, bytes]
    code_hashes: List[bytes]
    exec_seg: Tuple[int, int, int]
    raw: bytes


def parse_code_directory(blob: bytes) -> CodeDirectory:
    if len(blob) < 44:
        raise SignatureError("CodeDirectory too small")
    magic, length, version, flags, hash_off, ident_off, n_special, n_code, code_limit = (
        struct.unpack_from(">9I", blob, 0)
    )
    if magic != CSMAGIC_CODEDIRECTORY:
        raise SignatureError(f"unexpected CodeDirectory magic {magic:#x}")
    hash_size, hash_type, platform, page_size = struct.unpack_from(">4B", blob, 36)
    spare2, scatter_off, team_off, spare3 = struct.unpack_from(">4I", blob, 40)

    exec_seg = (0, 0, 0)
    code_limit64 = 0
    if version >= 0x20300 and len(blob) >= 64:
        code_limit64 = struct.unpack_from(">Q", blob, 56)[0]
    if version >= 0x20400 and len(blob) >= 88:
        exec_seg = struct.unpack_from(">QQQ", blob, 64)

    def _cstr(offset: int) -> str:
        if not offset:
            return ""
        end = blob.find(b"\x00", offset)
        if end < 0:
            end = len(blob)
        return blob[offset:end].decode("utf-8", "replace")

    identifier = _cstr(ident_off)
    team_id = _cstr(team_off)
    special: Dict[int, bytes] = {}
    for index in range(n_special):
        start = hash_off - (index + 1) * hash_size
        if start < 0:
            break
        # Special slots are stored in reverse: slot 1 sits closest to the
        # code-slot area, slot n_special furthest away.
        special[index + 1] = blob[start:start + hash_size]
    code_hashes = [
        blob[hash_off + i * hash_size:hash_off + (i + 1) * hash_size]
        for i in range(n_code)
    ]
    return CodeDirectory(
        version=version, flags=flags, hash_type=hash_type, hash_size=hash_size,
        page_size=page_size, identifier=identifier, team_id=team_id,
        code_limit=code_limit64 or code_limit, n_special=n_special, n_code=n_code,
        special_slots=special, code_hashes=code_hashes, exec_seg=exec_seg,
        raw=blob[:length],
    )


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------

@dataclass
class SignParameters:
    """Everything needed to sign a single Mach-O image."""

    identifier: str
    key: object = None
    certificates: List[object] = field(default_factory=list)
    team_id: str = ""
    entitlements: Optional[bytes] = None      # XML plist bytes
    info_plist: Optional[bytes] = None        # Info.plist bytes (bundle main binary)
    resource_dir: Optional[bytes] = None      # _CodeSignature/CodeResources bytes
    flags: int = 0
    ad_hoc: bool = False
    # Resource envelope / Info.plist are only hashed into slots when the binary
    # is the main executable of a bundle.  Loose dylibs pass None.


def _page_hashes(code: bytes, page_size: int = 4096) -> List[bytes]:
    return [
        hashlib.sha256(code[offset:offset + page_size]).digest()
        for offset in range(0, len(code), page_size)
    ]


def _ensure_code_signature_lc(data: bytes, layout: SliceLayout) -> bytes:
    """Add an LC_CODE_SIGNATURE load command when the binary lacks one."""
    lc_size = 16
    first_off = min(
        (segment.fileoff for segment in layout.segments.values() if segment.fileoff > 0),
        default=len(data),
    )
    free = first_off - layout.header_size - layout.sizeofcmds
    if free < lc_size:
        raise MachOError(
            "binary has no LC_CODE_SIGNATURE and no room in the header to add one "
            f"({free} bytes free, need {lc_size})"
        )
    if layout.linkedit is None:
        raise MachOError("binary has no __LINKEDIT segment; cannot append a signature")

    lc_off = layout.header_size + layout.sizeofcmds
    dataoff = align(len(data), 16)
    buf = bytearray(data)
    if dataoff > len(buf):
        buf += b"\x00" * (dataoff - len(buf))
    struct.pack_into(
        layout.endian + "IIII", buf, lc_off, LC_CODE_SIGNATURE, lc_size, dataoff, 0
    )
    _put32(buf, layout.ncmds_off, layout.ncmds + 1, layout.endian)
    _put32(buf, layout.sizeofcmds_off, layout.sizeofcmds + lc_size, layout.endian)
    return bytes(buf)


def sign_macho(data: bytes, params: SignParameters) -> bytes:
    """Return *data* re-signed with a fresh embedded signature."""
    image = split_slices(data)
    signed = [_sign_slice(slice_.data, params) for slice_ in image.slices]
    if not image.is_fat:
        return signed[0]
    return _rebuild_fat(image, signed)


def _rebuild_fat(image: MachOImage, signed: Sequence[bytes]) -> bytes:
    count = len(image.slices)
    entry = 32 if image.fat_is64 else 20
    header_len = 8 + count * entry
    offsets: List[int] = []
    cursor = header_len
    for slice_, blob in zip(image.slices, signed):
        alignment = 1 << (slice_.align or 0)
        cursor = align(cursor, alignment)
        offsets.append(cursor)
        cursor += len(blob)
    total = cursor

    out = bytearray(total)
    struct.pack_into(
        ">II", out, 0, FAT_MAGIC_64 if image.fat_is64 else FAT_MAGIC, count
    )
    for index, (slice_, blob) in enumerate(zip(image.slices, signed)):
        base = 8 + index * entry
        if image.fat_is64:
            struct.pack_into(">II", out, base, slice_.cputype, slice_.cpusubtype)
            struct.pack_into(">QQ", out, base + 8, offsets[index], len(blob))
            struct.pack_into(">II", out, base + 24, slice_.align or 0, 0)
        else:
            struct.pack_into(
                ">IIIII", out, base, slice_.cputype, slice_.cpusubtype,
                offsets[index], len(blob), slice_.align or 0,
            )
        out[offsets[index]:offsets[index] + len(blob)] = blob
    return bytes(out)


def _sign_slice(data: bytes, params: SignParameters) -> bytes:
    layout = parse_slice_layout(data)
    if layout.code_sig is None:
        data = _ensure_code_signature_lc(data, layout)
        layout = parse_slice_layout(data)

    code_sig = layout.code_sig
    assert code_sig is not None
    dataoff = code_sig.dataoff
    if dataoff == 0 or dataoff > len(data):
        # Placeholder load command: append the signature at a 16-byte boundary.
        dataoff = align(len(data), 16)
        data = data[:dataoff].ljust(dataoff, b"\x00")
        layout = parse_slice_layout(data)
        code_sig = layout.code_sig
        assert code_sig is not None
    body = data[:dataoff]

    # Keep whatever execSeg flags the previous signer used (codesign sets
    # CS_EXECSEG_ALLOW_UNSIGNED on some app binaries; zsign preserves it).
    original_exec_flags = None
    try:
        existing = read_signatures(data)
        if existing:
            original_exec_flags = existing[0].code_directory.exec_seg[2]
    except Exception:  # noqa: BLE001 - unsigned / unusual binary
        original_exec_flags = None

    linkedit = layout.linkedit
    link_off = linkedit.fileoff if linkedit else 0
    link_vmsize = linkedit.vmsize if linkedit else 0

    exec_seg = (0, 0, 0)
    if layout.text is not None and layout.filetype in (MH_EXECUTE, MH_DYLIB):
        default_flags = CS_EXECSEG_MAIN_BINARY if layout.filetype == MH_EXECUTE else 0
        flags = (
            original_exec_flags
            if original_exec_flags is not None
            else default_flags
        )
        exec_seg = (layout.text.fileoff, layout.text.filesize, flags)

    def assemble(datasize: int, link_filesize: int, link_vmsize_new: int) -> bytes:
        buf = bytearray(body)
        _put32(buf, code_sig.dataoff_off, dataoff, layout.endian)
        _put32(buf, code_sig.datasize_off, datasize, layout.endian)
        if linkedit is not None:
            if layout.is64:
                _put64(buf, linkedit.filesize_off, link_filesize, layout.endian)
                _put64(buf, linkedit.vmsize_off, link_vmsize_new, layout.endian)
            else:
                _put32(buf, linkedit.filesize_off, link_filesize, layout.endian)
                _put32(buf, linkedit.vmsize_off, link_vmsize_new, layout.endian)
        return bytes(buf)

    datasize = 0
    link_filesize = max(0, dataoff - link_off)
    link_vmsize_new = max(link_vmsize, align(link_filesize, 0x1000))

    signature = b""
    for _ in range(4):
        head = assemble(datasize, link_filesize, link_vmsize_new)
        signature = _pad_signature(
            _build_signature(head, dataoff, params, exec_seg)
        )
        if len(signature) == datasize:
            return head + signature
        datasize = len(signature)
        link_filesize = max(0, dataoff - link_off) + datasize
        link_vmsize_new = max(link_vmsize, align(link_filesize, 0x1000))

    # Did not converge (should not happen); fall back to the last attempt.
    head = assemble(len(signature), max(0, dataoff - link_off) + len(signature),
                    max(link_vmsize, align((dataoff - link_off) + len(signature), 0x1000)))
    return head + signature


def _build_signature(
    head: bytes,
    dataoff: int,
    params: SignParameters,
    exec_seg: Tuple[int, int, int],
) -> bytes:
    code_limit = min(dataoff, len(head))
    code_hashes = _page_hashes(head[:code_limit])

    requirements = (
        empty_requirements()
        if params.ad_hoc
        else designated_requirement(params.identifier)
    )

    special_slots: Dict[int, bytes] = {}
    if params.info_plist is not None:
        special_slots[CSSLOT_INFOSLOT] = hashlib.sha256(params.info_plist).digest()
    special_slots[CSSLOT_REQUIREMENTS] = hashlib.sha256(requirements).digest()
    if params.resource_dir is not None:
        special_slots[CSSLOT_RESOURCEDIR] = hashlib.sha256(params.resource_dir).digest()

    ent_blob = None
    der_ent_blob = None
    if params.entitlements is not None:
        import plistlib as _plistlib

        from .derplist import encode_entitlements

        ent_blob = entitlements_blob(params.entitlements)
        special_slots[CSSLOT_ENTITLEMENTS] = hashlib.sha256(ent_blob).digest()
        # iOS 15+ also seals a DER copy of the entitlements; iOS 26 rejects
        # signatures that only carry the XML blob (0xE8008029).
        # zsign only emits the DER copy when there are actual entitlements;
        # frameworks get an empty XML blob and no DER slot.
        entitlements_dict = _plistlib.loads(params.entitlements)
        if entitlements_dict:
            der_ent_blob = der_entitlements_blob(
                encode_entitlements(entitlements_dict)
            )
            special_slots[CSSLOT_DER_ENTITLEMENTS] = hashlib.sha256(
                der_ent_blob
            ).digest()

    if params.info_plist is None and params.resource_dir is None and ent_blob is None:
        special_slots = {}

    cd = build_code_directory(
        code_hashes,
        special_slots,
        identifier=params.identifier,
        team_id=params.team_id,
        code_limit=code_limit,
        flags=params.flags | (CS_ADHOC if params.ad_hoc else 0),
        exec_seg=exec_seg,
    )

    blobs: List[Tuple[int, bytes]] = [(CSSLOT_CODEDIRECTORY, cd)]
    blobs.append((CSSLOT_REQUIREMENTS, requirements))
    if ent_blob is not None:
        blobs.append((CSSLOT_ENTITLEMENTS, ent_blob))
    if der_ent_blob is not None:
        blobs.append((CSSLOT_DER_ENTITLEMENTS, der_ent_blob))
    if not params.ad_hoc:
        if params.key is None or not params.certificates:
            raise SignatureError("signing key and certificates are required")
        cms_blob = cms.build_detached_cms(
            cd, params.key, params.certificates, signing_time=_now(),
            cdhash=hashlib.sha256(cd).digest(),
        )
        # Apple wraps the CMS payload in a BlobWrapper, and so does zsign.
        blobs.append((CSSLOT_SIGNATURESLOT, blob_wrapper(cms_blob)))
    return build_superblob(blobs)


def _now():
    import datetime as _dt

    return _dt.datetime.now(_dt.timezone.utc)


# ---------------------------------------------------------------------------
# Inspection helpers
# ---------------------------------------------------------------------------

@dataclass
class SliceSignature:
    cputype: int
    cpusubtype: int
    code_directory: CodeDirectory
    entitlements: Optional[bytes]
    blobs: Dict[int, bytes]
    cms_blob: Optional[bytes]


def read_signatures(data: bytes) -> List[SliceSignature]:
    """Return the embedded signature of every slice, if present."""
    image = split_slices(data)
    out: List[SliceSignature] = []
    for slice_ in image.slices:
        layout = parse_slice_layout(slice_.data)
        if layout.code_sig is None or not layout.code_sig.datasize:
            continue
        start = layout.code_sig.dataoff
        end = start + layout.code_sig.datasize
        if end > len(slice_.data):
            raise SignatureError("LC_CODE_SIGNATURE points past end of file")
        blobs = parse_superblob(slice_.data[start:end])
        cd_blob = blobs.get(CSSLOT_CODEDIRECTORY)
        if cd_blob is None:
            raise SignatureError("signature has no CodeDirectory")
        ent_blob = blobs.get(CSSLOT_ENTITLEMENTS)
        entitlements = None
        if ent_blob and len(ent_blob) > 8:
            entitlements = ent_blob[8:]
        out.append(
            SliceSignature(
                cputype=slice_.cputype,
                cpusubtype=slice_.cpusubtype,
                code_directory=parse_code_directory(cd_blob),
                entitlements=entitlements,
                blobs=blobs,
                cms_blob=unwrap_blob(blobs[CSSLOT_SIGNATURESLOT])
                if CSSLOT_SIGNATURESLOT in blobs else None,
            )
        )
    return out


def verify_slice_hashes(data: bytes, signature: SliceSignature) -> List[str]:
    """Check page hashes of one slice against its CodeDirectory."""
    problems: List[str] = []
    image = split_slices(data)
    target = None
    for slice_ in image.slices:
        if slice_.cputype == signature.cputype and slice_.cpusubtype == signature.cpusubtype:
            target = slice_
            break
    if target is None:
        return ["slice not found"]
    cd = signature.code_directory
    limit = cd.code_limit
    if limit > len(target.data):
        problems.append(f"codeLimit {limit} exceeds slice size {len(target.data)}")
        limit = len(target.data)
    hashes = _page_hashes(target.data[:limit])
    if len(hashes) != cd.n_code:
        problems.append(f"page count mismatch: file has {len(hashes)}, CD declares {cd.n_code}")
    for index, (expected, actual) in enumerate(zip(cd.code_hashes, hashes)):
        if expected != actual:
            problems.append(f"page {index} hash mismatch")
            if len(problems) > 8:
                problems.append("...")
                break
    return problems
