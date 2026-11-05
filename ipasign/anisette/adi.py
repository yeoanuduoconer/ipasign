"""Apple ADI (Anisette Device Identity) state files — parsing only.

An ADI file is what makes Apple believe a request comes from a real Mac.
Version 3 files are laid out as::

    0..4    version          (big endian uint32, 3 for current files)
    4..8    prefix length    (big endian uint32)
    8..     prefix           (device / provisioning metadata)
    ...     iv               (16 bytes)
    ...     ciphertext       (multiple of 16)
    end-20  authentication   (20 bytes, SHA-1 based)

The ciphertext is AES-encrypted with a key derived from a hardware digest
via a heavily obfuscated MD5 diffusion routine, which is why this module only
implements the envelope: everything inside needs the native implementation.

Porting status: outer envelope ✅, body crypto ❌ (see the roadmap below).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

HEADER_SIZE = 8
IV_SIZE = 16
TAG_SIZE = 20
MIN_CIPHERTEXT = 16


class AdiError(ValueError):
    """Raised when an ADI state file is malformed or unsupported."""


@dataclass
class StateFile:
    """Outer structure of a v1/v3 ADI state file."""

    version: int
    prefix: bytes
    iv: bytes
    ciphertext: bytes
    tag: bytes
    raw: bytes

    @property
    def body_size(self) -> int:
        return len(self.ciphertext)

    def describe(self) -> dict:
        return {
            "version": self.version,
            "prefix_size": len(self.prefix),
            "iv": self.iv.hex(),
            "ciphertext_size": len(self.ciphertext),
            "tag": self.tag.hex(),
            "raw_size": len(self.raw),
        }

    def prefix_words(self) -> list:
        """Best-effort: interpret the prefix as big-endian words."""
        usable = len(self.prefix) - (len(self.prefix) % 4)
        return list(struct.unpack(f">{usable // 4}I", self.prefix[:usable]))


def parse_state_file(data: bytes) -> StateFile:
    """Parse the ADI envelope; raises :class:`AdiError` when it is malformed."""
    minimum = HEADER_SIZE + IV_SIZE + MIN_CIPHERTEXT + TAG_SIZE
    if len(data) < minimum:
        raise AdiError(f"truncated ADI file: {len(data)} bytes (need >= {minimum})")

    version = struct.unpack_from(">I", data, 0)[0]
    if version not in (1, 3):
        raise AdiError(f"unsupported ADI version: {version}")
    prefix_size = struct.unpack_from(">I", data, 4)[0]
    if prefix_size > len(data) - minimum:
        raise AdiError("ADI prefix length exceeds file size")

    prefix_start = HEADER_SIZE
    iv_start = prefix_start + prefix_size
    ciphertext_start = iv_start + IV_SIZE
    tag_start = len(data) - TAG_SIZE
    ciphertext_size = tag_start - ciphertext_start
    if ciphertext_size <= 0 or ciphertext_size % IV_SIZE != 0:
        raise AdiError(
            f"ADI ciphertext is not block aligned ({ciphertext_size} bytes)"
        )

    return StateFile(
        version=version,
        prefix=data[prefix_start:iv_start],
        iv=data[iv_start:ciphertext_start],
        ciphertext=data[ciphertext_start:tag_start],
        tag=data[tag_start:],
        raw=data,
    )


def load_state_file(path: "str | Path") -> StateFile:
    return parse_state_file(Path(path).read_bytes())


def describe_file(path: Optional["str | Path"] = None, data: Optional[bytes] = None) -> dict:
    if data is None:
        if path is None:
            raise AdiError("either path or data is required")
        data = Path(path).read_bytes()
    state = parse_state_file(data)
    info = state.describe()
    info["prefix_words"] = [f"{word:08x}" for word in state.prefix_words()]
    return info


if __name__ == "__main__":  # pragma: no cover - tiny diagnostic helper
    import json
    import sys

    target = sys.argv[1]
    print(json.dumps(describe_file(target), indent=2, ensure_ascii=False))
