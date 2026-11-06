"""Thin ctypes bridge to a locally built ``apple_auth.dll``.

The native library (MIT, built from ``apple-auth``) implements Apple's ADI
provisioning format — including v3 state files — and can derive the one-time
password used in ``X-Apple-I-MD`` from an existing ADI file plus the machine's
hardware digest.  That is the piece the pure-Python port cannot do cheaply.

Build it with::

    cmake -S apple-auth-src -B apple-auth-build -G "Visual Studio 17 2022" -A x64 \\
          -DCMAKE_TOOLCHAIN_FILE=<vcpkg>/scripts/buildsystems/vcpkg.cmake \\
          -DAPPLE_AUTH_WITH_CLIENT=OFF -DAPPLE_AUTH_WITH_CURL=OFF \\
          -DAPPLE_AUTH_BUILD_EXAMPLES=OFF -DBUILD_SHARED_LIBS=ON
    cmake --build apple-auth-build --config Release

Point ``IPASIGN_APPLE_AUTH_DLL`` at the resulting ``apple_auth.dll`` (its
mbedtls/curl dependencies must sit next to it or on ``PATH``).
"""

from __future__ import annotations

from ipasign import paths

import base64
import ctypes
import os
import time
from pathlib import Path
from typing import Optional

HARDWARE_ID_SIZE = 20
MACHINE_ID_SIZE = 60
OTP_SIZE = 16

AAUTH_OK = 0




class AnisetteError(RuntimeError):
    """Raised when the native library is missing or returns an error."""


def find_library() -> Path:
    explicit = os.environ.get("IPASIGN_APPLE_AUTH_DLL")
    if explicit:
        path = Path(explicit)
        if not path.is_file():
            raise AnisetteError(f"IPASIGN_APPLE_AUTH_DLL not found: {path}")
        return path
    found = paths.find_native(
        "apple_auth.dll", "libapple_auth.so", "libapple_auth.dylib"
    )
    if found is not None:
        return found
    raise AnisetteError(
        "cannot find the apple-auth core library (apple_auth.dll).\n"
        "See the README for build instructions, then put the library in "
        "~/.ipasign/native/ or point IPASIGN_APPLE_AUTH_DLL at it."
    )


class _Native:
    def __init__(self, path: Path):
        # mbedtls / curl DLLs live next to the vcpkg build tree.
        for extra in {
            path.parent,
            path.parent.parent / "vcpkg_installed" / "x64-windows" / "bin",
        }:
            if extra.is_dir():
                try:
                    os.add_dll_directory(str(extra))
                except (AttributeError, OSError):
                    pass
        self.lib = ctypes.CDLL(str(path))
        self._bind()

    def _bind(self) -> None:
        lib = self.lib
        lib.aauth_last_error.restype = ctypes.c_char_p
        lib.aauth_last_error.argtypes = []

        lib.aauth_local_hardware_id.restype = ctypes.c_int
        lib.aauth_local_hardware_id.argtypes = [ctypes.c_char_p, ctypes.c_size_t]

        lib.aauth_time_counter.restype = ctypes.c_int
        lib.aauth_time_counter.argtypes = [ctypes.c_int64, ctypes.POINTER(ctypes.c_uint32)]

        lib.aauth_profile_import.restype = ctypes.c_int
        lib.aauth_profile_import.argtypes = [
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        lib.aauth_profile_free.restype = None
        lib.aauth_profile_free.argtypes = [ctypes.c_void_p]

        for name in ("aauth_profile_machine_id", "aauth_profile_otp"):
            fn = getattr(lib, name)
            fn.restype = ctypes.c_int
            fn.argtypes = [
                ctypes.c_void_p,
                ctypes.c_size_t,  # counter (otp) / unused padding for machine_id
                ctypes.c_char_p,
                ctypes.c_size_t,
            ]
        # machine_id takes (profile, output, capacity); otp takes (profile, counter, output, capacity)
        lib.aauth_profile_machine_id.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_size_t,
        ]

        lib.aauth_provisioning_begin.restype = ctypes.c_int
        lib.aauth_provisioning_begin.argtypes = [
            ctypes.c_char_p, ctypes.c_size_t,   # challenge
            ctypes.c_char_p, ctypes.c_uint32,   # hardware[20], unix seconds
            ctypes.c_char_p, ctypes.c_size_t,   # selector (NULL)
            ctypes.c_char_p, ctypes.c_char_p,   # body entropy (NULL), nonce (NULL)
            ctypes.POINTER(ctypes.c_void_p),
        ]
        lib.aauth_provisioning_request.restype = ctypes.c_int
        lib.aauth_provisioning_request.argtypes = [
            ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_size_t),
        ]
        lib.aauth_provisioning_finish.restype = ctypes.c_int
        lib.aauth_provisioning_finish.argtypes = [
            ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t,
            ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p),
        ]
        lib.aauth_provisioning_free.restype = None
        lib.aauth_provisioning_free.argtypes = [ctypes.c_void_p]

        lib.aauth_profile_export.restype = ctypes.c_int
        lib.aauth_profile_export.argtypes = [
            ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32,
            ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p,
            ctypes.c_char_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
        ]

    def _raise(self) -> None:
        message = self.lib.aauth_last_error()
        raise AnisetteError(message.decode("utf-8", "replace") if message else "native error")

    def hardware_id(self) -> bytes:
        buf = ctypes.create_string_buffer(HARDWARE_ID_SIZE)
        status = self.lib.aauth_local_hardware_id(buf, HARDWARE_ID_SIZE)
        if status != AAUTH_OK:
            self._raise()
        return buf.raw

    def time_counter(self, when: Optional[float] = None) -> int:
        counter = ctypes.c_uint32(0)
        status = self.lib.aauth_time_counter(int(when or time.time()), ctypes.byref(counter))
        if status != AAUTH_OK:
            self._raise()
        return counter.value

    def import_profile(self, data: bytes, hardware: bytes, filename: str = "adi.pb"):
        handle = ctypes.c_void_p()
        status = self.lib.aauth_profile_import(
            data, len(data), hardware, filename.encode(), ctypes.byref(handle)
        )
        if status != AAUTH_OK:
            self._raise()
        return handle

    def machine_id(self, profile) -> bytes:
        buf = ctypes.create_string_buffer(MACHINE_ID_SIZE)
        status = self.lib.aauth_profile_machine_id(profile, buf, MACHINE_ID_SIZE)
        if status != AAUTH_OK:
            self._raise()
        return buf.raw

    def otp(self, profile, counter: int) -> bytes:
        buf = ctypes.create_string_buffer(OTP_SIZE)
        status = self.lib.aauth_profile_otp(profile, counter, buf, OTP_SIZE)
        if status != AAUTH_OK:
            self._raise()
        return buf.raw

    def free(self, profile) -> None:
        self.lib.aauth_profile_free(profile)

    # ---- provisioning -------------------------------------------------

    def provisioning_begin(self, challenge: bytes, hardware: bytes, seconds: int):
        session = ctypes.c_void_p()
        status = self.lib.aauth_provisioning_begin(
            challenge, len(challenge), hardware, seconds, None, 0, None, None,
            ctypes.byref(session),
        )
        if status != AAUTH_OK:
            self._raise()
        return session

    def provisioning_request(self, session) -> bytes:
        size = ctypes.c_size_t(0)
        status = self.lib.aauth_provisioning_request(
            session, None, 0, ctypes.byref(size)
        )
        if status not in (AAUTH_OK, 3):
            self._raise()
        buffer = ctypes.create_string_buffer(size.value)
        status = self.lib.aauth_provisioning_request(
            session, buffer, size.value, ctypes.byref(size)
        )
        if status != AAUTH_OK:
            self._raise()
        return buffer.raw[: size.value]

    def provisioning_finish(self, session, ptm: bytes, trust_key: bytes):
        profile = ctypes.c_void_p()
        status = self.lib.aauth_provisioning_finish(
            session, ptm, len(ptm), trust_key, ctypes.byref(profile)
        )
        if status != AAUTH_OK:
            self._raise()
        return profile

    def export_profile(
        self, profile, hardware: bytes, filename: str = "adi.pb",
        version: int = 3, prefix: bytes = b"", iv: "bytes | None" = None,
    ) -> bytes:
        iv = iv or os.urandom(16)
        size = ctypes.c_size_t(0)
        status = self.lib.aauth_profile_export(
            profile, hardware, filename.encode(), version,
            prefix, len(prefix), iv, None, 0, ctypes.byref(size),
        )
        if status not in (AAUTH_OK, 3):
            self._raise()
        buffer = ctypes.create_string_buffer(size.value)
        status = self.lib.aauth_profile_export(
            profile, hardware, filename.encode(), version,
            prefix, len(prefix), iv, buffer, size.value, ctypes.byref(size),
        )
        if status != AAUTH_OK:
            self._raise()
        return buffer.raw[: size.value]


class AnisetteProfile:
    """Generates Apple device-attestation headers from an ADI state file."""

    def __init__(self, adi_path: "str | Path", dll: Optional["str | Path"] = None):
        self.adi_path = Path(adi_path)
        library = Path(dll) if dll else find_library()
        self._native = _Native(library)
        self._hardware = self._native.hardware_id()
        self._profile = self._native.import_profile(
            self.adi_path.read_bytes(), self._hardware, self.adi_path.name
        )

    @property
    def hardware_id(self) -> bytes:
        return self._hardware

    @property
    def machine_id_base64(self) -> str:
        return base64.b64encode(self._native.machine_id(self._profile)).decode()

    def otp_base64(self, when: Optional[float] = None) -> str:
        counter = self._native.time_counter(when)
        return base64.b64encode(self._native.otp(self._profile, counter)).decode()

    def headers(self, when: Optional[float] = None) -> dict:
        """Headers that make a request look like it came from this Mac."""
        return {
            "X-Apple-I-MD": self.otp_base64(when),
            "X-Apple-I-MD-M": self.machine_id_base64,
        }

    def close(self) -> None:
        if self._profile:
            self._native.free(self._profile)
            self._profile = None

    def __enter__(self) -> "AnisetteProfile":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def default_adi() -> Optional[Path]:
    base = Path.home() / "AppData/Local/Sideloadly"
    candidates = sorted(base.glob("*/adi.pb")) if base.is_dir() else []
    return candidates[0] if candidates else None


if __name__ == "__main__":  # pragma: no cover - diagnostic
    adi = default_adi()
    if adi is None:
        raise SystemExit("no ADI file found")
    with AnisetteProfile(adi) as profile:
        print("adi:", adi)
        print("hardware:", profile.hardware_id.hex())
        print("machine id:", profile.machine_id_base64)
        print("otp:", profile.otp_base64())
