"""Anisette (device attestation) research module.

Why this package exists
-----------------------

Apple's GrandSlam login rejects requests whose ``X-Apple-I-MD`` one-time
password was not produced by a *provisioned* device identity (ADI).  Public
anisette servers hand out legacy v1 identities which Apple now answers with
``-80045``; current clients (Sideloadly, Xcode, AltStore) use v3 files whose
body is bound to the machine's hardware digest.

Status
------

* ``adi.parse_state_file`` — v1/v3 envelope parsing ✅ (tested)
* body decryption — needs the hardware-bound key schedule ❌
* OTP generation — table driven, not started ❌

The reference implementation (MIT, C++20) lives at
``E:\\tools\\ipasign\\apple-auth-src``; ``ipasign.anisette.adi`` mirrors its
``parse_state_file`` semantics so the two can be compared field by field.
"""

from .adi import AdiError, StateFile, load_state_file, parse_state_file

__all__ = ["AdiError", "StateFile", "load_state_file", "parse_state_file"]
