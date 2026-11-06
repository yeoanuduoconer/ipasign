"""Exception hierarchy used across ipasign."""

from __future__ import annotations


class IpasignError(Exception):
    """Base class for every error raised by ipasign."""


class MachOError(IpasignError):
    """Raised when a Mach-O file cannot be parsed or rewritten."""


class SignatureError(IpasignError):
    """Raised when a code signature cannot be built or verified."""


class ProfileError(IpasignError):
    """Raised for invalid or unusable provisioning profiles."""


class IdentityError(IpasignError):
    """Raised for unusable signing identities (p12, certificates, keys)."""


class BundleError(IpasignError):
    """Raised when an app bundle / IPA is malformed."""


class UnsupportedError(IpasignError):
    """Raised for intentionally unsupported constructs."""
