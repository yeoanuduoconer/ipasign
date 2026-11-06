"""ipasign - iOS IPA re-signing toolkit.

The public API is intentionally small::

    from ipasign import sign_ipa, SignOptions

    report = sign_ipa("in.ipa", "out.ipa", identity=identity,
                      profile=profile, options=SignOptions())
"""

from ipasign.core.errors import (
    BundleError,
    IdentityError,
    IpasignError,
    MachOError,
    ProfileError,
    SignatureError,
    UnsupportedError,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "BundleError",
    "IdentityError",
    "IpasignError",
    "MachOError",
    "ProfileError",
    "SignatureError",
    "UnsupportedError",
]
