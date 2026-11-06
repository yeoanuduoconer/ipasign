"""Batch re-sign every IPA in a folder with the same identity and profile.

Usage::

    python examples/batch_sign.py ./ipas ./out \
        --p12 cert.p12 --password 123456 \
        --profile profile.mobileprovision

The script keeps going when one file fails and prints a summary at the end.
"""

from __future__ import annotations

import argparse
import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ipasign.core.bundle import SignOptions, sign_ipa
from ipasign.core.pki import ensure_chain, load_identity
from ipasign.core.profile import ProvisioningProfile


def main() -> int:
    parser = argparse.ArgumentParser(description="Re-sign every IPA in a folder")
    parser.add_argument("source", help="Directory containing .ipa files")
    parser.add_argument("output", help="Output directory")
    parser.add_argument("-c", "--p12", required=True)
    parser.add_argument("-p", "--password")
    parser.add_argument("-m", "--profile", required=True)
    parser.add_argument("-b", "--bundle-id", help="Force this Bundle ID (useful when signing a single app)")
    args = parser.parse_args()

    source = Path(args.source)
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)

    identity = ensure_chain(
        load_identity(args.p12, args.password), log=lambda message: print("  " + message)
    )
    profile = ProvisioningProfile.load(args.profile)
    options = SignOptions(bundle_id=args.bundle_id)

    succeeded, failed = 0, 0
    for ipa in sorted(source.glob("*.ipa")):
        target = output / f"{ipa.stem}-signed.ipa"
        print(f"\n=== {ipa.name} -> {target.name} ===")
        try:
            report = sign_ipa(
                ipa,
                target,
                identity=identity,
                profile=profile,
                options=options,
                log=lambda message: print("  " + message),
            )
            print(f"  done: {report.bundle_id} ({len(report.steps)} Mach-O files)")
            for warning in report.warnings:
                print(f"  [warning] {warning}")
            succeeded += 1
        except Exception as exc:  # noqa: BLE001 - keep the batch going
            print(f"  failed: {exc}")
            traceback.print_exc()
            failed += 1

    print(f"\n{succeeded} succeeded, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
