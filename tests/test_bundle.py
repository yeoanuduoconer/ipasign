"""End-to-end tests: IPA in, signed IPA out."""

from __future__ import annotations

import plistlib
import zipfile
from pathlib import Path

from ipasign.core import macho
from ipasign.core.bundle import SignOptions, sign_app, sign_ipa
from ipasign.core.cms import verify_detached_cms
from ipasign.core.ipa import extract_ipa
from ipasign.core.macho import read_signatures, verify_slice_hashes
from ipasign.core.pki import SigningIdentity
from ipasign.core.profile import ProvisioningProfile

from . import fixtures


def _identity():
    key, cert = fixtures.make_identity()
    return SigningIdentity(key=key, certificates=[cert]), cert


def _walk_macho(root: Path):
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        with path.open("rb") as handle:
            magic = handle.read(4)
        if macho.is_macho(magic):
            yield path


def _assert_signed_tree(root: Path, expected_id: str):
    seen = 0
    for path in _walk_macho(root):
        signatures = read_signatures(path.read_bytes())
        assert signatures, f"{path} has no signature"
        for signature in signatures:
            assert verify_slice_hashes(path.read_bytes(), signature) == []
            if signature.cms_blob:
                verify_detached_cms(signature.cms_blob, signature.code_directory.raw)
        if path.name == "Demo":
            assert signatures[0].code_directory.identifier == expected_id
        elif path.name == "Widget":
            assert signatures[0].code_directory.identifier == expected_id + ".widget"
        seen += 1
    assert seen == 3  # app executable + appex executable + framework binary


def test_sign_ipa_end_to_end(tmp_path):
    identity, cert = _identity()
    profile = ProvisioningProfile.parse(
        fixtures.make_profile(certificates=[cert], app_id="TEAM123456.*")
    )
    app = fixtures.make_app_dir(str(tmp_path / "src"))
    ipa = fixtures.make_ipa(app, str(tmp_path / "in.ipa"))
    out = tmp_path / "out.ipa"

    report = sign_ipa(ipa, out, identity=identity, profile=profile, options=SignOptions())
    assert out.is_file()
    assert report.bundle_id == "com.example.demo"
    assert report.team_id == "TEAM123456"

    work = tmp_path / "unpacked"
    contents = extract_ipa(out, work)
    _assert_signed_tree(contents.app_path, "com.example.demo")

    info = plistlib.loads((contents.app_path / "Info.plist").read_bytes())
    assert info["CFBundleIdentifier"] == "com.example.demo"
    assert (contents.app_path / "embedded.mobileprovision").read_bytes() == profile.raw
    assert (contents.app_path / "_CodeSignature" / "CodeResources").is_file()

    signature = read_signatures((contents.app_path / "Demo").read_bytes())[0]
    ents = plistlib.loads(signature.entitlements)
    assert ents["application-identifier"] == "TEAM123456.com.example.demo"
    assert ents["com.apple.developer.team-identifier"] == "TEAM123456"
    assert ents["keychain-access-groups"] == ["TEAM123456.*"]

    # Extension keeps its own (prefixed) identifier and its own profile copy.
    appex = contents.app_path / "PlugIns" / "Widget.appex"
    appex_signature = read_signatures((appex / "Widget").read_bytes())[0]
    assert appex_signature.code_directory.identifier == "com.example.demo.widget"
    assert (appex / "embedded.mobileprovision").is_file()


def test_bundle_id_is_rewritten_for_explicit_profile(tmp_path):
    identity, cert = _identity()
    profile = ProvisioningProfile.parse(
        fixtures.make_profile(certificates=[cert], app_id="TEAM123456.com.example.demo")
    )
    app = fixtures.make_app_dir(str(tmp_path / "src"), bundle_id="com.other.app")
    ipa = fixtures.make_ipa(app, str(tmp_path / "in.ipa"))
    out = tmp_path / "out.ipa"

    report = sign_ipa(ipa, out, identity=identity, profile=profile)
    assert report.bundle_id == "com.example.demo"
    assert report.warnings

    contents = extract_ipa(out, tmp_path / "unpacked")
    info = plistlib.loads((contents.app_path / "Info.plist").read_bytes())
    assert info["CFBundleIdentifier"] == "com.example.demo"
    widget = plistlib.loads(
        (contents.app_path / "PlugIns" / "Widget.appex" / "Info.plist").read_bytes()
    )
    assert widget["CFBundleIdentifier"] == "com.example.demo.widget"
    signature = read_signatures((contents.app_path / "Demo").read_bytes())[0]
    assert signature.code_directory.identifier == "com.example.demo"


def test_explicit_bundle_id_conflict_raises(tmp_path):
    identity, cert = _identity()
    profile = ProvisioningProfile.parse(
        fixtures.make_profile(certificates=[cert], app_id="TEAM123456.com.allowed.app")
    )
    app = fixtures.make_app_dir(str(tmp_path / "src"), bundle_id="com.other.app")
    ipa = fixtures.make_ipa(app, str(tmp_path / "in.ipa"))
    try:
        sign_ipa(ipa, tmp_path / "out.ipa", identity=identity, profile=profile,
                 options=SignOptions(bundle_id="com.explicit.id"))
    except Exception as exc:  # noqa: BLE001
        assert "does not authorise" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected BundleError")


def test_ipa_repack_preserves_executable_bit(tmp_path):
    identity, cert = _identity()
    profile = ProvisioningProfile.parse(fixtures.make_profile(certificates=[cert]))
    app = fixtures.make_app_dir(str(tmp_path / "src"))
    ipa = fixtures.make_ipa(app, str(tmp_path / "in.ipa"))
    out = tmp_path / "out.ipa"
    sign_ipa(ipa, out, identity=identity, profile=profile)

    with zipfile.ZipFile(out) as archive:
        names = archive.namelist()
        assert "Payload/Demo.app/Demo" in names
        assert "Payload/Demo.app/_CodeSignature/CodeResources" in names
        info = archive.getinfo("Payload/Demo.app/Demo")
        mode = (info.external_attr >> 16) & 0o777
        assert mode & 0o111

def test_encrypted_app_is_rejected(tmp_path):
    identity, cert = _identity()
    profile = ProvisioningProfile.parse(fixtures.make_profile(certificates=[cert]))
    app = fixtures.make_app_dir(str(tmp_path / "src"), encrypted=True)
    import pytest as _pytest

    with _pytest.raises(Exception) as excinfo:
        sign_app(app, identity, profile)
    assert "加密" in str(excinfo.value)
