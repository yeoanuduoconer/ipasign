"""Tests for the CLI and the verifier."""

from __future__ import annotations

import json
import plistlib

import pytest

from ipasign import cli
from ipasign.core import verify
from ipasign.core.bundle import SignOptions, sign_app
from ipasign.core.bundle import sign_ipa
from ipasign.core.pki import SigningIdentity
from ipasign.core.profile import ProvisioningProfile

from . import fixtures


def _case(tmp_path, bundle_id="com.example.demo"):
    key, cert = fixtures.make_identity()
    p12 = tmp_path / "id.p12"
    p12.write_bytes(fixtures.make_p12(key, cert, password="secret"))
    profile = tmp_path / "profile.mobileprovision"
    profile.write_bytes(fixtures.make_profile(certificates=[cert]))
    app = fixtures.make_app_dir(str(tmp_path / "src"), bundle_id=bundle_id)
    ipa = tmp_path / "in.ipa"
    fixtures.make_ipa(app, str(ipa))
    identity = SigningIdentity(key=key, certificates=[cert])
    return {
        "key": key, "cert": cert, "p12": p12, "profile": profile,
        "ipa": ipa, "identity": identity,
    }


def test_cli_help(capsys):
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["--help"])
    assert excinfo.value.code == 0
    assert "sign" in capsys.readouterr().out


def test_cli_sign_info_verify(tmp_path, capsys):
    case = _case(tmp_path)
    out = tmp_path / "out.ipa"
    code = cli.main([
        "sign", str(case["ipa"]),
        "-c", str(case["p12"]), "-p", "secret",
        "-m", str(case["profile"]),
        "-o", str(out),
        "--no-download", "--force",
    ])
    assert code == 0
    assert out.is_file()
    assert "[done]" in capsys.readouterr().out

    assert cli.main(["info", str(out)]) == 0
    info = capsys.readouterr().out
    assert "com.example.demo" in info
    assert "arm64" in info
    assert "CMS" in info

    assert cli.main(["verify", str(out)]) == 0
    assert "signature structure verified" in capsys.readouterr().out


def test_cli_json_output(tmp_path, capsys):
    case = _case(tmp_path)
    out = tmp_path / "out.ipa"
    cli.main([
        "sign", str(case["ipa"]), "-c", str(case["p12"]), "-p", "secret",
        "-m", str(case["profile"]), "-o", str(out), "--no-download", "--json",
    ])
    payload = json.loads(capsys.readouterr().out)
    assert payload["bundle_id"] == "com.example.demo"
    assert payload["output"].endswith("out.ipa")


def test_cli_sign_requires_credentials(tmp_path):
    case = _case(tmp_path)
    code = cli.main(["sign", str(case["ipa"]), "-o", str(tmp_path / "x.ipa")])
    assert code == 1


def test_cli_verify_detects_tampering(tmp_path, capsys):
    case = _case(tmp_path)
    app = fixtures.make_app_dir(str(tmp_path / "src2"))
    sign_app(app, case["identity"], ProvisioningProfile.parse(case["profile"].read_bytes()))
    binary = tmp_path / "src2" / "Payload" / "Demo.app" / "Demo"
    data = bytearray(binary.read_bytes())
    data[0x120] ^= 0xFF
    binary.write_bytes(bytes(data))
    report = verify.verify_bundle(tmp_path / "src2" / "Payload" / "Demo.app")
    assert not report.ok
    assert any("hash mismatch" in item for item in report.all_problems())


def test_verify_report_for_unsigned_bundle(tmp_path):
    app = fixtures.make_app_dir(str(tmp_path / "src3"))
    report = verify.verify_bundle(__import__("pathlib").Path(app))
    assert not report.ok
    assert any("unsigned" in item for item in report.all_problems())


def test_cli_profile_command(tmp_path, capsys):
    case = _case(tmp_path)
    assert cli.main(["profile", str(case["profile"])]) == 0
    out = capsys.readouterr().out
    assert "TEAM123456.*" in out
