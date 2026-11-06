"""Tests for the auto-renewal scheduler (no network, no device)."""

from __future__ import annotations

import datetime as dt
import types

import pytest

from ipasign import watch
from ipasign.core import vault


def _entry(expires_in_days: float, team="TEAM123456", app="com.example.demo"):
    expiry = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=expires_in_days)
    return types.SimpleNamespace(
        name="entry",
        p12_path=None,
        profile_path=None,
        meta={
            "team_id": team,
            "profile_app_id": f"{team}.{app}",
            "profile_expires": expiry.isoformat(),
        },
    )


@pytest.fixture(autouse=True)
def isolated_store(monkeypatch, tmp_path):
    monkeypatch.setattr(watch, "store_path", lambda: tmp_path / "renewals.json")


def test_needs_renewal_thresholds():
    soon = dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=2)
    later = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=5)
    assert watch.needs_renewal(soon, 24)
    assert not watch.needs_renewal(later, 24)
    assert watch.needs_renewal(None, 24)
    past = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)
    assert watch.needs_renewal(past, 24)


def test_add_list_remove(tmp_path, monkeypatch):
    ipa = tmp_path / "app.ipa"
    ipa.write_bytes(b"PK")
    monkeypatch.setattr(watch, "vault", types.SimpleNamespace(load=lambda name: _entry(1)))

    job = watch.add_job(ipa, "entry", udid="UDID1", wifi=True, job_id="demo")
    assert job.id == "demo"
    jobs = watch.load_jobs()
    assert [j.id for j in jobs] == ["demo"]
    assert jobs[0].wifi is True
    assert jobs[0].output_path().name == "app-renewed.ipa"

    assert watch.remove_job("demo") is True
    assert watch.load_jobs() == []
    assert watch.remove_job("demo") is False


def test_add_rejects_missing_ipa(tmp_path):
    with pytest.raises(FileNotFoundError):
        watch.add_job(tmp_path / "nope.ipa", "entry")


def test_bundle_id_from_entry():
    assert watch.bundle_id_of(_entry(1)) == "com.example.demo"
    assert watch.bundle_id_of(types.SimpleNamespace(meta={"profile_app_id": "x.y"})) == "x.y"


def test_renew_job_refreshes(monkeypatch, tmp_path):
    ipa = tmp_path / "app.ipa"
    ipa.write_bytes(b"PK")
    entry = _entry(0.5)  # expires in 12h -> due
    calls = {}

    monkeypatch.setattr(watch.vault, "load", lambda name: entry)
    monkeypatch.setattr(watch, "_password_for", lambda job: "pw")
    monkeypatch.setattr(
        watch, "load_identity", lambda path, password: types.SimpleNamespace(key=1)
    )
    monkeypatch.setattr(
        watch, "ProvisioningProfile", types.SimpleNamespace(load=lambda path: "profile")
    )

    issued = {}

    def fake_issue(**kwargs):
        issued.update(kwargs)

    monkeypatch.setattr("ipasign.apple.issue.issue", fake_issue)

    def fake_sign(source, output, **kwargs):
        calls["signed"] = (str(source), str(output))

    monkeypatch.setattr(watch, "sign_ipa", fake_sign)

    def fake_install(path, **kwargs):
        calls["installed"] = (str(path), kwargs.get("udid"), kwargs.get("wifi"))

    monkeypatch.setattr("ipasign.device.install_ipa", fake_install)

    job = watch.Job(id="demo", ipa=str(ipa), vault="entry", udid="UDID1", wifi=True)
    result = watch.renew_job(job, log=lambda *_: None)

    assert result == "renewed"
    assert issued["bundle_id"] == "com.example.demo"
    assert issued["reuse"] == "entry"
    assert calls["signed"][1].endswith("app-renewed.ipa")
    assert calls["installed"] == (str(job.output_path()), "UDID1", True)
    assert job.last_result == "renewed"


def test_renew_job_skips_when_far(monkeypatch, tmp_path):
    ipa = tmp_path / "app.ipa"
    ipa.write_bytes(b"PK")
    monkeypatch.setattr(watch.vault, "load", lambda name: _entry(6))
    job = watch.Job(id="demo", ipa=str(ipa), vault="entry")
    assert watch.renew_job(job, log=lambda *_: None) == "skipped"


def test_run_once_records_failure(monkeypatch, tmp_path):
    ipa = tmp_path / "app.ipa"
    ipa.write_bytes(b"PK")
    watch.save_jobs([watch.Job(id="bad", ipa=str(ipa), vault="entry")])

    def boom(**kwargs):
        raise RuntimeError("503")

    monkeypatch.setattr(watch.vault, "load", lambda name: _entry(0))
    monkeypatch.setattr(watch, "_password_for", lambda job: "pw")
    monkeypatch.setattr("ipasign.apple.issue.issue", boom)

    results = watch.run_once(log=lambda *_: None)
    assert results["bad"].startswith("failed")
    saved = watch.load_jobs()[0]
    assert saved.last_result == "failed"
    assert "503" in (saved.last_error or "")
