"""Automatic re-signing / re-installation ("7-day refresh").

A *job* remembers one IPA, the vault entry used to sign it and the target
device.  ``run_once`` checks the profile's expiry and, when it is close (or
already past), refreshes the profile through the developer portal, re-signs the
IPA and installs it again.  ``run_forever`` does that on a timer, which is the
equivalent of Sideloadly's auto-refresh daemon.

State lives in ``~/.ipasign/renewals.json``::

    {
      "jobs": [
        {
          "id": "demo",
          "ipa": "C:/path/app.ipa",
          "vault": "team123456-9r769gwk2v",
          "udid": "00008110-...",
          "output": "C:/path/app-renewed.ipa",
          "wifi": false,
          "interval_hours": 24,
          "last_run": "2026-11-06T15:00:00Z",
          "last_result": "renewed"
        }
      ]
    }

The p12 password is only written when the caller explicitly asks for it
(``save_password=True``); otherwise it is prompted for once per process and
kept in memory.
"""

from __future__ import annotations

import datetime as dt
import getpass
import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from ipasign.core import vault
from ipasign.core.bundle import sign_ipa
from ipasign.core.pki import load_identity
from ipasign.core.profile import ProvisioningProfile

DEFAULT_THRESHOLD_HOURS = 24.0
DEFAULT_INTERVAL_MINUTES = 60


def store_path() -> Path:
    return Path.home() / ".ipasign" / "renewals.json"


@dataclass
class Job:
    id: str
    ipa: str
    vault: str
    udid: Optional[str] = None
    output: Optional[str] = None
    password: Optional[str] = None
    wifi: bool = False
    interval_hours: float = 24.0
    last_run: Optional[str] = None
    last_result: Optional[str] = None
    last_error: Optional[str] = None
    extra: Dict = field(default_factory=dict)

    def output_path(self) -> Path:
        if self.output:
            return Path(self.output)
        source = Path(self.ipa)
        return source.with_name(source.stem + "-renewed.ipa")

    def describe(self) -> str:
        device = self.udid or "自动选择"
        transport = "Wi-Fi" if self.wifi else "USB"
        return f"{self.id}: {Path(self.ipa).name} [{self.vault}] -> {device} ({transport})"


# ---------------------------------------------------------------------------
# persistence
# ---------------------------------------------------------------------------

def load_jobs() -> List[Job]:
    path = store_path()
    if not path.is_file():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    jobs = []
    for raw in payload.get("jobs", []):
        if not isinstance(raw, dict) or not raw.get("id"):
            continue
        known = {key: raw[key] for key in raw if key in Job.__dataclass_fields__}
        jobs.append(Job(**known))
    return jobs


def save_jobs(jobs: List[Job]) -> None:
    path = store_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"jobs": [asdict(job) for job in jobs]}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def add_job(
    ipa: "str | Path",
    vault_name: str,
    *,
    udid: Optional[str] = None,
    output: Optional[str] = None,
    password: Optional[str] = None,
    wifi: bool = False,
    interval_hours: float = 24.0,
    job_id: Optional[str] = None,
) -> Job:
    source = Path(ipa)
    if not source.is_file():
        raise FileNotFoundError(f"找不到 IPA: {source}")
    vault.load(vault_name)  # fail early when the entry does not exist
    job = Job(
        id=job_id or uuid.uuid4().hex[:8],
        ipa=str(source.resolve()),
        vault=vault_name,
        udid=udid,
        output=output,
        password=password,
        wifi=wifi,
        interval_hours=interval_hours,
    )
    jobs = [existing for existing in load_jobs() if existing.id != job.id]
    jobs.append(job)
    save_jobs(jobs)
    return job


def remove_job(job_id: str) -> bool:
    jobs = load_jobs()
    kept = [job for job in jobs if job.id != job_id]
    if len(kept) == len(jobs):
        return False
    save_jobs(kept)
    return True


# ---------------------------------------------------------------------------
# renewal
# ---------------------------------------------------------------------------

def _parse_time(value) -> Optional[dt.datetime]:
    if not value:
        return None
    try:
        stamp = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=dt.timezone.utc)
    return stamp


def profile_expiry(job: Job, password: Optional[str] = None) -> Optional[dt.datetime]:
    entry = vault.load(job.vault)
    expiry = _parse_time(entry.meta.get("profile_expires"))
    if expiry is not None:
        return expiry
    if entry.profile_path and entry.profile_path.is_file():
        profile = ProvisioningProfile.load(entry.profile_path)
        return profile.expiration
    return None


def needs_renewal(
    expiry: Optional[dt.datetime], threshold_hours: float = DEFAULT_THRESHOLD_HOURS
) -> bool:
    if expiry is None:
        # No expiry information: refresh rather than silently letting it die.
        return True
    now = dt.datetime.now(dt.timezone.utc)
    return expiry - now <= dt.timedelta(hours=threshold_hours)


_PASSWORD_CACHE: Dict[str, str] = {}


def _password_for(job: Job) -> str:
    if job.password:
        return job.password
    if job.vault in _PASSWORD_CACHE:
        return _PASSWORD_CACHE[job.vault]
    value = getpass.getpass(f"证书 {job.vault} 的 p12 密码: ")
    _PASSWORD_CACHE[job.vault] = value
    return value


def bundle_id_of(entry) -> str:
    """``TEAM.com.example.app`` -> ``com.example.app``."""
    app_id = str(entry.meta.get("profile_app_id") or "")
    team = str(entry.meta.get("team_id") or "")
    if team and app_id.startswith(team + "."):
        return app_id[len(team) + 1:]
    return app_id


def renew_job(
    job: Job,
    *,
    threshold_hours: float = DEFAULT_THRESHOLD_HOURS,
    force: bool = False,
    log=print,
) -> str:
    """Refresh one job.  Returns ``renewed`` / ``skipped`` / ``failed``."""
    entry = vault.load(job.vault)
    expiry = _parse_time(entry.meta.get("profile_expires"))
    if not force and not needs_renewal(expiry, threshold_hours):
        log(f"[..] {job.id}: 描述文件 {expiry.date()} 到期，暂不需要续签")
        return "skipped"

    password = _password_for(job)
    bundle_id = bundle_id_of(entry)
    if not bundle_id:
        raise RuntimeError(f"{job.vault} 缺少 profile_app_id，无法确定 Bundle ID")

    from ipasign.apple.issue import issue

    log(f"[..] {job.id}: 重新申请描述文件 ({bundle_id})")
    issue(
        bundle_id=bundle_id,
        app_name=bundle_id,
        reuse=job.vault,
        password=password,
        vault_name=job.vault,
        log=log,
    )

    entry = vault.load(job.vault)
    identity = load_identity(entry.p12_path, password)
    profile = (
        ProvisioningProfile.load(entry.profile_path) if entry.profile_path else None
    )
    output = job.output_path()
    log(f"[..] {job.id}: 重新签名 -> {output.name}")
    sign_ipa(job.ipa, output, identity=identity, profile=profile, log=log)

    if job.udid:
        from ipasign.device import install_ipa

        log(f"[..] {job.id}: 安装到 {job.udid}")
        install_ipa(output, udid=job.udid, wifi=job.wifi, log=log)

    job.last_run = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    job.last_result = "renewed"
    job.last_error = None
    return "renewed"


def run_once(
    *, threshold_hours: float = DEFAULT_THRESHOLD_HOURS, force: bool = False, log=print
) -> Dict[str, str]:
    """Check every job once and return ``{job_id: result}``."""
    jobs = load_jobs()
    results: Dict[str, str] = {}
    for job in jobs:
        try:
            results[job.id] = renew_job(
                job, threshold_hours=threshold_hours, force=force, log=log
            )
        except Exception as error:  # noqa: BLE001 - keep other jobs going
            job.last_result = "failed"
            job.last_error = str(error)[:400]
            job.last_run = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
            results[job.id] = f"failed: {error}"
            log(f"[错误] {job.id}: {error}")
    if jobs:
        save_jobs(jobs)
    return results


def run_forever(
    *,
    interval_minutes: float = DEFAULT_INTERVAL_MINUTES,
    threshold_hours: float = DEFAULT_THRESHOLD_HOURS,
    log=print,
) -> None:
    """Timer loop for the daemon; Ctrl+C stops it."""
    interval = max(1.0, float(interval_minutes))
    log(f"[..] 自动续签已启动，每 {interval:g} 分钟检查一次（Ctrl+C 停止）")
    try:
        while True:
            results = run_once(threshold_hours=threshold_hours, log=log)
            if not results:
                log("[..] 还没有添加任何任务，用 `ipasign watch add` 添加")
            next_at = dt.datetime.now() + dt.timedelta(minutes=interval)
            log(f"[..] 下次检查: {next_at:%H:%M:%S}")
            time.sleep(interval * 60)
    except KeyboardInterrupt:
        log("[..] 已停止自动续签")
