"""Interactive terminal UI for ipasign.

Run ``ipasign`` without arguments (or ``ipasign tui``) to open it.  The TUI is
a thin shell over the same functions the CLI uses, so every action it offers
has a scriptable equivalent::

    login          -> ipasign login --account ...
    issue          -> ipasign issue --bundle-id ...
    sign           -> ipasign sign / renew
    install        -> ipasign install
    doctor         -> ipasign doctor
    vault          -> ipasign vault ...

The interface is translated: English by default, Chinese available.  The first
start asks which language to use and remembers the choice.
"""

from __future__ import annotations

from ipasign import paths

import sys
from pathlib import Path
from typing import Callable, List, Optional

from rich.console import Console
from rich import box
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

from . import __version__, i18n
from .core import bundle, doctor as doctor_mod, pki, profile as profile_mod, vault
from .core.errors import IpasignError

console = Console()

BANNER = r"""
 _                 _
(_)_ __   __ _ ___(_)_ __   __ _
| | '_ \ / _` / __| | '_ \ / _` |
| | |_) | (_| \__ \ | | | | (_| |
|_| .__/ \__,_|___/_|_| |_|\__, |
  |_|                      |___/
"""

LANGUAGE_CHOICES = [("1", "en", "English"), ("2", "zh", "中文")]


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _strip_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def _ask_path(message: str, must_exist: bool = True) -> Optional[Path]:
    raw = Prompt.ask(message, default="")
    if not raw.strip():
        return None
    path = Path(_strip_quotes(raw)).expanduser()
    if must_exist and not path.exists():
        console.print(f"[red]{i18n.tr('path.not_found', path=path)}[/red]")
        return None
    return path


def _logger(prefix: str = "[dim]") -> Callable[[str], None]:
    def log(message: str) -> None:
        console.print(f"{prefix}{message}[/dim]" if prefix else message, highlight=False)

    return log


def _choose_vault_entry(title: Optional[str] = None) -> Optional[vault.StoredIdentity]:
    entries = vault.list_all()
    if not entries:
        console.print(f"[yellow]{i18n.tr('vault.empty')}[/yellow]")
        return None
    table = Table(title=title or i18n.tr("vault.choose"), show_lines=False)
    table.add_column("#", justify="right", style="cyan", width=3)
    table.add_column(i18n.tr("vault.name"))
    table.add_column(i18n.tr("vault.team"))
    table.add_column(i18n.tr("vault.bundle"))
    table.add_column(i18n.tr("vault.expires"))
    for index, entry in enumerate(entries, 1):
        table.add_row(
            str(index),
            entry.name,
            str(entry.meta.get("team_id", "-")),
            str(entry.meta.get("profile_app_id", "-")),
            str(entry.meta.get("profile_expires", "-"))[:10],
        )
    console.print(table)
    choice = Prompt.ask(i18n.tr("vault.index"), default="1")
    try:
        return entries[int(choice) - 1]
    except (ValueError, IndexError):
        console.print(f"[red]{i18n.tr('vault.bad_index')}[/red]")
        return None


def _load_identity(entry: vault.StoredIdentity, password: Optional[str] = None):
    # Identities created by the certificate factory carry their generated
    # container password in the vault metadata; only imported p12 files need
    # the user to type one.
    if password is None:
        password = vault.password_of(entry)
    if password is None:
        password = Prompt.ask(i18n.tr("vault.p12_password"), password=True)
    return pki.load_identity(entry.p12_path, password)


def _detect_devices(wifi: bool | None = None) -> List:
    try:
        from .device import list_devices

        return list_devices(wifi=wifi)
    except Exception:  # noqa: BLE001 - best effort
        return []


def _pick_device(devices: List):
    """Return the chosen DeviceInfo; a single device is used automatically."""
    if not devices:
        console.print(f"[yellow]{i18n.tr('device.none')}[/yellow]")
        return None
    if len(devices) == 1:
        device = devices[0]
        console.print(
            f"{i18n.tr('device.target')}: [bold]{device.label()}[/bold] "
            f"({device.transport.upper()})"
        )
        return device
    table = Table(title=i18n.tr("device.list"))
    table.add_column("#", width=3, style="cyan")
    table.add_column(i18n.tr("device.name"))
    table.add_column(i18n.tr("device.model"))
    table.add_column(i18n.tr("device.os"))
    table.add_column(i18n.tr("device.transport"))
    table.add_column("UDID")
    for index, device in enumerate(devices, 1):
        table.add_row(
            str(index),
            device.name,
            device.product_type,
            device.ios_version,
            device.transport.upper(),
            device.udid,
        )
    console.print(table)
    choice = Prompt.ask(i18n.tr("vault.index"), default="1")
    try:
        return devices[int(choice) - 1]
    except (ValueError, IndexError):
        return None


def _pick_language() -> str:
    """Ask which language to use; the prompt itself is bilingual."""
    console.print(f"[bold]{i18n.MESSAGES['lang.title']['en']}[/bold]")
    for key, _, label in LANGUAGE_CHOICES:
        console.print(f"  [cyan]{key}[/cyan]  {label}")
    choice = Prompt.ask("Language / 语言", choices=[c[0] for c in LANGUAGE_CHOICES], default="1")
    language = dict((key, code) for key, code, _ in LANGUAGE_CHOICES)[choice]
    i18n.set_language(language)
    return language


# ---------------------------------------------------------------------------
# screens
# ---------------------------------------------------------------------------

def render_home() -> None:
    entries = vault.list_all()
    devices = _detect_devices()
    status = Table.grid(padding=(0, 2))
    status.add_column(style="dim")
    status.add_column()
    status.add_row(i18n.tr("home.version"), f"[bold]{__version__}[/bold]")
    if entries:
        names = ", ".join(e.name for e in entries)
        vault_text = f"{len(entries)}{i18n.tr('home.vault_count')}: {names}"
    else:
        vault_text = f"0{i18n.tr('home.vault_count')}[yellow]{i18n.tr('home.vault_empty')}[/yellow]"
    status.add_row(i18n.tr("home.vault"), vault_text)
    status.add_row(
        i18n.tr("home.login"),
        f"[green]{i18n.tr('home.logged_in')}[/green]"
        if _has_session()
        else f"[yellow]{i18n.tr('home.logged_out')}[/yellow]",
    )
    status.add_row(
        i18n.tr("home.device"),
        ", ".join(f"{d.name} ({d.ios_version})" for d in devices)
        if devices
        else f"[yellow]{i18n.tr('home.no_device')}[/yellow]",
    )
    status.add_row(i18n.tr("home.data_dir"), str(paths.data_dir()))
    console.print(
        Panel(
            status,
            title="[bold cyan]ipasign[/bold cyan]  " + i18n.tr("app.title").split("  ", 1)[-1],
            border_style="cyan",
            box=box.ASCII,
        )
    )

    menu = Table(show_header=False, box=None, padding=(0, 2))
    menu.add_column(style="bold cyan", width=4)
    menu.add_column()
    for key, label in (
        ("1", i18n.tr("menu.login")),
        ("2", i18n.tr("menu.issue")),
        ("3", i18n.tr("menu.sign")),
        ("4", i18n.tr("menu.install")),
        ("5", i18n.tr("menu.doctor")),
        ("6", i18n.tr("menu.vault")),
        ("7", i18n.tr("menu.device")),
        ("8", i18n.tr("menu.watch")),
        ("9", i18n.tr("menu.about")),
        ("0", i18n.tr("menu.quit")),
    ):
        menu.add_row(key, label)
    console.print(menu)


def _has_session() -> bool:
    """True when a saved Apple ID session exists."""
    try:
        from .apple import auth

        return auth.open_device().session is not None
    except Exception:  # noqa: BLE001 - native library missing / not logged in
        return False


def _ensure_login() -> bool:
    """Log in on the spot when an action needs a session."""
    if _has_session():
        return True
    console.print(f"[yellow]{i18n.tr('login.needed')}[/yellow]")
    if not Confirm.ask(i18n.tr("login.now"), default=True):
        console.print(f"[dim]{i18n.tr('login.later')}[/dim]")
        return False
    screen_login()
    return _has_session()


def _ensure_vault(minimum: int = 1) -> bool:
    """Make sure the vault has an identity, offering to create one."""
    if len(vault.list_all()) >= minimum:
        return True
    console.print(f"[yellow]{i18n.tr('vault.empty_short')}[/yellow]")
    if not Confirm.ask(i18n.tr("menu.issue") + "?", default=True):
        console.print(f"[dim]{i18n.tr('prompt.cancelled')}[/dim]")
        return False
    screen_issue()
    return len(vault.list_all()) >= minimum


def screen_login() -> None:
    from .apple import auth

    account = Prompt.ask(i18n.tr("login.account"))
    if not account:
        return
    console.print(f"[dim]{i18n.tr('login.password_hint')}[/dim]")
    try:
        device = auth.open_device()
        session = device.session
        if session is not None and not Confirm.ask(i18n.tr("login.force"), default=False):
            session = session
        else:
            device, session = auth.login(account)
        headers = auth.developer_headers(device, session)
        from .apple.developer import DeveloperClient

        teams = DeveloperClient(headers).list_teams()
        console.print(f"[green]{i18n.tr('login.ok')}[/green]")
        for team in teams:
            console.print(f"  {team.get('name')}  teamId={team.get('teamId')}  type={team.get('type')}")
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]{i18n.tr('login.failed')}:[/red] {exc}")


def screen_issue() -> None:
    from .apple.issue import issue
    from .core.doctor import ipa_bundle_info

    if not _ensure_login():
        return

    # Drag the IPA in: bundle id and display name are read from the package so
    # the user never has to know or retype them.
    bundle_id = None
    app_name = None
    source = _ask_path(i18n.tr("issue.ipa_prompt"), must_exist=False)
    if source is not None:
        try:
            info = ipa_bundle_info(source)
            bundle_id = info["bundle_id"]
            app_name = info["name"] or bundle_id.rsplit(".", 1)[-1]
            console.print(
                f"[green]{i18n.tr('issue.detected')}:[/green] {app_name}  [bold]{bundle_id}[/bold]"
            )
        except Exception as error:  # noqa: BLE001
            console.print(f"[yellow]{i18n.tr('issue.read_failed', error=error)}[/yellow]")

    if not bundle_id:
        bundle_id = Prompt.ask(i18n.tr("issue.bundle_id"), default="com.example.myapp")
    if not app_name:
        app_name = Prompt.ask(
            i18n.tr("issue.app_name"), default=bundle_id.rsplit(".", 1)[-1]
        )
    devices = _detect_devices()
    udid = None
    if devices and Confirm.ask(i18n.tr("device.register"), default=True):
        target = _pick_device(devices)
        udid = target.udid if target else None

    reuse = None
    entries = vault.list_all()
    if entries:
        if Confirm.ask(i18n.tr("issue.reuse"), default=True):
            entry = _choose_vault_entry(i18n.tr("issue.reuse_choose"))
            reuse = entry.name if entry else None
    try:
        with console.status(f"[cyan]{i18n.tr('issue.working')}[/cyan]"):
            result = issue(
                bundle_id=bundle_id,
                app_name=app_name,
                device_udid=udid,
                reuse=reuse,
            )
    except Exception as exc:  # noqa: BLE001
        message = str(exc)
        if "limit" in message.lower():
            console.print(f"[yellow]{i18n.tr('issue.limit')}[/yellow]")
            console.print(f"[dim]{i18n.tr('issue.limit_note')}[/dim]")
            if Confirm.ask(i18n.tr("issue.revoke_confirm"), default=True):
                try:
                    with console.status(f"[cyan]{i18n.tr('issue.revoking')}[/cyan]"):
                        result = issue(
                            bundle_id=bundle_id,
                            app_name=app_name,
                            device_udid=udid,
                            reuse=reuse,
                            allow_revoke=True,
                        )
                except Exception as retry_error:  # noqa: BLE001
                    console.print(f"[red]{i18n.tr('issue.failed')}:[/red] {retry_error}")
                    return
            else:
                console.print(f"[dim]{i18n.tr('issue.cancelled')}[/dim]")
                return
        else:
            console.print(f"[red]{i18n.tr('issue.failed')}:[/red] {message}")
            return
    console.print(f"[green]{i18n.tr('issue.ok')}[/green]")
    console.print(f"  {i18n.tr('issue.entry_label'):10}: [bold]{result['name']}[/bold]")
    console.print(f"  {i18n.tr('issue.team'):10}: {result['team_id']}")
    console.print(f"  {i18n.tr('vault.bundle'):10}: {result['bundle_id']}")
    console.print(f"  {i18n.tr('issue.profile'):10}: {result['profile_app_id']}")


def screen_sign() -> None:
    source = _ask_path(i18n.tr("path.prompt_ipa"))
    if not source:
        return
    if not _ensure_vault():
        return
    entry = _choose_vault_entry(i18n.tr("sign.choose"))
    if not entry:
        return
    identity = _load_identity(entry)
    profile = None
    if entry.profile_path:
        profile = profile_mod.ProvisioningProfile.load(entry.profile_path)
        expires = (
            str(profile.expiration.date()) if profile.expiration else i18n.tr("sign.unknown")
        )
        console.print(
            f"[dim]{i18n.tr('sign.profile_line', name=profile.name, date=expires)}[/dim]"
        )

    default_out = source.with_name(source.stem + "-signed.ipa")
    raw_out = Prompt.ask(i18n.tr("sign.output"), default=str(default_out))
    output = Path(_strip_quotes(raw_out)).expanduser()

    install_after = Confirm.ask(i18n.tr("sign.install_after"), default=False)
    try:
        with console.status(f"[cyan]{i18n.tr('sign.working')}[/cyan]"):
            report = bundle.sign_ipa(
                source, output, identity=identity, profile=profile, log=_logger()
            )
    except IpasignError as exc:
        console.print(f"[red]{i18n.tr('sign.failed')}:[/red] {exc}")
        return
    console.print(f"[green]{i18n.tr('sign.done')}[/green] {output}  ({report.bundle_id})")
    if install_after:
        screen_install(default_ipa=output)


def screen_install(default_ipa: Optional[Path] = None) -> None:
    from .device import install_ipa

    if default_ipa is None:
        source = _ask_path(i18n.tr("device.install_prompt"))
    else:
        source = default_ipa
        console.print(i18n.tr("device.install_line", path=f"[bold]{source}[/bold]"))
    if not source:
        return
    # USB is preferred automatically; Wi-Fi is only used when that is the
    # device we can reach.  No transport question for the common case.
    device = _pick_device(_detect_devices())
    if device is None:
        return
    wifi = device.is_wifi
    try:
        with console.status(f"[cyan]{i18n.tr('device.installing')}[/cyan]"):
            install_ipa(source, udid=device.udid, wifi=wifi, log=_logger())
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]{i18n.tr('device.install_failed')}:[/red] {exc}")
        return
    console.print(f"[green]{i18n.tr('device.installed')}[/green]")


def screen_doctor() -> None:
    source = _ask_path(i18n.tr("doctor.ipa_prompt"))
    entry = _choose_vault_entry(i18n.tr("doctor.choose"))
    if not source or not entry:
        return
    identity = _load_identity(entry)
    profile = (
        profile_mod.ProvisioningProfile.load(entry.profile_path)
        if entry.profile_path
        else None
    )
    devices = _detect_devices()
    checks = doctor_mod.run_checks(
        ipa_path=source,
        identity=identity,
        profile=profile,
        devices=[d.udid for d in devices],
        allow_expired_profile=True,
    )
    table = Table(title=i18n.tr("doctor.title"))
    table.add_column(i18n.tr("doctor.item"))
    table.add_column(i18n.tr("doctor.result"), width=6)
    table.add_column(i18n.tr("doctor.detail"))
    for check in checks:
        mark = "[green]OK[/green]" if check.ok else "[red]FAIL[/red]"
        table.add_row(check.name, mark, check.detail)
    console.print(table)


def screen_vault() -> None:
    entries = vault.list_all()
    if not entries:
        console.print(f"[yellow]{i18n.tr('vault.empty_short')}[/yellow]")
        return
    entry = _choose_vault_entry(i18n.tr("vaultmgr.title"))
    if not entry:
        return
    console.print(Panel.fit(str(entry.meta), title=entry.name, box=box.ASCII))
    if Confirm.ask(i18n.tr("vault.delete_confirm"), default=False):
        vault.remove(entry.name)
        console.print(f"[green]{i18n.tr('vault.deleted')}[/green]")


def screen_devices() -> None:
    devices = _detect_devices()
    if not devices:
        console.print(f"[yellow]{i18n.tr('device.none_short')}[/yellow]")
        return
    table = Table(title=i18n.tr("device.list"))
    for column in (
        i18n.tr("device.name"),
        i18n.tr("device.model"),
        i18n.tr("device.os"),
        "UDID",
    ):
        table.add_column(column)
    for device in devices:
        table.add_row(device.name, device.product_type, device.ios_version, device.udid)
    console.print(table)


def screen_watch() -> None:
    from . import watch

    jobs = watch.load_jobs()
    table = Table(title=i18n.tr("watch.title"))
    for column in (
        i18n.tr("watch.id"),
        "IPA",
        i18n.tr("watch.vault"),
        i18n.tr("watch.device"),
        i18n.tr("watch.last"),
    ):
        table.add_column(column)
    for job in jobs:
        table.add_row(
            job.id,
            Path(job.ipa).name,
            job.vault,
            job.udid or i18n.tr("watch.auto"),
            job.last_result or "-",
        )
    console.print(table if jobs else f"[yellow]{i18n.tr('watch.none')}[/yellow]")

    choice = Prompt.ask(i18n.tr("watch.prompt"), default="0")
    if choice == "1":
        source = _ask_path(i18n.tr("watch.ipa_prompt"))
        if not source:
            return
        entry = _choose_vault_entry(i18n.tr("watch.choose"))
        if not entry:
            return
        target = _pick_device(_detect_devices())
        udid = target.udid if target else None
        wifi = bool(target and target.is_wifi)
        save_password = Confirm.ask(i18n.tr("watch.save_password"), default=False)
        password = (
            Prompt.ask(i18n.tr("vault.p12_password"), default="ipasign", password=True)
            if save_password
            else None
        )
        job = watch.add_job(
            source, entry.name, udid=udid, wifi=wifi,
            password=password,
        )
        console.print(f"[green]{i18n.tr('watch.added')}[/green] {job.id} -> {job.output_path()}")
    elif choice == "2":
        with console.status(f"[cyan]{i18n.tr('watch.checking')}[/cyan]"):
            results = watch.run_once(log=_logger())
        for job_id, result in results.items():
            console.print(f"  {job_id}: {result}")
    elif choice == "3":
        interval = Prompt.ask(i18n.tr("watch.interval"), default="60")
        try:
            watch.run_forever(interval_minutes=float(interval), log=_logger())
        except KeyboardInterrupt:
            console.print(f"[dim]{i18n.tr('watch.stopped')}[/dim]")


def screen_about() -> None:
    from .apple import auth

    info = Table.grid(padding=(0, 2))
    info.add_column(style="dim")
    info.add_column()
    info.add_row(i18n.tr("about.version"), __version__)
    info.add_row(i18n.tr("about.language"), i18n.LANGUAGES[i18n.current()])
    info.add_row(i18n.tr("about.data_dir"), str(paths.data_dir()))
    info.add_row(i18n.tr("about.vault_dir"), str(paths.data_dir() / "identities"))
    info.add_row(i18n.tr("about.adi"), str(auth.STATE_DIR))
    try:
        info.add_row(i18n.tr("about.native"), str(auth.library_path()))
    except Exception:  # noqa: BLE001
        info.add_row(
            i18n.tr("about.native"),
            f"[yellow]{i18n.tr('about.native_missing')}[/yellow]",
        )
    console.print(Panel(info, title=i18n.tr("about.title"), box=box.ASCII))

    if Confirm.ask(i18n.tr("about.switch_lang"), default=False):
        _pick_language()
        console.print(f"[green]{i18n.tr('lang.switched')}[/green]")


# ---------------------------------------------------------------------------
# main loop
# ---------------------------------------------------------------------------

ACTIONS = {
    "1": screen_login,
    "2": screen_issue,
    "3": screen_sign,
    "4": screen_install,
    "5": screen_doctor,
    "6": screen_vault,
    "7": screen_devices,
    "8": screen_watch,
    "9": screen_about,
}


def main() -> int:
    if not sys.stdin.isatty():
        print(i18n.tr("app.needs_tty"))
        return 2
    if not i18n.configured():
        _pick_language()
    console.print(Text(BANNER, style="bold cyan"))
    while True:
        try:
            render_home()
            choice = Prompt.ask(
                i18n.tr("menu.prompt"), choices=list(ACTIONS) + ["0"], default="0"
            )
            if choice == "0":
                console.print(f"[dim]{i18n.tr('app.goodbye')}[/dim]")
                return 0
            ACTIONS[choice]()
        except KeyboardInterrupt:
            console.print(f"\n[dim]{i18n.tr('app.interrupted')}[/dim]")
            continue
        except Exception as exc:  # noqa: BLE001 - never crash the TUI
            console.print(f"[red]{i18n.tr('app.error')}:[/red] {exc}")
        console.print()
        Prompt.ask(i18n.tr("prompt.press_enter"), default="", show_default=False)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
