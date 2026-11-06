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

The UI is built with `rich` only, so it works in any terminal on Windows,
macOS and Linux without an extra event loop.
"""

from __future__ import annotations

from ipasign import paths

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional

from rich.console import Console
from rich import box
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

from . import __version__
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
        console.print(f"[red]路径不存在:[/red] {path}")
        return None
    return path


def _logger(prefix: str = "[dim]") -> Callable[[str], None]:
    def log(message: str) -> None:
        console.print(f"{prefix}{message}[/dim]" if prefix else message, highlight=False)

    return log


def _choose_vault_entry(title: str = "选择证书库条目") -> Optional[vault.StoredIdentity]:
    entries = vault.list_all()
    if not entries:
        console.print("[yellow]证书库是空的。先到「证书」菜单申请或导入。[/yellow]")
        return None
    table = Table(title=title, show_lines=False)
    table.add_column("#", justify="right", style="cyan", width=3)
    table.add_column("名称")
    table.add_column("Team")
    table.add_column("Bundle ID")
    table.add_column("到期")
    for index, entry in enumerate(entries, 1):
        table.add_row(
            str(index),
            entry.name,
            str(entry.meta.get("team_id", "-")),
            str(entry.meta.get("profile_app_id", "-")),
            str(entry.meta.get("profile_expires", "-"))[:10],
        )
    console.print(table)
    choice = Prompt.ask("编号", default="1")
    try:
        return entries[int(choice) - 1]
    except (ValueError, IndexError):
        console.print("[red]编号无效[/red]")
        return None


def _load_identity(entry: vault.StoredIdentity, password: Optional[str] = None):
    # Identities created by the certificate factory carry their generated
    # container password in the vault metadata; only imported p12 files need
    # the user to type one.
    if password is None:
        password = vault.password_of(entry)
    if password is None:
        password = Prompt.ask("p12 密码", password=True)
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
        console.print(
            "[yellow]没有检测到设备。[/yellow]\n"
            "[dim]USB：用数据线连接并在手机上点「信任」；\n"
            "Wi-Fi：先在 iTunes/Finder 勾选「通过 Wi-Fi 同步」。[/dim]"
        )
        return None
    if len(devices) == 1:
        device = devices[0]
        console.print(
            f"目标设备: [bold]{device.label()}[/bold] "
            f"({device.transport.upper()})"
        )
        return device
    table = Table(title="已连接设备")
    table.add_column("#", width=3, style="cyan")
    table.add_column("名称")
    table.add_column("型号")
    table.add_column("系统")
    table.add_column("连接")
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
    choice = Prompt.ask("编号", default="1")
    try:
        return devices[int(choice) - 1]
    except (ValueError, IndexError):
        return None


# ---------------------------------------------------------------------------
# screens
# ---------------------------------------------------------------------------

def render_home() -> None:
    entries = vault.list_all()
    devices = _detect_devices()
    status = Table.grid(padding=(0, 2))
    status.add_column(style="dim")
    status.add_column()
    status.add_row("版本", f"[bold]{__version__}[/bold]")
    status.add_row(
        "证书库",
        f"{len(entries)} 套" + (": " + ", ".join(e.name for e in entries) if entries else " [yellow](空)[/yellow]"),
    )
    status.add_row(
        "登录",
        "[green]已登录[/green]" if _has_session() else "[yellow]未登录[/yellow]",
    )
    status.add_row(
        "设备",
        ", ".join(f"{d.name} ({d.ios_version})" for d in devices) if devices else "[yellow]未检测到[/yellow]",
    )
    status.add_row("配置目录", str(paths.data_dir()))
    console.print(
        Panel(
            status,
            title="[bold cyan]ipasign[/bold cyan]  iOS 签名工具",
            border_style="cyan",
            box=box.ASCII,
        )
    )

    menu = Table(show_header=False, box=None, padding=(0, 2))
    menu.add_column(style="bold cyan", width=4)
    menu.add_column()
    for key, label in (
        ("1", "Apple ID 登录（申请开发者会话）"),
        ("2", "申请证书 + 描述文件（证书工厂）"),
        ("3", "签名 IPA"),
        ("4", "安装到设备"),
        ("5", "签名体检（doctor）"),
        ("6", "证书库管理"),
        ("7", "设备与驱动信息"),
        ("8", "自动续签（到期自动重签重装）"),
        ("9", "关于 / 路径"),
        ("0", "退出"),
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
    console.print("[yellow]这个操作需要先登录 Apple ID。[/yellow]")
    if not Confirm.ask("现在登录？", default=True):
        console.print("[dim]已取消。可以稍后从主菜单选 1 登录。[/dim]")
        return False
    screen_login()
    return _has_session()


def _ensure_vault(minimum: int = 1) -> bool:
    """Make sure the vault has an identity, offering to create one."""
    if len(vault.list_all()) >= minimum:
        return True
    console.print("[yellow]证书库是空的。[/yellow]")
    if not Confirm.ask("现在申请一套证书 + 描述文件？", default=True):
        console.print("[dim]已取消。可以稍后从主菜单选 2 申请。[/dim]")
        return False
    screen_issue()
    return len(vault.list_all()) >= minimum


def screen_login() -> None:
    from .apple import auth

    account = Prompt.ask("Apple ID")
    if not account:
        return
    console.print("[dim]密码与验证码只在本机终端读取，不会写入磁盘。[/dim]")
    try:
        device = auth.open_device()
        session = device.session
        if session is not None and not Confirm.ask("已有登录会话，强制重新登录？", default=False):
            session = session
        else:
            device, session = auth.login(account)
        headers = auth.developer_headers(device, session)
        from .apple.developer import DeveloperClient

        teams = DeveloperClient(headers).list_teams()
        console.print("[green]登录成功[/green]")
        for team in teams:
            console.print(f"  {team.get('name')}  teamId={team.get('teamId')}  type={team.get('type')}")
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]登录失败:[/red] {exc}")


def screen_issue() -> None:
    from .apple.issue import issue
    from .core.doctor import ipa_bundle_info

    if not _ensure_login():
        return

    # Drag the IPA in: bundle id and display name are read from the package so
    # the user never has to know or retype them.
    bundle_id = None
    app_name = None
    source = _ask_path(
        "要签名的 IPA（拖进来即可，直接回车则手动输入 Bundle ID）", must_exist=False
    )
    if source is not None:
        try:
            info = ipa_bundle_info(source)
            bundle_id = info["bundle_id"]
            app_name = info["name"] or bundle_id.rsplit(".", 1)[-1]
            console.print(
                f"[green]已识别:[/green] {app_name}  [bold]{bundle_id}[/bold]"
            )
        except Exception as error:  # noqa: BLE001
            console.print(f"[yellow]读不出 Bundle ID（{error}），请手动输入[/yellow]")

    if not bundle_id:
        bundle_id = Prompt.ask("Bundle ID", default="com.example.myapp")
    if not app_name:
        app_name = Prompt.ask("App 名称（后台显示用）", default=bundle_id.rsplit(".", 1)[-1])
    devices = _detect_devices()
    udid = None
    if devices and Confirm.ask("注册已连接的设备？", default=True):
        target = _pick_device(devices)
        udid = target.udid if target else None

    reuse = None
    entries = vault.list_all()
    if entries:
        if Confirm.ask("复用已有证书（免费账号只能有 1 张证书）？", default=True):
            entry = _choose_vault_entry("选择要复用的证书")
            reuse = entry.name if entry else None
    try:
        with console.status("[cyan]正在向 Apple 申请…[/cyan]"):
            result = issue(
                bundle_id=bundle_id,
                app_name=app_name,
                device_udid=udid,
                reuse=reuse,
            )
    except Exception as exc:  # noqa: BLE001
        message = str(exc)
        if "证书名额已满" in message:
            console.print("[yellow]账号里还有一张旧证书，本机没有它的私钥。[/yellow]")
            console.print(
                "[dim]吊销它之后，之前用它签名的 App 会失效，需要用新证书重签。[/dim]"
            )
            if Confirm.ask("吊销旧证书并重试？", default=True):
                try:
                    with console.status("[cyan]正在吊销并重新申请…[/cyan]"):
                        result = issue(
                            bundle_id=bundle_id,
                            app_name=app_name,
                            device_udid=udid,
                            reuse=reuse,
                            allow_revoke=True,
                        )
                except Exception as retry_error:  # noqa: BLE001
                    console.print(f"[red]签发失败:[/red] {retry_error}")
                    return
            else:
                console.print("[dim]已取消。可以在证书库管理里处理旧证书。[/dim]")
                return
        else:
            console.print(f"[red]签发失败:[/red] {message}")
            return
    console.print("[green]签发成功[/green]")
    console.print(f"  证书库条目 : [bold]{result['name']}[/bold]")
    console.print(f"  Team       : {result['team_id']}")
    console.print(f"  Bundle ID  : {result['bundle_id']}")
    console.print(f"  描述文件   : {result['profile_app_id']}")


def screen_sign() -> None:
    source = _ask_path("IPA 路径（可直接拖进来）")
    if not source:
        return
    if not _ensure_vault():
        return
    entry = _choose_vault_entry("用哪套证书签名")
    if not entry:
        return
    identity = _load_identity(entry)
    profile = None
    if entry.profile_path:
        profile = profile_mod.ProvisioningProfile.load(entry.profile_path)
        expires = profile.expiration.date() if profile.expiration else "未知"
        console.print(f"[dim]描述文件: {profile.name}（{expires} 到期）[/dim]")

    default_out = source.with_name(source.stem + "-signed.ipa")
    raw_out = Prompt.ask("输出路径", default=str(default_out))
    output = Path(_strip_quotes(raw_out)).expanduser()

    install_after = Confirm.ask("签名后直接安装？", default=False)
    try:
        with console.status("[cyan]正在签名…[/cyan]"):
            report = bundle.sign_ipa(
                source, output, identity=identity, profile=profile, log=_logger()
            )
    except IpasignError as exc:
        console.print(f"[red]签名失败:[/red] {exc}")
        return
    console.print(f"[green]完成[/green] {output}  ({report.bundle_id})")
    if install_after:
        screen_install(default_ipa=output)


def screen_install(default_ipa: Optional[Path] = None) -> None:
    from .device import install_ipa

    if default_ipa is None:
        source = _ask_path("要安装的 IPA")
    else:
        source = default_ipa
        console.print(f"安装: [bold]{source}[/bold]")
    if not source:
        return
    # USB is preferred automatically; Wi-Fi is only used when that is the
    # device we can reach.  No transport question for the common case.
    device = _pick_device(_detect_devices())
    if device is None:
        return
    wifi = device.is_wifi
    try:
        with console.status("[cyan]上传并安装中（大文件需要几分钟）…[/cyan]"):
            install_ipa(source, udid=device.udid, wifi=wifi, log=_logger())
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]安装失败:[/red] {exc}")
        return
    console.print("[green]已安装[/green]")


def screen_doctor() -> None:
    source = _ask_path("要体检的 IPA")
    entry = _choose_vault_entry("对照哪套证书")
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
    table = Table(title="体检结果")
    table.add_column("项目")
    table.add_column("结果", width=6)
    table.add_column("说明")
    for check in checks:
        mark = "[green]OK[/green]" if check.ok else "[red]FAIL[/red]"
        table.add_row(check.name, mark, check.detail)
    console.print(table)


def screen_vault() -> None:
    entries = vault.list_all()
    if not entries:
        console.print("[yellow]证书库为空[/yellow]")
        return
    entry = _choose_vault_entry("证书库")
    if not entry:
        return
    console.print(Panel.fit(str(entry.meta), title=entry.name, box=box.ASCII))
    if Confirm.ask("删除这个条目？", default=False):
        vault.remove(entry.name)
        console.print("[green]已删除[/green]")


def screen_devices() -> None:
    devices = _detect_devices()
    if not devices:
        console.print("[yellow]未检测到设备[/yellow]")
        return
    table = Table(title="已连接设备")
    for column in ("名称", "型号", "系统", "UDID"):
        table.add_column(column)
    for device in devices:
        table.add_row(device.name, device.product_type, device.ios_version, device.udid)
    console.print(table)




def screen_watch() -> None:
    from . import watch

    jobs = watch.load_jobs()
    table = Table(title="自动续签任务")
    for column in ("ID", "IPA", "证书库", "设备", "上次结果"):
        table.add_column(column)
    for job in jobs:
        table.add_row(job.id, Path(job.ipa).name, job.vault, job.udid or "自动", job.last_result or "-")
    console.print(table if jobs else "[yellow]还没有任务[/yellow]")

    choice = Prompt.ask("1 添加 / 2 立即续签 / 3 启动守护 / 0 返回", default="0")
    if choice == "1":
        source = _ask_path("要续签的 IPA（原始或已签名都行）")
        if not source:
            return
        entry = _choose_vault_entry("用哪套证书续签")
        if not entry:
            return
        target = _pick_device(_detect_devices())
        udid = target.udid if target else None
        wifi = bool(target and target.is_wifi)
        save_password = Confirm.ask("保存 p12 密码？（明文存进任务文件）", default=False)
        password = Prompt.ask("p12 密码", default="ipasign", password=True) if save_password else None
        job = watch.add_job(
            source, entry.name, udid=udid, wifi=wifi,
            password=password,
        )
        console.print(f"[green]已添加[/green] {job.id} -> {job.output_path()}")
    elif choice == "2":
        with console.status("[cyan]检查并续签…[/cyan]"):
            results = watch.run_once(log=_logger())
        for job_id, result in results.items():
            console.print(f"  {job_id}: {result}")
    elif choice == "3":
        interval = Prompt.ask("检查间隔（分钟）", default="60")
        try:
            watch.run_forever(interval_minutes=float(interval), log=_logger())
        except KeyboardInterrupt:
            console.print("[dim]已停止[/dim]")


def screen_about() -> None:
    from .apple import auth

    info = Table.grid(padding=(0, 2))
    info.add_column(style="dim")
    info.add_column()
    info.add_row("版本", __version__)
    info.add_row("配置", str(paths.data_dir()))
    info.add_row("证书库", str(paths.data_dir() / "identities"))
    info.add_row("ADI", str(auth.STATE_DIR))
    try:
        info.add_row("原生库", str(auth.library_path()))
    except Exception:  # noqa: BLE001
        info.add_row("原生库", "[yellow]未找到（登录/签发不可用）[/yellow]")
    console.print(Panel(info, title="关于", box=box.ASCII))


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
        print("ipasign TUI 需要交互式终端；非交互环境请使用 `ipasign --help`。")
        return 2
    console.print(Text(BANNER, style="bold cyan"))
    while True:
        try:
            render_home()
            choice = Prompt.ask("请选择", choices=list(ACTIONS) + ["0"], default="0")
            if choice == "0":
                console.print("[dim]再见。[/dim]")
                return 0
            ACTIONS[choice]()
        except KeyboardInterrupt:
            console.print("\n[dim]已取消，返回主菜单。[/dim]")
            continue
        except Exception as exc:  # noqa: BLE001 - never crash the TUI
            console.print(f"[red]出错了:[/red] {exc}")
        console.print()
        Prompt.ask("按回车返回主菜单", default="", show_default=False)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
