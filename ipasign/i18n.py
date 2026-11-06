"""Small translation layer for the interactive interface.

The default language is English; Chinese is available as a translation.  Keys
are semantic (``menu.sign``), never the source text itself.  A missing
translation falls back to English rather than raising — the UI must never break
because of a typo.

Language resolution order:

1. ``IPASIGN_LANG`` environment variable
2. ``<data>/config.json`` (chosen once at first start, switchable in About)
3. ``en``
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, Optional

from ipasign import paths

DEFAULT = "en"
LANGUAGES = {"en": "English", "zh": "中文"}

_current: Optional[str] = None


# --------------------------------------------------------------------------
# catalog
# --------------------------------------------------------------------------

MESSAGES: Dict[str, Dict[str, str]] = {
    # language picker
    "lang.title": {"en": "Select language / 选择语言", "zh": "选择语言 / Select language"},
    "lang.prompt": {"en": "Language", "zh": "语言"},
    "lang.switched": {"en": "Interface language switched to English.", "zh": "界面语言已切换为中文。"},
    "lang.option_en": {"en": "English", "zh": "English"},
    "lang.option_zh": {"en": "中文", "zh": "中文"},

    # home screen
    "app.title": {"en": "ipasign  iOS signing tool", "zh": "ipasign  iOS 签名工具"},
    "home.version": {"en": "Version", "zh": "版本"},
    "home.vault": {"en": "Vault", "zh": "证书库"},
    "home.vault_count": {"en": " identities", "zh": " 套"},
    "home.vault_empty": {"en": " (empty)", "zh": " (空)"},
    "home.login": {"en": "Account", "zh": "登录"},
    "home.logged_in": {"en": "signed in", "zh": "已登录"},
    "home.logged_out": {"en": "not signed in", "zh": "未登录"},
    "home.device": {"en": "Device", "zh": "设备"},
    "home.no_device": {"en": "none detected", "zh": "未检测到"},
    "home.data_dir": {"en": "Data dir", "zh": "配置目录"},

    # menu
    "menu.login": {"en": "Apple ID sign-in (developer session)", "zh": "Apple ID 登录（申请开发者会话）"},
    "menu.issue": {"en": "Issue certificate + profile", "zh": "申请证书 + 描述文件（证书工厂）"},
    "menu.sign": {"en": "Sign an IPA", "zh": "签名 IPA"},
    "menu.install": {"en": "Install to device", "zh": "安装到设备"},
    "menu.doctor": {"en": "Check a signed IPA (doctor)", "zh": "签名体检（doctor）"},
    "menu.vault": {"en": "Manage the vault", "zh": "证书库管理"},
    "menu.device": {"en": "Devices and drivers", "zh": "设备与驱动信息"},
    "menu.watch": {"en": "Auto-renew (re-sign and reinstall)", "zh": "自动续签（到期自动重签重装）"},
    "menu.about": {"en": "About / paths", "zh": "关于 / 路径"},
    "menu.quit": {"en": "Quit", "zh": "退出"},
    "menu.prompt": {"en": "Select", "zh": "请选择"},

    # shared prompts
    "prompt.cancelled": {"en": "Cancelled.", "zh": "已取消。"},
    "prompt.press_enter": {"en": "Press Enter to return to the menu", "zh": "按回车返回主菜单"},
    "app.goodbye": {"en": "Bye.", "zh": "再见。"},
    "app.interrupted": {"en": "Cancelled, back to the menu.", "zh": "已取消，返回主菜单。"},
    "app.error": {"en": "Something went wrong", "zh": "出错了"},
    "app.needs_tty": {
        "en": "The TUI needs an interactive terminal; use `ipasign --help` in a non-interactive shell.",
        "zh": "ipasign TUI 需要交互式终端；非交互环境请使用 `ipasign --help`。",
    },

    # vault
    "vault.empty": {
        "en": "The vault is empty. Issue or import a certificate first.",
        "zh": "证书库是空的。先到「证书」菜单申请或导入。",
    },
    "vault.empty_short": {"en": "The vault is empty.", "zh": "证书库是空的。"},
    "vault.choose": {"en": "Choose a vault entry", "zh": "选择证书库条目"},
    "vault.name": {"en": "Name", "zh": "名称"},
    "vault.team": {"en": "Team", "zh": "Team"},
    "vault.bundle": {"en": "Bundle ID", "zh": "Bundle ID"},
    "vault.expires": {"en": "Expires", "zh": "到期"},
    "vault.index": {"en": "Number", "zh": "编号"},
    "vault.bad_index": {"en": "Invalid number.", "zh": "编号无效"},
    "vault.p12_password": {"en": "p12 password", "zh": "p12 密码"},
    "vault.delete_confirm": {"en": "Delete this entry?", "zh": "删除这个条目？"},
    "vault.deleted": {"en": "Deleted.", "zh": "已删除。"},

    # paths / devices
    "path.not_found": {"en": "Path not found: {path}", "zh": "路径不存在: {path}"},
    "path.prompt_ipa": {"en": "IPA path (drag it here)", "zh": "IPA 路径（可直接拖进来）"},
    "device.none": {
        "en": "No device detected.\nUSB: connect the cable and tap Trust on the phone;\nWi-Fi: enable Sync over Wi-Fi in iTunes/Finder first.",
        "zh": "没有检测到设备。\nUSB：用数据线连接并在手机上点「信任」；\nWi-Fi：先在 iTunes/Finder 勾选「通过 Wi-Fi 同步」。",
    },
    "device.none_short": {"en": "No device detected.", "zh": "未检测到设备"},
    "device.target": {"en": "Target device", "zh": "目标设备"},
    "device.list": {"en": "Connected devices", "zh": "已连接设备"},
    "device.model": {"en": "Model", "zh": "型号"},
    "device.os": {"en": "OS", "zh": "系统"},
    "device.transport": {"en": "Link", "zh": "连接"},
    "device.name": {"en": "Name", "zh": "名称"},
    "device.install_prompt": {"en": "IPA to install", "zh": "要安装的 IPA"},
    "device.register": {"en": "Register the connected device?", "zh": "注册已连接的设备？"},
    "device.installing": {"en": "Uploading and installing (large apps take a few minutes)…", "zh": "上传并安装中（大文件需要几分钟）…"},
    "device.installed": {"en": "Installed.", "zh": "已安装"},
    "device.install_failed": {"en": "Install failed", "zh": "安装失败"},
    "device.install_line": {"en": "Installing: {path}", "zh": "安装: {path}"},
    "device.trust_hint": {
        "en": "If the icon is greyed out, trust the certificate in Settings → General → VPN & Device Management.",
        "zh": "如果图标是灰色的，去 设置 → 通用 → VPN与设备管理 里信任对应证书。",
    },

    # login
    "login.needed": {"en": "This action needs an Apple ID sign-in first.", "zh": "这个操作需要先登录 Apple ID。"},
    "login.now": {"en": "Sign in now?", "zh": "现在登录？"},
    "login.later": {"en": "Cancelled. You can sign in later with menu 1.", "zh": "已取消。可以稍后从主菜单选 1 登录。"},
    "login.account": {"en": "Apple ID", "zh": "Apple ID"},
    "login.password_hint": {
        "en": "Password and 2FA code are read locally and never written to disk.",
        "zh": "密码与验证码只在本机终端读取，不会写入磁盘。",
    },
    "login.force": {"en": "A session exists; sign in again anyway?", "zh": "已有登录会话，强制重新登录？"},
    "login.ok": {"en": "Signed in", "zh": "登录成功"},
    "login.failed": {"en": "Sign-in failed", "zh": "登录失败"},

    # issue
    "issue.ipa_prompt": {
        "en": "IPA to sign (drag it in; press Enter to type a Bundle ID instead)",
        "zh": "要签名的 IPA（拖进来即可，直接回车则手动输入 Bundle ID）",
    },
    "issue.detected": {"en": "Detected", "zh": "已识别"},
    "issue.read_failed": {"en": "Cannot read the Bundle ID ({error}); please type it", "zh": "读不出 Bundle ID（{error}），请手动输入"},
    "issue.bundle_id": {"en": "Bundle ID", "zh": "Bundle ID"},
    "issue.app_name": {"en": "App name (shown in the portal)", "zh": "App 名称（后台显示用）"},
    "issue.reuse": {
        "en": "Reuse an existing certificate (free accounts allow only one)?",
        "zh": "复用已有证书（免费账号只能有 1 张证书）？",
    },
    "issue.reuse_choose": {"en": "Certificate to reuse", "zh": "选择要复用的证书"},
    "issue.working": {"en": "Requesting from Apple…", "zh": "正在向 Apple 申请…"},
    "issue.ok": {"en": "Issued", "zh": "签发成功"},
    "issue.failed": {"en": "Issuing failed", "zh": "签发失败"},
    "issue.limit": {
        "en": "The account still holds an old certificate whose key is not on this machine.",
        "zh": "账号里还有一张旧证书，本机没有它的私钥。",
    },
    "issue.limit_note": {
        "en": "Revoking it invalidates apps signed with it; they must be re-signed.",
        "zh": "吊销它之后，之前用它签名的 App 会失效，需要用新证书重签。",
    },
    "issue.revoke_confirm": {"en": "Revoke it and retry?", "zh": "吊销旧证书并重试？"},
    "issue.revoking": {"en": "Revoking and requesting again…", "zh": "正在吊销并重新申请…"},
    "issue.cancelled": {"en": "Cancelled. You can deal with the old certificate in the vault.", "zh": "已取消。可以在证书库管理里处理旧证书。"},
    "issue.entry_label": {"en": "Vault entry", "zh": "证书库条目"},
    "issue.team": {"en": "Team", "zh": "Team"},
    "issue.profile": {"en": "Profile", "zh": "描述文件"},

    # sign
    "sign.choose": {"en": "Which certificate to sign with", "zh": "用哪套证书签名"},
    "sign.profile_line": {"en": "Profile: {name} (expires {date})", "zh": "描述文件: {name}（{date} 到期）"},
    "sign.unknown": {"en": "unknown", "zh": "未知"},
    "sign.output": {"en": "Output path", "zh": "输出路径"},
    "sign.install_after": {"en": "Install right after signing?", "zh": "签名后直接安装？"},
    "sign.working": {"en": "Signing…", "zh": "正在签名…"},
    "sign.done": {"en": "Done", "zh": "完成"},
    "sign.failed": {"en": "Signing failed", "zh": "签名失败"},

    # doctor
    "doctor.ipa_prompt": {"en": "IPA to check", "zh": "要体检的 IPA"},
    "doctor.choose": {"en": "Which certificate to compare against", "zh": "对照哪套证书"},
    "doctor.title": {"en": "Check results", "zh": "体检结果"},
    "doctor.item": {"en": "Check", "zh": "项目"},
    "doctor.result": {"en": "Result", "zh": "结果"},
    "doctor.detail": {"en": "Detail", "zh": "说明"},

    # vault management
    "vaultmgr.title": {"en": "Vault", "zh": "证书库"},

    # watch
    "watch.title": {"en": "Renewal jobs", "zh": "自动续签任务"},
    "watch.none": {"en": "No renewal jobs yet.", "zh": "还没有任务"},
    "watch.id": {"en": "ID", "zh": "ID"},
    "watch.vault": {"en": "Vault", "zh": "证书库"},
    "watch.device": {"en": "Device", "zh": "设备"},
    "watch.last": {"en": "Last result", "zh": "上次结果"},
    "watch.auto": {"en": "auto", "zh": "自动"},
    "watch.prompt": {
        "en": "1 add / 2 run now / 3 start daemon / 0 back",
        "zh": "1 添加 / 2 立即续签 / 3 启动守护 / 0 返回",
    },
    "watch.ipa_prompt": {"en": "IPA to renew (original or signed)", "zh": "要续签的 IPA（原始或已签名都行）"},
    "watch.choose": {"en": "Which certificate to renew with", "zh": "用哪套证书续签"},
    "watch.save_password": {
        "en": "Store the p12 password? (plain text in the job file)",
        "zh": "保存 p12 密码？（明文存进任务文件）",
    },
    "watch.added": {"en": "Added", "zh": "已添加"},
    "watch.interval": {"en": "Check interval (minutes)", "zh": "检查间隔（分钟）"},
    "watch.checking": {"en": "Checking and renewing…", "zh": "检查并续签…"},
    "watch.stopped": {"en": "Stopped.", "zh": "已停止"},

    # about
    "about.title": {"en": "About", "zh": "关于"},
    "about.version": {"en": "Version", "zh": "版本"},
    "about.data_dir": {"en": "Config", "zh": "配置"},
    "about.vault_dir": {"en": "Vault", "zh": "证书库"},
    "about.adi": {"en": "ADI", "zh": "ADI"},
    "about.native": {"en": "Native lib", "zh": "原生库"},
    "about.native_missing": {"en": "not found (sign-in/issue unavailable)", "zh": "未找到（登录/签发不可用）"},
    "about.language": {"en": "Language", "zh": "语言"},
    "about.switch_lang": {"en": "Switch the interface language?", "zh": "切换界面语言？"},

    # errors
    "error.prefix": {"en": "Error", "zh": "错误"},
}


# --------------------------------------------------------------------------
# state
# --------------------------------------------------------------------------

def _config_path() -> Path:
    return paths.data_dir() / "config.json"


def load_saved() -> Optional[str]:
    try:
        data = json.loads(_config_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    language = data.get("language")
    return language if language in LANGUAGES else None


def save(language: str) -> None:
    path = _config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {}
    data["language"] = language
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def current() -> str:
    global _current
    if _current is None:
        env = os.environ.get("IPASIGN_LANG")
        if env in LANGUAGES:
            _current = env
        else:
            _current = load_saved() or DEFAULT
    return _current


def configured() -> bool:
    """True when a language was chosen already (env or saved preference)."""
    if os.environ.get("IPASIGN_LANG") in LANGUAGES:
        return True
    return load_saved() is not None


def set_language(language: str, persist: bool = True) -> None:
    global _current
    if language not in LANGUAGES:
        raise ValueError(f"unknown language: {language}")
    _current = language
    if persist:
        save(language)


def tr(key: str, **kwargs) -> str:
    """Translate ``key`` for the current language, formatting placeholders."""
    language = current()
    entry = MESSAGES.get(key)
    if entry is None:
        return key
    text = entry.get(language) or entry.get(DEFAULT) or key
    if kwargs:
        try:
            return text.format(**kwargs)
        except (KeyError, IndexError):
            return text
    return text
