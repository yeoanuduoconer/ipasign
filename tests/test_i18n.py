"""Translation layer tests."""

from __future__ import annotations

import json

from ipasign import i18n


def _reset(monkeypatch):
    monkeypatch.delenv("IPASIGN_LANG", raising=False)
    monkeypatch.setattr(i18n, "_current", None)


def test_default_language_is_english(monkeypatch, tmp_path):
    _reset(monkeypatch)
    monkeypatch.setenv("IPASIGN_HOME", str(tmp_path))
    assert i18n.current() == "en"
    assert i18n.tr("menu.quit") == "Quit"


def test_switch_to_chinese(monkeypatch, tmp_path):
    _reset(monkeypatch)
    monkeypatch.setenv("IPASIGN_HOME", str(tmp_path))
    i18n.set_language("zh")
    assert i18n.current() == "zh"
    assert i18n.tr("menu.quit") == "退出"


def test_choice_is_persisted(monkeypatch, tmp_path):
    _reset(monkeypatch)
    monkeypatch.setenv("IPASIGN_HOME", str(tmp_path))
    assert i18n.configured() is False

    i18n.set_language("zh")
    assert i18n.configured() is True
    data = json.loads((tmp_path / "config.json").read_text(encoding="utf-8"))
    assert data["language"] == "zh"

    # a fresh process picks the saved value up
    monkeypatch.setattr(i18n, "_current", None)
    assert i18n.current() == "zh"


def test_env_overrides_saved(monkeypatch, tmp_path):
    _reset(monkeypatch)
    monkeypatch.setenv("IPASIGN_HOME", str(tmp_path))
    i18n.set_language("zh")
    monkeypatch.setattr(i18n, "_current", None)
    monkeypatch.setenv("IPASIGN_LANG", "en")
    assert i18n.current() == "en"
    assert i18n.configured() is True


def test_unknown_key_falls_back_to_key(monkeypatch, tmp_path):
    _reset(monkeypatch)
    monkeypatch.setenv("IPASIGN_HOME", str(tmp_path))
    assert i18n.tr("no.such.key") == "no.such.key"


def test_placeholders_are_formatted(monkeypatch, tmp_path):
    _reset(monkeypatch)
    monkeypatch.setenv("IPASIGN_HOME", str(tmp_path))
    assert "x.ipa" in i18n.tr("path.not_found", path="x.ipa")


def test_every_key_has_both_languages():
    for key, entry in i18n.MESSAGES.items():
        assert entry.get("en"), f"{key} missing English"
        assert entry.get("zh"), f"{key} missing Chinese"


def test_unknown_language_rejected(monkeypatch, tmp_path):
    _reset(monkeypatch)
    monkeypatch.setenv("IPASIGN_HOME", str(tmp_path))
    try:
        i18n.set_language("de")
    except ValueError:
        return
    raise AssertionError("unknown language should raise")
