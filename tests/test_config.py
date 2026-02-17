import os
import json
from pathlib import Path
import onep_exporter.exporter as exporter_module


def test_save_and_load_config(tmp_path, monkeypatch):
    cfg_path = tmp_path / "cfg.json"
    monkeypatch.setenv("ONEP_EXPORTER_CONFIG", str(cfg_path))
    data = {"output_base": "/tmp/backups", "encrypt": "age",
            "age": {"pass_source": "keychain"}}

    p = exporter_module.save_config(data)
    assert p.exists()
    loaded = exporter_module.load_config()
    assert loaded["output_base"] == "/tmp/backups"
    assert loaded["age"]["pass_source"] == "keychain"


def test_cli_uses_config_defaults(monkeypatch):
    # provide a config and ensure CLI merges values when flags not provided
    cfg = {"output_base": "/tmp/fromcfg", "encrypt": "age", "formats": ["json"], "download_attachments": True, "age": {
        "pass_source": "prompt", "recipients": "", "keychain_service": "1p-exporter", "keychain_username": "backup"}}
    monkeypatch.setattr(exporter_module, "load_config", lambda: cfg)

    called = {}

    def fake_run_backup(**kwargs):
        called.update(kwargs)

    import importlib
    import onep_exporter.cli as cli
    # ensure the cli module uses the patched exporter.load_config/run_backup
    monkeypatch.setattr(cli, "load_config", lambda: cfg)
    monkeypatch.setattr(cli, "run_backup", fake_run_backup)

    cli.main(["backup"])

    assert called["output_base"] == "/tmp/fromcfg"
    assert called["encrypt"] == "age"
    assert called["formats"] == ["json"]


def test_cli_flag_overrides_config(monkeypatch):
    cfg = {"output_base": "/tmp/fromcfg",
           "encrypt": "age", "formats": ["json"]}
    monkeypatch.setattr(exporter_module, "load_config", lambda: cfg)

    called = {}

    def fake_run_backup(**kwargs):
        called.update(kwargs)

    import onep_exporter.cli as cli
    # ensure cli uses the patched load_config/run_backup
    monkeypatch.setattr(cli, "load_config", lambda: cfg)
    monkeypatch.setattr(cli, "run_backup", fake_run_backup)

    cli.main(["backup", "--output", "/tmp/explicit",
             "--formats", "json,md", "--encrypt", "gpg"])

    assert called["output_base"] == "/tmp/explicit"
    assert called["encrypt"] == "gpg"
    assert called["formats"] == ["json", "md"]
