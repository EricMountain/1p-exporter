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


def test_cli_doctor_success_exit_code(monkeypatch):
    import onep_exporter.cli as cli
    monkeypatch.setattr(cli, "doctor", lambda: True)
    try:
        cli.main(["doctor"])
    except SystemExit as e:
        assert e.code == 0
    else:
        raise AssertionError("expected SystemExit from cli.main")


def test_cli_doctor_failure_exit_code(monkeypatch):
    import onep_exporter.cli as cli
    monkeypatch.setattr(cli, "doctor", lambda: False)
    try:
        cli.main(["doctor"])
    except SystemExit as e:
        assert e.code == 2
    else:
        raise AssertionError("expected SystemExit from cli.main")


def test_cli_init_interactive_runs_doctor(monkeypatch):
    import onep_exporter.cli as cli
    called = {"interactive": False}
    monkeypatch.setattr(cli, "configure_interactive",
                        lambda: called.update({"interactive": True}) or {})
    monkeypatch.setattr(cli, "doctor", lambda: True)
    try:
        cli.main(["init"])
    except SystemExit as e:
        assert e.code == 0
    else:
        raise AssertionError("expected SystemExit from cli.main")


def test_configure_interactive_generates_age_key_and_stores(monkeypatch, tmp_path):
    """Interactive init should offer to generate an age keypair, add the public recipient to config,
    and store the private key in 1Password/keychain when requested."""
    import builtins
    import onep_exporter.exporter as exporter_module

    cfg_path = tmp_path / "cfg.json"
    monkeypatch.setenv("ONEP_EXPORTER_CONFIG", str(cfg_path))

    # pretend required tools are present
    monkeypatch.setattr(exporter_module, "ensure_tool", lambda name: True)

    # fake age-keygen output (private key block + public recipient)
    private_block = "-----BEGIN AGE PRIVATE KEY-----\nprivate-body\n-----END AGE PRIVATE KEY-----"
    public_recipient = "age1recipient12345"
    age_out = private_block + "\npublic key: " + public_recipient + "\n"

    def fake_run_cmd(cmd, capture_output=True, check=True, input=None):
        if cmd[0] == "age-keygen":
            return 0, age_out, ""
        return 0, "", ""

    monkeypatch.setattr(exporter_module, "run_cmd", fake_run_cmd)

    stored = {"1p_called": False, "kc_called": False}

    def fake_store_1p(self, title, field, pw, vault=None):
        stored["1p_called"] = True
        # ensure private key stored matches generated block
        assert pw.strip().startswith("-----BEGIN AGE PRIVATE KEY-----")
        return {"id": "fake-age-item"}

    monkeypatch.setattr(exporter_module.OpExporter,
                        "store_passphrase_in_1password", fake_store_1p)

    def fake_store_kc(service, username, pw):
        stored["kc_called"] = True
        assert "private-body" in pw

    monkeypatch.setattr(
        exporter_module, "_store_passphrase_in_keychain", fake_store_kc)

    # simulate interactive inputs (sequence)
    import sys
    monkeypatch.setattr(sys, "platform", "darwin")

    inputs = iter([
        "",     # Default backup directory (accept)
        "",     # formats (accept)
        "",     # encrypt (accept default 'age')
        "",     # download_attachments (accept)
        "prompt",  # age_pass_source
        "y",    # Generate a new age keypair? -> yes
        "y",    # Store private key in 1Password? -> yes
        "My Age Key",  # 1Password item title
        "",     # 1Password field name (accept default)
        "",     # 1Password vault (optional)
        "y",    # Store private key in macOS Keychain? -> yes
        "",     # age_recipients (accept default which includes generated pub)
        "n",    # include yubikey? -> no
        "n",    # Store generated passphrase in 1Password? (no)
        "n",    # Store generated passphrase in Keychain? (no)
    ])

    monkeypatch.setattr(builtins, "input", lambda prompt="": next(inputs))

    # run interactive config
    cfg = exporter_module.configure_interactive()

    # config should contain the generated public recipient
    assert cfg["age"]["recipients"] == public_recipient
    assert stored["1p_called"] is True
    assert stored["kc_called"] is True


def test_configure_interactive_parses_commented_public_and_secret_token(monkeypatch, tmp_path):
    """Ensure parser accepts commented public-key lines and AGE-SECRET-KEY tokens."""
    import builtins
    import onep_exporter.exporter as exporter_module

    cfg_path = tmp_path / "cfg2.json"
    monkeypatch.setenv("ONEP_EXPORTER_CONFIG", str(cfg_path))
    monkeypatch.setattr(exporter_module, "ensure_tool", lambda name: True)

    # variant A: commented public key line with private block
    pub_a = "age1commentedpub"
    out_a = "# created: blah\n-----BEGIN AGE PRIVATE KEY-----\npriv-a\n-----END AGE PRIVATE KEY-----\n# public key: " + pub_a + "\n"

    # variant B: AGE-SECRET-KEY token + commented public line
    pub_b = "age1tokpub"
    secret_b = "AGE-SECRET-KEY-1ABCDEFGHIJKLMNOP"
    out_b = "# public key: " + pub_b + "\n" + secret_b + "\n"

    seq = iter([out_a, out_b])

    def fake_run_cmd(cmd, capture_output=True, check=True, input=None):
        if cmd[0] == "age-keygen":
            return 0, next(seq), ""
        return 0, "", ""

    monkeypatch.setattr(exporter_module, "run_cmd", fake_run_cmd)

    stored = {"1p": [], "kc": []}

    def fake_store_1p(self, title, field, pw, vault=None):
        stored["1p"].append(pw)
        return {"id": "ok"}

    monkeypatch.setattr(exporter_module.OpExporter,
                        "store_passphrase_in_1password", fake_store_1p)
    monkeypatch.setattr(exporter_module, "_store_passphrase_in_keychain",
                        lambda s, u, p: stored["kc"].append(p))

    import sys
    monkeypatch.setattr(sys, "platform", "darwin")

    # run first interactive (out_a)
    inputs_a = iter(["", "", "", "", "prompt", "y", "y",
                    "T1", "", "", "y", "", "n", "n", "n"])
    monkeypatch.setattr(builtins, "input", lambda prompt="": next(inputs_a))
    cfg1 = exporter_module.configure_interactive()
    assert cfg1["age"]["recipients"] == pub_a
    assert stored["1p"][0].startswith("-----BEGIN AGE PRIVATE KEY-----")

    # run second interactive (out_b)
    inputs_b = iter(["", "", "", "", "prompt", "y", "y",
                    "T2", "", "", "y", "", "n", "n", "n"])
    monkeypatch.setattr(builtins, "input", lambda prompt="": next(inputs_b))
    cfg2 = exporter_module.configure_interactive()
    # new recipient should be present and previous recipient preserved
    assert pub_b in cfg2["age"]["recipients"]
    assert pub_a in cfg2["age"]["recipients"]
    # secret token stored in 1Password/keychain
    assert secret_b in stored["1p"][1]
    assert secret_b in stored["kc"][1]


def test_default_private_key_title_includes_username(monkeypatch, tmp_path):
    """Default 1Password item title should include the OS username and be used when accepted."""
    import builtins
    import getpass
    import onep_exporter.exporter as exporter_module

    cfg_path = tmp_path / "cfg3.json"
    monkeypatch.setenv("ONEP_EXPORTER_CONFIG", str(cfg_path))
    monkeypatch.setattr(exporter_module, "ensure_tool", lambda name: True)

    # fake age-keygen output
    public_recipient = "age1defaultpub"
    age_out = "-----BEGIN AGE PRIVATE KEY-----\npriv-default\n-----END AGE PRIVATE KEY-----\npublic key: " + \
        public_recipient + "\n"
    monkeypatch.setattr(exporter_module, "run_cmd", lambda cmd, capture_output=True,
                        check=True, input=None: (0, age_out, "") if cmd[0] == "age-keygen" else (0, "", ""))

    captured = {"title": None}

    def fake_store_1p(self, title, field, pw, vault=None):
        captured["title"] = title
        return {"id": "ok"}

    monkeypatch.setattr(exporter_module.OpExporter,
                        "store_passphrase_in_1password", fake_store_1p)
    monkeypatch.setattr(
        exporter_module, "_store_passphrase_in_keychain", lambda s, u, p: None)

    # ensure getuser returns a known value
    monkeypatch.setattr(getpass, "getuser", lambda: "ci-user")

    import sys
    monkeypatch.setattr(sys, "platform", "darwin")

    # interactive inputs: accept defaults for title (empty string)
    inputs = iter([
        "",     # Default backup directory
        "",     # formats
        "",     # encrypt (age)
        "",     # download_attachments
        "prompt",  # age_pass_source
        "y",    # Generate age keypair
        "y",    # Store private key in 1Password?
        "",     # Accept default title
        "",     # Accept default field
        "",     # vault (optional)
        "n",    # Store private key in keychain? -> no
        "",     # age_recipients (accept default)
        "n",    # yubikey? no
        "n",    # store passphrase in 1Password? no
        "n",    # store passphrase in keychain? no
    ])
    monkeypatch.setattr(builtins, "input", lambda prompt="": next(inputs))

    cfg = exporter_module.configure_interactive()

    expected = "1Password backup - ci-user - Age private key"
    assert captured["title"] == expected
    assert public_recipient in cfg["age"]["recipients"]


def test_cli_init_flagged_runs_doctor_failure(monkeypatch):
    import onep_exporter.cli as cli
    called = {"init_setup": False}

    def fake_init_setup(**kwargs):
        called["init_setup"] = True
        return "pw"
    monkeypatch.setattr(cli, "init_setup", fake_init_setup)
    monkeypatch.setattr(cli, "doctor", lambda: False)
    try:
        cli.main(["init", "--generate"])
    except SystemExit as e:
        assert e.code == 2
        assert called["init_setup"] is True
    else:
        raise AssertionError("expected SystemExit from cli.main")
