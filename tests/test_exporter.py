import json
from pathlib import Path

import onep_exporter.exporter as exporter_module


def test_get_item_field_value(monkeypatch):
    sample_item = {"fields": [
        {"id": "f1", "type": "password", "name": "password", "value": "seekrit"}]}

    def fake_run_cmd(cmd, capture_output=True, check=True, input=None):
        if cmd[:3] == ["op", "item", "get"]:
            return 0, json.dumps(sample_item), ""
        raise RuntimeError("unexpected command: %r" % (cmd,))

    monkeypatch.setattr(exporter_module, "run_cmd", fake_run_cmd)
    op = exporter_module.OpExporter()
    val = op.get_item_field_value("My Item", "password")
    assert val == "seekrit"


def test_age_encrypt_path(monkeypatch, tmp_path):
    # make ensure_tool return True for `op` and `age`
    monkeypatch.setattr(exporter_module, "ensure_tool", lambda name: True)

    # fake run_cmd to handle op vault list and age invocation
    captured = {"age_called": False, "args": None}

    def fake_run_cmd(cmd, capture_output=True, check=True, input=None):
        if cmd[:3] == ["op", "vault", "list"]:
            return 0, "[]", ""
        if cmd[0] == "age":
            captured["age_called"] = True
            captured["args"] = cmd
            return 0, "", ""
        # fallback for other invocations
        return 0, "", ""

    monkeypatch.setattr(exporter_module, "run_cmd", fake_run_cmd)

    # ensure prompt returns a passphrase
    monkeypatch.setattr("getpass.getpass", lambda prompt: "pw123")

    out = exporter_module.run_backup(output_base=str(
        tmp_path), encrypt="age", age_pass_source="prompt", age_recipients="", quiet=True)
    assert captured["age_called"], "age was not invoked"
    assert out.suffix == ".age"
    # last arg must be the plaintext archive path
    assert str(out).endswith(".age")


def test_get_passphrase_from_keychain_keyring(monkeypatch):
    # simulate keyring module being available
    import sys
    import types
    fake_keyring = types.SimpleNamespace(get_password=lambda s, u: "kpass")
    monkeypatch.setitem(sys.modules, "keyring", fake_keyring)
    val = exporter_module._get_passphrase_from_keychain("svc", "acct")
    assert val == "kpass"


def test_get_passphrase_from_keychain_security_fallback(monkeypatch):
    # simulate 'security' CLI via run_cmd fallback
    def fake_run_cmd(cmd, capture_output=True, check=True, input=None):
        if cmd[0] == "security":
            return 0, "sec-pass\n", ""
        raise RuntimeError("unexpected")

    monkeypatch.setattr(exporter_module, "run_cmd", fake_run_cmd)
    import sys
    monkeypatch.setattr(sys, "platform", "darwin")
    val = exporter_module._get_passphrase_from_keychain("svc", "acct")
    assert val == "sec-pass"


def test_init_setup_stores(monkeypatch):
    calls = {"1p": False, "kc": False}

    def fake_store_1p(self, title, field, pw, vault=None):
        calls["1p"] = True
        return {"id": "fake-item"}

    monkeypatch.setattr(exporter_module.OpExporter,
                        "store_passphrase_in_1password", fake_store_1p)
    monkeypatch.setattr(exporter_module, "_store_passphrase_in_keychain",
                        lambda s, u, p: calls.update({"kc": True}))

    pw = exporter_module.init_setup(passphrase="xyz", generate=False,
                                    store_in_1password="My Pass", store_in_keychain=True, onepassword_vault="myvault")
    assert pw == "xyz"
    assert calls["1p"] is True
    assert calls["kc"] is True


def test_store_passphrase_skips_if_exists(monkeypatch):
    # ensure find_item_by_title short-circuits creation
    monkeypatch.setattr(exporter_module.OpExporter, "find_item_by_title",
                        lambda self, title, vault=None: {"id": "exists"})
    called = {"create": False}

    def fake_run_cmd(cmd, capture_output=True, check=True, input=None):
        if cmd[:3] == ["op", "item", "create"]:
            called["create"] = True
            return 0, "{}", ""
        return 0, "{}", ""

    monkeypatch.setattr(exporter_module, "run_cmd", fake_run_cmd)
    op = exporter_module.OpExporter()
    res = op.store_passphrase_in_1password(
        "Title", "password", "pw", vault="myvault")
    assert res.get("id") == "exists"
    assert called["create"] is False


def test_store_passphrase_pipes_json_via_stdin(monkeypatch):
    """Verify that `op item create` receives the JSON template on stdin (via `-`)
    and uses category 'Secure Note' with field type CONCEALED."""
    seen = {}

    def fake_run_cmd(cmd, capture_output=True, check=True, input=None):
        seen["cmd"] = cmd
        seen["input"] = input
        return 0, '{"id": "new"}', ""

    monkeypatch.setattr(exporter_module.OpExporter,
                        "find_item_by_title", lambda self, t, vault=None: None)
    monkeypatch.setattr(exporter_module, "run_cmd", fake_run_cmd)

    op = exporter_module.OpExporter()
    res = op.store_passphrase_in_1password(
        "Title", "password", "s3cret", vault="myvault")
    assert res.get("id") == "new"

    cmd = seen["cmd"]
    # `-` must be the last positional arg so op reads template from stdin
    assert cmd[-1] == "-"
    assert "--format" in cmd
    assert "--vault" in cmd

    # the JSON template is sent as bytes on stdin
    payload = json.loads(seen["input"])
    assert payload["title"] == "Title"
    # category is passed via --category flag, not in the JSON template
    assert "category" not in payload
    assert "--category" in cmd
    cat_idx = cmd.index("--category")
    assert cmd[cat_idx + 1] == "Secure Note"
    assert len(payload["fields"]) == 1
    field = payload["fields"][0]
    assert field["type"] == "CONCEALED"
    assert field["value"] == "s3cret"
    assert field["label"] == "password"


def test_store_private_key_uses_concealed_field(monkeypatch):
    """Private keys are also stored as CONCEALED fields (same as passphrases)."""
    seen = {}

    def fake_run_cmd(cmd, capture_output=True, check=True, input=None):
        seen["input"] = input
        return 0, '{"id": "new"}', ""

    monkeypatch.setattr(exporter_module.OpExporter,
                        "find_item_by_title", lambda self, t, vault=None: None)
    monkeypatch.setattr(exporter_module, "run_cmd", fake_run_cmd)

    op = exporter_module.OpExporter()
    private = "AGE-SECRET-KEY-1ABCDEFGHIJKLMNOP"
    res = op.store_passphrase_in_1password(
        "Title", "private_key", private, vault="myvault")
    assert res.get("id") == "new"

    payload = json.loads(seen["input"])
    field = payload["fields"][0]
    assert field["type"] == "CONCEALED"
    assert field["id"] == "private_key"
    assert field["value"] == private


def test_passphrase_mismatch_raises(monkeypatch, tmp_path):
    # ensure tools exist
    monkeypatch.setattr(exporter_module, "ensure_tool", lambda name: True)

    # 1Password has one value, keychain has a different value
    monkeypatch.setattr(exporter_module.OpExporter,
                        "get_item_field_value", lambda self, item, field: "onepw")
    monkeypatch.setattr(
        exporter_module, "_get_passphrase_from_keychain", lambda s, u: "kc-different")

    # fake op vault list
    monkeypatch.setattr(exporter_module, "run_cmd", lambda cmd, capture_output=True, check=True, input=None: (
        0, "[]", "") if cmd[:3] == ["op", "vault", "list"] else (0, "", ""))

    try:
        exporter_module.run_backup(output_base=str(tmp_path), encrypt="age", age_pass_source="1password", age_pass_item="Item",
                                   age_pass_field="password", age_keychain_service="svc", age_keychain_username="acct", quiet=True)
    except RuntimeError as e:
        assert "passphrase mismatch" in str(e)
    else:
        raise AssertionError(
            "expected RuntimeError due to passphrase mismatch")


def test_sync_passphrase_from_1password_to_keychain(monkeypatch, tmp_path):
    # ensure tools exist and age will run
    monkeypatch.setattr(exporter_module, "ensure_tool", lambda name: True)

    # 1Password has the authoritative value; keychain empty
    monkeypatch.setattr(exporter_module.OpExporter,
                        "get_item_field_value", lambda self, item, field: "sync-me")
    monkeypatch.setattr(
        exporter_module, "_get_passphrase_from_keychain", lambda s, u: None)

    stored = {"kc": False}

    def fake_store_kc(srv, user, pw):
        stored["kc"] = (srv, user, pw)

    monkeypatch.setattr(
        exporter_module, "_store_passphrase_in_keychain", fake_store_kc)

    # fake run_cmd to allow vault listing and to accept age invocation
    def fake_run_cmd(cmd, capture_output=True, check=True, input=None):
        if cmd[:3] == ["op", "vault", "list"]:
            return 0, "[]", ""
        if cmd[0] == "age":
            return 0, "", ""
        return 0, "", ""

    monkeypatch.setattr(exporter_module, "run_cmd", fake_run_cmd)

    out = exporter_module.run_backup(output_base=str(tmp_path), encrypt="age", age_pass_source="1password", age_pass_item="Item",
                                     sync_passphrase_from_1password=True, age_keychain_service="svc", age_keychain_username="acct", quiet=True)

    assert stored["kc"] == ("svc", "acct", "sync-me")
    assert out.suffix == ".age"


def test_doctor_detects_missing_op(monkeypatch, capsys):
    # op missing -> critical failure
    monkeypatch.setattr(exporter_module, "ensure_tool",
                        lambda name: False if name == "op" else True)
    monkeypatch.setattr(exporter_module, "load_config", lambda: {})
    ok = exporter_module.doctor()
    captured = capsys.readouterr()
    assert ok is False
    assert "op" in captured.out
    assert "❌" in captured.out
    assert "FAILED" in captured.out


def test_doctor_detects_missing_age_tool_from_config(monkeypatch, capsys):
    # config requests age but `age` binary unavailable
    monkeypatch.setattr(exporter_module, "ensure_tool",
                        lambda name: False if name == "age" else True)
    monkeypatch.setattr(exporter_module, "load_config",
                        lambda: {"encrypt": "age", "age": {}})
    ok = exporter_module.doctor()
    captured = capsys.readouterr()
    assert ok is False
    assert "age" in captured.out
    assert "❌" in captured.out
    assert "FAILED" in captured.out


def test_doctor_ok_with_valid_config_and_tools(monkeypatch, capsys):
    monkeypatch.setattr(exporter_module, "ensure_tool", lambda name: True)
    monkeypatch.setenv("BACKUP_PASSPHRASE", "pw123")
    monkeypatch.setattr(exporter_module, "load_config", lambda: {
                        "encrypt": "age", "formats": ["json"], "age": {"pass_source": "env"}})
    ok = exporter_module.doctor()
    captured = capsys.readouterr()
    assert ok is True
    assert "✅" in captured.out
    assert "OK" in captured.out
    assert "BACKUP_PASSPHRASE" in captured.out


def test_doctor_tools_section_reports_presence_and_absence(monkeypatch, capsys):
    # simulate some tools present, others absent
    def fake_ensure(name):
        # report core tools + requested ones as present; leave others missing
        return name in ("op", "age", "gpg", "apt")

    monkeypatch.setattr(exporter_module, "ensure_tool", fake_ensure)
    monkeypatch.setattr(exporter_module, "load_config", lambda: {})

    ok = exporter_module.doctor()
    captured = capsys.readouterr()

    # overall still OK (missing tools are informational unless required by config)
    assert ok is True

    # present tools reported as available
    assert "`age` available" in captured.out
    assert "`gpg` available" in captured.out

    # missing tools reported as not found (warnings)
    assert "`age-keygen` not found" in captured.out
    # `security` is macOS-only so should NOT be listed on non-darwin platforms
    assert "`security`" not in captured.out

    # suggestions should include apt-based install for missing age-keygen
    assert "sudo apt install -y age" in captured.out or "install age" in captured.out


def test_doctor_tools_mark_config_required_tool_missing(monkeypatch, capsys):
    # config requires age but age tool missing -> failure
    def fake_ensure(n):
        # pretend apt is available for suggestion, but `age` itself is missing
        return n == "apt" or n == "op"

    monkeypatch.setattr(exporter_module, "ensure_tool", fake_ensure)
    monkeypatch.setattr(exporter_module, "load_config",
                        lambda: {"encrypt": "age", "age": {}})

    ok = exporter_module.doctor()
    captured = capsys.readouterr()
    assert ok is False
    assert "`age` not found" in captured.out or "age" in captured.out
    assert "sudo apt install -y age" in captured.out
    assert "❌" in captured.out
    assert "FAILED" in captured.out


def test_doctor_includes_security_for_darwin(monkeypatch, capsys):
    # on darwin `security` should be checked/reported
    import sys as _sys
    monkeypatch.setattr(_sys, "platform", "darwin")

    def fake_ensure(name):
        return name in ("op", "age")
    monkeypatch.setattr(exporter_module, "ensure_tool", fake_ensure)
    monkeypatch.setattr(exporter_module, "load_config", lambda: {})

    ok = exporter_module.doctor()
    captured = capsys.readouterr()

    # `security` should appear in the tools section on darwin
    assert "`security` not found" in captured.out or "security" in captured.out
