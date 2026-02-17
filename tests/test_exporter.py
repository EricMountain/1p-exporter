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
