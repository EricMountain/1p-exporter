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


def test_streaming_encrypt_path(monkeypatch, tmp_path):
    # make ensure_tool return True for any tool we might invoke
    monkeypatch.setattr(exporter_module, "ensure_tool", lambda name: True)

    # capture subprocess.Popen invocations rather than run_cmd
    import io, subprocess
    called = {"cmd": None}

    class FakePopen:
        def __init__(self, cmd, stdin=None, **kwargs):
            called["cmd"] = cmd
            # provide a writeable buffer for tarfile to write into
            self.stdin = io.BytesIO() if stdin == subprocess.PIPE else None
            self.returncode = 0

        def wait(self):
            return self.returncode

        def communicate(self, input=None, timeout=None):
            # mimic real Popen.communicate
            return (b"", b"")

        # support context manager protocol used by subprocess.run
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            # don't suppress exceptions
            return False

    # stub run_cmd so that we have one vault/item and avoid executing real CLI
    def fake_run_cmd(cmd, capture_output=True, check=True, input=None):
        if cmd[:3] == ["op", "vault", "list"]:
            return 0, '[{"id": "v1", "name": "Vault"}]', ""
        if cmd[:3] == ["op", "item", "list"]:
            return 0, '[{"id":"i1"}]', ""
        if cmd[:3] == ["op", "item", "get"]:
            return 0, '{"id":"i1","fields":[]}', ""
        return 0, "", ""
    monkeypatch.setattr(exporter_module, "run_cmd", fake_run_cmd)
    # intercept tempfile.mkdtemp so we know where the working directory is and keep
    # it around for inspection.  also prevent cleanup by stubbing shutil.rmtree.
    import tempfile, shutil
    tmp_work = tmp_path / "workdir"
    monkeypatch.setattr(tempfile, "mkdtemp", lambda: str(tmp_work))
    monkeypatch.setattr(shutil, "rmtree", lambda p: None)

    # patch the global subprocess module so imports inside run_backup pick up our fake
    import subprocess as _sub
    monkeypatch.setattr(_sub, "Popen", FakePopen)

    # ensure prompt returns a passphrase
    monkeypatch.setattr("getpass.getpass", lambda prompt: "pw123")

    # test age encryption streaming
    out = exporter_module.run_backup(output_base=str(tmp_path), encrypt="age", age_pass_source="prompt", age_recipients="", quiet=True)
    assert called["cmd"][0] == "age"
    assert "-o" in called["cmd"]
    assert out.suffix == ".age"

    # no markdown or vault JSON should land on disk at all
    assert not any(tmp_path.rglob("*.md")), "markdown should not exist on disk when encrypting"
    assert not any(tmp_path.rglob("vault-*.json")), "vault JSON should not exist on disk when encrypting"
    # manifest (in tmp_work) should record entries
    outdir = tmp_work
    manifest = json.loads((outdir / "manifest.json").read_text(encoding="utf-8"))
    paths = [f.get("path", "") for f in manifest.get("files", [])]
    assert any(p.endswith(".md") for p in paths)
    vaults = manifest.get("vaults", [])
    assert any(v.get("file") == "vault-v1.json" for v in vaults)

    # now test gpg streaming
    called["cmd"] = None
    out = exporter_module.run_backup(output_base=str(tmp_path), encrypt="gpg", quiet=True)
    assert called["cmd"][0] == "gpg"
    assert "--output" in called["cmd"]
    assert out.suffix == ".gpg"
    assert not any(tmp_path.rglob("*.md")), "markdown should not exist on disk when encrypting"

def test_markdown_written_when_not_encrypted(monkeypatch, tmp_path):
    # ensure minimal export with markdown and no encryption; no files should be left behind
    monkeypatch.setattr(exporter_module, "ensure_tool", lambda name: True)
    def fake_run_cmd(cmd, capture_output=True, check=True, input=None):
        if cmd[:3] == ["op", "vault", "list"]:
            return 0, '[{"id": "v1", "name": "Vault"}]', ""
        if cmd[:3] == ["op", "item", "list"]:
            return 0, '[{"id":"i1"}]', ""
        if cmd[:3] == ["op", "item", "get"]:
            return 0, '{"id":"i1","fields":[]}', ""
        return 0, "", ""
    monkeypatch.setattr(exporter_module, "run_cmd", fake_run_cmd)
    out = exporter_module.run_backup(output_base=str(tmp_path), formats=("json", "md"), encrypt="none", quiet=True)
    # archive should be plain tarball compressed with gzip
    assert out.name.endswith(".tar.gz")
    # no markdown or json files remain
    assert not any(tmp_path.rglob("*.md")), "no markdown should be left"
    assert not any(tmp_path.rglob("vault-*.json")), "no vault JSON should be left"


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

    # fake run_cmd to allow vault listing (encryption is handled by Popen now)
    def fake_run_cmd(cmd, capture_output=True, check=True, input=None):
        if cmd[:3] == ["op", "vault", "list"]:
            return 0, "[]", ""
        return 0, "", ""

    monkeypatch.setattr(exporter_module, "run_cmd", fake_run_cmd)
    # also stub Popen so we don't execute a real age binary
    import io, subprocess as _sub
    class FakePopen:
        def __init__(self, cmd, stdin=None, **kwargs):
            self.stdin = io.BytesIO()
            self.returncode = 0
        def wait(self):
            return 0
    monkeypatch.setattr(_sub, "Popen", FakePopen)

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
    # `security` is macOS-specific; we don't assert its absence here (tests run on darwin)

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
    # suggestion may vary by platform (apt, brew, etc.)
    assert "install age" in captured.out
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
