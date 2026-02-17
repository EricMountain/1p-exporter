import json
import onep_exporter.exporter as exporter_module


def test_find_item_by_title_with_vault(monkeypatch):
    sample_item = {"id": "i1", "title": "My Pass",
                   "vault": {"id": "v1", "name": "VaultA"}}

    def fake_run_cmd(cmd, capture_output=True, check=True, input=None):
        if cmd[:3] == ["op", "item", "get"]:
            return 0, json.dumps(sample_item), ""
        raise RuntimeError("unexpected")

    monkeypatch.setattr(exporter_module, "run_cmd", fake_run_cmd)
    op = exporter_module.OpExporter()
    assert op.find_item_by_title("My Pass", vault="VaultA") is not None
    assert op.find_item_by_title("My Pass", vault="v1") is not None
    assert op.find_item_by_title("My Pass", vault="other") is None
