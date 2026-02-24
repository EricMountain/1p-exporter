import json
from pathlib import Path

import pytest

from onep_exporter.cli import main
from onep_exporter.exporter import query_list_titles


def test_query_list_titles_dir(tmp_path):
    # create some vault JSON files with different titles
    d = tmp_path
    data1 = [{"id": "1", "title": "FooItem"}, {"id": "2", "title": "Bar"}]
    data2 = [{"id": "3", "title": "AnotherFoo"}]
    (d / "vault-a.json").write_text(json.dumps(data1))
    (d / "vault-b.json").write_text(json.dumps(data2))

    # pattern filters case-sensitively
    res = query_list_titles(d, "Foo")
    assert sorted(res) == ["AnotherFoo", "FooItem"]

    # no matches returns empty list
    assert query_list_titles(d, "^Q") == []


def test_query_list_cli(tmp_path, capsys):
    d = tmp_path
    data = [{"id": "1", "title": "baz"}, {"id": "2", "title": "qux"}]
    (d / "vault.json").write_text(json.dumps(data))

    # run command and capture output (cli.main exits via SystemExit)
    with pytest.raises(SystemExit) as exc:
        main(["query", "list", "ba", "--dir", str(d)])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "baz" in captured.out
    assert "qux" not in captured.out


def test_query_list_tarball(tmp_path):
    # construct a tar.gz archive containing a vault json
    root = tmp_path / "out"
    root.mkdir()
    data = [{"id": "1", "title": "spam"}, {"id": "2", "title": "eggs"}]
    (root / "vault.json").write_text(json.dumps(data))
    archive = tmp_path / "archive.tar.gz"
    import tarfile
    with tarfile.open(archive, "w:gz") as tf:
        tf.add(root / "vault.json", arcname="vault.json")

    res = query_list_titles(archive, "sp")
    assert res == ["spam"]
