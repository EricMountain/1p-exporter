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


def test_query_list_cli_age_identity(tmp_path, capsys):
    # ensure encrypted archive can be queried via CLI options
    import shutil, subprocess, os
    if shutil.which("age") is None:
        pytest.skip("age not installed")

    root = tmp_path / "out3"
    root.mkdir()
    data = [{"id": "1", "title": "spam"}]
    (root / "vault.json").write_text(json.dumps(data))
    archive = tmp_path / "archive3.tar.gz"
    import tarfile
    with tarfile.open(archive, "w:gz") as tf:
        tf.add(root / "vault.json", arcname="vault.json")

    keyfile = tmp_path / "agekey2.txt"
    proc = subprocess.run(["age-keygen", "-o", str(keyfile)], capture_output=True, text=True, check=True)
    pubkey = None
    for line in proc.stderr.splitlines():
        if line.startswith("Public key:"):
            pubkey = line.split(":", 1)[1].strip()
            break
    assert pubkey
    enc = tmp_path / "archive3.tar.gz.age"
    subprocess.run(["age", "-r", pubkey, "-o", str(enc), str(archive)], check=True)

    # use CLI flag to provide identity; should print "spam"
    with pytest.raises(SystemExit) as exc:
        main(["query", "list", "sp", "--dir", str(enc), "--age-identity", str(keyfile)])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "spam" in captured.out


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


def test_query_list_age(tmp_path):
    # if the age binary isn't present we can't perform decryption; skip
    import shutil, subprocess
    if shutil.which("age") is None:
        pytest.skip("age not installed")

    # create a simple tarball just like the previous test
    root = tmp_path / "out2"
    root.mkdir()
    data = [{"id": "1", "title": "spam"}, {"id": "2", "title": "eggs"}]
    (root / "vault.json").write_text(json.dumps(data))
    archive = tmp_path / "archive2.tar.gz"
    import tarfile
    with tarfile.open(archive, "w:gz") as tf:
        tf.add(root / "vault.json", arcname="vault.json")

    # generate an ephemeral age keypair and extract the public recipient
    keyfile = tmp_path / "agekey.txt"
    proc = subprocess.run(["age-keygen", "-o", str(keyfile)], capture_output=True, text=True, check=True)
    # the command prints the public key on stderr
    pubkey = None
    for line in proc.stderr.splitlines():
        if line.startswith("Public key:"):
            pubkey = line.split(":", 1)[1].strip()
            break
    assert pubkey, "failed to derive public key from age-keygen"

    # encrypt the archive using that recipient (no interaction)
    enc = tmp_path / "archive2.tar.gz.age"
    subprocess.run(["age", "-r", pubkey, "-o", str(enc), str(archive)], check=True)

    # tell query_list_titles where to find the corresponding identity
    import os
    os.environ["AGE_IDENTITIES"] = str(keyfile)

    # the query function should transparently decrypt and search
    res = query_list_titles(enc, "sp")
    assert res == ["spam"]
