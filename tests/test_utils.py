from pathlib import Path
from onep_exporter.utils import sha256_file


def test_sha256_file(tmp_path):
    p = tmp_path / "foo.txt"
    p.write_text("hello")
    assert sha256_file(
        p) == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
