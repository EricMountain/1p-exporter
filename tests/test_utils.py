from pathlib import Path
from onep_exporter.utils import sha256_file, CommandError


def test_sha256_file(tmp_path):
    p = tmp_path / "foo.txt"
    p.write_text("hello")
    assert sha256_file(
        p) == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"


def test_commanderror_redacts_age_secret_and_private_block():
    cmd = [
        "op",
        "item",
        "create",
        '{"title":"1Password backup - eric - Age private key", "fields": [{"label":"private_key","value":"AGE-SECRET-KEY-1ABCDEFGHIJKLMNOP"}]}'
    ]
    e = CommandError(cmd=cmd, rc=1, stderr="error")
    s = str(e)
    # AGE secret prefix (short) should be present but the full token must be redacted/truncated
    assert "AGE-SECRET" in s
    assert "AGE-SECRET-KEY-1ABCDEFGHIJKLMNOP" not in s
    assert "…" in s
    # ensure redaction did not inject extra quotes like ""AGE-SECRET…""
    assert '""' not in s

    # private key block redaction
    private_block = "-----BEGIN AGE PRIVATE KEY-----\nsecret-body\n-----END AGE PRIVATE KEY-----"
    cmd2 = ["op", "item", "create", '{"value":"' + private_block + '"}']
    e2 = CommandError(cmd=cmd2, rc=1, stderr="error")
    s2 = str(e2)
    # ensure body is not present and redaction token is shown
    assert "secret-body" not in s2
    assert "<redacted private key>" in s2 or "…" in s2
    # no doubled quotes introduced
    assert '""' not in s2
