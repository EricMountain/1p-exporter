import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import Tuple, Optional


import re


def _redact_sensitive(text: Optional[str]) -> Optional[str]:
    """Redact sensitive tokens and private-key material for safe display.

    - Truncates AGE secret tokens (keeps readable prefix + ellipsis)
    - Redacts AGE private key blocks (preserve header/footer)
    - Truncates long JSON `"value"` fields that likely contain secrets
    """
    if not text:
        return text

    redacted = text

    # redact AGE secret tokens (show short prefix + ellipsis)
    def _redact_token(m: re.Match) -> str:
        tok = m.group(0)
        return tok[:16] + "…"

    redacted = re.sub(
        r"AGE-SECRET-KEY-[A-Za-z0-9\-_=]+", _redact_token, redacted)

    # redact AGE private key blocks but keep headers
    redacted = re.sub(
        r"(-----BEGIN AGE [^-]+-----)(.*?)(-----END AGE [^-]+-----)",
        lambda m: m.group(1) + "\n<redacted private key>\n" + m.group(3),
        redacted,
        flags=re.S,
    )

    # redact long values in JSON-like payloads (e.g. value fields)
    def _redact_json_value(m: re.Match) -> str:
        prefix, val, suffix = m.group(1), m.group(2), m.group(3)
        # prefix already contains the opening quote for the value; avoid inserting extra quotes
        if len(val) > 16 or "AGE-SECRET-KEY" in val or "-----BEGIN AGE" in val:
            return f'{prefix}{val[:12]}…{suffix}'
        return m.group(0)

    redacted = re.sub(
        r'("value"\s*:\s*")([^"]*)("\s*[,}])', _redact_json_value, redacted)

    return redacted


class CommandError(RuntimeError):
    """CommandError holds structured data about a failed subprocess invocation and
    redacts sensitive bits when converted to string.

    Can be constructed either with a plain message or with keyword args `cmd`, `rc`, `stderr`.
    """

    def __init__(self, message: Optional[str] = None, *, cmd: Optional[list] = None, rc: Optional[int] = None, stderr: Optional[str] = None):
        if cmd is not None:
            self.cmd = cmd
            self.rc = rc
            self.stderr = stderr
            raw = f"Command {cmd!r} failed: {rc}: {stderr}"
            super().__init__(raw)
        else:
            self.cmd = None
            self.rc = None
            self.stderr = None
            super().__init__(message)

    def __str__(self) -> str:  # redacted representation for safe display
        return _redact_sensitive(super().__str__() or "")


def run_cmd(cmd: list[str], capture_output: bool = True, check: bool = True, input: Optional[bytes] = None) -> Tuple[int, str, str]:
    """Run subprocess command and return (rc, stdout, stderr)."""
    proc = subprocess.run(cmd, capture_output=capture_output, input=input)
    rc = proc.returncode
    out = proc.stdout.decode("utf-8") if proc.stdout else ""
    err = proc.stderr.decode("utf-8") if proc.stderr else ""
    if check and rc != 0:
        raise CommandError(cmd=cmd, rc=rc, stderr=err)
    return rc, out, err


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def write_json(path: Path, obj, *, indent: int = 2):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(obj, f, indent=indent, ensure_ascii=False)


def ensure_tool(name: str) -> bool:
    return shutil.which(name) is not None
