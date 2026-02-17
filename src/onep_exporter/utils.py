import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import Tuple, Optional


class CommandError(RuntimeError):
    pass


def run_cmd(cmd: list[str], capture_output: bool = True, check: bool = True, input: Optional[bytes] = None) -> Tuple[int, str, str]:
    """Run subprocess command and return (rc, stdout, stderr)."""
    proc = subprocess.run(cmd, capture_output=capture_output, input=input)
    rc = proc.returncode
    out = proc.stdout.decode("utf-8") if proc.stdout else ""
    err = proc.stderr.decode("utf-8") if proc.stderr else ""
    if check and rc != 0:
        raise CommandError(f"Command {cmd!r} failed: {rc}: {err}")
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
