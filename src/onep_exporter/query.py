"""Query and search operations for exported 1Password backup data."""

import glob
import json
import tarfile
from pathlib import Path
from typing import List, Optional, Union

from .utils import check_age_version


def _is_age_archive(p: Path) -> bool:
    return p.is_file() and (
        p.suffix == ".age"
        or p.name.endswith(".tar.age")
        or p.name.endswith(".tar.gz.age")
    )


def _is_plain_tar_archive(p: Path) -> bool:
    return p.is_file() and (
        p.suffix in (".tar", ".tgz", ".gz")
        or p.name.endswith(".tar.gz")
    )


def _decrypt_age_archive(p: Path) -> bytes:
    """Decrypt an age-encrypted archive at *p* and return the raw tar bytes."""
    check_age_version()
    import os
    import subprocess

    from .config import load_config
    from .encryption import resolve_decrypt_credentials

    try:
        cfg = load_config()
    except Exception as exc:
        import sys

        print(f"warning: failed to load config: {exc}", file=sys.stderr)
        cfg = {}
    ids, env_pass = resolve_decrypt_credentials(cfg)

    cmd = ["age", "--decrypt", "-o", "-"]
    identity_bytes: Optional[bytes] = None
    if isinstance(ids, tuple) and ids[0] == "stdin":
        cmd.extend(["-i", "-"])
        identity_bytes = ids[1].encode()
    elif ids:
        for entry in ids.split(os.pathsep):
            if entry:
                cmd.extend(["-i", entry])
    cmd.append(str(p))

    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError:
        raise RuntimeError("age not found for decryption")

    # supply identity or passphrase via communicate(input=...)
    input_bytes: Optional[bytes] = None
    if identity_bytes is not None:
        input_bytes = identity_bytes
    elif env_pass is not None:
        try:
            input_bytes = env_pass.encode() + b"\n"
        except Exception:
            input_bytes = None

    out_bytes, err_bytes = proc.communicate(input=input_bytes)
    rc = proc.returncode
    if rc != 0:
        err = err_bytes.decode(errors="ignore").strip()
        if "identities are required" in err:
            err += (
                "; ensure you have an age identity available "
                "(e.g. run `onep-exporter init` to store one in "
                "1Password, or use --age-identity)"
            )
        raise RuntimeError(f"age decryption failed: {err or rc}")
    if not out_bytes:
        raise RuntimeError(
            f"age decryption produced no output "
            f"(rc=0, stderr={err_bytes!r})"
        )
    return out_bytes


def _iter_exported_items(path: Union[str, Path]):
    """Yield all item dicts from exported backup data at *path*.

    *path* may be a directory containing per-vault JSON exports (as produced by
    :func:`run_backup`), a plain tar/tar.gz archive, or an age-encrypted
    archive.  Each yielded value is a ``dict`` parsed from a vault JSON file.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"path not found: {p}")

    def _items_from_tarfile(tf):
        for member in tf.getmembers():
            name = member.name
            if not name.endswith(".json") or name.endswith("manifest.json"):
                continue
            fobj = tf.extractfile(member)
            if not fobj:
                continue
            try:
                data = json.load(fobj)
            except Exception:
                continue
            if isinstance(data, list):
                yield from data

    # age-wrapped archive
    if _is_age_archive(p):
        import io

        out_bytes = _decrypt_age_archive(p)
        try:
            with io.BytesIO(out_bytes) as bio:
                with tarfile.open(fileobj=bio, mode="r:*") as tf:
                    yield from _items_from_tarfile(tf)
        except Exception as e:
            raise RuntimeError(f"failed to read archive {p}: {e}")
        return

    # plain tar archive
    if _is_plain_tar_archive(p):
        try:
            with tarfile.open(p, "r:*") as tf:
                yield from _items_from_tarfile(tf)
        except Exception as e:
            raise RuntimeError(f"failed to read archive {p}: {e}")
        return

    # directory tree
    for f in p.rglob("*.json"):
        if f.name == "manifest.json":
            continue
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        if isinstance(data, list):
            yield from data


def read_attachment_bytes(
    path: Union[str, Path], file_id: str, name: str
) -> Optional[bytes]:
    """Return the raw bytes of a file attachment from exported backup data.

    *path* accepts the same directory/tar/age-encrypted forms as
    :func:`_iter_exported_items`. *file_id* and *name* identify the
    attachment as recorded on the item's ``files``/``documents`` metadata
    (the attachment is stored on disk/in the archive as
    ``attachments/{file_id}-{name}``). Returns ``None`` if no matching
    attachment is found.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"path not found: {p}")

    suffix = f"attachments/{file_id}-{name}"

    def _find_in_tar(tf) -> Optional[bytes]:
        for member in tf.getmembers():
            if member.isfile() and member.name.endswith(suffix):
                fobj = tf.extractfile(member)
                if fobj:
                    return fobj.read()
        return None

    if _is_age_archive(p):
        import io

        out_bytes = _decrypt_age_archive(p)
        with io.BytesIO(out_bytes) as bio:
            with tarfile.open(fileobj=bio, mode="r:*") as tf:
                return _find_in_tar(tf)

    if _is_plain_tar_archive(p):
        with tarfile.open(p, "r:*") as tf:
            return _find_in_tar(tf)

    # directory tree
    direct = p / "attachments" / f"{file_id}-{name}"
    if direct.is_file():
        return direct.read_bytes()
    for f in p.glob(f"**/attachments/{glob.escape(file_id)}-{glob.escape(name)}"):
        if f.is_file():
            return f.read_bytes()
    return None


def query_list_titles(
    path: Union[str, Path], pattern: str
) -> List[str]:
    """Return item titles matching *pattern* in exported JSON under *path*.

    *path* may be a directory containing per-vault JSON exports, a tar
    archive, or an age-encrypted archive.
    """
    import re

    regex = re.compile(pattern)
    return [
        item["title"]
        for item in _iter_exported_items(path)
        if item.get("title") and regex.search(item["title"])
    ]


def query_get_item(
    path: Union[str, Path], item_ref: str
) -> dict:
    """Return the full item dict for a single item identified by *item_ref*.

    *item_ref* is matched first against each item's ``title`` (exact,
    case-sensitive) and then against its ``id``.  If no items match a
    :class:`KeyError` is raised.  If more than one item shares the same title
    a :class:`ValueError` is raised.
    """
    found = [
        item
        for item in _iter_exported_items(path)
        if item.get("title") == item_ref or item.get("id") == item_ref
    ]
    if not found:
        raise KeyError(f"no item found matching {item_ref!r}")
    if len(found) > 1:
        labels = [m.get("title", m.get("id", "?")) for m in found]
        raise ValueError(
            f"multiple items match {item_ref!r}: {labels}; "
            "use the item id to disambiguate"
        )
    return found[0]
