import json
import tarfile
import tempfile
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Union

from .utils import run_cmd, write_json, sha256_file, ensure_tool, CommandError
from .templates import item_to_md, vault_to_md


class OpExporter:
    def __init__(self):
        if not ensure_tool("op"):
            raise RuntimeError(
                "`op` (1Password CLI) not found in PATH — please install and sign in first")

    def list_vaults(self) -> List[dict]:
        _, out, _ = run_cmd(["op", "vault", "list", "--format=json"])
        return json.loads(out)

    def list_items(self, vault_id: str) -> List[dict]:
        _, out, _ = run_cmd(
            ["op", "item", "list", "--vault", vault_id, "--format=json"])
        return json.loads(out)

    def get_item(self, item_id: str) -> dict:
        _, out, _ = run_cmd(["op", "item", "get", item_id, "--format=json"])
        return json.loads(out)

    def download_document(self, doc_id: str, dest: Path) -> None:
        # Try `op document get <id> --output <file>` (works for document/file objects)
        try:
            run_cmd(["op", "document", "get", doc_id, "--output", str(dest)])
        except CommandError as e:
            raise RuntimeError(f"failed to download document {doc_id}: {e}")

    def get_item_field_value(self, item_ref: str, field_name: Optional[str] = None) -> Optional[str]:
        """Return a field value from a 1Password item JSON (best-effort).

        item_ref may be an item id or title (passed to `op item get`).
        If field_name is provided the field with matching `name` or `label` is returned.
        Otherwise the first password-like field is returned.
        """
        item = self.get_item(item_ref)
        fields = item.get("fields") or []
        # prefer an explicit field name
        if field_name:
            for f in fields:
                if (f.get("name") == field_name) or (f.get("label") == field_name):
                    val = f.get("value")
                    if isinstance(val, str):
                        return val
        # fallback: first password-like field
        for f in fields:
            if f.get("type") == "password" or "password" in (f.get("name") or "").lower() or "password" in (f.get("label") or "").lower():
                val = f.get("value")
                if isinstance(val, str):
                    return val
        # no match
        return None

    def find_item_by_title(self, title: str, vault: Optional[str] = None) -> Optional[dict]:
        """Return the item JSON for a given title if it exists (optionally restricted to a vault).

        Uses `op item get <title>` (which resolves by title or id). If the returned item is in a
        different vault than requested, treat as not found.
        """
        try:
            _, out, _ = run_cmd(["op", "item", "get", title, "--format=json"])
            item = json.loads(out)
            if vault:
                v = item.get("vault") or {}
                if vault != v.get("id") and vault != v.get("name"):
                    return None
            return item
        except CommandError:
            return None

    def store_passphrase_in_1password(self, title: str, field_name: str, passphrase: str, vault: Optional[str] = None) -> dict:
        """Create a Secure Note item in 1Password **only if it does not already exist**.

        The secret is stored as a CONCEALED custom field so it stays hidden in the
        1Password UI.  The JSON template is piped via stdin (``-`` positional arg)
        because ``op item create`` interprets bare positional args as assignment
        statements, not JSON.

        Returns the existing item JSON if present, or the created item JSON.

        See https://developer.1password.com/docs/cli/item-create/#with-an-item-json-template
        """
        existing = self.find_item_by_title(title, vault=vault)
        if existing:
            # do not overwrite existing item
            return existing

        # Build a JSON template.
        # • We omit "category" from the JSON and pass it via --category flag
        #   instead, because `op` expects an enum identifier (e.g. SECURE_NOTE)
        #   in JSON but the display name ("Secure Note") via the flag.
        # • category "Secure Note" — avoids built-in required fields that other
        #   categories (e.g. Password) enforce, which causes "cannot add a field
        #   with no value" errors.
        # • field type CONCEALED — keeps the value hidden in 1Password.
        payload = {
            "title": title,
            "fields": [
                {
                    "id": field_name,
                    "label": field_name,
                    "type": "CONCEALED",
                    "value": passphrase,
                }
            ],
        }

        cmd = ["op", "item", "create", "--category", "Secure Note",
               "--format", "json"]
        if vault:
            cmd.extend(["--vault", vault])
        # `-` tells op to read the item template from stdin
        cmd.append("-")

        _, out, _ = run_cmd(cmd, input=json.dumps(payload).encode())
        return json.loads(out)

    def ensure_secrets_item(self, title: str, vault: Optional[str] = None) -> dict:
        """Ensure a Secure Note item exists in 1Password for storing backup secrets.

        Creates an empty Secure Note if one with the given title doesn't exist.
        Returns the item JSON (existing or newly created).
        """
        existing = self.find_item_by_title(title, vault=vault)
        if existing:
            return existing
        payload = {"title": title, "fields": []}
        cmd = ["op", "item", "create", "--category", "Secure Note",
               "--format", "json"]
        if vault:
            cmd.extend(["--vault", vault])
        cmd.append("-")
        _, out, _ = run_cmd(cmd, input=json.dumps(payload).encode())
        return json.loads(out)

    def upsert_item_field(self, item_id: str, field_label: str, value: str,
                          field_type: str = "CONCEALED") -> dict:
        """Add or update a field on an existing 1Password item.

        Uses ``op item edit`` with assignment syntax.
        field_type should be 'CONCEALED' or 'TEXT'.
        Returns the updated item JSON.
        """
        type_str = "concealed" if field_type == "CONCEALED" else "text"
        assignment = f"{field_label}[type={type_str}]={value}"
        cmd = ["op", "item", "edit", item_id, assignment, "--format", "json"]
        _, out, _ = run_cmd(cmd)
        return json.loads(out)

    def signin_interactive(self, account: Optional[str] = None) -> str:
        """Run `op signin --raw` to obtain a session token (user will be prompted; Touch ID may be used by the 1Password app).

        Returns the token string printed by `op`.
        """
        cmd = ["op", "signin", "--raw"]
        if account:
            cmd.insert(2, account)
        _, out, _ = run_cmd(cmd)
        token = out.strip()
        print("op session token obtained. Set OP_SESSION_<account> in your shell to use it for automation.")
        print("(example) export OP_SESSION_your-account=", token)
        return token


def run_backup(*, output_base: Union[str, Path] = "backups", formats=("json", "md"), encrypt: str = "none", download_attachments: bool = True, quiet: bool = False, age_pass_source: str = "1password", age_pass_item: Optional[str] = None, age_pass_field: str = "password", age_recipients: str = "", age_use_yubikey: bool = False, sync_passphrase_from_1password: bool = False, age_keychain_service: str = "1p-exporter", age_keychain_username: str = "backup") -> Path:
    output_base = Path(output_base)
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

    # when encrypting we don't want persistent plaintext files left behind,
    # so create a temporary work directory that will be removed after the
    # archive is built.  If no encryption is requested we keep the timestamped
    # directory under output_base so users can examine files.
    if encrypt != "none":
        import tempfile, shutil
        work_dir = Path(tempfile.mkdtemp())
    else:
        work_dir = output_base / ts
        work_dir.mkdir(parents=True, exist_ok=True)
    outdir = work_dir

    exporter = OpExporter()

    vaults = exporter.list_vaults()
    manifest = {
        "timestamp": ts,
        "vaults": [],
        "files": [],
    }

    # list of (relative_name, bytes) for files we generate in memory
    # and later inject into the tar instead of writing to disk
    memory_files: list[tuple[str, bytes]] = []

    attachments_dir = outdir / "attachments"
    if download_attachments:
        attachments_dir.mkdir(parents=True, exist_ok=True)

    for v in vaults:
        vault_id = v.get("id")
        if not vault_id:
            print(f"  warning: skipping vault with missing id: {v}")
            continue
        vault_name = v.get("name") or vault_id
        if not quiet:
            print(f"Exporting vault: {vault_name} ({vault_id})")

        items_summary = exporter.list_items(vault_id)
        items_full = []
        for s in items_summary:
            item_id = s.get("id")
            if not item_id:
                print(f"    warning: skipping item with missing id: {s}")
                continue
            try:
                item = exporter.get_item(item_id)
            except Exception as e:
                print(f"  warning: failed to fetch item {item_id}: {e}")
                continue
            # download attachments if present
            files_meta = item.get("files") or item.get("documents") or []
            for fmeta in files_meta:
                fid = fmeta.get("id") or fmeta.get("file_id")
                name = fmeta.get("name") or fmeta.get("filename")
                if fid and name and download_attachments:
                    dest = attachments_dir / f"{fid}-{name}"
                    try:
                        exporter.download_document(fid, dest)
                    except Exception as e:
                        print(
                            f"    warning: could not download attachment {name}: {e}")
                    else:
                        manifest["files"].append(
                            {"path": str(dest.relative_to(outdir)), "sha256": sha256_file(dest)})
            items_full.append(item)

        if encrypt == "none":
            vault_filename = outdir / f"vault-{vault_id}.json"
            write_json(vault_filename, items_full)
            vault_sha = sha256_file(vault_filename)
        else:
            # create JSON bytes and keep in memory rather than disk
            import json as _json, hashlib as _hashlib
            vault_data = _json.dumps(items_full, indent=2, ensure_ascii=False).encode("utf-8")
            vault_sha = _hashlib.sha256(vault_data).hexdigest()
            memory_files.append((f"vault-{vault_id}.json", vault_data))
        manifest["vaults"].append({
            "id": vault_id,
            "name": vault_name,
            "items": len(items_full),
            "file": f"vault-{vault_id}.json",
            "sha256": vault_sha,
        })

        if "md" in formats:
            md_name = f"vault-{vault_id}.md"
            md_text = vault_to_md(vault_name, items_full)
            md_bytes = md_text.encode("utf-8")
            # if encryption is disabled, write markdown to disk for easier access
            if encrypt == "none":
                md_path = outdir / md_name
                md_path.write_text(md_text, encoding="utf-8")
                manifest["files"].append(
                    {"path": md_name, "sha256": sha256_file(md_path)})
            else:
                # keep in memory and compute hash
                import hashlib
                sha = hashlib.sha256(md_bytes).hexdigest()
                manifest["files"].append({"path": md_name, "sha256": sha})
                memory_files.append((md_name, md_bytes))

    # write manifest
    manifest_path = outdir / "manifest.json"
    write_json(manifest_path, manifest)
    manifest_hash = sha256_file(manifest_path)
    manifest["manifest_sha256"] = manifest_hash
    write_json(manifest_path, manifest)  # update with hash

    # helper class used when streaming tar output through an encryptor
    class _HashingWriter:
        def __init__(self, sink):
            # sink should be a writable file-like object (e.g. subprocess.stdin)
            self.sink = sink
            import hashlib
            self.hasher = hashlib.sha256()

        def write(self, data: bytes) -> int:
            # update hash then forward to underlying sink
            self.hasher.update(data)
            return self.sink.write(data)

        def flush(self):
            try:
                return self.sink.flush()
            except Exception:
                pass

        def close(self):
            try:
                return self.sink.close()
            except Exception:
                pass

    # create archive path (used for naming even if we stream)
    archive_path = output_base / f"1p-backup-{ts}.tar.gz"

    # write either to disk or stream directly into encryption tool
    if encrypt == "none":
        with tarfile.open(archive_path, "w:gz") as tar:
            tar.add(outdir, arcname=ts)
        archive_sha = sha256_file(archive_path)
        if not quiet:
            print(f"Created archive: {archive_path} (sha256={archive_sha})")
        return archive_path

    # At this point we know encryption is requested.
    # compute passphrase/recipients for the requested backend as before
    if encrypt == "gpg":
        if not ensure_tool("gpg"):
            raise RuntimeError("gpg not found for encryption")
        import os
        import getpass

        passphrase = os.environ.get("BACKUP_PASSPHRASE")
        if not passphrase:
            passphrase = getpass.getpass(
                "GPG passphrase for symmetric encryption: ")
        out_enc = str(archive_path) + ".gpg"
        # build command using loopback pinentry so we can pass passphrase as arg
        cmd = ["gpg", "--symmetric", "--cipher-algo", "AES256", "--batch",
               "--pinentry-mode", "loopback", "--passphrase", passphrase,
               "--output", out_enc]
    elif encrypt == "age":
        if not ensure_tool("age"):
            raise RuntimeError("age not found for encryption")
        import os
        import getpass

        # gather stored passphrases (for consistency checks / optional sync)
        passphrase = None
        stored_values = {}

        # 1Password (only if an item reference is available)
        if age_pass_item:
            try:
                v = exporter.get_item_field_value(
                    age_pass_item, age_pass_field)
            except Exception:
                v = None
            if v:
                stored_values["1password"] = v

        # keychain (platform/keyring may raise)
        try:
            kc = _get_passphrase_from_keychain(
                age_keychain_service, age_keychain_username)
        except Exception:
            kc = None
        if kc:
            stored_values["keychain"] = kc

        # environment variable
        env_val = os.environ.get("BACKUP_PASSPHRASE")
        if env_val:
            stored_values["env"] = env_val

        # If requested, sync authoritative value from 1Password into other stores.
        if sync_passphrase_from_1password:
            # ensure we can read 1Password value first
            auth = stored_values.get("1password")
            if not auth:
                if age_pass_item:
                    auth = exporter.get_item_field_value(
                        age_pass_item, age_pass_field)
                if not auth:
                    raise RuntimeError(
                        "--sync-passphrase-from-1password set but could not read passphrase from 1Password")

            # sync to keychain if missing or different
            try:
                if stored_values.get("keychain") != auth:
                    _store_passphrase_in_keychain(
                        age_keychain_service, age_keychain_username, auth)
                    stored_values["keychain"] = auth
            except Exception as e:
                raise RuntimeError(
                    f"failed to store passphrase in keychain during sync: {e}")

            # populate environment for this run (cannot persist across sessions)
            if stored_values.get("env") != auth:
                os.environ["BACKUP_PASSPHRASE"] = auth
                stored_values["env"] = auth

        # If the passphrase exists in more than one place, ensure they match
        if len(stored_values) > 1:
            unique_vals = set(stored_values.values())
            if len(unique_vals) > 1:
                raise RuntimeError(
                    f"passphrase mismatch between configured stores: {', '.join(sorted(stored_values.keys()))}")

        # determine passphrase source (respect user's configured source / CLI choice)
        if age_pass_source == "env":
            passphrase = os.environ.get("BACKUP_PASSPHRASE")
        elif age_pass_source == "prompt":
            passphrase = getpass.getpass("Age passphrase for encryption: ")
        elif age_pass_source == "1password":
            if not age_pass_item:
                raise RuntimeError(
                    "--age-pass-item is required when --age-pass-source=1password")
            # read passphrase from the user's 1Password entry
            passphrase = exporter.get_item_field_value(
                age_pass_item, age_pass_field)
            if not passphrase:
                raise RuntimeError(
                    "could not extract passphrase from the specified 1Password item/field")
        elif age_pass_source == "keychain":
            # read from macOS Keychain (keyring if available, else `security`)
            passphrase = None
            try:
                passphrase = _get_passphrase_from_keychain(
                    age_keychain_service, age_keychain_username)
            except Exception as e:
                raise RuntimeError(
                    f"failed to read passphrase from keychain: {e}")

        recipients = [r.strip()
                      for r in (age_recipients or "").split(",") if r.strip()]
        if age_use_yubikey and not recipients:
            # user asked for YubiKey support but provided no explicit recipient — warn and continue with passphrase only
            print("warning: --age-use-yubikey set but no explicit recipient provided; ensure your yubikey recipient is added via --age-recipients if you want hardware unlock")

        if not passphrase and not recipients:
            raise RuntimeError(
                "age encryption requires at least a passphrase or one recipient")

        out_enc = str(archive_path) + ".age"
        cmd = ["age", "-o", out_enc]
        for r in recipients:
            cmd.extend(["-r", r])
        if passphrase:
            # include passphrase recipient; age supports --passphrase
            cmd.append("--passphrase")
    else:
        # This branch should not be reachable because we handled 'none' earlier
        raise RuntimeError(f"unsupported encrypt mode: {encrypt}")

    # now stream the tarball through the encryptor subprocess
    import subprocess, io, shutil
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE)
    writer = _HashingWriter(proc.stdin)
    with tarfile.open(fileobj=writer, mode="w|gz") as tar:
        # add the on-disk directory first
        tar.add(outdir, arcname=ts)
        # inject any in-memory files (e.g. markdown when encrypting)
        for name, data in memory_files:
            # ensure stored with correct relative path under timestamp
            ti = tarfile.TarInfo(name=f"{ts}/{name}")
            ti.size = len(data)
            tar.addfile(ti, io.BytesIO(data))
    writer.flush()
    proc.stdin.close()
    rc = proc.wait()
    if rc != 0:
        raise CommandError(cmd=cmd, rc=rc, stderr="encryption failed")
    archive_sha = writer.hasher.hexdigest()
    # clean up temporary directory when encryption was used
    if encrypt != "none":
        try:
            shutil.rmtree(outdir)
        except Exception:
            pass
    if not quiet:
        # show sha of plaintext archive even though it was never written to disk
        print(f"Streamed archive -> {out_enc} (sha256={archive_sha})")
    return Path(out_enc)


def _get_passphrase_from_keychain(service: str, username: str) -> Optional[str]:
    """Attempt to get a password from macOS keychain (or platform keyring if available).

    On macOS the `security` CLI is used as a fallback which will prompt the user (Touch ID) if the
    item requires confirmation.
    """
    # try python-keyring first (if installed)
    try:
        import keyring  # pyright: ignore[reportMissingImports]

        val = keyring.get_password(service, username)
        if val:
            return val
    except Exception:
        # keyring not available or failed — fall back to `security` on darwin
        pass

    import sys
    if sys.platform != "darwin":
        raise RuntimeError(
            "keychain access supported only on macOS when keyring is not available")

    # use `security find-generic-password -s <service> -a <account> -w`
    _, out, _ = run_cmd(["security", "find-generic-password",
                        "-s", service, "-a", username, "-w"])
    return out.strip()


def _store_passphrase_in_keychain(service: str, username: str, passphrase: str) -> None:
    # prefer keyring if installed
    try:
        import keyring  # pyright: ignore[reportMissingImports]

        keyring.set_password(service, username, passphrase)
        return
    except Exception:
        pass

    import sys
    if sys.platform != "darwin":
        raise RuntimeError(
            "keychain storage supported only on macOS when keyring is not available")

    # use `security add-generic-password -s <service> -a <account> -w <password> -U` to update or add
    run_cmd(["security", "add-generic-password", "-s",
            service, "-a", username, "-w", passphrase, "-U"])


def _item_field_value(item: dict, field_name: str) -> Optional[str]:
    """Extract a field value from a 1Password item dict by label or name."""
    for f in (item.get("fields") or []):
        if f.get("label") == field_name or f.get("name") == field_name:
            val = f.get("value")
            if isinstance(val, str) and val:
                return val
    return None


def _generate_age_keypair_and_store(exporter: 'OpExporter', item_id: str) -> Optional[str]:
    """Generate an age keypair, store private key in the given 1Password item.

    Returns the public recipient string on success, or None on failure.
    """
    if not ensure_tool("age-keygen"):
        print("warning: 'age-keygen' not available; cannot generate age keypair")
        return None

    try:
        _, out, _ = run_cmd(["age-keygen"])
    except Exception as e:
        print(f"warning: failed to generate age keypair: {e}")
        return None

    import re
    private_key = None
    pub = None

    # PEM-like block
    m_block = re.search(
        r"(-----BEGIN AGE (?:PRIVATE KEY|KEY FILE|KEY-FILE)-----.*?-----END AGE (?:PRIVATE KEY|KEY FILE|KEY-FILE)-----)", out, re.S)
    if m_block:
        private_key = m_block.group(1).strip()

    # AGE-SECRET-KEY token
    if not private_key:
        m_secret = re.search(r"(AGE-SECRET-KEY-[0-9A-Za-z\-_=]+)", out)
        if m_secret:
            private_key = m_secret.group(1).strip()

    # comment line fallback
    if not private_key:
        m_line = re.search(r"(?m)^\s*#?\s*(?:secret|secret key):\s*(\S+)", out)
        if m_line:
            private_key = m_line.group(1).strip()

    # public key
    m_pub = re.search(r"(?m)^\s*#?\s*public key:\s*(age1[0-9a-z]+)", out)
    if m_pub:
        pub = m_pub.group(1)
    else:
        m_any = re.search(r"(age1[0-9a-z]+)", out)
        if m_any:
            pub = m_any.group(1)

    if not private_key or not pub:
        print("warning: could not parse generated age keypair output")
        return None

    # Store private key in 1Password item
    try:
        exporter.upsert_item_field(item_id, "age_private_key", private_key)
    except Exception as e:
        print(f"warning: failed to store private key in 1Password: {e}")

    print(f"Generated age recipient: {pub}")
    return pub


def init_setup(*, passphrase: Optional[str] = None, generate: bool = False, store_in_1password: Optional[str] = None, onepassword_vault: Optional[str] = None, store_in_keychain: bool = False, keychain_service: str = "1p-exporter", keychain_username: str = "backup", onepassword_field: str = "password") -> str:
    """Create or store an age passphrase according to provided options.

    Returns the plaintext passphrase (also stores it as requested).
    """
    import secrets
    import getpass

    if generate and passphrase:
        raise RuntimeError("cannot specify --generate and --passphrase")
    if not passphrase:
        if generate:
            passphrase = secrets.token_urlsafe(32)
        else:
            passphrase = getpass.getpass("Passphrase to store: ")

    exporter = OpExporter()

    if store_in_1password:
        try:
            res = exporter.store_passphrase_in_1password(
                store_in_1password, onepassword_field, passphrase, vault=onepassword_vault)
            if res.get("id"):
                print(
                    f"passphrase stored or already exists in 1Password item: {res.get('id')}")
        except Exception as e:
            print(f"failed to store passphrase in 1Password: {e}")

    if store_in_keychain:
        try:
            _store_passphrase_in_keychain(
                keychain_service, keychain_username, passphrase)
            print(
                f"stored passphrase in macOS Keychain: service={keychain_service} account={keychain_username}")
        except Exception as e:
            print(f"failed to store passphrase in keychain: {e}")

    print("Passphrase (keep this safe):", passphrase)
    return passphrase


# Configuration persistence -------------------------------------------------
def _config_file_path() -> Path:
    """Return path to config file (respect ONEP_EXPORTER_CONFIG or XDG_CONFIG_HOME).
    Uses `~/.config/1p-exporter/config.json` by default; legacy `onep-exporter` path is still supported when loading."""
    import os
    cfg = os.environ.get("ONEP_EXPORTER_CONFIG")
    if cfg:
        return Path(cfg)
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / "1p-exporter" / "config.json"


def save_config(data: dict) -> Path:
    """Save configuration (JSON) to the configured config file location and restrict file perms."""
    p = _config_file_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    try:
        p.chmod(0o600)
    except Exception:
        pass
    return p


def load_config() -> dict:
    p = _config_file_path()
    if p.exists():
        try:
            with p.open("r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    # fallback to legacy config path (`onep-exporter`) for backward compatibility
    legacy = p.parent.parent / "onep-exporter" / p.name
    if legacy.exists():
        try:
            with legacy.open("r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def configure_interactive() -> dict:
    """Interactive setup helper that prompts for common options and persists them.

    When age encryption is chosen, all secrets (private key, passphrase) are stored
    in a single 1Password Secure Note item.  Existing secrets are detected and the
    user is offered the choice to reuse or overwrite them.
    """
    import getpass
    import os
    import secrets

    print("Interactive setup — configure defaults for 1p-exporter backups")
    cfg = load_config()

    def prompt(prompt_text: str, default: Optional[str] = None) -> str:
        if default:
            resp = input(f"{prompt_text} [{default}]: ")
            return resp.strip() or default
        return input(f"{prompt_text}: ").strip()

    output = prompt("Default backup directory", cfg.get(
        "output_base", str(Path.home() / "1p-backups")))
    formats = prompt("Default formats (comma-separated)",
                     ",".join(cfg.get("formats", ["json", "md"])))
    encrypt = prompt("Default encryption (none/gpg/age)",
                     cfg.get("encrypt", "age"))
    download_attachments = prompt("Download attachments by default? (y/n)",
                                  "y" if cfg.get("download_attachments", True) else "n")

    age_cfg = cfg.get("age", {})
    age_pass_source = None
    age_pass_item = None
    age_pass_field = "passphrase"
    age_keychain_service = age_cfg.get("keychain_service", "1p-exporter")
    age_keychain_username = age_cfg.get("keychain_username", "backup")
    age_recipients = age_cfg.get("recipients", "")
    age_use_yubikey = age_cfg.get("use_yubikey", False)
    op_vault = None

    if encrypt == "age":
        import sys
        is_macos = sys.platform == "darwin"

        # --- single 1Password item for all secrets ---
        default_title = age_cfg.get(
            "pass_item") or f"1p-exporter backup - {getpass.getuser()}"
        op_item_title = prompt(
            "1Password item title for backup secrets", default_title)
        op_vault = prompt("1Password vault (optional)",
                          age_cfg.get("onepassword_vault") or None)
        age_pass_item = op_item_title

        # passphrase source (for backup-time retrieval)
        pass_source_choices = "env/prompt/1password/keychain" if is_macos else "env/prompt/1password"
        default_pass_source = age_cfg.get("pass_source", "1password")
        age_pass_source = prompt(
            f"age passphrase source ({pass_source_choices})", default_pass_source)
        if is_macos and age_pass_source == "keychain":
            age_keychain_service = prompt(
                "Keychain service name", age_keychain_service)
            age_keychain_username = prompt(
                "Keychain account name", age_keychain_username)

        # --- ensure the 1Password item exists and inspect existing fields ---
        exporter = OpExporter()
        item = exporter.ensure_secrets_item(
            op_item_title, vault=op_vault or None)
        item_id = item.get("id")

        existing_private_key = _item_field_value(item, "age_private_key")
        existing_passphrase = _item_field_value(item, "passphrase")
        existing_recipients = _item_field_value(item, "age_recipients")

        # --- age keypair ---
        generated_pub = None
        if existing_private_key:
            reuse = prompt(
                "Existing age private key found in 1Password. Reuse? (y/n)", "y")
            if not reuse.lower().startswith("y"):
                generated_pub = _generate_age_keypair_and_store(
                    exporter, item_id)
        else:
            gen_key = prompt("Generate a new age keypair? (y/n)", "y")
            if gen_key.lower().startswith("y"):
                generated_pub = _generate_age_keypair_and_store(
                    exporter, item_id)

        # --- recipients ---
        default_recipients = existing_recipients or age_recipients or ""
        if generated_pub:
            parts = [r.strip()
                     for r in default_recipients.split(",") if r.strip()]
            if generated_pub not in parts:
                parts.append(generated_pub)
            default_recipients = ",".join(parts)

        age_recipients = prompt(
            "Age recipients (comma-separated public recipients)",
            default_recipients or None)
        # store recipients in 1P item
        if age_recipients:
            try:
                exporter.upsert_item_field(
                    item_id, "age_recipients", age_recipients, field_type="TEXT")
            except Exception as e:
                print(f"warning: failed to store recipients in 1Password: {e}")

        yub = prompt("Include YubiKey recipient by default? (y/n)",
                     "y" if age_use_yubikey else "n")
        age_use_yubikey = yub.lower().startswith("y")

        # --- passphrase ---
        if existing_passphrase:
            reuse_pp = prompt(
                "Existing passphrase found in 1Password. Reuse? (y/n)", "y")
            if not reuse_pp.lower().startswith("y"):
                passphrase = secrets.token_urlsafe(32)
                try:
                    exporter.upsert_item_field(
                        item_id, "passphrase", passphrase)
                except Exception as e:
                    print(
                        f"warning: failed to store passphrase in 1Password: {e}")
                print(f"New passphrase stored in 1Password item "
                      f"'{op_item_title}', field 'passphrase'.")
                print(f"To export it safely, use:  "
                      f"op item get '{op_item_title}' --field passphrase")
        else:
            gen_pp = prompt("Generate a new passphrase? (y/n)", "y")
            if gen_pp.lower().startswith("y"):
                passphrase = secrets.token_urlsafe(32)
            else:
                passphrase = getpass.getpass("Enter passphrase to store: ")
            try:
                exporter.upsert_item_field(item_id, "passphrase", passphrase)
            except Exception as e:
                print(
                    f"warning: failed to store passphrase in 1Password: {e}")
            print(f"Passphrase stored in 1Password item "
                  f"'{op_item_title}', field 'passphrase'.")
            print(f"To export it safely, use:  "
                  f"op item get '{op_item_title}' --field passphrase")

    # assemble global config
    new_cfg = {
        "output_base": output,
        "formats": [f.strip() for f in formats.split(",") if f.strip()],
        "encrypt": encrypt,
        "download_attachments": download_attachments.lower().startswith("y"),
        "age": {
            "pass_source": age_pass_source,
            "pass_item": age_pass_item,
            "pass_field": age_pass_field,
            "recipients": age_recipients,
            "use_yubikey": bool(age_use_yubikey),
            "keychain_service": age_keychain_service,
            "keychain_username": age_keychain_username,
            "onepassword_vault": op_vault or None,
        },
    }

    save_config(new_cfg)
    print(f"Configuration saved to {_config_file_path()}")
    return new_cfg


def verify_manifest(manifest_path: str) -> bool:
    p = Path(manifest_path)
    if not p.exists():
        print(f"manifest not found: {manifest_path}")
        return False
    data = json.loads(p.read_text(encoding="utf-8"))
    base = p.parent
    ok = True
    for f in data.get("files", []):
        path = base / f["path"]
        if not path.exists():
            print(f"missing file: {path}")
            ok = False
            continue
        sha = sha256_file(path)
        if sha != f.get("sha256"):
            print(
                f"sha mismatch: {path} (expected {f.get('sha256')}, got {sha})")
            ok = False
    print("manifest verification:", "OK" if ok else "FAILED")
    return ok


def doctor() -> bool:
    """Perform sanity checks on environment and configuration.

    Prints a grouped, colorized summary of checks and returns True when all
    critical checks pass. Colors are emitted only when stdout is a TTY.
    """
    import os
    import sys

    OK_ICON = "✅"
    FAIL_ICON = "❌"
    WARN_ICON = "⚠️"
    INFO_ICON = "ℹ️"
    HEADER_ICON = "🔎"

    # enable colors only when stdout is a TTY and NO_COLOR is not set
    use_color = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

    def _color(text: str, code: str) -> str:
        if not use_color:
            return text
        return f"\x1b[{code}m{text}\x1b[0m"

    def _ok(msg: str):
        icon = _color(OK_ICON, "32")
        print(f" {icon}  {_color(msg, '0')}")

    def _err(msg: str):
        icon = _color(FAIL_ICON, "31")
        print(f" {icon}  {_color(msg, '0')}")

    def _warn(msg: str):
        icon = _color(WARN_ICON, "33")
        print(f" {icon}  {_color(msg, '0')}")

    ok = True

    # header
    print()
    title = f"{HEADER_ICON}  1p-exporter doctor — environment & configuration checks"
    print(_color(title, "1;36"))
    print(_color("─" * 52, "36"))

    # Environment checks
    print(_color("\nEnvironment:", "1;34"))
    if not ensure_tool("op"):
        _err("`op` (1Password CLI) not found in PATH")
        ok = False
    else:
        _ok("`op` available")

    # Tools availability (informational)
    print(_color("\nTools:", "1;34"))

    def _suggest_install_cmd(tool: str) -> str | None:
        # map tool -> package name
        pkg_map = {
            "age": "age",
            "age-keygen": "age",
            "gpg": "gnupg",
            "security": None,
        }
        pkg = pkg_map.get(tool, tool)

        # macOS -> Homebrew or Xcode for `security`
        if sys.platform == "darwin":
            if ensure_tool("brew") and pkg:
                return f"brew install {pkg}"
            if tool == "security":
                return "macOS: install Xcode Command Line Tools: `xcode-select --install`"
            return f"install {pkg} via Homebrew (https://brew.sh/)" if pkg else None

        # Linux: prefer apt, then dnf, then pacman
        if ensure_tool("apt") and pkg:
            return f"sudo apt install -y {pkg}"
        if ensure_tool("dnf") and pkg:
            return f"sudo dnf install -y {pkg}"
        if ensure_tool("pacman") and pkg:
            return f"sudo pacman -S --noconfirm {pkg}"

        # fallback
        return f"install package: {pkg}" if pkg else None

    tools_to_check = ["age", "age-keygen", "gpg"]
    # `security` is macOS-specific
    if sys.platform == "darwin":
        tools_to_check.append("security")

    for _tool in tools_to_check:
        try:
            present = ensure_tool(_tool)
        except Exception:
            present = False
        if present:
            _ok(f"`{_tool}` available")
        else:
            suggestion = _suggest_install_cmd(_tool)
            if suggestion:
                _warn(f"`{_tool}` not found in PATH — suggestion: {suggestion}")
            else:
                _warn(f"`{_tool}` not found in PATH")

    # Configuration checks
    print(_color("\nConfiguration:", "1;34"))
    cfg = load_config()
    if not cfg:
        _warn("config: not found (using defaults)")
    else:
        _ok(f"loaded from {_config_file_path()}")

        encrypt = cfg.get("encrypt", "none")
        if encrypt not in ("none", "gpg", "age"):
            _err(f"invalid encrypt in config: {encrypt}")
            ok = False
        else:
            _ok(f"encrypt={encrypt}")

        # tool checks required by config
        if encrypt == "gpg":
            if not ensure_tool("gpg"):
                _err("config requests gpg encryption but `gpg` not found")
                ok = False
            else:
                _ok("`gpg` available")
        if encrypt == "age":
            if not ensure_tool("age"):
                _err("config requests age encryption but `age` not found")
                ok = False
            else:
                _ok("`age` available")

        # formats
        fmts = cfg.get("formats", ["json", "md"]) or []
        invalid = [f for f in fmts if f not in ("json", "md")]
        if invalid:
            _err(f"invalid formats in config: {', '.join(invalid)}")
            ok = False
        else:
            _ok(f"formats={','.join(fmts)}")

    # Age-specific checks (separated so they read nicely)
    age_cfg = (cfg.get("age", {}) if cfg else {}) or {}
    if age_cfg:
        print(_color("\nAge/passphrase checks:", "1;34"))
        pass_source = age_cfg.get("pass_source")
        if pass_source:
            _ok(f"age.pass_source={pass_source}")
            if pass_source == "keychain":
                try:
                    import keyring  # type: ignore
                    _ok("keyring available for keychain access")
                except Exception:
                    if sys.platform == "darwin" and ensure_tool("security"):
                        _ok("macOS `security` available for keychain access")
                    else:
                        _err(
                            "keychain pass_source configured but keyring/security not available")
                        ok = False
            if pass_source == "env":
                if os.environ.get("BACKUP_PASSPHRASE"):
                    _ok("BACKUP_PASSPHRASE present in environment")
                else:
                    _warn("age.pass_source=env but BACKUP_PASSPHRASE is not set")
        recipients = (age_cfg.get("recipients") or "").strip()
        if recipients:
            _ok("age.recipients configured")

    # final summary
    print(_color("\n" + "─" * 52, "36"))
    summary_icon = OK_ICON if ok else FAIL_ICON
    summary_color = "32" if ok else "31"
    print(
        f"doctor result: {_color(summary_icon + ' ' + ('OK' if ok else 'FAILED'), summary_color)}")
    print()
    return ok
