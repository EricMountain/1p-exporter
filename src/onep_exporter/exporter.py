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
        """Create a password item in 1Password **only if it does not already exist**.

        Returns the existing item JSON if present, or the created item JSON.
        """
        existing = self.find_item_by_title(title, vault=vault)
        if existing:
            # do not overwrite existing item
            return existing

        # safer payload: explicit field name + type
        payload = {
            "title": title,
            "category": "password",
            "fields": [
                {"label": field_name, "name": field_name,
                    "type": "password", "value": passphrase}
            ]
        }
        cmd = ["op", "item", "create"]
        if vault:
            cmd.extend(["--vault", vault])
        cmd.append(json.dumps(payload))
        cmd.extend(["--format", "json"])
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


def run_backup(*, output_base: Union[str, Path] = "backups", formats=("json", "md"), encrypt: str = "none", download_attachments: bool = True, quiet: bool = False, age_pass_source: str = "1password", age_pass_item: Optional[str] = None, age_pass_field: str = "password", age_recipients: str = "", age_use_yubikey: bool = False, age_keychain_service: str = "1p-exporter", age_keychain_username: str = "backup") -> Path:
    output_base = Path(output_base)
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    outdir = output_base / ts
    outdir.mkdir(parents=True, exist_ok=True)

    exporter = OpExporter()

    vaults = exporter.list_vaults()
    manifest = {
        "timestamp": ts,
        "vaults": [],
        "files": [],
    }

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

        vault_filename = outdir / f"vault-{vault_id}.json"
        write_json(vault_filename, items_full)
        manifest["vaults"].append({"id": vault_id, "name": vault_name, "items": len(
            items_full), "file": str(vault_filename.name), "sha256": sha256_file(vault_filename)})

        if "md" in formats:
            md_path = outdir / f"vault-{vault_id}.md"
            md_text = vault_to_md(vault_name, items_full)
            md_path.write_text(md_text, encoding="utf-8")
            manifest["files"].append(
                {"path": str(md_path.name), "sha256": sha256_file(md_path)})

    # write manifest
    manifest_path = outdir / "manifest.json"
    write_json(manifest_path, manifest)
    manifest_hash = sha256_file(manifest_path)
    manifest["manifest_sha256"] = manifest_hash
    write_json(manifest_path, manifest)  # update with hash

    # create archive
    archive_path = output_base / f"1p-backup-{ts}.tar.gz"
    with tarfile.open(archive_path, "w:gz") as tar:
        tar.add(outdir, arcname=ts)

    archive_sha = sha256_file(archive_path)
    if not quiet:
        print(f"Created archive: {archive_path} (sha256={archive_sha})")

    # optional encryption (GPG symmetric)
    if encrypt == "gpg":
        if not ensure_tool("gpg"):
            raise RuntimeError("gpg not found for encryption")
        # read passphrase from env or prompt
        import os
        import getpass

        passphrase = os.environ.get("BACKUP_PASSPHRASE")
        if not passphrase:
            passphrase = getpass.getpass(
                "GPG passphrase for symmetric encryption: ")
        out_enc = str(archive_path) + ".gpg"
        # Use --batch and passphrase via stdin
        proc = run_cmd(["gpg", "--symmetric", "--cipher-algo", "AES256", "--batch", "--passphrase-fd",
                       "0", "--output", out_enc, str(archive_path)], input=passphrase.encode())
        # remove plaintext archive by default
        archive_path.unlink()
        if not quiet:
            print(f"Encrypted archive -> {out_enc}")
        return Path(out_enc)

    # optional encryption using age (supports passphrase + recipients)
    if encrypt == "age":
        if not ensure_tool("age"):
            raise RuntimeError("age not found for encryption")
        import os
        import getpass

        # determine passphrase source
        passphrase = None
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

        # run age: supply passphrase on stdin if present
        input_bytes = passphrase.encode() if passphrase else None
        run_cmd(cmd + [str(archive_path)], input=input_bytes)
        archive_path.unlink()
        if not quiet:
            print(f"Encrypted archive -> {out_enc}")
        return Path(out_enc)

    return archive_path


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

    The helper will ask for:
      - default output directory
      - formats
      - encryption choice (none/gpg/age)
      - age passphrase source and storage (1Password / keychain / prompt / env)
      - whether to store passphrase in 1Password/keychain
      - optional age recipients
    """
    import getpass
    import os

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
    age_pass_field = age_cfg.get("pass_field", "password")
    age_keychain_service = age_cfg.get("keychain_service", "1p-exporter")
    age_keychain_username = age_cfg.get("keychain_username", "backup")
    age_recipients = age_cfg.get("recipients", "")
    age_use_yubikey = age_cfg.get("use_yubikey", False)

    if encrypt == "age":
        age_pass_source = prompt(
            "age passphrase source (env/prompt/1password/keychain)", age_cfg.get("pass_source", "keychain"))
        if age_pass_source == "1password":
            age_pass_item = prompt("1Password item title for passphrase (item title)", age_cfg.get(
                "pass_item", "My Backup Passphrase"))
            age_pass_field = prompt("1Password field name", age_pass_field)
        if age_pass_source == "keychain":
            age_keychain_service = prompt(
                "Keychain service name", age_keychain_service)
            age_keychain_username = prompt(
                "Keychain account name", age_keychain_username)
        age_recipients = prompt(
            "Age recipients (comma-separated public recipients)", age_recipients)
        yub = prompt("Include YubiKey recipient by default? (y/n)",
                     "y" if age_use_yubikey else "n")
        age_use_yubikey = yub.lower().startswith("y")

        # optionally store passphrase now
        store_1p = prompt(
            "Store generated passphrase in 1Password? (y/n)", "n")
        store_kc = prompt(
            "Store generated passphrase in macOS Keychain? (y/n)", "n")

        passphrase = None
        if store_1p.lower().startswith("y") or store_kc.lower().startswith("y"):
            # ask whether to generate or provide
            gen = prompt("Generate a new passphrase? (y/n)", "y")
            if gen.lower().startswith("y"):
                import secrets

                passphrase = secrets.token_urlsafe(32)
                print("Generated passphrase — it will be stored as requested.")
            else:
                passphrase = getpass.getpass("Enter passphrase to store: ")

            # store where requested
            if store_1p.lower().startswith("y"):
                vault = prompt(
                    "1Password vault to store the passphrase in (optional)", age_cfg.get("vault"))
                try:
                    init_setup(passphrase=passphrase, generate=False, store_in_1password="Backup Passphrase",
                               onepassword_vault=vault, onepassword_field=age_pass_field)
                except Exception as e:
                    print(f"warning: failed to store in 1Password: {e}")
            if store_kc.lower().startswith("y"):
                try:
                    init_setup(passphrase=passphrase, generate=False, store_in_keychain=True,
                               keychain_service=age_keychain_service, keychain_username=age_keychain_username)
                except Exception as e:
                    print(f"warning: failed to store in keychain: {e}")

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
