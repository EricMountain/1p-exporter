# onep-exporter — 1Password vault exporter and secure local backup

## Overview

onep-exporter exports all your 1Password vaults/items to local files, packages them into a timestamped archive, and optionally encrypts that archive client‑side. It produces machine‑readable JSON and human‑readable Markdown, stores a `manifest.json` with checksums, and provides helpers for safe passphrase storage.

## Features

- Export vaults/items using the `op` CLI (requires sign‑in or `OP_SESSION_*`)
- Per‑vault `JSON` and `Markdown` exports
- Attachment download (best‑effort) and `manifest.json` with SHA256 checksums
- Optional client‑side encryption with `age` (recommended) or symmetric `gpg`
- Interactive `init` flow and persistent configuration (`~/.config/onep-exporter/config.json`)
- Helpers to store/retrieve passphrases in 1Password or macOS Keychain (Touch ID supported)

## Prerequisites

- `op` — 1Password CLI
- `age` and/or `gpg` — for encryption (install via Homebrew or your distro package manager)
- macOS: `security` CLI (built‑in) or Python `keyring` for Keychain integration

## Installation

```bash
python -m pip install -e .
```

## Quick start

Sign in (interactive):

```bash
op signin <your-domain>
# or
onep-exporter init --signin
```

Run a backup (unencrypted):

```bash
onep-exporter backup --output ~/onep-backups
```

Verify the backup:

```bash
onep-exporter verify ~/onep-backups/<timestamp>/manifest.json
```

## Interactive setup & helpers

- `onep-exporter init` — interactive configuration; can generate/store an `age` passphrase in 1Password or Keychain and persists defaults.
- Programmatic helpers: `configure_interactive()`, `init_setup()`, `OpExporter.signin_interactive()`

## Encryption

- `gpg` (symmetric): passphrase via `BACKUP_PASSPHRASE` env or prompt.
- `age` (recommended): supports passphrase recipients and public‑key recipients.
  - `--age-pass-source` may be `env`, `prompt`, `1password`, or `keychain`.
  - Use `--age-recipients` to include public recipients (e.g. YubiKey‑backed identities).

Examples:

```bash
# age passphrase from a 1Password item
onep-exporter backup --encrypt age --age-pass-source 1password --age-pass-item "Backup Passphrase"

# age passphrase from macOS Keychain (Touch ID may prompt)
onep-exporter backup --encrypt age --age-pass-source keychain
```

## Configuration

- Default config file: `~/.config/onep-exporter/config.json`
- Override with: `ONEP_EXPORTER_CONFIG=/path/to/config.json`
- CLI flags override saved config values.

Sample saved config keys: `output_base`, `formats`, `encrypt`, `download_attachments`, and `age` (contains pass_source, pass_item, recipients, keychain settings).

See `examples/config.example.json` for a ready-to-copy sample configuration.

## Security notes

- Prefer `age` with both a passphrase and a YubiKey/public‑recipient for layered recovery.
- When storing passphrases in 1Password, restrict item/vault access and rotate regularly.
- The config file stores references (item titles, recipient strings) — secret values are stored only if you explicitly choose 1Password/Keychain storage.

## Commands (summary)

- `onep-exporter init` — interactive setup and optional passphrase storage
- `onep-exporter backup [--encrypt age|gpg|none]` — run export (CLI overrides config)
- `onep-exporter verify <manifest.json>` — verify manifest integrity

## Development & tests

```bash
python -m pytest
```

## References

- 1Password CLI: [1Password CLI docs](https://developer.1password.com/docs/cli/)
- age: [age encryption](https://age-encryption.org/)
- sops: [mozilla/sops](https://github.com/mozilla/sops)
