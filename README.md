# 1p-exporter — 1Password vault exporter and secure local backup

## Overview

1p-exporter exports all your 1Password vaults/items to local files, packages them into a timestamped archive, and optionally encrypts that archive client‑side. It produces machine‑readable JSON and human‑readable Markdown, stores a `manifest.json` with checksums, and provides helpers for safe passphrase storage.

Note: the Python import package name remains `onep_exporter` (use `import onep_exporter`); the user-facing project/CLI name is `1p-exporter`.

## Features

- Export vaults/items using the `op` CLI (requires sign‑in or `OP_SESSION_*`)
- Per‑vault `JSON` and `Markdown` exports
- Attachment download (best‑effort) and `manifest.json` with SHA256 checksums
- Optional client‑side encryption with `age` (recommended) or symmetric `gpg`
- Interactive `init` flow and persistent configuration (`~/.config/1p-exporter/config.json`)
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
1p-exporter init --signin
```

Run a backup (unencrypted):

```bash
1p-exporter backup --output ~/onep-backups
```

Verify the backup:

```bash
1p-exporter verify ~/onep-backups/<timestamp>/manifest.json
```

## Interactive setup & helpers

- `1p-exporter init` — interactive configuration; can generate/store an `age` passphrase in 1Password or Keychain and persists defaults.
- Programmatic helpers: `configure_interactive()`, `init_setup()`, `OpExporter.signin_interactive()`

## Encryption

- `gpg` (symmetric): passphrase via `BACKUP_PASSPHRASE` env or prompt.
- `age` (recommended): supports passphrase recipients and public‑key recipients.
  - `--age-pass-source` may be `env`, `prompt`, `1password`, or `keychain`.
  - If the passphrase is present in multiple stores (1Password, Keychain, or the `BACKUP_PASSPHRASE` env), 1p-exporter will verify they are identical and will abort if they differ.
  - Use `--sync-passphrase-from-1password` to treat the value in 1Password as authoritative and copy it to other configured stores (keychain/ENV) before encrypting.
  - Use `--age-recipients` to include public recipients (e.g. YubiKey‑backed identities).

Examples:

```bash
# age passphrase from a 1Password item
1p-exporter backup --encrypt age --age-pass-source 1password --age-pass-item "Backup Passphrase"

# age passphrase from macOS Keychain (Touch ID may prompt)
1p-exporter backup --encrypt age --age-pass-source keychain
```

## Configuration

- Default config file: `~/.config/1p-exporter/config.json`
- Override with: `ONEP_EXPORTER_CONFIG=/path/to/config.json`
- CLI flags override saved config values.

Sample saved config keys: `output_base`, `formats`, `encrypt`, `download_attachments`, and `age` (contains pass_source, pass_item, recipients, keychain settings).

See `examples/config.example.json` for a ready-to-copy sample configuration.

## Security notes

- Prefer `age` with both a passphrase and a YubiKey/public‑recipient for layered recovery.
- When storing passphrases in 1Password, restrict item/vault access and rotate regularly.
- The config file stores references (item titles, recipient strings) — secret values are stored only if you explicitly choose 1Password/Keychain storage.

## Commands (summary)

- `1p-exporter init` — interactive setup and optional passphrase storage
- `1p-exporter backup [--encrypt age|gpg|none]` — run export (CLI overrides config)
- `1p-exporter verify <manifest.json>` — verify manifest integrity

## Development & tests

```bash
python -m pytest
```

### Development environment (direnv)

- A `.envrc` is provided in the project root to automatically add `src/` to `PYTHONPATH` and expose the project's `.venv/bin` on `PATH`.
- After installing `direnv` and adding its shell hook to your shell, run:

```bash
direnv allow
```

You can still run the package without direnv using `PYTHONPATH=src .venv/bin/python -m onep_exporter ...`.

## References

- 1Password CLI: [1Password CLI docs](https://developer.1password.com/docs/cli/)
- age: [age encryption](https://age-encryption.org/)
- sops: [mozilla/sops](https://github.com/mozilla/sops)

## Setup

### MacOS

- Ensure `op` is installed
  - `brew install 1password-cli`
- [Setup](https://developer.1password.com/docs/cli/app-integration/#set-up-the-app-integration) the `op` to `1Password` integration
- Run `op account add`: should report 1Password CLI is connected with the 1Password app.
- Run `op signin`: should be prompted to authorise 1Password access.
- `python -m onep_exporter doctor`
  - Need `age` and `op` installed. It's OK if the `config` is missing at this point.
- `python -m onep_exporter init`
  - Accept all defaults
  - `doctor` run at the end should be all green
