import argparse
import sys
import os
from .exporter import run_backup, verify_manifest, load_config, configure_interactive, init_setup, OpExporter, doctor


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="1p-exporter", description="Export 1Password vaults and create backups")
    sub = p.add_subparsers(dest="cmd")

    b = sub.add_parser(
        "backup", help="Create a backup archive from 1Password using `op` CLI")
    b.add_argument("--output", "-o", default=argparse.SUPPRESS,
                   help="output base directory (overrides saved config)")
    b.add_argument("--formats", "-f", default=argparse.SUPPRESS,
                   help="comma-separated formats to write (json,md). Overrides saved config")
    b.add_argument("--encrypt", choices=["gpg", "age", "none"],
                   default=argparse.SUPPRESS, help="encrypt archive (gpg/age) or none — overrides saved config")
    # age-pass-source: include 'keychain' only on macOS
    is_macos = sys.platform == "darwin"
    age_pass_choices = ["env", "prompt", "1password",
                        "keychain"] if is_macos else ["env", "prompt", "1password"]
    age_pass_help = ("where to obtain the age passphrase when using age (env=BACKUP_PASSPHRASE, prompt=ask, 1password=read from item, keychain=macOS keychain). Overrides saved config"
                     if is_macos else
                     "where to obtain the age passphrase when using age (env=BACKUP_PASSPHRASE, prompt=ask, 1password=read from item). Overrides saved config")
    b.add_argument("--age-pass-source", choices=age_pass_choices, default=argparse.SUPPRESS,
                   help=age_pass_help)
    b.add_argument("--age-pass-item", default=argparse.SUPPRESS,
                   help="1Password item title or id that contains the passphrase (used when --age-pass-source=1password)")
    b.add_argument("--age-pass-field", default=argparse.SUPPRESS,
                   help="field name inside the 1Password item to use for the passphrase (default: 'passphrase'). "
                        "if supplied but not found, the backup will fail instead of guessing")
    # keychain-related flags are macOS-specific — hide them from help on other platforms
    keychain_help = "macOS keychain service name (when using --age-pass-source keychain)" if is_macos else argparse.SUPPRESS
    b.add_argument("--age-keychain-service", default=argparse.SUPPRESS,
                   help=keychain_help)
    keychain_user_help = "macOS keychain account/username (when using --age-pass-source keychain)" if is_macos else argparse.SUPPRESS
    b.add_argument("--age-keychain-username", default=argparse.SUPPRESS,
                   help=keychain_user_help)
    b.add_argument("--age-recipients", default=argparse.SUPPRESS,
                   help="comma-separated age public recipients (optional)")
    b.add_argument("--age-use-yubikey", action="store_true", default=argparse.SUPPRESS,
                   help="(optional) include a YubiKey-backed recipient (requires user to have configured a yubikey age identity)")
    b.add_argument("--sync-passphrase-from-1password", action="store_true", default=argparse.SUPPRESS,
                   help="treat the passphrase stored in 1Password as authoritative and copy it to other configured stores (keychain/ENV) before encrypting")
    b.add_argument("--no-attachments", action="store_true", default=argparse.SUPPRESS,
                   help="do not attempt to download attachments (overrides saved config)")
    b.add_argument("--quiet", action="store_true", default=argparse.SUPPRESS,
                   help="minimal output (overrides saved config)")

    # init: generate/store a backup passphrase (1Password / macOS Keychain) and optionally run `op signin`
    i = sub.add_parser(
        "init", help="Initialize backup passphrase and store in 1Password/keychain")
    i.add_argument("--generate", action="store_true",
                   help="generate a new random passphrase")
    i.add_argument(
        "--passphrase", help="provide a passphrase to store instead of generating")
    i.add_argument("--store-in-1password",
                   help="store generated/provided passphrase in 1Password (item title)")
    # keychain flags are macOS-only; keep attributes available but hide on other platforms
    store_in_keychain_help = "store generated/provided passphrase in macOS Keychain" if sys.platform == "darwin" else argparse.SUPPRESS
    i.add_argument("--store-in-keychain", action="store_true",
                   help=store_in_keychain_help)
    keychain_service_help = "keychain service name to store under" if sys.platform == "darwin" else argparse.SUPPRESS
    i.add_argument("--keychain-service", default="1p-exporter",
                   help=keychain_service_help)
    keychain_user_help = "keychain account/username" if sys.platform == "darwin" else argparse.SUPPRESS
    i.add_argument("--keychain-username", default="backup",
                   help=keychain_user_help)
    i.add_argument("--onepassword-field", default="passphrase",
                   help="field name to use when storing in 1Password (default: passphrase)")
    i.add_argument("--onepassword-vault",
                   help="1Password vault name or id to store the passphrase in (optional)")
    i.add_argument("--signin", action="store_true",
                   help="invoke `op signin` to allow interactive unlock (Touch ID) and print session token")

    v = sub.add_parser("verify", help="Verify a produced manifest and files")
    v.add_argument("manifest", help="path to manifest.json")

    d = sub.add_parser(
        "doctor", help="Sanity-check environment and configuration")

    # 'query' command for post-processing exported data
    q = sub.add_parser("query", help="Query exported backup data")
    qsub = q.add_subparsers(dest="query_cmd")

    ql = qsub.add_parser("list", help="List item titles matching a regexp")
    ql.add_argument("pattern", help="regular expression to match item titles")
    ql.add_argument("--dir", "-d", default=".",
                    help="path to directory containing exported JSON (default: current directory)")
    ql.add_argument("--age-identity", action="append", dest="age_identities",
                    help="path to an age identity file to use for decrypting archives; can be repeated."
                    )
    ql.add_argument("--age-passphrase", dest="age_passphrase",
                    help="passphrase to use when decrypting age archives; sets BACKUP_PASSPHRASE environment variable")

    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.cmd == "backup":
        # merge saved config with CLI args (CLI overrides saved config)
        cfg = load_config()

        output_base = args.output if hasattr(
            args, "output") else cfg.get("output_base", "backups")

        if hasattr(args, "formats"):
            formats = args.formats.split(",")
        else:
            formats = cfg.get("formats", ["json", "md"]) or ["json", "md"]

        encrypt = args.encrypt if hasattr(
            args, "encrypt") else cfg.get("encrypt", "none")

        if hasattr(args, "no_attachments"):
            download_attachments = not args.no_attachments
        else:
            download_attachments = cfg.get("download_attachments", True)

        quiet = args.quiet if hasattr(
            args, "quiet") else cfg.get("quiet", False)

        age_cfg = cfg.get("age", {})
        age_pass_source = args.age_pass_source if hasattr(
            args, "age_pass_source") else age_cfg.get("pass_source", "prompt")
        age_pass_item = args.age_pass_item if hasattr(
            args, "age_pass_item") else age_cfg.get("pass_item")
        age_pass_field = args.age_pass_field if hasattr(
            args, "age_pass_field") else age_cfg.get("pass_field", "passphrase")
        age_recipients = args.age_recipients if hasattr(
            args, "age_recipients") else age_cfg.get("recipients", "")
        age_use_yubikey = args.age_use_yubikey if hasattr(
            args, "age_use_yubikey") else age_cfg.get("use_yubikey", False)
        sync_passphrase_from_1password = args.sync_passphrase_from_1password if hasattr(
            args, "sync_passphrase_from_1password") else False
        age_keychain_service = args.age_keychain_service if hasattr(
            args, "age_keychain_service") else age_cfg.get("keychain_service", "1p-exporter")
        age_keychain_username = args.age_keychain_username if hasattr(
            args, "age_keychain_username") else age_cfg.get("keychain_username", "backup")

        run_backup(
            output_base=output_base,
            formats=formats,
            encrypt=encrypt,
            download_attachments=download_attachments,
            quiet=quiet,
            age_pass_source=age_pass_source,
            age_pass_item=age_pass_item,
            age_pass_field=age_pass_field,
            age_recipients=age_recipients,
            age_use_yubikey=age_use_yubikey,
            sync_passphrase_from_1password=sync_passphrase_from_1password,
            age_keychain_service=age_keychain_service,
            age_keychain_username=age_keychain_username,
        )
    elif args.cmd == "init":
        # Interactive flow when no explicit options are provided
        any_flags = any((args.generate, args.passphrase,
                        args.store_in_1password, args.store_in_keychain, args.signin))
        if args.signin:
            OpExporter().signin_interactive()
        if not any_flags:
            configure_interactive()
        else:
            init_setup(
                passphrase=args.passphrase,
                generate=args.generate,
                store_in_1password=args.store_in_1password,
                onepassword_vault=None,
                store_in_keychain=args.store_in_keychain,
                keychain_service=args.keychain_service,
                keychain_username=args.keychain_username,
                onepassword_field=args.onepassword_field,
            )

        # After initialization, run a `doctor` check on the generated configuration
        ok = doctor()
        sys.exit(0 if ok else 2)
    elif args.cmd == "verify":
        ok = verify_manifest(args.manifest)
        sys.exit(0 if ok else 2)
    elif args.cmd == "doctor":
        ok = doctor()
        sys.exit(0 if ok else 2)
    elif args.cmd == "query":
        # only subcommand supported so far is ``list``
        if args.query_cmd == "list":
            # perform the search and print matching titles
            from .exporter import query_list_titles

            # allow quick CLI-based provision of decryption helpers; these
            # simply set the environment variables that ``query_list_titles``
            # respects.  environment has higher precedence than searching for
            # identities in the user's home config.
            if hasattr(args, "age_passphrase") and args.age_passphrase is not None:
                os.environ["BACKUP_PASSPHRASE"] = args.age_passphrase
            if hasattr(args, "age_identities") and args.age_identities:
                # join with pathsep so the function can split them later
                os.environ["AGE_IDENTITIES"] = os.pathsep.join(args.age_identities)

            try:
                # first argument is path (from --dir), second is regexp pattern
                matches = query_list_titles(args.dir, args.pattern)
            except Exception as e:
                print(f"error: {e}")
                sys.exit(1)

            for t in matches:
                print(t)
            # exit code 0 even if no matches; you can pipe into ``wc -l`` etc
            sys.exit(0)
        else:
            q.print_help()
            sys.exit(2)
    else:
        parser.print_help()
