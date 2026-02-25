from typing import Any, Optional


def _totp_now(otpauth_value: str) -> Optional[str]:
    """Generate the current TOTP code from an *otpauth://* URI or a bare base32 secret.

    Returns a zero-padded string (e.g. ``"034567"``) on success, or ``None`` if
    the input cannot be parsed or the TOTP calculation fails.
    """
    import base64
    import hashlib
    import hmac
    import struct
    import time
    from urllib.parse import parse_qs, urlparse

    try:
        secret_b32: str
        digits = 6
        period = 30
        algorithm = "SHA1"

        if otpauth_value.lower().startswith("otpauth://"):
            parsed = urlparse(otpauth_value)
            qs = parse_qs(parsed.query)
            raw_secret = qs.get("secret", [None])[0]
            if not raw_secret:
                return None
            secret_b32 = raw_secret.upper()
            digits = int(qs.get("digits", ["6"])[0])
            period = int(qs.get("period", ["30"])[0])
            algorithm = qs.get("algorithm", ["SHA1"])[0].upper()
        else:
            # treat the bare value as a base32 secret
            secret_b32 = otpauth_value.upper().strip()

        # add padding if needed
        pad = len(secret_b32) % 8
        if pad:
            secret_b32 += "=" * (8 - pad)
        key = base64.b32decode(secret_b32)

        hash_fn = {
            "SHA1": hashlib.sha1,
            "SHA256": hashlib.sha256,
            "SHA512": hashlib.sha512,
        }.get(algorithm, hashlib.sha1)

        counter = int(time.time()) // period
        msg = struct.pack(">Q", counter)
        digest = hmac.new(key, msg, hash_fn).digest()
        offset = digest[-1] & 0x0F
        code_int = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
        return str(code_int).zfill(digits)
    except Exception:
        return None


def item_to_md(item: dict[str, Any]) -> str:
    lines: list[str] = []
    title = item.get("title") or item.get("name") or "(no title)"
    lines.append(f"# {title}")
    lines.append("")
    if t := item.get("category"):
        lines.append(f"**Category:** {t}")
    if tags := item.get("tags"):
        lines.append(f"**Tags:** {', '.join(tags)}")
    lines.append("")
    # URLs
    for url in item.get("urls", []):
        href = url.get("href") or url.get("url") or ""
        label = url.get("label", "")
        if href:
            lines.append(f"- {label} {href}".strip())
    lines.append("")
    # Fields
    for f in item.get("fields", []):
        name = f.get("name") or f.get("label") or "field"
        value = f.get("value")
        if not value:
            continue
        if f.get("type", "").upper() in ("OTP", "TOTP"):
            # always compute the current code from the otpauth:// URI so the
            # value is valid at query time (the exported "totp" field is stale).
            code = _totp_now(value)
            if code:
                lines.append(f"- **{name}**: `{code}` *(TOTP)*")
            else:
                lines.append(f"- **{name}**: *(TOTP — unable to generate code)*")
        else:
            lines.append(f"- **{name}**: `{value}`")
    lines.append("")
    if note := item.get("notesPlain"):
        lines.append("---")
        lines.append(note)
    return "\n".join(lines)


def vault_to_md(vault_name: str, items: list[dict[str, Any]]) -> str:
    lines = [f"# Vault — {vault_name}", ""]
    for it in items:
        title = it.get("title") or it.get("name") or "(no title)"
        lines.append(f"- `{it.get('id')}` — **{title}**")
    lines.append("")
    return "\n".join(lines)
