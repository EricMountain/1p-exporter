from typing import Any


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
        lines.append(f"- {url.get('label', '')} {url.get('url')}")
    lines.append("")
    # Fields
    for f in item.get("fields", []):
        name = f.get("name") or f.get("label") or "field"
        value = f.get("value")
        if value:
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
