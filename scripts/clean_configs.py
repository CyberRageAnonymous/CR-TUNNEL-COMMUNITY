#!/usr/bin/env python3
"""Community configs policy guard.

Reads configs.json, enforces limits / clean text fields, preserves the
community likes counters, and commits the cleaned result back to the repo.
Runs on push via .github/workflows/validate-configs.yml.

Safe on any state:
- corrupt / not-an-array file is replaced with an empty array.
- entries with unsupported protocols are dropped.
- fields are trimmed and capped in length.
"""

import json
import re

CONFIG_FILE = "configs.json"

ALLOWED_SCHEMES = {
    "vmess", "ss", "socks", "socks4", "socks5",
    "trojan", "vless", "wireguard", "hysteria2", "hy2", "v2rayn",
}

MAX_ENTRIES = 200
MAX_LINK_LENGTH = 8000
MAX_NAME_LENGTH = 60
MAX_FIELD_LENGTH = 40


def is_valid_link(raw):
    if not raw:
        return False
    link = raw.strip()
    if not link or len(link) > MAX_LINK_LENGTH:
        return False
    if any(ch.isspace() or ch.iscontrol() for ch in link):
        return False
    scheme_end = link.find("://")
    if scheme_end <= 0:
        return False
    return link[:scheme_end].lower() in ALLOWED_SCHEMES


def clean_entry(raw, index):
    if not isinstance(raw, dict):
        return None
    link = raw.get("link")
    if not is_valid_link(link):
        print(f"  drop {index}: invalid link")
        return None
    entry = {
        "id": str(raw.get("id") or "")[:64],
        "name": str(raw.get("name") or "").strip()[:MAX_NAME_LENGTH] or "Config",
        "link": link.strip(),
        "volume": str(raw.get("volume") or "").strip()[:MAX_FIELD_LENGTH],
        "duration": str(raw.get("duration") or "").strip()[:MAX_FIELD_LENGTH],
        "users": str(raw.get("users") or "").strip()[:MAX_FIELD_LENGTH],
        "createdAt": raw.get("createdAt") if isinstance(raw.get("createdAt"), int) else 0,
        "ownerId": str(raw.get("ownerId") or "")[:64],
        "likes": raw.get("likes") if isinstance(raw.get("likes"), int) else 0,
    }
    if entry["likes"] < 0:
        entry["likes"] = 0
    return entry


def main():
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8-sig") as fh:
            raw_text = fh.read()
    except OSError as exc:
        print(f"ERROR: cannot read {CONFIG_FILE}: {exc}")
        raise SystemExit(1)

    try:
        raw = json.loads(raw_text)
    except json.JSONDecodeError:
        new_content = json.dumps([])
        with open(CONFIG_FILE, "w", encoding="utf-8") as fh:
            fh.write(new_content)
        print("CLEANED: corrupt json replaced with [] (no-op commit to avoid loop)")
        raise SystemExit(0)

    if not isinstance(raw, list):
        new_content = json.dumps([])
        with open(CONFIG_FILE, "w", encoding="utf-8") as fh:
            fh.write(new_content)
        print("CLEANED: root must be an array (no-op commit to avoid loop)")
        raise SystemExit(0)

    cleaned = []
    seen_links = set()
    dropped = 0
    for index, item in enumerate(raw):
        entry = clean_entry(item, index)
        if entry is None:
            dropped += 1
            continue
        if entry["link"] in seen_links:
            dropped += 1
            continue
        seen_links.add(entry["link"])
        cleaned.append(entry)

    if len(cleaned) > MAX_ENTRIES:
        dropped += len(cleaned) - MAX_ENTRIES
        cleaned = cleaned[:MAX_ENTRIES]

    new_content = json.dumps(cleaned)

    if new_content == raw_text.strip():
        print("OK: configs.json is clean")
        return

    with open(CONFIG_FILE, "w", encoding="utf-8") as fh:
        fh.write(new_content)
    print(f"CLEANED: dropped {dropped}, entries now {len(cleaned)}")


if __name__ == "__main__":
    main()