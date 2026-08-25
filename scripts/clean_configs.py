import json

ALLOWED_SCHEMES = {
    "vmess", "ss", "socks", "socks4", "socks5",
    "trojan", "vless", "wireguard", "hysteria2", "hy2", "v2rayn",
}

MAX_ENTRIES = 200
MAX_LINK_LENGTH = 8000
MAX_NAME_LENGTH = 60
MAX_FIELD_LENGTH = 40

PATH = "configs.json"


def is_valid_link(link):
    if not isinstance(link, str):
        return False
    t = link.strip()
    if not t or len(t) > MAX_LINK_LENGTH:
        return False
    if any(ch.isspace() for ch in t):
        return False
    idx = t.find("://")
    if idx <= 0:
        return False
    return t[:idx].lower() in ALLOWED_SCHEMES


def clean_text(value, cap):
    if not isinstance(value, str):
        value = "" if value is None else str(value)
    return "".join(ch for ch in value if not ord(ch) < 32).strip()[:cap]


def main():
    try:
        with open(PATH, encoding="utf-8") as f:
            raw = f.read()
        data = json.loads(raw)
        if not isinstance(data, list):
            raise ValueError("not a list")
    except Exception:
        print("configs.json unreadable, resetting to empty list")
        with open(PATH, "w", encoding="utf-8") as f:
            f.write("[]")
        return

    kept = []
    seen_links = set()

    for item in data:
        if not isinstance(item, dict):
            continue
        link = str(item.get("link", ""))
        if not is_valid_link(link):
            continue
        link = link.strip()
        if link in seen_links:
            continue
        seen_links.add(link)
        kept.append({
            "id": clean_text(item.get("id", ""), 64),
            "name": clean_text(item.get("name", ""), MAX_NAME_LENGTH) or "Config",
            "link": link,
            "volume": clean_text(item.get("volume", ""), MAX_FIELD_LENGTH),
            "duration": clean_text(item.get("duration", ""), MAX_FIELD_LENGTH),
            "users": clean_text(item.get("users", ""), MAX_FIELD_LENGTH),
            "createdAt": item["createdAt"] if isinstance(item.get("createdAt"), int) else 0,
            "ownerId": clean_text(item.get("ownerId", ""), 64),
        })

    kept = kept[-MAX_ENTRIES:]
    new_content = json.dumps(kept)

    if new_content == raw.strip():
        print("OK: %d entries, no policy violations" % len(kept))
        return

    with open(PATH, "w", encoding="utf-8") as f:
        f.write(new_content)
    print("CLEANED: dropped %d entries, %d valid remain" % (len(data) - len(kept), len(kept)))


if __name__ == "__main__":
    main()
