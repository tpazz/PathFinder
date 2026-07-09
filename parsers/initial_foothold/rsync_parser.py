import re

from parsers.ansi import ANSI_ESCAPE_PATTERN, warn


_MODULE_LINE = re.compile(
    r"^(?P<module>[A-Za-z0-9][A-Za-z0-9_.@-]{0,63})(?:\s{2,}|\t+)(?P<comment>.*)$"
    r"|^(?P<bare_module>[A-Za-z0-9][A-Za-z0-9_.@-]{0,63})$"
)
_PERMISSION_LINE = re.compile(r"^[bcdlps-][rwxstST-]{9}\b")
_LISTING_LINE = re.compile(
    r"^(?P<perm>[bcdlps-][rwxstST-]{9})\s+"
    r"(?P<size>[\d,]+)\s+"
    r"(?P<date>\S+)\s+"
    r"(?P<time>\S+)\s+"
    r"(?P<name>.+)$"
)


def parse_rsync_output(file_path, target_host):
    """Parse anonymous rsync module listings and file listings."""
    findings = []
    modules = []
    listed_files = []

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except FileNotFoundError:
        warn(f"[!] Error: rsync output file not found at {file_path}")
        return findings

    for raw_line in lines:
        line = ANSI_ESCAPE_PATTERN.sub("", raw_line).strip()
        if not line or line.lower().startswith(("receiving incremental", "sent ", "total size", "@error")):
            continue

        listing = _LISTING_LINE.match(line)
        if listing:
            listed_files.append({
                "name": listing.group("name").strip(),
                "size": int(listing.group("size").replace(",", "")),
                "permissions": listing.group("perm"),
            })
            continue

        if _PERMISSION_LINE.match(line):
            continue

        module = _MODULE_LINE.match(line)
        if not module:
            continue
        module_name = module.group("module") or module.group("bare_module")
        if module_name in {".", ".."} or module_name.startswith("-"):
            continue
        comment = (module.group("comment") or "").strip() or None
        modules.append({"name": module_name, "comment": comment})

    seen = set()
    for module in modules:
        name = module["name"]
        if name.lower() in seen:
            continue
        seen.add(name.lower())
        findings.append({
            "host": target_host,
            "port": 873,
            "source_tool": "rsync",
            "entity_type": "rsync_module",
            "name": name,
            "version": None,
            "attributes": {
                "protocol": "rsync",
                "anonymous": True,
                "comment": module.get("comment"),
                "source_file": file_path,
            },
        })

    if modules:
        findings.append({
            "host": target_host,
            "port": 873,
            "source_tool": "rsync",
            "entity_type": "misconfiguration",
            "name": "rsync_anonymous_module_listing",
            "version": None,
            "attributes": {
                "description": f"Anonymous rsync module listing exposed {len(modules)} module(s)",
                "modules": [m["name"] for m in modules],
                "confidence": "high",
                "source_file": file_path,
            },
        })

    if listed_files:
        findings.append({
            "host": target_host,
            "port": 873,
            "source_tool": "rsync",
            "entity_type": "information_leak",
            "name": "rsync_file_listing_exposed",
            "version": None,
            "attributes": {
                "description": f"Anonymous rsync file listing exposed {len(listed_files)} file(s)",
                "files": listed_files[:50],
                "source_file": file_path,
            },
        })

    return findings
