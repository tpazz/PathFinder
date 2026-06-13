import re

from parsers.ansi import ANSI_ESCAPE_PATTERN

# smbmap host header, e.g.  "[+] IP: 10.10.10.10:445	Name: dc01.corp.local"
_IP_LINE = re.compile(r"\[\+\]\s*IP:\s*([0-9a-fA-F:.]+?)(?::(\d+))?\s*(?:Name:|$)", re.IGNORECASE)
# A share row: name, permissions, optional comment. Permissions is the anchor token.
_SHARE_LINE = re.compile(
    r"^(?P<name>\S[\S ]*?)\s{2,}"
    r"(?P<perms>NO ACCESS|READ ONLY|READ,\s*WRITE|WRITE ONLY|READ-ONLY|READ/WRITE)"
    r"(?:\s+(?P<comment>.*\S))?\s*$",
    re.IGNORECASE,
)


def _normalize_perms(perms):
    p = perms.upper().replace("-", " ").replace("/", ", ").replace(",", ", ")
    p = re.sub(r"\s+", " ", p).strip()
    has_read = "READ" in p
    has_write = "WRITE" in p
    return has_read, has_write


def parse_smbmap_output(file_path, target_host=None):
    """
    Parses smbmap text output into share and misconfiguration findings.

    Writable shares become high-value misconfiguration findings (upload/lateral
    movement); every accessible share is also recorded as a 'share' finding for
    context. Host/port are read from smbmap's "[+] IP:" header, falling back to
    target_host.
    """
    findings = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except FileNotFoundError:
        print(f"[!] Error: smbmap output file not found at {file_path}")
        return findings

    host = target_host
    port = 445
    seen_shares = set()

    for raw_line in content.splitlines():
        line = ANSI_ESCAPE_PATTERN.sub("", raw_line).rstrip()
        stripped = line.strip()
        if not stripped:
            continue

        ip_match = _IP_LINE.search(stripped)
        if ip_match:
            host = ip_match.group(1)
            if ip_match.group(2):
                try:
                    port = int(ip_match.group(2))
                except (ValueError, TypeError):
                    port = 445
            continue

        share_match = _SHARE_LINE.match(stripped)
        if not share_match:
            continue

        share_name = share_match.group("name").strip()
        perms_raw = share_match.group("perms").strip()
        comment = (share_match.group("comment") or "").strip()

        # Skip the header row ("Disk   Permissions   Comment") and separators.
        if share_name.lower() in {"disk", "share"} or set(share_name) <= {"-"}:
            continue

        has_read, has_write = _normalize_perms(perms_raw)
        effective_host = host or "UNKNOWN_HOST"

        identifier = (effective_host, share_name)
        if identifier in seen_shares:
            continue
        seen_shares.add(identifier)

        if has_read or has_write:
            findings.append({
                "host": effective_host, "port": port, "source_tool": "smbmap",
                "entity_type": "share", "name": share_name, "version": None,
                "attributes": {"permissions": perms_raw, "comment": comment or None, "readable": has_read, "writable": has_write},
            })

        if has_write:
            findings.append({
                "host": effective_host, "port": port, "source_tool": "smbmap",
                "entity_type": "misconfiguration", "name": "writable_smb_share", "version": None,
                "attributes": {
                    "share": share_name,
                    "permissions": perms_raw,
                    "description": f"SMB share '{share_name}' is writable ({perms_raw}); usable for upload or lateral movement.",
                },
            })

    return findings
