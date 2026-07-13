import re
import os

from parsers.ansi import ANSI_ESCAPE_PATTERN, warn


_SMTP_USER_PATTERNS = [
    re.compile(r"\b(?P<user>[A-Za-z0-9._%+-]+)\s+exists\b", re.IGNORECASE),
    re.compile(r"\bexists:\s*(?P<user>[A-Za-z0-9._%+-]+)\b", re.IGNORECASE),
    re.compile(r"\bVALID\s+USER(?:NAME)?:\s*(?P<user>[A-Za-z0-9._%+-]+)\b", re.IGNORECASE),
    # 25x VRFY/EXPN success: capture the local part of an address so we don't grab
    # the enhanced status code (e.g. "250 2.1.5 <bob@host>" -> bob, not 2.1.5).
    re.compile(r"\b25[0-2]\b[^\n]*?(?P<user>[A-Za-z0-9._%+-]+)@", re.IGNORECASE),
]
_NOISE = {"user", "username", "valid", "exists", "root@localhost"}
# Reject SMTP status/enhanced-status codes (e.g. 250, 2.1.5) as usernames.
_STATUS_CODE = re.compile(r"^\d+(?:\.\d+)*$")


def _port_from_filename(file_path, default_port):
    match = re.search(r"smtp_user_enum_(\d{1,5})\.", os.path.basename(file_path))
    if match:
        candidate = int(match.group(1))
        if 0 < candidate <= 65535:
            return candidate
    return default_port


def parse_smtp_user_enum_output(file_path, target_host, default_port=25):
    """Parse smtp-user-enum / VRFY / EXPN valid-user output."""
    findings = []
    port = _port_from_filename(file_path, default_port)
    users = []
    seen = set()

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except FileNotFoundError:
        warn(f"[!] Error: SMTP user-enum output file not found at {file_path}")
        return findings

    for raw_line in lines:
        line = ANSI_ESCAPE_PATTERN.sub("", raw_line).strip()
        if not line:
            continue
        for pattern in _SMTP_USER_PATTERNS:
            match = pattern.search(line)
            if not match:
                continue
            user = match.group("user").strip("<>;,")
            if "@" in user:
                user = user.split("@", 1)[0]
            if not user or user.lower() in _NOISE or _STATUS_CODE.match(user):
                continue
            key = user.lower()
            if key in seen:
                continue
            seen.add(key)
            users.append(user)
            findings.append({
                "host": target_host,
                "port": port,
                "source_tool": "smtp-user-enum",
                "entity_type": "confirmed_username",
                "name": user,
                "version": None,
                "attributes": {
                    "source": "SMTP VRFY/EXPN/RCPT user enumeration",
                    "raw_line": line,
                    "source_file": file_path,
                },
            })
            break

    if users:
        findings.append({
            "host": target_host,
            "port": port,
            "source_tool": "smtp-user-enum",
            "entity_type": "information_leak",
            "name": "smtp_valid_users_enumerated",
            "version": None,
            "attributes": {
                "description": f"SMTP user enumeration identified {len(users)} valid user(s)",
                "users": users,
                "confidence": "high",
                "source_file": file_path,
            },
        })

    return findings
