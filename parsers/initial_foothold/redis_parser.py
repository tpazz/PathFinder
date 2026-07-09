import re
import os

from parsers.ansi import ANSI_ESCAPE_PATTERN, warn


_VERSION_PATTERNS = [
    re.compile(r"^redis_version:(?P<version>[^\s]+)", re.IGNORECASE),
    re.compile(r"^\s*\|?\s*Version:\s*(?P<version>[^\s]+)", re.IGNORECASE),
]
_KEYSPACE = re.compile(r"^(?P<db>db\d+):(?P<stats>.+)$", re.IGNORECASE)


def _parse_keyspace_stats(stats):
    parsed = {}
    for part in stats.split(","):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        key = key.strip()
        value = value.strip()
        try:
            parsed[key] = int(value)
        except ValueError:
            parsed[key] = value
    return parsed


def _port_from_filename(file_path, default_port):
    match = re.search(r"redis_(\d{1,5})\.", os.path.basename(file_path))
    if match:
        candidate = int(match.group(1))
        if 0 < candidate <= 65535:
            return candidate
    return default_port


def parse_redis_output(file_path, target_host, default_port=6379):
    """Parse redis-cli INFO / nmap redis-info output."""
    findings = []
    port = _port_from_filename(file_path, default_port)
    version = None
    keyspaces = {}
    auth_required = False
    saw_info = False

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except FileNotFoundError:
        warn(f"[!] Error: Redis output file not found at {file_path}")
        return findings

    for raw_line in lines:
        line = ANSI_ESCAPE_PATTERN.sub("", raw_line).strip()
        if not line:
            continue
        if "NOAUTH Authentication required" in line or "Authentication required" in line:
            auth_required = True
        if line.startswith("#") or line.lower().startswith("redis_version:") or "redis-info" in line.lower():
            saw_info = True
        for pattern in _VERSION_PATTERNS:
            match = pattern.search(line)
            if match:
                version = match.group("version")
                saw_info = True
                break
        keyspace = _KEYSPACE.match(line)
        if keyspace:
            keyspaces[keyspace.group("db")] = _parse_keyspace_stats(keyspace.group("stats"))
            saw_info = True

    if version:
        findings.append({
            "host": target_host,
            "port": port,
            "source_tool": "redis-cli",
            "entity_type": "software_product",
            "name": "Redis",
            "version": version,
            "attributes": {"source_file": file_path, "search_name": "redis"},
        })

    if saw_info and not auth_required:
        total_keys = sum(v.get("keys", 0) for v in keyspaces.values() if isinstance(v, dict))
        findings.append({
            "host": target_host,
            "port": port,
            "source_tool": "redis-cli",
            "entity_type": "misconfiguration",
            "name": "redis_unauthenticated_info",
            "version": None,
            "attributes": {
                "description": "Redis INFO responded without authentication",
                "version": version,
                "keyspaces": keyspaces,
                "total_keys": total_keys,
                "confidence": "high" if version or keyspaces else "medium",
                "source_file": file_path,
            },
        })

    return findings
