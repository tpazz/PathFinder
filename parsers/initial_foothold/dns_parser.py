"""Parse bounded dig output into DNS records and hostname candidates."""

import ipaddress
import re

from parsers.ansi import ANSI_ESCAPE_PATTERN, warn


MAX_DNS_OUTPUT_CHARS = 2_000_000
MAX_DNS_FINDINGS = 2_000
_ANSWER = re.compile(
    r"^\s*(?P<owner>\S+)\s+(?P<ttl>\d+)\s+(?P<class>IN)\s+"
    r"(?P<type>A|AAAA|CNAME|NS|MX|SRV|PTR|TXT)\s+(?P<value>.+?)\s*$",
    re.IGNORECASE,
)
_HOST_TYPES = {"A", "AAAA", "CNAME", "NS", "MX", "SRV", "PTR"}


def _clean_name(value):
    value = str(value or "").strip().strip('"').rstrip(".").lower()
    if not value or len(value) > 253 or " " in value:
        return None
    return value


def _target_from_record(record_type, value):
    parts = value.split()
    if not parts:
        return None
    if record_type in {"MX", "SRV", "CNAME", "NS", "PTR"}:
        return _clean_name(parts[-1])
    if record_type in {"A", "AAAA"}:
        try:
            return str(ipaddress.ip_address(parts[0]))
        except ValueError:
            return None
    return None


def parse_dns_output(path, target_host=None):
    findings = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            content = handle.read(MAX_DNS_OUTPUT_CHARS + 1)[:MAX_DNS_OUTPUT_CHARS]
    except OSError as exc:
        warn(f"[!] Error: Could not read DNS output '{path}': {exc}")
        return findings

    seen_records = set()
    seen_names = set()
    for raw_line in ANSI_ESCAPE_PATTERN.sub("", content).splitlines():
        if len(findings) >= MAX_DNS_FINDINGS:
            break
        line = raw_line.strip()
        if not line or line.startswith((";", "#")):
            continue
        match = _ANSWER.match(line)
        if not match:
            continue
        owner = _clean_name(match.group("owner"))
        record_type = match.group("type").upper()
        value = match.group("value").strip()
        if not owner:
            continue
        identifier = (owner, record_type, value.lower())
        if identifier in seen_records:
            continue
        seen_records.add(identifier)
        target = _target_from_record(record_type, value)
        findings.append({
            "host": target_host or owner,
            "port": 53,
            "source_tool": "dig",
            "entity_type": "dns_record",
            "name": owner,
            "version": None,
            "attributes": {
                "record_type": record_type,
                "value": value,
                "target": target,
                "ttl": int(match.group("ttl")),
                "discovery_source": str(path),
            },
        })

        candidates = [owner]
        if record_type in _HOST_TYPES and target:
            candidates.append(target)
        for candidate in candidates:
            try:
                ipaddress.ip_address(candidate)
                continue
            except ValueError:
                pass
            if "." not in candidate or candidate in seen_names:
                continue
            seen_names.add(candidate)
            findings.append({
                "host": target_host or owner,
                "port": 53,
                "source_tool": "dig",
                "entity_type": "hostname_candidate",
                "name": candidate,
                "version": None,
                "attributes": {
                    "hostname": candidate,
                    "record_type": record_type,
                    "record_owner": owner,
                    "record_value": value,
                    "confidence": "high",
                    "requires_manual_validation": True,
                    "discovery_source": str(path),
                },
            })
    return findings
