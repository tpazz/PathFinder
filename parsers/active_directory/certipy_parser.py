import json
from parsers.ansi import warn
import re

# ESC technique identifiers certipy reports under a template's vulnerabilities.
_ESC_RE = re.compile(r"\bESC\d+\b", re.IGNORECASE)


def _flatten_principals(value):
    values = []
    if isinstance(value, str):
        candidate = value.strip()
        if candidate:
            values.append(candidate)
    elif isinstance(value, list):
        for item in value:
            values.extend(_flatten_principals(item))
    elif isinstance(value, dict):
        for key, nested in value.items():
            if isinstance(key, str) and ("\\" in key or "@" in key or " " in key):
                values.append(key.strip())
            values.extend(_flatten_principals(nested))
    return values


def _enrollment_principals(obj):
    """Collect Certipy v4/v5 enrollment-principal fields recursively."""
    principals = []
    if not isinstance(obj, dict):
        return principals
    for key, value in obj.items():
        normalized = re.sub(r"[^a-z]", "", str(key).lower())
        if "enrollableprincipals" in normalized or normalized == "enrollmentrights":
            for principal in _flatten_principals(value):
                if principal not in principals:
                    principals.append(principal)
        if isinstance(value, dict):
            for principal in _enrollment_principals(value):
                if principal not in principals:
                    principals.append(principal)
    return principals


def _find_vulnerabilities(obj):
    """Return the vulnerabilities mapping from a template/CA object, tolerating
    certipy's varied key spellings ('Vulnerabilities', '[!] Vulnerabilities')."""
    if not isinstance(obj, dict):
        return {}
    for key, value in obj.items():
        if "vulnerabilit" in key.lower() and isinstance(value, dict):
            return value
    return {}


def _iter_objects(section):
    """certipy nests entries either as a dict keyed by index or as a list."""
    if isinstance(section, dict):
        yield from section.values()
    elif isinstance(section, list):
        yield from section


def parse_certipy_json(file_path, target_host=None):
    """
    Parses certipy 'find' JSON output into AD CS privilege_escalation findings.

    Each ESC* vulnerability on a certificate template (or CA) becomes a finding
    named 'adcs_esc<N>' so per-technique attack rules can fire. Tolerant of
    certipy version differences in key naming and nesting.
    """
    findings = []
    try:
        with open(file_path, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
    except FileNotFoundError:
        warn(f"[!] Error: certipy JSON file not found at {file_path}")
        return findings
    except json.JSONDecodeError:
        warn(f"[!] Error: Could not decode JSON from '{file_path}'.")
        return findings

    if not isinstance(data, dict):
        return findings

    host = target_host or "UNKNOWN_DOMAIN"
    seen = set()

    # Walk both certificate templates and CAs; both can carry ESC vulnerabilities.
    sections = []
    for key, value in data.items():
        if "template" in key.lower() or "authorit" in key.lower() or key.lower() in {"cas", "ca"}:
            sections.append(value)

    for section in sections:
        for obj in _iter_objects(section):
            if not isinstance(obj, dict):
                continue
            name = (obj.get("Template Name") or obj.get("CA Name")
                    or obj.get("Name") or "unknown_template")
            vulns = _find_vulnerabilities(obj)
            for esc_key, description in vulns.items():
                esc_match = _ESC_RE.search(esc_key)
                esc_id = esc_match.group(0).upper() if esc_match else esc_key.strip().upper()
                identifier = (name, esc_id)
                if identifier in seen:
                    continue
                seen.add(identifier)
                if isinstance(description, list):
                    description = "; ".join(str(d) for d in description)
                findings.append({
                    "host": host, "port": None, "source_tool": "certipy",
                    "entity_type": "privilege_escalation", "name": f"adcs_{esc_id.lower()}", "version": None,
                    "attributes": {
                        "esc": esc_id,
                        "template": name,
                        "description": f"{esc_id} on '{name}': {description}",
                        "enabled": obj.get("Enabled"),
                        "enrollment_principals": _enrollment_principals(obj),
                    },
                })

    return findings
