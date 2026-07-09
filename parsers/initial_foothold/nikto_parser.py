import json
from parsers.ansi import warn
import re
from parsers.initial_foothold.web_url_helpers import parameterized_url_finding


NIKTO_CLASSIFICATION_RULES = [
    {"contains": ["directory indexing found"], "entity_type": "misconfiguration", "name": "directory_indexing_found"},
    {"contains": ["allowed http methods"], "entity_type": "information_leak", "name": "http_methods_revealed"},
    {"contains": ["a backup file was found", ".bak file found"], "entity_type": "web_content", "name": "__URL__", "attrs": {"potential_risk": "sensitive_backup_file"}},
    {"contains": ["robots.txt contains entries"], "entity_type": "web_content", "name": "/robots.txt", "attrs": {"potential_risk": "interesting_robots_txt"}},
]


def _classify_nikto_item(item):
    """
    Classifies a single Nikto vulnerability item into Pathfinder's entity types.
    This helper function contains the core logic for interpreting Nikto's text-based messages.

    Returns a tuple: (entity_type, name, version, additional_attributes)
    """
    msg = item.get('msg', '').lower()
    url = item.get('url', '')
    version = None

    # Priority 1: Explicitly identify a major software product like WordPress.
    if "wordpress" in msg:
        entity_type = "software_product"
        name = "WordPress"
        # Try to extract the version number from the message text.
        version_match = re.search(r'wordpress version ([\d\.]+)', msg)
        if version_match:
            version = version_match.group(1)
        return entity_type, name, version, {}

    # Sanitize the raw message to create a clean, snake_case name for the finding.
    sanitized_msg_name = re.sub(r'[^a-zA-Z0-9_]', '_', msg).strip('_') or "nikto_finding"

    # Config-driven baseline classification rules.
    for rule in NIKTO_CLASSIFICATION_RULES:
        if any(token in msg for token in rule.get("contains", [])):
            attrs = dict(rule.get("attrs", {}))
            name = url if rule.get("name") == "__URL__" else rule.get("name")
            if name == "http_methods_revealed" and ("put" in msg or "delete" in msg or "trace" in msg):
                return "misconfiguration", name, version, {"dangerous_methods_found": True}
            return rule.get("entity_type", "information_leak"), name, version, attrs

    # Classify findings based on keywords in the message.
    if "is outdated" in msg or "appears to be outdated" in msg:
        entity_type = "vulnerability"
        name = "outdated_software_" + sanitized_msg_name
        return entity_type, name, version, {}

    if "header is not defined" in msg or "header is not set" in msg:
        name = "missing_header_" + sanitized_msg_name.replace('_header_is_not_defined', '')
        return "misconfiguration", name, version, {}
    if "/config" in url or "/.env" in url:
        return "web_content", url, version, {"potential_risk": "potential_config_or_credential_file"}
    if "apache default file found" in msg or "default file found" in msg:
        return "web_content", url, version, {"potential_risk": "default_framework_file"}

    # Catch generic "interesting file" findings from Nikto.
    if "might be interesting" in msg and url:
        return "web_content", url, version, {}

    # If no specific rule matches, classify it as a general information leak.
    return "information_leak", sanitized_msg_name, version, {}


def _load_nikto_records(json_file_path):
    """Loads Nikto records from either NDJSON or a standard JSON array/object payload."""
    with open(json_file_path, 'r', encoding='utf-8-sig') as f:
        content = f.read().strip()

    if not content:
        return []

    # Try full JSON first (array or object).
    try:
        parsed = json.loads(content)
        if isinstance(parsed, list):
            return parsed
        if isinstance(parsed, dict):
            return [parsed]
    except json.JSONDecodeError:
        pass

    # Fallback: NDJSON mode.
    records = []
    for line in content.splitlines():
        if not line.strip():
            continue
        try:
            data = json.loads(line)
            if isinstance(data, dict):
                records.append(data)
        except json.JSONDecodeError:
            warn(f"[!] Warning: Skipping malformed JSON line in '{json_file_path}': {line[:100]}")
    return records


def parse_nikto_json(json_file_path):
    """
    Parses Nikto JSON output (handling JSON and JSON Lines formats) and extracts findings.
    """
    findings = []
    try:
        records = _load_nikto_records(json_file_path)

        for data in records:
            host = data.get('host') or "UNKNOWN_HOST"
            raw_port = data.get('port')
            try:
                port = int(raw_port) if raw_port is not None else 80
            except (ValueError, TypeError):
                port = 80

            # Iterate through the list of vulnerabilities found for the host.
            for item in data.get('vulnerabilities', []):
                # Classify each item to determine its entity_type and name.
                entity_type, name, version, additional_attributes = _classify_nikto_item(item)

                attributes = {
                    "nikto_id": item.get('id'),
                    "osvdb": item.get('osvdb'),
                    "method": item.get('method'),
                    "description": item.get('msg'),
                    "references": item.get('references'),
                    "url_path_nikto": item.get('url')  # Store the specific URL path for context.
                }
                attributes.update(additional_attributes)

                finding = {
                    "host": host,
                    "port": port,
                    "source_tool": "nikto",
                    "entity_type": entity_type,
                    "name": name,
                    "version": version,
                    "attributes": attributes
                }
                findings.append(finding)
                param_finding = parameterized_url_finding(
                    host, port, "nikto", item.get('url'), name
                )
                if param_finding:
                    findings.append(param_finding)

    except FileNotFoundError:
        warn(f"[!] Error: Nikto JSON file not found at {json_file_path}")
    except Exception as e:
        warn(f"[!] An unexpected error occurred while parsing Nikto JSON: {e}")

    return findings
