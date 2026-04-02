import re
from urllib.parse import urlparse

from parsers.ansi import ANSI_ESCAPE_PATTERN


def _split_target_blocks(content):
    """Split sqlmap output into per-target blocks based on testing or target URL lines."""
    # Try the standard pattern first: [INFO] testing 'URL'
    starts = list(re.finditer(r"\[INFO\] testing '(\S+)'", content))

    # Fallback: look for target URL patterns used in other sqlmap log formats.
    if not starts:
        starts = list(re.finditer(r"\[INFO\] testing connection to the target URL '(\S+)'", content))
    if not starts:
        starts = list(re.finditer(r"Target URL:\s*(\S+)", content))

    # Try to extract the URL from vulnerable parameter lines as a last resort.
    if not starts:
        url_match = re.search(r"URL:\s*'?(\S+?)'?\s", content)
        if url_match:
            return [(url_match.group(1), content)]
        return [("http://UNKNOWN_HOST", content)]

    blocks = []
    for i, match in enumerate(starts):
        target_url = match.group(1)
        start_idx = match.start()
        end_idx = starts[i + 1].start() if i + 1 < len(starts) else len(content)
        blocks.append((target_url, content[start_idx:end_idx]))
    return blocks


def parse_sqlmap_log(file_path):
    """
    Parses a sqlmap log file to find confirmed injectable parameters.

    Args:
        file_path (str): Path to the sqlmap 'log' file from its output directory.

    Returns:
        list: A list of 'vulnerability' finding dictionaries for each injectable parameter.
    """
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"[!] Error: sqlmap log file not found at {file_path}")
        return findings
    except Exception as e:
        print(f"[!] An unexpected error occurred while parsing sqlmap log: {e}")
        return []

    sanitized_content = ANSI_ESCAPE_PATTERN.sub('', content)
    vuln_pattern = re.compile(r"\[INFO\] (\w+) parameter '([^']+)' is vulnerable")

    for target_url, block in _split_target_blocks(sanitized_content):
        dbms_match = re.search(r"back-end DBMS is '([^']+)'", block)
        dbms = dbms_match.group(1) if dbms_match else None

        technique_match = re.search(r"following injection techniques are supported: (.*)", block)
        technique = technique_match.group(1).strip() if technique_match else None

        risk_match = re.search(r"risk level: (\d+)", block, re.IGNORECASE)
        level_match = re.search(r"level: (\d+)", block, re.IGNORECASE)

        payload_match = re.search(r"Payload:\s*(.*)", block)
        payload = payload_match.group(1).strip() if payload_match else None

        vulnerable_params = vuln_pattern.findall(block)

        try:
            parsed_url = urlparse(target_url)
            host = parsed_url.hostname or "UNKNOWN_HOST"
            port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
        except (ValueError, AttributeError):
            host = "UNKNOWN_HOST"
            port = 0

        for method, parameter_name in vulnerable_params:
            findings.append({
                "host": host,
                "port": port,
                "source_tool": "sqlmap",
                "entity_type": "vulnerability",
                "name": "sql_injection_found",
                "version": None,
                "attributes": {
                    "url": target_url,
                    "parameter": parameter_name,
                    "method": method,
                    "dbms": dbms,
                    "technique": technique,
                    "risk": int(risk_match.group(1)) if risk_match else None,
                    "level": int(level_match.group(1)) if level_match else None,
                    "payload_snippet": payload,
                    "description": f"SQL Injection confirmed in '{parameter_name}' parameter via {method} request."
                }
            })

    return findings
