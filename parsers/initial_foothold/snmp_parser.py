import re

from parsers.ansi import ANSI_ESCAPE_PATTERN

# Canonical section headers and their aliases (for variant snmp-check versions).
SECTION_HEADER_MAP = {
    "system information:": "System information:",
    "user accounts:": "User accounts:",
    "running processes:": "Running processes:",
    "processes:": "Running processes:",
    "network interfaces:": "Network interfaces:",
}

# Strip common prefixes like "[*] " or "## " from snmp-check output.
_SECTION_PREFIX = re.compile(r'^(?:\[\*\]\s*|#+\s*)')


def _normalize_section_header(line):
    """Check if a line is a section header (with or without [*] prefix). Returns canonical name or None."""
    stripped = _SECTION_PREFIX.sub('', line).strip()
    return SECTION_HEADER_MAP.get(stripped.lower())


def _extract_sections(content):
    sections = {}
    current = None
    lines = []

    for raw_line in content.splitlines():
        line = raw_line.rstrip()
        canonical = _normalize_section_header(line)
        if canonical:
            if current is not None:
                sections[current] = "\n".join(lines).strip()
            current = canonical
            lines = []
            continue

        if current is not None:
            # Keep blank lines inside section only if meaningful context exists.
            if line or lines:
                lines.append(line)

    if current is not None:
        sections[current] = "\n".join(lines).strip()

    return sections


def parse_snmp_output(file_path, target_host):
    """
    Parses the output of snmp-check to find interesting information.

    Args:
        file_path (str): Path to the snmp-check output text file.
        target_host (str): The IP of the target host.

    Returns:
        list: A list of finding dictionaries.
    """
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"[!] Error: SNMP output file not found at {file_path}")
        return findings
    except Exception as e:
        print(f"[!] An unexpected error occurred while parsing SNMP: {e}")
        return []

    sanitized_content = ANSI_ESCAPE_PATTERN.sub('', content)
    sections = _extract_sections(sanitized_content)

    system_info = sections.get("System information:")
    if system_info:
        findings.append({
            "host": target_host, "port": 161, "source_tool": "snmp",
            "entity_type": "os_details",
            "name": "snmp_system_information",
            "version": None,
            "attributes": {"description": system_info}
        })

    user_accounts = sections.get("User accounts:")
    if user_accounts:
        for user_line in user_accounts.split('\n'):
            user = user_line.strip()
            if not user:
                continue
            findings.append({
                "host": target_host, "port": 161, "source_tool": "snmp",
                "entity_type": "user",
                "name": user,
                "version": None,
                "attributes": {"source": "SNMP enumeration"}
            })

    processes = sections.get("Running processes:")
    if processes:
        for process_line in processes.split('\n'):
            line = process_line.strip()
            if not line:
                continue
            # Keep full process text and use executable/binary tail as name when possible.
            tokens = line.split()
            process_name = tokens[-1].split('/')[-1] if tokens else "unknown_process"
            findings.append({
                "host": target_host, "port": 161, "source_tool": "snmp",
                "entity_type": "software_product",
                "name": process_name,
                "version": None,
                "attributes": {"description": line, "source": "SNMP enumeration"}
            })

    interfaces = sections.get("Network interfaces:")
    if interfaces:
        findings.append({
            "host": target_host, "port": 161, "source_tool": "snmp",
            "entity_type": "information_leak",
            "name": "snmp_network_interfaces_disclosed",
            "version": None,
            "attributes": {"details": interfaces}
        })

    return findings
