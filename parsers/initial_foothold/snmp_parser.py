import re

from parsers.ansi import ANSI_ESCAPE_PATTERN, warn

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

# --- Credential leakage from process arguments and NET-SNMP-EXTEND-MIB output ---
# SNMP frequently discloses full process command lines (snmp-check "Running
# processes:") and arbitrary command output (snmpwalk NET-SNMP-EXTEND-MIB), both of
# which routinely leak credentials. See the OSCP notes on SNMP enumeration.

# Explicit, low-false-positive patterns - always applied. The (?:^|[^a-zA-Z]) guard
# lets these match env-style keys like DB_PASSWORD=... while rejecting substrings
# such as "compass=" or "bypass=".
_EXPLICIT_CRED_PATTERNS = (
    re.compile(r'--password(?:=|\s+)(?P<pw>[^\s\'"]{1,})', re.IGNORECASE),
    re.compile(r'(?:^|[^a-zA-Z])(?:password|passwd|pwd|pass)\s*[=:]\s*(?P<pw>[^\s\'"]{2,})', re.IGNORECASE),
    re.compile(r'\bsshpass\s+-p\s*(?P<pw>[^\s\'"]{1,})'),
)
# user:pass@host connection strings, e.g. mysql://root:S3cret@db, ftp://u:p@host.
_CONNSTRING_PATTERN = re.compile(r'://(?P<user>[^:/\s]+):(?P<pw>[^@/\s]+)@')
# smbclient/impacket -U user%pass and curl/wget -u user:pass.
_SMB_PATTERN = re.compile(r'-U\s+(?P<user>[^\s%\'"]+)%(?P<pw>[^\s\'"]+)')
_USERPASS_FLAG_PATTERN = re.compile(r'-u\s+(?P<user>[^\s:\'"]+):(?P<pw>[^\s\'"]+)')
# mysql-style -u<user> / -p<pass> (no space) - only trusted for known DB/auth
# client binaries, because -p means many different things to other tools (nmap -p80).
_DB_AUTH_BINARIES = (
    "mysql", "mysqladmin", "mysqldump", "mariadb", "psql", "mongo", "mongosh",
    "redis-cli", "sqlcmd", "sqlplus", "sshpass",
)
_DB_SHORT_PW_PATTERN = re.compile(r'\s-[pP](?P<pw>[^\s\'"]{1,})')
_DB_SHORT_USER_PATTERN = re.compile(r'\s-u(?P<user>[^\s\'"]{2,})')
_USER_PATTERN = re.compile(
    r'(?:--user(?:name)?(?:=|\s+)|\s-u\s+)(?P<user>[^\s\'"%]{1,})', re.IGNORECASE)
# NET-SNMP-EXTEND-MIB command-output lines (snmpwalk).
_EXTEND_PATTERN = re.compile(
    r'(?:NET-SNMP-EXTEND-MIB::nsExtendOutput\S*|nsExtendOutput\S*)\s*=\s*STRING:\s*(?P<val>.*)',
    re.IGNORECASE)
# Reject obvious non-secrets / redactions.
_JUNK_SECRET = re.compile(r'^(?:[*x]+|<[^>]+>|null|none|password|empty)$', re.IGNORECASE)


def _looks_like_secret(value):
    value = (value or "").strip().strip('\'"')
    return bool(value) and len(value) >= 2 and not _JUNK_SECRET.match(value)


def _scan_text_for_credentials(text, host, source_label):
    """Extract credentials from a command line / command-output string. Returns a
    list of credential findings (deduped within this text)."""
    findings = []
    seen = set()
    tokens = text.split()
    # snmp-check prefixes process lines with PID/columns, so check every token, not
    # just the first, when deciding whether a DB/auth client is in play.
    db_binary = any(tok.split('/')[-1].lower() in _DB_AUTH_BINARIES for tok in tokens)

    user_match = _USER_PATTERN.search(text)
    default_user = user_match.group("user") if user_match else None
    if default_user is None and db_binary:
        short_user = _DB_SHORT_USER_PATTERN.search(text)
        default_user = short_user.group("user") if short_user else None

    def add(username, password):
        password = (password or "").strip().strip('\'"')
        if not _looks_like_secret(password):
            return
        key = ((username or "").lower(), password)
        if key in seen:
            return
        seen.add(key)
        findings.append({
            "host": host, "port": 161, "source_tool": "snmp",
            "entity_type": "credential",
            "name": username or "snmp_disclosed_credential",
            "version": None,
            "attributes": {
                "username": username,
                "password": password,
                "source_of_credential": source_label,
                "evidence": text.strip()[:300],
            },
        })

    for pattern in _EXPLICIT_CRED_PATTERNS:
        for m in pattern.finditer(text):
            add(default_user, m.group("pw"))
    for m in _CONNSTRING_PATTERN.finditer(text):
        add(m.group("user"), m.group("pw"))
    for m in _SMB_PATTERN.finditer(text):
        add(m.group("user"), m.group("pw"))
    for m in _USERPASS_FLAG_PATTERN.finditer(text):
        add(m.group("user"), m.group("pw"))
    if db_binary:
        for m in _DB_SHORT_PW_PATTERN.finditer(text):
            add(default_user, m.group("pw"))

    return findings


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
        warn(f"[!] Error: SNMP output file not found at {file_path}")
        return findings
    except Exception as e:
        warn(f"[!] An unexpected error occurred while parsing SNMP: {e}")
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
                "entity_type": "confirmed_username",
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
            # A trailing snmpwalk/MIB line can get swept into this section when no
            # further snmp-check header follows it; it is not a process - the extend
            # pass below handles it, so don't emit a bogus software_product/cred here.
            if "::" in line or "STRING:" in line:
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
            # Process command lines routinely leak credentials in their arguments.
            findings.extend(_scan_text_for_credentials(line, target_host, "SNMP process arguments"))

    # NET-SNMP-EXTEND-MIB output (snmpwalk): arbitrary command output exposed over
    # SNMP. Surface it as an info leak and scan the output itself for credentials.
    for match in _EXTEND_PATTERN.finditer(sanitized_content):
        output = match.group("val").strip().strip('"')
        if not output:
            continue
        findings.append({
            "host": target_host, "port": 161, "source_tool": "snmp",
            "entity_type": "information_leak",
            "name": "snmp_extend_output_disclosed",
            "version": None,
            "attributes": {"details": output[:500], "source": "NET-SNMP-EXTEND-MIB"}
        })
        findings.extend(_scan_text_for_credentials(output, target_host, "SNMP NET-SNMP-EXTEND-MIB output"))

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
