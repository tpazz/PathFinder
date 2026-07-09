import argparse
import sys
import json
import os
import re
import logging
import xml.etree.ElementTree as ET

# Import the core logic components and the single parser registry.
from .attack_path_synthesizer import AttackPathSynthesizer
from .vulnerability_mapper import VulnerabilityMapper
from .finding_schema import FindingValidationError, validate_and_normalize_finding, validate_findings
from .parser_registry import PARSER_SPECS, SPEC_BY_KEY, HOST_REQUIRED_KEYS, ParserContext

# ANSI color codes for formatted output (TTY-aware; togglable via --no-color)
from parsers.ansi import C, set_color_enabled, should_enable_color

# Build a full, unambiguous path to the credentials file relative to this script's location.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CREDENTIALS_FILE = os.path.join(SCRIPT_DIR, "credentials.json")

# OSCP exam profile: tools restricted on the exam. Prohibited tools (sqlmap,
# nuclei) are stripped from suggested commands and flagged on ingestion; the lead
# itself is kept. Metasploit is allowed but only against one target, so it is
# flagged with a reminder rather than removed.
OSCP_PROHIBITED_TOKENS = ("sqlmap", "nuclei")
OSCP_METASPLOIT_TOKENS = ("metasploit", "meterpreter", "msfconsole", "msfvenom", "exploit/")
# Auto-detected parser keys whose source tool is prohibited (for ingestion warnings).
OSCP_PROHIBITED_PARSER_KEYS = {"sqlmap_log": "sqlmap", "nuclei_jsonl": "nuclei"}


def _oscp_process_commands(commands):
    """Under the OSCP profile, replace prohibited-tool commands with a manual-exploitation
    note (keeping the lead) and report whether any Metasploit usage is present.

    Returns (processed_commands, uses_metasploit).
    """
    processed = []
    uses_msf = False
    for cmd in commands:
        low = cmd.lower()
        prohibited = next((t for t in OSCP_PROHIBITED_TOKENS if t in low), None)
        if prohibited:
            note = f"[OSCP] {prohibited} is restricted on the exam - perform this step manually."
            if note not in processed:  # collapse repeated notes for the same tool
                processed.append(note)
            continue
        if any(t in low for t in OSCP_METASPLOIT_TOKENS):
            uses_msf = True
        processed.append(cmd)
    return processed, uses_msf

LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s - %(message)s"
logger = logging.getLogger("pathfinder")


def configure_logging(verbosity):
    """Configures logger level based on CLI verbosity."""
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG
    logging.basicConfig(level=level, format=LOG_FORMAT)


def print_banner():
    """Prints a cool banner for the tool."""
    banner = f"""
{C.RED}__________         __  .__    ___________.__            .___
\\______   \\_____ _/  |_|  |__ \\_   _____/|__| ____    __| _/___________
 |     ___/\\__  \\\\   __\\  |  \\ |    __)  |  |/    \\  / __ |/ __ \\_  __ \\
 |    |     / __ \\|  | |   Y  \\|     \\   |  |   |  \\/ /_/ \\  ___/|  | \\/
 |____|    (____  /__| |___|  /\\___  /   |__|___|  /\\____ |\\___  >__|
                \\/          \\/     \\/            \\/      \\/    \\/
{C.END}
  {C.BOLD}{C.YELLOW}>> [Intelligent Reconnaissance Analysis for Pentesters] <<{C.END}
  {C.BOLD}{C.YELLOW}         >> [By {C.END}{C.BOLD}{C.RED}tpazz {C.END}{C.BOLD}{C.YELLOW}-{C.END}{C.BOLD}{C.GREEN} Green Lemon Company{C.END}{C.BOLD}{C.YELLOW}] << {C.END}
"""
    print(banner)


def format_finding_display(name, entity_type):
    """Applies color formatting to the name and entity_type of a finding."""
    display_name = name
    if "EDB-ID" in display_name: display_name = display_name.replace("EDB-ID", f"{C.BOLD}{C.RED}EDB-ID{C.END}")
    if "GitHub Exploit" in display_name: display_name = display_name.replace("GitHub Exploit", f"{C.BOLD}{C.GREEN}GitHub Exploit{C.END}")
    if entity_type == "privilege_escalation": display_type = f"({C.BOLD}{C.RED}{entity_type}{C.END})"
    elif entity_type == "web_content": display_type = f"({C.LIGHT_BLUE}{entity_type}{C.END})"
    elif entity_type == "misconfiguration": display_type = f"({C.YELLOW}{entity_type}{C.END})"
    elif entity_type == "vulnerability" and "sql" in name: display_type = f"({C.BOLD}{C.RED}{entity_type}{C.END})"
    else: display_type = f"({C.YELLOW}{entity_type}{C.END})"
    return display_name, display_type


def filter_prioritized_findings(findings, max_vulns):
    """Filters the list of prioritized findings to limit the number of EDB/GitHub results."""
    edb, github, other = [], [], []
    for f in findings:
        source = f.get("source_tool")
        if source == "searchsploit_mapper": edb.append(f)
        elif source == "github_exploit_mapper": github.append(f)
        else: other.append(f)
    edb.sort(key=lambda x: x.get("attributes", {}).get("score", 0), reverse=True)
    github.sort(key=lambda x: x.get("attributes", {}).get("score", 0), reverse=True)
    return other + edb[:max_vulns] + github[:max_vulns]


# Credential secret material. When the same identity appears twice (e.g. once with
# a cleartext password, once with an NTLM hash), we merge these fields instead of
# dropping the later finding, so a pass-the-hash *and* a password-spray path survive.
_CREDENTIAL_SECRET_FIELDS = (
    "password", "hash", "nt_hash", "lm_hash", "ntlm_hash", "aes256_key",
    "aes128_key", "kerberos_key", "private_key", "secret", "hash_type",
)

# Credential "names" that are placeholders for an unknown principal - a secret was
# disclosed but no username was recovered (e.g. an SNMP-leaked password). These must
# not collapse by name: two distinct disclosed secrets on one host are two leads.
_ANONYMOUS_CREDENTIAL_NAMES = {"snmp_disclosed_credential", "cracked_disclosed_credential"}


def _dedup_key(finding):
    """Identity used to collapse duplicates. Credentials key on host+user+domain
    (not port/secret) so the same identity from different tools merges; everything
    else keeps the classic host+port+name+type key.

    Identity-less credentials (a secret disclosed with no known principal, e.g. an
    SNMP-leaked password) are the exception: they key on the secret itself, so two
    distinct leaked secrets on one host stay two leads instead of collapsing into
    one (which would silently drop all but the first)."""
    entity_type = finding.get("entity_type")
    if entity_type == "credential":
        attrs = finding.get("attributes") or {}
        name = (finding.get("name") or "").lower()
        domain = (attrs.get("domain") or "").lower()
        if name in _ANONYMOUS_CREDENTIAL_NAMES or not name:
            secret = next((str(attrs[f]) for f in _CREDENTIAL_SECRET_FIELDS if attrs.get(f)), name)
            return ("credential", finding.get("host"), name, domain, secret)
        return ("credential", finding.get("host"), name, domain)
    return (finding.get("host"), finding.get("port"), finding.get("name"), entity_type)


def _merge_provenance(kept, duplicate):
    """Record that another tool/file corroborated the same finding (no data lost)."""
    kept_attrs = kept.setdefault("attributes", {})
    dup_attrs = duplicate.get("attributes") or {}

    sources = kept_attrs.get("corroborating_sources")
    if not isinstance(sources, list):
        sources = [kept.get("source_tool")] if kept.get("source_tool") else []
    dup_tool = duplicate.get("source_tool")
    if dup_tool and dup_tool not in sources:
        sources.append(dup_tool)
    if len(sources) > 1:
        kept_attrs["corroborating_sources"] = sources

    files = kept_attrs.get("source_files")
    if not isinstance(files, list):
        files = [kept_attrs["source_file"]] if kept_attrs.get("source_file") else []
    dup_file = dup_attrs.get("source_file")
    if dup_file and dup_file not in files:
        files.append(dup_file)
    if len(files) > 1:
        kept_attrs["source_files"] = files


def _merge_credential(kept, duplicate):
    """Merge a duplicate credential into the kept one: fill in any missing secret
    material and attributes (never overwrite an existing value), keep the max score,
    and record provenance."""
    kept_attrs = kept.setdefault("attributes", {})
    dup_attrs = duplicate.get("attributes") or {}
    for field, value in dup_attrs.items():
        if field in ("score", "source_file", "corroborating_sources", "source_files"):
            continue
        if value in (None, "") or kept_attrs.get(field) not in (None, ""):
            continue
        kept_attrs[field] = value
    dup_score = dup_attrs.get("score")
    if isinstance(dup_score, (int, float)):
        kept_attrs["score"] = max(kept_attrs.get("score") or 0, dup_score)
    _merge_provenance(kept, duplicate)


def deduplicate_findings(findings_list):
    """Collapse duplicate findings, merging rather than dropping: credentials merge
    their secret material (password + hash for one identity), and all findings merge
    corroborating tool/file provenance."""
    seen = {}
    unique_findings = []
    for finding in findings_list:
        key = _dedup_key(finding)
        kept = seen.get(key)
        if kept is None:
            seen[key] = finding
            unique_findings.append(finding)
        elif finding.get("entity_type") == "credential":
            _merge_credential(kept, finding)
        else:
            _merge_provenance(kept, finding)
    return unique_findings


def validate_parser_output(parser_name, findings):
    """Validate parser output per finding: keep the valid records, warn with counts,
    and skip only the malformed ones. Tool output drifts; one bad record must not
    discard an entire parser's results."""
    if not isinstance(findings, list):
        print(f"{C.BOLD}{C.YELLOW}[!] {parser_name} parser did not return a list; skipping.{C.END}")
        return []
    valid = []
    dropped = 0
    for finding in findings:
        try:
            valid.append(validate_and_normalize_finding(finding))
        except FindingValidationError as e:
            dropped += 1
            if dropped <= 3:  # show a few examples, then just count
                print(f"{C.BOLD}{C.YELLOW}[!] {parser_name}: skipping malformed finding: {e}{C.END}")
    if dropped:
        print(f"{C.BOLD}{C.YELLOW}[!] {parser_name}: kept {len(valid)} valid finding(s), "
              f"dropped {dropped} malformed.{C.END}")
    return valid


def manage_credentials():
    """Provides an interactive wizard for users to add credentials they have found."""
    print(f"\n{C.BOLD}{C.CYAN}[*] Pathfinder Credential Manager{C.END}")
    creds = []
    if os.path.exists(CREDENTIALS_FILE):
        try:
            with open(CREDENTIALS_FILE, 'r') as f:
                content = f.read()
                if content: creds = json.loads(content)
        except json.JSONDecodeError:
            print(f"{C.BOLD}{C.YELLOW}[!] Warning: {CREDENTIALS_FILE} is corrupted. Starting fresh.{C.END}")

    print(f"    [+] Found {len(creds)} existing credentials.")

    try:
        while True:
            print("\n--- Adding a New Credential ---")
            username = input(" > Enter username (or press Enter to finish): ").strip()
            if not username: break
            cred_type = input(" > Is this a [p]assword or a [h]ash? [p]: ").strip().lower() or 'p'

            password, hash_val, hash_type = None, None, None
            if cred_type == 'p':
                password = input(" > Enter password: ").strip()
            elif cred_type == 'h':
                hash_val = input(" > Enter full hash: ").strip()
                hash_type = input(" > Enter hash type (e.g., NTLM, Kerberos AS-REP (18200)): ").strip()
            else:
                print(f"{C.BOLD}{C.YELLOW}[!] Invalid type. Skipping.{C.END}"); continue

            source = input(" > Where did you find this credential? (e.g., 'config.php.bak'): ").strip()
            creds.append({"username": username, "password": password, "hash": hash_val, "hash_type": hash_type, "source": source})
            print(f"    {C.BOLD}{C.GREEN}[+] Credential for '{username}' added.{C.END}")
    except KeyboardInterrupt:
        print(f"\n{C.BOLD}{C.YELLOW}[!] User interrupted credential entry.{C.END}")

    try:
        with open(CREDENTIALS_FILE, 'w') as f: json.dump(creds, f, indent=4)
        print(f"\n{C.BOLD}{C.CYAN}[*] {len(creds)} total credentials saved to {CREDENTIALS_FILE}.{C.END}")
    except IOError as e:
        print(f"\n{C.BOLD}{C.YELLOW}[!] Error saving credentials: {e}{C.END}")


def load_base_findings(input_json_path):
    """Loads and validates pre-existing prioritized findings from disk."""
    if not input_json_path:
        return []
    print(f"\n{C.BOLD}{C.CYAN}[*] Loading base findings from file: {input_json_path}{C.END}")
    with open(input_json_path, 'r', encoding='utf-8') as f:
        loaded_findings = json.load(f)
    validated = validate_parser_output("input-json", loaded_findings)
    print(f"    [+] Loaded {len(validated)} valid base findings.")
    logger.info("Loaded %s base findings from %s", len(validated), input_json_path)
    return validated


def parse_new_data_files(args, target_host):
    """Runs configured parsers (driven by PARSER_SPECS) and returns validated raw findings."""
    if not any(getattr(args, spec.key, None) for spec in PARSER_SPECS):
        return []

    print(f"\n{C.BOLD}{C.CYAN}[*] Parsing new data files...{C.END}")

    ctx = ParserContext(
        target_host=target_host,
        gobuster_host=target_host,
        gobuster_port=args.gobuster_port,
        gobuster_mode=args.gobuster_mode,
    )

    findings = []
    for spec in PARSER_SPECS:
        file_path = getattr(args, spec.key, None)
        if not file_path:
            continue
        if spec.host_required and not target_host:
            print(f"{C.BOLD}{C.YELLOW}[!] {spec.key} parser requires --target-host (or domain) to be set.{C.END}")
            logger.warning("Skipped %s parser because --target-host is not set", spec.key)
            continue
        if args.verbose > 0:
            print(f"[*] Parsing {spec.key}: {file_path}")
        findings_from_parser = spec.run(file_path, ctx)
        validated_findings = validate_parser_output(spec.key, findings_from_parser)
        findings.extend(validated_findings)
        logger.info("Parser %s produced %s validated findings", spec.key, len(validated_findings))
        if args.verbose > 0:
            print(f"    [+] Found {len(validated_findings)} valid raw findings from {spec.key}.")

    return findings


def map_findings(args, new_raw_findings):
    """Runs vulnerability mapping/prioritization for new findings."""
    if not new_raw_findings:
        return []
    print(f"\n{C.BOLD}{C.CYAN}[*] Running Vulnerability Mapper on new findings...{C.END}")
    use_github = not (args.offline or args.skip_github)
    use_searchsploit = not (args.offline or args.skip_searchsploit)
    vuln_mapper = VulnerabilityMapper(
        use_github=use_github,
        use_searchsploit=use_searchsploit,
        github_cache_file=args.github_cache,
    )
    newly_prioritized_findings = vuln_mapper.map_and_prioritize(new_raw_findings)
    logger.info("Mapper prioritized %s findings", len(newly_prioritized_findings))
    if args.verbose > 0:
        print(f"    {C.GREEN}[+]{C.END} Mapper prioritized {len(newly_prioritized_findings)} of the new findings.")
    return newly_prioritized_findings


# ── Auto-detect helpers ────────────────────────────────────────────────────────

_SMTP_USER_ENUM_LINE = re.compile(
    r"(?mi)^\s*(?:[0-9a-fA-F:.]+|[A-Za-z0-9_.-]+\.[A-Za-z0-9_.-]+):\s+"
    r"(?:exists:\s*[A-Za-z0-9._%+-]+|[A-Za-z0-9._%+-]+\s+exists|"
    r"VALID\s+USER(?:NAME)?:\s*[A-Za-z0-9._%+-]+|25[0-2]\b[^\n]*<[A-Za-z0-9._%+-]+@)"
)


def _looks_like_smtp_user_enum(sanitized_head, basename):
    lower_head = sanitized_head.lower()
    if "smtp-user-enum" in lower_head:
        return True
    if _SMTP_USER_ENUM_LINE.search(sanitized_head):
        return True
    if basename.startswith("smtp_user_enum_"):
        return bool(re.search(
            r"(?mi)(?:exists:\s*[A-Za-z0-9._%+-]+|[A-Za-z0-9._%+-]+\s+exists|"
            r"VALID\s+USER(?:NAME)?:\s*[A-Za-z0-9._%+-]+|25[0-2]\b[^\n]*<[A-Za-z0-9._%+-]+@)",
            sanitized_head,
        ))
    return False


def _sniff_file_type_details(path):
    """
    Reads the first ~3KB of a file and returns (parser_key, reason).
    Detection is content-based, not extension-based.
    """
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            head = f.read(3072)
    except (IOError, OSError) as e:
        return None, f"unreadable file: {e}"

    # Make detection resilient to ANSI-colored captures and UTF-8 BOMs.
    sanitized_head = re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', head).lstrip('\ufeff')
    stripped = sanitized_head.lstrip()

    if not stripped:
        return None, "empty or whitespace-only content"

    # XML -> nmap
    if stripped.startswith('<'):
        if '<nmaprun' in sanitized_head or 'nmaprun' in sanitized_head[:300]:
            return 'nmap_xml', 'matched nmap XML signature'
        return None, 'XML-like content but no supported XML parser signature'

    # JSON formats. Be careful not to misclassify plain-text logs that start
    # with bracketed tokens like [INFO], [*], or [+].
    if stripped.startswith('{') or re.match(r'^\[\s*[{"]', stripped):
        # one-shot-enum LLM/AI enumeration output (self-identifying).
        if '"ai_surfaces"' in sanitized_head or '"type": "llm_enum"' in sanitized_head or '"type":"llm_enum"' in sanitized_head:
            return 'llm_enum_json', 'matched one-shot-enum LLM enum signature'
        # nuclei JSONL: one JSON object per line, before the broad checks below.
        if '"template-id"' in sanitized_head or '"matched-at"' in sanitized_head:
            return 'nuclei_jsonl', 'matched nuclei JSONL signature'
        if '"vulnerabilities"' in sanitized_head and '"msg"' in sanitized_head:
            return 'nikto_json', 'matched Nikto JSON signature'
        # certipy 'find' output.
        if '"Certificate Templates"' in sanitized_head or '"Certificate Authorities"' in sanitized_head:
            return 'certipy_json', 'matched certipy find JSON signature'
        # wpscan: check before whatweb because both carry a "plugins" key.
        if '"target_url"' in sanitized_head and (
                '"interesting_findings"' in sanitized_head or '"effective_url"' in sanitized_head or '"plugins"' in sanitized_head):
            return 'wpscan_json', 'matched wpscan JSON signature'
        # ffuf: results[] plus its commandline/config envelope.
        if '"results"' in sanitized_head and ('"commandline"' in sanitized_head or '"config"' in sanitized_head):
            return 'ffuf_json', 'matched ffuf JSON signature'
        if '"plugins"' in sanitized_head or '"WhatWeb-version"' in sanitized_head:
            return 'whatweb_json', 'matched WhatWeb JSON signature'
        if '"users"' in sanitized_head and ('"groups"' in sanitized_head or '"shares"' in sanitized_head or '"policy"' in sanitized_head):
            return 'enum4linux_json', 'matched enum4linux-ng JSON signature'
        # SharpHound individual files are handled at the directory level; skip here
        return None, 'JSON-like content but no supported top-level JSON parser signature'

    # Plain-text formats (order matters; more specific patterns first)
    basename = os.path.basename(path).lower()
    if basename.endswith(".pot") and re.search(r'(?m)^.+:.+$', sanitized_head):
        return 'potfile_txt', 'matched john/hashcat potfile extension and hash:plaintext shape'
    if re.search(r'VALID\s+USERNAME', sanitized_head, re.IGNORECASE):
        return 'kerbrute_txt', 'matched Kerbrute valid username signature'
    if '$krb5tgs$' in sanitized_head:
        return 'getuserspns_hashes', 'matched GetUserSPNs TGS-REP hash signature'
    if '$krb5asrep$' in sanitized_head:
        return 'getnpusers_hashes', 'matched GetNPUsers AS-REP hash signature'
    # secretsdump pwdump lines (user:rid:lm:nt:::) or its banner.
    if re.search(r'(?m)^[^\s:]+:\d+:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}:::', sanitized_head) \
            or 'dumping domain credentials' in sanitized_head.lower():
        return 'secretsdump_txt', 'matched secretsdump hash dump signature'
    # smbmap host/share header.
    if re.search(r'\[\+\]\s*IP:\s*[0-9a-fA-F:.]+', sanitized_head):
        return 'smbmap_txt', 'matched smbmap IP/share header signature'
    # NetExec/CrackMapExec: PROTO host port name [..] result lines.
    if re.search(r'(?m)^.*?\b(?:SMB|LDAP|LDAPS|WINRM|RDP|MSSQL)\b\s+[0-9a-fA-F:.]+\s+\d+\s+\S+\s+[\[\(]', sanitized_head):
        return 'netexec_log', 'matched NetExec/CrackMapExec result line signature'
    if re.search(r'\[\*\]\s*System information', sanitized_head, re.IGNORECASE) or 'snmp-check' in sanitized_head[:200].lower():
        return 'snmp_txt', 'matched snmp-check section header signature'
    if re.search(r'(?mi)^\s*Export list for\s+\S+:', sanitized_head):
        return 'nfs_txt', 'matched showmount export-list header'
    if re.search(r'(?m)^\s*(?:\|_?\s*)?/\S+\s+(?:\*|[0-9a-fA-F:.]+(?:/\d+)?|[A-Za-z0-9_.-]+)(?:\(|\s|$)', sanitized_head):
        return 'nfs_txt', 'matched NFS export line signature'
    if re.search(r'(?mi)^redis_version:', sanitized_head) or re.search(r'(?mi)redis-info:', sanitized_head):
        return 'redis_txt', 'matched Redis INFO signature'
    if basename.startswith("rsync_") and re.search(r'(?m)^[A-Za-z0-9_.@-]+(?:\s+\S.*)?$', sanitized_head):
        return 'rsync_txt', 'matched rsync output filename and module-list shape'
    if _looks_like_smtp_user_enum(sanitized_head, basename):
        return 'smtp_user_enum_txt', 'matched SMTP user-enum valid-user signature'
    if re.search(r'\[INFO\].*(?:parameter|injection|vulnerable)', sanitized_head, re.IGNORECASE) and 'sqlmap' in sanitized_head[:800].lower():
        return 'sqlmap_log', 'matched sqlmap [INFO] signature'
    if re.search(r'WinPEAS|SeImpersonatePrivilege|AlwaysInstallElevated|winpeas', sanitized_head, re.IGNORECASE):
        return 'winpeas_txt', 'matched WinPEAS keyword signature'
    if re.search(r'linpeas|╔══════════╣|Linux Privilege Escalation|linux local PE', sanitized_head, re.IGNORECASE):
        return 'linpeas_txt', 'matched LinPEAS keyword signature'

    # Gobuster dir/vhost output: accept common status wrappers and header-only captures.
    if re.search(r'^\s*(?:/)?[^\s\[\(]+\s+(?:\(Status:|\[Status:|Status:)', sanitized_head, re.MULTILINE | re.IGNORECASE):
        return 'gobuster_txt', 'matched Gobuster directory result signature'
    if re.search(r'^\s*Found:\s+\S+\s+(?:\(Status:|\[Status:|Status:)', sanitized_head, re.MULTILINE | re.IGNORECASE):
        return 'gobuster_txt', 'matched Gobuster vhost result signature'
    if re.search(r'Gobuster\s+v?\d', sanitized_head[:800], re.IGNORECASE):
        if re.search(r'^\s*\[\+\]\s+(?:Url|URL|Threads|Wordlist|Mode):', sanitized_head, re.MULTILINE):
            return 'gobuster_txt', 'matched Gobuster header signature'
        if re.search(r'Starting\s+gobuster', sanitized_head, re.IGNORECASE):
            return 'gobuster_txt', 'matched Gobuster startup banner signature'
        return 'gobuster_txt', 'matched Gobuster version banner signature'

    return None, 'no supported parser signature found in first 3072 bytes'


def _sniff_file_type(path):
    """Backward-compatible wrapper returning only the detected parser key."""
    file_type, _ = _sniff_file_type_details(path)
    return file_type

def _gobuster_extract_target(path):
    """
    Parses a gobuster output file header to extract (host, port, mode).
    Returns (None, 80, 'dir') if the header cannot be parsed.
    """
    host, port, mode = None, 80, 'dir'
    url_found = False
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', line).strip()
                if re.search(r'vhost enumeration mode', line, re.IGNORECASE):
                    mode = 'vhost'
                url_match = re.search(r'\[\+\]\s+(?:Url|URL):\s+(https?)://([^:/\s]+)(?::(\d+))?', line, re.IGNORECASE)
                if url_match:
                    url_found = True
                    scheme = url_match.group(1).lower()
                    host = url_match.group(2)
                    if url_match.group(3):
                        port = int(url_match.group(3))
                    elif scheme == 'https':
                        port = 443
                    # else leave port = 80 (http default)
                # Stop parsing once we hit results
                if line.startswith('/') or line.startswith('Found:') or 'Progress:' in line:
                    break
    except (IOError, OSError):
        pass
    # gobuster's -o file has no '[+] Url:' banner (that goes to stdout), so without
    # this every non-:80 scan would silently default to port 80. one-shot-enum names
    # its output 'gobuster_<port>.txt' - recover the port from the filename.
    if not url_found:
        fname_match = re.search(r'gobuster_(\d{1,5})\.', os.path.basename(path))
        if fname_match:
            candidate = int(fname_match.group(1))
            if 0 < candidate <= 65535:
                port = candidate
    return host, port, mode

def _nmap_extract_target(path):
    """Extracts the first target IP address from an nmap XML file."""
    try:
        tree = ET.parse(path)
        root = tree.getroot()
        for host_el in root.findall('host'):
            for addr_el in host_el.findall('address'):
                if addr_el.get('addrtype') in ('ipv4', 'ipv6'):
                    return addr_el.get('addr')
    except Exception:
        pass
    return None


def _detect_dir_based_parsers(scan_root, host, detections, dir_parser_paths, verbose):
    """Detect SharpHound / ldapdomaindump directories in scan_root or its immediate subdirs."""
    try:
        subdirs = [e.path for e in os.scandir(scan_root) if e.is_dir()]
    except (PermissionError, FileNotFoundError, NotADirectoryError):
        return
    for candidate in [scan_root] + subdirs:
        if candidate in dir_parser_paths:
            continue
        try:
            contents_lower = {f.lower() for f in os.listdir(candidate)}
        except (PermissionError, FileNotFoundError):
            continue
        # SharpHound: needs at least users.json + domains.json
        if 'users.json' in contents_lower and 'domains.json' in contents_lower:
            detections.append({"host": host, "key": "sharphound_dir", "path": candidate,
                               "reason": "directory with users.json + domains.json"})
            dir_parser_paths.add(candidate)
            if verbose > 0:
                print(f"    [auto-detect] {os.path.basename(candidate)}/ -> sharphound_dir"
                      + (f" (host {host})" if host else ""))
        # ldapdomaindump: needs domain_users.tsv
        if 'domain_users.tsv' in contents_lower:
            detections.append({"host": host, "key": "ldapdomaindump_dir", "path": candidate,
                               "reason": "directory with domain_users.tsv"})
            dir_parser_paths.add(candidate)
            if verbose > 0:
                print(f"    [auto-detect] {os.path.basename(candidate)}/ -> ldapdomaindump_dir"
                      + (f" (host {host})" if host else ""))


def _sniff_and_record(path, label, host, detections, verbose):
    """Content-sniff a single file and append a detection record if recognised."""
    file_type, reason = _sniff_file_type_details(path)
    if file_type:
        detections.append({"host": host, "key": file_type, "path": path, "reason": reason})
        if verbose > 0:
            print(f"    [auto-detect] {label} -> {file_type}" + (f" (host {host})" if host else ""))
        if verbose > 1:
            print(f"        reason: {reason}")
    elif verbose > 1:
        print(f"    [auto-detect] {label} skipped")
        print(f"        reason: {reason}")


def auto_detect_loot(directory, verbose=0):
    """
    Walks a loot directory and auto-detects every tool output file.

    Supports two layouts (and mixtures of them):
      - Flat: files sit directly in `directory`. Their host is unknown here and is
        resolved later from nmap/gobuster/--target-host (single-host workflow).
      - Per-host: one subdirectory per host, named after the host (e.g.
        `loot/10.10.10.10/`). Every file inside is attributed to that host, which
        is exactly the context the host-dependent parsers (linpeas, snmp,
        enum4linux, ...) need.

    Returns a list of detection records:
        [{"host": <str|None>, "key": <parser_key>, "path": <path>, "reason": <str>}]
    Every recognised file is returned (no first-per-type dropping), so repeated
    scans and multiple web ports/hosts are all ingested.
    """
    detections = []
    dir_parser_paths = set()

    try:
        top_entries = list(os.scandir(directory))
    except (NotADirectoryError, PermissionError, FileNotFoundError) as e:
        print(f"{C.BOLD}{C.YELLOW}[!] Cannot scan directory '{directory}': {e}{C.END}")
        return detections

    # Pass 1: directory-based parsers at the top level (host unknown).
    _detect_dir_based_parsers(directory, None, detections, dir_parser_paths, verbose)

    # Pass 2: loose files directly in the loot dir (flat / single-host).
    for entry in top_entries:
        if entry.is_file():
            _sniff_and_record(entry.path, entry.name, None, detections, verbose)

    # Pass 3: per-host subdirectories. The directory name is the host context.
    for entry in top_entries:
        if not entry.is_dir() or entry.path in dir_parser_paths:
            continue
        # Skip helper/hidden dirs (e.g. one-shot-enum's _logs stdout captures).
        if entry.name.startswith('_') or entry.name.startswith('.'):
            continue
        host = entry.name
        _detect_dir_based_parsers(entry.path, host, detections, dir_parser_paths, verbose)
        try:
            host_files = [e for e in os.scandir(entry.path) if e.is_file()]
        except (PermissionError, FileNotFoundError):
            continue
        for f in host_files:
            _sniff_and_record(f.path, f"{host}/{f.name}", host, detections, verbose)

    return detections


# ── Shared output pipeline ─────────────────────────────────────────────────────

def _save_findings(args, findings):
    """Saves the final prioritized findings to disk if --output-json is set."""
    if not getattr(args, 'output_json', None):
        return
    try:
        print(f"\n{C.BOLD}{C.CYAN}[*] Saving prioritized findings to: {args.output_json}{C.END}")
        with open(args.output_json, 'w') as f:
            json.dump(findings, f, indent=4)
        print(f"    {C.GREEN}[+]{C.END} Successfully saved {len(findings)} findings.")
    except IOError as e:
        print(f"\n{C.BOLD}{C.YELLOW}[!] Error saving to JSON file: {e}{C.END}")


def _display_results(args, synthesizer, prioritized_findings):
    """Runs the synthesizer and prints attack paths + findings list."""
    print(f"\n{C.BOLD}{C.CYAN}[*] Running Attack Path Synthesizer...{C.END}")
    suggested_paths = synthesizer.generate_attack_paths(prioritized_findings)

    if suggested_paths:
        print(f"\n{C.BOLD}{C.YELLOW}--- PathFinder has identified {len(suggested_paths)} potential attack path(s)! ---{C.END}")
        for i, path in enumerate(suggested_paths):
            print("\n" + "="*80)
            print(f"{C.BOLD}ATTACK PATH #{i+1}{C.END}")
            eff = path.get('effective_priority', path['priority'])
            base = path['priority']
            prio_label = (f"[Priority: {eff}]" if eff == base
                          else f"[Priority: {eff}  (base {base}, adjusted for evidence quality)]")
            print(f"Name:       {C.BOLD}{path['name']}{C.END} {C.YELLOW}{C.BOLD}{prio_label}{C.END}")
            print(f"Target:     {path['host']}")
            print("="*80)
            print(f"\n  [{C.BOLD}+{C.END}] Description:\n      {path['suggestion']['description']}")
            if args.verbose > 0:
                print(f"\n  [{C.BOLD}+{C.END}] Rationale:\n      {path['suggestion']['rationale']}")
            if path['suggestion'].get('commands'):
                print(f"\n  [{C.BOLD}+{C.END}] Suggested Commands:")
                cmds = path['suggestion']['commands']
                uses_msf = False
                if getattr(args, 'oscp', False):
                    cmds, uses_msf = _oscp_process_commands(cmds)
                for cmd in cmds:
                    print(f"      - {cmd}")
                if uses_msf:
                    print(f"      {C.YELLOW}[OSCP] Metasploit/Meterpreter is limited to ONE target on the exam.{C.END}")
            if path['suggestion'].get('injection_examples'):
                print(f"\n  [{C.BOLD}+{C.END}] {C.BOLD}Prompt-injection examples:{C.END}")
                for ex in path['suggestion']['injection_examples']:
                    print(f"      - {ex}")
            if path.get('atlas'):
                print(f"\n  [{C.BOLD}+{C.END}] MITRE ATLAS:")
                for tag in path['atlas']:
                    print(f"      - {tag}")
            if path['suggestion'].get('references'):
                print(f"\n  [{C.BOLD}+{C.END}] References:")
                for ref in path['suggestion']['references']:
                    print(f"      - {ref}")
            if args.verbose > 0 and path.get('evidence'):
                print(f"\n  [{C.BOLD}+{C.END}] Matched Evidence:")
                for ev in path['evidence']:
                    print(f"      - {ev}")
        print("\n" + "="*80)
    else:
        print(f"\n{C.BOLD}{C.YELLOW}[!] No specific attack paths were synthesized from the findings.{C.END}")

    total_exploit_count = sum(1 for f in prioritized_findings if f.get("source_tool") in ["searchsploit_mapper", "github_exploit_mapper"])
    filtered_list = filter_prioritized_findings(prioritized_findings, args.max_vulns)

    print(f"\n{C.BOLD}{C.YELLOW}--- Total Findings: {len(filtered_list)} (Public Exploits limited to --max-vulns, total discovered: {total_exploit_count}):{C.END}")

    filtered_list.sort(key=lambda x: x.get("attributes", {}).get("score", 0), reverse=True)

    for i, p_finding in enumerate(filtered_list):
        score = p_finding.get("attributes", {}).get("score", "N/A")
        display_name, display_type = format_finding_display(p_finding.get('name'), p_finding.get('entity_type'))
        print(f"\n[{i+1}] [Score: {score}] {display_name} {display_type}")
        print(f"    Host: {p_finding.get('host')}, Port: {p_finding.get('port')}")
        attributes = p_finding.get("attributes", {})
        if attributes.get("metasploit_module"):
            print(f"    {C.BOLD}Metasploit Module:{C.END} {attributes['metasploit_module']}")
            if getattr(args, 'oscp', False):
                print(f"    {C.YELLOW}[OSCP] Metasploit is limited to one target on the exam.{C.END}")
        if attributes.get("url"):
            print(f"    {C.BOLD}URL:{C.END} {attributes['url']}")

    return suggested_paths


# ── AI attack-intelligence brief ────────────────────────────────────────────────

# Maps an ai_service finding name to (crown-jewel asset, why it matters). Used to
# build the brief's crown-jewel table from whatever AI surfaces were actually found.
_AI_CROWN_JEWELS = {
    "vector-store-open": ("Knowledge-base corpus", "Readable source chunks - commonly leak credentials, hostnames, runbooks, and topology"),
    "rag-vector": ("Vector store / RAG corpus", "Retrieval context the model trusts; extraction and poisoning target"),
    "mcp-tools-confirmed": ("MCP tool capabilities", "Confirmed tools with real backend permissions (fs / exec / db / secrets)"),
    "agent-mcp": ("Agent/MCP tool surface", "Tool invocation authority - excessive agency and confused-deputy risk"),
    "mlflow": ("Model registry / artifacts", "Proprietary models and artifact write-to-RCE path"),
    "notebook": ("Notebook kernel", "Unauthenticated kernel = direct code execution"),
    "ai-agent-a2a": ("Multi-agent orchestration", "Agent registration/routing trust; rogue-agent and workflow abuse"),
    "ai-agent-sql": ("NL-to-SQL database bridge", "Generated SQL can reach dangerous DB functions (xp_cmdshell)"),
}


def _ai_trust_boundaries(names):
    """Derive the relevant trust boundaries (per the AI threat-modelling notes)
    from the set of AI finding names/attributes actually present."""
    boundaries = []
    if any(n in names for n in ("openai-compatible", "ollama", "vllm", "tgi", "gradio", "langserve", "ai-agent", "ai-agent-sql")):
        boundaries.append("**Input trust** (user prompt/query -> model): prompt injection, jailbreak, guardrail bypass.")
    if any(n in names for n in ("agent-mcp", "mcp-tools-confirmed", "ai-agent", "ai-workflow")):
        boundaries.append("**Tool-invocation trust** (agent -> tool server): parameter injection, overbroad tool scope, confused deputy.")
    if any(n in names for n in ("rag-vector", "vector-store-open")):
        boundaries.append("**Data-integrity trust** (retrieved context -> model): RAG/vector poisoning, indirect injection, chunk extraction.")
    if "ai-agent-a2a" in names:
        boundaries.append("**Delegation trust** (orchestrator -> sub-agents): rogue registration, agent-card spoofing, workflow-gate bypass.")
    if any("secrets/identity" in (str(c)) for c in names):
        boundaries.append("**Credential trust** (tool server -> secret store): secret rotation abuse, identity collapse, overprivileged role.")
    return boundaries


def generate_ai_brief(prioritized_findings, attack_paths):
    """Build a markdown AI attack-intelligence brief from AI findings + attack paths,
    mirroring the AI-Red-Team notes' brief (surfaces, crown jewels, trust boundaries,
    prioritized paths with MITRE ATLAS). Returns markdown text, or '' if no AI findings."""
    ai_findings = [f for f in prioritized_findings if f.get("entity_type") == "ai_service"]
    if not ai_findings:
        return ""

    lines = ["# AI Attack Intelligence Brief", "",
             "_Generated by PathFinder from one-shot-enum AI-surface enumeration. "
             "Read-only findings - validate and exploit only within your Rules of Engagement._", ""]

    # --- AI surfaces grouped by host ---
    lines.append("## AI Surfaces by Host")
    hosts = sorted({f.get("host") for f in ai_findings}, key=lambda h: (h is None, h))
    for host in hosts:
        lines.append("")
        lines.append(f"### {host}")
        for f in sorted([x for x in ai_findings if x.get("host") == host],
                        key=lambda x: x.get("attributes", {}).get("score", 0), reverse=True):
            a = f.get("attributes", {})
            role = a.get("agent_role") or a.get("label") or f.get("name")
            arch = a.get("agent_architecture")
            fw = a.get("agent_framework")
            descriptor = ", ".join(x for x in (arch, fw) if x and x != "unknown")
            suffix = f" ({descriptor})" if descriptor else ""
            loc = a.get("base_url") or a.get("vector_store_url") or a.get("mcp_url") or ""
            score = a.get("score", "?")
            lines.append(f"- **{role}**{suffix} - `{f.get('name')}` @ {loc} [score {score}]")
            if a.get("agent_capabilities"):
                lines.append(f"  - Capabilities: {', '.join(a['agent_capabilities'])}")
            if a.get("confirmed_mcp_tools"):
                cats = a.get("confirmed_mcp_categories") or []
                cat_str = f" [{', '.join(cats)}]" if cats else ""
                lines.append(f"  - Confirmed MCP tools{cat_str}: {', '.join(a['confirmed_mcp_tools'])}")
            if a.get("vector_store_collections"):
                lines.append(f"  - Unauthenticated {a.get('vector_store_engine', 'vector store')} collections: "
                             f"{', '.join(a['vector_store_collections'])}")

    # --- Crown jewels ---
    jewels = []
    seen_jewels = set()
    for f in ai_findings:
        entry = _AI_CROWN_JEWELS.get(f.get("name"))
        if entry and entry[0] not in seen_jewels:
            seen_jewels.add(entry[0])
            jewels.append((entry[0], f.get("host"), entry[1]))
    if jewels:
        lines += ["", "## Crown Jewels (highest-value AI assets reachable)", "",
                  "| Asset | Host | Why it matters |", "| --- | --- | --- |"]
        for asset, host, why in jewels:
            lines.append(f"| {asset} | {host} | {why} |")

    # --- Trust boundaries ---
    names = {f.get("name") for f in ai_findings}
    # also expose confirmed tool categories to the boundary heuristic
    for f in ai_findings:
        names.update(f.get("attributes", {}).get("confirmed_mcp_categories") or [])
    boundaries = _ai_trust_boundaries(names)
    if boundaries:
        lines += ["", "## Trust Boundaries to Test", ""]
        lines += [f"- {b}" for b in boundaries]

    # --- Prioritized AI attack paths (every AI rule carries MITRE ATLAS tags) ---
    ai_paths = [p for p in attack_paths if p.get("atlas")]
    if ai_paths:
        lines += ["", "## Prioritized AI Attack Paths", ""]
        for p in ai_paths:
            lines.append(f"### [P{p.get('effective_priority', p.get('priority'))}] {p.get('name')} - {p.get('host')}")
            lines.append("")
            lines.append(p["suggestion"].get("description", ""))
            if p.get("atlas"):
                lines.append("")
                lines.append(f"- **MITRE ATLAS:** {', '.join(p['atlas'])}")
            cmds = p["suggestion"].get("commands") or []
            if cmds:
                lines.append("- **Next steps:**")
                lines += [f"  - {c}" for c in cmds]
            examples = p["suggestion"].get("injection_examples") or []
            if examples:
                lines.append("- **Prompt-injection examples:**")
                lines += [f"  - {e}" for e in examples]
            lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def maybe_write_ai_brief(args, paths, prioritized_findings):
    """Write the AI intel brief to args.ai_brief if that flag was set.

    Reuses the paths already synthesized by _display_results so synthesis runs
    once per invocation.
    """
    brief_path = getattr(args, "ai_brief", None)
    if not brief_path:
        return
    markdown = generate_ai_brief(prioritized_findings, paths)
    if not markdown:
        print(f"\n{C.BOLD}{C.YELLOW}[!] --ai-brief: no AI (ai_service) findings to report; brief not written.{C.END}")
        return
    try:
        with open(brief_path, "w", encoding="utf-8") as fh:
            fh.write(markdown)
        print(f"\n{C.BOLD}{C.GREEN}[+]{C.END} AI attack-intelligence brief written to {brief_path}")
    except IOError as e:
        print(f"\n{C.BOLD}{C.YELLOW}[!] Error writing AI brief: {e}{C.END}")


# ── Scan mode ─────────────────────────────────────────────────────────────────

def run_scan_mode(args):
    """Handles the 'scan' subcommand: auto-detects all tool output files in a directory."""
    synthesizer = AttackPathSynthesizer()
    loot_dir = os.path.abspath(args.loot_dir)

    print(f"\n{C.BOLD}{C.CYAN}[*] Scanning loot directory: {loot_dir}{C.END}")

    if args.verbose > 0:
        print(f"\n{C.BOLD}{C.CYAN}[*] Running file detection...{C.END}")

    detections = auto_detect_loot(loot_dir, verbose=args.verbose)

    if not detections:
        print(f"{C.BOLD}{C.YELLOW}[!] No recognizable tool output files found in '{loot_dir}'.{C.END}")
        print(f"    Tip: Use manual flags (--nmap-xml, --gobuster-txt, etc.) if auto-detection fails.")
        sys.exit(1)

    # Summarise detections grouped by host (None = flat/loose files).
    hosts_seen = sorted({d['host'] for d in detections if d['host']})
    host_label = f" across {len(hosts_seen)} host(s)" if hosts_seen else ""
    print(f"\n{C.BOLD}{C.CYAN}[*] Detected {len(detections)} parseable source(s){host_label}:{C.END}")
    if hosts_seen:
        # Multi-host layout: group sources under each host (plus any loose files).
        for group in hosts_seen + [None]:
            group_records = [d for d in detections if d['host'] == group]
            if not group_records:
                continue
            header = f"host {group}" if group else "loose files (host inferred)"
            print(f"    {C.BOLD}{header}{C.END}")
            for d in group_records:
                rel = os.path.relpath(d['path'], loot_dir)
                print(f"      {C.GREEN}[+]{C.END} {d['key']:<25} -> {rel}")
    else:
        # Flat single-host loot: list sources directly.
        for d in detections:
            rel = os.path.relpath(d['path'], loot_dir)
            print(f"    {C.GREEN}[+]{C.END} {d['key']:<25} -> {rel}")

    if getattr(args, 'oscp', False):
        flagged = sorted({OSCP_PROHIBITED_PARSER_KEYS[d['key']]
                          for d in detections if d['key'] in OSCP_PROHIBITED_PARSER_KEYS})
        if flagged:
            print(f"\n{C.BOLD}{C.YELLOW}[!] OSCP profile: ingested output from restricted tool(s): "
                  f"{', '.join(flagged)}. Findings are shown, but running these tools is restricted on the exam.{C.END}")

    # A global target host is only needed for flat (host-less) host-dependent files;
    # per-host records already carry their host via the directory name.
    global_target = getattr(args, 'target_host', None)
    if not global_target:
        flat_nmap = next((d for d in detections if d['key'] == 'nmap_xml' and d['host'] is None), None)
        if flat_nmap:
            global_target = _nmap_extract_target(flat_nmap['path'])
            if global_target:
                print(f"\n{C.BOLD}{C.CYAN}[*] Target host inferred from Nmap XML: {C.END}{C.BOLD}{global_target}{C.END}")
    if not global_target:
        flat_gob = next((d for d in detections if d['key'] == 'gobuster_txt' and d['host'] is None), None)
        if flat_gob:
            gb_host, _, _ = _gobuster_extract_target(flat_gob['path'])
            if gb_host:
                global_target = gb_host
                print(f"\n{C.BOLD}{C.CYAN}[*] Target host inferred from Gobuster output: {C.END}{C.BOLD}{global_target}{C.END}")

    print(f"\n{C.BOLD}{C.CYAN}[*] Parsing detected files...{C.END}")
    all_raw_findings = []
    skipped_hostless = False

    for d in detections:
        key, path = d['key'], d['path']
        spec = SPEC_BY_KEY.get(key)
        if spec is None:
            continue

        host = d['host'] or global_target
        if spec.host_required and not host:
            rel = os.path.relpath(path, loot_dir)
            print(f"    {C.YELLOW}[!]{C.END} Skipping {key} ({rel}): no host context (pass --target-host or use per-host loot dirs).")
            skipped_hostless = True
            continue

        # Gobuster carries its own host/port/mode in the file header; fall back to the dir host.
        gb_host, gb_port, gb_mode = host, 80, 'dir'
        if key == 'gobuster_txt':
            _h, _p, _m = _gobuster_extract_target(path)
            gb_host = _h or host
            gb_port = _p or 80
            gb_mode = _m or 'dir'

        ctx = ParserContext(target_host=host, gobuster_host=gb_host,
                            gobuster_port=gb_port, gobuster_mode=gb_mode)
        raw = spec.run(path, ctx)
        validated = validate_parser_output(key, raw)
        # Record provenance: which file each finding came from.
        rel = os.path.relpath(path, loot_dir)
        for finding in validated:
            finding.setdefault('attributes', {})['source_file'] = rel
        all_raw_findings.extend(validated)
        host_tag = f" [{host}]" if host else ""
        print(f"    {C.GREEN}[+]{C.END} {key:<25} -> {len(validated)} findings  ({rel}){host_tag}")
        logger.info("Scan parser %s (%s) produced %s validated findings", key, rel, len(validated))

    if skipped_hostless and not global_target:
        print(f"\n{C.BOLD}{C.YELLOW}[!] Some host-dependent files were skipped for lack of host context.{C.END}")

    if not all_raw_findings:
        print(f"\n{C.BOLD}{C.YELLOW}[!] No findings produced from any parser. Exiting.{C.END}")
        sys.exit(0)

    print(f"\n{C.BOLD}{C.CYAN}[*] Running Vulnerability Mapper...{C.END}")
    use_github = not (getattr(args, 'offline', False) or getattr(args, 'skip_github', False))
    use_searchsploit = not (getattr(args, 'offline', False) or getattr(args, 'skip_searchsploit', False))
    vuln_mapper = VulnerabilityMapper(
        use_github=use_github,
        use_searchsploit=use_searchsploit,
        github_cache_file=args.github_cache,
    )
    prioritized = vuln_mapper.map_and_prioritize(all_raw_findings)
    prioritized = deduplicate_findings(prioritized)
    print(f"    {C.GREEN}[+]{C.END} Mapper prioritized {len(prioritized)} findings.")

    _save_findings(args, prioritized)
    suggested_paths = _display_results(args, synthesizer, prioritized)
    maybe_write_ai_brief(args, suggested_paths, prioritized)


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    main_parser = argparse.ArgumentParser(
        description="PathFinder — Intelligent Reconnaissance Analysis for Pentesters",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    subparsers = main_parser.add_subparsers(dest='command')

    # ── scan subcommand ────────────────────────────────────────────────────────
    scan_p = subparsers.add_parser(
        'scan',
        help='Auto-detect and parse all tool output files in a loot directory.',
        description=(
            'Automatically detects nmap, gobuster, nikto, linpeas, winpeas and other\n'
            'tool output files inside a directory and runs the full PathFinder pipeline.\n\n'
            'Example:\n'
            '  python3 -m main.pathfinder scan ./loot/ --target-host 10.10.10.10\n'
            '  python3 -m main.pathfinder scan ./loot/ -o findings.json --offline'
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    scan_p.add_argument('loot_dir', help='Path to directory containing tool output files.')
    scan_p.add_argument('--target-host', help='Target host IP or domain (inferred from nmap XML if omitted).')
    scan_p.add_argument('-o', '--output-json', help='Save prioritized findings to a JSON file.')
    scan_p.add_argument('-v', '--verbose', action='count', default=0, help='Verbosity level (-v, -vv).')
    scan_p.add_argument('--max-vulns', type=int, default=10, help='Max EDB/GitHub exploits to display (default: 10).')
    scan_p.add_argument('--offline', action='store_true', help='Disable all external enrichment lookups.')
    scan_p.add_argument('--skip-github', action='store_true', help='Skip GitHub exploit enrichment.')
    scan_p.add_argument('--skip-searchsploit', action='store_true', help='Skip Searchsploit enrichment.')
    scan_p.add_argument('--github-cache', default=os.path.join(SCRIPT_DIR, 'github_cache.json'), help='Path to GitHub lookup cache JSON file.')
    scan_p.add_argument('--no-color', action='store_true', help='Disable ANSI colour output.')
    scan_p.add_argument('--oscp', action='store_true', help='OSCP exam profile: strip prohibited-tool commands (sqlmap, nuclei) from suggestions and flag the Metasploit one-target limit.')
    scan_p.add_argument('--ai-brief', metavar='FILE', help='Write a markdown AI attack-intelligence brief (surfaces, crown jewels, trust boundaries, MITRE ATLAS-tagged paths) to FILE.')

    # ── manual mode args (no subcommand) ──────────────────────────────────────
    # The per-parser input flags are generated from the single PARSER_SPECS list.
    ag = main_parser.add_argument_group('Analysis Input Arguments')
    for spec in PARSER_SPECS:
        ag.add_argument(spec.flag, dest=spec.key, help=spec.help)
    ag.add_argument("--target-host", help="Target host IP or domain. Required for many parsers.")
    ag.add_argument("--gobuster-host", help="Target host for Gobuster. Deprecated, use --target-host.")
    ag.add_argument("--gobuster-port", type=int, help="Target port for Gobuster output.")
    ag.add_argument("--gobuster-mode", choices=['dir', 'vhost'], default='dir', help="Gobuster mode.")

    io_group = main_parser.add_argument_group('Data I/O Arguments')
    io_group.add_argument("-i", "--input-json", help="Load prioritized findings from a JSON file (can be used with other inputs).")
    io_group.add_argument("-o", "--output-json", help="Save the final prioritized findings to a JSON file.")

    lg = main_parser.add_argument_group('Intelligence Management Arguments')
    lg.add_argument("--learn", action="store_true", help="Enter interactive mode to teach a new attack path.")
    lg.add_argument("--add-cred", action="store_true", help="Enter interactive mode to manually add a found credential.")

    gg = main_parser.add_argument_group('General Arguments')
    gg.add_argument("-v", "--verbose", action="count", default=0, help="Verbosity level (-v, -vv).")
    gg.add_argument("--max-vulns", type=int, default=10, help="Max number of EDB/GitHub exploits to display (default: 10).")
    gg.add_argument("--offline", action="store_true", help="Disable external enrichment lookups (GitHub + Searchsploit).")
    gg.add_argument("--skip-github", action="store_true", help="Skip GitHub exploit repository enrichment.")
    gg.add_argument("--skip-searchsploit", action="store_true", help="Skip Searchsploit enrichment.")
    gg.add_argument("--github-cache", default=os.path.join(SCRIPT_DIR, "github_cache.json"), help="Path to GitHub lookup cache JSON file.")
    gg.add_argument("--no-color", action="store_true", help="Disable ANSI colour output.")
    gg.add_argument("--oscp", action="store_true", help="OSCP exam profile: strip prohibited-tool commands (sqlmap, nuclei) from suggestions and flag the Metasploit one-target limit.")
    gg.add_argument("--ai-brief", metavar="FILE", help="Write a markdown AI attack-intelligence brief (surfaces, crown jewels, trust boundaries, MITRE ATLAS-tagged paths) to FILE.")

    args = main_parser.parse_args()
    configure_logging(args.verbose)
    set_color_enabled(should_enable_color(getattr(args, 'no_color', False)))
    print_banner()

    # Dispatch to scan mode if subcommand given
    if args.command == 'scan':
        run_scan_mode(args)
        return

    # ── Manual mode ───────────────────────────────────────────────────────────
    synthesizer = AttackPathSynthesizer()

    if args.learn:
        synthesizer.learn_new_path_interactive()
        sys.exit(0)

    if args.add_cred:
        manage_credentials()
        sys.exit(0)

    try:
        base_prioritized_findings = load_base_findings(args.input_json)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"\n{C.BOLD}{C.YELLOW}[!] Error loading {args.input_json}: {e}{C.END}")
        logger.exception("Failed to load input-json")
        sys.exit(1)

    target_host = args.target_host or args.gobuster_host
    new_raw_findings = parse_new_data_files(args, target_host)

    if not base_prioritized_findings and not new_raw_findings:
        main_parser.error("For analysis, at least one input file (--nmap-xml, etc.) or --input-json must be provided.")

    newly_prioritized_findings = map_findings(args, new_raw_findings)
    combined = base_prioritized_findings + newly_prioritized_findings
    prioritized_findings = deduplicate_findings(combined)

    if len(combined) != len(prioritized_findings) and args.verbose > 0:
        print(f"\n{C.BOLD}{C.CYAN}[*]{C.END} Deduplicated {len(combined) - len(prioritized_findings)} overlapping findings.")

    if not prioritized_findings:
        print(f"\n{C.BOLD}{C.YELLOW}[!] No findings to process. Exiting.{C.END}")
        sys.exit(0)

    _save_findings(args, prioritized_findings)
    suggested_paths = _display_results(args, synthesizer, prioritized_findings)
    maybe_write_ai_brief(args, suggested_paths, prioritized_findings)


if __name__ == "__main__":
    main()
