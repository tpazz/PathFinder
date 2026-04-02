import argparse
import sys
import json
import os
import re
import logging
import xml.etree.ElementTree as ET

# Import all custom parser modules and the core logic components.
from .attack_path_synthesizer import AttackPathSynthesizer
from .vulnerability_mapper import VulnerabilityMapper
from .finding_schema import FindingValidationError, validate_findings
from parsers.active_directory.kerberos_parser import parse_getnpusers_output, parse_kerbrute_output
from parsers.active_directory.ldapdomaindump_parser import parse_ldapdomaindump_dir
from parsers.active_directory.sharphound_parser import parse_sharphound_dir
from parsers.initial_foothold.enum4linux_parser import parse_enum4linux_json
from parsers.initial_foothold.gobuster_parser import parse_gobuster_output
from parsers.initial_foothold.nikto_parser import parse_nikto_json
from parsers.initial_foothold.nmap_parser import parse_nmap_xml
from parsers.initial_foothold.snmp_parser import parse_snmp_output
from parsers.initial_foothold.sqlmap_parser import parse_sqlmap_log
from parsers.initial_foothold.whatweb_parser import parse_whatweb_json
from parsers.privilege_escalation.linpeas_parser import parse_linpeas
from parsers.privilege_escalation.winpeas_parser import parse_winpeas

# ANSI color codes for formatted output
class C:
    RED, GREEN, YELLOW, LIGHT_BLUE, CYAN, BOLD, END = '\033[91m', '\033[92m', '\033[93m', '\033[94m', '\033[96m', '\033[1m', '\033[0m'

# Build a full, unambiguous path to the credentials file relative to this script's location.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CREDENTIALS_FILE = os.path.join(SCRIPT_DIR, "credentials.json")

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


def deduplicate_findings(findings_list):
    """Removes duplicate findings from a list based on host, port, name, and type."""
    seen = set()
    unique_findings = []
    for finding in findings_list:
        identifier = (finding.get('host'), finding.get('port'), finding.get('name'), finding.get('entity_type'))
        if identifier not in seen:
            seen.add(identifier)
            unique_findings.append(finding)
    return unique_findings


def validate_parser_output(parser_name, findings):
    """Validates parser output against the normalized finding schema."""
    try:
        return validate_findings(findings)
    except FindingValidationError as e:
        print(f"{C.BOLD}{C.YELLOW}[!] {parser_name} parser produced invalid finding schema: {e}{C.END}")
        return []


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
        print("\n[!] User interrupted credential entry.")

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
    """Runs configured parsers and returns validated raw findings."""
    parser_inputs = [
        args.nmap_xml, args.gobuster_txt, args.nikto_json, args.whatweb_json, args.enum4linux_json,
        args.linpeas_txt, args.winpeas_txt, args.snmp_txt, args.sharphound_dir, args.ldapdomaindump_dir,
        args.kerbrute_txt, args.getnpusers_hashes, args.sqlmap_log
    ]
    if not any(parser_inputs):
        return []

    print(f"\n{C.BOLD}{C.CYAN}[*] Parsing new data files...{C.END}\n")

    parsers = {
        "Nmap": (args.nmap_xml, lambda f: parse_nmap_xml(f)),
        "Gobuster": (args.gobuster_txt, lambda f: parse_gobuster_output(f, target_host, args.gobuster_port, args.gobuster_mode)),
        "Nikto": (args.nikto_json, lambda f: parse_nikto_json(f)),
        "WhatWeb": (args.whatweb_json, lambda f: parse_whatweb_json(f)),
        "Enum4Linux-NG": (args.enum4linux_json, lambda f: parse_enum4linux_json(f, target_host)),
        "LinPEAS": (args.linpeas_txt, lambda f: parse_linpeas(f, target_host)),
        "WinPEAS": (args.winpeas_txt, lambda f: parse_winpeas(f, target_host)),
        "SNMP": (args.snmp_txt, lambda f: parse_snmp_output(f, target_host)),
        "SharpHound": (args.sharphound_dir, lambda f: parse_sharphound_dir(f)),
        "LDAPDomainDump": (args.ldapdomaindump_dir, lambda f: parse_ldapdomaindump_dir(f)),
        "Kerbrute": (args.kerbrute_txt, lambda f: parse_kerbrute_output(f, target_host)),
        "GetNPUsers": (args.getnpusers_hashes, lambda f: parse_getnpusers_output(f, target_host)),
        "SQLMap": (args.sqlmap_log, lambda f: parse_sqlmap_log(f)),
    }

    findings = []
    host_required_parsers = ["Gobuster", "Enum4Linux-NG", "LinPEAS", "WinPEAS", "SNMP", "Kerbrute", "GetNPUsers"]

    for name, (file_path, parser_func) in parsers.items():
        if not file_path:
            continue
        if name in host_required_parsers and not target_host:
            print(f"{C.BOLD}{C.YELLOW}[!] {name} parser requires --target-host (or domain) to be set.{C.END}")
            logger.warning("Skipped %s parser because --target-host is not set", name)
            continue
        if args.verbose > 0:
            print(f"[*] Parsing {name}: {file_path}")
        findings_from_parser = parser_func(file_path)
        validated_findings = validate_parser_output(name, findings_from_parser)
        findings.extend(validated_findings)
        logger.info("Parser %s produced %s validated findings", name, len(validated_findings))
        if args.verbose > 0:
            print(f"    [+] Found {len(validated_findings)} valid raw findings from {name}.")

    return findings


def map_findings(args, new_raw_findings):
    """Runs vulnerability mapping/prioritization for new findings."""
    if not new_raw_findings:
        return []
    print(f"\n{C.BOLD}{C.CYAN}[*] Running Vulnerability Mapper on new findings...{C.END}\n")
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
        if '"vulnerabilities"' in sanitized_head and '"msg"' in sanitized_head:
            return 'nikto_json', 'matched Nikto JSON signature'
        if '"plugins"' in sanitized_head or '"WhatWeb-version"' in sanitized_head:
            return 'whatweb_json', 'matched WhatWeb JSON signature'
        if '"users"' in sanitized_head and ('"groups"' in sanitized_head or '"shares"' in sanitized_head or '"policy"' in sanitized_head):
            return 'enum4linux_json', 'matched enum4linux-ng JSON signature'
        # SharpHound individual files are handled at the directory level; skip here
        return None, 'JSON-like content but no supported top-level JSON parser signature'

    # Plain-text formats (order matters; more specific patterns first)
    if re.search(r'VALID\s+USERNAME', sanitized_head, re.IGNORECASE):
        return 'kerbrute_txt', 'matched Kerbrute valid username signature'
    if '$krb5asrep$' in sanitized_head:
        return 'getnpusers_hashes', 'matched GetNPUsers AS-REP hash signature'
    if re.search(r'\[\*\]\s*System information', sanitized_head, re.IGNORECASE) or 'snmp-check' in sanitized_head[:200].lower():
        return 'snmp_txt', 'matched snmp-check section header signature'
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
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', line).strip()
                if re.search(r'vhost enumeration mode', line, re.IGNORECASE):
                    mode = 'vhost'
                url_match = re.search(r'\[\+\]\s+(?:Url|URL):\s+(https?)://([^:/\s]+)(?::(\d+))?', line, re.IGNORECASE)
                if url_match:
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


def auto_detect_loot(directory, verbose=0):
    """
    Walks a loot directory and auto-detects tool output files.

    Returns a dict mapping parser keys to file/directory paths, e.g.:
        {'nmap_xml': '/loot/nmap.xml', 'gobuster_txt': '/loot/gobuster.txt', ...}
    """
    detected = {}

    try:
        entries = list(os.scandir(directory))
    except (NotADirectoryError, PermissionError, FileNotFoundError) as e:
        print(f"{C.BOLD}{C.RED}[!] Cannot scan directory '{directory}': {e}{C.END}")
        return detected

    # Check the loot dir itself and immediate subdirectories for directory-based parsers.
    candidates = [directory] + [e.path for e in entries if e.is_dir()]
    for candidate in candidates:
        try:
            contents_lower = {f.lower() for f in os.listdir(candidate)}
        except PermissionError:
            continue
        # SharpHound: needs at least users.json + domains.json
        if 'users.json' in contents_lower and 'domains.json' in contents_lower:
            if 'sharphound_dir' not in detected:
                detected['sharphound_dir'] = candidate
                if verbose > 0:
                    print(f"    [auto-detect] {os.path.basename(candidate)}/ -> sharphound_dir")
        # ldapdomaindump: needs domain_users.tsv
        if 'domain_users.tsv' in contents_lower:
            if 'ldapdomaindump_dir' not in detected:
                detected['ldapdomaindump_dir'] = candidate
                if verbose > 0:
                    print(f"    [auto-detect] {os.path.basename(candidate)}/ -> ldapdomaindump_dir")

    # Sniff individual files in the top-level loot directory.
    for entry in entries:
        if not entry.is_file():
            continue
        file_type, reason = _sniff_file_type_details(entry.path)
        if file_type and file_type not in detected:
            detected[file_type] = entry.path
            if verbose > 0:
                print(f"    [auto-detect] {entry.name} -> {file_type}")
            if verbose > 1:
                print(f"        reason: {reason}")
        elif file_type and verbose > 1:
            original = os.path.basename(detected[file_type])
            print(f"    [auto-detect] {entry.name} skipped (duplicate {file_type}; first match: {original})")
            print(f"        reason: {reason}")
        elif verbose > 1:
            print(f"    [auto-detect] {entry.name} skipped")
            print(f"        reason: {reason}")

    return detected


# ── Shared output pipeline ─────────────────────────────────────────────────────

def _save_findings(args, findings):
    """Saves the final prioritized findings to disk if --output-json is set."""
    if not getattr(args, 'output_json', None):
        return
    try:
        print(f"\n{C.BOLD}{C.CYAN}[*] Saving prioritized findings to: {args.output_json}{C.END}\n")
        with open(args.output_json, 'w') as f:
            json.dump(findings, f, indent=4)
        print(f"    {C.GREEN}[+]{C.END} Successfully saved {len(findings)} findings.")
    except IOError as e:
        print(f"\n{C.BOLD}{C.YELLOW}[!] Error saving to JSON file: {e}{C.END}")


def _display_results(args, synthesizer, prioritized_findings):
    """Runs the synthesizer and prints attack paths + findings list."""
    print(f"\n{C.BOLD}{C.CYAN}[*] Running Attack Path Synthesizer...{C.END}\n")
    suggested_paths = synthesizer.generate_attack_paths(prioritized_findings)

    if suggested_paths:
        print(f"{C.BOLD}{C.YELLOW}--- Pathfinder has identified {len(suggested_paths)} potential attack path(s)! ---{C.END}")
        for i, path in enumerate(suggested_paths):
            print("\n" + "="*80)
            print(f"{C.BOLD}ATTACK PATH #{i+1}{C.END}")
            print(f"Name:       {C.BOLD}{path['name']}{C.END} {C.YELLOW}{C.BOLD}[Priority: {path['priority']}]{C.END}")
            print(f"Target:     {path['host']}")
            print("="*80)
            print(f"\n  [{C.BOLD}+{C.END}] Description:\n      {path['suggestion']['description']}")
            if args.verbose > 0:
                print(f"\n  [{C.BOLD}+{C.END}] Rationale:\n      {path['suggestion']['rationale']}")
            if path['suggestion'].get('commands'):
                print(f"\n  [{C.BOLD}+{C.END}] Suggested Commands:")
                for cmd in path['suggestion']['commands']:
                    print(f"      - {cmd}")
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
        if attributes.get("url"):
            print(f"    {C.BOLD}URL:{C.END} {attributes['url']}")


# ── Scan mode ─────────────────────────────────────────────────────────────────

def run_scan_mode(args):
    """Handles the 'scan' subcommand: auto-detects all tool output files in a directory."""
    synthesizer = AttackPathSynthesizer()
    loot_dir = os.path.abspath(args.loot_dir)

    print(f"\n{C.BOLD}{C.CYAN}[*] Scanning loot directory: {loot_dir}{C.END}\n")

    if args.verbose > 0:
        print(f"{C.BOLD}{C.CYAN}[*] Running file detection...{C.END}")

    detected = auto_detect_loot(loot_dir, verbose=args.verbose)

    if not detected:
        print(f"{C.BOLD}{C.YELLOW}[!] No recognizable tool output files found in '{loot_dir}'.{C.END}")
        print(f"    Tip: Use manual flags (--nmap-xml, --gobuster-txt, etc.) if auto-detection fails.")
        sys.exit(1)

    print(f"{C.BOLD}{C.CYAN}[*] Detected {len(detected)} parseable source(s):{C.END}\n")
    for key, path in detected.items():
        rel = os.path.relpath(path, loot_dir)
        print(f"    {C.GREEN}[+]{C.END} {key:<25} -> {rel}")

    # Infer target host
    target_host = getattr(args, 'target_host', None)
    if not target_host and 'nmap_xml' in detected:
        inferred = _nmap_extract_target(detected['nmap_xml'])
        if inferred:
            target_host = inferred
            print(f"\n{C.BOLD}{C.CYAN}[*] Target host inferred from Nmap XML: {C.END}{C.BOLD}{target_host}{C.END}")
    if not target_host and 'gobuster_txt' in detected:
        gb_host, _, _ = _gobuster_extract_target(detected['gobuster_txt'])
        if gb_host:
            target_host = gb_host
            print(f"\n{C.BOLD}{C.CYAN}[*] Target host inferred from Gobuster output: {C.END}{C.BOLD}{target_host}{C.END}")
    if not target_host:
        print(f"\n{C.BOLD}{C.YELLOW}[!] Could not infer target host. Pass --target-host to avoid skipping host-dependent parsers.{C.END}")

    # Determine gobuster connection details
    gb_host_val = target_host
    gb_port_val = 80
    gb_mode_val = 'dir'
    if 'gobuster_txt' in detected:
        _h, _p, _m = _gobuster_extract_target(detected['gobuster_txt'])
        if _h: gb_host_val = _h
        if _p: gb_port_val = _p
        if _m: gb_mode_val = _m

    # Map parser keys to (callable, host_required)
    HOST_REQUIRED = {
        'gobuster_txt', 'enum4linux_json', 'linpeas_txt',
        'winpeas_txt', 'snmp_txt', 'kerbrute_txt', 'getnpusers_hashes',
    }

    def _make_parser(key):
        if key == 'nmap_xml':        return lambda p: parse_nmap_xml(p)
        if key == 'gobuster_txt':    return lambda p: parse_gobuster_output(p, gb_host_val, gb_port_val, gb_mode_val)
        if key == 'nikto_json':      return lambda p: parse_nikto_json(p)
        if key == 'whatweb_json':    return lambda p: parse_whatweb_json(p)
        if key == 'enum4linux_json': return lambda p: parse_enum4linux_json(p, target_host)
        if key == 'linpeas_txt':     return lambda p: parse_linpeas(p, target_host)
        if key == 'winpeas_txt':     return lambda p: parse_winpeas(p, target_host)
        if key == 'snmp_txt':        return lambda p: parse_snmp_output(p, target_host)
        if key == 'sharphound_dir':  return lambda p: parse_sharphound_dir(p)
        if key == 'ldapdomaindump_dir': return lambda p: parse_ldapdomaindump_dir(p)
        if key == 'kerbrute_txt':    return lambda p: parse_kerbrute_output(p, target_host)
        if key == 'getnpusers_hashes': return lambda p: parse_getnpusers_output(p, target_host)
        if key == 'sqlmap_log':      return lambda p: parse_sqlmap_log(p)
        return None

    print(f"\n{C.BOLD}{C.CYAN}[*] Parsing detected files...{C.END}\n")
    all_raw_findings = []

    for key, path in detected.items():
        parser_fn = _make_parser(key)
        if parser_fn is None:
            continue
        if key in HOST_REQUIRED and not target_host:
            print(f"    {C.YELLOW}[!]{C.END} Skipping {key}: --target-host is required.")
            continue
        raw = parser_fn(path)
        validated = validate_parser_output(key, raw)
        all_raw_findings.extend(validated)
        label = os.path.relpath(path, loot_dir)
        print(f"    {C.GREEN}[+]{C.END} {key:<25} -> {len(validated)} findings  ({label})")
        logger.info("Scan parser %s produced %s validated findings", key, len(validated))

    if not all_raw_findings:
        print(f"\n{C.BOLD}{C.YELLOW}[!] No findings produced from any parser. Exiting.{C.END}")
        sys.exit(0)

    print(f"\n{C.BOLD}{C.CYAN}[*] Running Vulnerability Mapper...{C.END}\n")
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
    _display_results(args, synthesizer, prioritized)


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    print_banner()

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

    # ── manual mode args (no subcommand) ──────────────────────────────────────
    ag = main_parser.add_argument_group('Analysis Input Arguments')
    ag.add_argument("--nmap-xml", help="Path to Nmap XML output file.")
    ag.add_argument("--gobuster-txt", help="Path to Gobuster text output file.")
    ag.add_argument("--nikto-json", help="Path to Nikto JSON output file.")
    ag.add_argument("--whatweb-json", help="Path to WhatWeb JSON output file.")
    ag.add_argument("--enum4linux-json", help="Path to enum4linux-ng JSON output file.")
    ag.add_argument("--linpeas-txt", help="Path to LinPEAS output text file.")
    ag.add_argument("--winpeas-txt", help="Path to WinPEAS output text file.")
    ag.add_argument("--snmp-txt", help="Path to snmp-check output text file.")
    ag.add_argument("--sharphound-dir", help="Path to directory with unzipped SharpHound JSON files.")
    ag.add_argument("--ldapdomaindump-dir", help="Path to directory with ldapdomaindump TSV files.")
    ag.add_argument("--kerbrute-txt", help="Path to kerbrute valid user list.")
    ag.add_argument("--getnpusers-hashes", help="Path to impacket-GetNPUsers hash file.")
    ag.add_argument("--sqlmap-log", help="Path to sqlmap log file from its output directory.")
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

    args = main_parser.parse_args()
    configure_logging(args.verbose)

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
    _display_results(args, synthesizer, prioritized_findings)


if __name__ == "__main__":
    main()



