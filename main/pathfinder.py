import argparse
import sys
import json
import os
import re
import logging
import shlex
import shutil
import subprocess
import time
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
PROVENANCE_MANIFEST = "_pathfinder_provenance.json"


def configure_logging(verbosity):
    """Configures logger level based on CLI verbosity."""
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG
    logging.basicConfig(level=level, format=LOG_FORMAT)


def _normalise_provenance_path(path):
    """Return a stable, loot-root-relative key for provenance joins."""
    return str(path or "").replace("\\", "/").lstrip("./").lower()


def _load_provenance_manifest(loot_dir):
    """Load one-shot-enum's command-to-loot mapping, if present."""
    manifest_path = os.path.join(loot_dir, PROVENANCE_MANIFEST)
    try:
        with open(manifest_path, "r", encoding="utf-8-sig") as handle:
            payload = json.load(handle)
    except FileNotFoundError:
        return {}
    except (OSError, json.JSONDecodeError) as exc:
        print(f"{C.BOLD}{C.YELLOW}[!] Could not load discovery provenance from "
              f"'{manifest_path}': {exc}{C.END}")
        return {}

    records = payload.get("records", []) if isinstance(payload, dict) else []
    by_file = {}
    for record in records:
        if not isinstance(record, dict) or not record.get("output_file"):
            continue
        by_file[_normalise_provenance_path(record["output_file"])] = record
    return by_file


def _attach_discovery_provenance(finding, source_file=None, manifest_record=None):
    """Attach a normalized provenance record without changing finding identity."""
    attrs = finding.setdefault("attributes", {})
    if source_file:
        attrs["source_file"] = source_file

    record = manifest_record or {}
    provenance = {
        "tool": record.get("tool") or attrs.get("discovery_tool") or finding.get("source_tool"),
        "command": record.get("command") or attrs.get("discovery_command"),
    }
    effective_source = source_file or attrs.get("source_file")
    if effective_source:
        provenance["source_file"] = effective_source
    if record.get("status"):
        provenance["status"] = record["status"]
    if record.get("parser"):
        provenance["parser"] = record["parser"]

    existing = attrs.get("discovery_provenance")
    if not isinstance(existing, list):
        existing = []
    identity = (
        provenance.get("tool"), provenance.get("command"),
        provenance.get("source_file"), provenance.get("status"),
    )
    if identity not in {
        (p.get("tool"), p.get("command"), p.get("source_file"), p.get("status"))
        for p in existing if isinstance(p, dict)
    }:
        existing.append(provenance)
    attrs["discovery_provenance"] = existing


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
    is_public_exploit = "EDB-ID" in display_name or "GitHub Exploit" in display_name
    if "EDB-ID" in display_name: display_name = display_name.replace("EDB-ID", f"{C.BOLD}{C.RED}EDB-ID{C.END}")
    if "GitHub Exploit" in display_name: display_name = display_name.replace("GitHub Exploit", f"{C.BOLD}{C.GREEN}GitHub Exploit{C.END}")
    if not is_public_exploit:
        display_name = f"{C.BOLD}{display_name}{C.END}"
    if entity_type == "privilege_escalation": display_type = f"({C.BOLD}{C.RED}{entity_type}{C.END})"
    elif entity_type == "web_content": display_type = f"({C.LIGHT_BLUE}{entity_type}{C.END})"
    elif entity_type == "misconfiguration": display_type = f"({C.YELLOW}{entity_type}{C.END})"
    elif entity_type == "vulnerability": display_type = f"({C.RED}{entity_type}{C.END})"
    else: display_type = f"({C.YELLOW}{entity_type}{C.END})"
    return display_name, display_type


def _rule_line(char="=", colour=None):
    colour = colour if colour is not None else C.CYAN
    return f"{C.BOLD}{colour}{char * 80}{C.END}"


def _label(label, width=13):
    return f"{C.BOLD}{C.CYAN}{label:<{width}}{C.END}"


def _priority_token(label, value):
    return f"{C.BOLD}{C.YELLOW}[{label}: {value}]{C.END}"


def _score_token(score):
    try:
        numeric = int(score)
    except (TypeError, ValueError):
        return f"{C.BOLD}{C.YELLOW}[Score: {score}]{C.END}"
    colour = C.RED if numeric >= 90 else C.YELLOW if numeric >= 70 else C.GREEN
    return f"{C.BOLD}{colour}[Score: {numeric:>3}]{C.END}"


def _finding_type_token(entity_type):
    plain = f"({entity_type or 'unknown'})"
    if entity_type == "privilege_escalation":
        colour = C.RED
        weight = C.BOLD
    elif entity_type == "web_content":
        colour = C.LIGHT_BLUE
        weight = ""
    elif entity_type == "misconfiguration":
        colour = C.YELLOW
        weight = ""
    elif entity_type == "vulnerability":
        colour = C.RED
        weight = ""
    else:
        colour = C.YELLOW
        weight = ""
    return f"{weight}{colour}{plain:<26}{C.END}"


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
    if entity_type == "password_candidate":
        attrs = finding.get("attributes") or {}
        secret = str(attrs.get("password") or finding.get("name") or "")
        return ("password_candidate", finding.get("host"), secret)
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

    provenance = kept_attrs.get("discovery_provenance")
    if not isinstance(provenance, list):
        provenance = []
    identities = {
        (p.get("tool"), p.get("command"), p.get("source_file"), p.get("status"))
        for p in provenance if isinstance(p, dict)
    }
    for record in dup_attrs.get("discovery_provenance") or []:
        if not isinstance(record, dict):
            continue
        identity = (
            record.get("tool"), record.get("command"),
            record.get("source_file"), record.get("status"),
        )
        if identity not in identities:
            provenance.append(record)
            identities.add(identity)
    if provenance:
        kept_attrs["discovery_provenance"] = provenance


def _merge_credential(kept, duplicate):
    """Merge a duplicate credential into the kept one: fill in any missing secret
    material and attributes (never overwrite an existing value), keep the max score,
    and record provenance."""
    kept_attrs = kept.setdefault("attributes", {})
    dup_attrs = duplicate.get("attributes") or {}
    for field, value in dup_attrs.items():
        if field in ("score", "source_file", "corroborating_sources", "source_files",
                     "discovery_provenance"):
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
    """Provides an interactive wizard for users to add identities/secrets they have found."""
    print(f"\n{C.BOLD}{C.CYAN}[*] Pathfinder Credential Manager{C.END}")
    creds = []
    if os.path.exists(CREDENTIALS_FILE):
        try:
            with open(CREDENTIALS_FILE, 'r') as f:
                content = f.read()
                if content: creds = json.loads(content)
        except json.JSONDecodeError:
            print(f"{C.BOLD}{C.YELLOW}[!] Warning: {CREDENTIALS_FILE} is corrupted. Starting fresh.{C.END}")

    print(f"    [+] Found {len(creds)} existing manual entr{'y' if len(creds) == 1 else 'ies'}.")

    try:
        while True:
            print("\n--- Adding a Manual Identity / Secret ---")
            username = input(" > Enter username (blank for password-only, or 'q' to finish): ").strip()
            if username.lower() in {"q", "quit", "done", "exit"}:
                break
            if username:
                cred_type = input(" > Add [p]assword, [h]ash, or [n]o secret / username-only? [p]: ").strip().lower() or 'p'
            else:
                cred_type = input(" > Password-only candidate? Enter [p]assword or [q]uit: ").strip().lower() or 'p'
                if cred_type in {"q", "quit", "done", "exit"}:
                    break
                if cred_type != 'p':
                    print(f"{C.BOLD}{C.YELLOW}[!] Password-only entries need a cleartext password. Skipping.{C.END}")
                    continue

            password, hash_val, hash_type = None, None, None
            if cred_type == 'p':
                password = input(" > Enter password: ").strip()
            elif cred_type == 'h':
                hash_val = input(" > Enter full hash: ").strip()
                hash_type = input(" > Enter hash type (e.g., NTLM, Kerberos AS-REP (18200)): ").strip()
            elif cred_type == 'n' and username:
                pass
            else:
                print(f"{C.BOLD}{C.YELLOW}[!] Invalid type. Skipping.{C.END}"); continue

            if not any([username, password, hash_val]):
                print(f"{C.BOLD}{C.YELLOW}[!] Nothing to add. Skipping.{C.END}")
                continue

            source = input(" > Where did you find this? (e.g., 'config.php.bak'): ").strip()
            if username and (password or hash_val):
                kind = "credential"
                label = f"Credential for '{username}'"
            elif username:
                kind = "user"
                label = f"Username '{username}'"
            else:
                kind = "password_candidate"
                label = "Password candidate"
            creds.append({
                "kind": kind,
                "username": username or None,
                "password": password,
                "hash": hash_val,
                "hash_type": hash_type,
                "source": source,
            })
            print(f"    {C.BOLD}{C.GREEN}[+] {label} added as {kind}.{C.END}")
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
        for finding in validated_findings:
            _attach_discovery_provenance(finding, source_file=str(file_path))
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
        if (os.path.splitext(path)[1].lower() in {'.html', '.htm'}
                or re.search(r'(?i)<!doctype\s+html|<html(?:\s|>)|<body(?:\s|>)', sanitized_head)):
            return 'webpage_html', 'matched saved webpage HTML signature'
        return None, 'XML-like content but no supported XML parser signature'
    if os.path.splitext(path)[1].lower() in {'.html', '.htm'}:
        return 'webpage_html', 'matched saved webpage file extension'

    # JSON formats. Be careful not to misclassify plain-text logs that start
    # with bracketed tokens like [INFO], [*], or [+].
    if stripped.startswith('{') or re.match(r'^\[\s*[{"]', stripped):
        if '"type": "ai_post_exploitation_loot"' in sanitized_head or '"type":"ai_post_exploitation_loot"' in sanitized_head \
                or '"tool": "pathfinder-ai-loot-collector"' in sanitized_head:
            return 'ai_loot_json', 'matched PathFinder AI post-exploitation loot signature'
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
            for root, dirs, files in os.walk(entry.path):
                # Helper output and directory-parser payloads should not be
                # reinterpreted as loose files. ffuf response-body directories
                # intentionally remain visible here.
                dirs[:] = [name for name in dirs if not name.startswith(("_", "."))]
                if root in dir_parser_paths:
                    dirs[:] = []
                    continue
                for filename in files:
                    path = os.path.join(root, filename)
                    label = os.path.relpath(path, directory)
                    _sniff_and_record(path, label, host, detections, verbose)
        except (PermissionError, FileNotFoundError):
            continue

    return detections


def _inherited_ffuf_provenance(relative_path, provenance_by_file):
    """Use the producer record for ffuf JSON when parsing a stored -od body."""
    parts = re.split(r"[\\/]", str(relative_path))
    for index, part in enumerate(parts):
        match = re.fullmatch(r"ffuf_pages_(?:https?)_(\d{1,5})", part, re.IGNORECASE)
        if not match:
            continue
        ffuf_json = "/".join(parts[:index] + [f"ffuf_{match.group(1)}.json"])
        return provenance_by_file.get(_normalise_provenance_path(ffuf_json))
    return None


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


def _is_ai_related_finding(finding):
    if finding.get("entity_type") in ("ai_service", "ai_post_exploitation"):
        return True
    return str(finding.get("source_tool") or "").startswith("one-shot-enum-llm")


def _is_ai_related_path(path):
    if path.get("atlas"):
        return True
    return any("(ai_service)" in str(evidence) for evidence in (path.get("evidence") or []))


LIKELIHOOD_RANK = {"low": 0, "medium": 1, "high": 2}
LIKELIHOOD_LABELS = {
    "high": "Critical / likely exploitation",
    "medium": "High-signal next steps",
    "low": "Manual validation / lower confidence",
}
DEFAULT_TRIAGE_TOP = 20


def _path_text(path):
    suggestion = path.get("suggestion") or {}
    parts = [
        path.get("name", ""),
        suggestion.get("description", ""),
        suggestion.get("rationale", ""),
        " ".join(suggestion.get("commands") or []),
        " ".join(path.get("evidence") or []),
    ]
    return " ".join(str(p) for p in parts if p).lower()


def _path_likelihood(path):
    """Actionability estimate used only for human triage output.

    The rule priority remains the source of truth for path generation. Likelihood
    answers a narrower question: "how likely is this to be worth trying first?"
    """
    effective = path.get("effective_priority", path.get("priority", 0)) or 0
    evidence_score = path.get("evidence_score", 0) or 0
    text = _path_text(path)

    low_validation_terms = (
        "triage candidate", "parameterized url", "manual validation",
        "interesting but", "review manually",
    )
    if effective < 80 and any(term in text for term in low_validation_terms):
        return "low"

    high_action_terms = (
        "confirmed", "credential reuse", "pass-the-hash", "pwn3d", "dcsync",
        "secretsdump", "webshell", "rce", "remote code execution", "writable",
        "write-to-rce", "artifact write to code execution", "no_root_squash",
        "kerberoast", "as-rep", "admin access",
    )
    if effective >= 90 or any(term in text for term in high_action_terms):
        return "high"
    if effective >= 75 or evidence_score >= 80:
        return "medium"
    return "low"


def _passes_min_likelihood(path, min_likelihood):
    wanted = min_likelihood if min_likelihood in LIKELIHOOD_RANK else "low"
    return LIKELIHOOD_RANK[_path_likelihood(path)] >= LIKELIHOOD_RANK[wanted]


def _target_label(path):
    return str(path.get("host") or "GLOBAL")


def _target_summary(paths, limit=5):
    targets = []
    seen = set()
    for path in paths:
        label = _target_label(path)
        if label in seen:
            continue
        seen.add(label)
        targets.append(label)
    shown = targets[:limit]
    extra = len(targets) - len(shown)
    suffix = f" (+{extra} more)" if extra > 0 else ""
    return ", ".join(shown) + suffix if shown else "n/a"


def _group_attack_paths(paths):
    groups_by_name = {}
    for path in paths:
        key = path.get("name") or "<unnamed>"
        group = groups_by_name.setdefault(key, {"name": key, "paths": []})
        group["paths"].append(path)

    groups = []
    for group in groups_by_name.values():
        grouped_paths = group["paths"]
        representative = grouped_paths[0]
        likelihoods = [_path_likelihood(p) for p in grouped_paths]
        group["representative"] = representative
        group["count"] = len(grouped_paths)
        group["likelihood"] = max(likelihoods, key=lambda x: LIKELIHOOD_RANK[x])
        group["max_priority"] = max(
            p.get("effective_priority", p.get("priority", 0)) or 0 for p in grouped_paths
        )
        group["max_evidence_score"] = max(p.get("evidence_score", 0) or 0 for p in grouped_paths)
        group["targets"] = _target_summary(grouped_paths)
        groups.append(group)

    groups.sort(key=lambda g: (
        -LIKELIHOOD_RANK[g["likelihood"]],
        -g["max_priority"],
        -g["max_evidence_score"],
        g["name"],
    ))
    return groups


def _finding_discovery_provenance(finding):
    attrs = finding.get("attributes") or {}
    records = attrs.get("discovery_provenance")
    if isinstance(records, list) and records:
        return [record for record in records if isinstance(record, dict)]
    return [{
        "tool": attrs.get("discovery_tool") or finding.get("source_tool"),
        "command": attrs.get("discovery_command"),
        "source_file": attrs.get("source_file"),
    }]


def _deduplicate_provenance(records):
    unique = []
    seen = set()
    for record in records:
        if not isinstance(record, dict):
            continue
        normalized = {
            "tool": record.get("tool") or "unknown",
            # Commands are intentionally preserved verbatim. PathFinder is a
            # pentest loot tool and its findings may legitimately contain creds.
            "command": record.get("command"),
            "source_file": record.get("source_file"),
            "status": record.get("status"),
        }
        key = tuple(normalized.get(field) for field in
                    ("tool", "command", "source_file", "status"))
        if key in seen:
            continue
        seen.add(key)
        unique.append(normalized)
    return unique


def _path_discovery_provenance(path):
    records = []
    for matched in path.get("matched_findings") or []:
        finding = matched.get("finding") if isinstance(matched, dict) else None
        if isinstance(finding, dict):
            records.extend(_finding_discovery_provenance(finding))
    return _deduplicate_provenance(records)


def _print_discovery_provenance(records, args, indent="  "):
    if getattr(args, "hide_discovery", False):
        return
    records = _deduplicate_provenance(records)
    if not records:
        return
    print(f"\n{indent}{C.BOLD}{C.GREEN}[+]{C.END} {C.BOLD}Discovery Provenance:{C.END}")
    for record in records:
        command = record.get("command") or "not recorded"
        print(f"{indent}    {C.GREEN}-{C.END} Tool: {record['tool']}")
        print(f"{indent}      Command: {command}")
        if getattr(args, "verbose", 0) > 0:
            if record.get("source_file"):
                print(f"{indent}      Source: {record['source_file']}")
            if record.get("status"):
                print(f"{indent}      Status: {record['status']}")


def _print_finding_discovery(finding, args):
    if getattr(args, "hide_discovery", False):
        return
    records = _deduplicate_provenance(_finding_discovery_provenance(finding))
    for index, record in enumerate(records):
        label = "Discovery:" if index == 0 else "Corroborated:"
        print(f"      {_label(label, 14)}{record['tool']}")
        print(f"      {_label('Command:', 14)}{record.get('command') or 'not recorded'}")
        if getattr(args, "verbose", 0) > 0:
            if record.get("source_file"):
                print(f"      {_label('Source:', 14)}{record['source_file']}")
            if record.get("status"):
                print(f"      {_label('Status:', 14)}{record['status']}")


_ACTION_ENTITY_TYPES = {
    "service", "web_content", "share", "nfs_export", "ai_service",
    "software_product", "vulnerability", "misconfiguration", "database",
}
MAX_GROUP_ACTION_BUCKETS = 8
MAX_GROUP_INPUTS = 8
MAX_GROUP_COMMANDS = 8
CREDENTIAL_VALIDATION_TIMEOUT = 60
_LOGIN_PROTOCOLS = {
    "ssh": "ssh",
    "ftp": "ftp",
    "rdp": "rdp",
    "ms-wbt-server": "rdp",
    "winrm": "winrm",
    "smb": "smb",
    "microsoft-ds": "smb",
}
_LOGIN_DEFAULT_PORTS = {"ftp": 21, "ssh": 22, "smb": 445, "rdp": 3389, "winrm": 5985}


def _matched_finding_records(path):
    return [record for record in (path.get("matched_findings") or [])
            if isinstance(record, dict) and isinstance(record.get("finding"), dict)]


def _action_record(path):
    records = _matched_finding_records(path)
    for record in reversed(records):
        if record["finding"].get("entity_type") in _ACTION_ENTITY_TYPES:
            return record
    return records[-1] if records else None


def _action_label(path, record):
    if not record:
        return str(path.get("host") or "GLOBAL")
    finding = record["finding"]
    host = finding.get("host") or path.get("host") or "GLOBAL"
    port = finding.get("port")
    target = f"{host}:{port}" if port is not None else str(host)
    return f"{finding.get('name')} ({finding.get('entity_type')}) @ {target}"


def _variant_inputs(path, action):
    values = []
    for record in _matched_finding_records(path):
        if record is action:
            continue
        finding = record["finding"]
        value = f"{finding.get('name')} ({finding.get('entity_type')})"
        if value not in values:
            values.append(value)
    return values


def _group_action_buckets(paths):
    buckets = {}
    for path in paths:
        action = _action_record(path)
        label = _action_label(path, action)
        bucket = buckets.setdefault(label, {"label": label, "paths": [], "inputs": []})
        bucket["paths"].append(path)
        for value in _variant_inputs(path, action):
            if value not in bucket["inputs"]:
                bucket["inputs"].append(value)
    return list(buckets.values())


_COMPACT_LOGIN_RULES = {
    "Credential Reuse on Login Service",
    "Password Spray Discovered Users Against Services",
}


def _print_compact_login_bucket(bucket, rule_name):
    usernames = []
    candidates = []
    credentials = []
    secret_kinds = set()
    service = None
    for path in bucket["paths"]:
        for record in _matched_finding_records(path):
            finding = record["finding"]
            entity_type = finding.get("entity_type")
            attrs = finding.get("attributes") or {}
            if entity_type == "service":
                service = service or finding
            elif entity_type == "user" and finding.get("name") not in usernames:
                usernames.append(finding["name"])
            elif entity_type == "username_candidate" and finding.get("name") not in candidates:
                candidates.append(finding["name"])
            elif entity_type == "credential":
                username = attrs.get("username") or finding.get("name")
                if attrs.get("password"):
                    label = f"{username}:{attrs['password']}"
                    secret_kinds.add("password")
                elif _usable_ntlm_hash(attrs):
                    label = f"{username}:{_usable_ntlm_hash(attrs)}"
                    secret_kinds.add("hash")
                else:
                    label = str(username)
                if label not in credentials:
                    credentials.append(label)

    def print_values(label, values):
        if not values:
            return
        shown = values[:MAX_GROUP_INPUTS]
        suffix = f" (+{len(values) - len(shown)} more)" if len(values) > len(shown) else ""
        print(f"        {label}: {', '.join(shown)}{suffix}")

    print_values("Credentials", credentials)
    print_values("Confirmed usernames", usernames)
    print_values("Potential usernames (manual triage)", candidates)

    if not service:
        return
    service_name = str(service.get("name") or "").lower()
    protocol = _LOGIN_PROTOCOLS.get(service_name, "<PROTOCOL>")
    host = service.get("host") or "<TARGET>"
    port = service.get("port")
    base = f"nxc {protocol} {host}"
    if port and port != _LOGIN_DEFAULT_PORTS.get(protocol):
        base += f" --port {port}"
    print("        Core command:")
    if rule_name == "Credential Reuse on Login Service" and secret_kinds == {"hash"}:
        print(f"          {C.GREEN}-{C.END} {base} -u '<USERNAME>' -H '<NTLM_HASH>'")
    else:
        print(f"          {C.GREEN}-{C.END} {base} -u '<USERNAME>' -p '<PASSWORD>'")
        if rule_name == "Credential Reuse on Login Service" and "hash" in secret_kinds:
            print(f"          {C.GREEN}-{C.END} {base} -u '<USERNAME>' -H '<NTLM_HASH>'")


def _print_grouped_resolved_actions(group, args):
    buckets = _group_action_buckets(group["paths"])
    print(f"\n  {C.BOLD}{C.GREEN}[+]{C.END} {C.BOLD}Resolved Actions:{C.END}")
    for bucket in buckets[:MAX_GROUP_ACTION_BUCKETS]:
        paths = bucket["paths"]
        print(f"      {C.GREEN}-{C.END} {bucket['label']} "
              f"({len(paths)} resolved variant(s))")
        if group.get("name") in _COMPACT_LOGIN_RULES:
            _print_compact_login_bucket(bucket, group["name"])
            continue
        inputs = bucket["inputs"]
        if inputs:
            shown = inputs[:MAX_GROUP_INPUTS]
            suffix = f" (+{len(inputs) - len(shown)} more)" if len(inputs) > len(shown) else ""
            print(f"        Inputs: {', '.join(shown)}{suffix}")

        commands = []
        for path in paths:
            for command in (path.get("suggestion") or {}).get("commands") or []:
                if command not in commands:
                    commands.append(command)
        if commands:
            uses_msf = False
            if getattr(args, "oscp", False):
                commands, uses_msf = _oscp_process_commands(commands)
            print("        Resolved commands:")
            for command in commands[:MAX_GROUP_COMMANDS]:
                print(f"          {C.GREEN}-{C.END} {command}")
            if len(commands) > MAX_GROUP_COMMANDS:
                print(f"          {C.YELLOW}[!] {len(commands) - MAX_GROUP_COMMANDS} more resolved "
                      "command(s); use --show-all for every variant.")
            if uses_msf:
                print(f"          {C.YELLOW}[OSCP] Metasploit/Meterpreter is limited to ONE target "
                      f"on the exam.{C.END}")
    if len(buckets) > MAX_GROUP_ACTION_BUCKETS:
        print(f"      {C.YELLOW}[!] {len(buckets) - MAX_GROUP_ACTION_BUCKETS} more action bucket(s); "
              "use --show-all for every variant.")


def _credential_validation_binary(protocol):
    for binary in ("nxc", "netexec"):
        if shutil.which(binary):
            return binary, True
    if protocol in {"smb", "winrm", "ssh"} and shutil.which("crackmapexec"):
        return "crackmapexec", True
    return "nxc", False


def _display_command(argv):
    if os.name == "nt":
        return subprocess.list2cmdline(argv)
    return shlex.join(argv)


def _usable_ntlm_hash(attributes):
    direct = attributes.get("nt_hash") or attributes.get("ntlm_hash")
    if direct:
        return direct
    hash_value = attributes.get("hash")
    hash_type = str(attributes.get("hash_type") or "").lower()
    if hash_value and ("ntlm" in hash_type or hash_type in {"nt", "nthash"}):
        return hash_value
    return None


def _credential_validation_actions(paths):
    """Build one active login attempt per resolved credential/service pairing."""
    actions = []
    seen = set()
    for path in paths:
        if path.get("name") != "Credential Reuse on Login Service":
            continue
        findings = [record["finding"] for record in _matched_finding_records(path)]
        credential = next((f for f in findings if f.get("entity_type") == "credential"), None)
        service = next((f for f in findings if f.get("entity_type") == "service"), None)
        if not credential or not service:
            continue
        protocol = _LOGIN_PROTOCOLS.get(str(service.get("name") or "").lower())
        attrs = credential.get("attributes") or {}
        username = attrs.get("username") or credential.get("name")
        password = attrs.get("password")
        hash_value = _usable_ntlm_hash(attrs)
        if not protocol or not username:
            continue
        if password:
            secret_kind, secret = "password", str(password)
        elif hash_value and protocol in {"smb", "winrm"}:
            secret_kind, secret = "hash", str(hash_value)
        else:
            continue
        host = service.get("host") or path.get("host")
        if not host:
            continue
        port = service.get("port")
        key = (protocol, str(host), port, str(username), secret_kind, secret)
        if key in seen:
            continue
        seen.add(key)
        binary, binary_available = _credential_validation_binary(protocol)
        argv = [binary, protocol, str(host)]
        if port and port != _LOGIN_DEFAULT_PORTS.get(protocol):
            argv.extend(["--port", str(port)])
        argv.extend(["-u", str(username), "-p" if secret_kind == "password" else "-H", secret])
        domain = attrs.get("domain")
        if domain and "\\" not in str(username) and "@" not in str(username):
            argv.extend(["-d", str(domain)])
        actions.append({
            "protocol": protocol, "host": str(host), "port": port,
            "username": str(username), "secret": secret, "secret_kind": secret_kind,
            "argv": argv, "command": _display_command(argv),
            "binary_available": binary_available,
        })
    return actions


def _credential_login_succeeded(output, action):
    clean = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", output or "")
    lowered = clean.lower()
    if "pwn3d!" in lowered:
        return True
    username = action["username"].lower()
    for line in lowered.splitlines():
        if "[+]" in line and username in line:
            return True
        if "login successful" in line or "authentication successful" in line:
            if username in line or action["host"].lower() in line:
                return True
    return False


def _credential_login_rejected(output, action):
    clean = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", output or "").lower()
    username = action["username"].lower()
    return any("[-]" in line and username in line for line in clean.splitlines())


def _print_credential_validation_plan(actions):
    print(f"\n{C.BOLD}{C.CYAN}Credential Validation Plan{C.END}")
    print(f"  {C.GREEN}{len(actions)} active login attempt(s) queued sequentially{C.END}")
    for host in dict.fromkeys(action["host"] for action in actions):
        host_actions = [action for action in actions if action["host"] == host]
        print(f"\n  {C.BOLD}{C.CYAN}Host: {host}  ({len(host_actions)} attempt(s)){C.END}")
        for action in host_actions:
            identity = f"{action['username']}:{action['secret']}"
            print(f"    {C.BOLD}{action['protocol']:<8}{C.END} {identity}")
            print(f"      {action['command']}")


def _validation_cell(value, width):
    value = str(value)
    if len(value) > width:
        value = value[:width - 1] + "~"
    return value.ljust(width)


def _subprocess_text(value):
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return value or ""


def _run_credential_validations(paths):
    actions = _credential_validation_actions(paths)
    if not actions:
        print(f"\n{C.BOLD}{C.YELLOW}[!] Credential validation requested, but no resolved "
              f"credential/login-service actions were available.{C.END}")
        return []

    _print_credential_validation_plan(actions)
    print(f"\n{C.BOLD}{C.CYAN}Credential Validation Stage{C.END}")
    print(f"  {'#':<4}{'SERVICE':<10}{'TARGET':<24}{'IDENTITY':<24}{'STATUS':<12}{'TIME':>5}")
    results = []
    for index, action in enumerate(actions, start=1):
        print(f"\n  {C.CYAN}[{index}/{len(actions)}] Running:{C.END} {action['command']}")
        started = time.monotonic()
        output = ""
        if not action["binary_available"]:
            status = "no tool"
        else:
            try:
                completed = subprocess.run(
                    action["argv"], capture_output=True, text=True,
                    errors="replace", stdin=subprocess.DEVNULL,
                    timeout=CREDENTIAL_VALIDATION_TIMEOUT, check=False,
                )
                output = _subprocess_text(completed.stdout) + _subprocess_text(completed.stderr)
                if _credential_login_succeeded(output, action):
                    status = "SUCCESS"
                elif _credential_login_rejected(output, action):
                    status = "rejected"
                elif completed.returncode:
                    status = f"exit {completed.returncode}"
                else:
                    status = "unknown"
            except subprocess.TimeoutExpired as exc:
                output = _subprocess_text(exc.stdout) + _subprocess_text(exc.stderr)
                status = "timed out"
            except OSError as exc:
                output = str(exc)
                status = "failed"
        elapsed = int(time.monotonic() - started)
        target = f"{action['host']}:{action['port']}" if action.get("port") else action["host"]
        identity = f"{action['username']}:{action['secret']}"
        colour = C.GREEN if status == "SUCCESS" else C.YELLOW if status in {"unknown", "no tool"} else C.RED
        print(f"  {index:<4}{_validation_cell(action['protocol'], 10)}"
              f"{_validation_cell(target, 24)}{_validation_cell(identity, 24)}"
              f"{colour}{status:<12}{C.END}{elapsed // 60:02d}:{elapsed % 60:02d}")
        result = {**action, "status": status, "output": output}
        results.append(result)
        if status == "SUCCESS":
            print(f"\n  {C.BOLD}{C.GREEN}[+] VALID LOGIN: {identity} -> "
                  f"{action['protocol']}://{target}{C.END}\n")

    successes = [result for result in results if result["status"] == "SUCCESS"]
    print(f"\n{C.BOLD}{C.CYAN}Credential Validation Summary:{C.END} "
          f"{C.GREEN}{len(successes)} successful{C.END}, "
          f"{len(results) - len(successes)} unsuccessful/inconclusive, "
          f"{len(results)} total")
    if successes:
        print(f"{C.BOLD}{C.GREEN}[+] Confirmed valid login(s):{C.END}")
        for result in successes:
            target = f"{result['host']}:{result['port']}" if result.get("port") else result["host"]
            print(f"    {C.GREEN}-{C.END} {result['username']}:{result['secret']} -> "
                  f"{result['protocol']}://{target}")
    return results


def _print_path_details(path, args):
    suggestion = path.get("suggestion") or {}
    print(f"\n  {C.BOLD}{C.GREEN}[+]{C.END} {C.BOLD}Description:{C.END}\n      {suggestion.get('description', '')}")
    _print_discovery_provenance(_path_discovery_provenance(path), args)
    if getattr(args, 'verbose', 0) > 0:
        print(f"\n  {C.BOLD}{C.GREEN}[+]{C.END} {C.BOLD}Rationale:{C.END}\n      {suggestion.get('rationale', '')}")
    if suggestion.get('commands'):
        print(f"\n  {C.BOLD}{C.GREEN}[+]{C.END} {C.BOLD}Suggested Commands:{C.END}")
        cmds = suggestion.get('commands') or []
        uses_msf = False
        if getattr(args, 'oscp', False):
            cmds, uses_msf = _oscp_process_commands(cmds)
        for cmd in cmds:
            print(f"      {C.GREEN}-{C.END} {cmd}")
        if uses_msf:
            print(f"      {C.YELLOW}[OSCP] Metasploit/Meterpreter is limited to ONE target on the exam.{C.END}")
    if suggestion.get('injection_examples'):
        print(f"\n  {C.BOLD}{C.GREEN}[+]{C.END} {C.BOLD}Prompt-injection examples:{C.END}")
        for ex in suggestion['injection_examples']:
            print(f"      {C.GREEN}-{C.END} {ex}")
    if path.get('atlas'):
        print(f"\n  {C.BOLD}{C.GREEN}[+]{C.END} {C.BOLD}MITRE ATLAS:{C.END}")
        for tag in path['atlas']:
            print(f"      {C.GREEN}-{C.END} {tag}")
    if suggestion.get('references'):
        print(f"\n  {C.BOLD}{C.GREEN}[+]{C.END} {C.BOLD}References:{C.END}")
        for ref in suggestion['references']:
            print(f"      {C.GREEN}-{C.END} {ref}")
    if getattr(args, 'verbose', 0) > 0 and path.get('evidence'):
        print(f"\n  {C.BOLD}{C.GREEN}[+]{C.END} {C.BOLD}Matched Evidence:{C.END}")
        for ev in path['evidence']:
            print(f"      {C.GREEN}-{C.END} {ev}")


def _print_attack_path(path, args, index):
    print("\n" + _rule_line())
    print(f"{C.BOLD}{C.CYAN}ATTACK PATH #{index}{C.END}")
    eff = path.get('effective_priority', path['priority'])
    base = path['priority']
    prio_label = (f"{eff}" if eff == base
                  else f"{eff}  (base {base}, adjusted for evidence quality)")
    print(f"{_priority_token('Priority', prio_label)}")
    print(f"{_label('Name:')} {C.BOLD}{path['name']}{C.END}")
    print(f"{_label('Likelihood:')} {LIKELIHOOD_LABELS[_path_likelihood(path)]}")
    print(f"{_label('Target:')} {path['host']}")
    print(_rule_line())
    _print_path_details(path, args)


def _print_attack_path_group(group, args, index):
    path = group["representative"]
    print("\n" + _rule_line())
    print(f"{C.BOLD}{C.CYAN}TRIAGE ATTACK PATH #{index}{C.END}")
    print(f"{_priority_token('Top Priority', group['max_priority'])}")
    print(f"{_label('Name:')} {C.BOLD}{group['name']}{C.END}")
    print(f"{_label('Likelihood:')} {LIKELIHOOD_LABELS[group['likelihood']]}")
    print(f"{_label('Targets:')} {group['targets']}")
    print(f"{_label('Grouped hits:')} {group['count']} underlying path(s)")
    print(_rule_line())
    if group["count"] == 1:
        _print_path_details(path, args)
        return

    suggestion = path.get("suggestion") or {}
    _print_grouped_resolved_actions(group, args)
    provenance = []
    for grouped_path in group["paths"]:
        provenance.extend(_path_discovery_provenance(grouped_path))
    _print_discovery_provenance(provenance, args)
    if getattr(args, "verbose", 0) > 0:
        print(f"\n  {C.BOLD}{C.GREEN}[+]{C.END} {C.BOLD}Rationale:{C.END}\n"
              f"      {suggestion.get('rationale', '')}")
    if suggestion.get("injection_examples"):
        print(f"\n  {C.BOLD}{C.GREEN}[+]{C.END} {C.BOLD}Prompt-injection examples:{C.END}")
        for example in suggestion["injection_examples"]:
            print(f"      {C.GREEN}-{C.END} {example}")
    if path.get("atlas"):
        print(f"\n  {C.BOLD}{C.GREEN}[+]{C.END} {C.BOLD}MITRE ATLAS:{C.END}")
        for tag in path["atlas"]:
            print(f"      {C.GREEN}-{C.END} {tag}")
    if suggestion.get("references"):
        print(f"\n  {C.BOLD}{C.GREEN}[+]{C.END} {C.BOLD}References:{C.END}")
        for ref in suggestion["references"]:
            print(f"      {C.GREEN}-{C.END} {ref}")
    if getattr(args, "verbose", 0) > 0:
        evidence = []
        for grouped_path in group["paths"]:
            for item in grouped_path.get("evidence") or []:
                if item not in evidence:
                    evidence.append(item)
        if evidence:
            print(f"\n  {C.BOLD}{C.GREEN}[+]{C.END} {C.BOLD}Matched Evidence:{C.END}")
            for item in evidence[:MAX_GROUP_INPUTS]:
                print(f"      {C.GREEN}-{C.END} {item}")
            if len(evidence) > MAX_GROUP_INPUTS:
                print(f"      {C.YELLOW}[!] {len(evidence) - MAX_GROUP_INPUTS} more evidence item(s); "
                      "use --show-all for every variant.")


def _display_results(args, synthesizer, prioritized_findings):
    """Runs the synthesizer and prints attack paths + findings list."""
    print(f"\n{C.BOLD}{C.CYAN}[*] Running Attack Path Synthesizer...{C.END}")
    suggested_paths = synthesizer.generate_attack_paths(prioritized_findings)
    display_paths = suggested_paths
    display_findings = prioritized_findings
    min_likelihood = getattr(args, 'min_likelihood', 'low')
    display_paths = [p for p in display_paths if _passes_min_likelihood(p, min_likelihood)]

    if display_paths:
        print(f"\n{_rule_line('-', C.YELLOW)}")
        print(f"{C.BOLD}{C.YELLOW}PathFinder identified {len(display_paths)} potential attack path(s){C.END}")
        print(_rule_line('-', C.YELLOW))
        if getattr(args, 'show_all', False):
            for i, path in enumerate(display_paths, start=1):
                _print_attack_path(path, args, i)
        else:
            groups = _group_attack_paths(display_paths)
            top = getattr(args, 'top', DEFAULT_TRIAGE_TOP)
            shown_groups = groups if not top or top <= 0 else groups[:top]
            print(f"\n{C.BOLD}{C.CYAN}[*] Triage view: showing {len(shown_groups)} grouped lead(s) "
                  f"from {len(display_paths)} path(s). Use --show-all for the exhaustive list.{C.END}")
            if min_likelihood != "low":
                print(f"{C.BOLD}{C.CYAN}[*] Minimum likelihood filter: {min_likelihood}.{C.END}")
            for i, group in enumerate(shown_groups, start=1):
                _print_attack_path_group(group, args, i)
            if len(shown_groups) < len(groups):
                print(f"\n{C.BOLD}{C.YELLOW}[!] {len(groups) - len(shown_groups)} additional grouped lead(s) hidden by --top {top}.{C.END}")
        print("\n" + _rule_line())
    else:
        print(f"\n{C.BOLD}{C.YELLOW}[!] No specific attack paths were synthesized from the findings.{C.END}")

    if getattr(args, "validate_credentials", False):
        _run_credential_validations(display_paths)

    if not getattr(args, "hide_findings", False):
        total_exploit_count = sum(
            1 for f in display_findings
            if f.get("source_tool") in ["searchsploit_mapper", "github_exploit_mapper"]
        )
        filtered_list = filter_prioritized_findings(display_findings, args.max_vulns)

        print(f"\n{_rule_line('-', C.YELLOW)}")
        print(f"{C.BOLD}{C.YELLOW}Total Findings: {len(filtered_list)}{C.END} "
              f"{C.YELLOW}(Public Exploits limited to --max-vulns, total discovered: {total_exploit_count}){C.END}")
        print(_rule_line('-', C.YELLOW))

        filtered_list.sort(key=lambda x: x.get("attributes", {}).get("score", 0), reverse=True)

        for i, p_finding in enumerate(filtered_list):
            score = p_finding.get("attributes", {}).get("score", "N/A")
            finding_name = p_finding.get("name")
            attributes = p_finding.get("attributes", {})
            if (p_finding.get("source_tool") == "manual_input"
                    and p_finding.get("entity_type") == "credential"
                    and attributes.get("username") and attributes.get("password")):
                finding_name = f"{attributes['username']}:{attributes['password']}"
            display_name, _ = format_finding_display(finding_name, p_finding.get('entity_type'))
            display_type = _finding_type_token(p_finding.get('entity_type'))
            print(f"\n{C.BOLD}{C.CYAN}[{i+1:03d}]{C.END} {_score_token(score)} {display_type} {display_name}")
            print(f"      {_label('Host:', 6)}{p_finding.get('host')}   {_label('Port:', 6)}{p_finding.get('port')}")
            _print_finding_discovery(p_finding, args)
            if p_finding.get("entity_type") == "username_candidate":
                print(f"      {_label('Triage:', 14)}Potential username only; validate manually")
                if attributes.get("confidence"):
                    print(f"      {_label('Confidence:', 14)}{attributes['confidence']}")
                if attributes.get("extraction_reason"):
                    print(f"      {_label('Reason:', 14)}{attributes['extraction_reason']}")
                if attributes.get("evidence"):
                    print(f"      {_label('Evidence:', 14)}{attributes['evidence']}")
            if attributes.get("metasploit_module"):
                print(f"      {C.BOLD}Metasploit Module:{C.END} {attributes['metasploit_module']}")
                if getattr(args, 'oscp', False):
                    print(f"      {C.YELLOW}[OSCP] Metasploit is limited to one target on the exam.{C.END}")
            if attributes.get("url"):
                print(f"      {C.BOLD}URL:{C.END} {attributes['url']}")
            if p_finding.get("entity_type") in {"web_parameterized_url", "web_parameterized_request"}:
                print(f"      {_label('Triage:', 14)}Potential injection surface only; validate manually")
                if attributes.get("method"):
                    print(f"      {_label('Method:', 14)}{attributes['method']}")
                if attributes.get("parameters"):
                    print(f"      {_label('Parameters:', 14)}{', '.join(attributes['parameters'])}")
                if attributes.get("data"):
                    print(f"      {_label('Form data:', 14)}{attributes['data']}")

    return suggested_paths


# ── AI attack-intelligence brief ────────────────────────────────────────────────

# ── Scan mode ─────────────────────────────────────────────────────────────────

def run_scan_mode(args):
    """Handles the 'scan' subcommand: auto-detects all tool output files in a directory."""
    synthesizer = AttackPathSynthesizer()
    loot_dir = os.path.abspath(args.loot_dir)
    provenance_by_file = _load_provenance_manifest(loot_dir)

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
        # Record provenance: which file, tool, and exact producer command each
        # finding came from. Legacy/manual loot remains valid with command=None.
        rel = os.path.relpath(path, loot_dir)
        manifest_record = provenance_by_file.get(_normalise_provenance_path(rel))
        if manifest_record is None and key == "webpage_html":
            manifest_record = _inherited_ffuf_provenance(rel, provenance_by_file)
        for finding in validated:
            _attach_discovery_provenance(finding, source_file=rel,
                                         manifest_record=manifest_record)
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
    _display_results(args, synthesizer, prioritized)


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
    scan_p.add_argument('--show-all', action='store_true', help='Display every synthesized attack path instead of the grouped triage view.')
    scan_p.add_argument('--hide-discovery', action='store_true', help='Hide discovery tool and command provenance from findings and attack paths.')
    scan_p.add_argument('--hide-findings', action='store_true', help='Hide the prioritized findings list (attack paths are still displayed).')
    scan_p.add_argument('--validate-credentials', action='store_true', help='Actively test resolved Credential Reuse login actions sequentially (may trigger lockouts or alerts).')
    scan_p.add_argument('--top', type=int, default=DEFAULT_TRIAGE_TOP, help=f'Max grouped attack-path leads to display in triage view (default: {DEFAULT_TRIAGE_TOP}; 0 = all).')
    scan_p.add_argument('--min-likelihood', choices=sorted(LIKELIHOOD_RANK.keys()), default='low', help='Only display attack paths at or above this triage likelihood (default: low).')

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
    lg.add_argument("--add-cred", action="store_true", help="Enter interactive mode to manually add a credential, username, or password candidate.")

    gg = main_parser.add_argument_group('General Arguments')
    gg.add_argument("-v", "--verbose", action="count", default=0, help="Verbosity level (-v, -vv).")
    gg.add_argument("--max-vulns", type=int, default=10, help="Max number of EDB/GitHub exploits to display (default: 10).")
    gg.add_argument("--offline", action="store_true", help="Disable external enrichment lookups (GitHub + Searchsploit).")
    gg.add_argument("--skip-github", action="store_true", help="Skip GitHub exploit repository enrichment.")
    gg.add_argument("--skip-searchsploit", action="store_true", help="Skip Searchsploit enrichment.")
    gg.add_argument("--github-cache", default=os.path.join(SCRIPT_DIR, "github_cache.json"), help="Path to GitHub lookup cache JSON file.")
    gg.add_argument("--no-color", action="store_true", help="Disable ANSI colour output.")
    gg.add_argument("--oscp", action="store_true", help="OSCP exam profile: strip prohibited-tool commands (sqlmap, nuclei) from suggestions and flag the Metasploit one-target limit.")
    gg.add_argument("--show-all", action="store_true", help="Display every synthesized attack path instead of the grouped triage view.")
    gg.add_argument("--hide-discovery", action="store_true", help="Hide discovery tool and command provenance from findings and attack paths.")
    gg.add_argument("--hide-findings", action="store_true", help="Hide the prioritized findings list (attack paths are still displayed).")
    gg.add_argument("--validate-credentials", action="store_true", help="Actively test resolved Credential Reuse login actions sequentially (may trigger lockouts or alerts).")
    gg.add_argument("--top", type=int, default=DEFAULT_TRIAGE_TOP, help=f"Max grouped attack-path leads to display in triage view (default: {DEFAULT_TRIAGE_TOP}; 0 = all).")
    gg.add_argument("--min-likelihood", choices=sorted(LIKELIHOOD_RANK.keys()), default="low", help="Only display attack paths at or above this triage likelihood (default: low).")

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
    _display_results(args, synthesizer, prioritized_findings)


if __name__ == "__main__":
    main()
