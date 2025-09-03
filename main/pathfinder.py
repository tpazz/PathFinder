import argparse
import sys
import json
import os

# Import all custom parser modules and the core logic components.
from .attack_path_synthesizer import AttackPathSynthesizer
from .vulnerability_mapper import VulnerabilityMapper
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

def print_banner():
    """Prints a cool banner for the tool."""
    # Using an f-string to embed color codes; backslashes must be escaped (\\).
    banner = f"""
{C.RED}__________          __   .__      _____ .__             .___              
\\______   \\_____  _/  |_ |  |__ _/ ____\\|__|  ____    __| _/ ____ _______ 
 |     ___/\\__  \\ \\   __\\|  |  \\\\   __\\ |  | /    \\  / __ |_/ __ \\\\_  __ \\
 |    |     / __ \\_|  |  |   Y  \\|  |   |  ||   |  \\/ /_/ |\\  ___/ |  | \\/
 |____|    (____  /|__|  |___|  /|__|   |__||___|  /\\____ | \\___  >|__|   
                \\/            \\/                 \\/      \\/     \\/        
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
    # Fallback color for any other entity type.
    else: display_type = f"({C.YELLOW}{entity_type}{C.END})"
    return display_name, display_type

def filter_prioritized_findings(findings, max_vulns):
    """Filters the list of prioritized findings to limit the number of EDB/GitHub results."""
    edb, github, other = [], [], []
    # Separate findings into exploit categories and "other".
    for f in findings:
        source = f.get("source_tool")
        if source == "searchsploit_mapper": edb.append(f)
        elif source == "github_exploit_mapper": github.append(f)
        else: other.append(f)
    # Sort each exploit list by score to ensure we keep the most important ones.
    edb.sort(key=lambda x: x.get("attributes", {}).get("score", 0), reverse=True)
    github.sort(key=lambda x: x.get("attributes", {}).get("score", 0), reverse=True)
    # Return all "other" findings plus the top N exploits from each category.
    return other + edb[:max_vulns] + github[:max_vulns]

def deduplicate_findings(findings_list):
    """Removes duplicate findings from a list based on host, port, name, and type."""
    seen = set()
    unique_findings = []
    for finding in findings_list:
        # Create a unique but stable identifier for each finding.
        identifier = (finding.get('host'), finding.get('port'), finding.get('name'), finding.get('entity_type'))
        if identifier not in seen:
            seen.add(identifier)
            unique_findings.append(finding)
    return unique_findings

def manage_credentials():
    """Provides an interactive wizard for users to add credentials they have found."""
    print(f"\n{C.BOLD}{C.CYAN}[*] Pathfinder Credential Manager{C.END}")
    creds = []
    if os.path.exists(CREDENTIALS_FILE):
        try:
            with open(CREDENTIALS_FILE, 'r') as f:
                content = f.read()
                # Handle case where credentials file is empty.
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

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="Pathfinder", formatter_class=argparse.RawTextHelpFormatter)
    
    ag = parser.add_argument_group('Analysis Input Arguments')
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

    io_group = parser.add_argument_group('Data I/O Arguments')
    io_group.add_argument("-i", "--input-json", help="Load prioritized findings from a JSON file (can be used with other inputs).")
    io_group.add_argument("-o", "--output-json", help="Save the final prioritized findings to a JSON file.")

    lg = parser.add_argument_group('Intelligence Management Arguments')
    lg.add_argument("--learn", action="store_true", help="Enter interactive mode to teach a new attack path.")
    lg.add_argument("--add-cred", action="store_true", help="Enter interactive mode to manually add a found credential.")

    gg = parser.add_argument_group('General Arguments')
    gg.add_argument("-v", "--verbose", action="count", default=0, help="Verbosity level (-v, -vv).")
    gg.add_argument("--max-vulns", type=int, default=10, help="Max number of EDB/GitHub exploits to display (default: 10).")
    
    args = parser.parse_args()
    synthesizer = AttackPathSynthesizer()
    prioritized_findings = []

    # Handle standalone modes like --learn or --add-cred first.
    if args.learn:
        synthesizer.learn_new_path_interactive()
        sys.exit(0)
    
    if args.add_cred:
        manage_credentials()
        sys.exit(0)

    base_prioritized_findings = []
    new_raw_findings = []
    
    # If a previous session is provided, load its findings first.
    if args.input_json:
        try:
            print(f"\n{C.BOLD}{C.CYAN}[*] Loading base findings from file: {args.input_json}{C.END}")
            with open(args.input_json, 'r', encoding='utf-8') as f:
                base_prioritized_findings = json.load(f)
            print(f"    [+] Loaded {len(base_prioritized_findings)} base findings.")
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"\n{C.BOLD}{C.YELLOW}[!] Error loading {args.input_json}: {e}{C.END}")
            sys.exit(1)

    target_host = args.target_host or args.gobuster_host
    parser_inputs = [args.nmap_xml, args.gobuster_txt, args.nikto_json, args.whatweb_json, args.enum4linux_json, args.linpeas_txt, args.winpeas_txt, args.snmp_txt, args.sharphound_dir, args.ldapdomaindump_dir, args.kerbrute_txt, args.getnpusers_hashes, args.sqlmap_log]

    # If new scan files are provided, parse them.
    if any(parser_inputs):
        print(f"\n{C.BOLD}{C.CYAN}[*] Parsing new data files...{C.END}\n")
        
        parsers = { "Nmap": (args.nmap_xml, lambda f: parse_nmap_xml(f)), "Gobuster": (args.gobuster_txt, lambda f: parse_gobuster_output(f, target_host, args.gobuster_port, args.gobuster_mode)), "Nikto": (args.nikto_json, lambda f: parse_nikto_json(f)), "WhatWeb": (args.whatweb_json, lambda f: parse_whatweb_json(f)), "Enum4Linux-NG": (args.enum4linux_json, lambda f: parse_enum4linux_json(f, target_host)), "LinPEAS": (args.linpeas_txt, lambda f: parse_linpeas(f, target_host)), "WinPEAS": (args.winpeas_txt, lambda f: parse_winpeas(f, target_host)), "SNMP": (args.snmp_txt, lambda f: parse_snmp_output(f, target_host)), "SharpHound": (args.sharphound_dir, lambda f: parse_sharphound_dir(f)), "LDAPDomainDump": (args.ldapdomaindump_dir, lambda f: parse_ldapdomaindump_dir(f)), "Kerbrute": (args.kerbrute_txt, lambda f: parse_kerbrute_output(f, target_host)), "GetNPUsers": (args.getnpusers_hashes, lambda f: parse_getnpusers_output(f, target_host)), "SQLMap": (args.sqlmap_log, lambda f: parse_sqlmap_log(f)) }

        for name, (file_path, parser_func) in parsers.items():
            if file_path:
                if (name in ["Gobuster", "Enum4Linux-NG", "LinPEAS", "WinPEAS", "SNMP", "Kerbrute", "GetNPUsers"] and not target_host):
                    print(f"{C.BOLD}{C.YELLOW}[!] {name} parser requires --target-host (or domain) to be set.{C.END}")
                    continue
                if args.verbose > 0: print(f"[*] Parsing {name}: {file_path}")
                findings_from_parser = parser_func(file_path)
                new_raw_findings.extend(findings_from_parser)
                if args.verbose > 0: print(f"    [+] Found {len(findings_from_parser)} raw findings from {name}.")
    
    if not base_prioritized_findings and not new_raw_findings:
         parser.error("For analysis, at least one input file (--nmap-xml, etc.) or --input-json must be provided.")

    newly_prioritized_findings = []
    # Only run the heavy mapping process if new raw data was parsed.
    if new_raw_findings:
        print(f"\n{C.BOLD}{C.CYAN}[*] Running Vulnerability Mapper on new findings...{C.END}\n")
        vuln_mapper = VulnerabilityMapper()
        newly_prioritized_findings = vuln_mapper.map_and_prioritize(new_raw_findings)
        if args.verbose > 0: print(f"    [+] Mapper prioritized {len(newly_prioritized_findings)} of the new findings.")

    # Combine findings from a previous session with newly processed ones.
    combined_findings = base_prioritized_findings + newly_prioritized_findings
    prioritized_findings = deduplicate_findings(combined_findings)
    
    if len(combined_findings) != len(prioritized_findings):
        if args.verbose > 0: print(f"\n{C.BOLD}{C.CYAN}[*]{C.END} Deduplicated {len(combined_findings) - len(prioritized_findings)} overlapping findings.")

    if not prioritized_findings:
        print(f"\n{C.BOLD}{C.YELLOW}[!] No findings to process. Exiting.{C.END}")
        sys.exit(0)

    # If requested, save the final, combined list of findings to a file.
    if args.output_json:
        try:
            print(f"\n{C.BOLD}{C.CYAN}[*] Saving prioritized findings to: {args.output_json}{C.END}")
            with open(args.output_json, 'w') as f: json.dump(prioritized_findings, f, indent=4)
            print(f"    [+] Successfully saved {len(prioritized_findings)} findings.")
        except IOError as e:
            print(f"\n{C.BOLD}{C.YELLOW}[!] Error saving to JSON file: {e}{C.END}")

    print(f"\n{C.BOLD}{C.CYAN}[*] Running Attack Path Synthesizer...{C.END}\n")
    suggested_paths = synthesizer.generate_attack_paths(prioritized_findings)
    
    # First, display any high-level synthesized attack paths.
    if suggested_paths:
        print(f"{C.BOLD}{C.YELLOW}--- Pathfinder has identified {len(suggested_paths)} potential attack path(s)! ---{C.END}")
        for i, path in enumerate(suggested_paths):
            print("\n" + "="*80)
            print(f"{C.BOLD}ATTACK PATH #{i+1}{C.END}")
            print(f"Name:       {C.BOLD}{path['name']}{C.END} {C.YELLOW}{C.BOLD}[Priority: {path['priority']}]{C.END}")
            print(f"Target:     {path['host']}")
            print("="*80)
            print(f"\n  [{C.BOLD}+{C.END}] Description:\n      {path['suggestion']['description']}")
            if args.verbose > 0: print(f"\n  [{C.BOLD}+{C.END}] Rationale:\n      {path['suggestion']['rationale']}")
            if path['suggestion'].get('commands'):
                print(f"\n  [{C.BOLD}+{C.END}] Suggested Commands:")
                for cmd in path['suggestion']['commands']: print(f"      - {cmd}")
            if path['suggestion'].get('references'):
                 print(f"\n  [{C.BOLD}+{C.END}] References:")
                 for ref in path['suggestion']['references']: print(f"      - {ref}")
            if args.verbose > 0 and path.get('evidence'):
                 print(f"\n  [{C.BOLD}+{C.END}] Matched Evidence:")
                 for ev in path['evidence']: print(f"      - {ev}")
        print("\n" + "="*80)
    else:
        print(f"\n{C.BOLD}{C.YELLOW}[!] No specific attack paths were synthesized from the findings.{C.END}")

    # Then, always display the list of individual prioritized findings.
    total_exploit_count = sum(1 for f in prioritized_findings if f.get("source_tool") in ["searchsploit_mapper", "github_exploit_mapper"])
    filtered_list = filter_prioritized_findings(prioritized_findings, args.max_vulns)
    displayed_exploit_count = sum(1 for f in filtered_list if f.get("source_tool") in ["searchsploit_mapper", "github_exploit_mapper"])
    displayed_other_count = len(filtered_list) - displayed_exploit_count
    total_displayed = len(filtered_list)
        
    print(f"\n{C.BOLD}{C.YELLOW}--- Total Findings: {total_displayed} (Public Exploits limited to --max-vulns, total discovered: {total_exploit_count}):{C.END}")

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

if __name__ == "__main__":
    main()