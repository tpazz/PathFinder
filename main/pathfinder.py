import argparse
import sys
import json

from attack_path_synthesizer import AttackPathSynthesizer
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
from vulnerability_mapper import VulnerabilityMapper

# Import your custom modules

# ANSI color codes for formatted output
class C:
    RED, GREEN, YELLOW, LIGHT_BLUE, CYAN, BOLD, END = '\033[91m', '\033[92m', '\033[93m', '\033[94m', '\033[96m', '\033[1m', '\033[0m'

def print_banner():
    banner = r"""
__________          __   .__      _____ .__             .___              
\______   \_____  _/  |_ |  |__ _/ ____\|__|  ____    __| _/ ____ _______ 
 |     ___/\__  \ \   __\|  |  \\   __\ |  | /    \  / __ |_/ __ \\_  __ \
 |    |     / __ \_|  |  |   Y  \|  |   |  ||   |  \/ /_/ |\  ___/ |  | \/
 |____|    (____  /|__|  |___|  /|__|   |__||___|  /\____ | \___  >|__|   
                \/            \/                 \/      \/     \/        


  >> [Intelligent Reconnaissance Analysis for Pentesters] << 
"""
    print(banner)

def format_finding_display(name, entity_type):
    display_name = name
    if "EDB-ID" in display_name: display_name = display_name.replace("EDB-ID", f"{C.BOLD}{C.RED}EDB-ID{C.END}")
    if "GitHub Exploit" in display_name: display_name = display_name.replace("GitHub Exploit", f"{C.BOLD}{C.GREEN}GitHub Exploit{C.END}")
    if entity_type == "privilege_escalation": display_type = f"({C.BOLD}{C.RED}{entity_type}{C.END})"
    elif entity_type == "web_content": display_type = f"({C.LIGHT_BLUE}{entity_type}{C.END})"
    elif entity_type == "misconfiguration": display_type = f"({C.YELLOW}{entity_type}{C.END})"
    elif entity_type == "vulnerability" and "sql" in name: display_type = f"({C.BOLD}{C.RED}{entity_type}{C.END})"
    else: display_type = f"({entity_type})"
    return display_name, display_type

def filter_prioritized_findings(findings, max_vulns):
    edb, github, other = [], [], []
    for f in findings:
        source = f.get("source_tool")
        if source == "searchsploit_mapper": edb.append(f)
        elif source == "github_exploit_mapper": github.append(f)
        else: other.append(f)
    edb.sort(key=lambda x: x.get("attributes", {}).get("score", 0), reverse=True)
    github.sort(key=lambda x: x.get("attributes", {}).get("score", 0), reverse=True)
    return other + edb[:max_vulns] + github[:max_vulns]

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
    io_group.add_argument("-i", "--input-json", help="Load prioritized findings from a JSON file.")
    io_group.add_argument("-o", "--output-json", help="Save the final prioritized findings to a JSON file.")

    lg = parser.add_argument_group('Learning Arguments')
    lg.add_argument("--learn", action="store_true", help="Enter interactive mode to teach a new rule.")

    gg = parser.add_argument_group('General Arguments')
    gg.add_argument("-v", "--verbose", action="count", default=0, help="Verbosity level (-v, -vv).")
    gg.add_argument("--max-vulns", type=int, default=10, help="Max number of EDB/GitHub exploits to display (default: 10).")
    
    args = parser.parse_args()
    synthesizer = AttackPathSynthesizer()
    prioritized_findings = []

    if args.learn:
        synthesizer.learn_new_path_interactive()
        sys.exit(0)

    target_host = args.target_host or args.gobuster_host
    
    if args.input_json:
        if any([args.nmap_xml, args.gobuster_txt, args.nikto_json, args.whatweb_json, args.enum4linux_json, args.linpeas_txt, args.winpeas_txt, args.snmp_txt, args.sharphound_dir, args.ldapdomaindump_dir, args.kerbrute_txt, args.getnpusers_hashes, args.sqlmap_log]):
            parser.error("--input-json cannot be used with other parser inputs.")
        try:
            print(f"\n{C.BOLD}{C.CYAN}[*] Loading findings from file: {args.input_json}{C.END}")
            with open(args.input_json, 'r') as f: prioritized_findings = json.load(f)
            print(f"    [+] Loaded {len(prioritized_findings)} findings.")
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"\n{C.BOLD}{C.YELLOW}[!] Error loading {args.input_json}: {e}{C.END}")
            sys.exit(1)
    else:
        input_files = [args.nmap_xml, args.gobuster_txt, args.nikto_json, args.whatweb_json, args.enum4linux_json, args.linpeas_txt, args.winpeas_txt, args.snmp_txt, args.sharphound_dir, args.ldapdomaindump_dir, args.kerbrute_txt, args.getnpusers_hashes, args.sqlmap_log]
        if not any(input_files):
            parser.error("At least one input file or --input-json must be provided.")
        
        all_raw_findings = []
        print(f"\n{C.BOLD}{C.CYAN}[*] Parsing Data...{C.END}\n")

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
            "SQLMap": (args.sqlmap_log, lambda f: parse_sqlmap_log(f))
        }

        for name, (file_path, parser_func) in parsers.items():
            if file_path:
                if (name in ["Gobuster", "Enum4Linux-NG", "LinPEAS", "WinPEAS", "SNMP", "Kerbrute", "GetNPUsers"] and not target_host):
                    print(f"{C.BOLD}{C.YELLOW}[!] {name} parser requires --target-host (or domain) to be set.{C.END}")
                    continue
                if args.verbose > 0: print(f"[*] Parsing {name}: {file_path}")
                new_findings = parser_func(file_path)
                all_raw_findings.extend(new_findings)
                if args.verbose > 0: print(f"    [+] Found {len(new_findings)} raw findings from {name}.")

        if not all_raw_findings:
            print(f"\n{C.BOLD}{C.YELLOW}[!] No raw findings extracted from input files. Exiting.{C.END}")
            sys.exit(1)

        print(f"\n{C.BOLD}{C.CYAN}[*] Running Vulnerability Mapper...{C.END}\n")
        vuln_mapper = VulnerabilityMapper()
        prioritized_findings = vuln_mapper.map_and_prioritize(all_raw_findings)
        
        if args.verbose > 0: print(f"    [+] Vulnerability Mapper identified {len(prioritized_findings)} prioritized findings.")

    if not prioritized_findings:
        print(f"\n{C.BOLD}{C.YELLOW}[!] No prioritized findings identified by the Vulnerability Mapper. Exiting.{C.END}")
        sys.exit(0)

    if args.output_json:
        try:
            print(f"\n{C.BOLD}{C.CYAN}[*] Saving prioritized findings to: {args.output_json}{C.END}")
            with open(args.output_json, 'w') as f: json.dump(prioritized_findings, f, indent=4)
            print(f"    [+] Successfully saved {len(prioritized_findings)} findings.")
        except IOError as e:
            print(f"\n{C.BOLD}{C.YELLOW}[!] Error saving to JSON file: {e}{C.END}")

    print(f"\n{C.BOLD}{C.CYAN}[*] Running Attack Path Synthesizer...{C.END}\n")
    suggested_paths = synthesizer.generate_attack_paths(prioritized_findings)
    
    if not suggested_paths:
        print(f"\n{C.BOLD}{C.YELLOW}[!] No specific attack paths were synthesized! Displaying Prioritized Findings as Fallback {C.END}")
        filtered_list = filter_prioritized_findings(prioritized_findings, args.max_vulns)
        filtered_list.sort(key=lambda x: x.get("attributes", {}).get("score", 0), reverse=True)
        for i, p_finding in enumerate(filtered_list):
            score = p_finding.get("attributes", {}).get("score", "N/A")
            display_name, display_type = format_finding_display(p_finding.get('name'), p_finding.get('entity_type'))
            print(f"\n[{i+1}] [Score: {score}] {display_name} {display_type}")
            print(f"    Host: {p_finding.get('host')}, Port: {p_finding.get('port')}")
    else:
        print(f"\n--- Pathfinder has identified {len(suggested_paths)} potential attack path(s)! ---")
        for i, path in enumerate(suggested_paths):
            print("\n" + "="*80)
            print(f"ATTACK PATH #{i+1}")
            print(f"Name:       {path['name']} [Priority: {path['priority']}]")
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

if __name__ == "__main__":
    main()