# pathfinder.py (or main.py)

import argparse
import json # For potentially printing structured output

# Import your custom parser and mapper modules
from nmap_parser import parse_nmap_xml
from gobuster_parser import parse_gobuster_output
from vulnerability_mapper import VulnerabilityMapper
# You'll also need your AttackPathSynthesizer module here later

def main():
    parser = argparse.ArgumentParser(description="Pathfinder: Intelligent Recon Analysis & Attack Path Suggestion")
    parser.add_argument("--nmap-xml", help="Path to Nmap XML output file.")
    parser.add_argument("--gobuster-txt", help="Path to Gobuster output text file.")
    parser.add_argument("--gobuster-host", help="Target host for Gobuster output (e.g., 10.10.10.5 or example.com). Required if --gobuster-txt is used.")
    parser.add_argument("--gobuster-port", type=int, help="Target port for Gobuster output (e.g., 80, 443). Required if --gobuster-txt is used.")
    parser.add_argument("--gobuster-mode", choices=['dir', 'vhost'], default='dir', help="Gobuster mode used (default: dir).")
    # Add other arguments as needed (e.g., for other tool inputs, output formatting)
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Verbosity level (-v, -vv).")


    args = parser.parse_args()

    if not args.nmap_xml and not args.gobuster_txt:
        parser.error("At least one input file (--nmap-xml or --gobuster-txt) must be provided.")

    if args.gobuster_txt and (not args.gobuster_host or args.gobuster_port is None):
        parser.error("--gobuster-host and --gobuster-port are required when using --gobuster-txt.")

    all_raw_findings = []

    # 1. Parse Nmap XML
    if args.nmap_xml:
        if args.verbose > 0: print(f"[*] Parsing Nmap XML: {args.nmap_xml}")
        nmap_findings = parse_nmap_xml(args.nmap_xml)
        all_raw_findings.extend(nmap_findings)
        if args.verbose > 0: print(f"[+] Found {len(nmap_findings)} raw findings from Nmap.")

    # 2. Parse Gobuster Output
    if args.gobuster_txt:
        if args.verbose > 0: print(f"[*] Parsing Gobuster output: {args.gobuster_txt} for host {args.gobuster_host}:{args.gobuster_port} (mode: {args.gobuster_mode})")
        gobuster_findings = parse_gobuster_output(
            args.gobuster_txt,
            target_host=args.gobuster_host,
            target_port=args.gobuster_port,
            mode=args.gobuster_mode
        )
        all_raw_findings.extend(gobuster_findings)
        if args.verbose > 0: print(f"[+] Found {len(gobuster_findings)} raw findings from Gobuster.")

    if not all_raw_findings:
        print("[!] No raw findings extracted from input files. Exiting.")
        return

    if args.verbose > 1:
        print("\n--- All Raw Findings ---")
        for i, finding in enumerate(all_raw_findings):
            print(f"Raw Finding {i+1}: {finding.get('name')} ({finding.get('entity_type')}) from {finding.get('source_tool')}")
            # Could pretty print the full finding here if very verbose

    # 3. Vulnerability Mapping and Prioritization
    if args.verbose > 0: print("\n[*] Running Vulnerability Mapper...")
    vuln_mapper = VulnerabilityMapper()
    prioritized_findings = vuln_mapper.map_and_prioritize(all_raw_findings)
    
    if args.verbose > 0: print(f"[+] Vulnerability Mapper identified {len(prioritized_findings)} prioritized findings.")

    if not prioritized_findings:
        print("[!] No prioritized findings identified by the Vulnerability Mapper. Exiting.")
        return

    # --- Output Prioritized Findings (Example) ---
    # This section will be replaced/augmented by the Attack Path Synthesizer
    print("\n--- Prioritized Findings ---")
    # Sort by score if available, high to low
    prioritized_findings.sort(key=lambda x: x.get("attributes", {}).get("score", 0), reverse=True)

    for i, p_finding in enumerate(prioritized_findings):
        score = p_finding.get("attributes", {}).get("score", "N/A")
        print(f"\n[{i+1}] [Score: {score}] {p_finding.get('name')} ({p_finding.get('entity_type')})")
        print(f"    Host: {p_finding.get('host')}, Port: {p_finding.get('port')}")
        print(f"    Source: {p_finding.get('source_tool')}")
        if p_finding.get("version"):
            print(f"    Version: {p_finding.get('version')}")
        
        # Print relevant attributes based on verbosity or finding type
        attributes_to_show = ["title", "path", "url", "script_id", "script_output", "priority_reason", "potential_risk", "related_software_product"]
        for attr_key, attr_val in p_finding.get("attributes", {}).items():
            if attr_key in attributes_to_show or args.verbose > 1: # Show more with higher verbosity
                 # Truncate long script outputs for concise view unless very verbose
                if attr_key == "script_output" and args.verbose < 2 and isinstance(attr_val, str) and len(attr_val) > 100:
                    attr_val_display = attr_val[:100] + "..."
                else:
                    attr_val_display = attr_val
                print(f"    {attr_key.replace('_', ' ').capitalize()}: {attr_val_display}")


    # 4. Attack Path Synthesis (Placeholder for now)
    # print("\n[*] Running Attack Path Synthesizer...")
    # synthesizer = AttackPathSynthesizer(ruleset_file="default_rules.json") # Example
    # suggested_paths = synthesizer.generate_attack_paths(prioritized_findings)
    #
    # if suggested_paths:
    #     print("\n--- Suggested Attack Paths ---")
    #     for i, path in enumerate(suggested_paths):
    #         print(f"\nPath {i+1} [Priority: {path.get('priority_score', 'N/A')}]: {path.get('description')}")
    #         print(f"  Rationale: {path.get('rationale')}")
    #         if path.get('suggested_commands'):
    #             print(f"  Commands:")
    #             for cmd in path.get('suggested_commands'):
    #                 print(f"    - {cmd}")
    #         if path.get('references'):
    #             print(f"  References:")
    #             for ref in path.get('references'):
    #                 print(f"    - {ref}")
    # else:
    #     print("[!] No specific attack paths synthesized from the prioritized findings.")


if __name__ == "__main__":
    # Example of how to set GITHUB_TOKEN for testing if not set globally
    # import os
    # if not os.environ.get('GITHUB_TOKEN'):
    # print("INFO: GITHUB_TOKEN not set in environment, setting a dummy one for testing if needed by mapper")
    # os.environ['GITHUB_TOKEN'] = "YOUR_DUMMY_OR_REAL_TOKEN_HERE_FOR_TESTING_ONLY" # Be careful with real tokens
    
    main()