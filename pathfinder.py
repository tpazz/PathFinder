import argparse
import sys

# Import your custom modules
from nmap_parser import parse_nmap_xml
from gobuster_parser import parse_gobuster_output
from vulnerability_mapper import VulnerabilityMapper
from attack_path_synthesizer import AttackPathSynthesizer

def main():
    """
    Main function to orchestrate the Pathfinder tool.
    """
    parser = argparse.ArgumentParser(
        description="Pathfinder: Intelligent Recon Analysis & Attack Path Suggestion.",
        formatter_class=argparse.RawTextHelpFormatter # To allow for better help text formatting
    )
    
    # Input arguments for analysis
    analysis_group = parser.add_argument_group('Analysis Arguments')
    analysis_group.add_argument("--nmap-xml", help="Path to Nmap XML output file.")
    analysis_group.add_argument("--gobuster-txt", help="Path to Gobuster output text file.")
    analysis_group.add_argument("--gobuster-host", help="Target host for Gobuster output (e.g., '10.10.10.5' or 'example.com').\nRequired if --gobuster-txt is used.")
    analysis_group.add_argument("--gobuster-port", type=int, help="Target port for Gobuster output (e.g., 80, 443).\nRequired if --gobuster-txt is used.")
    analysis_group.add_argument("--gobuster-mode", choices=['dir', 'vhost'], default='dir', help="Gobuster mode used (default: dir).")

    # Learning mode argument
    learning_group = parser.add_argument_group('Learning Arguments')
    learning_group.add_argument("--learn", action="store_true", help="Enter interactive mode to teach Pathfinder a new attack path.")

    # General arguments
    general_group = parser.add_argument_group('General Arguments')
    general_group.add_argument("-v", "--verbose", action="count", default=0, help="Verbosity level. -v for general steps, -vv for detailed processing, -vvv for raw line debug.")
    
    args = parser.parse_args()

    # Initialize the synthesizer first as it's needed for both modes
    synthesizer = AttackPathSynthesizer()

    # --- Learning Mode ---
    if args.learn:
        synthesizer.learn_new_path_interactive()
        sys.exit(0) # Exit after learning

    # --- Analysis Mode ---
    # Check if any analysis input is provided
    if not args.nmap_xml and not args.gobuster_txt:
        parser.error("For analysis, at least one input file (--nmap-xml or --gobuster-txt) must be provided.\nOr, use --learn to teach a new rule.")

    # Validate gobuster arguments if gobuster input is given
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
            mode=args.gobuster_mode,
            verbose=args.verbose
        )
        all_raw_findings.extend(gobuster_findings)
        if args.verbose > 0: print(f"[+] Found {len(gobuster_findings)} raw findings from Gobuster.")

    if not all_raw_findings:
        print("\n[!] No raw findings extracted from input files. Exiting.")
        sys.exit(1)

    # 3. Vulnerability Mapping and Prioritization
    if args.verbose > 0: print("\n[*] Running Vulnerability Mapper...")
    vuln_mapper = VulnerabilityMapper()
    prioritized_findings = vuln_mapper.map_and_prioritize(all_raw_findings)
    
    if args.verbose > 0: print(f"[+] Vulnerability Mapper identified {len(prioritized_findings)} prioritized findings.")

    if not prioritized_findings:
        print("\n[!] No prioritized findings identified by the Vulnerability Mapper. Exiting.")
        sys.exit(0)

    # 4. Attack Path Synthesis
    if args.verbose > 0: print("\n[*] Running Attack Path Synthesizer...")
    suggested_paths = synthesizer.generate_attack_paths(prioritized_findings)
    
    if not suggested_paths:
        print("\n[!] No specific attack paths were synthesized from the findings.")
        print("--- Displaying Prioritized Findings as Fallback ---")
        prioritized_findings.sort(key=lambda x: x.get("attributes", {}).get("score", 0), reverse=True)
        for i, p_finding in enumerate(prioritized_findings):
            score = p_finding.get("attributes", {}).get("score", "N/A")
            print(f"\n[{i+1}] [Score: {score}] {p_finding.get('name')} ({p_finding.get('entity_type')})")
            print(f"    Host: {p_finding.get('host')}, Port: {p_finding.get('port')}")
            # Add more detail here if needed
            
    else:
        print(f"\n--- Pathfinder has identified {len(suggested_paths)} potential attack path(s)! ---")
        for i, path in enumerate(suggested_paths):
            print("\n" + "="*80)
            print(f"ATTACK PATH #{i+1}")
            print(f"Name:       {path['name']} [Priority: {path['priority']}]")
            print(f"Target:     {path['host']}")
            print("="*80)
            print("\n  [+] Description:")
            print(f"      {path['suggestion']['description']}")
            
            if args.verbose > 0:
                print("\n  [+] Rationale:")
                print(f"      {path['suggestion']['rationale']}")

            if path['suggestion'].get('commands'):
                print("\n  [+] Suggested Commands:")
                for cmd in path['suggestion']['commands']:
                    print(f"      - {cmd}")
            
            if path['suggestion'].get('references'):
                 print("\n  [+] References:")
                 for ref in path['suggestion']['references']:
                    print(f"      - {ref}")

            if args.verbose > 0 and path.get('evidence'):
                 print("\n  [+] Matched Evidence:")
                 for ev in path['evidence']:
                    print(f"      - {ev}")
        print("\n" + "="*80)


if __name__ == "__main__":
    # Example of how to set GITHUB_TOKEN for testing if not set globally
    # This is useful for development.
    # import os
    # if 'GITHUB_TOKEN' not in os.environ:
    #     print("[DEV_INFO] GITHUB_TOKEN not set in environment. GitHub searches will be limited.")
    #     # os.environ['GITHUB_TOKEN'] = "YOUR_DUMMY_OR_REAL_TOKEN_HERE_FOR_TESTING_ONLY" 
    
    main()