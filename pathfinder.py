# pathfinder.py

import argparse
# import json # Not strictly needed for current output format

from nmap_parser import parse_nmap_xml
from gobuster_parser import parse_gobuster_output
from vulnerability_mapper import VulnerabilityMapper

def main():
    parser = argparse.ArgumentParser(
        description="Pathfinder: Intelligent Recon Analysis & Attack Path Suggestion",
        formatter_class=argparse.RawTextHelpFormatter # For better help text formatting
    )
    parser.add_argument("--nmap-xml", help="Path to Nmap XML output file.")
    parser.add_argument("--gobuster-txt", help="Path to Gobuster output text file.")
    parser.add_argument("--gobuster-host", help="Target host for Gobuster (e.g., example.com). Required if --gobuster-txt.")
    parser.add_argument("--gobuster-port", type=int, help="Target port for Gobuster (e.g., 80). Required if --gobuster-txt.")
    parser.add_argument("--gobuster-mode", choices=['dir', 'vhost'], default='dir', help="Gobuster mode (default: dir).")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output mode.") # Changed to store_true

    args = parser.parse_args()

    if not args.nmap_xml and not args.gobuster_txt:
        parser.error("At least one input file (--nmap-xml or --gobuster-txt) must be provided.")

    if args.gobuster_txt and (not args.gobuster_host or args.gobuster_port is None):
        parser.error("--gobuster-host and --gobuster-port are required when using --gobuster-txt.")

    all_raw_findings = []
    verbose_level = 1 if args.verbose else 0 # 0 for default, 1 for verbose

    if args.nmap_xml:
        if verbose_level > 0: print(f"[*] Parsing Nmap XML: {args.nmap_xml}")
        nmap_findings = parse_nmap_xml(args.nmap_xml) # Assuming this parser doesn't need verbosity
        all_raw_findings.extend(nmap_findings)
        if verbose_level > 0: print(f"[+] Nmap: Found {len(nmap_findings)} raw findings.")

    if args.gobuster_txt:
        if verbose_level > 0: print(f"[*] Parsing Gobuster: {args.gobuster_txt} for {args.gobuster_host}:{args.gobuster_port} (mode: {args.gobuster_mode})")
        # Pass verbose_level if your gobuster_parser uses it for its own debug prints
        gobuster_findings = parse_gobuster_output(
            args.gobuster_txt,
            target_host=args.gobuster_host,
            target_port=args.gobuster_port,
            mode=args.gobuster_mode,
            verbose=verbose_level # Pass it along if gobuster_parser uses it
        )
        all_raw_findings.extend(gobuster_findings)
        if verbose_level > 0: print(f"[+] Gobuster: Found {len(gobuster_findings)} raw findings.")

    if not all_raw_findings:
        print("[!] No raw findings extracted. Exiting.")
        return

    if verbose_level > 0: print("\n[*] Running Vulnerability Mapper...")
    vuln_mapper = VulnerabilityMapper(verbose_level=verbose_level)
    prioritized_findings = vuln_mapper.map_and_prioritize(all_raw_findings)
    
    if verbose_level > 0: print(f"[+] Mapper identified {len(prioritized_findings)} prioritized findings.")

    if not prioritized_findings:
        print("[!] No prioritized findings identified. Exiting.")
        return

    print("\n--- Prioritized Findings ---")
    prioritized_findings.sort(key=lambda x: x.get("attributes", {}).get("score", 0), reverse=True)

    for i, p_finding in enumerate(prioritized_findings):
        score = p_finding.get("attributes", {}).get("score", "N/A")
        name = p_finding.get('name', 'Unknown Finding')
        entity_type = p_finding.get('entity_type', 'unknown_type')
        
        print(f"\n[{i+1}] [Score: {score}] {name} ({entity_type})")
        
        if verbose_level > 0: # Detailed output for -v
            print(f"    Host: {p_finding.get('host')}, Port: {p_finding.get('port')}")
            print(f"    Source: {p_finding.get('source_tool')}")
            if p_finding.get("version"):
                print(f"    Version: {p_finding.get('version')}")
            
            # Show specific, useful attributes
            attrs = p_finding.get("attributes", {})
            details_to_show = {
                "title": "Title", "path": "SearchSploit Path", "url": "URL",
                "script_id": "Nmap Script", "script_output": "Script Output",
                "priority_reason": "Reason", "potential_risk": "Gobuster Risk",
                "related_software_product": "Related Product", "cves": "CVEs",
                "status_code": "Status Code", "description": "Description", "stars": "Stars"
            }
            for key, display_name in details_to_show.items():
                if key in attrs and attrs[key] is not None:
                    value = attrs[key]
                    if key == "script_output" and isinstance(value, str) and len(value) > 100:
                        value = value[:100] + "..."
                    elif key == "cves" and isinstance(value, list):
                        value = ", ".join(value) if value else "N/A"

                    print(f"    {display_name}: {value}")
    print("") # Extra newline at the end

if __name__ == "__main__":
    main()