# pathfinder.py

import argparse
# import json

from nmap_parser import parse_nmap_xml
from gobuster_parser import parse_gobuster_output
from vulnerability_mapper import VulnerabilityMapper

def main():
    parser = argparse.ArgumentParser(
        description="Pathfinder: Intelligent Recon Analysis & Attack Path Suggestion",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--nmap-xml", help="Path to Nmap XML output file.")
    parser.add_argument("--gobuster-txt", help="Path to Gobuster output text file.")
    parser.add_argument("--gobuster-host", help="Target host for Gobuster. Required if --gobuster-txt.")
    parser.add_argument("--gobuster-port", type=int, help="Target port for Gobuster. Required if --gobuster-txt.")
    parser.add_argument("--gobuster-mode", choices=['dir', 'vhost'], default='dir', help="Gobuster mode (default: dir).")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose (info level) output.")

    args = parser.parse_args()

    if not args.nmap_xml and not args.gobuster_txt:
        parser.error("At least one input file (--nmap-xml or --gobuster-txt) must be provided.")

    if args.gobuster_txt and (not args.gobuster_host or args.gobuster_port is None):
        parser.error("--gobuster-host and --gobuster-port are required when using --gobuster-txt.")

    all_raw_findings = []
    verbose_level = 1 if args.verbose else 0 # 0 for default, 1 for verbose info messages

    # --- Parsing Phase ---
    if args.nmap_xml:
        if verbose_level > 0: print(f"[*] Parsing Nmap XML: {args.nmap_xml}")
        nmap_findings = parse_nmap_xml(args.nmap_xml)
        all_raw_findings.extend(nmap_findings)
        if verbose_level > 0: print(f"[+] Nmap: Found {len(nmap_findings)} raw findings.")

    if args.gobuster_txt:
        if verbose_level > 0: print(f"[*] Parsing Gobuster: {args.gobuster_txt} for {args.gobuster_host}:{args.gobuster_port} (mode: {args.gobuster_mode})")
        gobuster_findings = parse_gobuster_output(
            args.gobuster_txt,
            target_host=args.gobuster_host,
            target_port=args.gobuster_port,
            mode=args.gobuster_mode,
            verbose=verbose_level # Pass it along for gobuster_parser's own debugs if any
        )
        all_raw_findings.extend(gobuster_findings)
        if verbose_level > 0: print(f"[+] Gobuster: Found {len(gobuster_findings)} raw findings.")

    if not all_raw_findings:
        print("[!] No raw findings extracted. Exiting.") # Show this always if no findings
        return

    # --- Vulnerability Mapping Phase ---
    if verbose_level > 0: print("\n[*] Running Vulnerability Mapper...")
    vuln_mapper = VulnerabilityMapper(verbose_level=verbose_level) # Pass verbosity to mapper
    prioritized_findings = vuln_mapper.map_and_prioritize(all_raw_findings)
    
    if verbose_level > 0: print(f"[+] Mapper identified {len(prioritized_findings)} prioritized findings.")

    if not prioritized_findings:
        print("[!] No prioritized findings identified. Exiting.") # Show this always if no findings
        return

    # --- Output Phase ---
    print("\n--- Prioritized Findings ---")
    prioritized_findings.sort(key=lambda x: x.get("attributes", {}).get("score", 0), reverse=True)

    for i, p_finding in enumerate(prioritized_findings):
        score = p_finding.get("attributes", {}).get("score", "N/A")
        name = p_finding.get('name', 'Unknown Finding')
        entity_type = p_finding.get('entity_type', 'unknown_type')
        
        print(f"\n[{i+1}] [Score: {score}] {name} ({entity_type})")
        print(f"    Host: {p_finding.get('host')}, Port: {p_finding.get('port')}") # Always show Host/Port
        print(f"    Source: {p_finding.get('source_tool')}") # Always show Source
        if p_finding.get("version"): # Always show version if present
            print(f"    Version: {p_finding.get("version")}")
        
        # Always show a curated list of key attributes
        attrs = p_finding.get("attributes", {})
        details_to_show = {
            "title": "Title", "path": "SearchSploit Path", "url": "URL",
            "script_id": "Nmap Script", "script_output": "Script Output",
            "priority_reason": "Reason", "potential_risk": "Gobuster Risk",
            "related_software_product": "Related Product", "cves": "CVEs",
            "status_code": "Status Code", "description": "Description", "stars": "Stars"
            # Add more attributes here if you want them in the default output
        }
        
        has_printed_attrs_header = False
        for key, display_name in details_to_show.items():
            if key in attrs and attrs[key] is not None:
                if not has_printed_attrs_header and verbose_level == 0 : # Only print "Details:" once for default
                    # print(f"    Details:") # Optional header for attributes
                    has_printed_attrs_header = True
                
                value = attrs[key]
                # Truncate long script outputs for default view, full for verbose
                if key == "script_output" and isinstance(value, str) and len(value) > 100 and verbose_level == 0:
                    value = value[:100] + "..."
                elif key == "cves" and isinstance(value, list):
                    value = ", ".join(value) if value else "N/A"
                elif key == "description" and isinstance(value, str) and len(value) > 70 and verbose_level == 0:
                    value = value[:70] + "..."


                print(f"    {display_name}: {value}")
        
        # If verbose, and there are other attributes not in details_to_show, print them too
        if verbose_level > 0:
            printed_verbose_attrs_header = False
            for key, value in attrs.items():
                if key not in details_to_show and key not in ["score", "priority_reason", "potential_risk"]: # Avoid re-printing score etc.
                    if not printed_verbose_attrs_header:
                        print(f"    Other Attributes:")
                        printed_verbose_attrs_header = True
                    print(f"        {key}: {value}")

    print("") # Extra newline at the end

if __name__ == "__main__":
    main()