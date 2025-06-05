import re

def parse_gobuster_output(gobuster_output_file, target_host, target_port=None, mode='dir', verbose=0): # Added verbose
    """
    Parses Gobuster output (currently supports 'dir' mode primarily) and
    extracts findings into the specified format.
    ...
    """
    findings = []
    
    dir_pattern = re.compile(
        r"^(?P<path>/[^\s\(]+)"
        r"\s*"  # Matches the spaces between path and (Status:)
        r"\(Status:\s*(?P<status>\d{3})\)"
        r"(?:\s*\[Size:\s*(?P<size>\d+)\])?"
        r"(?:\s*-->\s*(?P<redirect_url>[^\s]+))?"
    )
    if verbose > 1: print(f"[DEBUG_GOBUSTER] Using dir_pattern: {dir_pattern.pattern}")


    try:
        with open(gobuster_output_file, 'r', encoding='utf-8', errors='ignore') as f:
            if verbose > 1: print(f"[DEBUG_GOBUSTER] Opened file: {gobuster_output_file}")
            line_number = 0
            for line in f:
                line_number += 1
                if verbose > 2: print(f"[DEBUG_GOBUSTER] Raw line {line_number}: '{line.rstrip()}'") # rstrip to see original trailing spaces if any
                
                line = line.strip() # Strip whitespace from both ends

                if not line or line.startswith("#") or line.startswith("Gobuster") or \
                   line.startswith("===") or "Progress:" in line or "Finished" in line or "Timeout:" in line:
                    if verbose > 2: print(f"[DEBUG_GOBUSTER] Skipping line {line_number}: '{line}'")
                    continue
                
                if verbose > 1: print(f"[DEBUG_GOBUSTER] Processing line {line_number}: '{line}' for mode '{mode}'")

                if mode == 'dir':
                    match = dir_pattern.match(line)
                    if match:
                        if verbose > 0: print(f"[DEBUG_GOBUSTER] SUCCESSFUL MATCH on line {line_number}: '{line}'")
                        data = match.groupdict()
                        path = data['path']
                        status_code = int(data['status'])
                        # ... (rest of your existing parsing logic for dir mode) ...
                        # (Make sure to copy it back here)
                        size = int(data['size']) if data['size'] else None
                        redirect_url = data['redirect_url'] if data['redirect_url'] else None

                        attributes = {
                            "status_code": status_code,
                            "raw_line": line 
                        }
                        if size is not None:
                            attributes["size_bytes"] = size
                        if redirect_url:
                            attributes["redirect_url"] = redirect_url
                        
                        potential_risk = None # Your risk logic here
                        is_directory = False # Your directory guess logic here
                        
                        # Copy your risk and directory guess logic here from the original parser
                        # Example (incomplete, just for structure):
                        if any(ext in path.lower() for ext in ['.bak', '.old']):
                            potential_risk = "sensitive_backup_file"
                        
                        attributes["is_directory_guess"] = is_directory
                        if potential_risk:
                            attributes["potential_risk"] = potential_risk

                        findings.append({
                            "host": target_host,
                            "port": target_port, 
                            "source_tool": "gobuster",
                            "entity_type": "web_content",
                            "name": path,
                            "version": None,
                            "attributes": attributes
                        })
                    else:
                        if verbose > 0: print(f"[DEBUG_GOBUSTER] NO MATCH on line {line_number}: '{line}'")
                
                elif mode == 'vhost':
                    # ... (your vhost logic) ...
                    pass 
    
    except FileNotFoundError:
        print(f"Error: Gobuster output file not found at {gobuster_output_file}")
    except Exception as e:
        print(f"An error occurred while parsing Gobuster output: {e}")
        
    return findings

# --- Example Usage (save this script as gobuster_parser.py) ---
if __name__ == '__main__':
    # Create a dummy gobuster_results.txt for testing
    test_gobuster_content_dir = """
Gobuster v3.1.0
===============================================================
[+] Url:            http://192.168.171.72
[+] Threads:        10
[+] Wordlist:       common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.1.0
[+] Timeout:        10s
===============================================================
2023/03/15 10:00:00 Starting gobuster
===============================================================
/app                  (Status: 301) [Size: 314] [--> http://192.168.171.72/app/]
/javascript           (Status: 301) [Size: 321] [--> http://192.168.171.72/javascript/]
/backup               (Status: 301) [Size: 317] [--> http://192.168.171.72/backup/]
/otherfile.txt        (Status: 200) [Size: 100]
===============================================================
2023/03/15 10:05:00 Finished
===============================================================
    """
    test_gobuster_file_dir = "test_gobuster_dir_debug.txt"
    with open(test_gobuster_file_dir, "w") as f:
        f.write(test_gobuster_content_dir)

    # Test with verbosity
    parsed_dir_findings = parse_gobuster_output(
        test_gobuster_file_dir, 
        "192.168.171.72", 
        80, 
        mode='dir',
        verbose=2 # Set verbosity level for debugging
    )
    
    if parsed_dir_findings:
        print(f"\nFound {len(parsed_dir_findings)} 'dir' mode findings (debug run):\n")
        for i, finding in enumerate(parsed_dir_findings):
            print(f"--- Finding {i+1} ---")
            # (Your existing printing logic)
            print(f"  Name: {finding.get('name')}, Status: {finding.get('attributes', {}).get('status_code')}")
    else:
        print("No 'dir' mode findings extracted (debug run).")