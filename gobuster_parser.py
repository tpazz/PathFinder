import re

def parse_gobuster_output(gobuster_output_file, target_host, target_port=None, mode='dir', verbose=0):
    """
    Parses Gobuster output and extracts findings into the specified format.

    Args:
        gobuster_output_file (str): Path to the Gobuster output text file.
        target_host (str): The target host/IP Gobuster was run against.
        target_port (int, optional): The target port.
        mode (str): The Gobuster mode used (e.g., 'dir', 'vhost').
        verbose (int): Verbosity level for debugging prints.

    Returns:
        list: A list of finding dictionaries.
    """
    findings = []
    
    # Regex for 'dir' mode
    # Example line: /config.php (Status: 200) [Size: 1234]
    # Example line: /images (Status: 301) [Size: 0] --> /images/
    dir_pattern = re.compile(
        r"^(?P<path>/[^\s\(]+)"          # Path (starts with /, no spaces or opening parenthesis)
        r"\s*"                           # Matches spaces between path and (Status:)
        r"\(Status:\s*(?P<status>\d{3})\)" # Status code
        r"(?:\s*\[Size:\s*(?P<size>\d+)\])?"  # Optional Size
        r"(?:\s*-->\s*(?P<redirect_url>[^\s]+))?" # Optional Redirect URL
    )

    # Regex for 'vhost' mode
    # Example line: Found: sub.domain.com (Status: 200)
    vhost_pattern = re.compile(r"Found:\s*(?P<vhost>[^\s\(]+)(?:\s*\(Status:\s*(?P<status>\d{3})\))?")

    if verbose > 1: print(f"[DEBUG_GOBUSTER] Using dir_pattern: {dir_pattern.pattern}")
    if verbose > 1 and mode == 'vhost': print(f"[DEBUG_GOBUSTER] Using vhost_pattern: {vhost_pattern.pattern}")

    try:
        with open(gobuster_output_file, 'r', encoding='utf-8', errors='ignore') as f:
            if verbose > 1: print(f"[DEBUG_GOBUSTER] Opened file: {gobuster_output_file}")
            line_number = 0
            for line_content in f:
                line_number += 1
                original_line_for_debug = line_content.rstrip('\n\r') # For debugging, keep original line ending
                
                if verbose > 2: print(f"[DEBUG_GOBUSTER] Raw line {line_number}: '{original_line_for_debug}'")
                
                line = line_content.strip() # Strip leading/trailing whitespace for processing

                # Enhanced skipping logic for header, footer, and meta lines
                if not line or \
                   line.startswith("#") or \
                   line.startswith("Gobuster v") or \
                   line.startswith("===") or \
                   line.startswith("[+]") or \
                   line.startswith("-->") and not line.startswith("/"): \
                   "Progress:" in line or \
                   "Finished" in line or \
                   "Timeout:" in line or \
                   "Starting gobuster" in line or \
                   "Use gobuster -h for list" in line or \
                   "by OJ Reeves" in line: # Add more specific Gobuster header lines if needed
                    if verbose > 1: print(f"[DEBUG_GOBUSTER] Skipping header/meta line {line_number}: '{line}'")
                    continue
                
                # This print should appear for any line that is NOT skipped
                if verbose > 0: print(f"[DEBUG_GOBUSTER] Attempting to process potential data line {line_number}: '{line}' (mode: '{mode}')")

                if mode == 'dir':
                    match = dir_pattern.match(line)
                    if match:
                        if verbose > 0: print(f"[DEBUG_GOBUSTER] SUCCESSFUL MATCH on line {line_number}: '{line}'")
                        data = match.groupdict()
                        path = data['path']
                        status_code = int(data['status'])
                        size = int(data['size']) if data['size'] else None
                        redirect_url = data['redirect_url'] if data['redirect_url'] else None

                        attributes = {
                            "status_code": status_code,
                            "raw_line": original_line_for_debug # Store the original line for reference
                        }
                        if size is not None:
                            attributes["size_bytes"] = size
                        if redirect_url:
                            attributes["redirect_url"] = redirect_url
                        
                        potential_risk = None
                        is_directory_guess = False
                        normalized_path = path.lower()

                        # Basic heuristic for potential risk - can be greatly expanded
                        # (This logic is from the vulnerability_mapper, consider centralizing if it grows complex)
                        INTERESTING_EXTENSIONS = ['.bak', '.old', '.swp', '.backup', '.copy', '.tmp', '.temp', '.config', '.cfg', '.ini', '.env', '.secret', '.sql', '.db', '.log', '.txt', '.zip', '.tar.gz', '.sh', '.php', '.asp', '.aspx', '.jsp']
                        INTERESTING_KEYWORDS_IN_PATH = ['admin', 'login', 'upload', 'config', 'backup', 'shell', 'console', 'manage', 'root', 'api', 'test', 'dev', 'prod', 'staging', 'user', 'passwd', 'shadow', 'secret', 'credential', 'key', 'token']
                        INTERESTING_FILENAMES = ['web.config', 'id_rsa', 'id_dsa', '.bash_history', '.ssh/known_hosts', '.git/config']
                        
                        if any(ext in normalized_path for ext in INTERESTING_EXTENSIONS):
                            potential_risk = "interesting_extension"
                        elif any(kw in normalized_path for kw in INTERESTING_KEYWORDS_IN_PATH):
                            potential_risk = "interesting_keyword_in_path"
                        elif normalized_path.split('/')[-1] in INTERESTING_FILENAMES:
                             potential_risk = "interesting_filename"
                        elif normalized_path.endswith(('/.git/', '/.git/config', '/.svn/', '/.hg/')):
                             potential_risk = "vcs_exposure"


                        if path.endswith('/'):
                            is_directory_guess = True
                        elif redirect_url and redirect_url.endswith('/') and redirect_url.startswith(path):
                            is_directory_guess = True
                        elif not '.' in path.split('/')[-1] and potential_risk != "vcs_exposure":
                             if status_code == 200: # Only guess dir for 200s without extension
                                is_directory_guess = True
                        
                        attributes["is_directory_guess"] = is_directory_guess
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
                        if verbose > 0: print(f"[DEBUG_GOBUSTER] NO MATCH on data line {line_number}: '{line}' with dir_pattern")
                
                elif mode == 'vhost':
                    match = vhost_pattern.match(line)
                    if match:
                        if verbose > 0: print(f"[DEBUG_GOBUSTER] SUCCESSFUL VHOST MATCH on line {line_number}: '{line}'")
                        data = match.groupdict()
                        vhost_name = data['vhost']
                        status_code_vhost = int(data['status']) if data['status'] else None

                        attributes = {"raw_line": original_line_for_debug}
                        if status_code_vhost:
                            attributes["status_code"] = status_code_vhost

                        findings.append({
                            "host": target_host,
                            "port": target_port,
                            "source_tool": "gobuster",
                            "entity_type": "virtual_host",
                            "name": vhost_name,
                            "version": None,
                            "attributes": attributes
                        })
                    else:
                         if verbose > 0: print(f"[DEBUG_GOBUSTER] NO MATCH on data line {line_number}: '{line}' with vhost_pattern")
                # Add other modes (dns, s3, etc.) here as needed
    
    except FileNotFoundError:
        print(f"[!] Error: Gobuster output file not found at {gobuster_output_file}")
    except Exception as e:
        print(f"[!] An error occurred while parsing Gobuster output: {e}")
        
    return findings

# --- Example Usage (for standalone testing of this script) ---
if __name__ == '__main__':
    # Create a dummy gobuster_results.txt for testing
    test_gobuster_content_dir = """Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.171.72
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/app                  (Status: 301) [Size: 314] [--> http://192.168.171.72/app/]
/javascript           (Status: 301) [Size: 321] [--> http://192.168.171.72/javascript/]
/backup               (Status: 301) [Size: 317] [--> http://192.168.171.72/backup/]
/otherfile.txt        (Status: 200) [Size: 100]
/.git/config          (Status: 200) [Size: 85]
/admin/login.php      (Status: 200) [Size: 1200]
===============================================================
Finished
===============================================================
"""
    test_gobuster_file_dir = "test_gobuster_parser_standalone.txt"
    with open(test_gobuster_file_dir, "w") as f:
        f.write(test_gobuster_content_dir)

    print("--- Testing Gobuster DIR mode parser (verbose=2) ---")
    parsed_dir_findings = parse_gobuster_output(
        test_gobuster_file_dir, 
        "192.168.171.72", 
        80, 
        mode='dir',
        verbose=2 # Set verbosity level for debugging
    )
    
    if parsed_dir_findings:
        print(f"\nFound {len(parsed_dir_findings)} 'dir' mode findings:\n")
        for i, finding in enumerate(parsed_dir_findings):
            print(f"--- Finding {i+1} ---")
            print(f"  Host: {finding.get('host')}, Port: {finding.get('port')}")
            print(f"  Source: {finding.get('source_tool')}")
            print(f"  Type: {finding.get('entity_type')}")
            print(f"  Name: {finding.get('name')}")
            print(f"  Attributes:")
            for key, val in finding.get("attributes", {}).items():
                print(f"    {key}: {val}")
            print("")
    else:
        print("No 'dir' mode findings extracted.")

    # --- Test VHOST mode ---
    test_gobuster_content_vhost = """Gobuster v3.6
===============================================================
[+] Url:          http://10.10.10.100
[+] Threads:      50
[+] Wordlist:     /path/to/vhost_wordlist.txt
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: dev.testserver.com (Status: 200)
Found: api.testserver.com (Status: 200)
===============================================================
Finished
===============================================================
"""
    test_gobuster_file_vhost = "test_gobuster_vhost_parser_standalone.txt"
    with open(test_gobuster_file_vhost, "w") as f:
        f.write(test_gobuster_content_vhost)

    print("\n--- Testing Gobuster VHOST mode parser (verbose=2) ---")
    parsed_vhost_findings = parse_gobuster_output(
        test_gobuster_file_vhost, 
        "10.10.10.100", 
        80, 
        mode='vhost',
        verbose=2
    )
    
    if parsed_vhost_findings:
        print(f"\nFound {len(parsed_vhost_findings)} 'vhost' mode findings:\n")
        for i, finding in enumerate(parsed_vhost_findings):
            # (Similar printing logic as above)
            print(f"--- Finding {i+1} ---")
            print(f"  Host: {finding.get('host')}, Port: {finding.get('port')}")
            print(f"  Name: {finding.get('name')}")
            print(f"  Attributes: {finding.get('attributes')}")
            print("")
    else:
        print("No 'vhost' mode findings extracted.")

    # import os
    # os.remove(test_gobuster_file_dir)
    # os.remove(test_gobuster_file_vhost)