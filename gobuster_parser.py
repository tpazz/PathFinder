import re

def parse_gobuster_output(gobuster_output_file, target_host, target_port=None, mode='dir'):
    """
    Parses Gobuster output (currently supports 'dir' mode primarily) and
    extracts findings into the specified format.

    Args:
        gobuster_output_file (str): Path to the Gobuster output text file.
        target_host (str): The target host/IP Gobuster was run against.
                           This is needed as Gobuster output doesn't always include it.
        target_port (int, optional): The target port. If None, it's assumed based on scheme
                                     (e.g., 80 for http, 443 for https if not specified in URL).
                                     It's best to provide this if known.
        mode (str): The Gobuster mode used (e.g., 'dir', 'vhost').
                    Currently, 'dir' is the primary focus.

    Returns:
        list: A list of finding dictionaries.
    """
    findings = []
    
    # Regular expression to parse common gobuster dir output lines
    # Example line: /config.php (Status: 200) [Size: 1234]
    # Example line: /images (Status: 301) [Size: 0] --> /images/
    # Example line: /admin (Status: 403) [Size: 212]
    # Needs to be flexible for presence/absence of Size and redirection
    dir_pattern = re.compile(
        r"^(?P<path>/[^\s\(]+)"          # Path (starts with /, no spaces or opening parenthesis)
        r"\s*\(Status:\s*(?P<status>\d{3})\)" # Status code
        r"(?:\s*\[Size:\s*(?P<size>\d+)\])?"  # Optional Size
        r"(?:\s*-->\s*(?P<redirect_url>[^\s]+))?" # Optional Redirect URL
    )

    try:
        with open(gobuster_output_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("Gobuster") or \
                   line.startswith("===") or "Progress:" in line or "Finished" in line:
                    continue

                if mode == 'dir':
                    match = dir_pattern.match(line)
                    if match:
                        data = match.groupdict()
                        path = data['path']
                        status_code = int(data['status'])
                        size = int(data['size']) if data['size'] else None
                        redirect_url = data['redirect_url'] if data['redirect_url'] else None

                        attributes = {
                            "status_code": status_code,
                            "raw_line": line # Store the original line for reference
                        }
                        if size is not None:
                            attributes["size_bytes"] = size
                        if redirect_url:
                            attributes["redirect_url"] = redirect_url
                        
                        # Basic heuristic for potential risk - can be greatly expanded
                        potential_risk = None
                        normalized_path = path.lower()
                        if any(ext in normalized_path for ext in ['.bak', '.old', '.swp', '.backup', '.copy', '.tmp', '.temp']):
                            potential_risk = "sensitive_backup_file"
                        elif any(kw in normalized_path for kw in ['config', '.cfg', '.ini', '.env', 'secret', 'cred', 'passwd', 'shadow']):
                            potential_risk = "potential_config_or_credential_file"
                        elif any(ext in normalized_path for ext in ['.sql', '.db', '.mdb']):
                            potential_risk = "database_file_exposure"
                        elif any(ext in normalized_path for ext in ['.log']):
                            potential_risk = "log_file_exposure"
                        elif any(kw in normalized_path for kw in ['admin', 'login', 'adm', 'cpanel', 'webadmin', 'phpmyadmin']):
                            potential_risk = "admin_or_login_interface"
                        elif normalized_path.endswith(('.zip', '.tar', '.gz', '.rar', '.7z')):
                            potential_risk = "archive_file_exposure"
                        elif normalized_path.endswith(('/.git/', '/.git/config', '/.svn/', '/.hg/')):
                             potential_risk = "vcs_exposure"
                        
                        # Check if it's likely a directory based on redirect or common names
                        is_directory = False
                        if path.endswith('/'):
                            is_directory = True
                        elif redirect_url and redirect_url.endswith('/') and redirect_url.startswith(path):
                            is_directory = True
                        elif status_code in [301, 302, 307, 308] and redirect_url and redirect_url.endswith('/'):
                            is_directory = True
                        elif not '.' in path.split('/')[-1] and potential_risk != "vcs_exposure": # Heuristic: no extension often means dir
                            if status_code == 200 and (size is None or size < 10000): # Small size 200s could be listings
                                # This is a weak heuristic, real directory listing checks are better
                                potential_risk = potential_risk or "potential_directory_listing"
                                is_directory = True
                        
                        attributes["is_directory_guess"] = is_directory
                        if potential_risk:
                            attributes["potential_risk"] = potential_risk

                        findings.append({
                            "host": target_host,
                            "port": target_port, # May need better logic if URL had scheme but no port
                            "source_tool": "gobuster",
                            "entity_type": "web_content",
                            "name": path,
                            "version": None, # Typically N/A for Gobuster findings
                            "attributes": attributes
                        })
                
                elif mode == 'vhost':
                    # Example line for vhost: Found: sub.domain.com (Status: 200)
                    vhost_pattern = re.compile(r"Found:\s*(?P<vhost>[^\s\(]+)(?:\s*\(Status:\s*(?P<status>\d{3})\))?")
                    match = vhost_pattern.match(line)
                    if match:
                        data = match.groupdict()
                        vhost_name = data['vhost']
                        status_code = int(data['status']) if data['status'] else None # Status might not always be there

                        attributes = {"raw_line": line}
                        if status_code:
                            attributes["status_code"] = status_code

                        findings.append({
                            "host": target_host, # The IP Gobuster was resolving against
                            "port": target_port,
                            "source_tool": "gobuster",
                            "entity_type": "virtual_host", # New entity_type for vhosts
                            "name": vhost_name,
                            "version": None,
                            "attributes": attributes
                        })
                # Add other modes (dns, s3, etc.) here as needed
    
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
[+] Url:            http://testserver.com
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.1.0
[+] Timeout:        10s
===============================================================
2023/03/15 10:00:00 Starting gobuster
===============================================================
/images (Status: 301) [Size: 0] --> http://testserver.com/images/
/uploads (Status: 200) [Size: 123]
/config.php.bak (Status: 200) [Size: 4096]
/admin (Status: 403) [Size: 212]
/backup.zip (Status: 200) [Size: 1024000]
/.git/config (Status: 200) [Size: 85]
/index.html (Status: 200) [Size: 700]
/secret-stuff (Status: 200) [Size: 100]
/api/users (Status: 200) [Size: 550]
/README.txt (Status: 200) [Size: 180]
===============================================================
2023/03/15 10:05:00 Finished
===============================================================
    """
    test_gobuster_file_dir = "test_gobuster_dir.txt"
    with open(test_gobuster_file_dir, "w") as f:
        f.write(test_gobuster_content_dir)

    parsed_dir_findings = parse_gobuster_output(test_gobuster_file_dir, "testserver.com", 80, mode='dir')
    
    if parsed_dir_findings:
        print(f"Found {len(parsed_dir_findings)} 'dir' mode findings:\n")
        for i, finding in enumerate(parsed_dir_findings):
            print(f"--- Finding {i+1} ---")
            for key, value in finding.items():
                if key == "attributes":
                    print(f"  {key}:")
                    for a_key, a_value in value.items():
                        print(f"    {a_key}: {a_value}")
                else:
                    print(f"  {key}: {value}")
            print("")
    else:
        print("No 'dir' mode findings extracted.")

    # --- Test VHOST mode ---
    test_gobuster_content_vhost = """
Gobuster v3.1.0
===============================================================
[+] Url:          http://10.10.10.100
[+] Threads:      50
[+] Wordlist:     /path/to/vhost_wordlist.txt
===============================================================
2023/03/15 11:00:00 Starting gobuster
===============================================================
Found: dev.testserver.com (Status: 200)
Found: api.testserver.com (Status: 200)
Found: staging.testserver.com (Status: 403)
Found: old.testserver.com
===============================================================
2023/03/15 11:05:00 Finished
===============================================================
    """
    test_gobuster_file_vhost = "test_gobuster_vhost.txt"
    with open(test_gobuster_file_vhost, "w") as f:
        f.write(test_gobuster_content_vhost)

    parsed_vhost_findings = parse_gobuster_output(test_gobuster_file_vhost, "10.10.10.100", 80, mode='vhost')
    
    if parsed_vhost_findings:
        print(f"\nFound {len(parsed_vhost_findings)} 'vhost' mode findings:\n")
        for i, finding in enumerate(parsed_vhost_findings):
            print(f"--- Finding {i+1} ---")
            # ... (same printing logic as above) ...
            for key, value in finding.items():
                if key == "attributes":
                    print(f"  {key}:")
                    for a_key, a_value in value.items():
                        print(f"    {a_key}: {a_value}")
                else:
                    print(f"  {key}: {value}")
            print("")
    else:
        print("No 'vhost' mode findings extracted.")


    # Clean up dummy files (optional)
    # import os
    # os.remove(test_gobuster_file_dir)
    # os.remove(test_gobuster_file_vhost)