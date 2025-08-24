import re

# Regex to find and remove all ANSI escape codes.
ANSI_ESCAPE_PATTERN = re.compile(r'\x1b\[[0-9;]*[mK]')

# Regex to specifically find the "red on yellow" signature for PE vectors.
# Looks for codes like [31;43m or [1;31;43m etc.
PE_COLOR_SIGNATURE = re.compile(r'\x1b\[[0-9;]*31[0-9;]*m.*\x1b\[[0-9;]*43[0-9;]*m|\x1b\[[0-9;]*43[0-9;]*m.*\x1b\[[0-9;]*31[0-9;]*m')

# Keywords for secondary PE vector detection (case-insensitive)
LINUX_PE_KEYWORDS = {
    "suid": "suid_binary_found",
    "guid": "guid_binary_found",
    "capabilities": "process_capabilities_found",
    "sudo version": "outdated_sudo_version",
    "sudo -l": "sudo_nopasswd_privileges",
    "writable.*(passwd|shadow)": "writable_sensitive_file_etc_passwd_shadow",
    "writable cron": "writable_cron_job",
    "docker.sock": "writable_docker_socket",
    "lxd": "lxd_privilege_escalation_possible",
    "nfs.*no_root_squash": "nfs_no_root_squash",
}

def parse_linpeas(file_path, target_host):
    """
    Parses LinPEAS output to find privilege escalation vectors.

    Args:
        file_path (str): Path to the LinPEAS output text file.
        target_host (str): The IP of the target host.

    Returns:
        list: A list of 'privilege_escalation' finding dictionaries.
    """
    findings = []
    found_lines = set() # To avoid duplicate findings from color and keyword

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                clean_line = ANSI_ESCAPE_PATTERN.sub('', line).strip()
                if not clean_line or len(clean_line) < 5:
                    continue

                # Primary Method: Check for "red on yellow" color signature
                if PE_COLOR_SIGNATURE.search(line):
                    if clean_line in found_lines:
                        continue
                    
                    findings.append({
                        "host": target_host, "port": None, "source_tool": "linpeas",
                        "entity_type": "privilege_escalation",
                        "name": "peas_highlighted_finding_95_pwnable",
                        "version": None,
                        "attributes": {
                            "description": clean_line,
                            "raw_line": line.strip(),
                            "reason": "Red/Yellow Highlight"
                        }
                    })
                    found_lines.add(clean_line)
                    continue # Prioritize color findings

                # Secondary Method: Check for keywords
                for keyword, vector_name in LINUX_PE_KEYWORDS.items():
                    if re.search(keyword, clean_line, re.IGNORECASE):
                        if clean_line in found_lines:
                            break # Already found, don't re-add
                        
                        findings.append({
                            "host": target_host, "port": None, "source_tool": "linpeas",
                            "entity_type": "privilege_escalation",
                            "name": vector_name,
                            "version": None,
                            "attributes": {
                                "description": clean_line,
                                "raw_line": line.strip(),
                                "reason": f"Keyword match: '{keyword}'"
                            }
                        })
                        found_lines.add(clean_line)
                        break # Move to next line after first keyword match
    except FileNotFoundError:
        print(f"[!] Error: LinPEAS output file not found at {file_path}")
    except Exception as e:
        print(f"[!] An unexpected error occurred while parsing LinPEAS: {e}")
        
    return findings