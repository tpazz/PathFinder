import re

# General regex to find and remove all ANSI escape codes to get a clean text line.
ANSI_ESCAPE_PATTERN = re.compile(r'\x1b\[[0-9;]*[mK]')

# Specific regex to find the "red text on yellow background" signature that LinPEAS
# uses for "95% pwnable" privilege escalation vectors.
# It looks for the color codes for red (31) and yellow background (43) appearing in any order.
PE_COLOR_SIGNATURE = re.compile(r'\x1b\[[0-9;]*31[0-9;]*m.*\x1b\[[0-9;]*43[0-9;]*m|\x1b\[[0-9;]*43[0-9;]*m.*\x1b\[[0-9;]*31[0-9;]*m')

# A dictionary of keywords for a secondary, broader search for PE vectors.
# Maps a regex pattern to a standardized finding name.
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
    # Use a set to track clean lines we've already processed to avoid creating duplicate findings.
    found_lines = set()

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                # Create a clean version of the line for keyword matching and storing.
                clean_line = ANSI_ESCAPE_PATTERN.sub('', line).strip()
                if not clean_line or len(clean_line) < 5:
                    continue

                # Primary Method: Check the raw line for the "red on yellow" color signature.
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
                    # Prioritize the color-based finding and skip keyword checks for this line.
                    continue

                # Secondary Method: If no color match, check the clean line for keywords.
                for keyword, vector_name in LINUX_PE_KEYWORDS.items():
                    if re.search(keyword, clean_line, re.IGNORECASE):
                        if clean_line in found_lines:
                            break # Line was already processed (e.g., as a color find), so skip.
                        
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
                        # Once a keyword is matched, we're done with this line.
                        break
    except FileNotFoundError:
        print(f"[!] Error: LinPEAS output file not found at {file_path}")
    except Exception as e:
        print(f"[!] An unexpected error occurred while parsing LinPEAS: {e}")
        
    return findings