import re

# Re-using the same ANSI patterns as LinPEAS parser
ANSI_ESCAPE_PATTERN = re.compile(r'\x1b\[[0-9;]*[mK]')
PE_COLOR_SIGNATURE = re.compile(r'\x1b\[[0-9;]*31[0-9;]*m.*\x1b\[[0-9;]*43[0-9;]*m|\x1b\[[0-9;]*43[0-9;]*m.*\x1b\[[0-9;]*31[0-9;]*m')

# Keywords for secondary PE vector detection on Windows
WINDOWS_PE_KEYWORDS = {
    "unquoted service path": "unquoted_service_path",
    "alwaysinstallelevated": "alwaysinstallelevated_registry_key",
    "credman": "stored_credentials_credman",
    "juicypotato": "juicypotato_vulnerable_service_user",
    "seimpersonateprivilege": "seimpersonateprivilege_enabled",
    "unattended installation": "unattended_install_file_found",
    "gpp passwords": "group_policy_preferences_password_found",
    "svc.exe.*write": "writable_service_binary",
    "dll hijacking": "dll_hijacking_opportunity",
}

def parse_winpeas(file_path, target_host):
    """
    Parses WinPEAS output to find privilege escalation vectors.

    Args:
        file_path (str): Path to the WinPEAS output text file.
        target_host (str): The IP of the target host.

    Returns:
        list: A list of 'privilege_escalation' finding dictionaries.
    """
    findings = []
    found_lines = set()

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                clean_line = ANSI_ESCAPE_PATTERN.sub('', line).strip()
                if not clean_line or len(clean_line) < 5:
                    continue

                if PE_COLOR_SIGNATURE.search(line):
                    if clean_line in found_lines:
                        continue
                    
                    findings.append({
                        "host": target_host, "port": None, "source_tool": "winpeas",
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
                    continue

                for keyword, vector_name in WINDOWS_PE_KEYWORDS.items():
                    if re.search(keyword, clean_line, re.IGNORECASE):
                        if clean_line in found_lines:
                            break
                        
                        findings.append({
                            "host": target_host, "port": None, "source_tool": "winpeas",
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
                        break
    except FileNotFoundError:
        print(f"[!] Error: WinPEAS output file not found at {file_path}")
    except Exception as e:
        print(f"[!] An unexpected error occurred while parsing WinPEAS: {e}")
        
    return findings