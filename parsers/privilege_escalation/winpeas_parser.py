import re

ANSI_ESCAPE_PATTERN = re.compile(r'\x1b\[[0-9;]*[mK]')
PE_COLOR_SIGNATURE = re.compile(r'\x1b\[[0-9;]*31[0-9;]*m.*\x1b\[[0-9;]*43[0-9;]*m|\x1b\[[0-9;]*43[0-9;]*m.*\x1b\[[0-9;]*31[0-9;]*m')

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

SECTION_HINTS = ["service", "privilege", "alwaysinstallelevated", "credentials", "dll", "gpp"]


def parse_winpeas(file_path, target_host):
    """Parses WinPEAS output to find privilege escalation vectors."""
    findings = []
    found_lines = set()
    current_section = "general"

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                clean_line = ANSI_ESCAPE_PATTERN.sub('', line).strip()
                if not clean_line or len(clean_line) < 5:
                    continue

                if clean_line.startswith("===") or clean_line.startswith("["):
                    current_section = clean_line.lower()

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
                            "reason": "Red/Yellow Highlight",
                            "signal_source": "color_signature",
                            "confidence": "high",
                        }
                    })
                    found_lines.add(clean_line)
                    continue

                for keyword, vector_name in WINDOWS_PE_KEYWORDS.items():
                    if re.search(keyword, clean_line, re.IGNORECASE):
                        if clean_line in found_lines:
                            break

                        relevant_section = any(hint in current_section for hint in SECTION_HINTS)
                        findings.append({
                            "host": target_host, "port": None, "source_tool": "winpeas",
                            "entity_type": "privilege_escalation",
                            "name": vector_name,
                            "version": None,
                            "attributes": {
                                "description": clean_line,
                                "raw_line": line.strip(),
                                "reason": f"Keyword match: '{keyword}'",
                                "section": current_section,
                                "signal_source": "keyword_section_match" if relevant_section else "keyword_match",
                                "confidence": "medium" if relevant_section else "low",
                            }
                        })
                        found_lines.add(clean_line)
                        break
    except FileNotFoundError:
        print(f"[!] Error: WinPEAS output file not found at {file_path}")
    except Exception as e:
        print(f"[!] An unexpected error occurred while parsing WinPEAS: {e}")

    return findings
