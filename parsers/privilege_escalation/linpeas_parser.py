import re

# General regex to find and remove all ANSI escape codes to get a clean text line.
ANSI_ESCAPE_PATTERN = re.compile(r'\x1b\[[0-9;]*[mK]')

# Specific regex to find the "red text on yellow background" signature that LinPEAS
# uses for "95% pwnable" privilege escalation vectors.
PE_COLOR_SIGNATURE = re.compile(r'\x1b\[[0-9;]*31[0-9;]*m.*\x1b\[[0-9;]*43[0-9;]*m|\x1b\[[0-9;]*43[0-9;]*m.*\x1b\[[0-9;]*31[0-9;]*m')

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

SECTION_HINTS = ["sudo", "suid", "capabilities", "cron", "docker", "lxd", "nfs"]


def parse_linpeas(file_path, target_host):
    """Parses LinPEAS output to find privilege escalation vectors."""
    findings = []
    found_lines = set()
    current_section = "general"

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                clean_line = ANSI_ESCAPE_PATTERN.sub('', line).strip()
                if not clean_line or len(clean_line) < 5:
                    continue

                # Track rough section boundaries for context-aware matching.
                if clean_line.startswith("===") or clean_line.startswith("["):
                    current_section = clean_line.lower()

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
                            "reason": "Red/Yellow Highlight",
                            "signal_source": "color_signature",
                            "confidence": "high",
                        }
                    })
                    found_lines.add(clean_line)
                    continue

                for keyword, vector_name in LINUX_PE_KEYWORDS.items():
                    if re.search(keyword, clean_line, re.IGNORECASE):
                        if clean_line in found_lines:
                            break

                        relevant_section = any(hint in current_section for hint in SECTION_HINTS)
                        findings.append({
                            "host": target_host, "port": None, "source_tool": "linpeas",
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
        print(f"[!] Error: LinPEAS output file not found at {file_path}")
    except Exception as e:
        print(f"[!] An unexpected error occurred while parsing LinPEAS: {e}")

    return findings
