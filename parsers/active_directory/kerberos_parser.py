import re


def parse_kerbrute_output(file_path, domain):
    """
    Parses the output of kerbrute userenum to get a list of valid users.

    Args:
        file_path (str): Path to the kerbrute valid users output file.
        domain (str): The target domain name.

    Returns:
        list: A list of 'user' finding dictionaries.
    """
    findings = []
    verbose_pattern = re.compile(r'(?:\[\+\]|VALID USERNAME:?)\s*([^@\s]+)(?:@[^\s]+)?', re.IGNORECASE)

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                raw = line.strip()
                if not raw:
                    continue

                username = None
                match = verbose_pattern.search(raw)
                if match:
                    username = match.group(1)
                else:
                    # Plain format: one username per line.
                    candidate = raw.split()[0]
                    if candidate and not candidate.startswith('['):
                        username = candidate.split('@')[0]

                if username:
                    findings.append({
                        "host": domain, "port": 88, "source_tool": "kerbrute",
                        "entity_type": "user", "name": username, "version": None,
                        "attributes": {"source": "Kerberos user enumeration", "raw_line": raw}
                    })
    except FileNotFoundError:
        print(f"[!] Error: Kerbrute output file not found at {file_path}")
    return findings


def parse_getnpusers_output(file_path, domain):
    """
    Parses the hash output file from impacket-GetNPUsers.

    Args:
        file_path (str): Path to the GetNPUsers hash file.
        domain (str): The target domain name.

    Returns:
        list: A list of 'privilege_escalation' finding dictionaries.
    """
    findings = []
    # Capture username from typical hash lines (supports optional domain prefix before $krb5asrep).
    hash_pattern = re.compile(r'(?:^|\s)\$krb5asrep\$(\d+)\$([^@:$\s]+)@([^:\s]+):')
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                raw = line.strip()
                match = hash_pattern.search(raw)
                if match:
                    etype, username, hash_domain = match.groups()
                    findings.append({
                        "host": domain or hash_domain, "port": 88, "source_tool": "impacket-GetNPUsers",
                        "entity_type": "privilege_escalation",
                        "name": "asreproastable_user_hash_found",
                        "version": None,
                        "attributes": {
                            "user": username,
                            "hash": raw,
                            "etype": etype,
                            "description": f"Crackable AS-REP hash for user '{username}' was captured."
                        }
                    })
    except FileNotFoundError:
        print(f"[!] Error: GetNPUsers output file not found at {file_path}")
    return findings
