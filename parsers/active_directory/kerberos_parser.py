import re

from parsers.ansi import ANSI_ESCAPE_PATTERN, warn


def parse_kerbrute_output(file_path, domain):
    """
    Parses the output of kerbrute userenum to get a list of valid users.

    Handles multiple output formats:
    - Verbose: [+] VALID USERNAME: alice@domain
    - Timestamped: 2023/01/01 10:00:00 > [+] VALID USERNAME: alice@domain
    - Plain: one username per line (optionally with @domain)

    Args:
        file_path (str): Path to the kerbrute valid users output file.
        domain (str): The target domain name.

    Returns:
        list: A list of 'user' finding dictionaries.
    """
    findings = []
    seen_users = set()
    # Handles: [+] VALID USERNAME: user@domain, VALID USERNAME: user, and timestamped variants.
    # The key anchor is "VALID USERNAME" - everything before it (timestamps, [+]) is noise.
    verbose_pattern = re.compile(
        r'VALID\s+USERNAME:?\s+([^@\s]+)(?:@[^\s]+)?',
        re.IGNORECASE
    )

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                raw = ANSI_ESCAPE_PATTERN.sub('', line).strip()
                if not raw:
                    continue

                username = None
                match = verbose_pattern.search(raw)
                if match:
                    username = match.group(1)
                else:
                    # Plain format: one username per line.
                    candidate = raw.split()[0]
                    if candidate and not candidate.startswith('[') and not candidate[0].isdigit():
                        username = candidate.split('@')[0]

                if username and username.lower() not in seen_users:
                    seen_users.add(username.lower())
                    findings.append({
                        "host": domain, "port": 88, "source_tool": "kerbrute",
                        "entity_type": "user", "name": username, "version": None,
                        "attributes": {"source": "Kerberos user enumeration", "raw_line": raw}
                    })
    except FileNotFoundError:
        warn(f"[!] Error: Kerbrute output file not found at {file_path}")
    return findings


def parse_getnpusers_output(file_path, domain):
    """
    Parses the hash output file from impacket-GetNPUsers (or Rubeus AS-REP output).

    Handles multiple hash formats:
    - Standard: $krb5asrep$23$user@DOMAIN:salt$hash
    - Without domain: $krb5asrep$23$user:salt$hash
    - With domain\\ prefix in surrounding text

    Args:
        file_path (str): Path to the GetNPUsers hash file.
        domain (str): The target domain name.

    Returns:
        list: A list of 'privilege_escalation' finding dictionaries.
    """
    findings = []
    # Pattern 1: $krb5asrep$etype$user@domain:hash (standard impacket)
    hash_with_domain = re.compile(r'\$krb5asrep\$(\d+)\$([^@:$\s]+)@([^:\s]+):')
    # Pattern 2: $krb5asrep$etype$user:hash (no domain - some Rubeus output or stripped)
    hash_without_domain = re.compile(r'\$krb5asrep\$(\d+)\$([^@:$\s]+):')

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                raw = ANSI_ESCAPE_PATTERN.sub('', line).strip()
                if '$krb5asrep$' not in raw:
                    continue

                match = hash_with_domain.search(raw)
                if match:
                    etype, username, hash_domain = match.groups()
                else:
                    match = hash_without_domain.search(raw)
                    if match:
                        etype, username = match.groups()
                        hash_domain = None
                    else:
                        continue

                findings.append({
                    "host": domain or hash_domain or "UNKNOWN_DOMAIN",
                    "port": 88,
                    "source_tool": "impacket-GetNPUsers",
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
        warn(f"[!] Error: GetNPUsers output file not found at {file_path}")
    return findings


def parse_getuserspns_output(file_path, domain):
    """
    Parses the hash output of impacket-GetUserSPNs (Kerberoasting).

    Handles the TGS-REP hash format:
      $krb5tgs$23$*user$REALM$.../user*$<hash>

    For each captured hash it emits both a 'credential' finding (so the hash can
    be sprayed/cracked and reused) and a 'kerberoastable_user' privilege
    escalation finding (matching the existing Kerberoast attack rule).

    Args:
        file_path (str): Path to the GetUserSPNs hash file.
        domain (str): The target domain name.

    Returns:
        list: A list of finding dictionaries.
    """
    findings = []
    seen_users = set()
    # $krb5tgs$<etype>$*<user>$<realm>$... ; user/realm are between the first '*' and '$'.
    tgs_pattern = re.compile(r'\$krb5tgs\$(\d+)\$\*([^$*]+)\$([^$*]+)\$')

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                raw = ANSI_ESCAPE_PATTERN.sub('', line).strip()
                if '$krb5tgs$' not in raw:
                    continue

                match = tgs_pattern.search(raw)
                if not match:
                    continue
                etype, username, realm = match.groups()
                if username.lower() in seen_users:
                    continue
                seen_users.add(username.lower())

                host = domain or realm or "UNKNOWN_DOMAIN"
                findings.append({
                    "host": host, "port": 88, "source_tool": "impacket-GetUserSPNs",
                    "entity_type": "privilege_escalation", "name": "kerberoastable_user", "version": None,
                    "attributes": {
                        "user": f"{username}@{realm}" if realm else username,
                        "description": f"User {username} has an SPN and is Kerberoastable; TGS-REP hash captured.",
                    },
                })
                findings.append({
                    "host": host, "port": 88, "source_tool": "impacket-GetUserSPNs",
                    "entity_type": "credential", "name": username, "version": None,
                    "attributes": {
                        "domain": realm or None,
                        "hash": raw,
                        "hash_type": "Kerberos (TGS-REP, 13100)",
                        "etype": etype,
                        "source_of_credential": "GetUserSPNs Kerberoast",
                    },
                })
    except FileNotFoundError:
        warn(f"[!] Error: GetUserSPNs output file not found at {file_path}")
    return findings
