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
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            # Kerbrute output is a simple list of usernames, one per line.
            for line in f:
                username = line.strip()
                if username:
                    findings.append({
                        "host": domain, "port": 88, "source_tool": "kerbrute",
                        "entity_type": "user", "name": username, "version": None,
                        "attributes": {"source": "Kerberos user enumeration"}
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
    # Regex to capture the username from a hash line, e.g., $krb5asrep$23$user@DOMAIN:HEXDATA
    hash_pattern = re.compile(r'^\$krb5asrep\$\d+\$(.*?)@.*?:.*')
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                match = hash_pattern.match(line.strip())
                # If a line matches the hash format, extract the username.
                if match:
                    username = match.group(1)
                    findings.append({
                        "host": domain, "port": 88, "source_tool": "impacket-GetNPUsers",
                        "entity_type": "privilege_escalation",
                        "name": "asreproastable_user_hash_found",
                        "version": None,
                        "attributes": {
                            "user": username,
                            "hash": line.strip(),
                            "description": f"Crackable AS-REP hash for user '{username}' was captured."
                        }
                    })
    except FileNotFoundError:
        print(f"[!] Error: GetNPUsers output file not found at {file_path}")
    return findings