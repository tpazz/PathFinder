import os
import csv

def parse_ldapdomaindump_dir(dir_path):
    """
    Parses the TSV files from ldapdomaindump output directory.

    Args:
        dir_path (str): Path to the directory containing ldapdomaindump TSV files.

    Returns:
        list: A list of finding dictionaries.
    """
    findings = []
    
    # Helper function to read .tsv files, which are tab-separated.
    # It yields each row as a dictionary, making it easy to access columns by name.
    def read_tsv(filename):
        file_path = os.path.join(dir_path, filename)
        if not os.path.exists(file_path):
            return
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f, delimiter='\t')
            for row in reader:
                yield row

    # The domain name is not explicitly provided, so we try to infer it from user data.
    domain = None

    # Parse Users from the domain_users.tsv file.
    for user_row in read_tsv('domain_users.tsv'):
        # Attempt to get the domain name from the first userprincipalname found.
        if not domain and '@' in user_row.get('userprincipalname', ''):
            domain = user_row['userprincipalname'].split('@')[1]

        # Check the UserAccountControl flags for specific vulnerabilities.
        uac_flags = int(user_row.get('useraccountcontrol', 0))
        # The flag 0x400000 (DONT_REQ_PREAUTH) indicates an AS-REP Roastable account.
        if uac_flags & 0x400000:
            findings.append({
                "host": domain or "UNKNOWN_DOMAIN", "port": 88, "source_tool": "ldapdomaindump",
                "entity_type": "privilege_escalation", "name": "asreproastable_user", "version": None,
                "attributes": {"user": user_row.get('samaccountname'), "description": f"User {user_row.get('samaccountname')} does not require Kerberos pre-authentication."}
            })

        # Create a standard 'user' finding for every user found.
        findings.append({
            "host": domain or "UNKNOWN_DOMAIN", "port": 389, "source_tool": "ldapdomaindump",
            "entity_type": "user", "name": user_row.get('samaccountname'), "version": None,
            "attributes": user_row # Store the full row of user data in attributes.
        })

    # Parse Groups from the domain_groups.tsv file.
    for group_row in read_tsv('domain_groups.tsv'):
        findings.append({
            "host": domain or "UNKNOWN_DOMAIN", "port": 389, "source_tool": "ldapdomaindump",
            "entity_type": "group", "name": group_row.get('samaccountname'), "version": None,
            "attributes": group_row
        })
        
    # Parse Computers from the domain_computers.tsv file.
    for computer_row in read_tsv('domain_computers.tsv'):
        findings.append({
            "host": computer_row.get('dnshostname'), "port": None, "source_tool": "ldapdomaindump",
            "entity_type": "computer", "name": computer_row.get('samaccountname'), "version": None,
            "attributes": computer_row
        })

    return findings