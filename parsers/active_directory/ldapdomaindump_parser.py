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
    
    # Helper to read TSV files and yield rows as dictionaries
    def read_tsv(filename):
        file_path = os.path.join(dir_path, filename)
        if not os.path.exists(file_path):
            return
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f, delimiter='\t')
            for row in reader:
                yield row

    domain = None # Will try to infer from users

    # Parse Users
    for user_row in read_tsv('domain_users.tsv'):
        if not domain and '@' in user_row.get('userprincipalname', ''):
            domain = user_row['userprincipalname'].split('@')[1]

        uac_flags = int(user_row.get('useraccountcontrol', 0))
        # Check for AS-REP Roastable (flag 0x400000)
        if uac_flags & 0x400000:
            findings.append({
                "host": domain or "UNKNOWN_DOMAIN", "port": 88, "source_tool": "ldapdomaindump",
                "entity_type": "privilege_escalation", "name": "asreproastable_user", "version": None,
                "attributes": {"user": user_row.get('samaccountname'), "description": f"User {user_row.get('samaccountname')} does not require Kerberos pre-authentication."}
            })

        findings.append({
            "host": domain or "UNKNOWN_DOMAIN", "port": 389, "source_tool": "ldapdomaindump",
            "entity_type": "user", "name": user_row.get('samaccountname'), "version": None,
            "attributes": user_row
        })

    # Parse Groups
    for group_row in read_tsv('domain_groups.tsv'):
        findings.append({
            "host": domain or "UNKNOWN_DOMAIN", "port": 389, "source_tool": "ldapdomaindump",
            "entity_type": "group", "name": group_row.get('samaccountname'), "version": None,
            "attributes": group_row
        })
        
    # Parse Computers
    for computer_row in read_tsv('domain_computers.tsv'):
        findings.append({
            "host": computer_row.get('dnshostname'), "port": None, "source_tool": "ldapdomaindump",
            "entity_type": "computer", "name": computer_row.get('samaccountname'), "version": None,
            "attributes": computer_row
        })

    return findings