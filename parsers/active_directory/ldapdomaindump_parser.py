import os
import csv


UAC_DONT_REQ_PREAUTH = 0x400000
UAC_PASSWD_NOTREQD = 0x20
UAC_DONT_EXPIRE_PASSWORD = 0x10000


def parse_ldapdomaindump_dir(dir_path):
    """
    Parses the TSV files from ldapdomaindump output directory.

    Args:
        dir_path (str): Path to the directory containing ldapdomaindump TSV files.

    Returns:
        list: A list of finding dictionaries.
    """
    findings = []

    def read_tsv(filename):
        file_path = os.path.join(dir_path, filename)
        if not os.path.exists(file_path):
            return
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f, delimiter='\t')
            for row in reader:
                yield row

    domain = None

    for user_row in read_tsv('domain_users.tsv'):
        sam = user_row.get('samaccountname') or "UNKNOWN_USER"

        if not domain and '@' in user_row.get('userprincipalname', ''):
            domain = user_row['userprincipalname'].split('@')[1]

        try:
            uac_flags = int(user_row.get('useraccountcontrol') or 0)
        except (ValueError, TypeError):
            uac_flags = 0

        if uac_flags & UAC_DONT_REQ_PREAUTH:
            findings.append({
                "host": domain or "UNKNOWN_DOMAIN", "port": 88, "source_tool": "ldapdomaindump",
                "entity_type": "privilege_escalation", "name": "asreproastable_user", "version": None,
                "attributes": {"user": sam, "description": f"User {sam} does not require Kerberos pre-authentication."}
            })

        if uac_flags & UAC_PASSWD_NOTREQD:
            findings.append({
                "host": domain or "UNKNOWN_DOMAIN", "port": 389, "source_tool": "ldapdomaindump",
                "entity_type": "misconfiguration", "name": "password_not_required_flag", "version": None,
                "attributes": {"user": sam, "description": f"User {sam} has PASSWD_NOTREQD enabled."}
            })

        if uac_flags & UAC_DONT_EXPIRE_PASSWORD:
            findings.append({
                "host": domain or "UNKNOWN_DOMAIN", "port": 389, "source_tool": "ldapdomaindump",
                "entity_type": "misconfiguration", "name": "password_never_expires", "version": None,
                "attributes": {"user": sam, "description": f"User {sam} has DONT_EXPIRE_PASSWORD enabled."}
            })

        selected_user_attrs = {
            "userprincipalname": user_row.get('userprincipalname'),
            "distinguishedname": user_row.get('distinguishedname'),
            "memberof": user_row.get('memberof'),
            "useraccountcontrol": user_row.get('useraccountcontrol'),
        }

        findings.append({
            "host": domain or "UNKNOWN_DOMAIN", "port": 389, "source_tool": "ldapdomaindump",
            "entity_type": "user", "name": sam, "version": None,
            "attributes": selected_user_attrs
        })

    for group_row in read_tsv('domain_groups.tsv'):
        findings.append({
            "host": domain or "UNKNOWN_DOMAIN", "port": 389, "source_tool": "ldapdomaindump",
            "entity_type": "group", "name": group_row.get('samaccountname') or "UNKNOWN_GROUP", "version": None,
            "attributes": {
                "distinguishedname": group_row.get('distinguishedname'),
                "description": group_row.get('description'),
            }
        })

    for computer_row in read_tsv('domain_computers.tsv'):
        hostname = computer_row.get('dnshostname') or domain or "UNKNOWN_HOST"
        findings.append({
            "host": hostname, "port": None, "source_tool": "ldapdomaindump",
            "entity_type": "computer", "name": computer_row.get('samaccountname') or "UNKNOWN_COMPUTER", "version": None,
            "attributes": {
                "operatingsystem": computer_row.get('operatingsystem'),
                "operatingsystemversion": computer_row.get('operatingsystemversion'),
                "distinguishedname": computer_row.get('distinguishedname'),
            }
        })

    return findings
