import json
import os

# Well-known SIDs for high-value groups
HIGH_VALUE_GROUP_SIDS = {
    "S-1-5-32-544": "Administrators",
    "S-1-5-21-DOMAIN-512": "Domain Admins",
    "S-1-5-21-DOMAIN-519": "Enterprise Admins",
}

def _load_sharphound_json(directory, filename):
    """Safely loads a JSON file from the SharpHound output directory."""
    try:
        with open(os.path.join(directory, filename), 'r', encoding='utf-8') as f:
            return json.load(f).get('data', [])
    except (FileNotFoundError, json.JSONDecodeError, AttributeError):
        print(f"[!] Warning: Could not load or parse '{filename}' from SharpHound directory.")
        return []

def parse_sharphound_dir(dir_path):
    """
    Parses SharpHound JSON files to find AD privilege escalation vectors.

    Args:
        dir_path (str): Path to the directory containing the unzipped SharpHound files.

    Returns:
        list: A list of 'privilege_escalation' finding dictionaries.
    """
    findings = []
    
    users = _load_sharphound_json(dir_path, 'users.json')
    groups = _load_sharphound_json(dir_path, 'groups.json')
    if not users: return findings

    # Create a map of group Object IDs to their names for easy lookup
    group_map = {group['ObjectIdentifier']: group['Name'] for group in groups}

    for user in users:
        username = user.get('Name')
        domain = user.get('Domain')
        user_fqdn = f"{username}@{domain}"
        
        # 1. AS-REP Roastable
        if user.get('DontReqPreAuth', False):
            findings.append({
                "host": domain, "port": 88, "source_tool": "sharphound",
                "entity_type": "privilege_escalation", "name": "asreproastable_user", "version": None,
                "attributes": {"user": user_fqdn, "description": f"User {user_fqdn} does not require Kerberos pre-authentication."}
            })

        # 2. Kerberoastable
        if user.get('HasSPN', False) and not user_fqdn.lower().endswith('krbtgt'):
            findings.append({
                "host": domain, "port": 88, "source_tool": "sharphound",
                "entity_type": "privilege_escalation", "name": "kerberoastable_user", "version": None,
                "attributes": {"user": user_fqdn, "description": f"User {user_fqdn} has a Service Principal Name and is likely Kerberoastable."}
            })

        # 3. Attractive Users (Admin Privileges)
        if user.get('IsAdmin', False) or user.get('IsPrimaryGroupAdmin', False):
            findings.append({
                "host": domain, "port": None, "source_tool": "sharphound",
                "entity_type": "privilege_escalation", "name": "attractive_user_high_privileges", "version": None,
                "attributes": {"user": user_fqdn, "description": f"User {user_fqdn} has AdminCount=true, indicating high privileges."}
            })
        
        # Check for membership in high-value groups
        for member_of in user.get('PrimaryGroupSID', []) + [g['ObjectIdentifier'] for g in user.get('MemberOf', [])]:
            # Normalize SID for Domain Admins/Enterprise Admins
            normalized_sid = member_of.replace(user.get('DomainSID'), "S-1-5-21-DOMAIN")
            if normalized_sid in HIGH_VALUE_GROUP_SIDS:
                group_name = HIGH_VALUE_GROUP_SIDS[normalized_sid]
                findings.append({
                    "host": domain, "port": None, "source_tool": "sharphound",
                    "entity_type": "privilege_escalation", "name": f"attractive_user_member_of_{group_name.lower().replace(' ', '_')}", "version": None,
                    "attributes": {"user": user_fqdn, "description": f"User {user_fqdn} is a member of the high-value group: {group_name}."}
                })

    return findings