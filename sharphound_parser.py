import json
import os

# Well-known SIDs for high-value groups. The "DOMAIN" placeholder will be replaced.
HIGH_VALUE_GROUP_SIDS = {
    "S-1-5-32-544": "Administrators",
    "S-1-5-21-DOMAIN-512": "Domain Admins",
    "S-1-5-21-DOMAIN-519": "Enterprise Admins",
}

# Specific rights that constitute a DCSync attack vector.
DCSYNC_RIGHTS = {
    "DS-Replication-Get-Changes",
    "DS-Replication-Get-Changes-All"
}

def _load_sharphound_json(directory, filename):
    """Safely loads a JSON file from the SharpHound output directory."""
    try:
        with open(os.path.join(directory, filename), 'r', encoding='utf-8') as f:
            # SharpHound JSON often has a 'meta' key and a 'data' key. We only want the data.
            return json.load(f).get('data', [])
    except (FileNotFoundError, json.JSONDecodeError, AttributeError):
        print(f"[!] Warning: Could not load or parse '{filename}' from SharpHound directory.")
        return []

def parse_sharphound_dir(dir_path):
    """
    Parses SharpHound JSON files (V2) to find AD attack paths, including ACL-based attacks.

    Args:
        dir_path (str): Path to the directory containing the unzipped SharpHound files.

    Returns:
        list: A list of 'privilege_escalation' and other finding dictionaries.
    """
    findings = []
    
    # Load all necessary data sources
    users = _load_sharphound_json(dir_path, 'users.json')
    groups = _load_sharphound_json(dir_path, 'groups.json')
    computers = _load_sharphound_json(dir_path, 'computers.json')
    domains = _load_sharphound_json(dir_path, 'domains.json')
    sessions = _load_sharphound_json(dir_path, 'sessions.json')

    if not users and not domains:
        return findings

    # --- Pre-computation Step: Create helper maps for fast lookups ---
    sid_to_name_map = {}
    for user in users: sid_to_name_map[user['ObjectIdentifier']] = user['Name']
    for group in groups: sid_to_name_map[group['ObjectIdentifier']] = group['Name']
    for computer in computers: sid_to_name_map[computer['ObjectIdentifier']] = computer['Name']
    
    domain_sid = domains[0]['ObjectIdentifier'] if domains else None
    domain_name = domains[0]['Name'] if domains else "UNKNOWN_DOMAIN"
    
    # Create a set of high-value group SIDs for this specific domain
    domain_high_value_sids = {sid.replace("DOMAIN", domain_sid) for sid in HIGH_VALUE_GROUP_SIDS}
    high_value_targets = set()
    for group in groups:
        if group['ObjectIdentifier'] in domain_high_value_sids:
            high_value_targets.add(group['ObjectIdentifier'])
    
    # --- 1. User-Centric Checks (AS-REP, Kerberoast, AdminCount) ---
    high_value_user_sids = set()
    for user in users:
        user_fqdn = user.get('Name')
        user_sid = user['ObjectIdentifier']

        if user.get('DontReqPreAuth', False):
            findings.append({
                "host": domain_name, "port": 88, "source_tool": "sharphound",
                "entity_type": "privilege_escalation", "name": "asreproastable_user",
                "attributes": {"user": user_fqdn, "description": f"User {user_fqdn} does not require Kerberos pre-authentication."}
            })

        if user.get('HasSPN', False) and not user_fqdn.lower().endswith('krbtgt'):
            findings.append({
                "host": domain_name, "port": 88, "source_tool": "sharphound",
                "entity_type": "privilege_escalation", "name": "kerberoastable_user",
                "attributes": {"user": user_fqdn, "description": f"User {user_fqdn} has a Service Principal Name and is likely Kerberoastable."}
            })

        if user.get('IsAdmin', False):
            high_value_user_sids.add(user_sid)
            findings.append({
                "host": domain_name, "port": None, "source_tool": "sharphound",
                "entity_type": "privilege_escalation", "name": "attractive_user_high_privileges",
                "attributes": {"user": user_fqdn, "description": f"User {user_fqdn} has AdminCount=true, indicating high privileges."}
            })
    
    # --- 2. ACL-Based Checks (DCSync, GenericWrite) ---
    all_objects = users + groups + computers + domains
    for obj in all_objects:
        obj_sid = obj['ObjectIdentifier']
        obj_name = obj['Name']
        
        # DCSync check (only on domain object)
        if obj.get('ObjectType') == 'Domain':
            user_dcsync_rights = {}
            for ace in obj.get('Aces', []):
                principal_sid = ace.get('PrincipalSID')
                right = ace.get('RightName')
                if right in DCSYNC_RIGHTS:
                    user_dcsync_rights.setdefault(principal_sid, set()).add(right)
            
            for principal_sid, rights in user_dcsync_rights.items():
                if rights.issuperset(DCSYNC_RIGHTS):
                    principal_name = sid_to_name_map.get(principal_sid, principal_sid)
                    findings.append({
                        "host": domain_name, "port": None, "source_tool": "sharphound",
                        "entity_type": "privilege_escalation", "name": "dcsync_rights_found",
                        "attributes": {"user": principal_name, "description": f"'{principal_name}' has DCSync rights over the domain."}
                    })

        # GenericWrite / GenericAll check
        for ace in obj.get('Aces', []):
            principal_sid = ace.get('PrincipalSID')
            right = ace.get('RightName')
            if right in ["GenericWrite", "GenericAll"] and obj_sid in high_value_targets and principal_sid not in high_value_targets:
                principal_name = sid_to_name_map.get(principal_sid, principal_sid)
                findings.append({
                    "host": domain_name, "port": None, "source_tool": "sharphound",
                    "entity_type": "privilege_escalation", "name": f"genericwrite_on_sensitive_group",
                    "attributes": {"attacker": principal_name, "target": obj_name, "description": f"'{principal_name}' has {right} rights on the high-value group '{obj_name}'."}
                })

    # --- 3. Delegation Checks ---
    for computer in computers:
        if computer.get('UnconstrainedDelegation', False):
            computer_name = computer.get('Name')
            findings.append({
                "host": domain_name, "port": None, "source_tool": "sharphound",
                "entity_type": "privilege_escalation", "name": "unconstrained_delegation_enabled",
                "attributes": {"computer": computer_name, "description": f"Computer '{computer_name}' has Unconstrained Delegation enabled."}
            })

    # --- 4. Privileged Session Checks ---
    for session in sessions:
        user_sid = session.get('UserSID')
        computer_sid = session.get('ComputerSID')
        if user_sid in high_value_user_sids:
            user_name = sid_to_name_map.get(user_sid, user_sid)
            computer_name = sid_to_name_map.get(computer_sid, computer_sid)
            findings.append({
                "host": domain_name, "port": None, "source_tool": "sharphound",
                "entity_type": "privilege_escalation", # High priority because it's an active session
                "name": "privileged_user_session_found",
                "attributes": {"user": user_name, "computer": computer_name, "description": f"High-privilege user '{user_name}' has an active session on '{computer_name}'."}
            })
            
    return findings