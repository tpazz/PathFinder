import json
import os

# Well-known Security Identifiers (SIDs) for high-value default groups.
# The "DOMAIN" placeholder will be dynamically replaced with the actual domain SID later.
HIGH_VALUE_GROUP_SIDS = {
    "S-1-5-32-544": "Administrators",
    "S-1-5-21-DOMAIN-512": "Domain Admins",
    "S-1-5-21-DOMAIN-519": "Enterprise Admins",
}

# The specific extended rights required to perform a DCSync attack.
DCSYNC_RIGHTS = {
    "DS-Replication-Get-Changes",
    "DS-Replication-Get-Changes-All"
}

def _load_sharphound_json(directory, filename):
    """Safely loads a JSON file from the SharpHound output directory."""
    try:
        with open(os.path.join(directory, filename), 'r', encoding='utf-8') as f:
            # SharpHound JSON has a 'meta' key and a 'data' key. We only need the 'data' part.
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
    
    # Load all necessary data sources from the SharpHound output files.
    users = _load_sharphound_json(dir_path, 'users.json')
    groups = _load_sharphound_json(dir_path, 'groups.json')
    computers = _load_sharphound_json(dir_path, 'computers.json')
    domains = _load_sharphound_json(dir_path, 'domains.json')
    sessions = _load_sharphound_json(dir_path, 'sessions.json')

    if not users and not domains:
        return findings

    # --- Pre-computation Step: Create helper maps and sets for fast lookups later ---
    # This avoids repeatedly searching through lists inside loops.
    sid_to_name_map = {}
    for user in users: sid_to_name_map[user['ObjectIdentifier']] = user['Name']
    for group in groups: sid_to_name_map[group['ObjectIdentifier']] = group['Name']
    for computer in computers: sid_to_name_map[computer['ObjectIdentifier']] = computer['Name']
    
    domain_sid = domains[0]['ObjectIdentifier'] if domains else None
    domain_name = domains[0]['Name'] if domains else "UNKNOWN_DOMAIN"
    
    # Create a set of high-value group SIDs specific to the discovered domain.
    domain_high_value_sids = {sid.replace("DOMAIN", domain_sid) for sid in HIGH_VALUE_GROUP_SIDS}
    high_value_targets = set()
    for group in groups:
        if group['ObjectIdentifier'] in domain_high_value_sids:
            high_value_targets.add(group['ObjectIdentifier'])
    
    # --- 1. User-Centric Checks (AS-REP, Kerberoast, AdminCount) ---
    # These checks focus on properties of individual user objects.
    high_value_user_sids = set()
    for user in users:
        user_fqdn = user.get('Name')
        user_sid = user['ObjectIdentifier']

        # Check for AS-REP Roastable accounts.
        if user.get('DontReqPreAuth', False):
            findings.append({
                "host": domain_name, "port": 88, "source_tool": "sharphound",
                "entity_type": "privilege_escalation", "name": "asreproastable_user",
                "attributes": {"user": user_fqdn, "description": f"User {user_fqdn} does not require Kerberos pre-authentication."}
            })

        # Check for Kerberoastable accounts (has an SPN and is not the krbtgt account).
        if user.get('HasSPN', False) and not user_fqdn.lower().endswith('krbtgt'):
            findings.append({
                "host": domain_name, "port": 88, "source_tool": "sharphound",
                "entity_type": "privilege_escalation", "name": "kerberoastable_user",
                "attributes": {"user": user_fqdn, "description": f"User {user_fqdn} has a Service Principal Name and is likely Kerberoastable."}
            })

        # Check for the AdminCount flag, a strong indicator of high privileges.
        if user.get('IsAdmin', False):
            high_value_user_sids.add(user_sid)
            findings.append({
                "host": domain_name, "port": None, "source_tool": "sharphound",
                "entity_type": "privilege_escalation", "name": "attractive_user_high_privileges",
                "attributes": {"user": user_fqdn, "description": f"User {user_fqdn} has AdminCount=true, indicating high privileges."}
            })
    
    # --- 2. ACL-Based Checks (DCSync, GenericWrite) ---
    # These checks parse the Access Control Lists (ACLs) of objects to find dangerous permissions.
    all_objects = users + groups + computers + domains
    for obj in all_objects:
        obj_sid = obj['ObjectIdentifier']
        obj_name = obj['Name']
        
        # DCSync rights can only be applied to the domain object itself.
        if obj.get('ObjectType') == 'Domain':
            user_dcsync_rights = {}
            # Iterate through all permissions (Aces) on the domain object.
            for ace in obj.get('Aces', []):
                principal_sid = ace.get('PrincipalSID')
                right = ace.get('RightName')
                if right in DCSYNC_RIGHTS:
                    user_dcsync_rights.setdefault(principal_sid, set()).add(right)
            
            # Check if any user has *both* required rights for DCSync.
            for principal_sid, rights in user_dcsync_rights.items():
                if rights.issuperset(DCSYNC_RIGHTS):
                    principal_name = sid_to_name_map.get(principal_sid, principal_sid)
                    findings.append({
                        "host": domain_name, "port": None, "source_tool": "sharphound",
                        "entity_type": "privilege_escalation", "name": "dcsync_rights_found",
                        "attributes": {"user": principal_name, "description": f"'{principal_name}' has DCSync rights over the domain."}
                    })

        # Check for GenericWrite/GenericAll permissions on high-value groups.
        for ace in obj.get('Aces', []):
            principal_sid = ace.get('PrincipalSID')
            right = ace.get('RightName')
            # The most interesting cases are when a non-privileged user can modify a privileged group.
            if right in ["GenericWrite", "GenericAll"] and obj_sid in high_value_targets and principal_sid not in high_value_targets:
                principal_name = sid_to_name_map.get(principal_sid, principal_sid)
                findings.append({
                    "host": domain_name, "port": None, "source_tool": "sharphound",
                    "entity_type": "privilege_escalation", "name": f"genericwrite_on_sensitive_group",
                    "attributes": {"attacker": principal_name, "target": obj_name, "description": f"'{principal_name}' has {right} rights on the high-value group '{obj_name}'."}
                })

    # --- 3. Delegation Checks ---
    # Checks for misconfigurations in Kerberos delegation.
    for computer in computers:
        # Unconstrained delegation is particularly dangerous.
        if computer.get('UnconstrainedDelegation', False):
            computer_name = computer.get('Name')
            findings.append({
                "host": domain_name, "port": None, "source_tool": "sharphound",
                "entity_type": "privilege_escalation", "name": "unconstrained_delegation_enabled",
                "attributes": {"computer": computer_name, "description": f"Computer '{computer_name}' has Unconstrained Delegation enabled."}
            })

    # --- 4. Privileged Session Checks ---
    # Finds where high-value users are currently logged on.
    for session in sessions:
        user_sid = session.get('UserSID')
        computer_sid = session.get('ComputerSID')
        # Check if the user in the session is one we previously identified as high-value.
        if user_sid in high_value_user_sids:
            user_name = sid_to_name_map.get(user_sid, user_sid)
            computer_name = sid_to_name_map.get(computer_sid, computer_sid)
            findings.append({
                "host": domain_name, "port": None, "source_tool": "sharphound",
                "entity_type": "privilege_escalation",
                "name": "privileged_user_session_found",
                "attributes": {"user": user_name, "computer": computer_name, "description": f"High-privilege user '{user_name}' has an active session on '{computer_name}'."}
            })
            
    return findings