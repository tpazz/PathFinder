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
ACL_ABUSE_RIGHTS = {"WriteDacl", "WriteOwner", "AddMember", "ForceChangePassword", "GenericAll", "GenericWrite"}


def _load_sharphound_json(directory, filename):
    """Safely loads a JSON file from the SharpHound output directory."""
    try:
        with open(os.path.join(directory, filename), 'r', encoding='utf-8') as f:
            payload = json.load(f)
            if isinstance(payload, dict):
                data = payload.get('data', [])
                return data if isinstance(data, list) else []
            if isinstance(payload, list):
                return payload
            return []
    except (FileNotFoundError, json.JSONDecodeError, AttributeError):
        print(f"[!] Warning: Could not load or parse '{filename}' from SharpHound directory.")
        return []


def _normalize_sharphound_object(obj):
    """Normalizes object keys for mild schema variance tolerance."""
    if not isinstance(obj, dict):
        return {}

    normalized = dict(obj)
    normalized.setdefault('ObjectIdentifier', normalized.get('ObjectID') or normalized.get('ObjectSid'))
    normalized.setdefault('Name', normalized.get('name') or normalized.get('DisplayName') or 'UNKNOWN')
    normalized.setdefault('Aces', normalized.get('Aces') or normalized.get('aces') or [])
    normalized.setdefault('ObjectType', normalized.get('ObjectType') or normalized.get('objectType'))
    return normalized


def parse_sharphound_dir(dir_path):
    """
    Parses SharpHound JSON files to find AD attack paths, including ACL-based attacks.

    Args:
        dir_path (str): Path to the directory containing the unzipped SharpHound files.

    Returns:
        list: A list of 'privilege_escalation' and other finding dictionaries.
    """
    findings = []

    users = [_normalize_sharphound_object(u) for u in _load_sharphound_json(dir_path, 'users.json')]
    groups = [_normalize_sharphound_object(g) for g in _load_sharphound_json(dir_path, 'groups.json')]
    computers = [_normalize_sharphound_object(c) for c in _load_sharphound_json(dir_path, 'computers.json')]
    domains = [_normalize_sharphound_object(d) for d in _load_sharphound_json(dir_path, 'domains.json')]
    sessions = _load_sharphound_json(dir_path, 'sessions.json')

    if not users and not domains:
        return findings

    sid_to_name_map = {}
    for user in users:
        if user.get('ObjectIdentifier'):
            sid_to_name_map[user['ObjectIdentifier']] = user.get('Name', 'UNKNOWN')
    for group in groups:
        if group.get('ObjectIdentifier'):
            sid_to_name_map[group['ObjectIdentifier']] = group.get('Name', 'UNKNOWN')
    for computer in computers:
        if computer.get('ObjectIdentifier'):
            sid_to_name_map[computer['ObjectIdentifier']] = computer.get('Name', 'UNKNOWN')

    domain_sid = domains[0].get('ObjectIdentifier') if domains else None
    domain_name = domains[0].get('Name') if domains else "UNKNOWN_DOMAIN"

    # Create a set of high-value group SIDs specific to the discovered domain.
    domain_high_value_sids = {sid.replace("DOMAIN", domain_sid) for sid in HIGH_VALUE_GROUP_SIDS} if domain_sid else set()
    high_value_targets = {group.get('ObjectIdentifier') for group in groups if group.get('ObjectIdentifier') in domain_high_value_sids}

    high_value_user_sids = set()
    for user in users:
        user_fqdn = user.get('Name', 'UNKNOWN_USER')
        user_sid = user.get('ObjectIdentifier')

        if user.get('DontReqPreAuth', False):
            findings.append({
                "host": domain_name, "port": 88, "source_tool": "sharphound",
                "entity_type": "privilege_escalation", "name": "asreproastable_user", "version": None,
                "attributes": {"user": user_fqdn, "description": f"User {user_fqdn} does not require Kerberos pre-authentication."}
            })

        if user.get('HasSPN', False) and not user_fqdn.lower().endswith('krbtgt'):
            findings.append({
                "host": domain_name, "port": 88, "source_tool": "sharphound",
                "entity_type": "privilege_escalation", "name": "kerberoastable_user", "version": None,
                "attributes": {"user": user_fqdn, "description": f"User {user_fqdn} has a Service Principal Name and is likely Kerberoastable."}
            })

        if user.get('IsAdmin', False) and user_sid:
            high_value_user_sids.add(user_sid)
            findings.append({
                "host": domain_name, "port": None, "source_tool": "sharphound",
                "entity_type": "privilege_escalation", "name": "attractive_user_high_privileges", "version": None,
                "attributes": {"user": user_fqdn, "description": f"User {user_fqdn} has AdminCount=true, indicating high privileges."}
            })

    all_objects = users + groups + computers + domains
    for obj in all_objects:
        obj_sid = obj.get('ObjectIdentifier')
        obj_name = obj.get('Name', 'UNKNOWN_OBJECT')

        if obj.get('ObjectType') == 'Domain':
            user_dcsync_rights = {}
            for ace in obj.get('Aces', []):
                principal_sid = ace.get('PrincipalSID')
                right = ace.get('RightName')
                if principal_sid and right in DCSYNC_RIGHTS:
                    user_dcsync_rights.setdefault(principal_sid, set()).add(right)

            for principal_sid, rights in user_dcsync_rights.items():
                if rights.issuperset(DCSYNC_RIGHTS):
                    principal_name = sid_to_name_map.get(principal_sid, principal_sid)
                    findings.append({
                        "host": domain_name, "port": None, "source_tool": "sharphound",
                        "entity_type": "privilege_escalation", "name": "dcsync_rights_found", "version": None,
                        "attributes": {"user": principal_name, "description": f"'{principal_name}' has DCSync rights over the domain."}
                    })

        for ace in obj.get('Aces', []):
            principal_sid = ace.get('PrincipalSID')
            right = ace.get('RightName')
            if right in ["GenericWrite", "GenericAll"] and obj_sid in high_value_targets and principal_sid not in high_value_targets:
                principal_name = sid_to_name_map.get(principal_sid, principal_sid)
                findings.append({
                    "host": domain_name, "port": None, "source_tool": "sharphound",
                    "entity_type": "privilege_escalation", "name": "genericwrite_on_sensitive_group", "version": None,
                    "attributes": {"attacker": principal_name, "target": obj_name, "description": f"'{principal_name}' has {right} rights on the high-value group '{obj_name}'."}
                })

            if right in ACL_ABUSE_RIGHTS and principal_sid:
                principal_name = sid_to_name_map.get(principal_sid, principal_sid)
                findings.append({
                    "host": domain_name,
                    "port": None,
                    "source_tool": "sharphound",
                    "entity_type": "privilege_escalation",
                    "name": "acl_abuse_right_on_object",
                    "version": None,
                    "attributes": {
                        "attacker": principal_name,
                        "target": obj_name,
                        "right": right,
                        "description": f"'{principal_name}' has potential abuse right '{right}' on '{obj_name}'.",
                    },
                })

    for computer in computers:
        computer_name = computer.get('Name', 'UNKNOWN_COMPUTER')
        if computer.get('UnconstrainedDelegation', False):
            findings.append({
                "host": domain_name, "port": None, "source_tool": "sharphound",
                "entity_type": "privilege_escalation", "name": "unconstrained_delegation_enabled", "version": None,
                "attributes": {"computer": computer_name, "description": f"Computer '{computer_name}' has Unconstrained Delegation enabled."}
            })

        allowed_to_act = computer.get('AllowedToAct', []) or computer.get('AllowedToDelegate', [])
        if allowed_to_act:
            findings.append({
                "host": domain_name,
                "port": None,
                "source_tool": "sharphound",
                "entity_type": "privilege_escalation",
                "name": "resource_based_constrained_delegation_possible",
                "version": None,
                "attributes": {
                    "computer": computer_name,
                    "delegation_entries": allowed_to_act,
                    "description": f"Computer '{computer_name}' exposes delegation entries that may enable RBCD abuse.",
                },
            })

    for session in sessions:
        user_sid = session.get('UserSID')
        computer_sid = session.get('ComputerSID')
        if user_sid in high_value_user_sids:
            user_name = sid_to_name_map.get(user_sid, user_sid)
            computer_name = sid_to_name_map.get(computer_sid, computer_sid)
            findings.append({
                "host": domain_name, "port": None, "source_tool": "sharphound",
                "entity_type": "privilege_escalation",
                "name": "privileged_user_session_found",
                "version": None,
                "attributes": {"user": user_name, "computer": computer_name, "description": f"High-privilege user '{user_name}' has an active session on '{computer_name}'."}
            })

    return findings
