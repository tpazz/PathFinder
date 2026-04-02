import json


def _iter_collection(data, key):
    """Iterate over an enum4linux-ng collection that may be a list or dict-of-dicts."""
    collection = data.get(key, [])
    if isinstance(collection, dict):
        yield from collection.values()
    elif isinstance(collection, list):
        yield from collection


def _get_user_name(user_obj):
    """Extract username from enum4linux-ng user object (handles both formats)."""
    return user_obj.get('username') or user_obj.get('name') or 'UNKNOWN_USER'


def _get_group_name(group_obj):
    """Extract group name from enum4linux-ng group object (handles both formats)."""
    return group_obj.get('groupname') or group_obj.get('name') or 'UNKNOWN_GROUP'


def parse_enum4linux_json(json_file_path, target_host):
    """
    Parses enum4linux-ng JSON output.

    Handles both the real enum4linux-ng format (dict-of-dicts keyed by RID,
    field names like 'username'/'groupname', OS at 'os_info', policy at 'policy')
    and simplified list-of-dicts formats.

    Args:
        json_file_path (str): Path to the enum4linux-ng JSON output file.
        target_host (str): The IP address of the target, as it's not in the JSON.

    Returns:
        list: A list of finding dictionaries.
    """
    findings = []
    try:
        with open(json_file_path, 'r', encoding='utf-8-sig') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"[!] Error: enum4linux-ng JSON file not found at {json_file_path}")
        return findings
    except json.JSONDecodeError:
        print(f"[!] Error: Could not decode JSON from '{json_file_path}'.")
        return findings

    # Extract user accounts discovered via RPC.
    for user in _iter_collection(data, 'users'):
        if not isinstance(user, dict):
            continue
        findings.append({
            "host": target_host, "port": 445, "source_tool": "enum4linux-ng",
            "entity_type": "user", "name": _get_user_name(user), "version": None,
            "attributes": {"rid": user.get('rid')}
        })

    # Extract group memberships.
    for group in _iter_collection(data, 'groups'):
        if not isinstance(group, dict):
            continue
        findings.append({
            "host": target_host, "port": 445, "source_tool": "enum4linux-ng",
            "entity_type": "group", "name": _get_group_name(group), "version": None,
            "attributes": {"rid": group.get('rid')}
        })

    # Extract available SMB shares.
    for share in _iter_collection(data, 'shares'):
        if not isinstance(share, dict):
            continue
        findings.append({
            "host": target_host, "port": 445, "source_tool": "enum4linux-ng",
            "entity_type": "share", "name": share.get('name') or 'UNKNOWN_SHARE', "version": None,
            "attributes": {"comment": share.get('comment'), "type": share.get('type')}
        })

    # Extract the domain password policy (supports both 'policy' and 'passpol' keys).
    passpol = data.get('policy') or data.get('passpol')
    if passpol:
        # Real enum4linux-ng nests policy under 'domain_password_information'.
        if isinstance(passpol, dict) and 'domain_password_information' in passpol:
            passpol = passpol['domain_password_information']
        findings.append({
            "host": target_host, "port": 445, "source_tool": "enum4linux-ng",
            "entity_type": "misconfiguration", "name": "password_policy_details", "version": None,
            "attributes": passpol if isinstance(passpol, dict) else {}
        })

    # Extract detailed OS information (supports both 'os_info' and 'osinfo' keys).
    os_info = data.get('os_info') or data.get('osinfo')
    if os_info and isinstance(os_info, dict):
        # Handle real format ('OS', 'OS version') and simplified ('os_name', 'os_version').
        os_name_part = os_info.get('OS') or os_info.get('os_name') or ''
        os_ver_part = os_info.get('OS version') or os_info.get('os_version') or ''
        os_name = f"{os_name_part} {os_ver_part}".strip() or "Unknown OS"
        findings.append({
            "host": target_host, "port": None, "source_tool": "enum4linux-ng",
            "entity_type": "os_details", "name": os_name, "version": None,
            "attributes": os_info
        })

    return findings
