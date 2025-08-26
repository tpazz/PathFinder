import json

def parse_enum4linux_json(json_file_path, target_host):
    """
    Parses enum4linux-ng JSON output.

    Args:
        json_file_path (str): Path to the enum4linux-ng JSON output file.
        target_host (str): The IP address of the target, as it's not in the JSON.

    Returns:
        list: A list of finding dictionaries.
    """
    findings = []
    try:
        with open(json_file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"[!] Error: enum4linux-ng JSON file not found at {json_file_path}")
        return findings
    except json.JSONDecodeError:
        print(f"[!] Error: Could not decode JSON from '{json_file_path}'.")
        return findings

    # Users
    for user in data.get('users', []):
        findings.append({
            "host": target_host, "port": 445, "source_tool": "enum4linux-ng",
            "entity_type": "user", "name": user.get('name'), "version": None,
            "attributes": {"rid": user.get('rid')}
        })
    
    # Groups
    for group in data.get('groups', []):
        findings.append({
            "host": target_host, "port": 445, "source_tool": "enum4linux-ng",
            "entity_type": "group", "name": group.get('name'), "version": None,
            "attributes": {"rid": group.get('rid')}
        })

    # Shares
    for share in data.get('shares', []):
        # We can try to infer permissions if available in future versions
        findings.append({
            "host": target_host, "port": 445, "source_tool": "enum4linux-ng",
            "entity_type": "share", "name": share.get('name'), "version": None,
            "attributes": {"comment": share.get('comment'), "type": share.get('type')}
        })
        
    # Password Policy
    passpol = data.get('passpol')
    if passpol:
        findings.append({
            "host": target_host, "port": 445, "source_tool": "enum4linux-ng",
            "entity_type": "misconfiguration", "name": "password_policy_details", "version": None,
            "attributes": passpol # Dump the whole policy into attributes
        })
        
    # OS Info
    os_info = data.get('osinfo')
    if os_info:
        os_name = f"{os_info.get('os_name', '')} {os_info.get('os_version', '')}".strip()
        findings.append({
            "host": target_host, "port": None, "source_tool": "enum4linux-ng",
            "entity_type": "os_details", "name": os_name, "version": None,
            "attributes": os_info
        })
        
    return findings