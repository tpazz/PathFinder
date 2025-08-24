import re

def parse_snmp_output(file_path, target_host):
    """
    Parses the output of snmp-check to find interesting information.

    Args:
        file_path (str): Path to the snmp-check output text file.
        target_host (str): The IP of the target host.

    Returns:
        list: A list of finding dictionaries.
    """
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"[!] Error: SNMP output file not found at {file_path}")
        return findings
    except Exception as e:
        print(f"[!] An unexpected error occurred while parsing SNMP: {e}")
        return []

    # System Information
    sys_info_match = re.search(r"System information:\s*\n(.*?)\n\n", content, re.DOTALL)
    if sys_info_match:
        findings.append({
            "host": target_host, "port": 161, "source_tool": "snmp",
            "entity_type": "os_details",
            "name": "snmp_system_information",
            "version": None,
            "attributes": {"description": sys_info_match.group(1).strip()}
        })

    # User Accounts
    user_accounts_match = re.search(r"User accounts:\s*\n(.*?)\n\n", content, re.DOTALL)
    if user_accounts_match:
        for user_line in user_accounts_match.group(1).strip().split('\n'):
            findings.append({
                "host": target_host, "port": 161, "source_tool": "snmp",
                "entity_type": "user",
                "name": user_line.strip(),
                "version": None,
                "attributes": {"source": "SNMP enumeration"}
            })

    # Running Processes
    processes_match = re.search(r"Running processes:\s*\n(.*?)\n\n", content, re.DOTALL)
    if processes_match:
        for process_line in processes_match.group(1).strip().split('\n'):
            # Simple process name extraction, might need refinement
            process_name = process_line.strip().split()[-1]
            findings.append({
                "host": target_host, "port": 161, "source_tool": "snmp",
                "entity_type": "software_product",
                "name": process_name,
                "version": None,
                "attributes": {"description": process_line.strip(), "source": "SNMP enumeration"}
            })

    # Network Interfaces
    interfaces_match = re.search(r"Network interfaces:\s*\n(.*?)\n\n", content, re.DOTALL)
    if interfaces_match:
        # Just log this as a single info leak for now
        findings.append({
            "host": target_host, "port": 161, "source_tool": "snmp",
            "entity_type": "information_leak",
            "name": "snmp_network_interfaces_disclosed",
            "version": None,
            "attributes": {"details": interfaces_match.group(1).strip()}
        })
        
    return findings