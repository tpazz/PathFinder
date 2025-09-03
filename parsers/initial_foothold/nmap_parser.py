import xml.etree.ElementTree as ET
import re

def normalize_product_name(product_name):
    """
    Attempts to standardize common software product names for consistent rule matching.
    """
    if not product_name:
        return None
    name = product_name.lower()
    if "apache httpd" in name or "apache" == name:
        return "Apache HTTP Server"
    if "vsftpd" in name:
        return "vsftpd"
    if "openssh" in name:
        return "OpenSSH"
    if "microsoft iis httpd" in name or "microsoft-iis" in name:
        return "Microsoft IIS"
    if "nginx" in name:
        return "nginx"
    # Return the original name if no specific normalization rule exists.
    return product_name

def parse_nmap_xml(xml_file_path):
    """
    Parses Nmap XML output and extracts findings into the standard Pathfinder format.

    Args:
        xml_file_path (str): Path to the Nmap XML file.

    Returns:
        list: A list of finding dictionaries.
    """
    findings = []
    try:
        tree = ET.parse(xml_file_path)
        root = tree.getroot()
    except ET.ParseError as e:
        print(f"Error parsing XML file: {e}")
        return findings
    except FileNotFoundError:
        print(f"Error: XML file not found at {xml_file_path}")
        return findings

    # Iterate through each <host> tag in the XML file.
    for host_node in root.findall('host'):
        host_ip = None
        # Find the IPv4 address for the host.
        addresses = host_node.find('address')
        if addresses is not None and addresses.get('addrtype') == 'ipv4':
            host_ip = addresses.get('addr')
        
        # Fallback for cases where the address is in a different structure.
        if not host_ip:
            for addr_node in host_node.findall('address'):
                if addr_node.get('addrtype') == 'ipv4':
                    host_ip = addr_node.get('addr')
                    break
        if not host_ip:
            continue # Skip this host if no IPv4 address can be found.

        # Extract OS Detection details from -A or -O scans.
        os_node = host_node.find('os')
        if os_node is not None:
            # Take the best OS match (usually the one with 100% accuracy).
            for osmatch_node in os_node.findall('osmatch'):
                if osmatch_node.get('accuracy', '0') == '100':
                    findings.append({
                        "host": host_ip,
                        "port": None, # OS is a host-level finding, not tied to a port.
                        "source_tool": "nmap",
                        "entity_type": "os_details",
                        "name": osmatch_node.get('name'),
                        "version": None,
                        "attributes": {
                            "accuracy": osmatch_node.get('accuracy'),
                            "os_family": osmatch_node.find('osclass').get('osfamily') if osmatch_node.find('osclass') is not None else None,
                        }
                    })
                    break # Only take the first, best guess for simplicity.

        ports_node = host_node.find('ports')
        if ports_node is None:
            continue

        # Iterate through each <port> tag for the current host.
        for port_node in ports_node.findall('port'):
            port_id = int(port_node.get('portid'))

            # We are only interested in ports that Nmap confirmed are open.
            state_node = port_node.find('state')
            if state_node is None or state_node.get('state') != 'open':
                continue

            # Extract service and version information from -sV scans.
            service_node = port_node.find('service')
            if service_node is not None:
                product = service_node.get('product')
                version = service_node.get('version')
                extrainfo = service_node.get('extrainfo', '')
                service_name = service_node.get('name', 'unknown')

                # Create a finding for the general service type (e.g., http, ftp).
                findings.append({
                    "host": host_ip,
                    "port": port_id,
                    "source_tool": "nmap",
                    "entity_type": "service",
                    "name": service_name,
                    "version": None,
                    "attributes": {
                        "protocol": port_node.get('protocol'),
                    }
                })

                # If a specific product was identified, create a separate, more detailed finding.
                if product:
                    normalized_product_name = normalize_product_name(product)
                    banner_parts = [p for p in [product, version, extrainfo] if p]
                    banner_extract = " ".join(banner_parts)

                    findings.append({
                        "host": host_ip,
                        "port": port_id,
                        "source_tool": "nmap",
                        "entity_type": "software_product",
                        "name": normalized_product_name,
                        "version": version if version else None,
                        "attributes": {
                            "banner_extract": banner_extract if banner_extract else None,
                            "service_name_on_port": service_name,
                        }
                    })

            # Extract findings from Nmap Scripting Engine (NSE) outputs.
            for script_node in port_node.findall('script'):
                script_id = script_node.get('id')
                script_output = script_node.get('output')

                if script_id and script_output:
                    # Default classification is 'information_leak'.
                    entity_type = "information_leak"
                    name = script_id
                    
                    # Heuristic to classify script output based on its name (ID).
                    if "vuln" in script_id.lower() or "exploit" in script_id.lower() or \
                       re.search(r'CVE-\d{4}-\d{4,}', script_output, re.IGNORECASE):
                        entity_type = "vulnerability"
                        # If a CVE is mentioned, use it as the finding name for clarity.
                        cve_match = re.search(r'(CVE-\d{4}-\d{4,})', script_output, re.IGNORECASE)
                        if cve_match:
                            name = cve_match.group(1).upper()
                    elif any(kw in script_id.lower() for kw in ["default", "creds", "anon", "login", "enum"]):
                        # Scripts related to auth or enumeration are often misconfigurations.
                        if "anon" in script_id.lower() or "default" in script_id.lower():
                             entity_type = "misconfiguration"
                        
                    findings.append({
                        "host": host_ip,
                        "port": port_id,
                        "source_tool": "nmap",
                        "entity_type": entity_type,
                        "name": name,
                        "version": None,
                        "attributes": {
                            "script_id": script_id,
                            "script_output": script_output.strip()
                        }
                    })
    return findings