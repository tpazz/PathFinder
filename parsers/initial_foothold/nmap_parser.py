import xml.etree.ElementTree as ET
import re
import json


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


def _extract_nse_structured_output(script_node):
    structured = []
    for table in script_node.findall('table'):
        row = {}
        for elem in table.findall('elem'):
            key = elem.get('key') or f"elem_{len(row)+1}"
            row[key] = (elem.text or '').strip()
        if row:
            structured.append(row)
    return structured


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
        # Prefer IPv4, fallback to first address.
        for addr_node in host_node.findall('address'):
            if addr_node.get('addrtype') == 'ipv4':
                host_ip = addr_node.get('addr')
                break
            if host_ip is None:
                host_ip = addr_node.get('addr')

        if not host_ip:
            continue

        # Extract OS Detection details from -A or -O scans.
        os_node = host_node.find('os')
        if os_node is not None:
            os_matches = os_node.findall('osmatch')
            if os_matches:
                # Choose best accuracy match, falling back if 100% doesn't exist.
                try:
                    best = max(os_matches, key=lambda n: int(n.get('accuracy', '0') or 0))
                except (ValueError, TypeError):
                    best = os_matches[0]
                osclass = best.find('osclass')
                findings.append({
                    "host": host_ip,
                    "port": None,
                    "source_tool": "nmap",
                    "entity_type": "os_details",
                    "name": best.get('name') or 'Unknown OS',
                    "version": None,
                    "attributes": {
                        "accuracy": best.get('accuracy'),
                        "confidence": "high" if best.get('accuracy') == '100' else "medium",
                        "os_family": osclass.get('osfamily') if osclass is not None else None,
                    }
                })

        ports_node = host_node.find('ports')
        if ports_node is None:
            continue

        # Iterate through each <port> tag for the current host.
        for port_node in ports_node.findall('port'):
            raw_port_id = port_node.get('portid')
            try:
                port_id = int(raw_port_id)
            except (TypeError, ValueError):
                continue

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
                cpe_values = [cpe.text for cpe in service_node.findall('cpe') if cpe.text]

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
                            "cpe": cpe_values or None,
                            # Raw banner product for exploit lookups (canonical name is for rules).
                            "search_name": product,
                        }
                    })

            # Extract findings from Nmap Scripting Engine (NSE) outputs.
            for script_node in port_node.findall('script'):
                script_id = script_node.get('id')
                script_output = script_node.get('output')
                structured_output = _extract_nse_structured_output(script_node)

                if script_id and (script_output or structured_output):
                    entity_type = "information_leak"
                    name = script_id
                    output_text = script_output or json.dumps(structured_output)

                    if "vuln" in script_id.lower() or "exploit" in script_id.lower() or \
                       re.search(r'CVE-\d{4}-\d{4,}', output_text, re.IGNORECASE):
                        entity_type = "vulnerability"
                        cve_match = re.search(r'(CVE-\d{4}-\d{4,})', output_text, re.IGNORECASE)
                        if cve_match:
                            name = cve_match.group(1).upper()
                    elif any(kw in script_id.lower() for kw in ["default", "creds", "anon", "login", "enum"]):
                        if "anon" in script_id.lower() or "default" in script_id.lower():
                            entity_type = "misconfiguration"

                    attributes = {
                        "script_id": script_id,
                        "script_output": output_text.strip() if isinstance(output_text, str) else output_text,
                    }
                    if structured_output:
                        attributes["structured_output"] = structured_output

                    findings.append({
                        "host": host_ip,
                        "port": port_id,
                        "source_tool": "nmap",
                        "entity_type": entity_type,
                        "name": name,
                        "version": None,
                        "attributes": attributes,
                    })
    return findings
