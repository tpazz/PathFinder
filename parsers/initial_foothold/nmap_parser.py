import xml.etree.ElementTree as ET
import re

def normalize_product_name(product_name):
    """
    Basic normalization for product names.
    Can be expanded significantly.
    """
    if not product_name:
        return None
    name = product_name.lower()
    if "apache httpd" in name or "apache" == name: # "apache" is often the service name, product "Apache httpd"
        return "Apache HTTP Server"
    if "vsftpd" in name:
        return "vsftpd"
    if "openssh" in name:
        return "OpenSSH"
    if "microsoft iis httpd" in name or "microsoft-iis" in name:
        return "Microsoft IIS"
    if "nginx" in name:
        return "nginx"
    # Add more normalizations as needed
    return product_name # Return original if no specific normalization rule

def parse_nmap_xml(xml_file_path):
    """
    Parses Nmap XML output and extracts findings into the specified format.

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

    for host_node in root.findall('host'):
        host_ip = None
        addresses = host_node.find('address')
        if addresses is not None and addresses.get('addrtype') == 'ipv4':
            host_ip = addresses.get('addr')
        
        # Fallback if primary address tag not found (less common for IPv4)
        if not host_ip:
            for addr_node in host_node.findall('address'):
                if addr_node.get('addrtype') == 'ipv4':
                    host_ip = addr_node.get('addr')
                    break
        if not host_ip:
            continue # Skip host if no IPv4 address found

        # OS Detection (-A or -O)
        os_node = host_node.find('os')
        if os_node is not None:
            for osmatch_node in os_node.findall('osmatch'):
                if osmatch_node.get('accuracy', '0') == '100': # Often multiple, take best guess
                    findings.append({
                        "host": host_ip,
                        "port": None, # OS is host-level
                        "source_tool": "nmap",
                        "entity_type": "os_details",
                        "name": osmatch_node.get('name'),
                        "version": None, # OS version might be in 'name' or an osclass
                        "attributes": {
                            "accuracy": osmatch_node.get('accuracy'),
                            "os_family": osmatch_node.find('osclass').get('osfamily') if osmatch_node.find('osclass') is not None else None,
                            "os_gen": osmatch_node.find('osclass').get('osgen') if osmatch_node.find('osclass') is not None else None,
                        }
                    })
                    break # Take the first best guess for simplicity

        ports_node = host_node.find('ports')
        if ports_node is None:
            continue

        for port_node in ports_node.findall('port'):
            port_id_str = port_node.get('portid')
            if not port_id_str:
                continue
            port_id = int(port_id_str)

            state_node = port_node.find('state')
            if state_node is None or state_node.get('state') != 'open':
                continue # Only interested in open ports

            service_node = port_node.find('service')
            if service_node is not None:
                product = service_node.get('product')
                version = service_node.get('version')
                extrainfo = service_node.get('extrainfo', '')
                service_name = service_node.get('name', 'unknown') # e.g. http, ftp

                # Finding for the general service
                findings.append({
                    "host": host_ip,
                    "port": port_id,
                    "source_tool": "nmap",
                    "entity_type": "service",
                    "name": service_name,
                    "version": None, # Version is for the product, not the service protocol
                    "attributes": {
                        "protocol": port_node.get('protocol'),
                        "product_raw": product, # Keep raw product for context if needed
                        "version_raw": version,
                        "extrainfo": extrainfo,
                        "ostype_service": service_node.get('ostype'), # OS type guessed by service
                        "method": service_node.get('method'),
                        "conf": service_node.get('conf')
                    }
                })

                # Finding for the specific software product
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
                            "service_name_on_port": service_name, # e.g. http, ftp
                             "raw_product": product, # Store original product name for reference
                             "raw_version": version, # Store original version for reference
                             "raw_extrainfo": extrainfo
                        }
                    })

            # Script outputs (-sC, --script=vuln, also part of -A)
            for script_node in port_node.findall('script'):
                script_id = script_node.get('id')
                script_output = script_node.get('output')

                if script_id and script_output:
                    entity_type = "information_leak" # Default
                    name = script_id # Default name
                    
                    # Basic heuristic for script type classification
                    if "vuln" in script_id.lower() or "exploit" in script_id.lower() or \
                       re.search(r'CVE-\d{4}-\d{4,}', script_output, re.IGNORECASE):
                        entity_type = "vulnerability"
                        # Try to extract CVE if possible as a name
                        cve_match = re.search(r'(CVE-\d{4}-\d{4,})', script_output, re.IGNORECASE)
                        if cve_match:
                            name = cve_match.group(1).upper()
                        else:
                            name = script_id # fallback to script_id
                    elif any(kw in script_id.lower() for kw in ["default", "creds", "anon", "login", "enum", "info"]):
                        # Could be misconfig or info leak, depends on script
                        if "anon" in script_id.lower() or "default" in script_id.lower():
                             entity_type = "misconfiguration"
                        # More specific checks can be added here
                        
                    findings.append({
                        "host": host_ip,
                        "port": port_id,
                        "source_tool": "nmap",
                        "entity_type": entity_type,
                        "name": name,
                        "version": None, # Typically not applicable for script findings directly
                        "attributes": {
                            "script_id": script_id,
                            "script_output": script_output.strip()
                        }
                    })
    return findings

# --- Example Usage (save this script as nmap_parser.py) ---
if __name__ == '__main__':
    # Create a dummy nmap_results.xml for testing
    # You should replace this with an actual Nmap XML output file
    test_xml_content = """
    <nmaprun scanner="nmap" args="nmap -sV -A -oX test_nmap.xml 127.0.0.1" start="1678886400" version="7.92" xmloutputversion="1.05">
      <host starttime="1678886401" endtime="1678886405">
        <status state="up" reason="localhost-response" reason_ttl="0"/>
        <address addr="127.0.0.1" addrtype="ipv4"/>
        <hostnames>
          <hostname name="localhost" type="PTR"/>
        </hostnames>
        <ports>
          <port protocol="tcp" portid="21">
            <state state="open" reason="syn-ack" reason_ttl="0"/>
            <service name="ftp" product="vsftpd" version="3.0.3" method="probed" conf="10"/>
            <script id="ftp-anon" output="Anonymous FTP login allowed (FTP code 230)"/>
          </port>
          <port protocol="tcp" portid="80">
            <state state="open" reason="syn-ack" reason_ttl="0"/>
            <service name="http" product="Apache httpd" version="2.4.41" extrainfo="(Ubuntu)" method="probed" conf="10">
              <cpe>cpe:/a:apache:http_server:2.4.41</cpe>
            </service>
            <script id="http-title" output="Apache2 Ubuntu Default Page: It works"/>
            <script id="http-vuln-cve2017-5638" output="State: VULNERABLE - Apache Struts2 S2-045"/>
          </port>
           <port protocol="tcp" portid="22">
            <state state="open" reason="syn-ack" reason_ttl="0"/>
            <service name="ssh" product="OpenSSH" version="8.2p1 Ubuntu 4ubuntu0.3" extrainfo="Ubuntu Linux; protocol 2.0" ostype="Linux" method="probed" conf="10">
              <cpe>cpe:/a:openbsd:openssh:8.2p1</cpe>
              <cpe>cpe:/o:linux:linux_kernel</cpe>
            </service>
          </port>
        </ports>
        <os>
          <portused state="open" proto="tcp" portid="22"/>
          <osmatch name="Linux 5.4 - 5.10" accuracy="100" line="62356">
            <osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="5.X" accuracy="100"/>
          </osmatch>
        </os>
        <times srtt="162" rttvar="50" to="100000"/>
      </host>
    </nmaprun>
    """
    test_xml_file = "test_nmap_output.xml"
    with open(test_xml_file, "w") as f:
        f.write(test_xml_content)

    parsed_findings = parse_nmap_xml(test_xml_file)
    if parsed_findings:
        print(f"Found {len(parsed_findings)} findings:\n")
        for i, finding in enumerate(parsed_findings):
            print(f"--- Finding {i+1} ---")
            for key, value in finding.items():
                if key == "attributes":
                    print(f"  {key}:")
                    for a_key, a_value in value.items():
                        print(f"    {a_key}: {a_value}")
                else:
                    print(f"  {key}: {value}")
            print("")
    else:
        print("No findings extracted.")

    # Clean up dummy file (optional)
    # import os
    # os.remove(test_xml_file)