import re
from urllib.parse import urlparse

def parse_sqlmap_log(file_path):
    """
    Parses a sqlmap log file to find confirmed injectable parameters.

    Args:
        file_path (str): Path to the sqlmap 'log' file.

    Returns:
        list: A list of 'vulnerability' finding dictionaries for each injectable parameter.
    """
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"[!] Error: sqlmap log file not found at {file_path}")
        return findings
    except Exception as e:
        print(f"[!] An unexpected error occurred while parsing sqlmap log: {e}")
        return []

    # Regex to find all confirmed vulnerable parameters. Captures method, name, and position.
    # Example: "[INFO] GET parameter 'id' is vulnerable"
    vuln_pattern = re.compile(r"\[INFO\] (GET|POST|URI|HEADER) parameter '([^']+)' is vulnerable")
    
    # Find the target URL, usually one of the first lines
    target_url_match = re.search(r"\[INFO\] testing '(\S+)'", content)
    target_url = target_url_match.group(1) if target_url_match else "http://UNKNOWN_HOST"

    # Find the identified DBMS
    dbms_match = re.search(r"back-end DBMS is '([^']+)'", content)
    dbms = dbms_match.group(1) if dbms_match else None
    
    # Find the identified injection technique
    technique_match = re.search(r"following injection techniques are supported: (.*)", content)
    technique = technique_match.group(1) if technique_match else None

    vulnerable_params = vuln_pattern.findall(content)

    for method, parameter_name in vulnerable_params:
        try:
            parsed_url = urlparse(target_url)
            host = parsed_url.hostname
            port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
        except (ValueError, AttributeError):
            host = "UNKNOWN_HOST"
            port = 0

        findings.append({
            "host": host,
            "port": port,
            "source_tool": "sqlmap",
            "entity_type": "vulnerability",
            "name": "sql_injection_found",
            "version": None,
            "attributes": {
                "url": target_url,
                "parameter": parameter_name,
                "method": method,
                "dbms": dbms,
                "technique": technique,
                "description": f"SQL Injection confirmed in '{parameter_name}' parameter via {method} request."
            }
        })

    return findings