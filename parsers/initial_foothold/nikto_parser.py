import json
import re

def _classify_nikto_item(item):
    """
    Classifies a single Nikto vulnerability item into Pathfinder's entity types.
    This helper function contains the core logic for interpreting Nikto's text-based messages.

    Returns a tuple: (entity_type, name, version, additional_attributes)
    """
    msg = item.get('msg', '').lower()
    url = item.get('url', '')
    version = None
    
    # Priority 1: Explicitly identify a major software product like WordPress.
    if "wordpress" in msg:
        entity_type = "software_product"
        name = "WordPress"
        # Try to extract the version number from the message text.
        version_match = re.search(r'wordpress version ([\d\.]+)', msg)
        if version_match:
            version = version_match.group(1)
        return entity_type, name, version, {}
    
    # Sanitize the raw message to create a clean, snake_case name for the finding.
    sanitized_msg_name = re.sub(r'[^a-zA-Z0-9_]', '_', msg).strip('_')
    
    # Classify findings based on keywords in the message.
    if "is outdated" in msg or "appears to be outdated" in msg:
        entity_type = "vulnerability"
        name = "outdated_software_" + sanitized_msg_name
        return entity_type, name, version, {}

    if "directory indexing found" in msg:
        return "misconfiguration", "directory_indexing_found", version, {}
    if "header is not defined" in msg or "header is not set" in msg:
        name = "missing_header_" + sanitized_msg_name.replace('_header_is_not_defined', '')
        return "misconfiguration", name, version, {}
    # Check for dangerous HTTP methods being allowed.
    if "allowed http methods" in msg:
        name = "http_methods_revealed"
        if "PUT" in msg or "DELETE" in msg or "TRACE" in msg:
            return "misconfiguration", name, version, {"dangerous_methods_found": True}
        return "information_leak", name, version, {}

    if "a backup file was found" in msg or ".bak file found" in msg:
        return "web_content", url, version, {"potential_risk": "sensitive_backup_file"}
    if "robots.txt contains entries" in msg:
        return "web_content", "/robots.txt", version, {"potential_risk": "interesting_robots_txt"}
    if "/config" in url or "/.env" in url:
        return "web_content", url, version, {"potential_risk": "potential_config_or_credential_file"}
    if "apache default file found" in msg or "default file found" in msg:
        return "web_content", url, version, {"potential_risk": "default_framework_file"}
    
    # Catch generic "interesting file" findings from Nikto.
    if "might be interesting" in msg and url:
        return "web_content", url, version, {}

    # If no specific rule matches, classify it as a general information leak.
    return "information_leak", sanitized_msg_name, version, {}


def parse_nikto_json(json_file_path):
    """
    Parses Nikto JSON output (handling JSON Lines format) and extracts findings.
    """
    findings = []
    try:
        with open(json_file_path, 'r', encoding='utf-8') as f:
            # Nikto often outputs one JSON object per line (JSON Lines/NDJSON format).
            # This loop reads the file line-by-line to handle this correctly.
            for line in f:
                if not line.strip():
                    continue # Skip empty lines

                try:
                    # Use json.loads() to parse a single line (string).
                    data = json.loads(line)
                except json.JSONDecodeError:
                    print(f"[!] Warning: Skipping malformed JSON line in '{json_file_path}': {line[:100]}")
                    continue

                host = data.get('host')
                port = int(data.get('port'))
                
                # Iterate through the list of vulnerabilities found for the host.
                for item in data.get('vulnerabilities', []):
                    # Classify each item to determine its entity_type and name.
                    entity_type, name, version, additional_attributes = _classify_nikto_item(item)
                    
                    attributes = {
                        "nikto_id": item.get('id'),
                        "osvdb": item.get('osvdb'),
                        "method": item.get('method'),
                        "description": item.get('msg'),
                        "references": item.get('references'),
                        "url_path_nikto": item.get('url') # Store the specific URL path for context.
                    }
                    attributes.update(additional_attributes)

                    finding = {
                        "host": host,
                        "port": port,
                        "source_tool": "nikto",
                        "entity_type": entity_type,
                        "name": name,
                        "version": version,
                        "attributes": attributes
                    }
                    findings.append(finding)
            
    except FileNotFoundError:
        print(f"[!] Error: Nikto JSON file not found at {json_file_path}")
    except Exception as e:
        print(f"[!] An unexpected error occurred while parsing Nikto JSON: {e}")
        
    return findings