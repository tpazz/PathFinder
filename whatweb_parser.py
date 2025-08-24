import json
from urllib.parse import urlparse

# A list of whatweb plugins that are informational and not a 'software_product'
PLUGINS_TO_IGNORE = [
    'HTTPServer', 'HttpOnly', 'Strict-Transport-Security', 'X-Frame-Options',
    'X-XSS-Protection', 'X-Content-Type-Options', 'Country', 'IP', 'Cookies',
    'RedirectLocation', 'Password-Field', 'Meta-Author', 'Frame'
]

def parse_whatweb_json(json_file_path):
    """
    Parses WhatWeb JSON output and extracts findings into the Pathfinder format.

    Args:
        json_file_path (str): Path to the WhatWeb JSON output file.

    Returns:
        list: A list of finding dictionaries.
    """
    findings = []
    try:
        with open(json_file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"[!] Error: WhatWeb JSON file not found at {json_file_path}")
        return findings
    except json.JSONDecodeError:
        print(f"[!] Error: Could not decode JSON from '{json_file_path}'.")
        return findings

    for target_result in data:
        try:
            parsed_url = urlparse(target_result.get('target', ''))
            host = parsed_url.hostname
            port = parsed_url.port
            # Handle default ports if not specified in the URL
            if not port:
                if parsed_url.scheme == 'https':
                    port = 443
                else:
                    port = 80
            if not host:
                continue
        except (ValueError, AttributeError):
            continue # Skip if the target URL is malformed

        for plugin_name, plugin_data in target_result.get("plugins", {}).items():
            if plugin_name in PLUGINS_TO_IGNORE:
                continue

            # WhatWeb version is often a list, take the first one.
            version = plugin_data.get("version", [None])[0]

            # Create a clean attributes dictionary, removing version if we already have it
            attributes = {k: v for k, v in plugin_data.items() if k != 'version'}

            finding = {
                "host": host,
                "port": port,
                "source_tool": "whatweb",
                "entity_type": "software_product",
                "name": plugin_name,
                "version": version,
                "attributes": attributes
            }
            findings.append(finding)
    
    return findings