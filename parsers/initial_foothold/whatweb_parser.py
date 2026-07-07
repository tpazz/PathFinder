import json
from parsers.ansi import warn
from urllib.parse import urlparse

# A list of WhatWeb plugins that are purely informational (like HTTP headers)
# and do not represent a distinct software product. We filter these out to reduce noise.
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
        with open(json_file_path, 'r', encoding='utf-8-sig') as f:
            data = json.load(f)
    except FileNotFoundError:
        warn(f"[!] Error: WhatWeb JSON file not found at {json_file_path}")
        return findings
    except json.JSONDecodeError:
        warn(f"[!] Error: Could not decode JSON from '{json_file_path}'.")
        return findings

    if isinstance(data, dict):
        data = [data]
    elif not isinstance(data, list):
        return findings

    # The WhatWeb JSON output is usually a list of results, one for each target scanned.
    for target_result in data:
        try:
            # Parse the target URL to reliably extract the hostname and port.
            parsed_url = urlparse(target_result.get('target', ''))
            host = parsed_url.hostname
            port = parsed_url.port
            # If a port is not specified in the URL, infer the default based on the scheme (http/https).
            if not port:
                if parsed_url.scheme == 'https':
                    port = 443
                else:
                    port = 80
            if not host:
                continue
        except (ValueError, AttributeError):
            continue # Skip this target if the URL is malformed.

        # Iterate through all the plugins that WhatWeb identified for the target.
        for plugin_name, plugin_data in target_result.get("plugins", {}).items():
            # Skip any plugins that are on our ignore list.
            if plugin_name in PLUGINS_TO_IGNORE:
                continue

            # WhatWeb's version field is often a list; preserve all candidates while keeping primary version.
            version_candidates = plugin_data.get("version", [None])
            if not isinstance(version_candidates, list):
                version_candidates = [version_candidates]
            version = version_candidates[0] if version_candidates else None

            # Create a clean attributes dictionary, dumping all other plugin data into it.
            # We remove 'version' since it's already a top-level key in our finding object.
            attributes = {k: v for k, v in plugin_data.items() if k != 'version'}
            if version_candidates and version_candidates != [None]:
                attributes['version_candidates'] = version_candidates

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
