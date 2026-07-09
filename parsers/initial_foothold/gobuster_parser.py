import re

from parsers.ansi import ANSI_ESCAPE_PATTERN, warn
from parsers.initial_foothold.web_url_helpers import parameterized_url_finding


def parse_gobuster_output(gobuster_output_file, target_host, target_port=None, mode='dir'):
    """
    Parses Gobuster output and extracts findings into the specified format.
    This parser's role is to extract facts (path, status, etc.), not to interpret their meaning.
    Interpretation is handled by the VulnerabilityMapper.

    Args:
        gobuster_output_file (str): Path to the Gobuster output text file.
        target_host (str): The target host/IP Gobuster was run against.
        target_port (int, optional): The target port. Defaults to 80 for dir mode, 443 for vhost.
        mode (str): The Gobuster mode used (e.g., 'dir', 'vhost').

    Returns:
        list: A list of finding dictionaries.
    """
    if target_port is None:
        target_port = 80
    findings = []
    seen_identifiers = set()
    
    # Regex for 'dir' mode, captures path, status, and optional size/redirect.
    # Accepts common variants such as:
    #   /images (Status: 301) [Size: 0] --> /images/
    #   /images [Status: 301] [Size: 0]
    #   /images Status: 301 Size: 0
    #   images (Status: 301) [Size: 327] [--> http://target/app/images/]
    dir_pattern = re.compile(
        r"^(?P<path>(?:/)?[^\s\[\(]+)"   # Path (e.g., /images or images)
        r"\s*"                           # Whitespace
        r"(?:\((?:Status:\s*(?P<status_paren>\d{3}))\)|\[(?:Status:\s*(?P<status_bracket>\d{3}))\]|Status:\s*(?P<status_plain>\d{3}))"
        r"(?:\s*(?:\[Size:\s*(?P<size_bracket>\d+)\]|Size:\s*(?P<size_plain>\d+)))?"  # Optional Size
        r"(?:\s*(?:\[\s*-->\s*(?P<redirect_url_bracket>[^\]\s]+)\s*\]|-->\s*(?P<redirect_url_plain>[^\s]+)))?" # Optional Redirect URL
    )

    # Regex for 'vhost' mode. Example: Found: admin.example.com (Status: 200)
    vhost_pattern = re.compile(
        r"Found:\s*(?P<vhost>[^\s\(]+)"
        r"(?:\s*(?:\((?:Status:\s*(?P<status_paren>\d{3}))\)|\[(?:Status:\s*(?P<status_bracket>\d{3}))\]|Status:\s*(?P<status_plain>\d{3})))?",
        re.IGNORECASE,
    )

    try:
        with open(gobuster_output_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line_content in f:
                
                # First, strip potential ANSI codes from the raw line to ensure clean parsing.
                sanitized_line_content = ANSI_ESCAPE_PATTERN.sub('', line_content)
                
                # Then, strip leading/trailing whitespace from the sanitized line.
                line = sanitized_line_content.strip()

                # Comprehensive skipping logic for Gobuster's header, footer, and progress lines.
                if (not line or
                        line.startswith("#") or
                        line.startswith("Gobuster v") or
                        line.startswith("===") or
                        line.startswith("[+]") or
                        (line.startswith("-->") and not (line.startswith("/") or line.startswith("http"))) or
                        "Progress:" in line or
                        "Finished" in line or
                        "Timeout:" in line or
                        "Starting gobuster" in line or
                        "Use gobuster -h for list" in line or
                        "by OJ Reeves" in line):
                    continue
                
                if mode == 'dir':
                    match = dir_pattern.match(line)
                    if match:
                        data = match.groupdict()
                        path = data['path']
                        if not path.startswith('/'):
                            path = f"/{path}"
                        status_raw = data.get('status_paren') or data.get('status_bracket') or data.get('status_plain')
                        status_code = int(status_raw)
                        size_raw = data.get('size_bracket') or data.get('size_plain')
                        size = int(size_raw) if size_raw else None
                        redirect_url = data.get('redirect_url_bracket') or data.get('redirect_url_plain')

                        attributes = {
                            "status_code": status_code,
                            # Store the original, potentially colored line for true raw data.
                            "raw_line": line_content.rstrip('\n\r')
                        }
                        if size is not None:
                            attributes["size_bytes"] = size
                        if redirect_url:
                            attributes["redirect_url"] = redirect_url
                        
                        # Heuristic to guess if a path is a directory, which aids the VulnerabilityMapper.
                        is_directory_guess = False
                        if path.endswith('/'):
                            is_directory_guess = True
                        elif redirect_url and redirect_url.endswith('/') and redirect_url.startswith(path):
                            is_directory_guess = True
                        # A path with no file extension is often a directory.
                        elif '.' not in path.split('/')[-1] and not any(vcs in path for vcs in ['/.git', '/.svn', '/.hg']):
                             if status_code in [200, 301, 302, 307, 308, 401, 403]:
                                is_directory_guess = True
                        
                        attributes["is_directory_guess"] = is_directory_guess

                        identifier = (target_host, target_port, "web_content", path, status_code)
                        if identifier not in seen_identifiers:
                            seen_identifiers.add(identifier)
                            findings.append({
                                "host": target_host,
                                "port": target_port,
                                "source_tool": "gobuster",
                                "entity_type": "web_content",
                                "name": path,
                                "version": None,
                                "attributes": attributes
                            })
                            param_finding = parameterized_url_finding(
                                target_host, target_port, "gobuster", path, path
                            )
                            if param_finding:
                                findings.append(param_finding)
                
                elif mode == 'vhost':
                    match = vhost_pattern.match(line)
                    if match:
                        data = match.groupdict()
                        vhost_name = data['vhost']
                        status_raw_vhost = data.get('status_paren') or data.get('status_bracket') or data.get('status_plain')
                        status_code_vhost = int(status_raw_vhost) if status_raw_vhost else None

                        attributes = {"raw_line": line_content.rstrip('\n\r')}
                        if status_code_vhost:
                            attributes["status_code"] = status_code_vhost

                        identifier = (target_host, target_port, "virtual_host", vhost_name, status_code_vhost)
                        if identifier not in seen_identifiers:
                            seen_identifiers.add(identifier)
                            findings.append({
                                "host": target_host,
                                "port": target_port,
                                "source_tool": "gobuster",
                                "entity_type": "virtual_host",
                                "name": vhost_name,
                                "version": None,
                                "attributes": attributes
                            })
    
    except FileNotFoundError:
        warn(f"[!] Error: Gobuster output file not found at {gobuster_output_file}")
    except Exception as e:
        warn(f"[!] An error occurred while parsing Gobuster output: {e}")
        
    return findings
