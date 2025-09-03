import re

# Regex to find and remove ANSI escape codes for colors/styles from raw terminal output.
ANSI_ESCAPE_PATTERN = re.compile(r'\x1b\[[0-9;]*m')


def parse_gobuster_output(gobuster_output_file, target_host, target_port=None, mode='dir'):
    """
    Parses Gobuster output and extracts findings into the specified format.
    This parser's role is to extract facts (path, status, etc.), not to interpret their meaning.
    Interpretation is handled by the VulnerabilityMapper.

    Args:
        gobuster_output_file (str): Path to the Gobuster output text file.
        target_host (str): The target host/IP Gobuster was run against.
        target_port (int, optional): The target port.
        mode (str): The Gobuster mode used (e.g., 'dir', 'vhost').

    Returns:
        list: A list of finding dictionaries.
    """
    findings = []
    
    # Regex for 'dir' mode, captures path, status, and optional size/redirect.
    # Example: /images (Status: 301) [Size: 0] --> /images/
    dir_pattern = re.compile(
        r"^(?P<path>/[^\s\(]+)"          # Path (e.g., /images)
        r"\s*"                           # Whitespace
        r"\(Status:\s*(?P<status>\d{3})\)" # Status code (e.g., 301)
        r"(?:\s*\[Size:\s*(?P<size>\d+)\])?"  # Optional Size (e.g., 0)
        r"(?:\s*-->\s*(?P<redirect_url>[^\s]+))?" # Optional Redirect URL (e.g., /images/)
    )

    # Regex for 'vhost' mode. Example: Found: admin.example.com (Status: 200)
    vhost_pattern = re.compile(r"Found:\s*(?P<vhost>[^\s\(]+)(?:\s*\(Status:\s*(?P<status>\d{3})\))?")

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
                        status_code = int(data['status'])
                        size = int(data['size']) if data['size'] else None
                        redirect_url = data['redirect_url'] if data['redirect_url'] else None

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

                        findings.append({
                            "host": target_host,
                            "port": target_port,
                            "source_tool": "gobuster",
                            "entity_type": "web_content",
                            "name": path,
                            "version": None,
                            "attributes": attributes
                        })
                
                elif mode == 'vhost':
                    match = vhost_pattern.match(line)
                    if match:
                        data = match.groupdict()
                        vhost_name = data['vhost']
                        status_code_vhost = int(data['status']) if data['status'] else None

                        attributes = {"raw_line": line_content.rstrip('\n\r')}
                        if status_code_vhost:
                            attributes["status_code"] = status_code_vhost

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
        print(f"[!] Error: Gobuster output file not found at {gobuster_output_file}")
    except Exception as e:
        print(f"[!] An error occurred while parsing Gobuster output: {e}")
        
    return findings