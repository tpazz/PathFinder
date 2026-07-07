import json
from parsers.ansi import warn
from urllib.parse import urlparse


def _result_path(result):
    """Derive the URL path (gobuster-style, leading slash) from an ffuf result."""
    url = result.get("url") or ""
    parsed = urlparse(url)
    path = parsed.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    return path


def _result_host_port(result):
    """Extract (host, port) from an ffuf result, preferring the full URL."""
    url = result.get("url") or ""
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port
    if not port:
        port = 443 if parsed.scheme == "https" else 80
    # Fall back to ffuf's "host" field (e.g. "10.10.10.10:80") if the URL lacked a host.
    if not host:
        raw_host = result.get("host") or ""
        if ":" in raw_host:
            host, _, raw_port = raw_host.partition(":")
            try:
                port = int(raw_port)
            except (ValueError, TypeError):
                pass
        elif raw_host:
            host = raw_host
    return host, port


def parse_ffuf_json(json_file_path):
    """
    Parses ffuf JSON output (ffuf -of json -o file) into web_content findings.

    The findings mirror the Gobuster parser's shape (status_code, size_bytes,
    redirect_url, is_directory_guess) so the VulnerabilityMapper's web scoring
    and the existing web attack-path rules apply unchanged.
    """
    findings = []
    try:
        with open(json_file_path, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
    except FileNotFoundError:
        warn(f"[!] Error: ffuf JSON file not found at {json_file_path}")
        return findings
    except json.JSONDecodeError:
        warn(f"[!] Error: Could not decode JSON from '{json_file_path}'.")
        return findings

    if not isinstance(data, dict):
        return findings

    seen = set()
    for result in data.get("results", []):
        if not isinstance(result, dict):
            continue

        host, port = _result_host_port(result)
        if not host:
            continue
        path = _result_path(result)

        try:
            status_code = int(result.get("status")) if result.get("status") is not None else None
        except (ValueError, TypeError):
            status_code = None

        redirect_url = result.get("redirectlocation") or None
        size = result.get("length")
        size = size if isinstance(size, int) else None

        # Same directory heuristic as the Gobuster parser.
        is_directory_guess = path.endswith("/")
        if not is_directory_guess and redirect_url and redirect_url.endswith("/") and redirect_url.startswith(path):
            is_directory_guess = True
        elif "." not in path.split("/")[-1] and not any(vcs in path for vcs in ["/.git", "/.svn", "/.hg"]):
            if status_code in [200, 301, 302, 307, 308, 401, 403]:
                is_directory_guess = True

        identifier = (host, port, path, status_code)
        if identifier in seen:
            continue
        seen.add(identifier)

        attributes = {"status_code": status_code, "fuzz_input": result.get("input")}
        if size is not None:
            attributes["size_bytes"] = size
        if redirect_url:
            attributes["redirect_url"] = redirect_url
        attributes["is_directory_guess"] = is_directory_guess

        findings.append({
            "host": host,
            "port": port,
            "source_tool": "ffuf",
            "entity_type": "web_content",
            "name": path,
            "version": None,
            "attributes": attributes,
        })

    return findings
