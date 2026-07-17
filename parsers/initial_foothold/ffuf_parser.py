import json
import re
from parsers.ansi import warn
from urllib.parse import urlparse
from parsers.initial_foothold.web_url_helpers import parameter_triage_findings, parameterized_url_finding


_VHOST_HEADER = re.compile(
    r"(?:^|\s)(?:-H|--header)(?:=|\s+)[\"']?Host:\s*FUZZ\.(?P<suffix>[A-Za-z0-9.-]+)",
    re.IGNORECASE,
)


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
    try:
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        host, port = None, None
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


def _vhost_suffix(commandline):
    match = _VHOST_HEADER.search(commandline or "")
    return match.group("suffix").lower().rstrip(".") if match else None


def _vhost_input(result):
    values = result.get("input")
    if not isinstance(values, dict):
        return None
    value = values.get("FUZZ")
    if isinstance(value, str):
        value = value.strip().strip(".")
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", value):
            return value.lower()
    return None


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

    commandline = data.get("commandline") if isinstance(data.get("commandline"), str) else None
    vhost_suffix = _vhost_suffix(commandline)
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

        fuzz_value = _vhost_input(result)
        if vhost_suffix and fuzz_value:
            vhost_name = fuzz_value if fuzz_value.endswith("." + vhost_suffix) else f"{fuzz_value}.{vhost_suffix}"
            identifier = (host, port, "virtual_host", vhost_name, status_code)
            if identifier not in seen:
                seen.add(identifier)
                attributes = {
                    "status_code": status_code,
                    "size_bytes": size,
                    "fuzz_input": result.get("input"),
                    "discovery_command": commandline,
                }
                if redirect_url:
                    attributes["redirect_url"] = redirect_url
                findings.append({
                    "host": host,
                    "port": port,
                    "source_tool": "ffuf",
                    "entity_type": "virtual_host",
                    "name": vhost_name,
                    "version": None,
                    "attributes": attributes,
                })
            continue

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
        if commandline:
            attributes["discovery_command"] = commandline
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
        param_finding = parameterized_url_finding(host, port, "ffuf", result.get("url"), path)
        if param_finding:
            if commandline:
                param_finding.setdefault("attributes", {})["discovery_command"] = commandline
            findings.append(param_finding)
            findings.extend(parameter_triage_findings(param_finding))

    return findings
