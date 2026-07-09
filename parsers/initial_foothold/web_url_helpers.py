from urllib.parse import parse_qsl, urlparse


def _absolute_url(host, port, candidate):
    value = (candidate or "").strip()
    if not value:
        return None
    parsed = urlparse(value)
    if parsed.scheme and parsed.netloc:
        return value
    if not value.startswith("/"):
        value = "/" + value
    scheme = "https" if port in {443, 8443, 9443} else "http"
    return f"{scheme}://{host}:{port}{value}"


def parameterized_url_finding(host, port, source_tool, candidate, source_name=None):
    """Return a sqlmap-candidate finding for URLs/paths with query parameters."""
    url = _absolute_url(host, port, candidate)
    if not url:
        return None
    parsed = urlparse(url)
    if not parsed.query:
        return None

    params = [name for name, _value in parse_qsl(parsed.query, keep_blank_values=True) if name]
    if not params:
        return None

    return {
        "host": parsed.hostname or host,
        "port": parsed.port or port,
        "source_tool": source_tool,
        "entity_type": "web_parameterized_url",
        "name": url,
        "version": None,
        "attributes": {
            "url": url,
            "path": parsed.path or "/",
            "query": parsed.query,
            "parameters": sorted(set(params)),
            "source_finding": source_name,
        },
    }
