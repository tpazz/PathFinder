import re
from urllib.parse import parse_qsl, urlparse


_PARAMETER_TRIAGE = {
    "path_traversal_lfi": re.compile(r"(?i)(?:^|_)(?:file|filename|filepath|path|page|include|inc|lang|locale|folder|dir|directory|download|document)(?:$|_)"),
    "ssrf": re.compile(r"(?i)(?:^|_)(?:url|uri|host|hostname|callback|webhook|redirect|return|next|feed|proxy|endpoint|site|domain)(?:$|_)"),
    "command_injection": re.compile(r"(?i)(?:^|_)(?:cmd|command|exec|execute|shell|ping|lookup|ip|host|hostname|domain)(?:$|_)"),
    "xxe": re.compile(r"(?i)(?:^|_)(?:xml|soap|svg|doctype|document|payload)(?:$|_)"),
    "sqli": re.compile(r"(?i)(?:^|_)(?:sql|query|search|filter|where|sort|order|column|table|category)(?:$|_)"),
    "idor": re.compile(r"(?i)(?:^|_)(?:id|uid|user|user_id|account|account_id|customer|order_id|invoice|record|object|item|product_id|priority)(?:$|_)"),
    "ssti": re.compile(r"(?i)(?:^|_)(?:template|render|renderer|engine|layout|theme|preview|format)(?:$|_)"),
}


def _absolute_url(host, port, candidate):
    value = str(candidate or "").strip()
    if not value:
        return None
    parsed = urlparse(value)
    if parsed.scheme and parsed.netloc:
        try:
            parsed.port
        except ValueError:
            return None
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

    try:
        parsed_host = parsed.hostname
        parsed_port = parsed.port
    except ValueError:
        return None

    params = [name for name, _value in parse_qsl(parsed.query, keep_blank_values=True) if name]
    if not params:
        return None

    return {
        "host": parsed_host or host,
        "port": parsed_port or port,
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


def classify_parameter_names(parameters):
    classifications = []
    seen = set()
    for raw_name in parameters:
        name = str(raw_name or "").strip()
        normalized = re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_")
        if not normalized:
            continue
        for category, pattern in _PARAMETER_TRIAGE.items():
            key = (name.lower(), category)
            if key not in seen and pattern.search(normalized):
                seen.add(key)
                classifications.append((name, category))
    return classifications


def parameter_triage_findings(request_finding):
    attributes = request_finding.get("attributes") or {}
    findings = []
    for parameter, category in classify_parameter_names(attributes.get("parameters") or []):
        findings.append({
            "host": request_finding.get("host"),
            "port": request_finding.get("port"),
            "source_tool": request_finding.get("source_tool"),
            "entity_type": "web_parameter_candidate",
            "name": f"{category}:{parameter}",
            "version": None,
            "attributes": {
                **attributes,
                "parameter": parameter,
                "triage_category": category,
                "candidate_only": True,
                "requires_manual_validation": True,
            },
        })
    return findings
