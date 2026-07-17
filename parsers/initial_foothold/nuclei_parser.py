import json
from parsers.ansi import warn
from urllib.parse import urlparse
from parsers.initial_foothold.web_url_helpers import parameter_triage_findings, parameterized_url_finding

# Severities that warrant a high-signal "vulnerability" finding; everything else
# (low/info/unknown) is recorded as an information_leak for context.
VULN_SEVERITIES = {"critical", "high", "medium"}


def _host_port(record):
    """Resolve (host, port) from a nuclei record's host/matched-at URL."""
    candidate = str(record.get("matched-at") or record.get("host") or record.get("matched_at") or "")
    try:
        parsed = urlparse(candidate if "://" in candidate else f"http://{candidate}")
        host = parsed.hostname or candidate or "UNKNOWN_HOST"
        port = parsed.port
    except ValueError:
        return candidate or "UNKNOWN_HOST", 80
    if not port:
        port = 443 if parsed.scheme == "https" else 80
    return host, port


def parse_nuclei_jsonl(file_path):
    """
    Parses nuclei JSONL output (nuclei -jsonl) into vulnerability findings.

    Each line is an independent JSON object. CVE id (when present) becomes the
    finding name so it flows into the VulnerabilityMapper's exploit enrichment;
    severity and references are preserved for the rules engine.
    """
    findings = []
    try:
        with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as f:
            lines = f.read().splitlines()
    except FileNotFoundError:
        warn(f"[!] Error: nuclei JSONL file not found at {file_path}")
        return findings

    seen = set()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            # Tolerate a stray non-JSON line rather than aborting the whole file.
            continue
        if not isinstance(record, dict):
            continue

        info = record.get("info", {}) if isinstance(record.get("info"), dict) else {}
        severity = str(info.get("severity") or "unknown").lower()
        template_id = str(record.get("template-id") or record.get("templateID") or "nuclei_finding")

        classification = info.get("classification", {}) if isinstance(info.get("classification"), dict) else {}
        cve_ids = classification.get("cve-id") or classification.get("cve_id") or []
        if isinstance(cve_ids, str):
            cve_ids = [cve_ids]
        elif not isinstance(cve_ids, (list, tuple, set)):
            cve_ids = []
        cve_ids = [str(cve).upper() for cve in cve_ids if cve not in (None, "")]
        primary_cve = cve_ids[0] if cve_ids else None

        host, port = _host_port(record)
        entity_type = "vulnerability" if severity in VULN_SEVERITIES else "information_leak"
        name = primary_cve or template_id

        identifier = (host, port, name, str(record.get("matched-at") or ""))
        if identifier in seen:
            continue
        seen.add(identifier)

        finding = {
            "host": host,
            "port": port,
            "source_tool": "nuclei",
            "entity_type": entity_type,
            "name": name,
            "version": None,
            "attributes": {
                "template_id": template_id,
                "template_name": info.get("name"),
                "severity": severity,
                "cves": cve_ids or None,
                "cvss_score": classification.get("cvss-score") or classification.get("cvss_score"),
                "matched_at": record.get("matched-at"),
                "tags": info.get("tags"),
                "references": info.get("reference"),
                "description": info.get("description") or info.get("name"),
            },
        }
        findings.append(finding)
        param_finding = parameterized_url_finding(
            host, port, "nuclei", record.get("matched-at") or record.get("matched_at"), name
        )
        if param_finding:
            findings.append(param_finding)
            findings.extend(parameter_triage_findings(param_finding))

    return findings
