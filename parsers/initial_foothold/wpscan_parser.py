import json
from parsers.ansi import warn
from urllib.parse import urlparse


def _host_port(target_url):
    parsed = urlparse(target_url or "")
    host = parsed.hostname or "UNKNOWN_HOST"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return host, port


def _version_number(version_obj):
    """wpscan version fields are objects like {'number': '5.8', ...}."""
    if isinstance(version_obj, dict):
        return version_obj.get("number")
    if isinstance(version_obj, str):
        return version_obj
    return None


def _emit_vulnerabilities(findings, host, port, vulns, related_product, related_version):
    for vuln in vulns or []:
        if not isinstance(vuln, dict):
            continue
        refs = vuln.get("references", {}) if isinstance(vuln.get("references"), dict) else {}
        cves = refs.get("cve")
        if isinstance(cves, str):
            cves = [cves]
        # wpscan lists CVEs as bare numbers (e.g. "2021-1234"); normalise to CVE-….
        normalized_cves = [c if str(c).upper().startswith("CVE-") else f"CVE-{c}" for c in (cves or [])]
        findings.append({
            "host": host,
            "port": port,
            "source_tool": "wpscan",
            "entity_type": "vulnerability",
            "name": vuln.get("title") or "wordpress_vulnerability",
            "version": None,
            "attributes": {
                "cves": normalized_cves or None,
                "references": refs,
                "fixed_in": vuln.get("fixed_in"),
                "related_software_product": related_product,
                "related_software_version": related_version,
            },
        })


def parse_wpscan_json(json_file_path):
    """
    Parses wpscan JSON output (--format json) into findings.

    Emits the WordPress core, plugins, and theme as software_product findings
    (so the exploit mapper can enrich them by version), each reported
    vulnerability as a vulnerability finding, and enumerated users as user
    findings (so credential spraying / brute-force rules can fire).
    """
    findings = []
    try:
        with open(json_file_path, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
    except FileNotFoundError:
        warn(f"[!] Error: wpscan JSON file not found at {json_file_path}")
        return findings
    except json.JSONDecodeError:
        warn(f"[!] Error: Could not decode JSON from '{json_file_path}'.")
        return findings

    if not isinstance(data, dict):
        return findings

    host, port = _host_port(data.get("target_url") or data.get("target_ip"))

    # WordPress core.
    core_version = _version_number(data.get("version"))
    findings.append({
        "host": host, "port": port, "source_tool": "wpscan",
        "entity_type": "software_product", "name": "WordPress", "version": core_version,
        "attributes": {"status": (data.get("version") or {}).get("status") if isinstance(data.get("version"), dict) else None},
    })
    if isinstance(data.get("version"), dict):
        _emit_vulnerabilities(findings, host, port, data["version"].get("vulnerabilities"), "WordPress", core_version)

    # Active theme.
    main_theme = data.get("main_theme")
    if isinstance(main_theme, dict):
        theme_version = _version_number(main_theme.get("version"))
        theme_name = main_theme.get("slug") or main_theme.get("style_name") or "wordpress_theme"
        findings.append({
            "host": host, "port": port, "source_tool": "wpscan",
            "entity_type": "software_product", "name": f"WordPress theme: {theme_name}", "version": theme_version,
            "attributes": {"slug": main_theme.get("slug")},
        })
        _emit_vulnerabilities(findings, host, port, main_theme.get("vulnerabilities"), theme_name, theme_version)

    # Plugins.
    plugins = data.get("plugins", {})
    if isinstance(plugins, dict):
        for slug, plugin in plugins.items():
            if not isinstance(plugin, dict):
                continue
            plugin_version = _version_number(plugin.get("version"))
            findings.append({
                "host": host, "port": port, "source_tool": "wpscan",
                "entity_type": "software_product", "name": f"WordPress plugin: {slug}", "version": plugin_version,
                "attributes": {"slug": slug, "location": plugin.get("location")},
            })
            _emit_vulnerabilities(findings, host, port, plugin.get("vulnerabilities"), slug, plugin_version)

    # Enumerated users.
    users = data.get("users", {})
    if isinstance(users, dict):
        for username in users:
            findings.append({
                "host": host, "port": port, "source_tool": "wpscan",
                "entity_type": "user", "name": username, "version": None,
                "attributes": {"source": "wpscan user enumeration"},
            })

    return findings
