"""Parse bounded one-shot-enum or raw OpenAPI/Swagger documents."""

import json
from pathlib import Path
from urllib.parse import urlparse

from parsers.ansi import warn
from parsers.initial_foothold.web_url_helpers import parameter_triage_findings


MAX_OPENAPI_FILE_BYTES = 16 * 1024 * 1024
MAX_OPENAPI_ENDPOINTS = 500
MAX_PARAMETERS_PER_ENDPOINT = 50
MAX_LOCAL_REF_DEPTH = 12
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head", "trace"}


def _safe_port(value):
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 0 < port <= 65535 else None


def _resolve_local_ref(document, value, seen=None, depth=0):
    """Resolve a bounded local JSON Pointer while preserving allowed siblings."""
    if not isinstance(value, dict):
        return {}
    ref = value.get("$ref")
    if not ref:
        return value
    if (not isinstance(ref, str) or not ref.startswith("#/")
            or depth >= MAX_LOCAL_REF_DEPTH):
        return {}
    seen = set(seen or ())
    if ref in seen:
        return {}
    seen.add(ref)
    target = document
    for raw_token in ref[2:].split("/"):
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if not isinstance(target, dict) or token not in target:
            return {}
        target = target[token]
    resolved = _resolve_local_ref(document, target, seen, depth + 1)
    if not isinstance(resolved, dict):
        return {}
    merged = dict(resolved)
    merged.update({key: item for key, item in value.items() if key != "$ref"})
    return merged


def _schema_properties(document, schema, depth=0):
    if depth >= MAX_LOCAL_REF_DEPTH:
        return {}, set()
    schema = _resolve_local_ref(document, schema)
    if not schema:
        return {}, set()
    properties = {}
    required = set(schema.get("required") if isinstance(schema.get("required"), list) else [])
    for branch in schema.get("allOf") if isinstance(schema.get("allOf"), list) else []:
        branch_properties, branch_required = _schema_properties(document, branch, depth + 1)
        properties.update(branch_properties)
        required.update(branch_required)
    direct = schema.get("properties")
    if isinstance(direct, dict):
        properties.update(direct)
    return properties, required


def _parameter_details(document, path_item, operation):
    values = []
    indexes = {}

    def add(name, location, required, value_type):
        name = str(name or "").strip()
        location = str(location or "unknown").strip().lower() or "unknown"
        if not name:
            return
        detail = {
            "name": name,
            "location": location,
            "required": bool(required),
            "type": str(value_type or "unknown"),
        }
        key = (name.lower(), location)
        if key in indexes:
            values[indexes[key]] = detail
        elif len(values) < MAX_PARAMETERS_PER_ENDPOINT:
            indexes[key] = len(values)
            values.append(detail)

    for container in (path_item, operation):
        parameters = container.get("parameters") if isinstance(container, dict) else None
        if not isinstance(parameters, list):
            continue
        for parameter in parameters:
            parameter = _resolve_local_ref(document, parameter)
            if not parameter:
                continue
            name = str(parameter.get("name") or "").strip()
            location = str(parameter.get("in") or "unknown")
            schema = _resolve_local_ref(document, parameter.get("schema"))
            if location.lower() == "body":
                properties, required = _schema_properties(document, schema)
                if properties:
                    for property_name, definition in properties.items():
                        definition = _resolve_local_ref(document, definition)
                        add(property_name, "body", property_name in required,
                            definition.get("type") if definition else "unknown")
                    continue
            add(name, location, parameter.get("required"),
                schema.get("type") or parameter.get("type") if schema else parameter.get("type"))
            if len(values) >= MAX_PARAMETERS_PER_ENDPOINT:
                return values

    request_body = _resolve_local_ref(
        document, operation.get("requestBody") if isinstance(operation, dict) else None,
    )
    content = request_body.get("content") if isinstance(request_body, dict) else None
    if isinstance(content, dict):
        for media in content.values():
            schema = _resolve_local_ref(
                document, media.get("schema") if isinstance(media, dict) else None,
            )
            properties, required = _schema_properties(document, schema)
            for name, definition in properties.items():
                definition = _resolve_local_ref(document, definition)
                add(name, "body", name in required,
                    definition.get("type") if definition else "unknown")
                if len(values) >= MAX_PARAMETERS_PER_ENDPOINT:
                    return values
    return values


def _raw_endpoints(document):
    paths = document.get("paths") if isinstance(document, dict) else None
    if not isinstance(paths, dict):
        return []
    endpoints = []
    for path, path_item in paths.items():
        path_item = _resolve_local_ref(document, path_item)
        if not path_item:
            continue
        for method, operation in path_item.items():
            if str(method).lower() not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            endpoints.append({
                "method": str(method).upper(),
                "path": str(path),
                "parameters": _parameter_details(document, path_item, operation),
                "security_declared": "security" in operation or "security" in document,
                "operation_id": str(operation.get("operationId") or ""),
            })
            if len(endpoints) >= MAX_OPENAPI_ENDPOINTS:
                return endpoints
    return endpoints


def _endpoint_url(base_url, path):
    if not base_url:
        return str(path)
    return f"{str(base_url).rstrip('/')}/{str(path).lstrip('/')}"


def parse_openapi_json(path, target_host=None):
    """Return an API inventory and context-aware parameter candidates."""
    try:
        source = Path(path)
        if not source.is_file() or source.stat().st_size > MAX_OPENAPI_FILE_BYTES:
            warn(f"[!] Warning: OpenAPI input is missing or exceeds {MAX_OPENAPI_FILE_BYTES} bytes: {path}")
            return []
        with source.open("r", encoding="utf-8-sig") as handle:
            payload = json.load(handle)
    except (OSError, ValueError, UnicodeError, json.JSONDecodeError):
        warn(f"[!] Warning: Could not load OpenAPI JSON from '{path}'.")
        return []
    if not isinstance(payload, dict):
        return []

    envelope = payload.get("type") == "openapi_enum"
    endpoints = payload.get("endpoints") if envelope else _raw_endpoints(payload)
    if not isinstance(endpoints, list) or not endpoints:
        return []
    endpoints = [item for item in endpoints[:MAX_OPENAPI_ENDPOINTS] if isinstance(item, dict)]

    base_url = payload.get("base_url") if envelope else None
    if not base_url and not envelope:
        servers = payload.get("servers")
        if isinstance(servers, list) and servers and isinstance(servers[0], dict):
            base_url = servers[0].get("url")
            variables = servers[0].get("variables")
            if isinstance(base_url, str) and isinstance(variables, dict):
                for name, definition in variables.items():
                    if isinstance(definition, dict) and definition.get("default") is not None:
                        base_url = base_url.replace(
                            "{" + str(name) + "}", str(definition["default"]),
                        )
    if not base_url and not envelope and str(payload.get("swagger") or "").startswith("2"):
        schemes = payload.get("schemes")
        scheme = str(schemes[0]).lower() if isinstance(schemes, list) and schemes else "http"
        swagger_host = str(payload.get("host") or "").strip()
        base_path = "/" + str(payload.get("basePath") or "").strip("/")
        if swagger_host:
            base_url = f"{scheme}://{swagger_host}{base_path.rstrip('/')}"
    if isinstance(base_url, str) and base_url.startswith("/") and target_host:
        base_url = f"http://{target_host}{base_url}"
    parsed = urlparse(str(base_url or ""))
    try:
        parsed_port = parsed.port
    except ValueError:
        parsed_port = None
    host = str(target_host or parsed.hostname or payload.get("host") or "unknown")
    port = _safe_port(payload.get("port")) or parsed_port
    if port is None and parsed.scheme.lower() in {"http", "https"}:
        port = 443 if parsed.scheme.lower() == "https" else 80
    if not base_url and host != "unknown":
        port = port or 80
        scheme = "https" if port in {443, 8443, 9443} else "http"
        base_url = f"{scheme}://{host}:{port}"

    info = payload.get("info") if isinstance(payload.get("info"), dict) else {}
    title = str(payload.get("openapi_title") or info.get("title") or "OpenAPI surface")
    version = str(payload.get("openapi_version") or payload.get("openapi")
                  or payload.get("swagger") or "unknown")
    source_tool = "one-shot-enum-openapi" if envelope else "openapi"
    command = payload.get("discovery_command") if envelope else None
    source_file = str(source)
    provenance = ([{"tool": source_tool, "command": command, "source_file": source_file}]
                  if command else [{"tool": source_tool, "source_file": source_file}])

    findings = [{
        "host": host,
        "port": port,
        "source_tool": source_tool,
        "entity_type": "api_surface",
        "name": title,
        "version": version,
        "attributes": {
            "title": title,
            "base_url": base_url,
            "schema_url": payload.get("openapi_url") if envelope else None,
            "endpoint_count": len(endpoints),
            "bounded": len(endpoints) >= MAX_OPENAPI_ENDPOINTS,
            "discovery_command": command,
            "discovery_provenance": provenance,
            "description": f"{title} exposes {len(endpoints)} documented API operation(s).",
        },
    }]

    seen = set()
    for endpoint in endpoints:
        method = str(endpoint.get("method") or "").upper()
        endpoint_path = str(endpoint.get("path") or "").strip()
        if method.lower() not in HTTP_METHODS or not endpoint_path:
            continue
        parameter_details = endpoint.get("parameters")
        parameter_details = (
            [item for item in parameter_details[:MAX_PARAMETERS_PER_ENDPOINT]
             if isinstance(item, dict) and item.get("name")]
            if isinstance(parameter_details, list) else []
        )
        parameters = list(dict.fromkeys(str(item["name"]) for item in parameter_details))
        key = (method, endpoint_path)
        if key in seen:
            continue
        seen.add(key)
        url = _endpoint_url(base_url, endpoint_path)
        attrs = {
            "method": method,
            "path": endpoint_path,
            "url": url,
            "parameters": parameters,
            "parameter_details": parameter_details,
            "operation_id": endpoint.get("operation_id") or endpoint.get("operationId"),
            "security_declared": endpoint.get("security_declared"),
            "schema_url": payload.get("openapi_url") if envelope else None,
            "candidate_only": True,
            "requires_manual_validation": True,
            "discovery_command": command,
            "discovery_provenance": provenance,
        }
        endpoint_finding = {
            "host": host,
            "port": port,
            "source_tool": source_tool,
            "entity_type": "api_endpoint",
            "name": f"{method} {endpoint_path}",
            "version": None,
            "attributes": attrs,
        }
        findings.append(endpoint_finding)
        findings.extend(parameter_triage_findings(endpoint_finding))
    return findings
