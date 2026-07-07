import json


def parse_llm_enum_json(json_file_path):
    """
    Parses one-shot-enum's LLM/AI enumeration output into `ai_service` findings.

    one-shot-enum performs the live AI-surface fingerprinting (OpenAI-compatible
    APIs, Ollama, vLLM, agent/MCP, RAG stores, MLflow, notebooks, ...) and writes
    a self-identifying JSON per service:

        {"tool": "one-shot-enum", "type": "llm_enum", "host": ..., "port": ...,
         "base_url": ..., "endpoints": [{"method","path"}...],
         "ai_surfaces": [{"key","label","confidence","evidence"[]}...]}

    Each detected surface becomes one `ai_service` finding (name = surface key,
    e.g. "openai-compatible"/"ollama"/"agent-mcp"), which the AI/LLM attack rules
    correlate into attack paths.
    """
    findings = []
    try:
        with open(json_file_path, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"[!] Error: LLM enum JSON file not found at {json_file_path}")
        return findings
    except json.JSONDecodeError:
        print(f"[!] Error: Could not decode JSON from '{json_file_path}'.")
        return findings

    if not isinstance(data, dict):
        return findings

    host = data.get("host") or "UNKNOWN_HOST"
    raw_port = data.get("port")
    try:
        port = int(raw_port) if raw_port is not None else None
    except (ValueError, TypeError):
        port = None
    base_url = data.get("base_url")
    endpoints = data.get("endpoints") if isinstance(data.get("endpoints"), list) else []
    probe_hits = data.get("probe_hits") if isinstance(data.get("probe_hits"), list) else []
    service = data.get("service") if isinstance(data.get("service"), dict) else {}

    for surface in data.get("ai_surfaces", []):
        if not isinstance(surface, dict):
            continue
        key = surface.get("key") or "ai_service"
        findings.append({
            "host": host,
            "port": port,
            "source_tool": "one-shot-enum-llm",
            "entity_type": "ai_service",
            "name": key,
            "version": None,
            "attributes": {
                "label": surface.get("label"),
                "confidence": surface.get("confidence"),
                "evidence": surface.get("evidence"),
                "next_steps": surface.get("next_steps"),
                "base_url": base_url,
                "framework": key,
                "endpoints": endpoints,
                "probe_hits": probe_hits,
                "probe_count": data.get("probe_count"),
                "probe_paths": [hit.get("path") for hit in probe_hits if isinstance(hit, dict) and hit.get("path")],
                "chat_path": data.get("chat_path"),
                "openapi_url": data.get("openapi_url"),
                "openapi_status": data.get("openapi_status"),
                "openapi_error": data.get("openapi_error"),
                "service_banner": service.get("banner"),
                "service_product": service.get("product"),
            },
        })

    return findings
