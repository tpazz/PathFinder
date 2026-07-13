import json
from parsers.ansi import warn


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
        warn(f"[!] Error: LLM enum JSON file not found at {json_file_path}")
        return findings
    except json.JSONDecodeError:
        warn(f"[!] Error: Could not decode JSON from '{json_file_path}'.")
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
    agent = data.get("agent_profile") if isinstance(data.get("agent_profile"), dict) else {}
    vector_store = data.get("vector_store") if isinstance(data.get("vector_store"), dict) else {}
    mcp_tools = data.get("mcp_tools") if isinstance(data.get("mcp_tools"), dict) else {}
    agent_cards = data.get("agent_cards") if isinstance(data.get("agent_cards"), list) else []
    confirmed_tools = mcp_tools.get("tools") if isinstance(mcp_tools.get("tools"), list) else []
    confirmed_tool_names = [t.get("name") for t in confirmed_tools if isinstance(t, dict) and t.get("name")]
    confirmed_categories = sorted({
        c for t in confirmed_tools if isinstance(t, dict) for c in (t.get("categories") or [])
    })
    agent_card_paths = [c.get("path") for c in agent_cards if isinstance(c, dict) and c.get("path")]
    # Attributes added to every finding from this service when active (--ai-active)
    # confirmation ran, so the confirmed capabilities travel with the finding.
    active_attrs = {
        "confirmed_mcp_tools": confirmed_tool_names or None,
        "confirmed_mcp_categories": confirmed_categories or None,
        "agent_card_paths": agent_card_paths or None,
    }

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
                "agent_role": agent.get("role"),
                "agent_architecture": agent.get("architecture"),
                "agent_framework": agent.get("framework"),
                "agent_capabilities": agent.get("capabilities"),
                "agent_evidence": agent.get("evidence"),
                **active_attrs,
            },
        })

    # Agent archetype finding. Specific archetypes are high-value, name-based attack
    # surfaces, so emit them even when a framework surface (openai-compatible, etc.)
    # also exists - an LLM API can itself BE a multi-agent orchestrator or NL-to-SQL
    # agent, and the exact-match archetype rules can't match on the architecture that
    # otherwise only lives in attributes:
    #   multi-agent / A2A -> "ai-agent-a2a"   database capability -> "ai-agent-sql"
    # The generic "ai-agent" is only a fallback when no framework surface was found,
    # so the generic capability rule doesn't fire on every plain LLM API.
    archetype = None
    if agent.get("role"):
        capabilities = agent.get("capabilities") if isinstance(agent.get("capabilities"), list) else []
        if agent.get("architecture") == "multi-agent":
            archetype = "ai-agent-a2a"
        elif "database" in capabilities:
            archetype = "ai-agent-sql"
        elif not findings:
            archetype = "ai-agent"
    if archetype and archetype not in {f["name"] for f in findings}:
        findings.append({
            "host": host,
            "port": port,
            "source_tool": "one-shot-enum-llm",
            "entity_type": "ai_service",
            "name": archetype,
            "version": None,
            "attributes": {
                "label": agent.get("role"),
                "confidence": "medium",
                "framework": agent.get("framework") or "ai-agent",
                "base_url": base_url,
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
                "agent_role": agent.get("role"),
                "agent_architecture": agent.get("architecture"),
                "agent_framework": agent.get("framework"),
                "agent_capabilities": agent.get("capabilities"),
                "agent_evidence": agent.get("evidence"),
                **active_attrs,
            },
        })

    # Active confirmation (--ai-active) recovered a real MCP tool inventory: emit a
    # dedicated finding so the engine can point at those specific tools/categories.
    if confirmed_tool_names:
        findings.append({
            "host": host,
            "port": port,
            "source_tool": "one-shot-enum-llm",
            "entity_type": "ai_service",
            "name": "mcp-tools-confirmed",
            "version": None,
            "attributes": {
                "label": f"{len(confirmed_tool_names)} confirmed MCP tool(s)",
                "confidence": "high",
                "framework": "mcp",
                "base_url": base_url,
                "mcp_url": mcp_tools.get("url"),
                "confirmed_mcp_tools": confirmed_tool_names,
                "confirmed_mcp_categories": confirmed_categories or None,
                "service_banner": service.get("banner"),
                "service_product": service.get("product"),
            },
        })

    # Unauthenticated vector store: emit a dedicated high-value finding so the engine
    # can fire the "read the chunks directly" (plaintext-first) attack path. This is
    # independent of framework surfaces - the store may be its own service.
    if vector_store.get("unauthenticated"):
        findings.append({
            "host": host,
            "port": port,
            "source_tool": "one-shot-enum-llm",
            "entity_type": "ai_service",
            "name": "vector-store-open",
            "version": None,
            "attributes": {
                "label": f"Unauthenticated {vector_store.get('engine', 'vector store')}",
                "confidence": "high",
                "framework": "vector-store",
                "base_url": base_url,
                "vector_store_engine": vector_store.get("engine"),
                "vector_store_url": vector_store.get("url"),
                "vector_store_collections": vector_store.get("collections"),
                "vector_store_collection_count": vector_store.get("collection_count"),
                "service_banner": service.get("banner"),
                "service_product": service.get("product"),
            },
        })

    discovery_command = data.get("discovery_command")
    if isinstance(discovery_command, str) and discovery_command:
        for finding in findings:
            finding.setdefault("attributes", {})["discovery_command"] = discovery_command
    return findings
