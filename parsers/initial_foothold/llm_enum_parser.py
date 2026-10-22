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
    usable_hits = [h for h in probe_hits if isinstance(h, dict) and not h.get('baseline_match')]

    def verified_surface(key):
        if 'mcp' in key and confirmed_tool_names:
            return True
        if 'agent' in key and agent_card_paths:
            return True
        paths = [str(h.get('path', '')).lower() for h in usable_hits if h.get('protocol_verified') is True]
        if key == 'mlflow' and any('mlflow' in path for path in paths):
            return True
        if key in ('agent-mcp', 'ai-agent-a2a', 'ai-agent'):
            return any('agent' in path or path in ('/a2a', '/mcp') for path in paths)
        # A parsed OpenAPI document or exact product banner corroborates service
        # presence. Neither establishes write access or successful exploitation.
        banner = str(service.get('product', '')).lower()
        if key == 'notebook' and ('jupyter' in banner or any(path in ('/api/kernels', '/api/sessions', '/api/status') for path in paths)):
            return True
        if key and key in banner.split():
            return True
        expected = {'ollama': ('/api/tags', '/api/chat', '/api/generate'),
                    'openai-compatible': ('/v1/models', '/v1/chat/completions', '/v1/completions'),
                    'mlflow': ('/api/2.0/mlflow/',), 'notebook': ('/api/kernels', '/api/sessions', '/api/status'), 'jupyter': ('/api/kernels', '/api/sessions'),
                    'gradio': ('/gradio_api/',), 'langserve': ('/invoke', '/batch', '/stream')}
        relevant = expected.get(key, ())
        parsed = [str(e.get('path', '')) for e in endpoints if isinstance(e, dict)] if not data.get('openapi_error') else []
        return any(path == prefix or prefix.endswith('/') and path.startswith(prefix)
                   for path in [*paths, *parsed] for prefix in relevant)
    # Attributes added to every finding from this service when active (--ai-active)
    # confirmation ran, so the confirmed capabilities travel with the finding.
    active_attrs = {
        "confirmed_mcp_tools": confirmed_tool_names or None,
        "confirmed_mcp_categories": confirmed_categories or None,
        "agent_card_paths": agent_card_paths or None,
    }
    # Explicit externally-collected capability evidence; presence is not proof.
    capability_evidence = data.get('capability_evidence')
    capability_evidence = capability_evidence if isinstance(capability_evidence, dict) else {}
    for flag in ('artifact_write_verified', 'kernel_creation_verified'):
        evidence = capability_evidence.get(flag, {})
        if isinstance(evidence, dict) and evidence.get('verified') is True and evidence.get('evidence'):
            active_attrs[flag] = True
            active_attrs.setdefault('capability_evidence', {})[flag] = evidence

    for surface in data.get("ai_surfaces", []):
        if not isinstance(surface, dict):
            continue
        key = surface.get("key") or "ai_service"
        verified = verified_surface(key)
        findings.append({
            "host": host,
            "port": port,
            "source_tool": "one-shot-enum-llm",
            "entity_type": "ai_service" if verified else "ai_service_candidate",
            "name": key,
            "version": None,
            "attributes": {
                "label": surface.get("label"),
                "confidence": surface.get("confidence"),
                "evidence": surface.get("evidence"),
                "next_steps": surface.get("next_steps"),
                "base_url": base_url,
                "framework": key,
                "protocol_verified": verified,
                "evidence_state": 'Suspected' if verified else 'Not assessed',
                "assessment_role": 'finding' if verified else 'validation',
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
        verified = verified_surface(archetype)
        findings.append({
            "host": host,
            "port": port,
            "source_tool": "one-shot-enum-llm",
            "entity_type": "ai_service" if verified else "ai_service_candidate",
            "name": archetype,
            "version": None,
            "attributes": {
                "label": agent.get("role"),
                "confidence": "medium",
                "framework": agent.get("framework") or "ai-agent",
                "protocol_verified": verified,
                "evidence_state": 'Suspected' if verified else 'Not assessed',
                "assessment_role": 'finding' if verified else 'validation',
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

    # The host resolved to a CDN/edge (Cloudflare, Railway, ...). An AI surface
    # seen at the edge may belong to the edge or a shared tenant, not this origin,
    # so annotate every finding and down-weight it - the mapper then scores it as
    # Info. Never dropped: a real exposed surface behind a CDN is still reported,
    # just flagged for manual confirmation against the origin.
    cdn = data.get("cdn")
    if isinstance(cdn, str) and cdn:
        for finding in findings:
            attrs = finding.setdefault("attributes", {})
            attrs["edge_fronted"] = cdn
            attrs["observed_hostname"] = base_url
            attrs["observed_ip"] = host
            attrs["infrastructure_scope"] = 'edge_fronted'
            attrs["requires_manual_validation"] = True
            # severity=info drives the score scaler to its floor (the mapper ranks
            # ai_service at 70 * 0.4), so an edge-fronted surface sorts to the
            # bottom as informational rather than a confirmed origin finding.
            if not (attrs.get('protocol_verified') or attrs.get('confirmed_mcp_tools') or attrs.get('agent_card_paths')):
                attrs["severity"] = "info"
                attrs["confidence"] = "low"
            attrs.setdefault("edge_note", f"Observed behind {cdn}; may be the edge, not the origin service.")
    return findings
