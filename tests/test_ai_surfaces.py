import json
import tempfile
import unittest
from pathlib import Path

from main.attack_path_synthesizer import AttackPathSynthesizer
from main.finding_schema import validate_findings
from main.vulnerability_mapper import VulnerabilityMapper
from parsers.initial_foothold.llm_enum_parser import parse_llm_enum_json

RULES_FILE = str(Path(__file__).parent.parent / "main" / "attack_rules.json")


def _write(content, suffix=".json"):
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False, encoding="utf-8")
    tmp.write(content)
    tmp.close()
    return tmp.name


class LlmEnumParserTests(unittest.TestCase):
    def test_parses_surfaces_into_ai_service_findings(self):
        payload = {
            "tool": "one-shot-enum", "type": "llm_enum",
            "host": "10.10.10.10", "port": 11434,
            "base_url": "http://10.10.10.10:11434",
            "openapi_url": "http://10.10.10.10:11434/openapi.json",
            "openapi_status": 404,
            "endpoints": [{"method": "GET", "path": "/api/tags"}],
            "probe_count": 2,
            "probe_hits": [{"path": "/api/tags", "status": 200, "content_type": "application/json"}],
            "chat_path": "/api/chat",
            "service": {"banner": "http ollama", "product": "ollama"},
            "ai_surfaces": [
                {"key": "ollama", "label": "Ollama API", "confidence": "high", "evidence": ["/api/tags exposed"], "next_steps": ["GET /api/tags"]},
                {"key": "openai-compatible", "label": "OpenAI-compatible LLM API", "confidence": "medium", "evidence": []},
            ],
        }
        path = _write(json.dumps(payload))
        try:
            findings = parse_llm_enum_json(path)
        finally:
            Path(path).unlink(missing_ok=True)

        validate_findings(findings)
        self.assertEqual(len(findings), 2)
        self.assertTrue(all(f["entity_type"] == "ai_service" for f in findings))
        ollama = next(f for f in findings if f["name"] == "ollama")
        self.assertEqual(ollama["host"], "10.10.10.10")
        self.assertEqual(ollama["port"], 11434)
        self.assertEqual(ollama["attributes"]["confidence"], "high")
        self.assertEqual(ollama["attributes"]["base_url"], "http://10.10.10.10:11434")
        self.assertEqual(ollama["attributes"]["probe_paths"], ["/api/tags"])
        self.assertEqual(ollama["attributes"]["chat_path"], "/api/chat")
        self.assertEqual(ollama["attributes"]["openapi_status"], 404)
        self.assertEqual(ollama["attributes"]["service_banner"], "http ollama")


class AiServiceScoringTests(unittest.TestCase):
    def test_confidence_scales_ai_service_score(self):
        mapper = VulnerabilityMapper(use_github=False, use_searchsploit=False)
        findings = [
            {"host": "h", "port": 80, "source_tool": "one-shot-enum-llm", "entity_type": "ai_service",
             "name": "ollama", "version": None, "attributes": {"confidence": "high"}},
            {"host": "h", "port": 81, "source_tool": "one-shot-enum-llm", "entity_type": "ai_service",
             "name": "gradio", "version": None, "attributes": {"confidence": "low"}},
        ]
        scored = {f["name"]: f["attributes"]["score"] for f in mapper.map_and_prioritize(findings)}
        self.assertGreater(scored["ollama"], scored["gradio"])


class AiRuleTests(unittest.TestCase):
    def setUp(self):
        self.synth = AttackPathSynthesizer(rules_file_path=RULES_FILE)

    def _f(self, name, **attrs):
        return {"host": "10.10.10.10", "port": 8000, "source_tool": "one-shot-enum-llm",
                "entity_type": "ai_service", "name": name, "version": None,
                "attributes": {"base_url": "http://10.10.10.10:8000", **attrs}}

    def _names(self, findings):
        return [p["name"] for p in self.synth.generate_attack_paths(findings)]

    def test_ollama_rule_fires(self):
        self.assertIn("Exposed Ollama API - Unauthenticated Model Access",
                      self._names([self._f("ollama", score=70)]))

    def test_notebook_rce_rule_fires(self):
        self.assertIn("Exposed Jupyter - Unauthenticated Kernel = RCE",
                      self._names([self._f("notebook", score=70)]))

    def test_openai_compatible_rule_fires(self):
        paths = self.synth.generate_attack_paths([self._f("openai-compatible", score=70)])
        hit = [p for p in paths if "Prompt Injection" in p["name"]]
        self.assertGreaterEqual(len(hit), 1)
        self.assertIn("http://10.10.10.10:8000", hit[0]["suggestion"]["description"])

    def test_agent_and_rag_and_mlflow_rules_fire(self):
        names = self._names([self._f("agent-mcp", score=70), self._f("rag-vector", score=70), self._f("mlflow", score=70)])
        self.assertIn("Agent/MCP Surface - Excessive Agency & Tool Abuse", names)
        self.assertIn("RAG / Vector Store - Indirect Injection & Data Extraction", names)
        self.assertIn("MLflow Exposed - Artifact Write to Code Execution", names)

    def test_additional_ai_surface_rules_fire(self):
        names = self._names([
            self._f("langserve", score=70),
            self._f("vllm", score=70),
            self._f("tgi", score=70),
            self._f("model-serving", score=70),
            self._f("ai-workflow", score=70),
            self._f("image-generation", score=70),
        ])
        self.assertIn("LangServe API - Schema Recovery to Chain Abuse", names)
        self.assertIn("vLLM/TGI/Model Server - Model Metadata, Tokenizer, and Adapter Recon", names)
        self.assertIn("AI Workflow Builder - Flow, Credential, and Tool Graph Enumeration", names)
        self.assertIn("Image Generation API - Model, Plugin, and File Path Abuse", names)

    def test_cross_surface_ai_chain_rules_fire(self):
        names = self._names([
            self._f("agent-mcp", score=70),
            self._f("rag-vector", score=70),
            self._f("openai-compatible", score=70),
            self._f("mlflow", score=70),
            self._f("model-serving", score=70),
            self._f("notebook", score=70),
        ])
        self.assertIn("Tool-Enabled RAG Chain - Retrieved Context to Agent/MCP Action", names)
        self.assertIn("LLM + RAG Surface - Retrieval Context Extraction and Poisoning Candidate", names)
        self.assertIn("MLflow + Model Server - Artifact Consumer Path", names)
        self.assertIn("Notebook + ML Platform - Credential and Artifact Pivot", names)


class AgentProfileTests(unittest.TestCase):
    def test_framework_less_agent_emits_generic_ai_agent_finding(self):
        payload = {
            "tool": "one-shot-enum", "type": "llm_enum",
            "host": "192.168.167.21", "port": 8001,
            "base_url": "http://192.168.167.21:8001",
            "endpoints": [{"method": "POST", "path": "/kb/search"}, {"method": "POST", "path": "/browse"}],
            "ai_surfaces": [],
            "agent_profile": {
                "role": "Knowledge Base / RAG agent",
                "capabilities": ["knowledge-base", "web-browsing", "tool-calling"],
                "evidence": {"knowledge-base": ["/kb/search"]},
            },
        }
        path = _write(json.dumps(payload))
        try:
            findings = parse_llm_enum_json(path)
        finally:
            Path(path).unlink(missing_ok=True)

        validate_findings(findings)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["name"], "ai-agent")
        self.assertEqual(findings[0]["attributes"]["agent_role"], "Knowledge Base / RAG agent")
        self.assertIn("knowledge-base", findings[0]["attributes"]["agent_capabilities"])

    def test_agent_role_attached_to_framework_surface(self):
        payload = {
            "tool": "one-shot-enum", "type": "llm_enum", "host": "h", "port": 8000,
            "base_url": "http://h:8000",
            "ai_surfaces": [{"key": "openai-compatible", "label": "x", "confidence": "high"}],
            "agent_profile": {"role": "Tool-orchestration agent", "capabilities": ["tool-calling"], "evidence": {}},
        }
        path = _write(json.dumps(payload))
        try:
            findings = parse_llm_enum_json(path)
        finally:
            Path(path).unlink(missing_ok=True)
        self.assertEqual(findings[0]["attributes"]["agent_role"], "Tool-orchestration agent")

    def test_ai_agent_rule_fires(self):
        synth = AttackPathSynthesizer(rules_file_path=RULES_FILE)
        finding = {"host": "192.168.167.21", "port": 8001, "source_tool": "one-shot-enum-llm",
                   "entity_type": "ai_service", "name": "ai-agent", "version": None,
                   "attributes": {"base_url": "http://192.168.167.21:8001",
                                  "agent_role": "Knowledge Base / RAG agent",
                                  "agent_capabilities": ["knowledge-base"], "score": 70}}
        names = [p["name"] for p in synth.generate_attack_paths([finding])]
        self.assertIn("AI Agent - Capability & Tool Abuse", names)


class AgentArchetypeTests(unittest.TestCase):
    """Framework-less agents are classified into archetype-specific findings
    (multi-agent/A2A, NL-to-SQL) that fire archetype-specific attack paths, while
    still triggering the generic capability-abuse rule (contains match)."""

    def _parse(self, architecture, capabilities, role="AI agent"):
        payload = {
            "tool": "one-shot-enum", "type": "llm_enum", "host": "10.0.0.5", "port": 8000,
            "base_url": "http://10.0.0.5:8000", "ai_surfaces": [],
            "agent_profile": {"role": role, "architecture": architecture,
                              "framework": "Google A2A" if architecture == "multi-agent" else "",
                              "capabilities": capabilities, "evidence": {}},
        }
        path = _write(json.dumps(payload))
        try:
            return parse_llm_enum_json(path)
        finally:
            Path(path).unlink(missing_ok=True)

    def test_multi_agent_emits_a2a_finding(self):
        findings = self._parse("multi-agent", ["agent-discovery", "orchestration"],
                               role="A2A / multi-agent system")
        self.assertEqual(findings[0]["name"], "ai-agent-a2a")
        self.assertEqual(findings[0]["attributes"]["agent_architecture"], "multi-agent")
        self.assertEqual(findings[0]["attributes"]["agent_framework"], "Google A2A")

    def test_database_agent_emits_sql_finding(self):
        findings = self._parse("single-agent", ["database", "conversational"],
                               role="Database / NL-to-SQL agent")
        self.assertEqual(findings[0]["name"], "ai-agent-sql")

    def test_vector_store_emits_generic_ai_agent(self):
        findings = self._parse("vector-store", ["vector-store"], role="Embedding / vector store")
        self.assertEqual(findings[0]["name"], "ai-agent")

    def test_archetype_and_generic_rules_fire(self):
        synth = AttackPathSynthesizer(rules_file_path=RULES_FILE)
        base = {"host": "10.0.0.5", "port": 8000, "source_tool": "one-shot-enum-llm",
                "entity_type": "ai_service", "version": None}
        a2a = {**base, "name": "ai-agent-a2a",
               "attributes": {"base_url": "http://10.0.0.5:8000", "agent_role": "A2A / multi-agent system",
                              "agent_architecture": "multi-agent", "agent_framework": "Google A2A",
                              "agent_capabilities": ["agent-discovery"], "score": 70}}
        sql = {**base, "name": "ai-agent-sql",
               "attributes": {"base_url": "http://10.0.0.5:8000", "agent_role": "Database / NL-to-SQL agent",
                              "agent_architecture": "single-agent", "agent_framework": "",
                              "agent_capabilities": ["database"], "score": 70}}
        names = [p["name"] for p in synth.generate_attack_paths([a2a, sql])]
        self.assertIn("A2A / Multi-Agent System - Rogue Registration & Workflow Abuse", names)
        self.assertIn("LLM-to-SQL Agent - Generated Query to Database Command Execution", names)
        # The generic rule uses a "contains ai-agent" match, so it still fires for both.
        self.assertGreaterEqual(names.count("AI Agent - Capability & Tool Abuse"), 2)

    def _parse_with_framework(self, architecture, capabilities, role="AI agent"):
        """Same as _parse but the service also exposes a framework surface, so the
        archetype must be emitted *in addition* to it (not gated behind 'no findings')."""
        payload = {
            "tool": "one-shot-enum", "type": "llm_enum", "host": "10.0.0.5", "port": 8000,
            "base_url": "http://10.0.0.5:8000",
            "ai_surfaces": [{"key": "openai-compatible", "label": "OpenAI-compatible LLM API",
                             "confidence": "high", "evidence": ["/v1/chat/completions"]}],
            "agent_profile": {"role": role, "architecture": architecture,
                              "framework": "Google A2A" if architecture == "multi-agent" else "",
                              "capabilities": capabilities, "evidence": {}},
        }
        path = _write(json.dumps(payload))
        try:
            return [f["name"] for f in parse_llm_enum_json(path)]
        finally:
            Path(path).unlink(missing_ok=True)

    def test_a2a_archetype_emitted_alongside_framework(self):
        names = self._parse_with_framework("multi-agent", ["orchestration"])
        self.assertIn("openai-compatible", names)
        self.assertIn("ai-agent-a2a", names)

    def test_sql_archetype_emitted_alongside_framework(self):
        names = self._parse_with_framework("single-agent", ["database", "conversational"])
        self.assertIn("openai-compatible", names)
        self.assertIn("ai-agent-sql", names)

    def test_generic_ai_agent_not_added_when_framework_present(self):
        # A plain framework service with no distinguishing archetype must NOT get a
        # generic ai-agent finding - that would fire the generic rule on every LLM API.
        names = self._parse_with_framework("single-agent", ["conversational"])
        self.assertIn("openai-compatible", names)
        self.assertNotIn("ai-agent", names)


class VectorStoreAndActiveTests(unittest.TestCase):
    """Unauthenticated vector-store enumeration and active (--ai-active) MCP/A2A
    confirmation flow through the parser into dedicated findings and attack paths."""

    def _parse(self, payload):
        path = _write(json.dumps(payload))
        try:
            return parse_llm_enum_json(path)
        finally:
            Path(path).unlink(missing_ok=True)

    def test_unauth_vector_store_emits_finding(self):
        findings = self._parse({
            "tool": "one-shot-enum", "type": "llm_enum", "host": "10.10.50.20", "port": 6333,
            "base_url": "http://10.10.50.20:6333", "ai_surfaces": [],
            "vector_store": {"engine": "Qdrant", "url": "http://10.10.50.20:6333/collections",
                             "collections": ["detection_rules", "runbook_corpus"],
                             "collection_count": 2, "unauthenticated": True},
        })
        names = [f["name"] for f in findings]
        self.assertIn("vector-store-open", names)
        vs = next(f for f in findings if f["name"] == "vector-store-open")
        self.assertEqual(vs["attributes"]["vector_store_engine"], "Qdrant")
        self.assertEqual(vs["attributes"]["vector_store_collections"], ["detection_rules", "runbook_corpus"])

    def test_confirmed_mcp_tools_emit_finding_and_enrich_surface(self):
        findings = self._parse({
            "tool": "one-shot-enum", "type": "llm_enum", "host": "10.10.50.15", "port": 9005,
            "base_url": "http://10.10.50.15:9005",
            "ai_surfaces": [{"key": "agent-mcp", "label": "MCP", "confidence": "high"}],
            "mcp_tools": {"url": "http://10.10.50.15:9005/mcp", "path": "/mcp", "tool_count": 2, "tools": [
                {"name": "aws_cli_exec", "description": "Execute AWS CLI", "categories": ["code-execution"]},
                {"name": "vault_rotate_secret", "description": "Rotate Vault", "categories": ["secrets/identity"]}]},
        })
        confirmed = next(f for f in findings if f["name"] == "mcp-tools-confirmed")
        self.assertEqual(confirmed["attributes"]["confirmed_mcp_tools"], ["aws_cli_exec", "vault_rotate_secret"])
        surface = next(f for f in findings if f["name"] == "agent-mcp")
        self.assertIn("code-execution", surface["attributes"]["confirmed_mcp_categories"])

    def test_new_rules_fire_with_atlas(self):
        synth = AttackPathSynthesizer(rules_file_path=RULES_FILE)
        base = {"host": "h", "port": 1, "source_tool": "x", "entity_type": "ai_service", "version": None}
        vs = {**base, "name": "vector-store-open",
              "attributes": {"base_url": "http://h", "vector_store_engine": "Qdrant",
                             "vector_store_url": "http://h/collections", "vector_store_collections": ["c"],
                             "vector_store_collection_count": 1, "score": 90}}
        mcp = {**base, "name": "mcp-tools-confirmed",
               "attributes": {"base_url": "http://h", "mcp_url": "http://h/mcp",
                              "confirmed_mcp_tools": ["shell_exec"], "confirmed_mcp_categories": ["code-execution"], "score": 90}}
        paths = synth.generate_attack_paths([vs, mcp])
        by_name = {p["name"]: p for p in paths}
        self.assertIn("Unauthenticated Vector Store - Knowledge Base Extraction", by_name)
        self.assertIn("Confirmed MCP Tool Inventory - Targeted Capability Abuse", by_name)
        # Every AI path carries MITRE ATLAS tags.
        self.assertTrue(by_name["Unauthenticated Vector Store - Knowledge Base Extraction"]["atlas"])


class InjectionExampleTests(unittest.TestCase):
    def setUp(self):
        self.synth = AttackPathSynthesizer(rules_file_path=RULES_FILE)

    def _paths(self, name, **attrs):
        f = {"host": "h", "port": 8000, "source_tool": "x", "entity_type": "ai_service",
             "name": name, "version": None, "attributes": {"base_url": "http://h:8000", "score": 70, **attrs}}
        return self.synth.generate_attack_paths([f])

    def test_llm_api_rule_carries_injection_examples(self):
        p = next(x for x in self._paths("openai-compatible") if "Prompt Injection" in x["name"])
        self.assertTrue(p["suggestion"].get("injection_examples"))

    def test_ssti_payload_survives_placeholder_resolution(self):
        # The {{ ... }} SSTI probe must not be mangled by the {trigger.N.x} resolver.
        p = next(x for x in self._paths("mcp-tools-confirmed", mcp_url="http://h/mcp",
                                        confirmed_mcp_tools=["render_report"], confirmed_mcp_categories=["code-execution"])
                 if "Confirmed MCP" in x["name"])
        joined = " ".join(p["suggestion"]["injection_examples"])
        self.assertIn("{{ lipsum.__globals__", joined)

    def test_agent_rule_has_tool_call_coercion(self):
        p = next(x for x in self._paths("agent-mcp") if "Agent/MCP" in x["name"])
        joined = " ".join(p["suggestion"]["injection_examples"]).lower()
        self.assertIn("tool call", joined)


if __name__ == "__main__":
    unittest.main()
