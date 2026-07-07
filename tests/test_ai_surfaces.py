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


if __name__ == "__main__":
    unittest.main()
