import json
import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from main.attack_path_synthesizer import AttackPathSynthesizer
from main.finding_schema import validate_findings
from main.pathfinder import _sniff_file_type
from parsers.post_exploitation.ai_loot_parser import parse_ai_loot_json
ROOT = Path(__file__).parent.parent
COLLECTOR = ROOT / "tools" / "ai-peas.py"
RULES_FILE = str(ROOT / "main" / "attack_rules.json")
_SPEC = importlib.util.spec_from_file_location("pathfinder_ai_peas", COLLECTOR)
_AI_PEAS = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_AI_PEAS)
clean_snippet = _AI_PEAS.clean_snippet


class AiLootCollectorTests(unittest.TestCase):
    def _fixture_tree(self, root):
        app = root / "app"
        app.mkdir()
        (app / ".env").write_text(
            "\n".join([
                "OPENAI_API_KEY=sk-supersecret",
                "QDRANT_URL=http://127.0.0.1:6333",
                "MLFLOW_TRACKING_URI=http://mlflow.local:5000",
                "AWS_ENDPOINT_URL=http://minio.local:9000",
                "JUPYTER_TOKEN=notebook-token",
            ]),
            encoding="utf-8",
        )
        (app / "tools.json").write_text(json.dumps({
            "mcpServers": {"ops": {"command": "python", "args": ["server.py"]}},
            "tools": [{"name": "read_file", "description": "Read filesystem path"}],
        }), encoding="utf-8")
        (app / "system_prompt.md").write_text(
            "You are a remediation agent. Use read_file only for approved paths.\n",
            encoding="utf-8",
        )
        (app / "loader.py").write_text(
            "import torch\nmodel = torch.load(model_path)\n",
            encoding="utf-8",
        )
        (app / "model.pkl").write_bytes(b"pickle-ish")
        (app / "adapter_config.json").write_text("{}", encoding="utf-8")
        return app

    def test_collector_preserves_discovered_values_by_default(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            app = self._fixture_tree(root)
            out = root / "ai_loot.json"

            proc = subprocess.run(
                [sys.executable, str(COLLECTOR), str(app), "-o", str(out)],
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(payload["type"], "ai_post_exploitation_loot")
            self.assertFalse(payload["options"]["secret_values_redacted"])
            secret = payload["findings"]["secrets"][0]
            self.assertEqual(secret["value"]["value"], "sk-supersecret")
            self.assertIn("sk-supersecret", json.dumps(payload))
            self.assertEqual(payload["stats"]["files_skipped_due_to_errors"], 0)
            self.assertGreaterEqual(len(payload["findings"]["vector_stores"]), 1)
            self.assertGreaterEqual(len(payload["findings"]["mcp_tools"]), 1)
            self.assertGreaterEqual(len(payload["findings"]["unsafe_loaders"]), 1)
            self.assertEqual(_sniff_file_type(str(out)), "ai_loot_json")

    def test_parser_and_rules_consume_collector_output(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            app = self._fixture_tree(root)
            out = root / "ai_loot.json"
            subprocess.run([sys.executable, str(COLLECTOR), str(app), "-o", str(out)], check=True)

            findings = parse_ai_loot_json(str(out))
            validate_findings(findings)
            names = {finding["name"] for finding in findings}
            self.assertIn("ai_secret_reference", names)
            self.assertIn("vector_store_config_found", names)
            self.assertIn("mcp_tool_manifest_found", names)
            self.assertIn("unsafe_model_loader_found", names)
            self.assertIn("writable_ai_artifact_found", names)

            synth = AttackPathSynthesizer(rules_file_path=RULES_FILE)
            paths = synth.generate_attack_paths(findings)
            path_names = {path["name"] for path in paths}
            self.assertIn("AI Loot - Platform Secrets and Tokens Found", path_names)
            self.assertIn("AI Loot - MLflow and Object Store Artifact Chain", path_names)
            self.assertIn("AI Loot - Unsafe Model Loader Found", path_names)

    def test_parser_prefers_supplied_host_context(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            out = root / "ai_loot.json"
            out.write_text(json.dumps({
                "type": "ai_post_exploitation_loot",
                "schema_version": "1.0",
                "host": "target-self-name",
                "findings": {
                    "secrets": [{"path": "app/.env", "name": "OPENAI_API_KEY"}],
                },
            }), encoding="utf-8")

            findings = parse_ai_loot_json(str(out), target_host="192.0.2.10")
            self.assertTrue(findings)
            self.assertEqual({f["host"] for f in findings}, {"192.0.2.10"})

    def test_snippets_preserve_values_by_default_and_support_opt_in_redaction(self):
        line = "custom_token: sk-supersecretvalue and access=AKIA1234567890ABCDEF"
        self.assertEqual(clean_snippet(line), line)
        cleaned = clean_snippet(line, redact_secret_values=True)
        self.assertNotIn("sk-supersecretvalue", cleaned)
        self.assertNotIn("AKIA1234567890ABCDEF", cleaned)
        self.assertIn("<redacted-token>", cleaned)

    def test_collector_can_redact_values_when_explicitly_requested(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            app = self._fixture_tree(root)
            out = root / "ai_loot.json"

            proc = subprocess.run(
                [sys.executable, str(COLLECTOR), str(app),
                 "--redact-secret-values", "-o", str(out)],
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(out.read_text(encoding="utf-8"))
            self.assertTrue(payload["options"]["secret_values_redacted"])
            self.assertNotIn("sk-supersecret", json.dumps(payload))
            self.assertTrue(payload["findings"]["secrets"][0]["value"]["redacted"])

    def test_collector_survives_bad_json_file(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            app = root / "app"
            app.mkdir()
            (app / "broken.json").write_text("[" * 6000 + "0" + "]" * 6000, encoding="utf-8")
            (app / ".env").write_text("OPENAI_API_KEY=sk-still-redacted\n", encoding="utf-8")
            out = root / "ai_loot.json"

            proc = subprocess.run(
                [sys.executable, str(COLLECTOR), str(app), "-o", str(out)],
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(out.read_text(encoding="utf-8"))
            self.assertGreaterEqual(len(payload["findings"]["secrets"]), 1)

    def test_scan_mode_sniffs_ai_loot_json(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as tmp:
            json.dump({"type": "ai_post_exploitation_loot", "findings": {}}, tmp)
            path = tmp.name
        self.addCleanup(lambda: Path(path).unlink(missing_ok=True))

        self.assertEqual(_sniff_file_type(path), "ai_loot_json")

if __name__ == "__main__":
    unittest.main()
