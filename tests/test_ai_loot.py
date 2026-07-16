import json
import importlib.util
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from main.attack_path_synthesizer import AttackPathSynthesizer
from main.finding_schema import validate_findings
from main.pathfinder import _sniff_file_type
from parsers.post_exploitation.ai_peas_parser import parse_ai_loot_json
ROOT = Path(__file__).parent.parent
COLLECTOR = ROOT / "tools" / "ai-peas.py"
RULES_FILE = str(ROOT / "main" / "attack_rules.json")
_SPEC = importlib.util.spec_from_file_location("pathfinder_ai_peas", COLLECTOR)
_AI_PEAS = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_AI_PEAS)
clean_snippet = _AI_PEAS.clean_snippet
load_text = _AI_PEAS.load_text


class AiLootCollectorTests(unittest.TestCase):
    def test_load_text_rejects_directories_and_samples_oversized_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate = root / "config.json"
            self.assertIsNone(load_text(root, 10))
            candidate.write_bytes(b"HEAD" + b"x" * 100 + b"TAIL")
            sampled = load_text(candidate, 20)
            self.assertIn("HEAD", sampled)
            self.assertIn("TAIL", sampled)
            self.assertIn("omitted middle", sampled)
            candidate.write_bytes(b"x" * 10)
            self.assertEqual(load_text(candidate, 10), "x" * 10)

    def test_default_output_uses_ai_peas_name(self):
        self.assertEqual(_AI_PEAS.DEFAULT_OUTPUT, "ai-peas-loot.json")

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
            secret = next(item for item in payload["findings"]["secrets"]
                          if item["name"] == "OPENAI_API_KEY")
            self.assertEqual(secret["value"]["value"], "sk-supersecret")
            self.assertIn("sk-supersecret", json.dumps(payload))
            self.assertEqual(payload["stats"]["files_skipped_due_to_errors"], 0)
            self.assertGreaterEqual(len(payload["findings"]["vector_stores"]), 1)
            self.assertGreaterEqual(len(payload["findings"]["mcp_tools"]), 1)
            self.assertGreaterEqual(len(payload["findings"]["unsafe_loaders"]), 1)
            self.assertGreaterEqual(len(payload["findings"]["config_refs"]), 1)
            self.assertGreaterEqual(len(payload["findings"]["application_chains"]), 1)
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
            secret = next(item for item in payload["findings"]["secrets"]
                          if item["name"] == "OPENAI_API_KEY")
            self.assertTrue(secret["value"]["redacted"])

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

    def test_notebook_cells_and_new_provider_secrets_are_collected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            notebook = root / "analysis.ipynb"
            notebook.write_text(json.dumps({
                "cells": [{
                    "cell_type": "code",
                    "source": [
                        "GROQ_API_KEY='groq-secret-value'\n",
                        "vector_store = Qdrant(url='http://qdrant:6333')\n",
                    ],
                    "outputs": [{"output_type": "stream", "text": "x" * (600 * 1024)}],
                }],
                "metadata": {"kernelspec": {"name": "python3"}},
            }), encoding="utf-8")
            out = root / "loot.json"

            subprocess.run(
                [sys.executable, str(COLLECTOR), str(root), "--quiet", "-o", str(out)],
                check=True,
            )
            payload = json.loads(out.read_text(encoding="utf-8"))
            self.assertTrue(payload["findings"]["notebooks"])
            self.assertGreater(notebook.stat().st_size, 512 * 1024)
            names = {item["name"] for item in payload["findings"]["secrets"]}
            self.assertIn("GROQ_API_KEY", names)
            self.assertTrue(payload["findings"]["vector_stores"])

    def test_noise_is_not_promoted_as_ai_evidence(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "general.py").write_text(
                "import subprocess\nsubprocess.run(['echo', 'hello'])\nchunks = 3\n",
                encoding="utf-8",
            )
            (root / "server.conf").write_text(
                "listen=localhost:8080\nsearch=localhost:9200\n", encoding="utf-8"
            )
            (root / "ordinary.csv").write_text("name,value\na,1\n", encoding="utf-8")
            out = root / "loot.json"

            subprocess.run(
                [sys.executable, str(COLLECTOR), str(root), "--quiet", "-o", str(out)],
                check=True,
            )
            findings = json.loads(out.read_text(encoding="utf-8"))["findings"]
            self.assertFalse(findings["unsafe_loaders"])
            self.assertFalse(findings["rag_sources"])
            self.assertFalse(findings["vector_stores"])
            self.assertFalse(findings["model_artifacts"])

    def test_generic_subprocess_in_ai_source_is_not_an_unsafe_model_loader(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "ai_agent.py").write_text(
                "import subprocess\nsubprocess.run(['worker', '--health'])\n",
                encoding="utf-8",
            )
            out = root / "loot.json"
            subprocess.run(
                [sys.executable, str(COLLECTOR), str(root), "--quiet", "-o", str(out)],
                check=True,
            )
            findings = json.loads(out.read_text(encoding="utf-8"))["findings"]
            self.assertFalse(findings["unsafe_loaders"])

    def test_relevant_files_are_prioritized_before_max_files(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for index in range(8):
                (root / f"z{index}.txt").write_text("ordinary text", encoding="utf-8")
            (root / "system_prompt.md").write_text("system_prompt=important", encoding="utf-8")
            selected, candidates, limited = _AI_PEAS.walk_paths([str(root)], 3)
            self.assertTrue(limited)
            self.assertGreater(candidates, len(selected))
            self.assertIn("system_prompt.md", {path.name for path in selected})

    def test_secret_mount_kube_files_and_systemd_units_are_candidates(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            service_account = root / "var" / "run" / "secrets" / "kubernetes.io" / "serviceaccount"
            service_account.mkdir(parents=True)
            token = service_account / "token"
            namespace = service_account / "namespace"
            unit = root / "rag-worker.service"
            token.write_text("eyJhbGciOiJub25lIn0.eyJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6bWw6cmFnIn0.", encoding="utf-8")
            namespace.write_text("ml", encoding="utf-8")
            unit.write_text("[Service]\nExecStart=/opt/rag/worker.py\n", encoding="utf-8")

            selected, _, _ = _AI_PEAS.walk_paths([str(root)], 20)
            selected_paths = {path.resolve() for path in selected}
            self.assertIn(token.resolve(), selected_paths)
            self.assertIn(namespace.resolve(), selected_paths)
            self.assertIn(unit.resolve(), selected_paths)

    def test_collector_inspects_local_rag_sqlite_and_mcp_source(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            app = root / "rag-app"
            app.mkdir()
            database = app / "chroma.sqlite3"
            connection = sqlite3.connect(database)
            connection.execute("CREATE TABLE embeddings (document TEXT, metadata TEXT)")
            connection.execute(
                "INSERT INTO embeddings VALUES (?, ?)",
                ("internal deployment runbook", '{"source":"runbook.md"}'),
            )
            connection.commit()
            connection.close()
            (app / "server.py").write_text(
                "from fastmcp import FastMCP\n"
                "mcp = FastMCP('ops')\n"
                "@mcp.tool()\n"
                "def read_runbook(path: str):\n"
                "    '''Read an approved filesystem runbook.'''\n"
                "    return open(path).read()\n",
                encoding="utf-8",
            )
            out = root / "loot.json"

            subprocess.run(
                [sys.executable, str(COLLECTOR), str(app), "--quiet", "-o", str(out)],
                check=True,
            )
            findings = json.loads(out.read_text(encoding="utf-8"))["findings"]
            self.assertTrue(findings["rag_stores"])
            self.assertIn("embeddings", findings["rag_stores"][0]["tables"])
            self.assertIn("internal deployment runbook", json.dumps(findings["rag_stores"]))
            source_tool = next(item for item in findings["mcp_tools"]
                               if item.get("name") == "read_runbook")
            self.assertEqual(source_tool["context"], "python-source")
            self.assertIn("filesystem", source_tool["risk_categories"])

    def test_collector_records_git_branches_packages_and_non_sql_rag_stores(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            app = root / "ai-app"
            (app / ".git" / "refs" / "heads").mkdir(parents=True)
            (app / ".git" / "HEAD").write_text("ref: refs/heads/dev\n", encoding="utf-8")
            (app / ".git" / "refs" / "heads" / "dev").write_text("a" * 40, encoding="ascii")
            (app / ".git" / "config").write_text(
                "[remote \"origin\"]\n"
                "    url = https://gitlab.example/ai/app.git\n",
                encoding="utf-8",
            )
            (app / "rag.index.faiss").write_bytes(b"FAISS")
            package = app / "agent_tools.whl"
            with zipfile.ZipFile(package, "w") as archive:
                archive.writestr("agent_tools/plugin.py", "def tool(): pass")
                archive.writestr("agent_tools-1.0.dist-info/entry_points.txt", "[console_scripts]")
            out = root / "loot.json"

            subprocess.run(
                [sys.executable, str(COLLECTOR), str(app), "--quiet", "-o", str(out)],
                check=True,
            )
            findings = json.loads(out.read_text(encoding="utf-8"))["findings"]
            self.assertEqual(findings["developer_context"][0]["current_branch"], "dev")
            self.assertIn("dev", findings["developer_context"][0]["branches"])
            self.assertTrue(findings["rag_stores"])
            package_record = next(item for item in findings["model_artifacts"]
                                  if item["path"].endswith("agent_tools.whl"))
            self.assertIn("agent_tools/plugin.py", package_record["interesting_members"])

    def test_parser_surfaces_new_exam_context_categories(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "loot.json"
            out.write_text(json.dumps({
                "type": "ai_post_exploitation_loot",
                "schema_version": "1.2",
                "host": "exam-host",
                "findings": {
                    "listeners": [{
                        "path": "listener:127.0.0.1:6333", "address": "127.0.0.1",
                        "port": 6333, "process_name": "qdrant",
                    }],
                    "cloud_identities": [{
                        "path": "/var/run/secrets/kubernetes.io/serviceaccount/token",
                        "kind": "kubernetes-service-account",
                    }],
                    "rag_stores": [{
                        "path": "/opt/rag/chroma.sqlite3", "kind": "sqlite-rag-store",
                        "tables": ["embeddings"], "writable": True,
                    }],
                    "pipeline_consumers": [{
                        "path": "/opt/rag/ingest.py", "signal": "DirectoryLoader",
                        "writable": True,
                    }],
                    "guardrail_rules": [{
                        "path": "/opt/rag/config.yml", "writable": True,
                    }],
                    "developer_context": [{
                        "path": "/opt/rag", "kind": "git-repository",
                        "current_branch": "dev",
                        "remotes": ["https://gitlab.example/rag.git"],
                    }],
                },
            }), encoding="utf-8")

            findings = parse_ai_loot_json(str(out))
            names = {finding["name"] for finding in findings}
            self.assertIn("ai_local_listener_found", names)
            self.assertIn("ai_cloud_identity_found", names)
            self.assertIn("local_rag_store_found", names)
            self.assertIn("ai_pipeline_consumer_found", names)
            self.assertIn("ai_guardrail_rule_found", names)
            self.assertIn("ai_developer_context_found", names)
            paths = AttackPathSynthesizer(rules_file_path=RULES_FILE).generate_attack_paths(findings)
            path_names = {path["name"] for path in paths}
            self.assertIn("AI Loot - Local Service and Workload Identity Pivot", path_names)
            self.assertIn("AI Loot - Local RAG Plaintext and Ingestion Path", path_names)

    def test_parser_exposes_config_runtime_and_correlated_chain_findings(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            app = root / "app"
            app.mkdir()
            (app / "docker-compose.yml").write_text(
                "services:\n  rag:\n    environment:\n"
                "      OPENROUTER_API_KEY: secret-value\n"
                "      QDRANT_URL: http://qdrant:6333\n",
                encoding="utf-8",
            )
            out = root / "loot.json"
            subprocess.run(
                [sys.executable, str(COLLECTOR), str(app), "--quiet", "-o", str(out)],
                check=True,
            )
            payload = json.loads(out.read_text(encoding="utf-8"))
            payload["findings"]["runtime_context"].append({
                "path": "process:42", "kind": "running-process", "process_name": "ollama.exe"
            })
            out.write_text(json.dumps(payload), encoding="utf-8")

            findings = parse_ai_loot_json(str(out))
            names = {finding["name"] for finding in findings}
            self.assertIn("ai_config_inventory", names)
            self.assertIn("ai_runtime_context_found", names)
            self.assertIn("ai_application_chain_found", names)
            paths = AttackPathSynthesizer(rules_file_path=RULES_FILE).generate_attack_paths(findings)
            path_names = {path["name"] for path in paths}
            self.assertIn("AI Loot - Deployment and Runtime Configuration", path_names)
            self.assertIn("AI Loot - Active Runtime Context", path_names)
            self.assertIn("AI Loot - Correlated Application Control-Plane Chain", path_names)

if __name__ == "__main__":
    unittest.main()
