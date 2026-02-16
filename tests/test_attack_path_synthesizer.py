import json
import tempfile
import unittest
from pathlib import Path

from main.attack_path_synthesizer import AttackPathSynthesizer


class AttackPathSynthesizerTests(unittest.TestCase):
    def _build_synth(self, rules):
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        json.dump(rules, tmp)
        tmp.close()
        self.addCleanup(lambda: Path(tmp.name).unlink(missing_ok=True))
        return AttackPathSynthesizer(rules_file_path=tmp.name)

    def test_invalid_placeholder_rule_is_skipped(self):
        invalid_rule = {
            "name": "Bad rule",
            "priority": 90,
            "triggers": [{"id": 1, "entity_type": "service", "name_match": {"type": "exact", "value": "ssh"}}],
            "suggestion": {"description": "Use {trigger.2.name}", "rationale": "x", "commands": [], "references": []},
        }
        synth = self._build_synth([invalid_rule])
        self.assertEqual(len(synth.rules), 0)

    def test_any_host_scope_allows_cross_host_path(self):
        rule = {
            "name": "Credential reuse any host",
            "priority": 95,
            "host_scope": "any_host",
            "triggers": [
                {"id": 1, "entity_type": "credential", "name_match": {"type": "exact", "value": "admin"}},
                {"id": 2, "entity_type": "service", "name_match": {"type": "exact", "value": "ssh"}},
            ],
            "suggestion": {
                "description": "Try {trigger.1.name} on {trigger.2.name}",
                "rationale": "re-use",
                "commands": [],
                "references": [],
            },
        }
        synth = self._build_synth([rule])
        findings = [
            {"host": "A", "port": None, "source_tool": "manual_input", "entity_type": "credential", "name": "admin", "version": None, "attributes": {}},
            {"host": "B", "port": 22, "source_tool": "nmap", "entity_type": "service", "name": "ssh", "version": None, "attributes": {}},
        ]

        paths = synth.generate_attack_paths(findings)
        self.assertEqual(len(paths), 1)
        self.assertIn("admin", paths[0]["suggestion"]["description"])


if __name__ == "__main__":
    unittest.main()
