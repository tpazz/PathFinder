import json
import tempfile
import unittest
from pathlib import Path

from main.attack_path_synthesizer import AttackPathSynthesizer

# Load the production rules for integration tests.
PRODUCTION_RULES = Path(__file__).parent.parent / "main" / "attack_rules.json"


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

    def test_production_rules_all_valid(self):
        """All rules in attack_rules.json must pass validation."""
        synth = AttackPathSynthesizer(rules_file_path=str(PRODUCTION_RULES))
        with open(PRODUCTION_RULES, 'r') as f:
            total_rules = len(json.load(f))
        self.assertEqual(len(synth.rules), total_rules,
                         f"Expected {total_rules} valid rules, but only {len(synth.rules)} passed validation")

    def test_sqli_to_shell_rule_fires(self):
        """SQL injection rule should fire when a sql_injection_found finding is present."""
        synth = AttackPathSynthesizer(rules_file_path=str(PRODUCTION_RULES))
        findings = [
            {
                "host": "10.10.10.10", "port": 80, "source_tool": "sqlmap",
                "entity_type": "vulnerability", "name": "sql_injection_found", "version": None,
                "attributes": {"parameter": "id", "url": "http://10.10.10.10/item.php?id=1", "score": 85},
            },
        ]
        paths = synth.generate_attack_paths(findings)
        sqli_paths = [p for p in paths if "SQL Injection" in p["name"]]
        self.assertGreaterEqual(len(sqli_paths), 1)

    def test_kerberoast_rule_fires(self):
        """Kerberoastable user rule should fire."""
        synth = AttackPathSynthesizer(rules_file_path=str(PRODUCTION_RULES))
        findings = [
            {
                "host": "LAB.LOCAL", "port": 88, "source_tool": "sharphound",
                "entity_type": "privilege_escalation", "name": "kerberoastable_user", "version": None,
                "attributes": {"user": "svc_sql@LAB.LOCAL", "score": 95},
            },
        ]
        paths = synth.generate_attack_paths(findings)
        kerb_paths = [p for p in paths if "Kerberoast" in p["name"]]
        self.assertGreaterEqual(len(kerb_paths), 1)

    def test_suid_rule_fires(self):
        """SUID binary rule should fire."""
        synth = AttackPathSynthesizer(rules_file_path=str(PRODUCTION_RULES))
        findings = [
            {
                "host": "10.10.10.30", "port": None, "source_tool": "linpeas",
                "entity_type": "privilege_escalation", "name": "suid_binary_found", "version": None,
                "attributes": {"description": "/usr/bin/pkexec", "score": 95},
            },
        ]
        paths = synth.generate_attack_paths(findings)
        suid_paths = [p for p in paths if "SUID" in p["name"]]
        self.assertGreaterEqual(len(suid_paths), 1)

    def test_credential_reuse_fires_with_ssh_service(self):
        """Credential reuse rule should fire when cred + SSH service are on same host."""
        synth = AttackPathSynthesizer(rules_file_path=str(PRODUCTION_RULES))
        findings = [
            {
                "host": "MANUALLY_ADDED", "port": None, "source_tool": "manual_input",
                "entity_type": "credential", "name": "admin", "version": None,
                "attributes": {"password": "P@ssw0rd", "score": 100},
            },
            {
                "host": "10.10.10.10", "port": 22, "source_tool": "nmap",
                "entity_type": "service", "name": "ssh", "version": None,
                "attributes": {"score": 10},
            },
        ]
        paths = synth.generate_attack_paths(findings)
        cred_paths = [p for p in paths if "Credential Reuse on Login Service" in p["name"]]
        self.assertGreaterEqual(len(cred_paths), 1)


if __name__ == "__main__":
    unittest.main()
