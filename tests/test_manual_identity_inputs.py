import json
import tempfile
import unittest
from pathlib import Path

from main.attack_path_synthesizer import AttackPathSynthesizer
from main.pathfinder import deduplicate_findings
from main import vulnerability_mapper as vm_module
from main.vulnerability_mapper import VulnerabilityMapper


RULES_FILE = str(Path(__file__).parent.parent / "main" / "attack_rules.json")


def _finding(host, port, etype, name, **attrs):
    return {
        "host": host,
        "port": port,
        "source_tool": "test",
        "entity_type": etype,
        "name": name,
        "version": None,
        "attributes": attrs,
    }


class ManualIdentityInputTests(unittest.TestCase):
    def test_manual_entries_become_credentials_users_and_password_candidates(self):
        entries = [
            {"kind": "credential", "username": "alice", "password": "Welcome1", "hash": None, "hash_type": None, "source": "notes.txt"},
            {"kind": "user", "username": "bob", "password": None, "hash": None, "hash_type": None, "source": "kerbrute"},
            {"kind": "password_candidate", "username": None, "password": "Summer2026!", "hash": None, "hash_type": None, "source": "config.php"},
        ]
        with tempfile.TemporaryDirectory() as d:
            cred_file = Path(d) / "credentials.json"
            cred_file.write_text(json.dumps(entries), encoding="utf-8")
            original = vm_module.CREDENTIALS_FILE
            vm_module.CREDENTIALS_FILE = str(cred_file)
            try:
                findings = VulnerabilityMapper(use_github=False, use_searchsploit=False)._load_manual_credentials()
            finally:
                vm_module.CREDENTIALS_FILE = original

        by_type = {f["entity_type"]: f for f in findings}
        self.assertEqual(by_type["credential"]["name"], "alice")
        self.assertEqual(by_type["credential"]["attributes"]["password"], "Welcome1")
        self.assertEqual(by_type["confirmed_username"]["name"], "bob")
        self.assertEqual(by_type["password_candidate"]["name"], "manual_password_candidate")
        self.assertEqual(by_type["password_candidate"]["attributes"]["password"], "Summer2026!")

    def test_legacy_username_only_entry_becomes_user(self):
        entries = [{"username": "charlie", "password": None, "hash": None, "hash_type": None, "source": "manual"}]
        with tempfile.TemporaryDirectory() as d:
            cred_file = Path(d) / "credentials.json"
            cred_file.write_text(json.dumps(entries), encoding="utf-8")
            original = vm_module.CREDENTIALS_FILE
            vm_module.CREDENTIALS_FILE = str(cred_file)
            try:
                findings = VulnerabilityMapper(use_github=False, use_searchsploit=False)._load_manual_credentials()
            finally:
                vm_module.CREDENTIALS_FILE = original

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["entity_type"], "confirmed_username")
        self.assertEqual(findings[0]["name"], "charlie")

    def test_password_candidates_deduplicate_by_secret(self):
        findings = [
            _finding("MANUALLY_ADDED", None, "password_candidate", "manual_password_candidate", password="OnePass!"),
            _finding("MANUALLY_ADDED", None, "password_candidate", "manual_password_candidate", password="TwoPass!"),
            _finding("MANUALLY_ADDED", None, "password_candidate", "manual_password_candidate", password="OnePass!"),
        ]
        out = deduplicate_findings(findings)
        self.assertEqual(len(out), 2)
        self.assertEqual({f["attributes"]["password"] for f in out}, {"OnePass!", "TwoPass!"})

    def test_password_candidate_requires_user_and_login_service_for_spray_path(self):
        findings = [
            _finding("MANUALLY_ADDED", None, "password_candidate", "manual_password_candidate",
                     password="Summer2026!", source_of_credential="config.php", confidence="medium"),
            _finding("dc", None, "confirmed_username", "alice"),
            _finding("dc", 445, "service", "microsoft-ds"),
        ]
        paths = AttackPathSynthesizer(RULES_FILE).generate_attack_paths(findings)
        names = [p["name"] for p in paths]
        self.assertIn("Password Candidate + Enumerated User - Lockout-Aware Spray", names)
        self.assertNotIn("Credential Reuse on Login Service", names)

    def test_password_candidate_alone_does_not_fire(self):
        findings = [
            _finding("MANUALLY_ADDED", None, "password_candidate", "manual_password_candidate",
                     password="Summer2026!", source_of_credential="config.php"),
        ]
        paths = AttackPathSynthesizer(RULES_FILE).generate_attack_paths(findings)
        self.assertFalse(any("Password Candidate" in p["name"] for p in paths))

    def test_password_candidate_can_suggest_default_service_accounts(self):
        findings = [
            _finding("MANUALLY_ADDED", None, "password_candidate", "manual_password_candidate",
                     password="Summer2026!", source_of_credential="config.php"),
            _finding("db", 5432, "service", "postgresql"),
        ]
        paths = AttackPathSynthesizer(RULES_FILE).generate_attack_paths(findings)
        names = [p["name"] for p in paths]
        self.assertIn("Password Candidate + Default Service Account - Manual Check", names)
        self.assertNotIn("Credential Reuse on Login Service", names)

    def test_password_candidate_can_suggest_web_default_user_check(self):
        findings = [
            _finding("MANUALLY_ADDED", None, "password_candidate", "manual_password_candidate",
                     password="Summer2026!", source_of_credential="config.php"),
            _finding("web", 80, "web_content", "/admin/login"),
        ]
        paths = AttackPathSynthesizer(RULES_FILE).generate_attack_paths(findings)
        names = [p["name"] for p in paths]
        self.assertIn("Password Candidate + Web Login - Manual Default-User Check", names)
        self.assertNotIn("Credential Reuse on Web Login Page", names)

    def test_web_username_candidate_gets_manual_review_path_but_is_not_confirmed(self):
        candidate = _finding(
            "web", 80, "username_candidate", "ts_svc",
            candidate_only=True, requires_manual_validation=True, confidence="high",
            url="http://web/dashboard", evidence="User: ts_svc",
        )
        findings = [candidate, _finding("server", 22, "service", "ssh")]
        paths = AttackPathSynthesizer(RULES_FILE).generate_attack_paths(findings)
        review = [p for p in paths if p["name"] == "Username Candidates for Manual Review"]
        self.assertEqual(len(review), 1)
        self.assertIn("manual review", review[0]["suggestion"]["description"])
        self.assertIn("http://web/dashboard", review[0]["suggestion"]["commands"][0])
        self.assertEqual(candidate["entity_type"], "username_candidate")
        self.assertFalse(any("Discovered User with Weak Password Policy" in p["name"] for p in paths))


if __name__ == "__main__":
    unittest.main()
