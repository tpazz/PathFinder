import json
import io
import sys
import tempfile
import unittest
from argparse import Namespace
from contextlib import redirect_stdout
from pathlib import Path

from main.attack_path_synthesizer import AttackPathSynthesizer
from main.finding_schema import validate_findings
from main.parser_registry import SPEC_BY_KEY
from main.pathfinder import _attach_discovery_provenance, _sniff_file_type
from parsers.post_exploitation.manual_privesc_parser import parse_manual_privesc_json
from tools.manual_privesc_collector import Collector, _git_loot_search, _windows_writable


ROOT = Path(__file__).parent.parent
RULES_FILE = str(ROOT / "main" / "attack_rules.json")


class ManualPrivilegeEscalationLootTests(unittest.TestCase):
    def _payload(self):
        return {
            "tool": "pathfinder-manual-privesc-collector",
            "type": "pathfinder_manual_privesc_loot",
            "schema_version": "1.0",
            "host": "target-hostname",
            "platform": "linux",
            "user": "www-data",
            "collected_at": "2026-07-14T00:00:00+00:00",
            "command": "python3 manual_privesc_collector.py -o loot.json",
            "options": {"sensitive_values_redacted": False},
            "checks": [
                {
                    "label": "sudo privileges",
                    "command": "sudo -n -l",
                    "returncode": 0,
                },
            ],
            "findings": [
                {
                    "name": "sudo_nopasswd_privileges",
                    "description": "Potentially abusable sudo rule found",
                    "confidence": "high",
                    "evidence": "(root) NOPASSWD: /usr/bin/find",
                },
                {
                    "name": "credential_material_found",
                    "description": "Credential-like material found in /opt/app/.env",
                    "confidence": "high",
                    "evidence": "DATABASE_PASSWORD=LabPassword123!",
                    "path": "/opt/app/.env",
                },
                {
                    "name": "private_key_found",
                    "description": "Readable private key found",
                    "confidence": "high",
                    "evidence": "-----BEGIN OPENSSH PRIVATE KEY-----\nraw-key-data",
                    "path": "/home/alice/.ssh/id_rsa",
                },
            ],
        }

    def _write(self, payload):
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8")
        with tmp:
            json.dump(payload, tmp, indent=2)
        self.addCleanup(lambda: Path(tmp.name).unlink(missing_ok=True))
        return tmp.name

    def test_parser_preserves_raw_evidence_and_target_override(self):
        path = self._write(self._payload())
        findings = parse_manual_privesc_json(path, target_host="192.0.2.50")
        validate_findings(findings)

        self.assertEqual(len(findings), 3)
        self.assertEqual({finding["host"] for finding in findings}, {"192.0.2.50"})
        credential = next(f for f in findings if f["name"] == "credential_material_found")
        self.assertEqual(credential["attributes"]["evidence"], "DATABASE_PASSWORD=LabPassword123!")
        self.assertFalse(credential["attributes"]["sensitive_values_redacted"])
        self.assertEqual(credential["attributes"]["discovery_provenance"][0]["tool"],
                         "manual-privesc-collector")
        self.assertEqual(credential["attributes"]["discovery_command"], self._payload()["command"])

        sudo = next(f for f in findings if f["name"] == "sudo_nopasswd_privileges")
        self.assertEqual(sudo["attributes"]["discovery_command"], "sudo -n -l")

        _attach_discovery_provenance(credential, source_file=path)
        self.assertEqual(len(credential["attributes"]["discovery_provenance"]), 1)
        self.assertNotIn(None, [p.get("command") for p in credential["attributes"]["discovery_provenance"]])

    def test_scan_mode_and_registry_recognize_report(self):
        path = self._write(self._payload())
        self.assertEqual(_sniff_file_type(path), "manual_privesc_json")
        self.assertIn("manual_privesc_json", SPEC_BY_KEY)
        self.assertEqual(SPEC_BY_KEY["manual_privesc_json"].flag, "--manual-privesc-json")

    def test_relative_windows_actions_are_not_treated_as_writable(self):
        self.assertFalse(_windows_writable("sc.exe"))
        self.assertFalse(_windows_writable("relative\\task.exe"))

    def test_collector_progressively_reports_checks_and_findings(self):
        args = Namespace(max_output_kb=64, max_file_kb=64, command_timeout=5,
                         max_files=10)
        collector = Collector(args)
        output = io.StringIO()
        with redirect_stdout(output):
            collector.command("progress test", [sys.executable, "-c", "print('ok')"])
            collector.finding("credential_material_found", "Test credential discovered",
                              evidence="password=LabSecret")
        rendered = output.getvalue()
        self.assertIn("[>] Check: progress test", rendered)
        self.assertIn("[complete] progress test", rendered)
        self.assertIn("[!] Finding: Test credential discovered", rendered)

    def test_git_loot_search_reads_metadata_without_scanning_objects(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            metadata = root / "project" / ".git"
            metadata.mkdir(parents=True)
            (metadata / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
            (metadata / "config").write_text(
                '[remote "origin"]\n'
                '    url = https://labuser:LabPassword123!@git.example/repo.git\n',
                encoding="utf-8",
            )
            args = Namespace(max_output_kb=64, max_file_kb=64, command_timeout=1,
                             max_files=100, max_git_repos=10)
            collector = Collector(args)
            with redirect_stdout(io.StringIO()):
                _git_loot_search(collector, [root])

            finding = next(f for f in collector.findings
                           if f.get("material_type") == "git-metadata")
            self.assertIn("labuser:LabPassword123!", finding["evidence"])
            self.assertEqual(finding["discovery_command"], f"read {metadata / 'config'}")
            self.assertFalse(any("objects" in str(check.get("path", ""))
                                 for check in collector.checks))

    def test_linux_findings_synthesize_existing_and_new_attack_paths(self):
        findings = parse_manual_privesc_json(self._write(self._payload()))
        paths = AttackPathSynthesizer(rules_file_path=RULES_FILE).generate_attack_paths(findings)
        names = {path["name"] for path in paths}
        self.assertIn("Sudo Misconfiguration - GTFOBins Escalation", names)
        self.assertIn("Post-Foothold Credential Material - Review and Reuse", names)
        self.assertIn("Readable Private Key - Validate Account Access", names)

    def test_windows_findings_synthesize_new_attack_paths(self):
        payload = self._payload()
        payload["platform"] = "windows"
        payload["findings"] = [
            {
                "name": "writable_scheduled_task_binary",
                "description": "Task action is writable",
                "evidence": {"TaskName": "Backup", "Execute": "C:\\Tools\\backup.exe"},
                "path": "C:\\Tools\\backup.exe",
            },
            {
                "name": "writable_autorun_binary",
                "description": "Autorun binary is writable",
                "evidence": "Updater REG_SZ C:\\Tools\\update.exe",
                "path": "C:\\Tools\\update.exe",
            },
            {
                "name": "sedebugprivilege_enabled",
                "description": "SeDebugPrivilege enabled",
                "evidence": "SeDebugPrivilege Enabled",
            },
        ]
        findings = parse_manual_privesc_json(self._write(payload))
        paths = AttackPathSynthesizer(rules_file_path=RULES_FILE).generate_attack_paths(findings)
        names = {path["name"] for path in paths}
        self.assertIn("Writable Scheduled Task Action - Binary Hijacking", names)
        self.assertIn("Writable Autorun or Startup Location - Privileged Logon Execution", names)
        self.assertIn("Dangerous Windows Token Privilege - Manual Abuse Review", names)


if __name__ == "__main__":
    unittest.main()
