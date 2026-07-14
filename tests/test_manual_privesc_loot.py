import json
import importlib.util
import io
import os
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch
from argparse import Namespace
from contextlib import redirect_stdout
from pathlib import Path

from main.attack_path_synthesizer import AttackPathSynthesizer
from main.finding_schema import validate_findings
from main.parser_registry import SPEC_BY_KEY
from main.pathfinder import _attach_discovery_provenance, _sniff_file_type, deduplicate_findings
from parsers.post_exploitation.manual_privesc_parser import parse_manual_privesc_json
ROOT = Path(__file__).parent.parent
RULES_FILE = str(ROOT / "main" / "attack_rules.json")
_COLLECTOR_PATH = ROOT / "tools" / "mini-peas.py"
_SPEC = importlib.util.spec_from_file_location("pathfinder_mini_peas", _COLLECTOR_PATH)
_MINI_PEAS = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MINI_PEAS)
Collector = _MINI_PEAS.Collector
_git_loot_search = _MINI_PEAS._git_loot_search
_windows_writable = _MINI_PEAS._windows_writable
_windows_readable = _MINI_PEAS._windows_readable
_credential_lines = _MINI_PEAS._credential_lines
_history_credential_lines = _MINI_PEAS._history_credential_lines
_dangerous_capabilities = _MINI_PEAS._dangerous_capabilities
_linux_special_file_classification = _MINI_PEAS._linux_special_file_classification
_extract_windows_script_paths = _MINI_PEAS._extract_windows_script_paths
_is_privileged_windows_principal = _MINI_PEAS._is_privileged_windows_principal


class ManualPrivilegeEscalationLootTests(unittest.TestCase):
    def test_default_output_uses_mini_peas_name(self):
        self.assertEqual(_MINI_PEAS.DEFAULT_OUTPUT, "mini-peas-loot.json")

    def _payload(self):
        return {
            "tool": "mini-peas",
            "type": "pathfinder_manual_privesc_loot",
            "schema_version": "1.0",
            "host": "target-hostname",
            "platform": "linux",
            "user": "www-data",
            "collected_at": "2026-07-14T00:00:00+00:00",
            "command": "python3 mini-peas.py -o loot.json",
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
                         "mini-peas")
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
        self.assertEqual(SPEC_BY_KEY["manual_privesc_json"].flag, "--mini-peas-json")
        self.assertIn("--manual-privesc-json", SPEC_BY_KEY["manual_privesc_json"].aliases)

    def test_relative_windows_actions_are_not_treated_as_writable(self):
        self.assertFalse(_windows_writable("sc.exe"))
        self.assertFalse(_windows_writable("relative\\task.exe"))

    def test_windows_read_probe_treats_access_denied_as_not_readable(self):
        with patch.object(Path, "is_file", side_effect=PermissionError("denied")):
            self.assertFalse(_windows_readable(r"C:\Windows\System32\config\SAM"))

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

    def test_many_credential_material_findings_survive_dedup_and_share_one_rule(self):
        payload = self._payload()
        payload["findings"] = [
            {
                "name": "credential_material_found",
                "description": f"Credential material found in /opt/app/config-{index}.yml",
                "evidence": f"PASSWORD=LabSecret{index}",
                "path": f"/opt/app/config-{index}.yml",
                "material_type": "file-content",
            }
            for index in range(32)
        ]
        findings = deduplicate_findings(parse_manual_privesc_json(self._write(payload)))
        self.assertEqual(len(findings), 32)

        paths = AttackPathSynthesizer(rules_file_path=RULES_FILE).generate_attack_paths(findings)
        credential_paths = [
            path for path in paths
            if path["name"] == "Post-Foothold Credential Material - Review and Reuse"
        ]
        self.assertEqual(len(credential_paths), 32)

    def test_privilege_escalation_rules_do_not_reference_private_notes(self):
        rules = json.loads(Path(RULES_FILE).read_text(encoding="utf-8"))
        privilege_rules = [
            rule for rule in rules
            if any(trigger.get("entity_type") == "privilege_escalation"
                   for trigger in rule.get("triggers", []))
        ]
        self.assertTrue(privilege_rules)
        self.assertNotIn("OSCP-Prep", json.dumps(privilege_rules))

    def test_file_budget_prioritizes_candidates_and_excludes_own_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index in range(12):
                (root / f"ordinary-{index}.txt").write_text("ordinary", encoding="utf-8")
            secret = root / ".netrc"
            secret.write_text("machine lab login alice password LabSecret", encoding="utf-8")
            output = root / "mini-peas-loot.json"
            output.write_text('{"password":"old-secret"}', encoding="utf-8")
            args = Namespace(max_output_kb=64, max_file_kb=64, command_timeout=1,
                             max_files=3, max_git_repos=1, out=str(output), quiet=True)
            collector = Collector(args)
            selected = list(collector.walk_files([root]))

            self.assertIn(secret, selected)
            self.assertNotIn(output, selected)
            self.assertEqual(len(selected), 3)
            self.assertTrue(collector.file_limit_reached)

    def test_credential_line_precision_and_history_commands(self):
        text = "\n".join([
            "# password documentation only",
            "password policy requires twelve characters",
            "DATABASE_PASSWORD=LabSecret123!",
            "Authorization: Bearer raw-token-value",
        ])
        lines = _credential_lines(text)
        self.assertEqual(lines, ["DATABASE_PASSWORD=LabSecret123!", "Authorization: Bearer raw-token-value"])
        history = _history_credential_lines("sshpass -p 'LabSecret' ssh alice@host\necho password policy")
        self.assertEqual(history, ["sshpass -p 'LabSecret' ssh alice@host"])

    def test_linux_suid_and_capability_noise_filtering(self):
        normal = _linux_special_file_classification(Path("/usr/bin/passwd"), stat.S_ISUID)
        exploitable = _linux_special_file_classification(Path("/usr/bin/find"), stat.S_ISUID)
        custom = _linux_special_file_classification(Path("/opt/tools/backup"), stat.S_ISUID)
        self.assertEqual(normal, (False, False, None))
        self.assertEqual(exploitable, (True, False, "known-abusable"))
        self.assertEqual(custom, (True, False, "unusual"))
        self.assertEqual(_dangerous_capabilities("/usr/bin/ping cap_net_raw=ep"), [])
        self.assertEqual(_dangerous_capabilities("/opt/python cap_setuid,cap_net_raw=ep"), ["cap_setuid"])

    def test_windows_task_script_and_principal_parsing(self):
        paths = _extract_windows_script_paths(
            r"powershell.exe -File C:\ProgramData\Jobs\backup.ps1 C:\Safe\other.cmd"
        )
        self.assertEqual(paths, [r"C:\ProgramData\Jobs\backup.ps1", r"C:\Safe\other.cmd"])
        self.assertTrue(_is_privileged_windows_principal("SYSTEM"))
        self.assertTrue(_is_privileged_windows_principal("S-1-5-18"))
        self.assertFalse(_is_privileged_windows_principal("INTERACTIVE"))
        self.assertFalse(_is_privileged_windows_principal(r"LAB\ordinary-user"))
        self.assertFalse(_is_privileged_windows_principal(_MINI_PEAS.getpass.getuser()))

    def test_new_linux_and_windows_findings_synthesize_paths(self):
        payload = self._payload()
        payload["findings"] = [
            {"name": "writable_systemd_execution_chain", "description": "writable unit", "path": "/etc/systemd/system/x.service"},
            {"name": "writable_dynamic_loader_configuration", "description": "writable preload", "path": "/etc/ld.so.preload"},
            {"name": "service_change_config_allowed", "description": "service DACL", "service": "Updater"},
            {"name": "readable_windows_registry_hives", "description": "hives readable", "paths": ["SAM", "SYSTEM"]},
            {"name": "writable_machine_path_directory", "description": "PATH writable", "path": r"C:\Tools"},
        ]
        findings = parse_manual_privesc_json(self._write(payload))
        validate_findings(findings)
        names = {path["name"] for path in AttackPathSynthesizer(
            rules_file_path=RULES_FILE).generate_attack_paths(findings)}
        self.assertIn("Mini-PEAS - Writable Privileged Linux Execution Chain", names)
        self.assertIn("Mini-PEAS - Dynamic Loader Configuration Hijack", names)
        self.assertIn("Mini-PEAS - Windows Service Control or Directory Hijack", names)
        self.assertIn("Mini-PEAS - Readable Windows Registry Hives", names)
        self.assertIn("Mini-PEAS - Writable Windows Machine PATH", names)


if __name__ == "__main__":
    unittest.main()
