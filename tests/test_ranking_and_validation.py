"""Tests for confidence-weighted attack-path ranking, regex-trigger validation,
and gobuster port attribution.
"""
import json
import io
import os
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from main.attack_path_synthesizer import AttackPathSynthesizer, _finding_confidence_penalty
from main.pathfinder import (
    _attach_discovery_provenance,
    _deduplicate_provenance,
    _credential_validation_actions,
    _display_results,
    _finding_type_token,
    _gobuster_extract_target,
    _group_attack_paths,
    _load_provenance_manifest,
    _path_likelihood,
    _run_credential_validations,
    format_finding_display,
)
from parsers.ansi import C, set_color_enabled


def _finding(entity_type, name, host="H", **attrs):
    return {"host": host, "port": None, "source_tool": "t", "entity_type": entity_type,
            "name": name, "version": None, "attributes": attrs}


def _one_trigger_rule(name, priority, entity_type, value):
    return {"name": name, "priority": priority, "host_scope": "same_host",
            "triggers": [{"id": 1, "entity_type": entity_type,
                          "name_match": {"type": "exact", "value": value}}],
            "suggestion": {"description": name, "rationale": "r", "commands": [], "references": []}}


class _SynthMixin:
    def _synth(self, rules):
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        json.dump(rules, tmp)
        tmp.close()
        self.addCleanup(lambda: Path(tmp.name).unlink(missing_ok=True))
        return AttackPathSynthesizer(rules_file_path=tmp.name)


class ConfidencePenaltyTests(unittest.TestCase):
    def test_absent_grade_is_zero(self):
        # The 'absent == confirmed' convention: unlabelled findings keep full priority.
        self.assertEqual(_finding_confidence_penalty(_finding("vulnerability", "x")), 0)

    def test_low_confidence_is_penalised(self):
        self.assertEqual(_finding_confidence_penalty(_finding("privilege_escalation", "x", confidence="low")), -12)

    def test_medium_confidence_is_penalised(self):
        self.assertEqual(_finding_confidence_penalty(_finding("ai_service", "x", confidence="medium")), -6)

    def test_severity_preferred_over_confidence(self):
        f = _finding("vulnerability", "x", severity="critical", confidence="low")
        self.assertEqual(_finding_confidence_penalty(f), 0)


class RankingTests(_SynthMixin, unittest.TestCase):
    def test_confirmed_outranks_higher_priority_low_confidence(self):
        # Mirrors the real case: a low-confidence LinPEAS keyword guess (priority 95)
        # must not sit above a confirmed exploit (priority 85).
        synth = self._synth([
            _one_trigger_rule("Privesc keyword", 95, "privilege_escalation", "guess"),
            _one_trigger_rule("Confirmed exploit", 85, "vulnerability", "rce"),
        ])
        findings = [
            _finding("privilege_escalation", "guess", confidence="low"),  # 95 - 12 = 83
            _finding("vulnerability", "rce"),                             # 85 -  0 = 85
        ]
        paths = synth.generate_attack_paths(findings)
        self.assertEqual(paths[0]["name"], "Confirmed exploit")
        self.assertEqual(paths[0]["effective_priority"], 85)
        self.assertEqual(paths[1]["effective_priority"], 83)

    def test_high_value_medium_confidence_still_beats_low_value_confirmed(self):
        # The window is bounded: confidence decides close calls, not big gaps.
        synth = self._synth([
            _one_trigger_rule("Kerberoast", 90, "privilege_escalation", "kerb"),   # 90 - 6 = 84
            _one_trigger_rule("Writable share", 75, "misconfiguration", "share"),  # 75 - 0 = 75
        ])
        findings = [
            _finding("privilege_escalation", "kerb", confidence="medium"),
            _finding("misconfiguration", "share"),
        ]
        paths = synth.generate_attack_paths(findings)
        self.assertEqual(paths[0]["name"], "Kerberoast")

    def test_weakest_link_governs_two_trigger_path(self):
        rule = {"name": "Two", "priority": 90, "host_scope": "same_host",
                "triggers": [
                    {"id": 1, "entity_type": "vulnerability", "name_match": {"type": "exact", "value": "a"}},
                    {"id": 2, "entity_type": "service", "name_match": {"type": "exact", "value": "b"}}],
                "suggestion": {"description": "d {trigger.1.name} {trigger.2.name}",
                               "rationale": "r", "commands": [], "references": []}}
        synth = self._synth([rule])
        findings = [_finding("vulnerability", "a"),                # penalty 0
                    _finding("service", "b", confidence="low")]    # penalty -12 (weakest link)
        paths = synth.generate_attack_paths(findings)
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0]["effective_priority"], 78)  # 90 - 12

    def test_evidence_score_breaks_priority_tie_over_host(self):
        synth = self._synth([_one_trigger_rule("R", 80, "vulnerability", "x")])
        findings = [_finding("vulnerability", "x", host="A", score=5),
                    _finding("vulnerability", "x", host="B", score=50)]
        paths = synth.generate_attack_paths(findings)
        self.assertEqual(paths[0]["host"], "B")  # higher evidence_score wins over host order
        self.assertEqual(paths[0]["evidence_score"], 50)

    def test_host_tiebreak_is_deterministic(self):
        synth = self._synth([_one_trigger_rule("R", 80, "vulnerability", "x")])
        findings = [_finding("vulnerability", "x", host="B", score=10),
                    _finding("vulnerability", "x", host="A", score=10)]
        paths = synth.generate_attack_paths(findings)
        self.assertEqual([p["host"] for p in paths], ["A", "B"])

    def test_confirmed_finding_keeps_full_priority(self):
        synth = self._synth([_one_trigger_rule("R", 88, "vulnerability", "x")])
        paths = synth.generate_attack_paths([_finding("vulnerability", "x")])
        self.assertEqual(paths[0]["effective_priority"], paths[0]["priority"])

    def test_synthesized_path_keeps_structured_trigger_findings(self):
        synth = self._synth([_one_trigger_rule("R", 88, "vulnerability", "x")])
        finding = _finding("vulnerability", "x", discovery_command="nmap -sV H")
        path = synth.generate_attack_paths([finding])[0]
        self.assertEqual(path["matched_findings"][0]["trigger_id"], 1)
        self.assertEqual(path["matched_findings"][0]["finding"]["name"], "x")
        self.assertEqual(
            path["matched_findings"][0]["finding"]["attributes"]["discovery_command"],
            "nmap -sV H",
        )


class TriageDisplayTests(unittest.TestCase):
    def _path(self, name, host="H", priority=80, effective_priority=None, evidence_score=0):
        return {
            "name": name,
            "priority": priority,
            "effective_priority": effective_priority if effective_priority is not None else priority,
            "evidence_score": evidence_score,
            "host": host,
            "suggestion": {"description": name, "rationale": "r", "commands": [], "references": []},
            "atlas": [],
            "evidence": [f"Trigger 1: {name} (vulnerability)"],
        }

    def test_parameterized_sqlmap_candidate_is_low_likelihood(self):
        path = self._path("Parameterized URL - SQLi Triage Candidate", priority=74)
        self.assertEqual(_path_likelihood(path), "low")

    def test_actionable_chain_is_high_likelihood(self):
        path = self._path("Credential Reuse on Login Service", priority=82)
        self.assertEqual(_path_likelihood(path), "high")

    def test_grouping_collapses_repeated_rule_hits(self):
        groups = _group_attack_paths([
            self._path("Known Vulnerable Software with Public Exploit", host="10.0.0.1", priority=85),
            self._path("Known Vulnerable Software with Public Exploit", host="10.0.0.2", priority=85),
        ])
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["count"], 2)
        self.assertIn("10.0.0.1", groups[0]["targets"])
        self.assertIn("10.0.0.2", groups[0]["targets"])

    def test_display_defaults_to_grouped_top_triage(self):
        class Synth:
            def generate_attack_paths(self, _findings):
                return [
                    self_path("Credential Reuse on Login Service", host="10.0.0.1", priority=88),
                    self_path("Credential Reuse on Login Service", host="10.0.0.2", priority=88),
                    self_path("Parameterized URL - SQLi Triage Candidate", host="10.0.0.3", priority=74),
                ]

        def self_path(name, host, priority):
            return self._path(name, host=host, priority=priority)

        args = SimpleNamespace(verbose=0, max_vulns=10, oscp=False,
                               show_all=False, top=1, min_likelihood="low")
        out = io.StringIO()
        with redirect_stdout(out):
            paths = _display_results(args, Synth(), [])

        text = out.getvalue()
        self.assertEqual(len(paths), 3)
        self.assertIn("TRIAGE ATTACK PATH #1", text)
        self.assertIn("Grouped hits: 2 underlying path(s)", text)
        self.assertIn("Use --show-all", text)
        self.assertIn("\n\n[*] Triage view:", text)
        self.assertIn("additional grouped lead(s) hidden by --top 1", text)

    def test_non_exploit_names_are_bold_but_vulnerability_type_is_not(self):
        previous = C.enabled
        set_color_enabled(True)
        try:
            display_name, _display_type = format_finding_display("sql_injection_found", "vulnerability")
            vulnerability_type = _finding_type_token("vulnerability")
            self.assertTrue(display_name.startswith(C.BOLD))
            self.assertNotIn(C.BOLD, vulnerability_type)

            exploit_name, _ = format_finding_display("EDB-ID: 12345", "vulnerability")
            self.assertIn(f"{C.BOLD}{C.RED}EDB-ID", exploit_name)
        finally:
            set_color_enabled(previous)

    def test_grouped_triage_renders_all_action_buckets_and_provenance(self):
        def finding(entity_type, name, host, port, tool, command):
            return {
                "host": host, "port": port, "source_tool": tool,
                "entity_type": entity_type, "name": name, "version": None,
                "attributes": {"discovery_provenance": [{"tool": tool, "command": command}]},
            }

        def path(user, service, port, entity_type="confirmed_username"):
            tool = "webpage_identity_extractor" if entity_type == "username_candidate" else "kerbrute"
            command = "curl http://target/" if entity_type == "username_candidate" else "kerbrute userenum ..."
            user_finding = finding(entity_type, user, "DC", None, tool, command)
            service_finding = finding("service", service, "10.0.0.5", port, "nmap", "nmap -sV 10.0.0.5")
            return {
                "name": "Password Spray Discovered Users Against Services",
                "priority": 83, "effective_priority": 83, "evidence_score": 0,
                "host": "10.0.0.5", "atlas": [],
                "suggestion": {
                    "description": f"Try {user} on {service}", "rationale": "r",
                    "commands": [f"nxc {service} 10.0.0.5 -u {user} -p Password1"],
                    "references": [],
                },
                "evidence": [f"Trigger 1: {user} ({entity_type})", f"Trigger 2: {service} (service)"],
                "matched_findings": [
                    {"trigger_id": 1, "finding": user_finding},
                    {"trigger_id": 2, "finding": service_finding},
                ],
            }

        paths = [
            path("alice", "ssh", 22), path("bob", "ssh", 22),
            path("alice", "smb", 445),
        ]

        class Synth:
            def generate_attack_paths(self, _findings):
                return paths

        args = SimpleNamespace(verbose=0, max_vulns=10, oscp=False,
                               show_all=False, top=20, min_likelihood="low")
        out = io.StringIO()
        with redirect_stdout(out):
            _display_results(args, Synth(), [])
        text = out.getvalue()
        self.assertIn("Resolved Actions:", text)
        self.assertIn("ssh (service) @ 10.0.0.5:22 (2 resolved variant(s))", text)
        self.assertIn("smb (service) @ 10.0.0.5:445 (1 resolved variant(s))", text)
        self.assertIn("Tool: kerbrute", text)
        self.assertIn("Command: kerbrute userenum ...", text)
        self.assertIn("Confirmed usernames: alice, bob", text)
        self.assertIn("Core command:", text)
        self.assertIn("nxc ssh 10.0.0.5 -u '<USERNAME>' -p '<PASSWORD>'", text)
        self.assertNotIn("nxc ssh 10.0.0.5 -u alice -p Password1", text)

    def test_grouped_username_candidates_have_dedicated_manual_review_section(self):
        paths = []
        for username in ("r.chen", "ts_svc"):
            finding = {
                "host": "192.168.129.14", "port": 8080,
                "source_tool": "webpage_identity_extractor",
                "entity_type": "username_candidate", "name": username, "version": None,
                "attributes": {
                    "confidence": "high", "url": "http://192.168.129.14:8080/dashboard",
                    "evidence": f"Recent activity | {username}",
                },
            }
            paths.append({
                "name": "Username Candidates for Manual Review",
                "priority": 72, "effective_priority": 72, "evidence_score": 35,
                "host": "192.168.129.14", "atlas": [],
                "suggestion": {
                    "description": f"Review {username}", "rationale": "heuristic",
                    "commands": [], "references": [],
                },
                "evidence": [f"Trigger 1: {username} (username_candidate)"],
                "matched_findings": [{"trigger_id": 1, "finding": finding}],
            })

        class Synth:
            def generate_attack_paths(self, _findings):
                return paths

        args = SimpleNamespace(verbose=0, max_vulns=10, oscp=False,
                               show_all=False, top=20, min_likelihood="low")
        out = io.StringIO()
        with redirect_stdout(out):
            _display_results(args, Synth(), [])
        text = out.getvalue()
        self.assertIn("Name:         Username Candidates for Manual Review", text)
        self.assertIn("Username Candidates for Manual Review:", text)
        self.assertIn("r.chen [high confidence]", text)
        self.assertIn("ts_svc [high confidence]", text)
        self.assertIn("Source page: http://192.168.129.14:8080/dashboard", text)

    def test_default_findings_display_includes_discovery_tool_and_command(self):
        finding = _finding("service", "ssh", host="10.0.0.5", score=50)
        finding["attributes"]["discovery_provenance"] = [
            {"tool": "nmap", "command": "nmap -sV 10.0.0.5"}
        ]

        class Synth:
            def generate_attack_paths(self, _findings):
                return []

        args = SimpleNamespace(verbose=0, max_vulns=10, oscp=False,
                               show_all=False, top=20, min_likelihood="low")
        out = io.StringIO()
        with redirect_stdout(out):
            _display_results(args, Synth(), [finding])
        text = out.getvalue()
        self.assertIn("nmap", text)
        self.assertIn("nmap -sV 10.0.0.5", text)

    def test_grouped_credential_reuse_lists_pairs_and_one_placeholder_command(self):
        service = {
            "host": "10.0.0.5", "port": 22, "source_tool": "nmap",
            "entity_type": "service", "name": "ssh", "version": None,
            "attributes": {},
        }
        paths = []
        for username, password in (("alice", "Secret1!"), ("bob", "Secret2!")):
            credential = {
                "host": "MANUALLY_ADDED", "port": None, "source_tool": "manual_input",
                "entity_type": "credential", "name": username, "version": None,
                "attributes": {"username": username, "password": password},
            }
            path = self._path("Credential Reuse on Login Service", host="10.0.0.5", priority=98)
            path["matched_findings"] = [
                {"trigger_id": 1, "finding": credential},
                {"trigger_id": 2, "finding": service},
            ]
            path["suggestion"]["commands"] = [
                f"nxc ssh 10.0.0.5 -u '{username}' -p '{password}'"
            ]
            paths.append(path)

        class Synth:
            def generate_attack_paths(self, _findings):
                return paths

        args = SimpleNamespace(verbose=0, max_vulns=10, oscp=False,
                               show_all=False, top=20, min_likelihood="low")
        out = io.StringIO()
        with redirect_stdout(out):
            _display_results(args, Synth(), [])
        text = out.getvalue()
        self.assertIn("Credentials: alice:Secret1!, bob:Secret2!", text)
        self.assertEqual(text.count("nxc ssh 10.0.0.5 -u '<USERNAME>' -p '<PASSWORD>'"), 1)
        self.assertNotIn("-u 'alice' -p 'Secret1!'", text)

    def test_hide_discovery_applies_to_grouped_triage(self):
        finding = _finding("service", "ssh", host="10.0.0.5", score=50)
        finding["attributes"]["discovery_provenance"] = [
            {"tool": "nmap", "command": "producer-command --secret"}
        ]
        paths = []
        for user in ("alice", "bob"):
            path = self._path("Credential Reuse on Login Service", host="10.0.0.5")
            path["matched_findings"] = [{"trigger_id": 1, "finding": finding}]
            path["suggestion"]["commands"] = [f"suggested-command -u {user}"]
            paths.append(path)

        class Synth:
            def generate_attack_paths(self, _findings):
                return paths

        args = SimpleNamespace(verbose=0, max_vulns=10, oscp=False,
                               show_all=False, top=20, min_likelihood="low",
                               hide_discovery=True)
        out = io.StringIO()
        with redirect_stdout(out):
            _display_results(args, Synth(), [finding])
        text = out.getvalue()
        self.assertNotIn("Discovery Provenance", text)
        self.assertNotIn("producer-command --secret", text)
        self.assertIn("nxc ssh 10.0.0.5 -u '<USERNAME>' -p '<PASSWORD>'", text)

    def test_hide_discovery_applies_to_full_paths(self):
        finding = _finding("service", "ssh", host="10.0.0.5", score=50)
        finding["attributes"]["discovery_provenance"] = [
            {"tool": "nmap", "command": "producer-command --secret"}
        ]
        path = self._path("SSH follow-up", host="10.0.0.5")
        path["matched_findings"] = [{"trigger_id": 1, "finding": finding}]

        class Synth:
            def generate_attack_paths(self, _findings):
                return [path]

        args = SimpleNamespace(verbose=0, max_vulns=10, oscp=False,
                               show_all=True, top=20, min_likelihood="low",
                               hide_discovery=True)
        out = io.StringIO()
        with redirect_stdout(out):
            _display_results(args, Synth(), [finding])
        text = out.getvalue()
        self.assertIn("ATTACK PATH #1", text)
        self.assertNotIn("Discovery Provenance", text)
        self.assertNotIn("producer-command --secret", text)

    def test_hide_findings_keeps_attack_paths(self):
        finding = _finding("service", "finding-only-marker", host="10.0.0.5", score=50)
        path = self._path("Visible attack path", host="10.0.0.5")

        class Synth:
            def generate_attack_paths(self, _findings):
                return [path]

        args = SimpleNamespace(verbose=0, max_vulns=10, oscp=False,
                               show_all=True, top=20, min_likelihood="low",
                               hide_findings=True)
        out = io.StringIO()
        with redirect_stdout(out):
            returned = _display_results(args, Synth(), [finding])
        text = out.getvalue()
        self.assertEqual(returned, [path])
        self.assertIn("Visible attack path", text)
        self.assertNotIn("Total Findings", text)
        self.assertNotIn("finding-only-marker", text)

    def test_manual_username_password_is_displayed_as_pair(self):
        finding = _finding("credential", "alice", host="MANUALLY_ADDED", score=100)
        finding["source_tool"] = "manual_input"
        finding["attributes"].update({"username": "alice", "password": "Secret123!"})

        class Synth:
            def generate_attack_paths(self, _findings):
                return []

        args = SimpleNamespace(verbose=0, max_vulns=10, oscp=False,
                               show_all=False, top=20, min_likelihood="low")
        out = io.StringIO()
        with redirect_stdout(out):
            _display_results(args, Synth(), [finding])
        self.assertIn("alice:Secret123!", out.getvalue())


class ProvenanceManifestTests(unittest.TestCase):
    def test_commands_are_preserved_verbatim_without_redaction(self):
        command = "ffuf -H 'Authorization: Bearer secret-token' --password hunter2"
        records = _deduplicate_provenance([{"tool": "ffuf", "command": command}])
        self.assertEqual(records[0]["command"], command)

    def test_manifest_joins_command_to_finding(self):
        with tempfile.TemporaryDirectory() as directory:
            payload = {
                "schema_version": 1,
                "records": [{
                    "tool": "kerbrute", "parser": "kerbrute_txt",
                    "output_file": "10.0.0.5/kerbrute.txt",
                    "command": "kerbrute userenum -d corp.local users.txt",
                    "status": "done",
                }],
            }
            Path(directory, "_pathfinder_provenance.json").write_text(
                json.dumps(payload), encoding="utf-8"
            )
            records = _load_provenance_manifest(directory)
            finding = _finding("confirmed_username", "alice")
            _attach_discovery_provenance(
                finding, "10.0.0.5\\kerbrute.txt", records["10.0.0.5/kerbrute.txt"]
            )
        provenance = finding["attributes"]["discovery_provenance"][0]
        self.assertEqual(provenance["tool"], "kerbrute")
        self.assertEqual(provenance["status"], "done")
        self.assertIn("userenum", provenance["command"])


class CredentialValidationTests(unittest.TestCase):
    @staticmethod
    def _path(username, password, service, host, port):
        credential = {
            "host": "MANUALLY_ADDED", "port": None, "source_tool": "manual_input",
            "entity_type": "credential", "name": username, "version": None,
            "attributes": {"username": username, "password": password},
        }
        login_service = {
            "host": host, "port": port, "source_tool": "nmap",
            "entity_type": "service", "name": service, "version": None,
            "attributes": {},
        }
        return {
            "name": "Credential Reuse on Login Service", "host": host,
            "matched_findings": [
                {"trigger_id": 1, "finding": credential},
                {"trigger_id": 2, "finding": login_service},
            ],
        }

    @patch("main.pathfinder.shutil.which", return_value="/usr/bin/nxc")
    def test_builds_one_structured_action_per_resolved_pair(self, _which):
        path = self._path("alice", "Secret!", "microsoft-ds", "10.0.0.5", 1445)
        actions = _credential_validation_actions([path, path])
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["protocol"], "smb")
        self.assertEqual(
            actions[0]["argv"],
            ["nxc", "smb", "10.0.0.5", "--port", "1445", "-u", "alice", "-p", "Secret!"],
        )

    @patch("main.pathfinder.shutil.which", return_value="/usr/bin/nxc")
    def test_incomplete_credential_is_not_attempted(self, _which):
        path = self._path("alice", None, "ssh", "10.0.0.5", 22)
        self.assertEqual(_credential_validation_actions([path]), [])

    @patch("main.pathfinder.shutil.which", return_value="/usr/bin/nxc")
    def test_ntlm_hash_is_used_only_for_supported_login_protocols(self, _which):
        smb = self._path("alice", None, "smb", "10.0.0.5", 445)
        smb["matched_findings"][0]["finding"]["attributes"].update({
            "hash": "31d6cfe0d16ae931b73c59d7e0c089c0", "hash_type": "NTLM",
        })
        ssh = self._path("alice", None, "ssh", "10.0.0.6", 22)
        ssh["matched_findings"][0]["finding"]["attributes"].update({
            "hash": "31d6cfe0d16ae931b73c59d7e0c089c0", "hash_type": "NTLM",
        })
        actions = _credential_validation_actions([smb, ssh])
        self.assertEqual(len(actions), 1)
        self.assertIn("-H", actions[0]["argv"])

    @patch("main.pathfinder.shutil.which", return_value="/usr/bin/nxc")
    @patch("main.pathfinder.subprocess.run")
    def test_success_is_obvious_and_does_not_stop_later_attempts(self, run, _which):
        run.side_effect = [
            SimpleNamespace(
                stdout="SMB 10.0.0.5 445 HOST [+] alice:Secret! (Pwn3d!)\n",
                stderr="", returncode=0,
            ),
            SimpleNamespace(
                stdout="SSH 10.0.0.6 22 HOST [-] bob:Wrong!\n",
                stderr="", returncode=0,
            ),
        ]
        paths = [
            self._path("alice", "Secret!", "smb", "10.0.0.5", 445),
            self._path("bob", "Wrong!", "ssh", "10.0.0.6", 22),
        ]
        out = io.StringIO()
        with redirect_stdout(out):
            results = _run_credential_validations(paths)
        text = out.getvalue()
        self.assertEqual(run.call_count, 2)
        self.assertEqual([result["status"] for result in results], ["SUCCESS", "rejected"])
        self.assertIn("Credential Validation Plan", text)
        self.assertIn("Credential Validation Stage", text)
        self.assertIn("VALID LOGIN: alice:Secret! -> smb://10.0.0.5:445", text)
        self.assertIn("1 successful", text)


class RegexValidationTests(_SynthMixin, unittest.TestCase):
    def test_invalid_regex_trigger_is_skipped_not_crashed(self):
        bad = {"name": "Bad regex", "priority": 50, "host_scope": "same_host",
               "triggers": [{"id": 1, "entity_type": "service",
                             "name_match": {"type": "regex", "value": "([unclosed"}}],
               "suggestion": {"description": "d", "rationale": "r", "commands": [], "references": []}}
        synth = self._synth([bad])
        self.assertEqual(len(synth.rules), 0)
        # Synthesis over a matching finding must not raise an uncaught re.error.
        self.assertEqual(synth.generate_attack_paths([_finding("service", "anything")]), [])

    def test_valid_regex_trigger_is_kept(self):
        good = {"name": "Good regex", "priority": 50, "host_scope": "same_host",
                "triggers": [{"id": 1, "entity_type": "service",
                              "name_match": {"type": "regex", "value": "^ssh$"}}],
                "suggestion": {"description": "d", "rationale": "r", "commands": [], "references": []}}
        synth = self._synth([good])
        self.assertEqual(len(synth.rules), 1)

    def test_invalid_match_type_is_rejected_not_broad_matched(self):
        # A typo like "contain" would otherwise fall through to "match every finding
        # of this entity_type" - reject it at load instead.
        bad = {"name": "Bad type", "priority": 50, "host_scope": "same_host",
               "triggers": [{"id": 1, "entity_type": "service",
                             "name_match": {"type": "contain", "value": "ssh"}}],
               "suggestion": {"description": "d", "rationale": "r", "commands": [], "references": []}}
        synth = self._synth([bad])
        self.assertEqual(len(synth.rules), 0)


class GobusterPortTests(unittest.TestCase):
    def _write(self, name, content):
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        p = os.path.join(d, name)
        with open(p, "w", encoding="utf-8") as f:
            f.write(content)
        return p

    def test_port_recovered_from_filename_when_no_banner(self):
        # gobuster's -o file has result lines only; the '[+] Url:' banner goes to stdout.
        p = self._write("gobuster_8080.txt", "/admin (Status: 200)\n/login (Status: 302)\n")
        _host, port, _mode = _gobuster_extract_target(p)
        self.assertEqual(port, 8080)

    def test_banner_port_takes_precedence_over_filename(self):
        p = self._write("gobuster_80.txt", "[+] Url: http://10.10.10.10:8443\n/x (Status: 200)\n")
        host, port, _mode = _gobuster_extract_target(p)
        self.assertEqual(port, 8443)
        self.assertEqual(host, "10.10.10.10")

    def test_defaults_to_80_without_banner_or_filename_port(self):
        p = self._write("results.txt", "/x (Status: 200)\n")
        _host, port, _mode = _gobuster_extract_target(p)
        self.assertEqual(port, 80)


if __name__ == "__main__":
    unittest.main()
