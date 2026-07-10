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

from main.attack_path_synthesizer import AttackPathSynthesizer, _finding_confidence_penalty
from main.pathfinder import (
    _display_results,
    _gobuster_extract_target,
    _group_attack_paths,
    _path_likelihood,
)


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
        self.assertIn("additional grouped lead(s) hidden by --top 1", text)


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
