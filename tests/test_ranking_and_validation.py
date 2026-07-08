"""Tests for confidence-weighted attack-path ranking, regex-trigger validation,
gobuster port attribution, and single-pass AI-brief wiring.
"""
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from main.attack_path_synthesizer import AttackPathSynthesizer, _finding_confidence_penalty
from main.pathfinder import _gobuster_extract_target, maybe_write_ai_brief


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


class BriefWiringTests(unittest.TestCase):
    def test_brief_written_from_supplied_paths(self):
        # maybe_write_ai_brief now consumes the already-synthesized paths (one
        # synthesis per run) instead of recomputing them.
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        brief = os.path.join(d, "brief.md")
        args = SimpleNamespace(ai_brief=brief)
        ai_finding = {"host": "H", "port": 443, "source_tool": "one-shot-enum",
                      "entity_type": "ai_service", "name": "openai-compatible", "version": None,
                      "attributes": {"score": 90, "base_url": "https://H/v1"}}
        paths = [{"name": "Exposed LLM API - Prompt Injection & Guardrail Testing",
                  "priority": 90, "effective_priority": 84, "evidence_score": 90, "host": "H",
                  "suggestion": {"description": "d", "rationale": "r", "commands": [], "references": []},
                  "atlas": ["AML.T0051 LLM Prompt Injection"], "evidence": []}]
        maybe_write_ai_brief(args, paths, [ai_finding])
        self.assertTrue(os.path.exists(brief))
        text = Path(brief).read_text(encoding="utf-8")
        self.assertIn("AI Attack Intelligence Brief", text)
        self.assertIn("P84", text)  # brief header reflects effective priority

    def test_no_brief_when_flag_absent(self):
        args = SimpleNamespace(ai_brief=None)
        # Should be a no-op and must not raise even with no paths.
        self.assertIsNone(maybe_write_ai_brief(args, [], []))


if __name__ == "__main__":
    unittest.main()
