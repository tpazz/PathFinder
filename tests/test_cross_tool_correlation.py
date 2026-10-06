"""Integration tests for the cross-tool correlation rules (Omega DAST/SAST/Dependency
findings fed into PathFinder via --input-json).

These rules chain findings imported from other scanners into attack paths:
a reachable surface (DAST web_finding) + a matching code sink (SAST code_finding)
of the same vulnerability class, and a high-impact dependency behind a reachable
web surface.
"""
import unittest
from pathlib import Path

from main.attack_path_synthesizer import AttackPathSynthesizer

RULES_FILE = str(Path(__file__).parent.parent / "main" / "attack_rules.json")
HOST = "whatweknow.today"


def _synth():
    return AttackPathSynthesizer(rules_file_path=RULES_FILE)


def _web(cls, **attrs):
    return {"host": HOST, "port": 443, "source_tool": "omega-dast", "entity_type": "web_finding",
            "name": cls, "version": None, "attributes": {"class": cls, **attrs}}


def _code(cls, **attrs):
    return {"host": HOST, "port": None, "source_tool": "omega-sast", "entity_type": "code_finding",
            "name": cls, "version": None, "attributes": {"class": cls, **attrs}}


def _dep(severity, high_impact, **attrs):
    return {"host": HOST, "port": None, "source_tool": "omega-dependencies",
            "entity_type": "dependency_finding", "name": attrs.get("package", "pkg"), "version": None,
            "attributes": {"severity": severity, "high_impact": high_impact, **attrs}}


def _names(paths):
    return [p["name"] for p in paths]


class CrossToolCorrelationTests(unittest.TestCase):
    def test_matching_class_chains_dast_and_sast(self):
        findings = [_web("sql-injection", route="/search", url="https://x/search"),
                    _code("sql-injection", file="api/search.py", line=42)]
        paths = _synth().generate_attack_paths(findings)
        hit = [p for p in paths if "Reachable SQL injection" in p["name"]]
        self.assertTrue(hit, "DAST+SAST same-class should synthesize a correlated path")
        self.assertIn("api/search.py", hit[0]["suggestion"]["description"])

    def test_command_injection_class_also_chains(self):
        findings = [_web("command-injection", route="/run"), _code("command-injection", file="x.py", line=9)]
        self.assertTrue(any("command injection" in n for n in _names(_synth().generate_attack_paths(findings))))

    def test_mismatched_classes_do_not_chain(self):
        # DAST SQLi + SAST XSS on the same host must NOT produce a correlated path.
        findings = [_web("sql-injection", route="/a"), _code("xss", file="b.py", line=1)]
        paths = _synth().generate_attack_paths(findings)
        self.assertFalse([p for p in paths if "exposed surface with a matching code sink" in p["name"]])

    def test_high_impact_dependency_behind_web_surface_chains(self):
        findings = [_dep("Critical", "true", package="lodash", installed_version="4.17.1",
                         advisory_ids=["CVE-2021-23337"]),
                    _web("xss", route="/")]
        paths = _synth().generate_attack_paths(findings)
        self.assertTrue(any("High-impact vulnerable dependency" in n for n in _names(paths)))

    def test_low_impact_dependency_does_not_chain(self):
        findings = [_dep("Low", "false", package="leftpad", installed_version="1.0.0"),
                    _web("xss", route="/")]
        paths = _synth().generate_attack_paths(findings)
        self.assertFalse(any("High-impact vulnerable dependency" in n for n in _names(paths)))


if __name__ == "__main__":
    unittest.main()
