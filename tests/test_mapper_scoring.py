import unittest

from main.vulnerability_mapper import VulnerabilityMapper, _scale_score_by_confidence


def _f(etype, name, **attrs):
    return {"host": "h", "port": None, "source_tool": "t", "entity_type": etype,
            "name": name, "version": None, "attributes": attrs}


class ScaleHelperTests(unittest.TestCase):
    def test_confidence_bands(self):
        self.assertEqual(_scale_score_by_confidence(95, {"confidence": "high"}), 95)
        self.assertEqual(_scale_score_by_confidence(95, {"confidence": "medium"}), 76)
        self.assertEqual(_scale_score_by_confidence(95, {"confidence": "low"}), 57)

    def test_severity_preferred_over_confidence(self):
        # severity wins when both are present
        self.assertEqual(_scale_score_by_confidence(85, {"severity": "critical", "confidence": "low"}), 85)

    def test_no_signal_keeps_base(self):
        self.assertEqual(_scale_score_by_confidence(85, {}), 85)
        self.assertEqual(_scale_score_by_confidence(95, {"confidence": "unknown-value"}), 95)


class MapperScoringTests(unittest.TestCase):
    def setUp(self):
        self.mapper = VulnerabilityMapper(use_github=False, use_searchsploit=False)

    def _scores(self, findings):
        out = self.mapper.map_and_prioritize(findings)
        return {f["name"]: f["attributes"]["score"] for f in out}

    def test_privesc_confidence_orders_findings(self):
        scores = self._scores([
            _f("privilege_escalation", "pe_high", confidence="high", signal_source="color_signature"),
            _f("privilege_escalation", "pe_low", confidence="low", signal_source="keyword_match"),
        ])
        self.assertGreater(scores["pe_high"], scores["pe_low"])
        # A low-confidence keyword privesc should fall below a confirmed vulnerability (85).
        self.assertLess(scores["pe_low"], 85)

    def test_nuclei_severity_orders_vulns(self):
        scores = self._scores([
            _f("vulnerability", "CVE-crit", severity="critical"),
            _f("vulnerability", "CVE-med", severity="medium"),
        ])
        self.assertGreater(scores["CVE-crit"], scores["CVE-med"])

    def test_confirmed_finding_without_signal_keeps_full_score(self):
        # sqlmap-style confirmed vuln carries no severity/confidence -> full 85.
        scores = self._scores([_f("vulnerability", "sql_injection_found")])
        self.assertEqual(scores["sql_injection_found"], 85)

    def test_structural_privesc_keeps_full_score(self):
        # SharpHound-style structural finding (no confidence attr) stays at 95.
        scores = self._scores([_f("privilege_escalation", "dcsync_rights_found")])
        self.assertEqual(scores["dcsync_rights_found"], 95)


if __name__ == "__main__":
    unittest.main()
