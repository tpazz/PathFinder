import unittest

from main.vulnerability_mapper import VulnerabilityMapper, _scale_score_by_confidence, _searchsploit_cves


def _f(etype, name, **attrs):
    return {"host": "h", "port": None, "source_tool": "t", "entity_type": etype,
            "name": name, "version": None, "attributes": attrs}


class ScaleHelperTests(unittest.TestCase):
    def test_searchsploit_cves_are_canonical_and_null_safe(self):
        self.assertEqual(
            _searchsploit_cves("CVE-2021-41773; cve-2021-42013;EDB-123"),
            ["CVE-2021-41773", "CVE-2021-42013"],
        )
        self.assertEqual(_searchsploit_cves(None), [])
        self.assertEqual(_searchsploit_cves({"unexpected": "object"}), [])

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

    def test_github_exploit_finding_name_omits_long_description(self):
        mapper = VulnerabilityMapper(use_github=True, use_searchsploit=False, github_cache_file=None)
        mapper._search_github_for_exploits = lambda _product, _version: [{
            "repo_name": "S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet",
            "url": "https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet",
            "description": "A cheat sheet that contains common enumeration and attack methods for Windows Active Directory.",
            "stars": 100,
            "search_term_used": "ldap exploit",
            "relevance_score": 60,
            "relevance_reasons": ["matched product tokens"],
        }]

        findings = mapper.map_and_prioritize([{
            "host": "h",
            "port": 389,
            "source_tool": "nmap",
            "entity_type": "software_product",
            "name": "Microsoft Windows Active Directory LDAP",
            "version": "10.0",
            "attributes": {
                "search_name": "ldap",
                "discovery_provenance": [{
                    "tool": "nmap",
                    "command": "nmap -sC -sV -p389 h --script-args password=hunter2",
                }],
            },
        }])
        gh = next(f for f in findings if f.get("source_tool") == "github_exploit_mapper")

        self.assertEqual(gh["name"], "GitHub Exploit: S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet")
        self.assertEqual(gh["attributes"]["repo_name"], "S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet")
        self.assertIn("common enumeration", gh["attributes"]["description"])
        provenance = gh["attributes"]["discovery_provenance"]
        self.assertEqual([p["tool"] for p in provenance], ["nmap", "github-api"])
        self.assertIn("password=hunter2", provenance[0]["command"])
        self.assertIn("api.github.com/search/repositories", provenance[1]["command"])

    def test_searchsploit_finding_keeps_enumeration_and_enrichment_provenance(self):
        mapper = VulnerabilityMapper(use_github=False, use_searchsploit=True)
        mapper._run_searchsploit = lambda _product, _version: [{
            "Title": "Example RCE", "EDB-ID": "12345", "Type": "remote",
            "Platform": "linux", "Path": "exploits/12345.py", "Codes": "",
            "_pathfinder_query": "apache 2.4.49",
        }]
        findings = mapper.map_and_prioritize([{
            "host": "h", "port": 80, "source_tool": "nmap",
            "entity_type": "software_product", "name": "Apache HTTP Server",
            "version": "2.4.49", "attributes": {
                "search_name": "apache",
                "discovery_provenance": [{"tool": "nmap", "command": "nmap -sV h"}],
            },
        }])
        exploit = next(f for f in findings if f.get("source_tool") == "searchsploit_mapper")
        provenance = exploit["attributes"]["discovery_provenance"]
        self.assertEqual([p["tool"] for p in provenance], ["nmap", "searchsploit"])
        self.assertEqual(provenance[0]["command"], "nmap -sV h")
        self.assertEqual(provenance[1]["command"], "searchsploit --json 'apache 2.4.49'")


if __name__ == "__main__":
    unittest.main()
