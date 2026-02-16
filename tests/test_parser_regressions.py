import unittest
from pathlib import Path

from main.finding_schema import validate_findings
from parsers.initial_foothold.gobuster_parser import parse_gobuster_output
from parsers.initial_foothold.nmap_parser import parse_nmap_xml
from parsers.initial_foothold.sqlmap_parser import parse_sqlmap_log
from parsers.initial_foothold.whatweb_parser import parse_whatweb_json


FIXTURES = Path(__file__).parent / "fixtures"


class ParserRegressionTests(unittest.TestCase):
    def test_nmap_parser_extracts_service_product_and_vuln(self):
        findings = parse_nmap_xml(str(FIXTURES / "nmap_sample.xml"))
        self.assertGreaterEqual(len(findings), 4)
        validate_findings(findings)

        service = next(f for f in findings if f["entity_type"] == "service")
        software = next(f for f in findings if f["entity_type"] == "software_product")
        vulnerability = next(f for f in findings if f["entity_type"] == "vulnerability")

        self.assertEqual(service["name"], "ssh")
        self.assertEqual(software["name"], "OpenSSH")
        self.assertEqual(software["version"], "8.2p1")
        self.assertEqual(software["attributes"]["cpe"], ["cpe:/a:openbsd:openssh:8.2p1"])
        self.assertEqual(vulnerability["name"], "CVE-2020-15778")

    def test_gobuster_parser_extracts_web_content_findings(self):
        findings = parse_gobuster_output(str(FIXTURES / "gobuster_sample.txt"), "10.10.10.10", 80, "dir")
        self.assertEqual(len(findings), 2)
        validate_findings(findings)
        self.assertEqual(findings[0]["name"], "/admin")
        self.assertTrue(findings[0]["attributes"]["is_directory_guess"])
        self.assertEqual(findings[1]["attributes"]["status_code"], 200)

    def test_whatweb_parser_ignores_noise_plugin_and_keeps_products(self):
        findings = parse_whatweb_json(str(FIXTURES / "whatweb_sample.json"))
        self.assertEqual(len(findings), 1)
        validate_findings(findings)
        self.assertEqual(findings[0]["name"], "WordPress")
        self.assertEqual(findings[0]["version"], "6.5.2")
        self.assertEqual(findings[0]["attributes"]["version_candidates"], ["6.5.2", "6.5.x"])

    def test_sqlmap_parser_extracts_vulnerable_parameter(self):
        findings = parse_sqlmap_log(str(FIXTURES / "sqlmap_sample.log"))
        self.assertEqual(len(findings), 2)
        validate_findings(findings)

        first = findings[0]
        self.assertEqual(first["name"], "sql_injection_found")
        self.assertEqual(first["attributes"]["parameter"], "id")
        self.assertEqual(first["host"], "10.10.10.10")
        self.assertEqual(first["attributes"]["risk"], 2)

        second = findings[1]
        self.assertEqual(second["host"], "10.10.10.11")
        self.assertEqual(second["port"], 443)


if __name__ == "__main__":
    unittest.main()
