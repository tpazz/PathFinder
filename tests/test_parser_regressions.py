import tempfile
import unittest
from pathlib import Path

from main.finding_schema import validate_findings
from parsers.initial_foothold.enum4linux_parser import parse_enum4linux_json
from parsers.initial_foothold.gobuster_parser import parse_gobuster_output
from parsers.initial_foothold.nikto_parser import parse_nikto_json
from parsers.initial_foothold.nmap_parser import parse_nmap_xml
from parsers.initial_foothold.snmp_parser import parse_snmp_output
from parsers.initial_foothold.sqlmap_parser import parse_sqlmap_log
from parsers.initial_foothold.whatweb_parser import parse_whatweb_json


FIXTURES = Path(__file__).parent / "fixtures"


class ParserRegressionTests(unittest.TestCase):
    def test_nmap_parser_extracts_service_product_and_vuln(self):
        findings = parse_nmap_xml(str(FIXTURES / "nmap_sample.xml"))
        self.assertGreaterEqual(len(findings), 3)

        service = next(f for f in findings if f["entity_type"] == "service")
        software = next(f for f in findings if f["entity_type"] == "software_product")
        vulnerability = next(f for f in findings if f["entity_type"] == "vulnerability")

        self.assertEqual(service["name"], "ssh")
        self.assertEqual(software["name"], "OpenSSH")
        self.assertEqual(software["version"], "8.2p1")
        self.assertEqual(vulnerability["name"], "CVE-2020-15778")

    def test_nmap_parser_preserves_xml_commandline(self):
        content = (FIXTURES / "nmap_sample.xml").read_text(encoding="utf-8")
        content = content.replace("<nmaprun>", '<nmaprun args="nmap -sC -sV 10.10.10.10">', 1)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False,
                                         encoding="utf-8") as handle:
            handle.write(content)
            path = Path(handle.name)
        self.addCleanup(lambda: path.unlink(missing_ok=True))
        findings = parse_nmap_xml(str(path))
        self.assertTrue(findings)
        self.assertTrue(all(f["attributes"]["discovery_command"] ==
                            "nmap -sC -sV 10.10.10.10" for f in findings))

    def test_gobuster_parser_extracts_web_content_findings(self):
        findings = parse_gobuster_output(str(FIXTURES / "gobuster_sample.txt"), "10.10.10.10", 80, "dir")
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0]["name"], "/admin")
        self.assertTrue(findings[0]["attributes"]["is_directory_guess"])
        self.assertEqual(findings[1]["attributes"]["status_code"], 200)

    def test_gobuster_parser_defaults_port_to_80(self):
        findings = parse_gobuster_output(str(FIXTURES / "gobuster_sample.txt"), "10.10.10.10")
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0]["port"], 80)

    def test_whatweb_parser_ignores_noise_plugin_and_keeps_products(self):
        findings = parse_whatweb_json(str(FIXTURES / "whatweb_sample.json"))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["name"], "WordPress")
        self.assertEqual(findings[0]["version"], "6.5.2")

    def test_sqlmap_parser_extracts_vulnerable_parameter(self):
        findings = parse_sqlmap_log(str(FIXTURES / "sqlmap_sample.log"))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["name"], "sql_injection_found")
        self.assertEqual(findings[0]["attributes"]["parameter"], "id")
        self.assertEqual(findings[0]["host"], "10.10.10.10")

    def test_enum4linux_real_format_dict_of_dicts(self):
        """Test that the parser handles real enum4linux-ng output (dict-of-dicts, different field names)."""
        findings = parse_enum4linux_json(str(FIXTURES / "enum4linux_ng_sample.json"), "10.10.10.40")
        validate_findings(findings)

        users = [f for f in findings if f["entity_type"] == "user"]
        groups = [f for f in findings if f["entity_type"] == "group"]
        shares = [f for f in findings if f["entity_type"] == "share"]
        policy = [f for f in findings if f["entity_type"] == "misconfiguration"]
        os_info = [f for f in findings if f["entity_type"] == "os_details"]

        self.assertEqual(len(users), 3)
        self.assertIn("alice", [u["name"] for u in users])
        self.assertIn("bob", [u["name"] for u in users])

        self.assertEqual(len(groups), 2)
        self.assertIn("Domain Admins", [g["name"] for g in groups])

        self.assertEqual(len(shares), 2)
        self.assertIn("backups", [s["name"] for s in shares])

        self.assertEqual(len(policy), 1)
        self.assertIn("min_pw_length", policy[0]["attributes"])

        self.assertEqual(len(os_info), 1)
        self.assertIn("Windows", os_info[0]["name"])

    def test_snmp_parser_with_real_snmpcheck_format(self):
        """Test that the parser handles real snmp-check output with [*] prefixed headers."""
        findings = parse_snmp_output(str(FIXTURES / "snmpcheck_sample.txt"), "10.10.10.20")
        validate_findings(findings)

        os_findings = [f for f in findings if f["entity_type"] == "os_details"]
        users = [f for f in findings if f["entity_type"] == "user"]
        processes = [f for f in findings if f["entity_type"] == "software_product"]
        network = [f for f in findings if f["entity_type"] == "information_leak"]

        self.assertGreaterEqual(len(os_findings), 1)
        self.assertEqual(len(users), 3)
        self.assertIn("administrator", [u["name"] for u in users])
        self.assertIn("svc_backup", [u["name"] for u in users])
        self.assertGreaterEqual(len(processes), 4)
        self.assertGreaterEqual(len(network), 1)

    def test_nikto_parser_classifies_findings_correctly(self):
        """Test that nikto parser classifies backup files, directory indexing, methods, etc."""
        findings = parse_nikto_json(str(FIXTURES / "nikto_sample.json"))
        validate_findings(findings)

        entity_types = [f["entity_type"] for f in findings]
        self.assertIn("misconfiguration", entity_types)
        self.assertIn("web_content", entity_types)

        # The backup file should be found.
        backup_findings = [f for f in findings if "config.php.bak" in (f.get("name") or "")]
        self.assertGreaterEqual(len(backup_findings), 1)

        # Directory indexing should be classified as misconfiguration.
        dir_index = [f for f in findings if f["name"] == "directory_indexing_found"]
        self.assertEqual(len(dir_index), 1)
        self.assertEqual(dir_index[0]["entity_type"], "misconfiguration")

        # HTTP methods with dangerous methods should be a misconfiguration.
        method_findings = [f for f in findings if f["name"] == "http_methods_revealed"]
        self.assertEqual(len(method_findings), 1)
        self.assertEqual(method_findings[0]["entity_type"], "misconfiguration")
        self.assertTrue(method_findings[0]["attributes"].get("dangerous_methods_found"))


if __name__ == "__main__":
    unittest.main()
