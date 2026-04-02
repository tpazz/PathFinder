import unittest
from pathlib import Path

from main.finding_schema import validate_findings
from parsers.active_directory.kerberos_parser import parse_kerbrute_output
from parsers.initial_foothold.gobuster_parser import parse_gobuster_output
from parsers.initial_foothold.snmp_parser import parse_snmp_output
from parsers.initial_foothold.sqlmap_parser import parse_sqlmap_log


REAL_WORLD = Path(__file__).parent / "fixtures" / "real_world"


class RealWorldFormatTests(unittest.TestCase):
    def test_gobuster_kali_capture_without_leading_slashes(self):
        findings = parse_gobuster_output(str(REAL_WORLD / "gobuster_kali_no_slash.txt"), "192.168.231.211", 80, "dir")
        self.assertEqual(len(findings), 7)
        self.assertEqual(findings[0]["name"], "/media")
        self.assertTrue(findings[0]["attributes"]["is_directory_guess"])
        validate_findings(findings)

    def test_sqlmap_ansi_capture(self):
        findings = parse_sqlmap_log(str(REAL_WORLD / "sqlmap_ansi.log"))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["host"], "10.10.10.10")
        self.assertEqual(findings[0]["attributes"]["parameter"], "id")
        validate_findings(findings)

    def test_kerbrute_ansi_capture(self):
        findings = parse_kerbrute_output(str(REAL_WORLD / "kerbrute_ansi.txt"), "LAB.LOCAL")
        self.assertEqual({f["name"] for f in findings}, {"alice", "bob"})
        validate_findings(findings)

    def test_snmpcheck_ansi_capture(self):
        findings = parse_snmp_output(str(REAL_WORLD / "snmpcheck_ansi.txt"), "10.10.10.20")
        self.assertGreaterEqual(len(findings), 4)
        self.assertIn("admin", {f["name"] for f in findings if f["entity_type"] == "user"})
        validate_findings(findings)


if __name__ == "__main__":
    unittest.main()
