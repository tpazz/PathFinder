import json
import tempfile
import unittest
from pathlib import Path

from main.finding_schema import validate_findings
from parsers.active_directory.certipy_parser import parse_certipy_json
from parsers.active_directory.kerberos_parser import parse_getuserspns_output
from parsers.active_directory.secretsdump_parser import parse_secretsdump
from parsers.initial_foothold.ffuf_parser import parse_ffuf_json
from parsers.initial_foothold.gobuster_parser import parse_gobuster_output
from parsers.initial_foothold.nikto_parser import parse_nikto_json
from parsers.initial_foothold.netexec_parser import parse_netexec_output
from parsers.initial_foothold.nuclei_parser import parse_nuclei_jsonl
from parsers.initial_foothold.smbmap_parser import parse_smbmap_output
from parsers.initial_foothold.wpscan_parser import parse_wpscan_json


class NewParserTests(unittest.TestCase):
    def _write(self, content, suffix=".txt"):
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False, encoding="utf-8")
        tmp.write(content)
        tmp.close()
        self.addCleanup(lambda: Path(tmp.name).unlink(missing_ok=True))
        return tmp.name

    def test_ffuf(self):
        payload = {
            "commandline": "ffuf -u http://10.10.10.10/FUZZ -w wl",
            "time": "now",
            "results": [
                {"input": {"FUZZ": "admin"}, "status": 200, "length": 100, "url": "http://10.10.10.10/admin", "host": "10.10.10.10:80"},
                {"input": {"FUZZ": "index.html"}, "status": 200, "length": 50, "url": "http://10.10.10.10/index.html", "host": "10.10.10.10:80"},
            ],
            "config": {},
        }
        findings = parse_ffuf_json(self._write(json.dumps(payload), ".json"))
        validate_findings(findings)
        self.assertEqual(len(findings), 2)
        self.assertTrue(all(f["entity_type"] == "web_content" for f in findings))
        admin = next(f for f in findings if f["name"] == "/admin")
        self.assertEqual(admin["port"], 80)
        self.assertTrue(admin["attributes"]["is_directory_guess"])
        self.assertFalse(next(f for f in findings if f["name"] == "/index.html")["attributes"]["is_directory_guess"])

    def test_ffuf_emits_sqlmap_candidate_for_parameterized_url(self):
        payload = {
            "commandline": "ffuf -u http://10.10.10.10/FUZZ -w wl",
            "results": [
                {"input": {"FUZZ": "item.php?id=1"}, "status": 200, "length": 100,
                 "url": "http://10.10.10.10/item.php?id=1", "host": "10.10.10.10:80"},
            ],
            "config": {},
        }
        findings = parse_ffuf_json(self._write(json.dumps(payload), ".json"))
        validate_findings(findings)
        candidate = next(f for f in findings if f["entity_type"] == "web_parameterized_url")
        self.assertEqual(candidate["attributes"]["url"], "http://10.10.10.10/item.php?id=1")
        self.assertEqual(candidate["attributes"]["parameters"], ["id"])

    def test_gobuster_and_nikto_emit_sqlmap_candidates_for_parameterized_urls(self):
        gobuster_findings = parse_gobuster_output(
            self._write("/search.php?q=test (Status: 200) [Size: 10]\n"),
            "10.10.10.10",
            80,
        )
        nikto_payload = {
            "host": "10.10.10.11",
            "port": "8080",
            "vulnerabilities": [{"id": "001", "msg": "/view.php?page=home might be interesting",
                                 "url": "/view.php?page=home", "method": "GET"}],
        }
        nikto_findings = parse_nikto_json(self._write(json.dumps(nikto_payload), ".json"))
        validate_findings(gobuster_findings + nikto_findings)

        urls = {f["attributes"]["url"] for f in gobuster_findings + nikto_findings
                if f["entity_type"] == "web_parameterized_url"}
        self.assertIn("http://10.10.10.10:80/search.php?q=test", urls)
        self.assertIn("http://10.10.10.11:8080/view.php?page=home", urls)

    def test_nuclei(self):
        lines = [
            json.dumps({"template-id": "CVE-2021-41773", "info": {"name": "Apache Path Traversal", "severity": "high",
                        "classification": {"cve-id": ["CVE-2021-41773"], "cvss-score": 7.5}},
                        "matched-at": "http://10.10.10.10/cgi-bin", "host": "http://10.10.10.10"}),
            json.dumps({"template-id": "tech-detect", "info": {"name": "Tech", "severity": "info"},
                        "matched-at": "http://10.10.10.10"}),
        ]
        findings = parse_nuclei_jsonl(self._write("\n".join(lines) + "\n", ".jsonl"))
        validate_findings(findings)
        self.assertEqual(len(findings), 2)
        vuln = next(f for f in findings if f["name"] == "CVE-2021-41773")
        self.assertEqual(vuln["entity_type"], "vulnerability")
        self.assertEqual(vuln["attributes"]["severity"], "high")
        info = next(f for f in findings if f["attributes"]["severity"] == "info")
        self.assertEqual(info["entity_type"], "information_leak")

    def test_nuclei_emits_sqlmap_candidate_for_parameterized_match(self):
        line = json.dumps({"template-id": "reflected-param", "info": {"name": "Reflected parameter", "severity": "info"},
                           "matched-at": "http://10.10.10.10/product.php?cat=2"})
        findings = parse_nuclei_jsonl(self._write(line + "\n", ".jsonl"))
        validate_findings(findings)
        candidate = next(f for f in findings if f["entity_type"] == "web_parameterized_url")
        self.assertEqual(candidate["attributes"]["parameters"], ["cat"])

    def test_wpscan(self):
        payload = {
            "target_url": "http://10.10.10.10/",
            "version": {"number": "5.8", "status": "insecure",
                        "vulnerabilities": [{"title": "WP <5.8.1 SQLi", "references": {"cve": ["2021-1234"]}}]},
            "main_theme": {"slug": "twentytwentyone", "version": {"number": "1.4"}, "vulnerabilities": []},
            "plugins": {"contact-form-7": {"slug": "contact-form-7", "version": {"number": "5.4"},
                        "vulnerabilities": [{"title": "CF7 RCE", "references": {"cve": ["2020-0001"]}}]}},
            "users": {"admin": {"id": 1}},
        }
        findings = parse_wpscan_json(self._write(json.dumps(payload), ".json"))
        validate_findings(findings)
        core = next(f for f in findings if f["name"] == "WordPress")
        self.assertEqual(core["version"], "5.8")
        self.assertTrue(any(f["name"] == "WordPress plugin: contact-form-7" for f in findings))
        self.assertTrue(any(f["entity_type"] == "vulnerability" for f in findings))
        self.assertTrue(any(f["entity_type"] == "user" and f["name"] == "admin" for f in findings))

    def test_smbmap(self):
        content = (
            "[+] IP: 10.10.10.10:445\tName: dc01.corp.local\n"
            "\tDisk                                                  Permissions\tComment\n"
            "\t----                                                  -----------\t-------\n"
            "\tADMIN$                                                NO ACCESS\tRemote Admin\n"
            "\tIPC$                                                  READ ONLY\tRemote IPC\n"
            "\tbackups                                               READ, WRITE\t\n"
        )
        findings = parse_smbmap_output(self._write(content), "10.10.10.10")
        validate_findings(findings)
        shares = {f["name"] for f in findings if f["entity_type"] == "share"}
        self.assertIn("backups", shares)
        self.assertIn("IPC$", shares)
        writable = [f for f in findings if f["name"] == "writable_smb_share"]
        self.assertEqual(len(writable), 1)
        self.assertEqual(writable[0]["attributes"]["share"], "backups")

    def test_netexec(self):
        content = (
            "SMB   10.10.10.10   445   DC01   [*] Windows 10.0 Build 17763 (name:DC01) (domain:corp.local) (signing:False) (SMBv1:False)\n"
            "SMB   10.10.10.10   445   DC01   [+] corp.local\\admin:Password123 (Pwn3d!)\n"
            "SMB   10.10.10.10   445   DC01   [+] corp.local\\svc:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0\n"
            "SMB   10.10.10.10   445   DC01   [-] corp.local\\baduser:wrong STATUS_LOGON_FAILURE\n"
            "SMB   10.10.10.10   445   DC01   [*] Enumerated shares\n"
            "SMB   10.10.10.10   445   DC01   Share           Permissions     Remark\n"
            "SMB   10.10.10.10   445   DC01   -----           -----------     ------\n"
            "SMB   10.10.10.10   445   DC01   ADMIN$                          Remote Admin\n"
            "SMB   10.10.10.10   445   DC01   data            READ,WRITE      Data share\n"
        )
        findings = parse_netexec_output(self._write(content, ".log"), "10.10.10.10")
        validate_findings(findings)

        creds = [f for f in findings if f["entity_type"] == "credential"]
        self.assertEqual({c["name"] for c in creds}, {"admin", "svc"})
        admin = next(c for c in creds if c["name"] == "admin")
        self.assertEqual(admin["attributes"]["password"], "Password123")
        svc = next(c for c in creds if c["name"] == "svc")
        self.assertEqual(svc["attributes"]["hash_type"], "NTLM")
        self.assertIsNone(svc["attributes"]["password"])

        self.assertEqual(len([f for f in findings if f["name"] == "admin_access_validated"]), 1)
        self.assertEqual(len([f for f in findings if f["name"] == "smb_signing_disabled"]), 1)
        self.assertEqual(len([f for f in findings if f["name"] == "writable_smb_share"]), 1)

    def test_secretsdump(self):
        content = (
            "[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)\n"
            "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
            "CORP.LOCAL\\svc_sql:1104:aad3b435b51404eeaad3b435b51404ee:abcdef0123456789abcdef0123456789:::\n"
            "DC01$:1000:aad3b435b51404eeaad3b435b51404ee:11111111111111111111111111111111:::\n"
        )
        findings = parse_secretsdump(self._write(content), "10.10.10.10")
        validate_findings(findings)
        names = {f["name"] for f in findings}
        self.assertEqual(names, {"Administrator", "svc_sql", "DC01$"})
        self.assertTrue(all(f["entity_type"] == "credential" for f in findings))
        svc = next(f for f in findings if f["name"] == "svc_sql")
        self.assertEqual(svc["attributes"]["hash_type"], "NTLM")
        self.assertEqual(svc["attributes"]["domain"], "CORP.LOCAL")
        self.assertTrue(next(f for f in findings if f["name"] == "DC01$")["attributes"]["machine_account"])

    def test_getuserspns(self):
        content = "$krb5tgs$23$*svc_sql$CORP.LOCAL$cifs/svc.corp.local*$abcdef0123456789\n"
        findings = parse_getuserspns_output(self._write(content), "CORP.LOCAL")
        validate_findings(findings)
        self.assertEqual(len([f for f in findings if f["name"] == "kerberoastable_user"]), 1)
        creds = [f for f in findings if f["entity_type"] == "credential"]
        self.assertEqual(len(creds), 1)
        self.assertEqual(creds[0]["name"], "svc_sql")
        self.assertIn("13100", creds[0]["attributes"]["hash_type"])

    def test_certipy(self):
        payload = {
            "Certificate Authorities": {"0": {"CA Name": "CORP-DC-CA"}},
            "Certificate Templates": {
                "0": {"Template Name": "VulnTemplate", "Enabled": True,
                      "[!] Vulnerabilities": {"ESC1": "Enrollee supplies subject + client auth"}},
            },
        }
        findings = parse_certipy_json(self._write(json.dumps(payload), ".json"), "CORP.LOCAL")
        validate_findings(findings)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["name"], "adcs_esc1")
        self.assertEqual(findings[0]["attributes"]["esc"], "ESC1")
        self.assertEqual(findings[0]["attributes"]["template"], "VulnTemplate")


if __name__ == "__main__":
    unittest.main()
