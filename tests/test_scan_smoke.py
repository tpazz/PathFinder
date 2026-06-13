import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).parent / "fixtures"
REAL_WORLD = FIXTURES / "real_world"


class ScanSmokeTests(unittest.TestCase):
    def _run_scan(self, loot_dir, *extra_args):
        return subprocess.run(
            [sys.executable, "-m", "main.pathfinder", "scan", str(loot_dir), "--offline", *extra_args],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
        )

    def test_scan_cli_handles_mixed_loot_directory(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            loot = Path(tmp_dir)
            shutil.copy(FIXTURES / "nmap_sample.xml", loot / "nmap.xml")
            shutil.copy(REAL_WORLD / "gobuster_kali_no_slash.txt", loot / "gobuster.txt")
            shutil.copy(REAL_WORLD / "sqlmap_ansi.log", loot / "sqlmap.log")

            result = self._run_scan(loot)

            self.assertEqual(result.returncode, 0, result.stdout + "\n" + result.stderr)
            self.assertIn("Detected 3 parseable source(s)", result.stdout)
            self.assertIn("nmap_xml", result.stdout)
            self.assertIn("gobuster_txt", result.stdout)
            self.assertIn("sqlmap_log", result.stdout)

    def test_scan_cli_detects_and_parses_new_parser_types(self):
        """End-to-end: the Phase 3-4 parsers are auto-detected and run by `scan`."""
        files = {
            "ffuf.json": '{"commandline":"ffuf","time":"t","results":[{"input":{"FUZZ":"admin"},"status":200,"length":5,"url":"http://10.10.10.10/admin","host":"10.10.10.10:80"}],"config":{}}',
            "nuclei.jsonl": '{"template-id":"CVE-2021-41773","info":{"name":"x","severity":"high","classification":{"cve-id":["CVE-2021-41773"]}},"matched-at":"http://10.10.10.10","host":"http://10.10.10.10"}\n',
            "wpscan.json": '{"target_url":"http://10.10.10.10/","interesting_findings":[],"version":{"number":"5.8"},"plugins":{"akismet":{"slug":"akismet","version":{"number":"4.0"}}},"users":{"admin":{}}}',
            "netexec.log": "SMB   10.10.10.10   445   DC01   [*] Windows (domain:corp.local) (signing:False)\nSMB   10.10.10.10   445   DC01   [+] corp.local\\admin:Pass123 (Pwn3d!)\n",
            "smbmap.txt": "[+] IP: 10.10.10.10:445\tName: dc01\n\tbackups                                               READ, WRITE\n",
            "secretsdump.txt": "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n",
            "getuserspns.txt": "$krb5tgs$23$*svc$CORP.LOCAL$cifs/svc*$abcd\n",
            "certipy.json": '{"Certificate Templates":{"0":{"Template Name":"Vuln","[!] Vulnerabilities":{"ESC1":"x"}}}}',
        }
        with tempfile.TemporaryDirectory() as tmp_dir:
            loot = Path(tmp_dir)
            for name, content in files.items():
                (loot / name).write_text(content, encoding="utf-8")

            result = self._run_scan(loot)

            self.assertEqual(result.returncode, 0, result.stdout + "\n" + result.stderr)
            self.assertIn(f"Detected {len(files)} parseable source(s)", result.stdout)
            for key in ["ffuf_json", "nuclei_jsonl", "wpscan_json", "netexec_log",
                        "smbmap_txt", "secretsdump_txt", "getuserspns_hashes", "certipy_json"]:
                self.assertIn(key, result.stdout)

    def test_scan_cli_vv_reports_detection_reasons_and_duplicates(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            loot = Path(tmp_dir)
            shutil.copy(FIXTURES / "nmap_sample.xml", loot / "nmap.xml")
            shutil.copy(REAL_WORLD / "gobuster_kali_no_slash.txt", loot / "gobuster.txt")
            shutil.copy(REAL_WORLD / "gobuster_kali_no_slash.txt", loot / "gobuster-duplicate.txt")
            (loot / "notes.txt").write_text("just some notes about the target\n", encoding="utf-8")

            result = self._run_scan(loot, "-vv")

            self.assertEqual(result.returncode, 0, result.stdout + "\n" + result.stderr)
            self.assertIn("duplicate gobuster_txt", result.stdout)
            self.assertIn("notes.txt skipped", result.stdout)
            self.assertIn("reason:", result.stdout)


if __name__ == "__main__":
    unittest.main()
