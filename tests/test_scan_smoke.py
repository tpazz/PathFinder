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

    def test_scan_cli_vv_ingests_every_file_and_reports_reasons(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            loot = Path(tmp_dir)
            shutil.copy(FIXTURES / "nmap_sample.xml", loot / "nmap.xml")
            shutil.copy(REAL_WORLD / "gobuster_kali_no_slash.txt", loot / "gobuster.txt")
            shutil.copy(REAL_WORLD / "gobuster_kali_no_slash.txt", loot / "gobuster-second.txt")
            (loot / "notes.txt").write_text("just some notes about the target\n", encoding="utf-8")

            result = self._run_scan(loot, "-vv")

            self.assertEqual(result.returncode, 0, result.stdout + "\n" + result.stderr)
            # Both gobuster files are now ingested (no first-per-type dropping).
            self.assertIn("gobuster.txt", result.stdout)
            self.assertIn("gobuster-second.txt", result.stdout)
            self.assertIn("notes.txt skipped", result.stdout)
            self.assertIn("reason:", result.stdout)

    @staticmethod
    def _mini_nmap_xml(ip):
        return (
            '<?xml version="1.0"?><nmaprun scanner="nmap">'
            f'<host><address addr="{ip}" addrtype="ipv4"/><ports>'
            '<port protocol="tcp" portid="22"><state state="open"/>'
            '<service name="ssh" product="OpenSSH" version="8.2p1"/></port>'
            '<port protocol="tcp" portid="445"><state state="open"/>'
            '<service name="microsoft-ds"/></port>'
            '</ports></host></nmaprun>'
        )

    def test_scan_cli_cross_host_credential_reuse(self):
        """The flagship multi-host behaviour: a credential captured on one host is
        suggested against services on a *different* host (which has no creds of its own)."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            loot = Path(tmp_dir)
            for host in ("10.10.10.10", "10.10.10.20"):
                (loot / host).mkdir()
                (loot / host / "nmap.xml").write_text(self._mini_nmap_xml(host), encoding="utf-8")
            # Credential + admin access captured ONLY on .10.
            (loot / "10.10.10.10" / "nxc.log").write_text(
                "SMB   10.10.10.10   445   DC01   [*] Windows (domain:corp.local) (signing:False)\n"
                "SMB   10.10.10.10   445   DC01   [+] corp.local\\admin:Spring2024 (Pwn3d!)\n",
                encoding="utf-8",
            )

            result = self._run_scan(loot)

            self.assertEqual(result.returncode, 0, result.stdout + "\n" + result.stderr)
            self.assertIn("across 2 host(s)", result.stdout)
            self.assertIn("Credential Reuse on Login Service", result.stdout)
            # .20 has no credential of its own, so any path targeting it is cross-host.
            self.assertIn("10.10.10.20", result.stdout)

    def test_scan_cli_multihost_per_host_directories(self):
        """Per-host subdirectories: every file is ingested and stamped with the
        correct host from its directory name, with no --target-host needed."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            loot = Path(tmp_dir)
            for host in ("10.10.10.10", "10.10.10.20"):
                (loot / host).mkdir()
                (loot / host / "linpeas.txt").write_text(
                    "linpeas.sh - Linux Privilege Escalation Awesome Script\n"
                    "sudo -l is available to this user without a password\n",
                    encoding="utf-8")

            result = self._run_scan(loot)

            self.assertEqual(result.returncode, 0, result.stdout + "\n" + result.stderr)
            self.assertIn("across 2 host(s)", result.stdout)
            # Host-dependent linpeas findings must carry the host from their directory.
            self.assertIn("Host: 10.10.10.10", result.stdout)
            self.assertIn("Host: 10.10.10.20", result.stdout)


if __name__ == "__main__":
    unittest.main()
