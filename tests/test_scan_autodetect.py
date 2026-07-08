import tempfile
import unittest
from pathlib import Path

from main.pathfinder import _gobuster_extract_target, _sniff_file_type, auto_detect_loot
from parsers.initial_foothold.gobuster_parser import parse_gobuster_output


class ScanAutodetectTests(unittest.TestCase):
    def test_sniff_detects_sqlmap_with_ansi(self):
        content = (
            "\x1b[36m[INFO]\x1b[0m testing 'http://10.10.10.10/item.php?id=1'\n"
            "\x1b[36m[INFO]\x1b[0m GET parameter 'id' is vulnerable\n"
            "sqlmap resumed the following injection point(s)\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False, encoding="utf-8") as tmp:
            tmp.write(content)
            tmp_path = tmp.name

        self.addCleanup(lambda: Path(tmp_path).unlink(missing_ok=True))
        self.assertEqual(_sniff_file_type(tmp_path), "sqlmap_log")

    def test_sniff_detects_kerbrute_with_ansi(self):
        content = "\x1b[32m[+]\x1b[0m \x1b[1mVALID USERNAME:\x1b[0m alice@LAB.LOCAL\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as tmp:
            tmp.write(content)
            tmp_path = tmp.name

        self.addCleanup(lambda: Path(tmp_path).unlink(missing_ok=True))
        self.assertEqual(_sniff_file_type(tmp_path), "kerbrute_txt")

    def test_sniff_detects_snmp_with_ansi(self):
        content = "\x1b[36m[*] System information:\x1b[0m\nLinux target 5.4\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as tmp:
            tmp.write(content)
            tmp_path = tmp.name

        self.addCleanup(lambda: Path(tmp_path).unlink(missing_ok=True))
        self.assertEqual(_sniff_file_type(tmp_path), "snmp_txt")

    def test_sniff_detects_showmount_nfs_output(self):
        content = "Export list for 10.10.10.10:\n/srv/share *(rw,sync,no_root_squash)\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as tmp:
            tmp.write(content)
            tmp_path = tmp.name

        self.addCleanup(lambda: Path(tmp_path).unlink(missing_ok=True))
        self.assertEqual(_sniff_file_type(tmp_path), "nfs_txt")

    def test_sniff_detects_potfile_by_extension(self):
        content = "$krb5asrep$23$svc_sql@LAB.LOCAL:abcdef0123456789:Summer2026!\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".pot", delete=False, encoding="utf-8") as tmp:
            tmp.write(content)
            tmp_path = tmp.name

        self.addCleanup(lambda: Path(tmp_path).unlink(missing_ok=True))
        self.assertEqual(_sniff_file_type(tmp_path), "potfile_txt")

    def test_sniff_detects_gobuster_header_with_uppercase_url_and_ansi(self):
        content = (
            "\ufeff\x1b[32m===============================================================\x1b[0m\n"
            "Gobuster v3.6\n"
            "[+] URL:                     http://10.10.10.10\n"
            "[+] Wordlist:                common.txt\n"
            "Starting gobuster in directory enumeration mode\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as tmp:
            tmp.write(content)
            tmp_path = tmp.name

        self.addCleanup(lambda: Path(tmp_path).unlink(missing_ok=True))
        self.assertEqual(_sniff_file_type(tmp_path), "gobuster_txt")

    def test_auto_detect_loot_finds_top_level_gobuster_file_with_bare_status(self):
        content = (
            "Gobuster v3.6\n"
            "[+] URL: http://10.10.10.10\n"
            "Starting gobuster in directory enumeration mode\n"
            "/admin Status: 301 --> /admin/\n"
        )
        with tempfile.TemporaryDirectory() as tmp_dir:
            loot = Path(tmp_dir)
            (loot / "gobuster-first.txt").write_text(content, encoding="utf-8")

            detected = auto_detect_loot(str(loot))
            gobuster_paths = [d["path"] for d in detected if d["key"] == "gobuster_txt"]
            self.assertIn(str(loot / "gobuster-first.txt"), gobuster_paths)

    def test_auto_detect_loot_finds_gobuster_file_without_leading_slash(self):
        content = (
            "media                (Status: 301) [Size: 327] [--> http://192.168.231.211/election/media/]\n"
            "themes               (Status: 301) [Size: 328] [--> http://192.168.231.211/election/themes/]\n"
        )
        with tempfile.TemporaryDirectory() as tmp_dir:
            loot = Path(tmp_dir)
            (loot / "gobuster.txt").write_text(content, encoding="utf-8")

            detected = auto_detect_loot(str(loot))
            gobuster_paths = [d["path"] for d in detected if d["key"] == "gobuster_txt"]
            self.assertIn(str(loot / "gobuster.txt"), gobuster_paths)

    def test_gobuster_target_extraction_accepts_uppercase_url(self):
        content = (
            "Gobuster v3.6\n"
            "[+] URL: https://target.local:8443\n"
            "Starting gobuster in vhost enumeration mode\n"
            "Found: admin.target.local Status: 200\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as tmp:
            tmp.write(content)
            tmp_path = tmp.name

        self.addCleanup(lambda: Path(tmp_path).unlink(missing_ok=True))
        self.assertEqual(_gobuster_extract_target(tmp_path), ("target.local", 8443, "vhost"))

    def test_gobuster_parser_accepts_bracket_and_bare_status_variants(self):
        content = (
            "/admin [Status: 301] [Size: 0] --> /admin/\n"
            "/login.php Status: 200 Size: 123\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as tmp:
            tmp.write(content)
            tmp_path = tmp.name

        self.addCleanup(lambda: Path(tmp_path).unlink(missing_ok=True))
        findings = parse_gobuster_output(tmp_path, "10.10.10.10", 80, "dir")

        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0]["name"], "/admin")
        self.assertTrue(findings[0]["attributes"]["is_directory_guess"])
        self.assertEqual(findings[1]["name"], "/login.php")
        self.assertEqual(findings[1]["attributes"]["status_code"], 200)

    def test_gobuster_parser_accepts_lines_without_leading_slash(self):
        content = (
            "media                (Status: 301) [Size: 327] [--> http://192.168.231.211/election/media/]\n"
            "admin                (Status: 301) [Size: 327] [--> http://192.168.231.211/election/admin/]\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as tmp:
            tmp.write(content)
            tmp_path = tmp.name

        self.addCleanup(lambda: Path(tmp_path).unlink(missing_ok=True))
        findings = parse_gobuster_output(tmp_path, "192.168.231.211", 80, "dir")

        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0]["name"], "/media")
        self.assertEqual(findings[0]["attributes"]["redirect_url"], "http://192.168.231.211/election/media/")
        self.assertTrue(findings[0]["attributes"]["is_directory_guess"])


if __name__ == "__main__":
    unittest.main()
