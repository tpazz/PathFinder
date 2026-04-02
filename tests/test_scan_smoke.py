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
