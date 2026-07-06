import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from main.pathfinder import _oscp_process_commands

REPO_ROOT = Path(__file__).resolve().parent.parent


class OscpCommandProcessingTests(unittest.TestCase):
    def test_prohibited_replaced_and_deduped(self):
        out, uses_msf = _oscp_process_commands([
            "sqlmap -u http://x/?id=1 --os-shell",
            "sqlmap -u http://x/?id=1 --dump",
            "curl http://x/",
        ])
        self.assertEqual(out, [
            "[OSCP] sqlmap is restricted on the exam - perform this step manually.",
            "curl http://x/",
        ])
        self.assertFalse(uses_msf)

    def test_metasploit_flagged_not_removed(self):
        out, uses_msf = _oscp_process_commands(["msfconsole -x 'use exploit/windows/smb/ms17_010'"])
        self.assertTrue(uses_msf)
        self.assertEqual(out, ["msfconsole -x 'use exploit/windows/smb/ms17_010'"])

    def test_nuclei_prohibited(self):
        out, _ = _oscp_process_commands(["nuclei -u http://x -jsonl"])
        self.assertIn("nuclei", out[0].lower())
        self.assertIn("restricted", out[0].lower())


class OscpScanCliTests(unittest.TestCase):
    def test_scan_oscp_flags_sqlmap_and_strips_commands(self):
        content = (
            "[INFO] testing 'http://10.10.10.10/item.php?id=1'\n"
            "[INFO] GET parameter 'id' is vulnerable\n"
            "[INFO] the back-end DBMS is MySQL\n"
            "sqlmap identified the following injection point\n"
        )
        with tempfile.TemporaryDirectory() as tmp_dir:
            loot = Path(tmp_dir)
            (loot / "sqlmap.log").write_text(content, encoding="utf-8")

            result = subprocess.run(
                [sys.executable, "-m", "main.pathfinder", "scan", str(loot),
                 "--offline", "--no-color", "--oscp", "--target-host", "10.10.10.10"],
                capture_output=True, text=True, cwd=REPO_ROOT,
            )

            self.assertEqual(result.returncode, 0, result.stdout + "\n" + result.stderr)
            # Prohibited-tool output is flagged on ingestion...
            self.assertIn("ingested output from restricted tool(s): sqlmap", result.stdout)
            # ...and its commands are replaced with the manual-exploitation note.
            self.assertIn("sqlmap is restricted on the exam", result.stdout)
            self.assertNotIn("--os-shell", result.stdout)


if __name__ == "__main__":
    unittest.main()
