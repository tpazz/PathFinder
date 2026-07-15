import tempfile
import unittest
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path

from main.report_generator import render_html_report, write_html_report


class _DocumentParser(HTMLParser):
    pass


class HtmlReportTests(unittest.TestCase):
    def setUp(self):
        self.password = "S3cret!Pass"
        self.nt_hash = "0123456789abcdef0123456789abcdef"
        self.findings = [{
            "name": f"alice:{self.password}",
            "entity_type": "credential",
            "host": "dc01.corp.local",
            "port": 445,
            "source_tool": "netexec",
            "version": None,
            "attributes": {
                "score": 99,
                "username": "alice",
                "password": self.password,
                "nt_hash": self.nt_hash,
                "notes": "<script>alert('finding')</script>",
                "command": "netexec smb -h dc01 -u alice -p provenance-only",
                "discovery_provenance": [{
                    "tool": "netexec",
                    "status": "done",
                    "source_file": "loot/<dc01>/nxc.log",
                    "command": (
                        f"netexec smb -h dc01 -u alice -p {self.password} "
                        f"-H {self.nt_hash} --token bearer-value "
                        "https://alice:url-password@dc01/"
                    ),
                }],
            },
        }]
        self.paths = [{
            "name": "ZERO-HOP: Owned DCSync <win>",
            "host": "corp.local",
            "priority": "99",
            "effective_priority": "not-a-number",
            "evidence": [f"alice:{self.password}"],
            "suggestion": {
                "description": "Owned principal has DCSync.",
                "rationale": "Direct control.",
                "commands": [f"secretsdump -hashes :{self.nt_hash} corp/alice@dc01"],
                "references": ["https://example.invalid/reference", "javascript:alert(1)"],
            },
            "matched_findings": [{"finding": self.findings[0]}],
        }]

    def test_opt_in_redaction_hides_secrets_and_escapes_untrusted_content(self):
        document = render_html_report(
            self.findings,
            self.paths,
            include_secrets=False,
            generated_at=datetime(2026, 7, 15, tzinfo=timezone.utc),
        )

        self.assertNotIn(self.password, document)
        self.assertNotIn(self.nt_hash, document)
        self.assertNotIn("provenance-only", document)
        self.assertNotIn("bearer-value", document)
        self.assertNotIn("url-password", document)
        self.assertIn("[REDACTED]", document)
        self.assertIn("-h dc01", document)
        self.assertIn("&lt;script&gt;alert", document)
        self.assertNotIn("<script", document.lower())
        self.assertIn("default-src 'none'", document)
        self.assertIn("Executive summary", document)
        self.assertIn("Prioritized attack paths", document)
        self.assertIn("Normalized findings", document)
        self.assertIn("Discovery provenance", document)
        self.assertIn("https://example.invalid/reference", document)
        self.assertNotIn("javascript:alert", document)
        _DocumentParser().feed(document)

    def test_default_report_preserves_engagement_evidence(self):
        document = render_html_report(
            self.findings, self.paths,
            generated_at="fixed-time",
        )

        self.assertIn(self.password, document)
        self.assertIn(self.nt_hash, document)
        self.assertIn("url-password", document)
        self.assertIn("preserved; treat this report as sensitive engagement loot", document)

    def test_write_report_creates_parent_and_returns_absolute_path(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "nested" / "engagement.html"
            written = write_html_report(target, self.findings, self.paths)

            self.assertEqual(Path(written), target.resolve())
            self.assertTrue(target.is_file())
            self.assertTrue(target.read_text(encoding="utf-8").startswith("<!doctype html>"))


if __name__ == "__main__":
    unittest.main()
