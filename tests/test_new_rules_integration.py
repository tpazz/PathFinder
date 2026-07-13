"""Integration tests for the attack rules added alongside the Phase 3-4 parsers."""
import unittest
from pathlib import Path

from main.attack_path_synthesizer import AttackPathSynthesizer

RULES_FILE = str(Path(__file__).parent.parent / "main" / "attack_rules.json")


def _synth():
    return AttackPathSynthesizer(rules_file_path=RULES_FILE)


def _f(host, port, tool, etype, name, version=None, **attrs):
    return {"host": host, "port": port, "source_tool": tool, "entity_type": etype,
            "name": name, "version": version, "attributes": attrs}


def _names(paths):
    return [p["name"] for p in paths]


class NewRuleTests(unittest.TestCase):
    def test_validated_admin_access_fires(self):
        findings = [_f("10.10.10.10", 445, "netexec", "privilege_escalation", "admin_access_validated",
                       user="corp.local\\admin", protocol="SMB", description="Validated admin (Pwn3d!) on 10.10.10.10", score=95)]
        paths = _synth().generate_attack_paths(findings)
        self.assertIn("Validated Admin Access (Pwn3d!) - Dump Secrets", _names(paths))

    def test_writable_share_fires(self):
        findings = [_f("10.10.10.10", 445, "smbmap", "misconfiguration", "writable_smb_share",
                       share="backups", permissions="READ, WRITE", description="writable", score=75)]
        paths = _synth().generate_attack_paths(findings)
        wr = [p for p in paths if "Writable SMB Share" in p["name"]]
        self.assertGreaterEqual(len(wr), 1)
        self.assertIn("backups", wr[0]["suggestion"]["description"])

    def test_smb_signing_disabled_fires(self):
        findings = [_f("10.10.10.10", 445, "netexec", "misconfiguration", "smb_signing_disabled",
                       protocol="SMB", description="signing disabled", score=75)]
        paths = _synth().generate_attack_paths(findings)
        self.assertIn("SMB Signing Disabled - NTLM Relay", _names(paths))

    def test_null_session_fires(self):
        findings = [_f("10.10.10.10", 445, "netexec", "misconfiguration", "null_session_allowed",
                       protocol="SMB", description="null session", score=75)]
        paths = _synth().generate_attack_paths(findings)
        self.assertIn("Null/Guest SMB Session - Enumerate Without Creds", _names(paths))

    def test_adcs_esc_fires(self):
        findings = [_f("CORP.LOCAL", None, "certipy", "privilege_escalation", "adcs_esc1",
                       esc="ESC1", template="VulnTemplate", description="ESC1 on VulnTemplate", score=95)]
        paths = _synth().generate_attack_paths(findings)
        adcs = [p for p in paths if "AD CS Vulnerable Certificate Template" in p["name"]]
        self.assertGreaterEqual(len(adcs), 1)
        self.assertIn("ESC1", adcs[0]["suggestion"]["description"])

    def test_cve_detected_fires(self):
        findings = [_f("10.10.10.10", 80, "nuclei", "vulnerability", "CVE-2021-41773",
                       severity="high", matched_at="http://10.10.10.10/cgi-bin", score=85)]
        paths = _synth().generate_attack_paths(findings)
        cve = [p for p in paths if p["name"] == "CVE Detected - Find Public Exploit"]
        self.assertGreaterEqual(len(cve), 1)
        self.assertIn("CVE-2021-41773", cve[0]["suggestion"]["description"])

    def test_parameterized_url_fires_sqlmap_triage_candidate(self):
        findings = [_f("10.10.10.10", 80, "ffuf", "web_parameterized_url",
                       "http://10.10.10.10/item.php?id=1",
                       url="http://10.10.10.10/item.php?id=1", parameters=["id"], score=45)]
        paths = _synth().generate_attack_paths(findings)
        triage = [p for p in paths if p["name"] == "Parameterized URL - SQLi Triage Candidate"]
        self.assertEqual(len(triage), 1)
        self.assertIn("sqlmap -u 'http://10.10.10.10/item.php?id=1'", triage[0]["suggestion"]["commands"][0])

    def test_hash_credential_reuse_emits_pth_command(self):
        """A hash-only credential (e.g. from secretsdump) reused against SMB should
        retain a compact pass-the-hash command template."""
        findings = [
            _f("10.10.10.10", 445, "nmap", "service", "microsoft-ds", score=10),
            _f("10.10.10.10", None, "secretsdump", "credential", "Administrator",
               hash="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
               hash_type="NTLM", password=None, score=90),
        ]
        paths = _synth().generate_attack_paths(findings)
        reuse = [p for p in paths if "Credential Reuse on Login Service" in p["name"]]
        self.assertGreaterEqual(len(reuse), 1)
        commands = " ".join(reuse[0]["suggestion"]["commands"])
        self.assertIn("-H", commands)
        self.assertIn("<NTLM_HASH>", commands)
        self.assertNotIn("31d6cfe0d16ae931b73c59d7e0c089c0", commands)


class NewServiceParserRuleTests(unittest.TestCase):
    """Findings from the Redis / rsync / SMTP / NFS parsers fire their intended
    rules (and NFS exports do NOT fire the SMB share rules)."""

    def setUp(self):
        self.synth = _synth()

    def test_redis_unauthenticated_fires(self):
        findings = [_f("10.10.10.10", 6379, "redis-cli", "misconfiguration", "redis_unauthenticated_info",
                       description="Redis INFO responded without authentication", confidence="high", score=84)]
        self.assertTrue(any("Redis" in n for n in _names(self.synth.generate_attack_paths(findings))))

    def test_rsync_anonymous_listing_fires(self):
        findings = [_f("10.10.10.10", 873, "rsync", "misconfiguration", "rsync_anonymous_module_listing",
                       modules=["backups"], confidence="high", score=82)]
        self.assertTrue(any("Rsync" in n for n in _names(self.synth.generate_attack_paths(findings))))

    def test_smtp_user_enum_fires(self):
        findings = [_f("10.10.10.10", 25, "smtp-user-enum", "information_leak", "smtp_valid_users_enumerated",
                       users=["root", "admin"], confidence="high", score=78)]
        self.assertTrue(any("SMTP User Enumeration" in n for n in _names(self.synth.generate_attack_paths(findings))))

    def test_nfs_export_fires_nfs_rule_not_smb(self):
        findings = [_f("10.10.10.10", 2049, "nfs", "nfs_export", "/srv/share",
                       clients=["*"], options=["rw", "no_root_squash"], world_accessible=True)]
        names = _names(self.synth.generate_attack_paths(findings))
        self.assertIn("NFS Export Accessible - Mount and Loot", names)
        self.assertFalse(any("SMB" in n for n in names))

    def test_nfs_no_root_squash_fires(self):
        findings = [_f("10.10.10.10", 2049, "nfs", "privilege_escalation", "nfs_no_root_squash",
                       export="/srv/share", description="NFS export /srv/share includes no_root_squash and rw")]
        self.assertIn("NFS no_root_squash - SUID Shell via NFS",
                      _names(self.synth.generate_attack_paths(findings)))


if __name__ == "__main__":
    unittest.main()
