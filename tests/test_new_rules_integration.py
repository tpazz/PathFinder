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

    def test_adcs_esc_rules_are_technique_specific(self):
        cases = (
            ("ESC1", "AD CS ESC1 - Arbitrary Principal Certificate", "-upn"),
            ("ESC3", "AD CS ESC3 - Enrollment Agent Impersonation", "-on-behalf-of"),
            ("ESC4", "AD CS ESC4 - Certificate Template Takeover", "-write-default-configuration"),
            ("ESC6", "AD CS ESC6 - Conditional SAN Impersonation Chain", "ESC9"),
            ("ESC8", "AD CS ESC8 - Relay to Web Enrollment", "https://<CA_HOST>"),
            ("ESC11", "AD CS ESC11 - Relay to RPC Enrollment", "rpc://<CA_HOST>"),
            ("ESC13", "AD CS ESC13 - Issuance Policy Group Escalation", "-oids"),
        )
        for esc, expected_name, command_marker in cases:
            with self.subTest(esc=esc):
                finding = _f(
                    "CORP.LOCAL", None, "certipy", "privilege_escalation",
                    f"adcs_{esc.lower()}", esc=esc, template="VulnTemplate",
                    description=f"{esc} on VulnTemplate", enrollment_principals=["CORP\\alice"],
                    score=95,
                )
                paths = _synth().generate_attack_paths([finding])
                self.assertIn(expected_name, _names(paths))
                self.assertNotIn("AD CS ESC - Technique-Specific Manual Validation", _names(paths))
                path = next(p for p in paths if p["name"] == expected_name)
                self.assertIn(command_marker, " ".join(path["suggestion"]["commands"]))

    def test_unknown_adcs_esc_uses_manual_validation_not_esc1_workflow(self):
        finding = _f(
            "CORP.LOCAL", None, "certipy", "privilege_escalation", "adcs_esc16",
            esc="ESC16", template="CORP-DC-CA", description="ESC16 on CORP-DC-CA",
            enrollment_principals=[], score=95,
        )
        paths = _synth().generate_attack_paths([finding])
        self.assertIn("AD CS ESC - Technique-Specific Manual Validation", _names(paths))
        manual = next(p for p in paths
                      if p["name"] == "AD CS ESC - Technique-Specific Manual Validation")
        commands = " ".join(manual["suggestion"]["commands"])
        self.assertIn("ESC16", commands)
        self.assertNotIn("-upn", commands)

    def test_cve_detected_fires(self):
        findings = [_f("10.10.10.10", 80, "nuclei", "vulnerability", "CVE-2021-41773",
                       severity="high", matched_at="http://10.10.10.10/cgi-bin", score=85)]
        paths = _synth().generate_attack_paths(findings)
        cve = [p for p in paths if p["name"] == "CVE Detected - Find Public Exploit"]
        self.assertGreaterEqual(len(cve), 1)
        self.assertIn("CVE-2021-41773", cve[0]["suggestion"]["description"])

    def test_query_parameter_fires_contextual_sqli_triage(self):
        findings = [_f("10.10.10.10", 80, "ffuf", "web_parameter_candidate",
                       "sqli:search_query", url="http://10.10.10.10/item.php?search_query=x",
                       parameter="search_query", triage_category="sqli", score=45)]
        paths = _synth().generate_attack_paths(findings)
        triage = [p for p in paths if p["name"] == "Query/Filter Parameter - SQLi Triage"]
        self.assertEqual(len(triage), 1)
        self.assertIn("-p 'search_query'", triage[0]["suggestion"]["commands"][1])

    def test_id_parameter_fires_idor_not_generic_sqli(self):
        findings = [_f("10.10.10.10", 80, "webpage_parameter_extractor",
                       "web_parameter_candidate", "idor:account_id",
                       url="http://10.10.10.10/account?account_id=1", method="GET",
                       parameter="account_id", triage_category="idor", score=45)]
        paths = _synth().generate_attack_paths(findings)
        self.assertIn("Object Identifier Parameter - IDOR Triage", _names(paths))
        self.assertNotIn("Query/Filter Parameter - SQLi Triage", _names(paths))

    def test_smb_service_enum_fallback_fires_with_service_only(self):
        findings = [_f("10.10.10.10", 445, "nmap", "service", "microsoft-ds", score=10)]
        paths = _synth().generate_attack_paths(findings)
        self.assertIn("SMB Service - Enumerate Shares and Users", _names(paths))

    def test_smb_service_enum_fallback_is_suppressed_after_share_discovery(self):
        findings = [
            _f("10.10.10.10", 445, "nmap", "service", "microsoft-ds", score=10),
            _f("10.10.10.10", 445, "smbmap", "share", "backups", permissions="READ"),
        ]
        paths = _synth().generate_attack_paths(findings)
        self.assertNotIn("SMB Service - Enumerate Shares and Users", _names(paths))
        self.assertIn("SMB Share Accessible - Enumerate for Sensitive Files", _names(paths))
        self.assertNotIn("Unhandled Open Service - Manual Protocol Triage", _names(paths))

    def test_smb_service_enum_fallback_is_suppressed_after_user_enumeration(self):
        findings = [
            _f("10.10.10.10", 445, "nmap", "service", "microsoft-ds", score=10),
            _f("10.10.10.10", 445, "enum4linux-ng", "confirmed_username", "alice"),
        ]
        paths = _synth().generate_attack_paths(findings)
        self.assertNotIn("SMB Service - Enumerate Shares and Users", _names(paths))

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
        reuse = [p for p in paths if "Pass-the-Hash on Windows Login Service" in p["name"]]
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
