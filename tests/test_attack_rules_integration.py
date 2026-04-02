"""
Integration tests that simulate realistic Proving Grounds Practice / OSCP lab
scenarios by feeding realistic findings into the synthesizer and verifying
that the expected attack paths fire.

Each test method represents a different lab archetype.
"""
import json
import unittest
from pathlib import Path

from main.attack_path_synthesizer import AttackPathSynthesizer

RULES_FILE = str(Path(__file__).parent.parent / "main" / "attack_rules.json")


def _synth():
    return AttackPathSynthesizer(rules_file_path=RULES_FILE)


def _path_names(paths):
    return [p["name"] for p in paths]


# ---------------------------------------------------------------------------
# Helper to build findings quickly
# ---------------------------------------------------------------------------
def _f(host, port, tool, etype, name, version=None, **attrs):
    return {
        "host": host, "port": port, "source_tool": tool,
        "entity_type": etype, "name": name, "version": version,
        "attributes": attrs,
    }


class TestAllProductionRulesValid(unittest.TestCase):
    def test_all_rules_pass_validation(self):
        synth = _synth()
        with open(RULES_FILE) as f:
            total = len(json.load(f))
        self.assertEqual(len(synth.rules), total,
                         f"{total - len(synth.rules)} rules failed validation")


class TestLinuxWebServerLab(unittest.TestCase):
    """
    Scenario: Classic PG Practice Linux box.
    nmap finds SSH + HTTP, gobuster finds /admin and /backup.zip,
    nikto finds directory indexing, whatweb finds WordPress 6.5.
    User adds a credential found in backup.zip.
    """

    def setUp(self):
        self.synth = _synth()
        self.findings = [
            # nmap
            _f("10.10.10.10", 22, "nmap", "service", "ssh"),
            _f("10.10.10.10", 80, "nmap", "service", "http"),
            _f("10.10.10.10", 22, "nmap", "software_product", "OpenSSH", "8.2p1", score=40),
            _f("10.10.10.10", 80, "nmap", "software_product", "Apache HTTP Server", "2.4.49", score=40),
            # gobuster
            _f("10.10.10.10", 80, "gobuster", "web_content", "/admin", status_code=301, is_directory_guess=True, score=90),
            _f("10.10.10.10", 80, "gobuster", "web_content", "/backup.zip", status_code=200, is_directory_guess=False, score=85),
            _f("10.10.10.10", 80, "gobuster", "web_content", "/uploads", status_code=301, is_directory_guess=True, score=70),
            _f("10.10.10.10", 80, "gobuster", "web_content", "/wp-login.php", status_code=200, is_directory_guess=False, score=90),
            # nikto
            _f("10.10.10.10", 80, "nikto", "misconfiguration", "directory_indexing_found", url_path_nikto="/icons/"),
            _f("10.10.10.10", 80, "nikto", "misconfiguration", "http_methods_revealed", dangerous_methods_found=True),
            # whatweb
            _f("10.10.10.10", 80, "whatweb", "software_product", "WordPress", "6.5", score=40),
            # searchsploit found an exploit for Apache 2.4.49
            _f("10.10.10.10", 80, "searchsploit_mapper", "vulnerability", "EDB-ID:50383 - Apache 2.4.49 Path Traversal", score=80),
            # manual credential from backup.zip
            _f("MANUALLY_ADDED", None, "manual_input", "credential", "admin", password="Backup2024!", hash=None, score=100),
        ]

    def test_credential_reuse_on_ssh(self):
        paths = self.synth.generate_attack_paths(self.findings)
        cred_ssh = [p for p in paths if "Credential Reuse on Login Service" in p["name"]]
        self.assertGreaterEqual(len(cred_ssh), 1)
        self.assertIn("admin", cred_ssh[0]["suggestion"]["description"])

    def test_credential_reuse_on_wp_login(self):
        paths = self.synth.generate_attack_paths(self.findings)
        cred_web = [p for p in paths if "Credential Reuse on Web Login" in p["name"]]
        self.assertGreaterEqual(len(cred_web), 1)

    def test_wordpress_wpscan_fires(self):
        paths = self.synth.generate_attack_paths(self.findings)
        wp = [p for p in paths if "WordPress" in p["name"]]
        self.assertGreaterEqual(len(wp), 1)

    def test_backup_file_fires(self):
        paths = self.synth.generate_attack_paths(self.findings)
        backup = [p for p in paths if "Backup" in p["name"] or "backup" in p["name"]]
        self.assertGreaterEqual(len(backup), 1)

    def test_upload_endpoint_fires(self):
        paths = self.synth.generate_attack_paths(self.findings)
        upload = [p for p in paths if "Upload" in p["name"] or "upload" in p["name"]]
        self.assertGreaterEqual(len(upload), 1)

    def test_directory_indexing_fires(self):
        paths = self.synth.generate_attack_paths(self.findings)
        diridx = [p for p in paths if "Directory Indexing" in p["name"]]
        self.assertGreaterEqual(len(diridx), 1)

    def test_dangerous_http_methods_fires(self):
        paths = self.synth.generate_attack_paths(self.findings)
        methods = [p for p in paths if "HTTP Methods" in p["name"]]
        self.assertGreaterEqual(len(methods), 1)

    def test_known_exploit_for_apache(self):
        paths = self.synth.generate_attack_paths(self.findings)
        exploit = [p for p in paths if "Known Vulnerable Software" in p["name"] and "Public" in p["name"]]
        self.assertGreaterEqual(len(exploit), 1)

    def test_ftp_webshell_does_not_fire(self):
        """FTP+web combo should NOT fire because there's no FTP service."""
        paths = self.synth.generate_attack_paths(self.findings)
        ftp_web = [p for p in paths if "Webshell via FTP" in p["name"]]
        self.assertEqual(len(ftp_web), 0)


class TestLinuxPrivEscLab(unittest.TestCase):
    """
    Scenario: Got a shell on a Linux box, ran LinPEAS.
    Found SUID binary, writable cron, sudo misconfiguration, and Docker socket.
    """

    def setUp(self):
        self.synth = _synth()
        self.findings = [
            _f("10.10.10.10", None, "linpeas", "privilege_escalation", "sudo_nopasswd_privileges",
               description="/usr/bin/vim", confidence="high", signal_source="keyword_section_match", score=95),
            _f("10.10.10.10", None, "linpeas", "privilege_escalation", "suid_binary_found",
               description="/usr/bin/pkexec", confidence="medium", signal_source="keyword_match", score=95),
            _f("10.10.10.10", None, "linpeas", "privilege_escalation", "writable_cron_job",
               description="/opt/scripts/backup.sh", confidence="high", signal_source="keyword_section_match", score=95),
            _f("10.10.10.10", None, "linpeas", "privilege_escalation", "writable_docker_socket",
               description="/var/run/docker.sock", confidence="high", signal_source="color_signature", score=95),
            _f("10.10.10.10", None, "linpeas", "privilege_escalation", "lxd_privilege_escalation_possible",
               description="User is member of lxd group", confidence="medium", signal_source="keyword_match", score=95),
            _f("10.10.10.10", None, "linpeas", "privilege_escalation", "writable_sensitive_file_etc_passwd_shadow",
               description="/etc/passwd is world-writable", confidence="high", signal_source="color_signature", score=95),
            _f("10.10.10.10", None, "linpeas", "privilege_escalation", "nfs_no_root_squash",
               description="/srv/nfs *(rw,no_root_squash)", confidence="high", signal_source="keyword_match", score=95),
            _f("10.10.10.10", None, "linpeas", "privilege_escalation", "outdated_sudo_version",
               description="Sudo version 1.8.21p2", confidence="medium", signal_source="keyword_match", score=95),
            _f("10.10.10.10", None, "linpeas", "privilege_escalation", "process_capabilities_found",
               description="/usr/bin/python3.8 = cap_setuid+ep", confidence="medium", signal_source="keyword_match", score=95),
            _f("10.10.10.10", None, "linpeas", "privilege_escalation", "guid_binary_found",
               description="/usr/bin/expiry", confidence="low", signal_source="keyword_match", score=95),
            _f("10.10.10.10", None, "linpeas", "privilege_escalation", "peas_highlighted_finding_95_pwnable",
               description="Some critical finding", confidence="high", signal_source="color_signature", score=95),
        ]

    def test_all_linux_privesc_rules_fire(self):
        paths = self.synth.generate_attack_paths(self.findings)
        names = _path_names(paths)
        self.assertIn("Sudo Misconfiguration - GTFOBins Escalation", names)
        self.assertIn("SUID Binary - GTFOBins / Custom Binary Exploitation", names)
        self.assertIn("Writable Cron Job - Command Injection", names)
        self.assertIn("Docker Socket Writable - Container Escape to Root", names)
        self.assertIn("LXD Group Membership - Container Escape to Root", names)
        self.assertIn("Writable /etc/passwd or /etc/shadow", names)
        self.assertIn("NFS no_root_squash - SUID Shell via NFS", names)
        self.assertIn("Outdated Sudo Version - CVE Exploit", names)
        self.assertIn("Linux Capabilities - Escalation via Cap Abuse", names)
        self.assertIn("GUID Binary Found", names)
        self.assertIn("PEAS Highlighted Critical Finding (95% Exploitable)", names)

    def test_highest_priority_is_writable_passwd(self):
        paths = self.synth.generate_attack_paths(self.findings)
        top = paths[0]
        self.assertEqual(top["name"], "Writable /etc/passwd or /etc/shadow")


class TestWindowsPrivEscLab(unittest.TestCase):
    """
    Scenario: Got a shell on a Windows box, ran WinPEAS.
    Found SeImpersonate, unquoted service path, AlwaysInstallElevated, etc.
    """

    def setUp(self):
        self.synth = _synth()
        self.findings = [
            _f("10.10.10.20", None, "winpeas", "privilege_escalation", "seimpersonateprivilege_enabled",
               description="SeImpersonatePrivilege is enabled", confidence="high", score=95),
            _f("10.10.10.20", None, "winpeas", "privilege_escalation", "unquoted_service_path",
               description="C:\\Program Files\\Vuln App\\service.exe", confidence="high", score=95),
            _f("10.10.10.20", None, "winpeas", "privilege_escalation", "alwaysinstallelevated_registry_key",
               description="Both HKLM and HKCU keys set", confidence="high", score=95),
            _f("10.10.10.20", None, "winpeas", "privilege_escalation", "stored_credentials_credman",
               description="Target: Domain:interactive=CORP\\admin", confidence="high", score=95),
            _f("10.10.10.20", None, "winpeas", "privilege_escalation", "group_policy_preferences_password_found",
               description="Found cpassword in Groups.xml", confidence="high", score=95),
            _f("10.10.10.20", None, "winpeas", "privilege_escalation", "writable_service_binary",
               description="C:\\Services\\backup_svc.exe (writable)", confidence="high", score=95),
            _f("10.10.10.20", None, "winpeas", "privilege_escalation", "dll_hijacking_opportunity",
               description="C:\\Services\\missing.dll not found in writable path", confidence="medium", score=95),
            _f("10.10.10.20", None, "winpeas", "privilege_escalation", "unattended_install_file_found",
               description="C:\\Windows\\Panther\\unattend.xml", confidence="medium", score=95),
        ]

    def test_all_windows_privesc_rules_fire(self):
        paths = self.synth.generate_attack_paths(self.findings)
        names = _path_names(paths)
        self.assertIn("SeImpersonatePrivilege - Potato Attack to SYSTEM", names)
        self.assertIn("Unquoted Service Path - Binary Hijacking", names)
        self.assertIn("AlwaysInstallElevated - MSI Shell as SYSTEM", names)
        self.assertIn("Stored Credentials in Credential Manager", names)
        self.assertIn("GPP Passwords Found - Recover Plaintext Credentials", names)
        self.assertIn("Writable Service Binary - Replace with Shell", names)
        self.assertIn("DLL Hijacking Opportunity", names)
        self.assertIn("Unattended Install File - Recover Credentials", names)

    def test_seimpersonate_is_high_priority(self):
        paths = self.synth.generate_attack_paths(self.findings)
        potato = next(p for p in paths if "Potato" in p["name"])
        self.assertGreaterEqual(potato["priority"], 94)


class TestADLabScenario(unittest.TestCase):
    """
    Scenario: Active Directory lab.
    SharpHound found Kerberoastable user, AS-REP roastable, DCSync rights,
    unconstrained delegation, ACL abuses, RBCD, and privileged sessions.
    ldapdomaindump found users with PASSWD_NOTREQD.
    """

    def setUp(self):
        self.synth = _synth()
        self.findings = [
            # SharpHound findings
            _f("CORP.LOCAL", 88, "sharphound", "privilege_escalation", "kerberoastable_user",
               user="svc_sql@CORP.LOCAL", score=95),
            _f("CORP.LOCAL", 88, "sharphound", "privilege_escalation", "asreproastable_user",
               user="svc_backup@CORP.LOCAL", score=95),
            _f("CORP.LOCAL", None, "sharphound", "privilege_escalation", "dcsync_rights_found",
               user="svc_replication@CORP.LOCAL", score=95),
            _f("CORP.LOCAL", None, "sharphound", "privilege_escalation", "unconstrained_delegation_enabled",
               computer="WEB01.CORP.LOCAL", score=95),
            _f("CORP.LOCAL", None, "sharphound", "privilege_escalation", "genericwrite_on_sensitive_group",
               attacker="svc_sql@CORP.LOCAL", target="Domain Admins", score=95),
            _f("CORP.LOCAL", None, "sharphound", "privilege_escalation", "acl_abuse_right_on_object",
               attacker="helpdesk@CORP.LOCAL", target="admin@CORP.LOCAL", right="ForceChangePassword", score=95),
            _f("CORP.LOCAL", None, "sharphound", "privilege_escalation", "resource_based_constrained_delegation_possible",
               computer="DB01.CORP.LOCAL", delegation_entries=["WEB01$"], score=95),
            _f("CORP.LOCAL", None, "sharphound", "privilege_escalation", "privileged_user_session_found",
               user="admin@CORP.LOCAL", computer="WEB01.CORP.LOCAL", score=95),
            _f("CORP.LOCAL", None, "sharphound", "privilege_escalation", "attractive_user_high_privileges",
               user="admin@CORP.LOCAL", score=95),
            # ldapdomaindump
            _f("CORP.LOCAL", 389, "ldapdomaindump", "misconfiguration", "password_not_required_flag",
               user="guest_svc", score=75),
            _f("CORP.LOCAL", 445, "enum4linux-ng", "misconfiguration", "password_policy_details",
               min_length=5, pw_complexity="0", score=75),
            # kerbrute users
            _f("CORP.LOCAL", 88, "kerbrute", "user", "svc_sql", source="Kerberos user enumeration", score=20),
            _f("CORP.LOCAL", 88, "kerbrute", "user", "admin", source="Kerberos user enumeration", score=20),
            # Services
            _f("10.10.10.100", 445, "nmap", "service", "microsoft-ds", score=10),
            _f("10.10.10.100", 5985, "nmap", "service", "winrm", score=10),
        ]

    def test_all_ad_rules_fire(self):
        paths = self.synth.generate_attack_paths(self.findings)
        names = _path_names(paths)
        self.assertIn("Kerberoastable User - Crack Service Account", names)
        self.assertIn("AS-REP Roastable User - Crack Without Pre-Auth", names)
        self.assertIn("DCSync Rights - Dump All Domain Hashes", names)
        self.assertIn("Unconstrained Delegation - Coerce DC Authentication", names)
        self.assertIn("GenericWrite/GenericAll on High-Value Group", names)
        self.assertIn("ACL Abuse Right - ForceChangePassword / WriteDacl / WriteOwner", names)
        self.assertIn("Resource-Based Constrained Delegation (RBCD) Abuse", names)
        self.assertIn("Privileged User Session on Computer - Credential Theft Target", names)
        self.assertIn("High-Privilege Admin User Identified", names)
        self.assertIn("Password Not Required Flag - Try Empty Password", names)

    def test_dcsync_is_highest_priority(self):
        paths = self.synth.generate_attack_paths(self.findings)
        self.assertEqual(paths[0]["name"], "DCSync Rights - Dump All Domain Hashes")
        self.assertEqual(paths[0]["priority"], 97)

    def test_password_spray_fires_with_users_and_services(self):
        paths = self.synth.generate_attack_paths(self.findings)
        spray = [p for p in paths if "Spray" in p["name"] or "spray" in p.get("suggestion", {}).get("description", "")]
        self.assertGreaterEqual(len(spray), 1)

    def test_user_with_weak_policy_fires(self):
        paths = self.synth.generate_attack_paths(self.findings)
        weak = [p for p in paths if "Weak Password Policy" in p["name"]]
        self.assertGreaterEqual(len(weak), 1)


class TestFTPWebComboLab(unittest.TestCase):
    """Scenario: Box with FTP and HTTP on same host - classic webshell upload."""

    def setUp(self):
        self.synth = _synth()
        self.findings = [
            _f("10.10.10.30", 21, "nmap", "service", "ftp", score=10),
            _f("10.10.10.30", 80, "nmap", "service", "http", score=10),
            _f("10.10.10.30", 21, "nmap", "misconfiguration", "ftp-anon",
               script_id="ftp-anon", script_output="Anonymous FTP login allowed", score=75),
        ]

    def test_ftp_web_combo_fires(self):
        paths = self.synth.generate_attack_paths(self.findings)
        combo = [p for p in paths if "Webshell via FTP" in p["name"]]
        self.assertGreaterEqual(len(combo), 1)

    def test_anon_ftp_confirmed_fires(self):
        paths = self.synth.generate_attack_paths(self.findings)
        anon = [p for p in paths if "Anonymous FTP Misconfiguration" in p["name"]]
        self.assertGreaterEqual(len(anon), 1)

    def test_ftp_check_fires(self):
        paths = self.synth.generate_attack_paths(self.findings)
        ftp = [p for p in paths if "FTP Service" in p["name"]]
        self.assertGreaterEqual(len(ftp), 1)


class TestSQLiToShellLab(unittest.TestCase):
    """Scenario: sqlmap confirmed injectable parameter."""

    def setUp(self):
        self.synth = _synth()
        self.findings = [
            _f("10.10.10.40", 80, "nmap", "service", "http", score=10),
            _f("10.10.10.40", 80, "sqlmap", "vulnerability", "sql_injection_found",
               parameter="id", method="GET", url="http://10.10.10.40/items.php?id=1",
               dbms="MySQL", technique="boolean-based blind", score=85),
        ]

    def test_sqli_to_shell_fires(self):
        paths = self.synth.generate_attack_paths(self.findings)
        sqli = [p for p in paths if "SQL Injection" in p["name"]]
        self.assertGreaterEqual(len(sqli), 1)
        self.assertIn("os-shell", sqli[0]["suggestion"]["commands"][0])

    def test_sqli_includes_parameter_in_description(self):
        paths = self.synth.generate_attack_paths(self.findings)
        sqli = next(p for p in paths if "SQL Injection" in p["name"])
        self.assertIn("id", sqli["suggestion"]["description"])


class TestSMBShareEnumerationLab(unittest.TestCase):
    """Scenario: enum4linux found shares, users, and a credential is available."""

    def setUp(self):
        self.synth = _synth()
        self.findings = [
            _f("10.10.10.50", 445, "nmap", "service", "microsoft-ds", score=10),
            _f("10.10.10.50", 445, "enum4linux-ng", "share", "backups", comment="Backup share", score=20),
            _f("10.10.10.50", 445, "enum4linux-ng", "share", "IPC$", comment="IPC Service", score=20),
            _f("10.10.10.50", 445, "enum4linux-ng", "user", "alice", rid=1001, score=20),
            _f("10.10.10.50", 445, "enum4linux-ng", "user", "bob", rid=1002, score=20),
            _f("MANUALLY_ADDED", None, "manual_input", "credential", "alice", password="Welcome1", hash=None, score=100),
        ]

    def test_credential_access_to_share_fires(self):
        paths = self.synth.generate_attack_paths(self.findings)
        share_access = [p for p in paths if "Credential Access to SMB Share" in p["name"]]
        self.assertGreaterEqual(len(share_access), 1)

    def test_share_enumeration_fires(self):
        paths = self.synth.generate_attack_paths(self.findings)
        share_enum = [p for p in paths if "SMB Share Accessible" in p["name"]]
        self.assertGreaterEqual(len(share_enum), 1)

    def test_password_spray_fires_with_discovered_users(self):
        paths = self.synth.generate_attack_paths(self.findings)
        spray = [p for p in paths if "Password Spray" in p["name"]]
        self.assertGreaterEqual(len(spray), 1)

    def test_credential_reuse_on_smb(self):
        paths = self.synth.generate_attack_paths(self.findings)
        cred = [p for p in paths if "Credential Reuse on Login Service" in p["name"]]
        self.assertGreaterEqual(len(cred), 1)


class TestConfigFileExposureLab(unittest.TestCase):
    """Scenario: gobuster finds .git, .env, and config.php.bak on a web server."""

    def setUp(self):
        self.synth = _synth()
        self.findings = [
            _f("10.10.10.60", 80, "nmap", "service", "http", score=10),
            _f("10.10.10.60", 80, "gobuster", "web_content", "/.git", status_code=403, score=90),
            _f("10.10.10.60", 80, "gobuster", "web_content", "/.env", status_code=200, score=90),
            _f("10.10.10.60", 80, "gobuster", "web_content", "/config.php.bak", status_code=200, score=85),
            _f("10.10.10.60", 80, "gobuster", "web_content", "/robots.txt", status_code=200, score=60),
        ]

    def test_config_file_exposure_fires(self):
        paths = self.synth.generate_attack_paths(self.findings)
        config = [p for p in paths if "Configuration" in p["name"] or "Credential File" in p["name"]]
        # Should match .git, .env, and config.php
        self.assertGreaterEqual(len(config), 1)

    def test_backup_file_fires(self):
        paths = self.synth.generate_attack_paths(self.findings)
        backup = [p for p in paths if "Backup" in p["name"]]
        self.assertGreaterEqual(len(backup), 1)

    def test_robots_fires(self):
        paths = self.synth.generate_attack_paths(self.findings)
        robots = [p for p in paths if "Robots" in p["name"] or "robots" in p["name"]]
        self.assertGreaterEqual(len(robots), 1)


class TestVirtualHostDiscoveryLab(unittest.TestCase):
    """Scenario: gobuster vhost mode found a virtual host."""

    def setUp(self):
        self.synth = _synth()
        self.findings = [
            _f("10.10.10.70", 80, "nmap", "service", "http", score=10),
            _f("10.10.10.70", 80, "gobuster", "virtual_host", "dev.target.htb", status_code=200, score=50),
        ]

    def test_vhost_fires(self):
        paths = self.synth.generate_attack_paths(self.findings)
        vhost = [p for p in paths if "Virtual Host" in p["name"]]
        self.assertGreaterEqual(len(vhost), 1)
        self.assertIn("dev.target.htb", vhost[0]["suggestion"]["commands"][0])


class TestSNMPIntelligenceLab(unittest.TestCase):
    """Scenario: SNMP exposed system information and users."""

    def setUp(self):
        self.synth = _synth()
        self.findings = [
            _f("10.10.10.80", 22, "nmap", "service", "ssh", score=10),
            _f("10.10.10.80", 161, "snmp", "os_details", "snmp_system_information",
               description="Linux target 5.4.0-42-generic x86_64", score=15),
            _f("10.10.10.80", 161, "snmp", "user", "admin", source="SNMP enumeration", score=20),
            _f("10.10.10.80", 161, "snmp", "user", "svc_backup", source="SNMP enumeration", score=20),
        ]

    def test_snmp_intelligence_fires(self):
        paths = self.synth.generate_attack_paths(self.findings)
        snmp = [p for p in paths if "SNMP" in p["name"]]
        self.assertGreaterEqual(len(snmp), 1)

    def test_user_spray_fires_with_snmp_users(self):
        paths = self.synth.generate_attack_paths(self.findings)
        spray = [p for p in paths if "Spray" in p["name"]]
        self.assertGreaterEqual(len(spray), 1)


if __name__ == "__main__":
    unittest.main()
