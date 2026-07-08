import json
import tempfile
import unittest
from pathlib import Path

from main.finding_schema import validate_findings
from parsers.active_directory.kerberos_parser import parse_getnpusers_output, parse_kerbrute_output
from parsers.active_directory.ldapdomaindump_parser import parse_ldapdomaindump_dir
from parsers.active_directory.potfile_parser import parse_potfile
from parsers.active_directory.sharphound_parser import parse_sharphound_dir
from parsers.initial_foothold.enum4linux_parser import parse_enum4linux_json
from parsers.initial_foothold.nfs_parser import parse_nfs_output
from parsers.initial_foothold.nikto_parser import parse_nikto_json
from parsers.initial_foothold.snmp_parser import parse_snmp_output
from parsers.initial_foothold.sqlmap_parser import parse_sqlmap_log
from parsers.initial_foothold.whatweb_parser import parse_whatweb_json
from parsers.privilege_escalation.linpeas_parser import parse_linpeas
from parsers.privilege_escalation.winpeas_parser import parse_winpeas


class ParserCoverageTests(unittest.TestCase):
    def _write_temp(self, content, suffix=".txt"):
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False, encoding="utf-8")
        tmp.write(content)
        tmp.close()
        self.addCleanup(lambda: Path(tmp.name).unlink(missing_ok=True))
        return tmp.name

    def test_nikto_ndjson_and_malformed_line(self):
        data = (
            '{"host":"10.10.10.10","port":"80","vulnerabilities":[{"id":"001","msg":"/admin might be interesting","url":"/admin","method":"GET","references":"ref"}]}'
            '\nnot-json\n'
        )
        path = self._write_temp(data, suffix=".json")
        findings = parse_nikto_json(path)
        self.assertEqual(len(findings), 1)
        validate_findings(findings)

    def test_nikto_json_array(self):
        payload = [{
            "host": "10.10.10.11",
            "port": 8080,
            "vulnerabilities": [{"id": "002", "msg": "WordPress version 6.0", "url": "/", "method": "GET", "references": []}],
        }]
        path = self._write_temp(json.dumps(payload), suffix=".json")
        findings = parse_nikto_json(path)
        self.assertEqual(len(findings), 1)
        validate_findings(findings)

    def test_nikto_ndjson_with_bom(self):
        data = (
            '\ufeff{"host":"10.10.10.10","port":"80","vulnerabilities":[{"id":"001","msg":"/admin might be interesting","url":"/admin","method":"GET","references":"ref"}]}\n'
        )
        path = self._write_temp(data, suffix=".json")
        findings = parse_nikto_json(path)
        self.assertEqual(len(findings), 1)
        validate_findings(findings)

    def test_snmp_parser(self):
        text = (
            "System information:\nLinux target 5.4\n\n"
            "User accounts:\nadmin\nguest\n\n"
            "Running processes:\n1 root /usr/sbin/sshd\n\n"
            "Network interfaces:\neth0 10.10.10.10\n\n"
        )
        path = self._write_temp(text)
        findings = parse_snmp_output(path, "10.10.10.10")
        self.assertGreaterEqual(len(findings), 4)
        validate_findings(findings)

    def test_snmp_parser_with_ansi_headers(self):
        text = (
            "\x1b[36m[*] System information:\x1b[0m\nLinux target 5.4\n\n"
            "\x1b[33m[*] User accounts:\x1b[0m\nadmin\nguest\n\n"
            "\x1b[32m[*] Running processes:\x1b[0m\n1 root /usr/sbin/sshd\n\n"
            "\x1b[35m[*] Network interfaces:\x1b[0m\neth0 10.10.10.10\n\n"
        )
        path = self._write_temp(text)
        findings = parse_snmp_output(path, "10.10.10.10")
        self.assertGreaterEqual(len(findings), 4)
        validate_findings(findings)

    def test_snmp_extracts_credentials_from_process_args(self):
        text = (
            "Running processes:\n"
            "1 2 3 4 /usr/sbin/sshd\n"
            "5 6 7 8 mysql -uroot -pSup3rS3cret shopdb\n"
            "9 10 11 12 /usr/bin/curl --password=hunter2 http://x\n"
            "13 14 15 16 smbclient //srv/share -U admin%P@ssw0rd\n"
            "17 18 19 20 nmap -p80 scanme.local\n\n"
        )
        path = self._write_temp(text)
        findings = parse_snmp_output(path, "10.10.10.10")
        validate_findings(findings)
        creds = {(f["attributes"].get("username"), f["attributes"]["password"])
                 for f in findings if f["entity_type"] == "credential"}
        self.assertIn(("root", "Sup3rS3cret"), creds)
        self.assertIn((None, "hunter2"), creds)
        self.assertIn(("admin", "P@ssw0rd"), creds)
        # nmap -p80 must NOT be mistaken for a password (only DB clients trust -p).
        self.assertFalse(any(pw == "80" for _, pw in creds))

    def test_snmp_extracts_credentials_from_extend_output(self):
        text = (
            'NET-SNMP-EXTEND-MIB::nsExtendOutputFull."backup" = STRING: '
            'DB_PASSWORD=leaked_from_extend\n'
        )
        path = self._write_temp(text)
        findings = parse_snmp_output(path, "10.10.10.10")
        validate_findings(findings)
        self.assertTrue(any(f["name"] == "snmp_extend_output_disclosed" for f in findings))
        self.assertTrue(any(f["entity_type"] == "credential"
                            and f["attributes"]["password"] == "leaked_from_extend"
                            for f in findings))

    def test_enum4linux_parser(self):
        payload = {
            "users": [{"name": "alice", "rid": "1001"}],
            "groups": [{"name": "Domain Users", "rid": "513"}],
            "shares": [{"name": "IPC$", "comment": "IPC", "type": "DISKTREE"}],
            "passpol": {"min_length": 7},
            "osinfo": {"os_name": "Windows", "os_version": "2019"},
        }
        path = self._write_temp(json.dumps(payload), suffix=".json")
        findings = parse_enum4linux_json(path, "10.10.10.20")
        self.assertGreaterEqual(len(findings), 5)
        validate_findings(findings)

    def test_enum4linux_parser_with_bom(self):
        payload = {
            "users": [{"username": "alice", "rid": "1001"}],
            "groups": [{"groupname": "Domain Users", "rid": "513"}],
            "shares": [{"name": "IPC$", "comment": "IPC", "type": "DISKTREE"}],
            "policy": {"domain_password_information": {"min_length": 7}},
            "os_info": {"OS": "Windows", "OS version": "2019"},
        }
        path = self._write_temp("\ufeff" + json.dumps(payload), suffix=".json")
        findings = parse_enum4linux_json(path, "10.10.10.20")
        self.assertGreaterEqual(len(findings), 5)
        validate_findings(findings)

    def test_kerberos_parsers(self):
        kerbrute_file = self._write_temp("[+] VALID USERNAME: alice@LAB.LOCAL\n[+] VALID USERNAME: bob@LAB.LOCAL\n")
        getnpusers_file = self._write_temp("$krb5asrep$23$svc@LAB.LOCAL:abcdef\n")

        user_findings = parse_kerbrute_output(kerbrute_file, "LAB.LOCAL")
        hash_findings = parse_getnpusers_output(getnpusers_file, "LAB.LOCAL")

        self.assertEqual(len(user_findings), 2)
        self.assertEqual(len(hash_findings), 1)
        validate_findings(user_findings)
        validate_findings(hash_findings)

    def test_kerberos_parsers_with_ansi(self):
        kerbrute_file = self._write_temp(
            "\x1b[32m[+]\x1b[0m \x1b[1mVALID USERNAME:\x1b[0m alice@LAB.LOCAL\n"
            "\x1b[32m[+]\x1b[0m \x1b[1mVALID USERNAME:\x1b[0m bob@LAB.LOCAL\n"
        )
        getnpusers_file = self._write_temp(
            "\x1b[31m$krb5asrep$23$svc_sql@LAB.LOCAL:abcdef0123456789\x1b[0m\n"
        )

        user_findings = parse_kerbrute_output(kerbrute_file, "LAB.LOCAL")
        hash_findings = parse_getnpusers_output(getnpusers_file, "LAB.LOCAL")

        self.assertEqual(len(user_findings), 2)
        self.assertEqual(len(hash_findings), 1)
        self.assertEqual(hash_findings[0]["attributes"]["user"], "svc_sql")
        validate_findings(user_findings)
        validate_findings(hash_findings)

    def test_potfile_parser_extracts_cracked_kerberos_password(self):
        content = "$krb5asrep$23$svc_sql@LAB.LOCAL:abcdef0123456789:Summer2026!\n"
        path = self._write_temp(content, suffix=".pot")
        findings = parse_potfile(path, "LAB.LOCAL")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["entity_type"], "credential")
        self.assertEqual(findings[0]["name"], "svc_sql")
        self.assertEqual(findings[0]["attributes"]["domain"], "LAB.LOCAL")
        self.assertEqual(findings[0]["attributes"]["password"], "Summer2026!")
        validate_findings(findings)

    def test_potfile_parser_keeps_identity_less_ntlm_secret(self):
        content = "8846f7eaee8fb117ad06bdd830b7586c:password\n"
        path = self._write_temp(content, suffix=".pot")
        findings = parse_potfile(path)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["name"], "cracked_disclosed_credential")
        self.assertEqual(findings[0]["attributes"]["hash_type"], "NTLM")
        self.assertEqual(findings[0]["attributes"]["password"], "password")
        validate_findings(findings)

    def test_nfs_parser_emits_export_and_no_root_squash_finding(self):
        content = (
            "Export list for 10.10.10.10:\n"
            "/srv/share *(rw,sync,no_root_squash)\n"
            "/backups 10.10.10.0/24(ro,sync)\n"
        )
        path = self._write_temp(content)
        findings = parse_nfs_output(path, "10.10.10.10")

        shares = [f for f in findings if f["entity_type"] == "share"]
        privesc = [f for f in findings if f["name"] == "nfs_no_root_squash"]
        self.assertEqual({f["name"] for f in shares}, {"/srv/share", "/backups"})
        self.assertEqual(len(privesc), 1)
        self.assertEqual(privesc[0]["attributes"]["export"], "/srv/share")
        validate_findings(findings)

    def test_ldapdomaindump_parser(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            (tmp / "domain_users.tsv").write_text(
                "samaccountname\tuserprincipalname\tuseraccountcontrol\n"
                "alice\talice@lab.local\t66048\n"
                "svc_roast\tsvc_roast@lab.local\t4194304\n",
                encoding="utf-8",
            )
            (tmp / "domain_groups.tsv").write_text(
                "samaccountname\nDomain Admins\n",
                encoding="utf-8",
            )
            (tmp / "domain_computers.tsv").write_text(
                "samaccountname\tdnshostname\nDC01$\tdc01.lab.local\n",
                encoding="utf-8",
            )

            findings = parse_ldapdomaindump_dir(str(tmp))
            self.assertGreaterEqual(len(findings), 4)
            validate_findings(findings)

    def test_sharphound_parser(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            (tmp / "users.json").write_text(
                json.dumps({"data": [{"ObjectIdentifier": "S-1-5-21-1-2-3-1100", "Name": "ALICE@LAB.LOCAL", "DontReqPreAuth": True, "HasSPN": False, "IsAdmin": False, "Aces": []}]}),
                encoding="utf-8",
            )
            (tmp / "groups.json").write_text(
                json.dumps({"data": [{"ObjectIdentifier": "S-1-5-21-1-2-3-512", "Name": "DOMAIN ADMINS@LAB.LOCAL", "Aces": []}]}),
                encoding="utf-8",
            )
            (tmp / "computers.json").write_text(
                json.dumps({"data": [{"ObjectIdentifier": "S-1-5-21-1-2-3-2000", "Name": "DC01.LAB.LOCAL", "UnconstrainedDelegation": True, "Aces": []}]}),
                encoding="utf-8",
            )
            (tmp / "domains.json").write_text(
                json.dumps({"data": [{"ObjectIdentifier": "S-1-5-21-1-2-3", "Name": "LAB.LOCAL", "ObjectType": "Domain", "Aces": []}]}),
                encoding="utf-8",
            )
            (tmp / "sessions.json").write_text(json.dumps({"data": []}), encoding="utf-8")

            findings = parse_sharphound_dir(str(tmp))
            self.assertGreaterEqual(len(findings), 2)
            validate_findings(findings)

    def test_sharphound_parser_with_bom_json(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            (tmp / "users.json").write_text(
                "\ufeff" + json.dumps({"data": [{"ObjectIdentifier": "S-1-5-21-1-2-3-1100", "Name": "ALICE@LAB.LOCAL", "DontReqPreAuth": True, "HasSPN": False, "IsAdmin": False, "Aces": []}]}),
                encoding="utf-8",
            )
            (tmp / "groups.json").write_text("\ufeff" + json.dumps({"data": []}), encoding="utf-8")
            (tmp / "computers.json").write_text("\ufeff" + json.dumps({"data": []}), encoding="utf-8")
            (tmp / "domains.json").write_text(
                "\ufeff" + json.dumps({"data": [{"ObjectIdentifier": "S-1-5-21-1-2-3", "Name": "LAB.LOCAL", "ObjectType": "Domain", "Aces": []}]}),
                encoding="utf-8",
            )
            (tmp / "sessions.json").write_text("\ufeff" + json.dumps({"data": []}), encoding="utf-8")

            findings = parse_sharphound_dir(str(tmp))
            self.assertGreaterEqual(len(findings), 1)
            validate_findings(findings)

    def test_linpeas_winpeas_parsers(self):
        lin = self._write_temp("sudo -l may be allowed\n")
        win = self._write_temp("Unquoted service path found\n")

        lin_findings = parse_linpeas(lin, "10.10.10.30")
        win_findings = parse_winpeas(win, "10.10.10.40")

        self.assertGreaterEqual(len(lin_findings), 1)
        self.assertGreaterEqual(len(win_findings), 1)
        validate_findings(lin_findings)
        validate_findings(win_findings)

    def test_enum4linux_backwards_compat_list_format(self):
        """Old-style list-of-dicts format should still work."""
        payload = {
            "users": [{"name": "legacy_user", "rid": "999"}],
            "groups": [{"name": "Legacy Group", "rid": "600"}],
            "shares": [{"name": "share1", "comment": "test", "type": "DISKTREE"}],
            "passpol": {"min_length": 7},
            "osinfo": {"os_name": "Linux", "os_version": "5.4"},
        }
        path = self._write_temp(json.dumps(payload), suffix=".json")
        findings = parse_enum4linux_json(path, "10.10.10.50")
        validate_findings(findings)

        users = [f for f in findings if f["entity_type"] == "user"]
        self.assertEqual(len(users), 1)
        self.assertEqual(users[0]["name"], "legacy_user")

        os_findings = [f for f in findings if f["entity_type"] == "os_details"]
        self.assertEqual(len(os_findings), 1)
        self.assertIn("Linux", os_findings[0]["name"])

    def test_ldapdomaindump_case_insensitive_columns(self):
        """Column headers with different casing should still be parsed correctly."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            # Use PascalCase column names (some ldapdomaindump versions output this)
            (tmp / "domain_users.tsv").write_text(
                "SamAccountName\tUserPrincipalName\tUserAccountControl\n"
                "admin\tadmin@corp.local\t512\n",
                encoding="utf-8",
            )
            (tmp / "domain_groups.tsv").write_text(
                "SamAccountName\tDistinguishedName\tDescription\n"
                "Domain Admins\tCN=Domain Admins,DC=corp,DC=local\tBuilt-in admin group\n",
                encoding="utf-8",
            )
            (tmp / "domain_computers.tsv").write_text(
                "SamAccountName\tDNSHostName\tOperatingSystem\n"
                "DC01$\tdc01.corp.local\tWindows Server 2019\n",
                encoding="utf-8",
            )

            findings = parse_ldapdomaindump_dir(str(tmp))
            validate_findings(findings)

            users = [f for f in findings if f["entity_type"] == "user"]
            self.assertEqual(len(users), 1)
            self.assertEqual(users[0]["name"], "admin")

            groups = [f for f in findings if f["entity_type"] == "group"]
            self.assertEqual(len(groups), 1)
            self.assertEqual(groups[0]["name"], "Domain Admins")

            computers = [f for f in findings if f["entity_type"] == "computer"]
            self.assertEqual(len(computers), 1)
            self.assertEqual(computers[0]["host"], "dc01.corp.local")

    def test_ldapdomaindump_bom_headers(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            (tmp / "domain_users.tsv").write_text(
                "\ufeffSamAccountName\tUserPrincipalName\tUserAccountControl\n"
                "admin\tadmin@corp.local\t512\n",
                encoding="utf-8",
            )
            (tmp / "domain_groups.tsv").write_text(
                "\ufeffSamAccountName\tDescription\n"
                "Domain Admins\tBuilt-in admin group\n",
                encoding="utf-8",
            )
            (tmp / "domain_computers.tsv").write_text(
                "\ufeffSamAccountName\tDNSHostName\tOperatingSystem\n"
                "DC01$\tdc01.corp.local\tWindows Server 2019\n",
                encoding="utf-8",
            )

            findings = parse_ldapdomaindump_dir(str(tmp))
            validate_findings(findings)
            self.assertIn("admin", {f["name"] for f in findings if f["entity_type"] == "user"})

    def test_getnpusers_hash_without_domain(self):
        """GetNPUsers hashes without @domain should still be parsed."""
        content = "$krb5asrep$23$svc_sql:abcdef0123456789\n"
        path = self._write_temp(content)
        findings = parse_getnpusers_output(path, "CORP.LOCAL")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["attributes"]["user"], "svc_sql")
        self.assertEqual(findings[0]["host"], "CORP.LOCAL")
        validate_findings(findings)

    def test_kerbrute_timestamped_format(self):
        """Kerbrute output with timestamps should still be parsed."""
        content = (
            "2023/10/15 14:30:01 >  [+] VALID USERNAME:       admin@CORP.LOCAL\n"
            "2023/10/15 14:30:02 >  [+] VALID USERNAME:       svc_sql@CORP.LOCAL\n"
            "2023/10/15 14:30:03 >  Done! 2 valid usernames found\n"
        )
        path = self._write_temp(content)
        findings = parse_kerbrute_output(path, "CORP.LOCAL")
        self.assertEqual(len(findings), 2)
        usernames = {f["name"] for f in findings}
        self.assertEqual(usernames, {"admin", "svc_sql"})
        validate_findings(findings)

    def test_sqlmap_parser_with_ansi(self):
        content = (
            "\x1b[36m[INFO]\x1b[0m testing 'http://10.10.10.10/item.php?id=1'\n"
            "\x1b[36m[INFO]\x1b[0m GET parameter 'id' is vulnerable\n"
            "\x1b[36m[INFO]\x1b[0m back-end DBMS is 'MySQL'\n"
            "\x1b[36m[INFO]\x1b[0m following injection techniques are supported: boolean-based blind\n"
        )
        path = self._write_temp(content)
        findings = parse_sqlmap_log(path)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["attributes"]["parameter"], "id")
        self.assertEqual(findings[0]["host"], "10.10.10.10")
        validate_findings(findings)

    def test_whatweb_single_object_with_bom(self):
        payload = {
            "target": "https://example.com",
            "plugins": {
                "WordPress": {"version": ["6.5.2"]},
                "HTTPServer": {"string": ["Apache"]},
            },
        }
        path = self._write_temp("\ufeff" + json.dumps(payload), suffix=".json")
        findings = parse_whatweb_json(path)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["name"], "WordPress")
        self.assertEqual(findings[0]["port"], 443)
        validate_findings(findings)

    def test_linpeas_bright_color_signature(self):
        """LinPEAS output with bright ANSI codes (91/103) should be detected."""
        # Bright red foreground (91) + bright yellow background (103)
        colored_line = "\x1b[91mCritical finding\x1b[103m SUID binary\x1b[0m\n"
        path = self._write_temp(colored_line)
        findings = parse_linpeas(path, "10.10.10.30")
        pe_findings = [f for f in findings if f["attributes"].get("signal_source") == "color_signature"]
        self.assertGreaterEqual(len(pe_findings), 1)
        validate_findings(findings)

    def test_sharphound_v5_properties_format(self):
        """SharpHound v5/CE format with Properties sub-object should work."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            (tmp / "users.json").write_text(
                json.dumps({"data": [{
                    "ObjectIdentifier": "S-1-5-21-1-2-3-1100",
                    "Name": "SVC_SQL@LAB.LOCAL",
                    "Properties": {"HasSPN": True, "DontReqPreAuth": False, "IsAdmin": False},
                    "Aces": []
                }]}),
                encoding="utf-8",
            )
            (tmp / "groups.json").write_text(json.dumps({"data": []}), encoding="utf-8")
            (tmp / "computers.json").write_text(json.dumps({"data": []}), encoding="utf-8")
            (tmp / "domains.json").write_text(
                json.dumps({"data": [{"ObjectIdentifier": "S-1-5-21-1-2-3", "Name": "LAB.LOCAL", "ObjectType": "Domain", "Aces": []}]}),
                encoding="utf-8",
            )
            (tmp / "sessions.json").write_text(json.dumps({"data": []}), encoding="utf-8")

            findings = parse_sharphound_dir(str(tmp))
            validate_findings(findings)

            kerb_findings = [f for f in findings if f["name"] == "kerberoastable_user"]
            self.assertEqual(len(kerb_findings), 1)
            self.assertIn("SVC_SQL", kerb_findings[0]["attributes"]["user"])


if __name__ == "__main__":
    unittest.main()
