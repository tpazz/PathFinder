import json
import tempfile
import unittest
from pathlib import Path

from main.finding_schema import validate_findings
from parsers.active_directory.kerberos_parser import parse_getnpusers_output, parse_kerbrute_output
from parsers.active_directory.ldapdomaindump_parser import parse_ldapdomaindump_dir
from parsers.active_directory.sharphound_parser import parse_sharphound_dir
from parsers.initial_foothold.enum4linux_parser import parse_enum4linux_json
from parsers.initial_foothold.nikto_parser import parse_nikto_json
from parsers.initial_foothold.snmp_parser import parse_snmp_output
from parsers.privilege_escalation.linpeas_parser import parse_linpeas
from parsers.privilege_escalation.winpeas_parser import parse_winpeas


class ParserCoverageTests(unittest.TestCase):
    def _write_temp(self, content, suffix=".txt"):
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False)
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

    def test_kerberos_parsers(self):
        kerbrute_file = self._write_temp("[+] VALID USERNAME: alice@LAB.LOCAL\n[+] VALID USERNAME: bob@LAB.LOCAL\n")
        getnpusers_file = self._write_temp("$krb5asrep$23$svc@LAB.LOCAL:abcdef\n")

        user_findings = parse_kerbrute_output(kerbrute_file, "LAB.LOCAL")
        hash_findings = parse_getnpusers_output(getnpusers_file, "LAB.LOCAL")

        self.assertEqual(len(user_findings), 2)
        self.assertEqual(len(hash_findings), 1)
        validate_findings(user_findings)
        validate_findings(hash_findings)

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

    def test_linpeas_winpeas_parsers(self):
        lin = self._write_temp("sudo -l may be allowed\n")
        win = self._write_temp("Unquoted service path found\n")

        lin_findings = parse_linpeas(lin, "10.10.10.30")
        win_findings = parse_winpeas(win, "10.10.10.40")

        self.assertGreaterEqual(len(lin_findings), 1)
        self.assertGreaterEqual(len(win_findings), 1)
        validate_findings(lin_findings)
        validate_findings(win_findings)


if __name__ == "__main__":
    unittest.main()
