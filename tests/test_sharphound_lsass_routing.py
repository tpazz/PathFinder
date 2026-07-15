import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path

from main.attack_path_synthesizer import AttackPathSynthesizer, DEFAULT_RULES_FILE
from main.finding_schema import validate_findings
from main.pathfinder import _sniff_file_type, auto_detect_loot
from parsers.active_directory.lsass_parser import parse_lsass_json
from parsers.active_directory.sharphound_parser import parse_sharphound_dir
from parsers.credential_routing import credential_usage, credential_usages, usable_ntlm_hash


def _collection(data):
    return json.dumps({"data": data})


def _domain_with_dcsync():
    return {
        "ObjectIdentifier": "S-1-5-21-1-2-3",
        "Name": "LAB.LOCAL",
        # Intentionally no ObjectType: current SharpHound domain exports may omit it.
        "Aces": [
            {"PrincipalSID": "S-1-5-21-1-2-3-1100", "RightName": "DS-Replication-Get-Changes"},
            {"PrincipalSID": "S-1-5-21-1-2-3-1100", "RightName": "DS-Replication-Get-Changes-All"},
        ],
    }


class SharpHoundLoaderTests(unittest.TestCase):
    def test_newest_timestamped_files_and_domain_collection_dcsync(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            old = root / "users.json"
            new = root / "20260715120000_users.json"
            old.write_text(_collection([{
                "ObjectIdentifier": "S-1-5-21-1-2-3-1200", "Name": "OLD@LAB.LOCAL",
                "DontReqPreAuth": True, "Aces": [],
            }]), encoding="utf-8")
            new.write_text(_collection([{
                "ObjectIdentifier": "S-1-5-21-1-2-3-1100", "Name": "SVC_WEB@LAB.LOCAL",
                "HasSPN": True, "Aces": [],
            }]), encoding="utf-8")
            (root / "20260715120000_domains.json").write_text(
                _collection([_domain_with_dcsync()]), encoding="utf-8")
            os.utime(old, (1, 1))

            findings = parse_sharphound_dir(str(root))
            validate_findings(findings)
            names = {finding["name"] for finding in findings}
            self.assertIn("kerberoastable_user", names)
            self.assertIn("dcsync_rights_found", names)
            self.assertNotIn("asreproastable_user", names)
            self.assertEqual(_sniff_file_type(str(new)), None)

            detections = auto_detect_loot(str(root))
            self.assertTrue(any(item["key"] == "sharphound_dir" for item in detections))

    def test_zip_archive_is_detected_and_parsed_without_extraction(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            archive_path = Path(tmp_dir) / "bloodhound.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("nested/20260715120000_users.json", _collection([{
                    "ObjectIdentifier": "S-1-5-21-1-2-3-1100", "Name": "SVC_WEB@LAB.LOCAL",
                    "HasSPN": True, "Aces": [],
                }]))
                archive.writestr("nested/20260715120000_domains.json", _collection([_domain_with_dcsync()]))
                archive.writestr("nested/20260715120000_groups.json", _collection([]))

            self.assertEqual(_sniff_file_type(str(archive_path)), "sharphound_dir")
            findings = parse_sharphound_dir(str(archive_path))
            validate_findings(findings)
            self.assertIn("dcsync_rights_found", {finding["name"] for finding in findings})


class LsassParserTests(unittest.TestCase):
    def _write(self, payload, name):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / name
        path.write_text(json.dumps(payload), encoding="utf-8")
        return str(path)

    def test_pypykatz_nested_sessions_emit_typed_material(self):
        nt_hash = "31d6cfe0d16ae931b73c59d7e0c089c0"
        payload = {
            "memory.dmp": {
                "logon_sessions": {
                    "0x123": {
                        "username": "svc_web", "domainname": "CORP", "luid": "0x123",
                        "msv_creds": [{"NThash": nt_hash}],
                        "wdigest_creds": [{"password": "Summer2026!"}],
                        "kerberos_creds": [{"aes256": "ab" * 32}],
                        "dpapi_creds": [{"masterkey": "cd" * 32}],
                    }
                }
            }
        }
        path = self._write(payload, "pypykatz.json")
        self.assertEqual(_sniff_file_type(path), "lsass_json")
        findings = parse_lsass_json(path, "WS01.CORP.LOCAL")
        validate_findings(findings)

        usages = {finding["attributes"]["credential_usage"] for finding in findings}
        self.assertEqual(usages, {"password_reuse", "pass_the_hash", "ticket_key", "crack_first"})
        nt = next(finding for finding in findings if finding["attributes"].get("nt_hash"))
        self.assertEqual(nt["attributes"]["hash_type"], "NTLM")
        self.assertEqual(nt["attributes"]["domain"], "CORP")
        self.assertEqual(nt["attributes"]["logon_session"], "0x123")

    def test_lsassy_flat_export_is_supported(self):
        payload = {"credentials": [{
            "domain": "CORP", "username": "alice",
            "password": "Secret!", "nt_hash": "8846f7eaee8fb117ad06bdd830b7586c",
        }]}
        path = self._write(payload, "lsassy-output.json")
        self.assertEqual(_sniff_file_type(path), "lsass_json")
        findings = parse_lsass_json(path)
        self.assertEqual({item["source_tool"] for item in findings}, {"lsassy"})
        self.assertEqual(len(findings), 2)


class CredentialRoutingTests(unittest.TestCase):
    @staticmethod
    def _credential(name, hash_value=None, hash_type=None, password=None, **extra):
        attrs = {"username": name, "hash": hash_value, "hash_type": hash_type, "password": password}
        attrs.update(extra)
        return {
            "host": "CAPTURE", "port": None, "source_tool": "test",
            "entity_type": "credential", "name": name, "version": None,
            "attributes": attrs,
        }

    @staticmethod
    def _service():
        return {
            "host": "10.0.0.5", "port": 445, "source_tool": "nmap",
            "entity_type": "service", "name": "microsoft-ds", "version": None,
            "attributes": {},
        }

    def test_classifier_never_routes_crack_formats_to_pth(self):
        samples = [
            ("NetNTLMv2", "ALICE::CORP:challenge:response"),
            ("Kerberos AS-REP (18200)", "$krb5asrep$23$alice:deadbeef"),
            ("Kerberos TGS-REP (13100)", "$krb5tgs$23$*alice$CORP$svc$deadbeef"),
            ("DCC2", "$DCC2$10240#alice#deadbeef"),
            ("DPAPI", "$DPAPImk$*1*deadbeef"),
        ]
        for hash_type, value in samples:
            attrs = {"hash": value, "hash_type": hash_type, "credential_usage": "pass_the_hash"}
            with self.subTest(hash_type=hash_type):
                self.assertEqual(credential_usage(attrs), "crack_first")
                self.assertIsNone(usable_ntlm_hash(attrs))

    def test_rules_split_password_pth_and_crack_first(self):
        synth = AttackPathSynthesizer(DEFAULT_RULES_FILE)
        nt = self._credential(
            "administrator", "31d6cfe0d16ae931b73c59d7e0c089c0", "NTLM")
        netntlm = self._credential(
            "alice", "ALICE::CORP:challenge:response", "NetNTLMv2")
        password = self._credential("bob", password="Secret!")
        paths = synth.generate_attack_paths([nt, netntlm, password, self._service()])
        names = [path["name"] for path in paths]

        self.assertIn("Pass-the-Hash on Windows Login Service", names)
        self.assertIn("Credential Hash Requires Cracking", names)
        self.assertIn("Credential Reuse on Login Service", names)
        pth = [path for path in paths if path["name"] == "Pass-the-Hash on Windows Login Service"]
        self.assertTrue(all(path["matched_findings"][0]["finding"]["name"] == "administrator" for path in pth))

    def test_correlated_password_and_nt_hash_retain_both_routes(self):
        credential = self._credential(
            "svc_web", "31d6cfe0d16ae931b73c59d7e0c089c0", "NTLM",
            password="Secret!", nt_hash="31d6cfe0d16ae931b73c59d7e0c089c0",
        )
        self.assertEqual(
            credential_usages(credential["attributes"]),
            {"password_reuse", "pass_the_hash"},
        )
        synth = AttackPathSynthesizer(DEFAULT_RULES_FILE)
        names = {
            path["name"]
            for path in synth.generate_attack_paths([credential, self._service()])
        }
        self.assertIn("Credential Reuse on Login Service", names)
        self.assertIn("Pass-the-Hash on Windows Login Service", names)


if __name__ == "__main__":
    unittest.main()
