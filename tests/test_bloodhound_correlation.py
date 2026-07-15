import json
import tempfile
import unittest
from pathlib import Path

from main.attack_path_synthesizer import AttackPathSynthesizer, DEFAULT_RULES_FILE
from main.bloodhound_correlator import (
    MAX_CORRELATED_FINDINGS,
    correlate_bloodhound_ownership,
)
from main.finding_schema import validate_findings
from parsers.active_directory.certipy_parser import parse_certipy_json
from parsers.active_directory.sharphound_parser import parse_sharphound_dir


def _finding(source, entity_type, name, host="CORP.LOCAL", **attrs):
    return {
        "host": host,
        "port": None,
        "source_tool": source,
        "entity_type": entity_type,
        "name": name,
        "version": None,
        "attributes": attrs,
    }


def _credential(name, domain="CORP.LOCAL", source="secretsdump"):
    return _finding(
        source, "credential", name, host="WS01.CORP.LOCAL",
        username=name, domain=domain,
        hash="31d6cfe0d16ae931b73c59d7e0c089c0",
        nt_hash="31d6cfe0d16ae931b73c59d7e0c089c0",
        hash_type="NTLM",
    )


def _acl(attacker, target, right="ForceChangePassword", contexts=None):
    return _finding(
        "sharphound", "privilege_escalation", "acl_abuse_right_on_object",
        attacker=attacker, target=target, right=right,
        target_high_value=bool(contexts),
        target_high_value_contexts=list(contexts or []),
    )


class BoundedCorrelationTests(unittest.TestCase):
    def test_owned_acl_is_actionable_and_gets_one_high_value_hint(self):
        findings = [
            _credential("svc_web"),
            _acl(
                "SVC_WEB@CORP.LOCAL", "HELPDESK_ADMIN@CORP.LOCAL",
                contexts=["direct member of DOMAIN ADMINS@CORP.LOCAL"],
            ),
        ]
        correlated = correlate_bloodhound_ownership(findings)
        derived = [item for item in correlated if item["source_tool"] == "bloodhound-correlation"]
        self.assertEqual(
            {item["name"] for item in derived},
            {"bloodhound_owned_acl_edge", "bloodhound_owned_one_hop_high_value"},
        )
        self.assertTrue(all(item["attributes"]["owned_principal"] == "SVC_WEB@CORP.LOCAL" for item in derived))

    def test_target_never_becomes_owned_and_no_transitive_search_occurs(self):
        findings = [
            _credential("svc_web"),
            _acl("SVC_WEB@CORP.LOCAL", "helpdesk_admin@CORP.LOCAL"),
            _acl("helpdesk_admin@CORP.LOCAL", "DOMAIN ADMINS@CORP.LOCAL", "AddMember"),
        ]
        correlated = correlate_bloodhound_ownership(findings)
        derived_targets = {
            item["attributes"]["target"]
            for item in correlated
            if item["source_tool"] == "bloodhound-correlation"
        }
        self.assertEqual(derived_targets, {"helpdesk_admin@CORP.LOCAL"})

    def test_unowned_and_ambiguous_short_principals_do_not_match(self):
        findings = [
            _credential("administrator", "ALPHA.LOCAL"),
            _credential("administrator", "BETA.LOCAL", source="pypykatz"),
            _acl("administrator", "target@ALPHA.LOCAL"),
            _acl("nobody@ALPHA.LOCAL", "other@ALPHA.LOCAL"),
        ]
        correlated = correlate_bloodhound_ownership(findings)
        self.assertFalse(any(item["source_tool"] == "bloodhound-correlation" for item in correlated))

    def test_zero_hop_dcsync_and_gmsa_are_loud(self):
        dcsync = _finding(
            "sharphound", "privilege_escalation", "dcsync_rights_found",
            user="svc_web@CORP.LOCAL", target="CORP.LOCAL", right="DCSync",
        )
        gmsa = _finding(
            "sharphound", "privilege_escalation", "gmsa_password_read_right_found",
            attacker="svc_web@CORP.LOCAL", target="sql_gmsa$@CORP.LOCAL",
            right="ReadGMSAPassword", target_high_value_contexts=[],
        )
        correlated = correlate_bloodhound_ownership([_credential("svc_web"), dcsync, gmsa])
        names = {item["name"] for item in correlated}
        self.assertIn("bloodhound_owned_zero_hop_dcsync", names)
        self.assertIn("bloodhound_owned_zero_hop_gmsa_read", names)

    def test_potfile_and_pypykatz_material_build_the_owned_set_but_uncracked_capture_does_not(self):
        cracked = _finding(
            "john/hashcat-pot", "credential", "svc_cracked", host="CRACKED",
            username="svc_cracked", domain="CORP.LOCAL", password="Recovered!",
            hash="$krb5tgs$23$*svc_cracked$CORP.LOCAL$svc$deadbeef",
            hash_type="Kerberos TGS-REP (13100)",
        )
        pypykatz = _credential("svc_memory", source="pypykatz")
        capture = _finding(
            "responder", "credential", "svc_capture", host="CAPTURE",
            username="svc_capture", domain="CORP.LOCAL",
            hash="SVC_CAPTURE::CORP:challenge:response", hash_type="NetNTLMv2",
        )
        findings = [
            cracked, pypykatz, capture,
            _acl("svc_cracked@CORP.LOCAL", "target1@CORP.LOCAL"),
            _acl("svc_memory@CORP.LOCAL", "target2@CORP.LOCAL"),
            _acl("svc_capture@CORP.LOCAL", "target3@CORP.LOCAL"),
        ]
        correlated = correlate_bloodhound_ownership(findings)
        targets = {
            item["attributes"]["target"]
            for item in correlated
            if item["name"] == "bloodhound_owned_acl_edge"
        }
        self.assertEqual(targets, {"target1@CORP.LOCAL", "target2@CORP.LOCAL"})

    def test_adcs_requires_vulnerability_and_enrollment_correlation(self):
        safe_edge = _finding(
            "sharphound", "privilege_escalation", "adcs_enrollment_right_found",
            attacker="svc_web@CORP.LOCAL", target="SafeTemplate", right="Enroll",
            template_vulnerable=False, target_high_value_contexts=[],
        )
        vulnerable = _finding(
            "certipy", "privilege_escalation", "adcs_esc1",
            template="ESC1-Template", esc="ESC1",
            enrollment_principals=["CORP.LOCAL\\svc_web"],
        )
        correlated = correlate_bloodhound_ownership([
            _credential("svc_web"), safe_edge, vulnerable,
        ])
        adcs = [item for item in correlated if item["name"] == "bloodhound_owned_zero_hop_adcs"]
        self.assertEqual(len(adcs), 1)
        self.assertEqual(adcs[0]["attributes"]["target"], "ESC1-Template")
        self.assertTrue(any(
            item["name"] == "bloodhound_owned_acl_edge"
            and item["attributes"]["target"] == "SafeTemplate"
            for item in correlated
        ))

    def test_broad_domain_users_enrollment_matches_owned_user(self):
        vulnerable = _finding(
            "certipy", "privilege_escalation", "adcs_esc1",
            template="ESC1-Template", esc="ESC1",
            enrollment_principals=["CORP.LOCAL\\Domain Users"],
        )
        correlated = correlate_bloodhound_ownership([_credential("alice"), vulnerable])
        self.assertTrue(any(item["name"] == "bloodhound_owned_zero_hop_adcs" for item in correlated))

    def test_direct_results_are_hard_capped(self):
        edges = [
            _acl("svc_web@CORP.LOCAL", f"user{index}@CORP.LOCAL")
            for index in range(MAX_CORRELATED_FINDINGS + 50)
        ]
        correlated = correlate_bloodhound_ownership([_credential("svc_web"), *edges])
        derived = [item for item in correlated if item["source_tool"] == "bloodhound-correlation"]
        self.assertEqual(len(derived), MAX_CORRELATED_FINDINGS)


class CorrelationRuleTests(unittest.TestCase):
    def test_owned_paths_replace_generic_noise_on_same_domain(self):
        synth = AttackPathSynthesizer(DEFAULT_RULES_FILE)
        findings = [
            _credential("svc_web"),
            _acl(
                "svc_web@CORP.LOCAL", "helpdesk_admin@CORP.LOCAL",
                contexts=["local administrator on FILE01.CORP.LOCAL"],
            ),
        ]
        names = {path["name"] for path in synth.generate_attack_paths(findings)}
        self.assertIn("OWNED DIRECT EDGE - ACL Abuse Now", names)
        self.assertIn("OWNED ONE-HOP - Take Over High-Value Principal", names)
        self.assertNotIn("ACL Abuse Right - ForceChangePassword / WriteDacl / WriteOwner", names)

    def test_owned_dcsync_is_priority_100_and_suppresses_generic_path(self):
        synth = AttackPathSynthesizer(DEFAULT_RULES_FILE)
        finding = _finding(
            "sharphound", "privilege_escalation", "dcsync_rights_found",
            user="svc_sync@CORP.LOCAL", target="CORP.LOCAL", right="DCSync",
        )
        paths = synth.generate_attack_paths([_credential("svc_sync"), finding])
        self.assertEqual(paths[0]["name"], "OWNED ZERO-HOP - DCSync Now")
        self.assertEqual(paths[0]["priority"], 100)
        self.assertNotIn("DCSync Rights - Dump All Domain Hashes", {path["name"] for path in paths})


class SharpHoundGraphMetadataTests(unittest.TestCase):
    def test_parser_attaches_direct_high_value_and_delegation_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            domain_sid = "S-1-5-21-1-2-3"
            svc_sid = f"{domain_sid}-1100"
            helpdesk_sid = f"{domain_sid}-1101"
            gmsa_sid = f"{domain_sid}-1200"
            computer_sid = f"{domain_sid}-2000"
            template_sid = "11111111-2222-3333-4444-555555555555"

            users = [
                {"ObjectIdentifier": svc_sid, "Name": "SVC_WEB@CORP.LOCAL", "Aces": []},
                {
                    "ObjectIdentifier": helpdesk_sid, "Name": "HELPDESK_ADMIN@CORP.LOCAL",
                    "IsAdmin": True,
                    "Aces": [{"PrincipalSID": svc_sid, "RightName": "ForceChangePassword"}],
                },
                {
                    "ObjectIdentifier": gmsa_sid, "Name": "SQL_GMSA$@CORP.LOCAL",
                    "Aces": [{"PrincipalSID": svc_sid, "RightName": "ReadGMSAPassword"}],
                },
            ]
            groups = [{
                "ObjectIdentifier": f"{domain_sid}-512", "Name": "DOMAIN ADMINS@CORP.LOCAL",
                "Members": [{"ObjectIdentifier": helpdesk_sid, "ObjectType": "User"}], "Aces": [],
            }]
            computers = [{
                "ObjectIdentifier": computer_sid, "Name": "FILE01.CORP.LOCAL", "Aces": [],
                "LocalAdmins": {"Results": [{"ObjectIdentifier": helpdesk_sid, "ObjectType": "User"}]},
                "AllowedToAct": {"Results": [{"ObjectIdentifier": svc_sid, "ObjectType": "User"}]},
            }]
            domains = [{"ObjectIdentifier": domain_sid, "Name": "CORP.LOCAL", "Aces": []}]
            templates = [{
                "ObjectIdentifier": template_sid, "Name": "ESC1-Template",
                "Properties": {"Vulnerabilities": {"ESC1": True}},
                "Aces": [{"PrincipalSID": svc_sid, "RightName": "Enroll"}],
            }]
            for name, data in (
                ("users", users), ("groups", groups), ("computers", computers),
                ("domains", domains), ("certtemplates", templates),
            ):
                (root / f"20260715_{name}.json").write_text(
                    json.dumps({"data": data}), encoding="utf-8",
                )

            findings = parse_sharphound_dir(str(root))
            validate_findings(findings)
            acl = next(
                item for item in findings
                if item["name"] == "acl_abuse_right_on_object"
                and item["attributes"]["target"] == "HELPDESK_ADMIN@CORP.LOCAL"
            )
            contexts = acl["attributes"]["target_high_value_contexts"]
            self.assertTrue(any("DOMAIN ADMINS" in value for value in contexts))
            self.assertTrue(any("local administrator" in value for value in contexts))
            self.assertIn("gmsa_password_read_right_found", {item["name"] for item in findings})
            self.assertIn("delegation_abuse_edge", {item["name"] for item in findings})
            adcs = next(item for item in findings if item["name"] == "adcs_enrollment_right_found")
            self.assertTrue(adcs["attributes"]["template_vulnerable"])

            correlated = correlate_bloodhound_ownership([_credential("svc_web"), *findings])
            names = {item["name"] for item in correlated}
            self.assertIn("bloodhound_owned_zero_hop_gmsa_read", names)
            self.assertIn("bloodhound_owned_zero_hop_adcs", names)
            self.assertIn("bloodhound_owned_delegation_edge", names)


class CertipyEnrollmentTests(unittest.TestCase):
    def test_parser_preserves_user_enrollable_principals(self):
        payload = {
            "Certificate Templates": {
                "0": {
                    "Template Name": "ESC1-Template",
                    "Enabled": True,
                    "[+] User Enrollable Principals": ["CORP.LOCAL\\svc_web"],
                    "[!] Vulnerabilities": {"ESC1": "Enrollee supplies subject"},
                }
            }
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", encoding="utf-8", delete=False) as stream:
            json.dump(payload, stream)
            path = stream.name
        self.addCleanup(lambda: Path(path).unlink(missing_ok=True))
        findings = parse_certipy_json(path, "CORP.LOCAL")
        self.assertEqual(
            findings[0]["attributes"]["enrollment_principals"],
            ["CORP.LOCAL\\svc_web"],
        )


if __name__ == "__main__":
    unittest.main()
