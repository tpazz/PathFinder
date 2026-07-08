"""Tests for credential-aware deduplication and per-finding validation in
main.pathfinder (dedup merges rather than drops; validation skips only bad records).
"""
import unittest

from main.pathfinder import deduplicate_findings, validate_parser_output


def _cred(host, user, domain=None, **attrs):
    a = {"source_of_credential": "test"}
    if domain is not None:
        a["domain"] = domain
    a.update(attrs)
    return {"host": host, "port": None, "source_tool": attrs.pop("tool", "toolA"),
            "entity_type": "credential", "name": user, "version": None, "attributes": a}


class CredentialDedupMergeTests(unittest.TestCase):
    def test_password_and_hash_for_same_user_merge(self):
        findings = [
            {"host": "dc", "port": None, "source_tool": "netexec", "entity_type": "credential",
             "name": "admin", "version": None, "attributes": {"domain": "CORP", "password": "P@ss", "score": 70}},
            {"host": "dc", "port": None, "source_tool": "secretsdump", "entity_type": "credential",
             "name": "admin", "version": None, "attributes": {"domain": "CORP", "nt_hash": "aad3b", "hash_type": "NTLM", "score": 60}},
        ]
        out = deduplicate_findings(findings)
        self.assertEqual(len(out), 1)
        attrs = out[0]["attributes"]
        self.assertEqual(attrs["password"], "P@ss")
        self.assertEqual(attrs["nt_hash"], "aad3b")
        self.assertEqual(attrs["score"], 70)  # max of the two
        self.assertEqual(set(attrs["corroborating_sources"]), {"netexec", "secretsdump"})

    def test_same_user_different_domain_not_merged(self):
        findings = [_cred("dc", "admin", "CORP", password="a"),
                    _cred("dc", "admin", "OTHER", password="b")]
        self.assertEqual(len(deduplicate_findings(findings)), 2)

    def test_existing_secret_not_overwritten(self):
        findings = [_cred("dc", "svc", "CORP", password="first"),
                    _cred("dc", "svc", "CORP", password="second")]
        out = deduplicate_findings(findings)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["attributes"]["password"], "first")


class AnonymousCredentialDedupTests(unittest.TestCase):
    """Credentials disclosed with no username (e.g. SNMP leaks) must key on the
    secret, so two distinct leaked secrets on one host stay two leads."""

    def _snmp_cred(self, host, password, tool="snmp"):
        return {"host": host, "port": 161, "source_tool": tool, "entity_type": "credential",
                "name": "snmp_disclosed_credential", "version": None,
                "attributes": {"username": None, "password": password, "source_of_credential": "SNMP"}}

    def test_distinct_anonymous_secrets_not_merged(self):
        out = deduplicate_findings([self._snmp_cred("h", "hunter2"),
                                    self._snmp_cred("h", "backuppass")])
        self.assertEqual(len(out), 2)
        self.assertEqual({o["attributes"]["password"] for o in out}, {"hunter2", "backuppass"})

    def test_same_anonymous_secret_still_merges(self):
        out = deduplicate_findings([self._snmp_cred("h", "hunter2"),
                                    self._snmp_cred("h", "hunter2", tool="snmpwalk")])
        self.assertEqual(len(out), 1)
        self.assertEqual(set(out[0]["attributes"]["corroborating_sources"]), {"snmp", "snmpwalk"})

    def test_named_credential_without_domain_still_merges_secrets(self):
        # Regression guard: a real (domainless) user must still merge password + hash.
        findings = [
            {"host": "box", "port": None, "source_tool": "netexec", "entity_type": "credential",
             "name": "admin", "version": None, "attributes": {"password": "P@ss"}},
            {"host": "box", "port": None, "source_tool": "secretsdump", "entity_type": "credential",
             "name": "admin", "version": None, "attributes": {"nt_hash": "aad3b"}},
        ]
        out = deduplicate_findings(findings)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["attributes"]["password"], "P@ss")
        self.assertEqual(out[0]["attributes"]["nt_hash"], "aad3b")


class ProvenanceMergeTests(unittest.TestCase):
    def test_non_credential_duplicate_records_provenance(self):
        findings = [
            {"host": "h", "port": 80, "source_tool": "nmap", "entity_type": "software_product",
             "name": "Apache", "version": "2.4", "attributes": {"source_file": "a.xml"}},
            {"host": "h", "port": 80, "source_tool": "whatweb", "entity_type": "software_product",
             "name": "Apache", "version": "2.4", "attributes": {"source_file": "b.txt"}},
        ]
        out = deduplicate_findings(findings)
        self.assertEqual(len(out), 1)
        self.assertEqual(set(out[0]["attributes"]["corroborating_sources"]), {"nmap", "whatweb"})
        self.assertEqual(set(out[0]["attributes"]["source_files"]), {"a.xml", "b.txt"})


class PerFindingValidationTests(unittest.TestCase):
    def test_keeps_good_drops_bad(self):
        good = {"host": "h", "port": 80, "source_tool": "t", "entity_type": "service",
                "name": "http", "version": None, "attributes": {}}
        bad_missing = {"host": "h", "name": "no-required-fields"}
        bad_type = "not a dict"
        out = validate_parser_output("demo", [good, bad_missing, bad_type])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["name"], "http")

    def test_non_list_returns_empty(self):
        self.assertEqual(validate_parser_output("demo", {"not": "a list"}), [])

    def test_all_valid_passes_through(self):
        findings = [{"host": None, "port": None, "source_tool": "t", "entity_type": "credential",
                     "name": "u", "version": None, "attributes": {}}]
        self.assertEqual(len(validate_parser_output("demo", findings)), 1)


if __name__ == "__main__":
    unittest.main()
