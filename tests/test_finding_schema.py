import unittest

from main.finding_schema import FindingValidationError, validate_and_normalize_finding, validate_findings


class FindingSchemaTests(unittest.TestCase):
    def test_accepts_valid_finding(self):
        finding = {
            "host": "10.10.10.10",
            "port": 80,
            "source_tool": "test-tool",
            "entity_type": "web_content",
            "name": "/admin",
            "version": None,
            "attributes": {"status_code": 200},
        }

        normalized = validate_and_normalize_finding(finding)
        self.assertEqual(normalized["name"], "/admin")

    def test_rejects_missing_required_field(self):
        with self.assertRaises(FindingValidationError):
            validate_and_normalize_finding({"host": "10.10.10.10"})

    def test_rejects_non_list_batch_payload(self):
        with self.assertRaises(FindingValidationError):
            validate_findings({"host": "10.10.10.10"})


if __name__ == "__main__":
    unittest.main()
