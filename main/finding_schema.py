"""Schema validation helpers for normalized Pathfinder findings."""

from copy import deepcopy

REQUIRED_FIELDS = [
    "host",
    "port",
    "source_tool",
    "entity_type",
    "name",
    "version",
    "attributes",
]


class FindingValidationError(ValueError):
    """Raised when a finding does not conform to the normalized schema."""


def validate_and_normalize_finding(finding):
    """Validate and normalize a single finding dictionary.

    Returns a normalized copy of the input finding or raises FindingValidationError.
    """
    if not isinstance(finding, dict):
        raise FindingValidationError("Finding must be a dictionary")

    missing = [field for field in REQUIRED_FIELDS if field not in finding]
    if missing:
        raise FindingValidationError(f"Missing required field(s): {', '.join(missing)}")

    normalized = deepcopy(finding)

    host = normalized.get("host")
    if host is not None and not isinstance(host, str):
        raise FindingValidationError("'host' must be a string or None")

    port = normalized.get("port")
    if port is not None and not isinstance(port, int):
        raise FindingValidationError("'port' must be an integer or None")

    for field in ["source_tool", "entity_type", "name"]:
        value = normalized.get(field)
        if not isinstance(value, str) or not value.strip():
            raise FindingValidationError(f"'{field}' must be a non-empty string")

    # `user` was the original normalized entity name. Treat saved findings from
    # older PathFinder versions as confirmed identities while exposing the more
    # explicit type used by current parsers and rules.
    if normalized.get("entity_type") == "user":
        normalized["entity_type"] = "confirmed_username"

    version = normalized.get("version")
    if version is not None and not isinstance(version, str):
        raise FindingValidationError("'version' must be a string or None")

    if normalized.get("attributes") is None:
        normalized["attributes"] = {}

    if not isinstance(normalized.get("attributes"), dict):
        raise FindingValidationError("'attributes' must be a dictionary")

    return normalized


def validate_findings(findings):
    """Validate and normalize a list of finding dictionaries."""
    if not isinstance(findings, list):
        raise FindingValidationError("Parser output must be a list of findings")

    return [validate_and_normalize_finding(finding) for finding in findings]
