"""Classify credential material by the action it safely supports."""

import re


_NT_HASH = re.compile(r"^[0-9a-fA-F]{32}$")
_LM_NT_HASH = re.compile(r"^[0-9a-fA-F]{32}:[0-9a-fA-F]{32}$")
_CRACK_FIRST_TYPE_MARKERS = (
    "netntlm", "net-ntlm", "net ntlm", "as-rep", "asrep", "tgs-rep", "tgsrep",
    "kerberoast", "dcc2", "mscash", "cached domain", "dpapi",
)
_CRACK_FIRST_HASH_MARKERS = (
    "$netntlm$", "$krb5asrep$", "$krb5tgs$", "$dcc2$", "$dpapi",
)
_PASS_THE_HASH_TYPES = {"ntlm", "nt", "nthash", "nt hash"}


def credential_usages(attributes):
    """Return every safe action supported by the credential's material."""
    attrs = attributes if isinstance(attributes, dict) else {}
    explicit = str(attrs.get("credential_usage") or "").strip().lower()
    usages = set()
    if attrs.get("password") not in (None, ""):
        usages.add("password_reuse")

    hash_type = str(attrs.get("hash_type") or "").strip().lower()
    hash_value = str(
        attrs.get("hash") or attrs.get("nt_hash") or attrs.get("ntlm_hash")
        or attrs.get("dpapi") or attrs.get("kerberos_key") or ""
    ).strip()
    low_hash = hash_value.lower()

    crack_only = (any(marker in hash_type for marker in _CRACK_FIRST_TYPE_MARKERS)
                  or any(marker in low_hash for marker in _CRACK_FIRST_HASH_MARKERS))
    if crack_only and "password_reuse" not in usages:
        usages.add("crack_first")
    if any(attrs.get(field) for field in ("aes128_key", "aes256_key", "kerberos_key")):
        usages.add("ticket_key")

    direct_nt = str(attrs.get("nt_hash") or attrs.get("ntlm_hash") or "").strip()
    if not crack_only:
        if direct_nt and _NT_HASH.fullmatch(direct_nt) and hash_type in _PASS_THE_HASH_TYPES | {""}:
            usages.add("pass_the_hash")
        elif hash_type in _PASS_THE_HASH_TYPES and (
                _NT_HASH.fullmatch(hash_value) or _LM_NT_HASH.fullmatch(hash_value)):
            usages.add("pass_the_hash")
        elif (hash_value and "ticket_key" not in usages
              and "password_reuse" not in usages):
            usages.add("crack_first")
    if not usages and explicit in {"crack_first", "ticket_key", "review"}:
        usages.add(explicit)
    return usages or {"review"}


def credential_usage(attributes):
    """Return the primary usage while preserving all capabilities via credential_usages."""
    usages = credential_usages(attributes)
    for usage in ("password_reuse", "pass_the_hash", "crack_first", "ticket_key", "review"):
        if usage in usages:
            return usage
    return "review"


def usable_ntlm_hash(attributes):
    """Return only hash material that is valid for NTLM pass-the-hash."""
    attrs = attributes if isinstance(attributes, dict) else {}
    if "pass_the_hash" not in credential_usages(attrs):
        return None
    direct = str(attrs.get("nt_hash") or attrs.get("ntlm_hash") or "").strip()
    if _NT_HASH.fullmatch(direct):
        return direct
    value = str(attrs.get("hash") or "").strip()
    if _NT_HASH.fullmatch(value) or _LM_NT_HASH.fullmatch(value):
        return value
    return None
