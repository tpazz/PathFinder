"""Tolerant pypykatz and lsassy JSON credential ingestion."""

import json
import os
import re

from parsers.ansi import warn

MAX_LSASS_JSON_BYTES = 128 * 1024 * 1024
_NT_HASH = re.compile(r"^[0-9a-fA-F]{32}$")
_EMPTY_VALUES = {"", "none", "null", "(null)", "<null>", "(nil)", "n/a", "unknown"}


def _key(value):
    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def _string(value):
    if value is None or isinstance(value, (dict, list, tuple, set)):
        return None
    text = str(value).strip()
    return None if text.lower() in _EMPTY_VALUES else text


def _ci_value(record, *names):
    if not isinstance(record, dict):
        return None
    wanted = {_key(name) for name in names}
    for name, value in record.items():
        if _key(name) in wanted:
            text = _string(value)
            if text is not None:
                return text
    return None


def _identity(record, inherited):
    context = dict(inherited)
    username = _ci_value(record, "username", "user", "account", "samaccountname")
    domain = _ci_value(record, "domainname", "domain", "realm")
    if username:
        context["username"] = username
    if domain:
        context["domain"] = domain
    session = _ci_value(record, "authentication_id", "luid", "session_id", "session")
    if session:
        context["session"] = session
    return context


def _finding(host, tool, context, secret_kind, secret, source_file, package=None):
    username = context.get("username")
    if not username:
        return None
    attrs = {
        "username": username,
        "domain": context.get("domain"),
        "source_of_credential": f"{tool} LSASS JSON",
        "source_file": source_file,
    }
    if context.get("session"):
        attrs["logon_session"] = context["session"]
    if package:
        attrs["authentication_package"] = package

    if secret_kind == "password":
        attrs.update({"password": secret, "credential_usage": "password_reuse"})
    elif secret_kind == "nt_hash":
        attrs.update({
            "hash": secret,
            "nt_hash": secret,
            "hash_type": "NTLM",
            "credential_usage": "pass_the_hash",
        })
    elif secret_kind == "lm_hash":
        attrs.update({
            "hash": secret,
            "lm_hash": secret,
            "hash_type": "LM",
            "credential_usage": "crack_first",
        })
    elif secret_kind in {"aes128", "aes256"}:
        bits = "128" if secret_kind == "aes128" else "256"
        attrs.update({
            f"aes{bits}_key": secret,
            "hash": secret,
            "hash_type": f"Kerberos AES-{bits} key",
            "credential_usage": "ticket_key",
        })
    elif secret_kind == "dpapi":
        attrs.update({
            "dpapi": secret,
            "hash": secret,
            "hash_type": "DPAPI credential material",
            "credential_usage": "crack_first",
        })
    else:
        attrs.update({
            "hash": secret,
            "hash_type": "SHA1 credential digest",
            "credential_usage": "crack_first",
        })

    return {
        "host": host,
        "port": None,
        "source_tool": tool,
        "entity_type": "credential",
        "name": username,
        "version": None,
        "attributes": attrs,
    }


def _record_secrets(record):
    """Yield normalized secret kinds from one schema-variant record."""
    fields = {
        "password": ("password", "cleartext", "plaintext", "pass"),
        "nt_hash": ("nthash", "nt_hash", "ntlmhash", "ntlm_hash"),
        "lm_hash": ("lmhash", "lm_hash"),
        "aes128": ("aes128", "aes128key", "aes128_key"),
        "aes256": ("aes256", "aes256key", "aes256_key"),
        "dpapi": ("dpapi", "dpapikey", "dpapi_key", "masterkey", "master_key"),
        "sha1": ("shahash", "sha_hash", "sha1", "sha1hash", "sha1_hash"),
    }
    for kind, aliases in fields.items():
        value = _ci_value(record, *aliases)
        if not value:
            continue
        if kind in {"nt_hash", "lm_hash"} and not _NT_HASH.fullmatch(value):
            continue
        yield kind, value


def _walk_records(value, inherited=None, package=None, depth=0):
    if depth > 80:
        return
    inherited = inherited or {}
    if isinstance(value, dict):
        context = _identity(value, inherited)
        yield value, context, package
        for name, child in value.items():
            child_package = package
            normalized_name = _key(name)
            if normalized_name.endswith("creds") or normalized_name.endswith("credentials"):
                child_package = str(name)
            yield from _walk_records(child, context, child_package, depth + 1)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_records(child, inherited, package, depth + 1)


def _detect_tool(payload, file_path):
    hint = os.path.basename(str(file_path)).lower()
    if "lsassy" in hint:
        return "lsassy"
    if isinstance(payload, dict) and any("lsassy" in str(key).lower() for key in payload):
        return "lsassy"
    return "pypykatz"


def parse_lsass_json(file_path, target_host=None):
    """Parse pypykatz/lsassy JSON into password, PtH, and crack-first findings."""
    findings = []
    try:
        if os.path.getsize(file_path) > MAX_LSASS_JSON_BYTES:
            warn(f"[!] Warning: Skipping oversized LSASS JSON file '{file_path}'.")
            return findings
        with open(file_path, "r", encoding="utf-8-sig") as stream:
            payload = json.load(stream)
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        warn(f"[!] Warning: Could not load pypykatz/lsassy JSON '{file_path}': {exc}")
        return findings

    tool = _detect_tool(payload, file_path)
    host = target_host or "LSASS"
    seen = set()
    try:
        for record, context, package in _walk_records(payload):
            for kind, secret in _record_secrets(record):
                finding = _finding(host, tool, context, kind, secret, file_path, package)
                if finding is None:
                    continue
                attrs = finding["attributes"]
                marker = (
                    finding["name"].lower(), str(attrs.get("domain") or "").lower(),
                    kind, secret.lower(),
                )
                if marker in seen:
                    continue
                seen.add(marker)
                findings.append(finding)
    except RecursionError:
        warn(f"[!] Warning: pypykatz/lsassy JSON nesting was too deep in '{file_path}'.")
    return findings
