import re

from parsers.ansi import ANSI_ESCAPE_PATTERN, warn


_ASREP_USER = re.compile(r"\$krb5asrep\$(?P<etype>\d+)\$(?P<user>[^@:$\s]+)(?:@(?P<domain>[^:\s]+))?:")
_TGS_USER = re.compile(r"\$krb5tgs\$(?P<etype>\d+)\$\*(?P<user>[^$*]+)\$(?P<domain>[^$*]+)\$")
_PWDUMP_POT = re.compile(
    r"^(?P<raw_user>[^:\s][^:]*):(?P<rid>\d+):(?P<lm>[a-fA-F0-9]{32}):"
    r"(?P<nt>[a-fA-F0-9]{32}):::(?P<password>.+)$"
)
_NTLM_POT = re.compile(r"^(?P<hash>[a-fA-F0-9]{32}):(?P<password>.+)$")


def _hash_type(hash_value, etype=None):
    low = hash_value.lower()
    if "$krb5asrep$" in low:
        return f"Kerberos AS-REP ({etype or '18200'})"
    if "$krb5tgs$" in low:
        return f"Kerberos TGS-REP ({etype or '13100'})"
    if re.fullmatch(r"[a-f0-9]{32}", low):
        return "NTLM"
    if low.startswith("$"):
        return "john/hashcat"
    return "unknown"


def _split_known_hash(raw):
    """Return (hash, password) for pot lines while preserving colons inside krb5 hashes."""
    pwdump = _PWDUMP_POT.match(raw)
    if pwdump:
        hash_value = f"{pwdump.group('lm')}:{pwdump.group('nt')}"
        return hash_value, pwdump.group("password"), pwdump

    ntlm = _NTLM_POT.match(raw)
    if ntlm:
        return ntlm.group("hash"), ntlm.group("password"), ntlm

    if "$krb5asrep$" in raw.lower() or "$krb5tgs$" in raw.lower() or raw.startswith("$"):
        if ":" not in raw:
            return None, None, None
        hash_value, password = raw.rsplit(":", 1)
        if hash_value and password:
            return hash_value, password, None

    return None, None, None


def _principal_from_hash(hash_value, match_obj=None):
    if match_obj and match_obj.re is _PWDUMP_POT:
        raw_user = match_obj.group("raw_user")
        domain, _, user = raw_user.rpartition("\\")
        return user, domain or None, None

    asrep = _ASREP_USER.search(hash_value)
    if asrep:
        return asrep.group("user"), asrep.group("domain"), asrep.group("etype")

    tgs = _TGS_USER.search(hash_value)
    if tgs:
        return tgs.group("user"), tgs.group("domain"), tgs.group("etype")

    return None, None, None


def parse_potfile(file_path, target_host=None):
    """
    Parse john/hashcat .pot cracked-password files.

    Kerberos AS-REP/TGS and pwdump-shaped pot entries carry the account name, so
    they become spray-ready credential findings. Hash-only entries are still kept
    as identity-less cracked secrets for operator correlation.
    """
    findings = []
    seen = set()
    host = target_host or "CRACKED"

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except FileNotFoundError:
        warn(f"[!] Error: potfile not found at {file_path}")
        return findings

    for raw_line in lines:
        raw = ANSI_ESCAPE_PATTERN.sub("", raw_line).strip()
        if not raw or raw.startswith("#"):
            continue

        hash_value, password, match_obj = _split_known_hash(raw)
        if not hash_value or not password:
            continue

        username, domain, etype = _principal_from_hash(hash_value, match_obj)
        name = username or "cracked_disclosed_credential"
        key = (name.lower(), (domain or "").lower(), hash_value.lower(), password)
        if key in seen:
            continue
        seen.add(key)

        attrs = {
            "username": username,
            "domain": domain,
            "password": password,
            "hash": hash_value,
            "hash_type": _hash_type(hash_value, etype),
            "source_of_credential": "john/hashcat potfile",
            "source_file": file_path,
        }
        if match_obj and match_obj.re is _PWDUMP_POT:
            attrs["rid"] = match_obj.group("rid")
            attrs["lm_hash"] = match_obj.group("lm")
            attrs["nt_hash"] = match_obj.group("nt")

        findings.append({
            "host": host,
            "port": None,
            "source_tool": "john/hashcat-pot",
            "entity_type": "credential",
            "name": name,
            "version": None,
            "attributes": attrs,
        })

    return findings
