import re

from parsers.ansi import ANSI_ESCAPE_PATTERN, warn

# pwdump line: user:rid:lmhash:nthash:::   (SAM dump or NTDS dump)
_PWDUMP = re.compile(
    r"^(?P<user>[^:\s][^:]*):(?P<rid>\d+):(?P<lm>[a-fA-F0-9]{32}):(?P<nt>[a-fA-F0-9]{32}):::"
)
# Cleartext creds line emitted for reversible-encryption / WDigest accounts.
_CLEARTEXT = re.compile(r"^(?P<user>[^:\s][^:]*):CLEARTEXT:(?P<password>.*)$", re.IGNORECASE)


def parse_secretsdump(file_path, target_host=None):
    """
    Parses impacket-secretsdump output (SAM/NTDS dump or stdout capture).

    Emits one credential finding per recovered account: NT hash (for
    pass-the-hash / cracking) and any cleartext recovered from reversible
    encryption. Machine accounts (ending in '$') are tagged but still emitted.
    """
    findings = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except FileNotFoundError:
        warn(f"[!] Error: secretsdump output file not found at {file_path}")
        return findings

    host = target_host or "SECRETSDUMP"
    seen = set()

    for raw_line in content.splitlines():
        line = ANSI_ESCAPE_PATTERN.sub("", raw_line).strip()
        if not line:
            continue

        pw = _PWDUMP.match(line)
        if pw:
            raw_user = pw.group("user")
            # Accounts may be "DOMAIN\user" in NTDS dumps.
            domain, _, user = raw_user.rpartition("\\")
            nt_hash = pw.group("nt")
            full_hash = f"{pw.group('lm')}:{nt_hash}"
            key = (user.lower(), nt_hash.lower())
            if key in seen:
                continue
            seen.add(key)
            findings.append({
                "host": host, "port": None, "source_tool": "secretsdump",
                "entity_type": "credential", "name": user, "version": None,
                "attributes": {
                    "domain": domain or None,
                    "hash": full_hash,
                    "nt_hash": nt_hash,
                    "hash_type": "NTLM",
                    "rid": pw.group("rid"),
                    "machine_account": user.endswith("$"),
                    "source_of_credential": "secretsdump",
                },
            })
            continue

        ct = _CLEARTEXT.match(line)
        if ct:
            raw_user = ct.group("user")
            domain, _, user = raw_user.rpartition("\\")
            password = ct.group("password").strip()
            key = (user.lower(), password)
            if not password or key in seen:
                continue
            seen.add(key)
            findings.append({
                "host": host, "port": None, "source_tool": "secretsdump",
                "entity_type": "credential", "name": user, "version": None,
                "attributes": {
                    "domain": domain or None,
                    "password": password,
                    "source_of_credential": "secretsdump (cleartext)",
                },
            })

    return findings
