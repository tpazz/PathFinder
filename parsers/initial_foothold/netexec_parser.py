import re

from parsers.ansi import ANSI_ESCAPE_PATTERN

# A NetExec/CrackMapExec result line:
#   SMB   10.10.10.10   445   DC01   [+] corp.local\admin:Password123 (Pwn3d!)
# re.search (not match) tolerates a leading --log timestamp/level prefix.
_PROTO_LINE = re.compile(
    r"\b(?P<proto>SMB|LDAP|LDAPS|WINRM|RDP|MSSQL|SSH|FTP|WMI|NFS|VNC)\s+"
    r"(?P<host>[0-9a-fA-F:.]+)\s+(?P<port>\d+)\s+(?P<name>\S+)\s+(?P<body>.*\S)\s*$"
)
# [+] domain\user:secret  (secret stops at whitespace or '(')
_CRED = re.compile(r"\[\+\]\s*(?P<dom>[^\\\s]*)\\(?P<user>[^:\s]+):(?P<secret>[^\s(]*)")
# domain\:  with empty user => null session
_NULL_SESSION = re.compile(r"\[\+\]\s*\S*\\\s*:\s*(?:\(|$)")
# Hash forms: NTLM "lm:nt" or a bare 32-hex NT hash.
_HASH = re.compile(r"^[a-fA-F0-9]{32}(:[a-fA-F0-9]{32})?$")
_SHARE_ROW = re.compile(r"^(?P<share>\S[\S ]*?)\s{2,}(?P<perms>READ(?:,\s*WRITE)?|WRITE(?:,\s*READ)?|READ ONLY|WRITE ONLY)\b(?:\s+(?P<remark>.*\S))?")


def parse_netexec_output(file_path, target_host=None):
    """
    Parses NetExec (nxc) / CrackMapExec output (console capture or --log file).

    Emits:
      - credential        : validated creds ([+] domain\\user:secret), password or hash
      - privilege_escalation: admin access (Pwn3d!) on a host
      - misconfiguration  : SMB signing disabled, null-session access, writable shares
      - share             : enumerated readable/writable shares
    """
    findings = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except FileNotFoundError:
        print(f"[!] Error: NetExec output file not found at {file_path}")
        return findings

    seen_creds = set()
    signing_flagged = set()
    domain_by_host = {}
    in_shares_for = None  # host whose share table we are currently inside

    for raw_line in content.splitlines():
        line = ANSI_ESCAPE_PATTERN.sub("", raw_line).rstrip()
        match = _PROTO_LINE.search(line)
        if not match:
            continue

        proto = match.group("proto").upper()
        host = match.group("host")
        try:
            port = int(match.group("port"))
        except (ValueError, TypeError):
            port = None
        body = match.group("body").strip()

        # Track the share table state machine.
        if "enumerated shares" in body.lower() or re.match(r"^Share\s+Permissions", body, re.IGNORECASE):
            in_shares_for = host
            continue

        # Capture domain from the host info line, e.g. "(domain:CORP.LOCAL)".
        dom_match = re.search(r"\(domain:([^)]+)\)", body, re.IGNORECASE)
        if dom_match:
            domain_by_host[host] = dom_match.group(1).strip()

        # SMB signing disabled -> relay target.
        if re.search(r"signing\s*:\s*false", body, re.IGNORECASE) and host not in signing_flagged:
            signing_flagged.add(host)
            findings.append({
                "host": host, "port": port or 445, "source_tool": "netexec",
                "entity_type": "misconfiguration", "name": "smb_signing_disabled", "version": None,
                "attributes": {"protocol": proto, "description": f"SMB signing is disabled on {host}; viable NTLM relay target."},
            })

        # A [+]/[-]/[*] status line ends any share table we were reading.
        is_status_line = bool(re.match(r"^\[[-+*!]\]", body))
        if is_status_line:
            in_shares_for = None

        # Null session.
        if _NULL_SESSION.search(body) or "(guest)" in body.lower():
            findings.append({
                "host": host, "port": port or 445, "source_tool": "netexec",
                "entity_type": "misconfiguration", "name": "null_session_allowed", "version": None,
                "attributes": {"protocol": proto, "description": f"Anonymous/guest session allowed on {host} ({proto})."},
            })
            continue

        # Validated credential.
        cred_match = _CRED.search(body)
        if cred_match and body.startswith("[+]"):
            domain = cred_match.group("dom") or domain_by_host.get(host) or ""
            user = cred_match.group("user")
            secret = cred_match.group("secret")
            pwned = "(Pwn3d!)" in body or "pwn3d" in body.lower()

            cred_key = (host, domain.lower(), user.lower(), secret)
            if cred_key not in seen_creds:
                seen_creds.add(cred_key)
                is_hash = bool(_HASH.match(secret))
                attributes = {
                    "domain": domain or None,
                    "password": None if is_hash else (secret or None),
                    "hash": secret if is_hash else None,
                    "hash_type": "NTLM" if is_hash else None,
                    "protocol": proto,
                    "validated": True,
                    "admin": pwned,
                    "source_of_credential": f"netexec {proto.lower()}",
                }
                findings.append({
                    "host": host, "port": port, "source_tool": "netexec",
                    "entity_type": "credential", "name": user, "version": None,
                    "attributes": attributes,
                })

            if pwned:
                findings.append({
                    "host": host, "port": port, "source_tool": "netexec",
                    "entity_type": "privilege_escalation", "name": "admin_access_validated", "version": None,
                    "attributes": {
                        "user": f"{domain}\\{user}" if domain else user,
                        "protocol": proto,
                        "description": f"Validated administrative access (Pwn3d!) as '{user}' on {host} via {proto}.",
                    },
                })
            continue

        # Share rows within an "Enumerated shares" table.
        if in_shares_for == host:
            share_match = _SHARE_ROW.match(body)
            if share_match:
                share_name = share_match.group("share").strip()
                perms = share_match.group("perms").upper()
                if share_name.lower() in {"share", "disk"} or set(share_name) <= {"-"}:
                    continue
                writable = "WRITE" in perms
                findings.append({
                    "host": host, "port": port or 445, "source_tool": "netexec",
                    "entity_type": "share", "name": share_name, "version": None,
                    "attributes": {"permissions": perms, "remark": (share_match.group("remark") or "").strip() or None,
                                   "writable": writable, "readable": "READ" in perms},
                })
                if writable:
                    findings.append({
                        "host": host, "port": port or 445, "source_tool": "netexec",
                        "entity_type": "misconfiguration", "name": "writable_smb_share", "version": None,
                        "attributes": {"share": share_name, "permissions": perms,
                                       "description": f"SMB share '{share_name}' on {host} is writable ({perms})."},
                    })

    return findings
