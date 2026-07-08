import re

from parsers.ansi import ANSI_ESCAPE_PATTERN, warn


_EXPORT_LINE = re.compile(r"^\s*(?:\|_?\s*)?(?P<export>/\S+)\s+(?P<clients>.+?)\s*$")
_CLIENT_SPEC = re.compile(r"^(?P<client>[^()\s]+)(?:\((?P<options>[^)]*)\))?$")


def _parse_client_specs(raw_clients):
    clients = []
    options = []
    for token in raw_clients.split():
        token = token.strip().strip("|").strip("_")
        if not token:
            continue
        match = _CLIENT_SPEC.match(token)
        if not match:
            continue
        client = match.group("client")
        if client:
            clients.append(client)
        opt_text = match.group("options") or ""
        for opt in [o.strip() for o in opt_text.split(",") if o.strip()]:
            if opt not in options:
                options.append(opt)
    return clients, options


def parse_nfs_output(file_path, target_host):
    """
    Parse NFS export enumeration from showmount -e, nmap nfs-showmount, or
    /etc/exports-style captures.
    """
    findings = []
    seen_exports = set()
    seen_privesc = set()

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except FileNotFoundError:
        warn(f"[!] Error: NFS output file not found at {file_path}")
        return findings

    for raw_line in lines:
        line = ANSI_ESCAPE_PATTERN.sub("", raw_line).strip()
        if not line or line.lower().startswith("export list for"):
            continue

        match = _EXPORT_LINE.match(line)
        if not match:
            continue

        export = match.group("export")
        clients, options = _parse_client_specs(match.group("clients"))
        if not clients and not options:
            continue

        world_accessible = "*" in clients
        read_write = "rw" in options
        no_root_squash = "no_root_squash" in options
        share_key = export.lower()

        if share_key not in seen_exports:
            seen_exports.add(share_key)
            findings.append({
                "host": target_host,
                "port": 2049,
                "source_tool": "nfs",
                "entity_type": "share",
                "name": export,
                "version": None,
                "attributes": {
                    "protocol": "NFS",
                    "export": export,
                    "clients": clients,
                    "options": options,
                    "world_accessible": world_accessible,
                    "read_write": read_write,
                    "no_root_squash": no_root_squash,
                    "source_file": file_path,
                },
            })

        if no_root_squash and share_key not in seen_privesc:
            seen_privesc.add(share_key)
            findings.append({
                "host": target_host,
                "port": 2049,
                "source_tool": "nfs",
                "entity_type": "privilege_escalation",
                "name": "nfs_no_root_squash",
                "version": None,
                "attributes": {
                    "export": export,
                    "clients": clients,
                    "options": options,
                    "description": f"NFS export {export} includes no_root_squash"
                                   + (" and rw" if read_write else ""),
                    "source_file": file_path,
                },
            })

    return findings
