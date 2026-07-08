"""Single source of truth for PathFinder's input parsers.

Both manual mode (explicit --flags) and scan mode (auto-detection) drive their
parser dispatch, CLI flags, and host-required checks from PARSER_SPECS here, so
adding a parser means editing exactly one list instead of four call sites.
"""
from collections import namedtuple

from parsers.active_directory.kerberos_parser import parse_getnpusers_output, parse_getuserspns_output, parse_kerbrute_output
from parsers.active_directory.ldapdomaindump_parser import parse_ldapdomaindump_dir
from parsers.active_directory.potfile_parser import parse_potfile
from parsers.active_directory.sharphound_parser import parse_sharphound_dir
from parsers.active_directory.certipy_parser import parse_certipy_json
from parsers.active_directory.secretsdump_parser import parse_secretsdump
from parsers.initial_foothold.enum4linux_parser import parse_enum4linux_json
from parsers.initial_foothold.ffuf_parser import parse_ffuf_json
from parsers.initial_foothold.gobuster_parser import parse_gobuster_output
from parsers.initial_foothold.llm_enum_parser import parse_llm_enum_json
from parsers.initial_foothold.netexec_parser import parse_netexec_output
from parsers.initial_foothold.nfs_parser import parse_nfs_output
from parsers.initial_foothold.nikto_parser import parse_nikto_json
from parsers.initial_foothold.nmap_parser import parse_nmap_xml
from parsers.initial_foothold.nuclei_parser import parse_nuclei_jsonl
from parsers.initial_foothold.smbmap_parser import parse_smbmap_output
from parsers.initial_foothold.snmp_parser import parse_snmp_output
from parsers.initial_foothold.sqlmap_parser import parse_sqlmap_log
from parsers.initial_foothold.whatweb_parser import parse_whatweb_json
from parsers.initial_foothold.wpscan_parser import parse_wpscan_json
from parsers.privilege_escalation.linpeas_parser import parse_linpeas
from parsers.privilege_escalation.winpeas_parser import parse_winpeas


class ParserContext:
    """Carries the shared, host-related context parsers may need."""

    def __init__(self, target_host=None, gobuster_host=None, gobuster_port=80, gobuster_mode="dir"):
        self.target_host = target_host
        self.gobuster_host = gobuster_host if gobuster_host is not None else target_host
        self.gobuster_port = gobuster_port if gobuster_port is not None else 80
        self.gobuster_mode = gobuster_mode or "dir"


# key:          stable identifier used by auto-detection and as the argparse dest
# flag:         the manual-mode CLI flag
# help:         argparse help text
# host_required: skip in scan mode (and warn in manual mode) when no target host is known
# run:          callable(path, ParserContext) -> list[finding]
ParserSpec = namedtuple("ParserSpec", ["key", "flag", "help", "host_required", "run"])


PARSER_SPECS = [
    ParserSpec("nmap_xml", "--nmap-xml", "Path to Nmap XML output file.",
               False, lambda p, ctx: parse_nmap_xml(p)),
    ParserSpec("gobuster_txt", "--gobuster-txt", "Path to Gobuster text output file.",
               True, lambda p, ctx: parse_gobuster_output(p, ctx.gobuster_host, ctx.gobuster_port, ctx.gobuster_mode)),
    ParserSpec("nikto_json", "--nikto-json", "Path to Nikto JSON output file.",
               False, lambda p, ctx: parse_nikto_json(p)),
    ParserSpec("whatweb_json", "--whatweb-json", "Path to WhatWeb JSON output file.",
               False, lambda p, ctx: parse_whatweb_json(p)),
    ParserSpec("ffuf_json", "--ffuf-json", "Path to ffuf JSON output file (-of json).",
               False, lambda p, ctx: parse_ffuf_json(p)),
    ParserSpec("nuclei_jsonl", "--nuclei-jsonl", "Path to nuclei JSONL output file (-jsonl).",
               False, lambda p, ctx: parse_nuclei_jsonl(p)),
    ParserSpec("wpscan_json", "--wpscan-json", "Path to wpscan JSON output file (--format json).",
               False, lambda p, ctx: parse_wpscan_json(p)),
    ParserSpec("llm_enum_json", "--llm-enum-json", "Path to one-shot-enum LLM/AI enumeration JSON.",
               False, lambda p, ctx: parse_llm_enum_json(p)),
    ParserSpec("enum4linux_json", "--enum4linux-json", "Path to enum4linux-ng JSON output file.",
               True, lambda p, ctx: parse_enum4linux_json(p, ctx.target_host)),
    ParserSpec("smbmap_txt", "--smbmap-txt", "Path to smbmap text output file.",
               False, lambda p, ctx: parse_smbmap_output(p, ctx.target_host)),
    ParserSpec("netexec_log", "--netexec-log", "Path to NetExec/CrackMapExec log or console output.",
               False, lambda p, ctx: parse_netexec_output(p, ctx.target_host)),
    ParserSpec("linpeas_txt", "--linpeas-txt", "Path to LinPEAS output text file.",
               True, lambda p, ctx: parse_linpeas(p, ctx.target_host)),
    ParserSpec("winpeas_txt", "--winpeas-txt", "Path to WinPEAS output text file.",
               True, lambda p, ctx: parse_winpeas(p, ctx.target_host)),
    ParserSpec("snmp_txt", "--snmp-txt", "Path to snmp-check output text file.",
               True, lambda p, ctx: parse_snmp_output(p, ctx.target_host)),
    ParserSpec("nfs_txt", "--nfs-txt", "Path to NFS export enumeration output (showmount/nmap).",
               True, lambda p, ctx: parse_nfs_output(p, ctx.target_host)),
    ParserSpec("sharphound_dir", "--sharphound-dir", "Path to directory with unzipped SharpHound JSON files.",
               False, lambda p, ctx: parse_sharphound_dir(p)),
    ParserSpec("ldapdomaindump_dir", "--ldapdomaindump-dir", "Path to directory with ldapdomaindump TSV files.",
               False, lambda p, ctx: parse_ldapdomaindump_dir(p)),
    ParserSpec("kerbrute_txt", "--kerbrute-txt", "Path to kerbrute valid user list.",
               True, lambda p, ctx: parse_kerbrute_output(p, ctx.target_host)),
    ParserSpec("getnpusers_hashes", "--getnpusers-hashes", "Path to impacket-GetNPUsers AS-REP hash file.",
               True, lambda p, ctx: parse_getnpusers_output(p, ctx.target_host)),
    ParserSpec("getuserspns_hashes", "--getuserspns-hashes", "Path to impacket-GetUserSPNs Kerberoast hash file.",
               False, lambda p, ctx: parse_getuserspns_output(p, ctx.target_host)),
    ParserSpec("secretsdump_txt", "--secretsdump-txt", "Path to impacket-secretsdump output.",
               False, lambda p, ctx: parse_secretsdump(p, ctx.target_host)),
    ParserSpec("potfile_txt", "--potfile", "Path to john/hashcat .pot cracked-password file.",
               False, lambda p, ctx: parse_potfile(p, ctx.target_host)),
    ParserSpec("certipy_json", "--certipy-json", "Path to certipy find JSON output.",
               False, lambda p, ctx: parse_certipy_json(p, ctx.target_host)),
    ParserSpec("sqlmap_log", "--sqlmap-log", "Path to sqlmap log file from its output directory.",
               False, lambda p, ctx: parse_sqlmap_log(p)),
]

# Convenience lookups.
SPEC_BY_KEY = {spec.key: spec for spec in PARSER_SPECS}
HOST_REQUIRED_KEYS = {spec.key for spec in PARSER_SPECS if spec.host_required}
