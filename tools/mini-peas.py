#!/usr/bin/env python3
"""Mini-PEAS: read-only manual privilege-escalation collector for PathFinder.

This collector automates focused Linux and Windows post-foothold checks. It
preserves command output, credential-like
lines, keys, histories, and other sensitive evidence without redaction. The
only intended write is the JSON report selected with --out.
"""

from __future__ import annotations

import argparse
import datetime as dt
import getpass
import json
import os
import platform
import re
import shlex
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Iterable


TOOL_NAME = "mini-peas"
REPORT_TYPE = "pathfinder_manual_privesc_loot"
SCHEMA_VERSION = "1.1"
DEFAULT_OUTPUT = "mini-peas-loot.json"
SKIP_DIRS = {
    ".git", ".svn", ".hg", "node_modules", "venv", ".venv", "__pycache__",
    "proc", "sys", "dev", "run", "snap", "WindowsApps",
}
TEXT_SUFFIXES = {
    ".txt", ".log", ".ini", ".conf", ".config", ".cfg", ".xml", ".json",
    ".yaml", ".yml", ".toml", ".env", ".properties", ".ps1", ".bat",
    ".cmd", ".sh", ".py", ".php", ".bak", ".old", ".save", ".sql",
    ".rdp", ".service", ".timer", ".socket", ".path",
    ".pem", ".key", ".ovpn",
}
INTERESTING_EXACT_NAMES = {
    ".netrc", ".npmrc", ".pypirc", ".dockerconfigjson", "credentials",
    "config.json", "kubeconfig", "unattend.xml", "unattended.xml",
    "autounattend.xml", "sysprep.xml", "web.config", "applicationhost.config",
}
INTERESTING_NAME_RE = re.compile(
    r"password|passwd|credential|secret|token|key|login|database|db|backup|"
    r"history|unattend|web\.config|config|settings|connection|string|env",
    re.I,
)
SECRET_LINE_RE = re.compile(
    r"password|passwd|pwd|secret|token|api[_-]?key|private[_-]?key|credential|"
    r"connectionstring|database_url|authorization|bearer",
    re.I,
)
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:OPENSSH |RSA |EC |DSA )?PRIVATE KEY-----")

COMMON_SUID_BASENAMES = {
    "chfn", "chsh", "fusermount", "fusermount3", "gpasswd", "mount", "newgrp",
    "passwd", "pkexec", "su", "sudo", "umount", "unix_chkpwd", "ssh-keysign",
}
KNOWN_ABUSABLE_SUID_BASENAMES = {
    "ash", "awk", "bash", "busybox", "cp", "dash", "env", "find", "less",
    "lua", "more", "nano", "nmap", "node", "perl", "php", "python",
    "python2", "python3", "ruby", "sh", "tar", "tee", "vim", "vi", "zip",
}
DANGEROUS_CAPABILITIES = {
    "cap_setuid", "cap_setgid", "cap_dac_override", "cap_dac_read_search",
    "cap_sys_admin", "cap_sys_ptrace", "cap_sys_module", "cap_chown", "cap_fowner",
}
DANGEROUS_GROUPS = {
    "docker", "lxd", "lxc", "disk", "adm", "shadow", "libvirt", "incus",
}


def _credential_lines(text: str) -> list[str]:
    lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "//")) or not SECRET_LINE_RE.search(stripped):
            continue
        if (re.search(r"(?i)(?:password|passwd|pwd|secret|token|api[_-]?key|credential|"
                     r"connectionstring|database_url|authorization)\s*[=:]\s*\S+", stripped)
                or re.search(r"(?i)<(?:password|token|secret|connectionString)>[^<]+</", stripped)
                or re.search(r"(?i)\bBearer\s+\S+", stripped)
                or re.search(r"(?i)\bmachine\s+\S+\s+login\s+\S+\s+password\s+\S+", stripped)
                or re.search(r"[a-z][a-z0-9+.-]*://[^\s/:]+:[^\s/@]+@", stripped)):
            lines.append(line)
    return lines


def _credential_context(text: str) -> dict[str, list[str]]:
    usernames = []
    secret_keys = []
    for line in text.splitlines():
        user_match = re.search(r"(?i)\b(?:user(?:name)?|login)\s*[=:]\s*[\"']?([^\s\"',;]+)", line)
        if user_match and user_match.group(1) not in usernames:
            usernames.append(user_match.group(1))
        key_match = re.search(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|connectionstring|database_url)\b", line)
        if key_match:
            key = key_match.group(1)
            if key not in secret_keys:
                secret_keys.append(key)
    return {"associated_usernames": usernames[:20], "secret_keys": secret_keys[:20]}


def _history_credential_lines(text: str) -> list[str]:
    patterns = re.compile(
        r"(?i)(?:sshpass\s+-p|curl\s+[^\n]*\s-u\s+\S+:\S+|"
        r"(?:mysql|psql|mssql|ftp)\s+[^\n]*(?:--password|-p\S+)|"
        r"export\s+\w*(?:PASSWORD|TOKEN|SECRET|KEY)\w*\s*=)"
    )
    values = _credential_lines(text)
    values.extend(line for line in text.splitlines() if patterns.search(line) and line not in values)
    return values


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("roots", nargs="*", help="Additional roots for credential/config searches")
    parser.add_argument(
        "-o",
        "--out",
        default=DEFAULT_OUTPUT,
        help=f"Output JSON path (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument("--max-files", type=int, default=50000, help="Max files examined in bounded searches")
    parser.add_argument("--max-file-kb", type=int, default=512, help="Largest text file read")
    parser.add_argument("--max-output-kb", type=int, default=2048, help="Max captured output per command/check")
    parser.add_argument("--command-timeout", type=int, default=30, help="Per-command timeout in seconds")
    parser.add_argument("--max-git-repos", type=int, default=100, help="Max Git repositories examined")
    parser.add_argument("--quiet", action="store_true", help="Suppress progressive check and finding output")
    parser.add_argument("--only-specified-roots", action="store_true",
                        help="Search only positional roots instead of also adding common OS locations")
    return parser.parse_args()


def _clip(value: str, max_bytes: int) -> tuple[str, bool]:
    encoded = value.encode("utf-8", errors="replace")
    if len(encoded) <= max_bytes:
        return value, False
    marker = b"\n... [mini-peas output truncated; head and tail retained] ...\n"
    if max_bytes <= len(marker) + 2:
        return encoded[:max_bytes].decode("utf-8", errors="replace"), True
    remaining = max_bytes - len(marker)
    head_size = remaining // 2
    tail_size = remaining - head_size
    clipped = encoded[:head_size] + marker + encoded[-tail_size:]
    return clipped.decode("utf-8", errors="replace"), True


class Collector:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.max_output_bytes = max(1, args.max_output_kb) * 1024
        self.max_file_bytes = max(1, args.max_file_kb) * 1024
        self.checks: list[dict[str, Any]] = []
        self.findings: list[dict[str, Any]] = []
        self._finding_keys: set[str] = set()
        self.files_examined = 0
        self.candidate_files_seen = 0
        self.file_errors = 0
        self.file_limit_reached = False
        try:
            self.excluded_output = str(Path(getattr(args, "out", DEFAULT_OUTPUT)).resolve())
        except OSError:
            self.excluded_output = str(Path(getattr(args, "out", DEFAULT_OUTPUT)))

    def progress(self, message: str) -> None:
        if not getattr(self.args, "quiet", False):
            print(message, flush=True)

    def command(self, label: str, argv: list[str], timeout: int | None = None) -> dict[str, Any]:
        started = time.monotonic()
        self.progress(f"[>] Check: {label}")
        record: dict[str, Any] = {
            "label": label,
            "command": subprocess.list2cmdline(argv) if os.name == "nt" else shlex.join(argv),
        }
        try:
            proc = subprocess.run(
                argv,
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                timeout=timeout or self.args.command_timeout,
                check=False,
            )
            stdout, stdout_truncated = _clip(proc.stdout, self.max_output_bytes)
            stderr, stderr_truncated = _clip(proc.stderr, self.max_output_bytes)
            record.update({
                "returncode": proc.returncode,
                "stdout": stdout,
                "stderr": stderr,
                "truncated": stdout_truncated or stderr_truncated,
            })
        except FileNotFoundError:
            record.update({"returncode": None, "stdout": "", "stderr": "command not available", "unavailable": True})
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            stderr = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            record.update({"returncode": None, "stdout": _clip(stdout, self.max_output_bytes)[0],
                           "stderr": _clip(stderr, self.max_output_bytes)[0], "timed_out": True})
        except OSError as exc:
            record.update({"returncode": None, "stdout": "", "stderr": str(exc), "error": True})
        record["duration_seconds"] = round(time.monotonic() - started, 3)
        self.checks.append(record)
        if record.get("timed_out"):
            status = "timed out"
        elif record.get("unavailable"):
            status = "unavailable"
        elif record.get("error"):
            status = "error"
        elif record.get("returncode") == 0:
            status = "complete"
        else:
            status = f"exit {record.get('returncode')}"
        self.progress(f"    [{status}] {label} ({record['duration_seconds']:.3f}s)")
        return record

    def file_check(self, label: str, path: Path) -> dict[str, Any] | None:
        self.progress(f"[>] Check: {label} ({path})")
        try:
            if not path.is_file() or path.stat().st_size > self.max_file_bytes:
                self.progress(f"    [skipped] {label}")
                return None
            raw = path.read_text(encoding="utf-8", errors="replace")
            content, truncated = _clip(raw, self.max_output_bytes)
            record = {
                "label": label,
                "path": str(path),
                "content": content,
                "truncated": truncated,
                "readable": True,
                "writable": os.access(path, os.W_OK),
            }
            self.checks.append(record)
            self.progress(f"    [complete] {label}")
            return record
        except OSError as exc:
            self.checks.append({"label": label, "path": str(path), "readable": False, "error": str(exc)})
            self.progress(f"    [error] {label}: {exc}")
            return None

    def finding(self, name: str, description: str, *, evidence: Any = None,
                confidence: str = "high", **attributes: Any) -> None:
        if isinstance(evidence, str):
            evidence = _clip(evidence, self.max_output_bytes)[0]
        if not attributes.get("discovery_command") and attributes.get("path"):
            attributes["discovery_command"] = f"inspect {attributes['path']}"
        record = {
            "name": name,
            "description": description,
            "confidence": confidence,
            "evidence": evidence,
            **attributes,
        }
        key = json.dumps(record, sort_keys=True, default=str)
        if key in self._finding_keys:
            return
        self._finding_keys.add(key)
        self.findings.append(record)
        self.progress(f"[!] Finding: {description}")

    @staticmethod
    def _file_priority(path: Path) -> int:
        name = path.name.lower()
        if name in INTERESTING_EXACT_NAMES or name in {
                ".bash_history", ".zsh_history", "consolehost_history.txt",
                "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}:
            return 0
        if INTERESTING_NAME_RE.search(name):
            return 1
        if path.suffix.lower() in TEXT_SUFFIXES or path.suffix.lower() in {".kdbx", ".rdg", ".pfx", ".p12"}:
            return 2
        return 3

    @staticmethod
    def _is_candidate(path: Path) -> bool:
        name = path.name.lower()
        return (name in INTERESTING_EXACT_NAMES
                or bool(INTERESTING_NAME_RE.search(name))
                or path.suffix.lower() in TEXT_SUFFIXES
                or path.suffix.lower() in {".kdbx", ".rdg", ".settings", ".pfx", ".p12"})

    def walk_files(self, roots: Iterable[Path]) -> Iterable[Path]:
        seen: set[str] = set()
        buckets: dict[int, list[Path]] = {0: [], 1: [], 2: [], 3: []}
        discovery_cap = max(1, self.args.max_files) * 4
        stop = False
        for root in roots:
            try:
                root = root.expanduser()
                if not root.exists():
                    continue
                if root.is_file():
                    candidates = [root]
                else:
                    candidates = None
                if candidates is not None:
                    iterator = (("", [], [str(p)]) for p in candidates)
                else:
                    iterator = os.walk(root)
                for current, dirs, names in iterator:
                    dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
                    for name in names:
                        path = Path(name) if not current else Path(current) / name
                        try:
                            resolved = str(path.resolve())
                        except OSError:
                            resolved = str(path)
                        if resolved in seen:
                            continue
                        seen.add(resolved)
                        if resolved == self.excluded_output or not self._is_candidate(path):
                            continue
                        self.candidate_files_seen += 1
                        buckets[self._file_priority(path)].append(path)
                        if self.candidate_files_seen >= discovery_cap:
                            stop = True
                            break
                    if stop:
                        break
                if stop:
                    break
            except OSError:
                self.file_errors += 1
                continue
        selected = [path for priority in range(4) for path in buckets[priority]][:max(1, self.args.max_files)]
        self.file_limit_reached = self.candidate_files_seen > len(selected) or stop
        for path in selected:
            self.files_examined += 1
            yield path


def _default_search_roots(extra: list[str], include_defaults: bool = True) -> list[Path]:
    roots = [Path(value) for value in extra]
    if not include_defaults:
        return roots
    if os.name == "nt":
        roots.extend(Path(value) for value in (
            os.environ.get("USERPROFILE", ""),
            os.environ.get("PROGRAMDATA", ""),
            os.environ.get("APPDATA", ""),
            os.environ.get("LOCALAPPDATA", ""),
            os.path.join(os.environ.get("SystemDrive", "C:"), "inetpub", "wwwroot"),
        ) if value)
    else:
        roots.extend([Path("/home"), Path("/opt"), Path("/srv"), Path("/var/www")])
    return roots


def _credential_search(collector: Collector, roots: list[Path]) -> None:
    started = time.monotonic()
    starting_count = collector.files_examined
    collector.progress("[>] Check: bounded credential, key, history, and configuration search")
    for path in collector.walk_files(roots):
        try:
            lower_name = path.name.lower()
            is_history = lower_name in {".bash_history", ".zsh_history", "consolehost_history.txt"}
            is_key = lower_name in {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}
            is_credential_artifact = path.suffix.lower() in {".kdbx", ".rdg", ".rdp", ".settings", ".pfx", ".p12"}
            is_config_candidate = path.suffix.lower() in {
                ".conf", ".config", ".ini", ".env", ".bak", ".old", ".save",
                ".php", ".yml", ".yaml", ".json", ".xml", ".properties",
            }
            interesting = (lower_name in INTERESTING_EXACT_NAMES or is_history or is_key or is_credential_artifact
                           or is_config_candidate or bool(INTERESTING_NAME_RE.search(lower_name)))
            if not interesting:
                continue
            if is_credential_artifact and path.suffix.lower() in {".kdbx", ".pfx", ".p12"}:
                collector.finding(
                    "credential_material_found",
                    f"Credential-store artifact found at {path}",
                    evidence={"path": str(path), "size": path.stat().st_size},
                    path=str(path),
                    material_type="credential-artifact",
                    discovery_command=f"stat {path}",
                )
                continue
            if path.stat().st_size > collector.max_file_bytes:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            collector.file_errors += 1
            continue

        if is_key or PRIVATE_KEY_RE.search(text):
            collector.finding(
                "private_key_found",
                f"Readable private key found at {path}",
                evidence=text,
                path=str(path),
                discovery_command=f"read {path}",
            )
        history_matches = _history_credential_lines(text) if is_history else []
        if is_history and history_matches:
            collector.finding(
                "credential_material_found",
                f"Credential-bearing shell/history lines found at {path}",
                evidence="\n".join(history_matches),
                path=str(path),
                material_type="history",
                confidence="medium",
                discovery_command=f"read {path}",
            )
        if is_credential_artifact:
            collector.finding(
                "credential_material_found",
                f"Credential-store/settings artifact found at {path}",
                evidence=text,
                path=str(path),
                material_type="credential-artifact",
                discovery_command=f"read {path}",
            )
        matching = _credential_lines(text)
        if matching:
            context = _credential_context("\n".join(matching) + "\n" + text[:5000])
            collector.finding(
                "credential_material_found",
                f"Credential-like material found in {path}",
                evidence="\n".join(matching),
                path=str(path),
                material_type="file-content",
                discovery_command=f"read {path}",
                **context,
            )
    examined = collector.files_examined - starting_count
    collector.progress(
        f"    [complete] bounded credential search: {examined} file(s) examined "
        f"from {collector.candidate_files_seen} candidate(s) "
        f"({time.monotonic() - started:.3f}s)"
    )


def _git_secret_lines(text: str) -> list[str]:
    patterns = (
        SECRET_LINE_RE,
        re.compile(r"https?://[^/\s:@]+:[^@\s/]+@", re.I),
        re.compile(r"\b(?:gh[opusr]_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,})\b"),
    )
    return [line for line in text.splitlines() if any(pattern.search(line) for pattern in patterns)]


def _git_metadata_dir(repository: Path) -> Path | None:
    marker = repository / ".git"
    if marker.is_dir():
        return marker
    if marker.is_file():
        try:
            match = re.match(r"gitdir:\s*(.+)", marker.read_text(encoding="utf-8", errors="replace").strip(), re.I)
            if match:
                value = Path(match.group(1))
                return value if value.is_absolute() else (repository / value).resolve()
        except OSError:
            return None
    if repository.name.lower().endswith(".git") and (repository / "HEAD").is_file():
        return repository
    return None


def _discover_git_repositories(roots: list[Path], limit: int) -> list[tuple[Path, Path]]:
    repositories: list[tuple[Path, Path]] = []
    seen: set[str] = set()
    for root in roots:
        try:
            root = root.expanduser()
            if not root.exists() or not root.is_dir():
                continue
            direct_metadata = _git_metadata_dir(root)
            if direct_metadata:
                key = str(root.resolve())
                seen.add(key)
                repositories.append((root, direct_metadata))
            for current, dirs, _ in os.walk(root):
                current_path = Path(current)
                current_metadata = _git_metadata_dir(current_path)
                if current_metadata:
                    key = str(current_path.resolve())
                    if key not in seen:
                        seen.add(key)
                        repositories.append((current_path, current_metadata))
                if ".git" in dirs:
                    dirs.remove(".git")
                dirs[:] = [directory for directory in dirs if directory not in SKIP_DIRS]
                if len(repositories) >= limit:
                    return repositories
        except OSError:
            continue
    return repositories


def _git_loot_search(collector: Collector, roots: list[Path]) -> None:
    started = time.monotonic()
    collector.progress("[>] Check: targeted Git repository loot search")
    repositories = _discover_git_repositories(roots, max(1, collector.args.max_git_repos))
    for repository, metadata in repositories:
        collector.progress(f"    [repo] {repository}")
        metadata_files = [
            metadata / "config",
            metadata / "HEAD",
            metadata / "packed-refs",
            metadata / "logs" / "HEAD",
        ]
        for subtree in (metadata / "refs", metadata / "logs" / "refs"):
            try:
                metadata_files.extend(path for path in subtree.rglob("*") if path.is_file())
            except OSError:
                pass
        for metadata_file in metadata_files[:200]:
            record = collector.file_check("Git metadata", metadata_file)
            if not record:
                continue
            secret_lines = _git_secret_lines(record.get("content", ""))
            if secret_lines:
                collector.finding(
                    "credential_material_found",
                    f"Credential-like material found in Git metadata at {metadata_file}",
                    evidence="\n".join(secret_lines),
                    path=str(metadata_file),
                    material_type="git-metadata",
                    discovery_command=f"read {metadata_file}",
                )

        git_checks = [
            ("remotes", ["git", "-C", str(repository), "remote", "-v"]),
            ("configuration", ["git", "-C", str(repository), "config", "--list", "--show-origin"]),
            ("history", ["git", "-C", str(repository), "log", "--all", "--oneline", "-n", "100"]),
            ("stashes", ["git", "-C", str(repository), "stash", "list"]),
            ("secret-bearing diffs", [
                "git", "-C", str(repository), "log", "--all", "-p", "-n", "100", "--",
                ".env", "*.env", "*config*", "*settings*", "*secret*", "*credential*",
                "*.ini", "*.conf", "*.properties", "*.yml", "*.yaml", "*.json", "*.xml",
            ]),
        ]
        stash_refs: list[str] = []
        for kind, argv in git_checks:
            result = collector.command(f"Git {kind}: {repository}", argv)
            if kind == "stashes":
                stash_refs = re.findall(r"^stash@\{\d+\}", result.get("stdout", ""), re.M)[:20]
            secret_lines = _git_secret_lines(result.get("stdout", ""))
            if secret_lines:
                collector.finding(
                    "credential_material_found",
                    f"Credential-like material found in Git {kind} for {repository}",
                    evidence="\n".join(secret_lines),
                    path=str(repository),
                    material_type=f"git-{kind}",
                    discovery_command=result.get("command"),
                )
        for stash_ref in stash_refs:
            result = collector.command(
                f"Git stash contents {stash_ref}: {repository}",
                ["git", "-C", str(repository), "stash", "show", "-p", stash_ref],
            )
            secret_lines = _git_secret_lines(result.get("stdout", ""))
            if secret_lines:
                collector.finding(
                    "credential_material_found",
                    f"Credential-like material found in {stash_ref} for {repository}",
                    evidence="\n".join(secret_lines),
                    path=str(repository),
                    material_type="git-stash-content",
                    stash=stash_ref,
                    discovery_command=result.get("command"),
                )
    collector.progress(
        f"    [complete] targeted Git loot search: {len(repositories)} repository/repositories "
        f"({time.monotonic() - started:.3f}s)"
    )


def _linux_writable(path: Path) -> bool:
    try:
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            return False
        return path.exists() and os.access(path, os.W_OK)
    except OSError:
        return False


def _linux_special_file_classification(path: Path, mode: int) -> tuple[bool, bool, str | None]:
    basename = path.name.lower()
    normalized = str(path).replace("\\", "/")
    nonstandard = not normalized.startswith(("/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/"))
    classification = "known-abusable" if basename in KNOWN_ABUSABLE_SUID_BASENAMES else "unusual"
    actionable_suid = bool(mode & stat.S_ISUID and (
        basename in KNOWN_ABUSABLE_SUID_BASENAMES
        or basename not in COMMON_SUID_BASENAMES
        or nonstandard
    ))
    actionable_sgid = bool(mode & stat.S_ISGID and (
        basename in KNOWN_ABUSABLE_SUID_BASENAMES or nonstandard
    ))
    return actionable_suid, actionable_sgid, classification if actionable_suid or actionable_sgid else None


def _dangerous_capabilities(line: str) -> list[str]:
    return sorted(cap for cap in DANGEROUS_CAPABILITIES if cap in line.lower())


def _is_privileged_windows_principal(user_id: str | None) -> bool:
    value = str(user_id or "")
    if not value:
        return False
    return bool(re.search(
        r"(?i)(?:^|\\)(?:SYSTEM|LOCAL SERVICE|NETWORK SERVICE|Administrator|Administrators)$"
        r"|^S-1-5-(?:18|19|20)$|^S-1-5-32-544$",
        value.strip(),
    ))


def _extract_windows_script_paths(action_text: str) -> list[str]:
    return list(dict.fromkeys(
        path.strip()
        for path in re.findall(r"[A-Za-z]:\\[^\"'\r\n]+?\.(?:ps1|bat|cmd|vbs|js|py)", action_text, re.I)
    ))


def _extract_absolute_paths(text: str) -> list[Path]:
    values = []
    for token in re.findall(r"/(?:[^\s'\";|&,)}]+)", text or ""):
        value = Path(token.rstrip(",)]}"))
        if value not in values:
            values.append(value)
    return values


def _linux_path_and_process_checks(collector: Collector, identity: str) -> None:
    groups = set(re.findall(r"\d+\(([^)]+)\)", identity or ""))
    for group in sorted(groups.intersection(DANGEROUS_GROUPS) - {"lxd", "lxc"}):
        collector.finding(
            "dangerous_group_membership",
            f"Current user belongs to potentially privileged group: {group}",
            evidence=identity,
            group=group,
            discovery_command="id",
        )

    writable_path_dirs = []
    for value in os.environ.get("PATH", "").split(os.pathsep):
        path = Path(value or ".")
        if path.is_absolute() and _linux_writable(path):
            writable_path_dirs.append(str(path))
    for path in dict.fromkeys(writable_path_dirs):
        collector.finding(
            "writable_path_directory",
            f"Current user can write to PATH directory: {path}",
            evidence={"path": path, "path_value": os.environ.get("PATH", "")},
            path=path,
            confidence="medium",
            discovery_command=f"inspect permissions {path}",
        )

    proc_root = Path("/proc")
    if not proc_root.is_dir():
        return
    inspected = 0
    for proc_dir in proc_root.iterdir():
        if not proc_dir.name.isdigit() or inspected >= 512:
            continue
        inspected += 1
        try:
            if proc_dir.stat().st_uid != 0:
                continue
            command = (proc_dir / "cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", "replace").strip()
            executable = (proc_dir / "exe").resolve()
        except OSError:
            continue
        candidates = [executable] + [p for p in _extract_absolute_paths(command) if p.exists()]
        for candidate in candidates:
            if _linux_writable(candidate):
                collector.finding(
                    "privileged_process_writable_component",
                    f"Root process {proc_dir.name} uses writable component: {candidate}",
                    evidence={"pid": int(proc_dir.name), "command": command, "component": str(candidate)},
                    path=str(candidate),
                    pid=int(proc_dir.name),
                    discovery_command=f"inspect /proc/{proc_dir.name}/cmdline and permissions {candidate}",
                )
        if command:
            first = command.split()[0]
            if not first.startswith("/") and writable_path_dirs and not first.startswith("["):
                collector.finding(
                    "privileged_relative_path_execution",
                    f"Root process uses relative command with writable PATH entries: {first}",
                    evidence={"pid": int(proc_dir.name), "command": command,
                              "writable_path_directories": writable_path_dirs},
                    command_name=first,
                    confidence="medium",
                    discovery_command=f"read /proc/{proc_dir.name}/cmdline",
                )
        try:
            environment = (proc_dir / "environ").read_bytes().split(b"\0")
        except OSError:
            environment = []
        for raw in environment:
            decoded = raw.decode("utf-8", "replace")
            if not decoded.startswith(("LD_PRELOAD=", "LD_LIBRARY_PATH=", "PYTHONPATH=")):
                continue
            name, _, value = decoded.partition("=")
            paths = [Path(part) for part in value.split(os.pathsep) if part]
            writable = [str(path) for path in paths if _linux_writable(path)]
            if writable:
                collector.finding(
                    "privileged_environment_hijack",
                    f"Root process {proc_dir.name} uses {name} with writable component(s)",
                    evidence={"pid": int(proc_dir.name), "command": command,
                              "variable": name, "value": value, "writable_paths": writable},
                    paths=writable, variable=name, pid=int(proc_dir.name),
                    discovery_command=f"read /proc/{proc_dir.name}/environ and inspect path permissions",
                )


def _linux_systemd_checks(collector: Collector) -> None:
    unit_dirs = (Path("/etc/systemd/system"), Path("/usr/local/lib/systemd/system"), Path("/lib/systemd/system"))
    seen: set[str] = set()
    for directory in unit_dirs:
        try:
            units = [p for p in directory.rglob("*") if p.is_file() and p.suffix in {".service", ".timer", ".path"}]
        except OSError:
            continue
        for unit in units[:1000]:
            try:
                resolved = str(unit.resolve())
                if resolved in seen or unit.stat().st_size > collector.max_file_bytes:
                    continue
                seen.add(resolved)
                text = unit.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            writable = _linux_writable(unit)
            referenced = []
            for line in text.splitlines():
                if re.match(r"\s*(?:ExecStart|ExecStartPre|ExecStartPost|EnvironmentFile)\s*=", line):
                    referenced.extend(_extract_absolute_paths(line))
            writable_refs = [str(path) for path in referenced if _linux_writable(path)]
            if writable or writable_refs:
                collector.finding(
                    "writable_systemd_execution_chain",
                    f"Systemd unit has writable execution/configuration component: {unit}",
                    evidence={"unit": text, "writable_unit": writable,
                              "writable_references": writable_refs},
                    path=str(unit),
                    writable_references=writable_refs,
                    discovery_command=f"read {unit} and inspect referenced paths",
                )


def _linux_logrotate_and_library_checks(collector: Collector) -> None:
    candidates = [Path("/etc/logrotate.conf")]
    try:
        candidates.extend(p for p in Path("/etc/logrotate.d").iterdir() if p.is_file())
    except OSError:
        pass
    for path in candidates:
        if _linux_writable(path):
            collector.finding(
                "writable_logrotate_configuration",
                f"Logrotate configuration is writable: {path}",
                evidence=str(path), path=str(path),
                discovery_command=f"inspect permissions {path}",
            )

    preload = Path("/etc/ld.so.preload")
    if _linux_writable(preload):
        collector.finding(
            "writable_dynamic_loader_configuration",
            f"Dynamic loader preload configuration is writable: {preload}",
            evidence=str(preload), path=str(preload),
            discovery_command=f"inspect permissions {preload}",
        )
    conf_dir = Path("/etc/ld.so.conf.d")
    try:
        for path in conf_dir.iterdir():
            if path.is_file() and _linux_writable(path):
                collector.finding(
                    "writable_dynamic_loader_configuration",
                    f"Dynamic loader search configuration is writable: {path}",
                    evidence=str(path), path=str(path),
                    discovery_command=f"inspect permissions {path}",
                )
    except OSError:
        pass


def _linux_mount_checks(collector: Collector) -> None:
    for source in (Path("/etc/fstab"), Path("/proc/mounts")):
        try:
            text = source.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            if re.search(r"\bcredentials=|\buser(?:s)?\b|\bsuid\b|\bexec\b", line, re.I):
                credential_files = [p for p in _extract_absolute_paths(line) if "credential" in p.name.lower()]
                collector.finding(
                    "interesting_mount_configuration",
                    f"Potentially useful mount configuration in {source}: {line[:180]}",
                    evidence=line,
                    path=str(source),
                    credential_files=[str(p) for p in credential_files],
                    confidence="medium",
                    discovery_command=f"read {source}",
                )
                for credential_file in credential_files:
                    try:
                        if credential_file.stat().st_size > collector.max_file_bytes:
                            continue
                        content = credential_file.read_text(encoding="utf-8", errors="replace")
                    except OSError:
                        continue
                    collector.finding(
                        "credential_material_found",
                        f"Readable mount credential file: {credential_file}",
                        evidence=content, path=str(credential_file), material_type="mount-credentials",
                        discovery_command=f"read {credential_file}",
                        **_credential_context(content),
                    )


def _linux_collect(collector: Collector, roots: list[Path]) -> None:
    inventory_commands = [
        ("identity", ["id"]),
        ("kernel", ["uname", "-a"]),
        ("architecture", ["uname", "-m"]),
        ("interfaces", ["ip", "address"]),
        ("routes", ["ip", "route"]),
        ("listening sockets", ["ss", "-anp"]),
        ("root processes", ["ps", "-eo", "user,pid,args"]),
        ("kernel modules", ["lsmod"]),
        ("systemd timers", ["systemctl", "list-timers", "--all", "--no-pager"]),
        ("Debian packages", ["dpkg", "-l"]),
        ("RPM packages", ["rpm", "-qa"]),
    ]
    for label, argv in inventory_commands:
        collector.command(label, argv)
    collector.checks.append({"label": "environment", "values": dict(os.environ)})
    for path in (Path("/etc/os-release"), Path("/etc/issue"), Path("/proc/version"),
                 Path("/etc/passwd"), Path("/etc/fstab"), Path("/etc/exports"),
                 Path("/etc/crontab")):
        collector.file_check(path.name, path)

    sudo = collector.command("sudo privileges", ["sudo", "-n", "-l"])
    sudo_text = f"{sudo.get('stdout', '')}\n{sudo.get('stderr', '')}".strip()
    if sudo_text and "NOPASSWD" in sudo_text:
        collector.finding("sudo_nopasswd_privileges", "Potentially abusable sudo rule found",
                          evidence=sudo_text, description_raw=sudo_text)
    elif sudo.get("returncode") == 0 and re.search(r"(?m)^\s*\([^\n]+\)\s+", sudo_text):
        collector.finding(
            "sudo_allowed_commands", "Sudo permits one or more commands for the current user",
            evidence=sudo_text, discovery_command=sudo.get("command"), confidence="medium",
        )

    suid = collector.command(
        "SUID and SGID files",
        ["find", "/", "-type", "f", "(", "-perm", "-4000", "-o", "-perm", "-2000", ")", "-print"],
        timeout=max(collector.args.command_timeout, 90),
    )
    for value in suid.get("stdout", "").splitlines():
        path = Path(value.strip())
        if not value.strip():
            continue
        try:
            mode = path.stat().st_mode
        except OSError:
            mode = 0
        actionable_suid, actionable_sgid, classification = _linux_special_file_classification(path, mode)
        if actionable_suid:
            collector.finding(
                "suid_binary_found", f"Actionable or unusual SUID binary: {path}",
                evidence=str(path), path=str(path),
                classification=classification,
                discovery_command=suid.get("command"),
            )
        if actionable_sgid:
            collector.finding(
                "sgid_binary_found", f"Actionable or unusual SGID binary: {path}", evidence=str(path),
                path=str(path), confidence="medium",
                classification=classification,
                discovery_command=suid.get("command"),
            )

    caps = collector.command("file capabilities", ["getcap", "-r", "/"], timeout=max(collector.args.command_timeout, 90))
    for line in caps.get("stdout", "").splitlines():
        capability_names = _dangerous_capabilities(line)
        if "=" in line and capability_names:
            collector.finding(
                "process_capabilities_found", f"Dangerous Linux file capability: {line}",
                evidence=line, capabilities=capability_names, discovery_command=caps.get("command"),
            )

    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    for sensitive in (Path("/etc/passwd"), Path("/etc/shadow")):
        if not is_root and sensitive.exists() and os.access(sensitive, os.W_OK):
            collector.finding("writable_sensitive_file_etc_passwd_shadow",
                              f"Sensitive account file is writable: {sensitive}", evidence=str(sensitive), path=str(sensitive))
    if not is_root and Path("/etc/shadow").is_file() and os.access(Path("/etc/shadow"), os.R_OK):
        shadow = collector.file_check("readable shadow", Path("/etc/shadow"))
        if shadow:
            collector.finding("readable_shadow_file", "The current user can read /etc/shadow",
                              evidence=shadow.get("content"), path="/etc/shadow")

    cron_paths = [Path("/etc/crontab")]
    for directory in (Path("/etc/cron.d"), Path("/var/spool/cron"), Path("/var/spool/cron/crontabs")):
        try:
            cron_paths.extend(path for path in directory.iterdir() if path.is_file())
        except OSError:
            pass
    for cron_path in cron_paths:
        record = collector.file_check("cron configuration", cron_path)
        if not record:
            continue
        if _linux_writable(cron_path):
            collector.finding("writable_cron_job", f"Cron configuration is writable: {cron_path}",
                              evidence=record.get("content"), path=str(cron_path))
        cron_content = record.get("content", "")
        for target in _extract_absolute_paths(cron_content):
            if target.exists() and _linux_writable(target):
                collector.finding("writable_cron_job", f"Cron-referenced path is writable: {target}",
                                  evidence=cron_content, path=str(target), cron_file=str(cron_path),
                                  discovery_command=f"read {cron_path} and inspect permissions {target}")
        directory_match = re.search(r"\bcd\s+(/\S+)", cron_content)
        if re.search(r"\btar\b[^\n]*\*", cron_content) and directory_match:
            directory = Path(directory_match.group(1).rstrip(";&"))
            if _linux_writable(directory):
                collector.finding(
                    "cron_wildcard_injection_candidate",
                    f"Privileged cron tar wildcard runs in writable directory: {directory}",
                    evidence=cron_content, path=str(directory), cron_file=str(cron_path),
                    discovery_command=f"read {cron_path} and inspect permissions {directory}",
                )
        cron_path_match = re.search(r"(?m)^\s*PATH\s*=\s*([^\n]+)", cron_content)
        if cron_path_match:
            writable_cron_path = [value for value in cron_path_match.group(1).split(":")
                                  if value and _linux_writable(Path(value))]
            relative_jobs = []
            for line in cron_content.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#") or "=" in stripped.split()[0]:
                    continue
                if re.search(r"(?:^|\s)(?:root\s+)?[A-Za-z0-9_.-]+(?:\s|$)", stripped) and not re.search(
                        r"(?:^|\s)/(?:\S+)", stripped):
                    relative_jobs.append(stripped)
            if writable_cron_path and relative_jobs:
                collector.finding(
                    "cron_path_hijack_candidate",
                    f"Cron uses relative commands with writable PATH entries: {cron_path}",
                    evidence={"jobs": relative_jobs, "writable_path_directories": writable_cron_path},
                    path=str(cron_path), writable_path_directories=writable_cron_path,
                    discovery_command=f"read {cron_path} and inspect cron PATH permissions",
                )

    docker_socket = Path("/var/run/docker.sock")
    if docker_socket.exists() and _linux_writable(docker_socket):
        collector.finding("writable_docker_socket", "Docker socket is writable",
                          evidence=str(docker_socket), path=str(docker_socket))
    identity = next((c.get("stdout", "") for c in collector.checks if c.get("label") == "identity"), "")
    if re.search(r"\b(lxd|lxc)\b", identity):
        collector.finding("lxd_privilege_escalation_possible", "Current user belongs to the LXD/LXC group",
                          evidence=identity)
    exports = next((c.get("content", "") for c in collector.checks if c.get("path") == "/etc/exports"), "")
    if "no_root_squash" in exports:
        collector.finding("nfs_no_root_squash", "NFS export uses no_root_squash", evidence=exports)
    _linux_path_and_process_checks(collector, identity)
    _linux_systemd_checks(collector)
    _linux_logrotate_and_library_checks(collector)
    _linux_mount_checks(collector)
    collector.command(
        "world-writable directories",
        ["find", "/", "-type", "d", "-perm", "-0002", "-print"],
        timeout=max(collector.args.command_timeout, 90),
    )
    _git_loot_search(collector, roots)
    _credential_search(collector, roots)


def _powershell(collector: Collector, label: str, script: str, timeout: int | None = None) -> dict[str, Any]:
    return collector.command(label, ["powershell.exe", "-NoProfile", "-NonInteractive",
                                     "-ExecutionPolicy", "Bypass", "-Command", script], timeout=timeout)


def _extract_windows_executable(command_line: str) -> str | None:
    command_line = (command_line or "").strip()
    if not command_line:
        return None
    if command_line.startswith('"'):
        match = re.match(r'^"([^\"]+\.exe)"', command_line, re.I)
    else:
        match = re.match(r'^(.+?\.exe)(?:\s|$)', command_line, re.I)
    return os.path.expandvars(match.group(1)) if match else None


def _windows_writable(path_value: str | None) -> bool:
    if not path_value:
        return False
    path = Path(path_value)
    # Relative service/task actions are resolved by Windows using execution-
    # context-specific rules.  Treating them as relative to the collector's
    # current directory creates false writable-binary findings.
    if not path.is_absolute():
        return False
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        create_file = kernel32.CreateFileW
        create_file.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
            wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
        ]
        create_file.restype = wintypes.HANDLE
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = [wintypes.HANDLE]
        close_handle.restype = wintypes.BOOL

        target = path if path.exists() else path.parent
        if not target.exists():
            return False
        flags = 0x02000000 if target.is_dir() else 0  # FILE_FLAG_BACKUP_SEMANTICS
        handle = create_file(
            str(target),
            0x40000000,  # GENERIC_WRITE; requests access but performs no write
            0x00000001 | 0x00000002 | 0x00000004,
            None,
            3,  # OPEN_EXISTING
            flags,
            None,
        )
        invalid_handle = ctypes.c_void_p(-1).value
        if handle in (None, invalid_handle):
            return False
        close_handle(handle)
        return True
    except OSError:
        return False


def _windows_readable(path_value: str | None) -> bool:
    if not path_value:
        return False
    path = Path(path_value)
    try:
        if not path.is_absolute() or not path.is_file():
            return False
        with path.open("rb") as handle:
            handle.read(1)
        return True
    except (OSError, PermissionError):
        return False


def _windows_service_changeable(service_name: str | None) -> bool:
    """Request SERVICE_CHANGE_CONFIG access without modifying the service."""
    if os.name != "nt" or not service_name:
        return False
    try:
        import ctypes
        from ctypes import wintypes

        advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        open_manager = advapi32.OpenSCManagerW
        open_manager.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
        open_manager.restype = wintypes.HANDLE
        open_service = advapi32.OpenServiceW
        open_service.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.DWORD]
        open_service.restype = wintypes.HANDLE
        close = advapi32.CloseServiceHandle
        close.argtypes = [wintypes.HANDLE]
        close.restype = wintypes.BOOL

        manager = open_manager(None, None, 0x0001)  # SC_MANAGER_CONNECT
        if not manager:
            return False
        try:
            service = open_service(manager, service_name, 0x0002)  # SERVICE_CHANGE_CONFIG
            if not service:
                return False
            close(service)
            return True
        finally:
            close(manager)
    except OSError:
        return False


def _windows_targeted_credential_checks(collector: Collector) -> None:
    system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    system_drive = os.environ.get("SystemDrive", "C:")
    candidates = [
        system_root / "Panther/Unattend.xml",
        system_root / "Panther/Unattended.xml",
        system_root / "Panther/Unattend/Unattend.xml",
        system_root / "System32/Sysprep/Unattend.xml",
        Path(system_drive + r"\unattend.xml"),
        Path(system_drive + r"\autounattend.xml"),
        system_root / "System32/inetsrv/config/applicationHost.config",
        Path(system_drive + r"\inetpub\wwwroot\web.config"),
    ]
    for path in candidates:
        record = collector.file_check("targeted deployment credential file", path)
        if not record:
            continue
        if "unattend" in path.name.lower() or "sysprep" in path.name.lower():
            collector.finding(
                "unattended_install_file_found", f"Readable unattended-installation file: {path}",
                evidence=record.get("content"), path=str(path), discovery_command=f"read {path}",
                confidence="medium",
            )
        matching = _credential_lines(record.get("content", ""))
        if matching:
            context = _credential_context(record.get("content", ""))
            collector.finding(
                "credential_material_found", f"Credential-like material found in {path}",
                evidence="\n".join(matching), path=str(path), material_type="deployment-config",
                discovery_command=f"read {path}",
                **context,
            )

    config_dir = system_root / "System32/config"
    hive_candidates = [config_dir / name for name in ("SAM", "SYSTEM", "SECURITY")]
    hive_candidates.extend(config_dir / "RegBack" / name for name in ("SAM", "SYSTEM", "SECURITY"))
    readable = [str(path) for path in hive_candidates if _windows_readable(str(path))]
    if len(readable) >= 2:
        collector.finding(
            "readable_windows_registry_hives",
            "Sensitive Windows registry hive files are readable",
            evidence=readable, paths=readable,
            discovery_command="inspect read access to SAM SYSTEM SECURITY hives",
        )


def _windows_path_checks(collector: Collector) -> None:
    machine_path = _powershell(
        collector, "machine PATH", "[Environment]::GetEnvironmentVariable('Path','Machine')"
    )
    for value in machine_path.get("stdout", "").strip().split(";"):
        expanded = os.path.expandvars(value.strip())
        if expanded and _windows_writable(expanded):
            collector.finding(
                "writable_machine_path_directory",
                f"Machine PATH directory is writable: {expanded}",
                evidence=machine_path.get("stdout"), path=expanded, confidence="medium",
                discovery_command=machine_path.get("command"),
            )


def _json_records(output: str) -> list[dict[str, Any]]:
    try:
        value = json.loads(output)
    except (json.JSONDecodeError, TypeError):
        return []
    if isinstance(value, dict):
        return [value]
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _windows_collect(collector: Collector, roots: list[Path]) -> None:
    commands = [
        ("identity", ["whoami.exe", "/all"]),
        ("token privileges", ["whoami.exe", "/priv"]),
        ("system information", ["systeminfo.exe"]),
        ("network configuration", ["ipconfig.exe", "/all"]),
        ("routes", ["route.exe", "print"]),
        ("listening sockets", ["netstat.exe", "-ano"]),
        ("processes", ["tasklist.exe", "/v"]),
        ("local users", ["net.exe", "user"]),
        ("local administrators", ["net.exe", "localgroup", "Administrators"]),
        ("stored credentials", ["cmdkey.exe", "/list"]),
        ("scheduled tasks raw", ["schtasks.exe", "/query", "/fo", "LIST", "/v"]),
    ]
    records = {label: collector.command(label, argv, timeout=max(collector.args.command_timeout, 60))
               for label, argv in commands}
    collector.checks.append({"label": "environment", "values": dict(os.environ)})
    _powershell(
        collector,
        "installed software",
        "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
        "'HKLM:\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' "
        "-ErrorAction SilentlyContinue | Select-Object DisplayName,DisplayVersion,Publisher,InstallLocation | "
        "ConvertTo-Json -Compress",
        timeout=max(collector.args.command_timeout, 60),
    )

    privilege_text = records["token privileges"].get("stdout", "")
    token_names = {
        "SeImpersonatePrivilege": "seimpersonateprivilege_enabled",
        "SeAssignPrimaryTokenPrivilege": "seassignprimarytokenprivilege_enabled",
        "SeDebugPrivilege": "sedebugprivilege_enabled",
        "SeBackupPrivilege": "sebackupprivilege_enabled",
        "SeRestorePrivilege": "serestoreprivilege_enabled",
        "SeTakeOwnershipPrivilege": "setakeownershipprivilege_enabled",
        "SeLoadDriverPrivilege": "seloaddriverprivilege_enabled",
    }
    for privilege, name in token_names.items():
        line = next((line for line in privilege_text.splitlines()
                     if privilege.lower() in line.lower() and "enabled" in line.lower()), None)
        if line:
            collector.finding(name, f"Enabled Windows token privilege: {privilege}", evidence=line,
                              privilege=privilege)

    cmdkey = records["stored credentials"].get("stdout", "")
    if re.search(r"Target:|User:", cmdkey, re.I):
        collector.finding("stored_credentials_credman", "Windows Credential Manager contains stored credentials",
                          evidence=cmdkey)

    installer_values: dict[str, str] = {}
    for hive in ("HKLM", "HKCU"):
        key = rf"{hive}\SOFTWARE\Policies\Microsoft\Windows\Installer"
        result = collector.command(f"{hive} AlwaysInstallElevated", ["reg.exe", "query", key, "/v", "AlwaysInstallElevated"])
        installer_values[hive] = result.get("stdout", "")
    if all(re.search(r"AlwaysInstallElevated\s+REG_DWORD\s+0x1", installer_values[hive], re.I)
           for hive in ("HKLM", "HKCU")):
        collector.finding("alwaysinstallelevated_registry_key",
                          "AlwaysInstallElevated is enabled in both HKLM and HKCU",
                          evidence=installer_values)

    autologon_key = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    autologon = collector.command("Windows AutoLogon configuration", ["reg.exe", "query", autologon_key])
    autologon_lines = [line for line in autologon.get("stdout", "").splitlines()
                       if re.search(r"Default(?:UserName|DomainName|Password)\s+REG_", line, re.I)]
    if any(re.search(r"DefaultPassword\s+REG_\w+\s+\S+", line, re.I) for line in autologon_lines):
        collector.finding(
            "credential_material_found", "Windows AutoLogon credentials are configured",
            evidence="\n".join(autologon_lines), path=autologon_key,
            material_type="registry-autologon", discovery_command=autologon.get("command"),
        )

    for hive in ("HKLM", "HKCU"):
        result = collector.command(f"{hive} registry password search",
                                   ["reg.exe", "query", hive, "/f", "password", "/t", "REG_SZ", "/d", "/s"],
                                   timeout=collector.args.command_timeout)
        output = result.get("stdout", "")
        # Keep the complete command output as a raw check, but only promote
        # registry lines that resemble an actual secret-bearing value. Broad
        # keyword matches include thousands of benign class descriptions.
        secret_lines = [
            line for line in output.splitlines()
            if re.search(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key)\b\s+REG_\w+\s+\S+", line)
        ]
        if secret_lines:
            collector.finding("credential_material_found", f"Credential-like registry values found in {hive}",
                              evidence="\n".join(secret_lines), material_type="registry", path=hive,
                              confidence="medium")

    service_script = (
        "Get-CimInstance Win32_Service | Select-Object Name,State,StartName,PathName | "
        "ConvertTo-Json -Compress"
    )
    services = _powershell(collector, "services", service_script, timeout=max(collector.args.command_timeout, 60))
    for service in _json_records(services.get("stdout", "")):
        path_name = str(service.get("PathName") or "")
        executable = _extract_windows_executable(path_name)
        start_name = str(service.get("StartName") or "")
        privileged_service = bool(re.search(r"LocalSystem|NT AUTHORITY\\(?:SYSTEM|LocalService|NetworkService)",
                                            start_name, re.I))
        if privileged_service and _windows_service_changeable(str(service.get("Name") or "")):
            collector.finding(
                "service_change_config_allowed",
                f"Current user can change privileged service configuration: {service.get('Name')}",
                evidence=service, service=service.get("Name"), start_name=start_name,
                discovery_command=f"request SERVICE_CHANGE_CONFIG access for {service.get('Name')}",
            )
        if privileged_service and executable and _windows_writable(executable):
            collector.finding("writable_service_binary", f"Writable service binary for {service.get('Name')}: {executable}",
                              evidence=service, service=service.get("Name"), path=executable)
        if privileged_service and executable and not _windows_writable(executable) and _windows_writable(str(Path(executable).parent)):
            collector.finding(
                "writable_service_directory",
                f"Privileged service executable directory is writable: {Path(executable).parent}",
                evidence=service, service=service.get("Name"), path=str(Path(executable).parent),
                executable=executable,
                discovery_command=f"inspect service {service.get('Name')} and directory permissions",
            )
        if privileged_service and " " in path_name and not path_name.lstrip().startswith('"') and executable:
            parts = executable.split(" ")
            candidates = [" ".join(parts[:index]) + ".exe" for index in range(1, len(parts))]
            writable_candidates = [candidate for candidate in candidates if _windows_writable(candidate)]
            if writable_candidates:
                collector.finding("unquoted_service_path", f"Unquoted service path has writable candidate for {service.get('Name')}",
                                  evidence=service, service=service.get("Name"), path_name=path_name,
                                  writable_candidates=writable_candidates)

    task_script = (
        "Get-ScheduledTask | ForEach-Object { $t=$_; $_.Actions | ForEach-Object { "
        "[pscustomobject]@{TaskName=$t.TaskName;TaskPath=$t.TaskPath;UserId=$t.Principal.UserId;"
        "Execute=$_.Execute;Arguments=$_.Arguments;WorkingDirectory=$_.WorkingDirectory} } } | ConvertTo-Json -Compress"
    )
    tasks = _powershell(collector, "scheduled task actions", task_script, timeout=max(collector.args.command_timeout, 60))
    seen_task_definitions: set[str] = set()
    for task in _json_records(tasks.get("stdout", "")):
        user_id = str(task.get("UserId") or "")
        privileged_task = _is_privileged_windows_principal(user_id)
        if not privileged_task:
            continue
        executable = os.path.expandvars(str(task.get("Execute") or ""))
        if executable and _windows_writable(executable):
            collector.finding("writable_scheduled_task_binary",
                              f"Scheduled task action is writable: {task.get('TaskName')} -> {executable}",
                              evidence=task, path=executable, task=task.get("TaskName"))
        action_text = " ".join(str(task.get(key) or "") for key in ("Execute", "Arguments", "WorkingDirectory"))
        script_paths = _extract_windows_script_paths(action_text)
        writable_scripts = [os.path.expandvars(path.strip()) for path in script_paths
                            if _windows_writable(os.path.expandvars(path.strip()))]
        if writable_scripts:
            collector.finding(
                "writable_scheduled_task_script",
                f"Privileged scheduled task uses writable script: {task.get('TaskName')}",
                evidence=task, paths=writable_scripts, task=task.get("TaskName"),
                discovery_command=tasks.get("command"),
            )
        working_directory = os.path.expandvars(str(task.get("WorkingDirectory") or "").strip())
        if (working_directory and executable and not Path(executable).is_absolute()
                and _windows_writable(working_directory)):
            collector.finding(
                "writable_scheduled_task_working_directory",
                f"Privileged task resolves a relative action from writable working directory: {task.get('TaskName')}",
                evidence=task, path=working_directory, task=task.get("TaskName"),
                discovery_command=tasks.get("command"),
            )
        task_path = (Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/Tasks" /
                     str(task.get("TaskPath") or "").lstrip("\\/") / str(task.get("TaskName") or ""))
        normalized_task_path = str(task_path).lower()
        if normalized_task_path not in seen_task_definitions and _windows_writable(str(task_path)):
            seen_task_definitions.add(normalized_task_path)
            collector.finding(
                "writable_scheduled_task_definition",
                f"Privileged scheduled-task definition is writable: {task_path}",
                evidence=task, path=str(task_path), task=task.get("TaskName"),
                discovery_command=f"inspect permissions {task_path}",
            )

    autorun_keys = [
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    ]
    for key in autorun_keys:
        result = collector.command(f"autoruns {key}", ["reg.exe", "query", key])
        for line in result.get("stdout", "").splitlines():
            if "REG_" not in line:
                continue
            value = re.split(r"\s+REG_\w+\s+", line.strip(), maxsplit=1)
            executable = _extract_windows_executable(value[1] if len(value) == 2 else "")
            # HKCU autoruns are user-controlled persistence, not privilege
            # escalation. Retain them in raw checks and promote only HKLM.
            if key.startswith("HKLM") and executable and _windows_writable(executable):
                collector.finding("writable_autorun_binary", f"Writable autorun binary: {executable}",
                                  evidence=line, path=executable, registry_key=key)

    program_data = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
    startup = Path(program_data) / "Microsoft/Windows/Start Menu/Programs/StartUp"
    if startup.exists() and _windows_writable(str(startup)):
        collector.finding("writable_startup_directory", f"Windows all-users Startup directory is writable: {startup}",
                          evidence=str(startup), path=str(startup))

    history_paths = []
    users_root = Path(os.environ.get("SystemDrive", "C:")) / "Users"
    try:
        history_paths = list(users_root.glob("*/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt"))
    except OSError:
        pass
    for history in history_paths:
        record = collector.file_check("PowerShell history", history)
        history_matches = _history_credential_lines(record.get("content", "")) if record else []
        if record and history_matches:
            collector.finding("credential_material_found", f"Readable PowerShell history: {history}",
                              evidence="\n".join(history_matches), path=str(history), material_type="history",
                              confidence="medium", discovery_command=f"read {history}")
    _windows_targeted_credential_checks(collector)
    _windows_path_checks(collector)
    _git_loot_search(collector, roots)
    _credential_search(collector, roots)


def main() -> int:
    args = parse_args()
    collector = Collector(args)
    roots = _default_search_roots(args.roots, include_defaults=not args.only_specified_roots)
    collector.progress(f"[*] {TOOL_NAME} starting on {socket.gethostname()} as {getpass.getuser()}")
    collector.progress(f"[*] Sensitive-value redaction: disabled")
    if os.name == "nt":
        _windows_collect(collector, roots)
        platform_name = "windows"
    else:
        _linux_collect(collector, roots)
        platform_name = "linux"

    payload = {
        "tool": TOOL_NAME,
        "type": REPORT_TYPE,
        "schema_version": SCHEMA_VERSION,
        "host": socket.gethostname(),
        "platform": platform_name,
        "platform_detail": platform.platform(),
        "user": getpass.getuser(),
        "collected_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "command": subprocess.list2cmdline(sys.argv) if os.name == "nt" else shlex.join(sys.argv),
        "options": {
            "max_files": args.max_files,
            "max_file_kb": args.max_file_kb,
            "max_output_kb": args.max_output_kb,
            "command_timeout": args.command_timeout,
            "max_git_repos": args.max_git_repos,
            "quiet": args.quiet,
            "only_specified_roots": args.only_specified_roots,
            "sensitive_values_redacted": False,
        },
        "stats": {
            "checks_run": len(collector.checks),
            "findings": len(collector.findings),
            "files_examined": collector.files_examined,
            "candidate_files_seen": collector.candidate_files_seen,
            "file_limit_reached": collector.file_limit_reached,
            "file_errors": collector.file_errors,
        },
        "checks": collector.checks,
        "findings": collector.findings,
    }
    out = Path(args.out)
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    collector.progress(f"[+] Wrote {out} ({len(collector.findings)} findings; {len(collector.checks)} checks)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
