#!/usr/bin/env python3
"""Mini-PEAS: read-only manual privilege-escalation collector for PathFinder.

This collector automates the Linux and Windows post-foothold checks documented
in the project's PEN-200 notes. It preserves command output, credential-like
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
SCHEMA_VERSION = "1.0"
NOTE_REFERENCES = [
    "OSCP-Prep/3_LinuxPrivilegeEscalation.md",
    "OSCP-Prep/2_WindowsPrivilegeEscalation.md",
    "OSCP-Prep/Methodology.md#4-privilege-escalation",
]

SKIP_DIRS = {
    ".git", ".svn", ".hg", "node_modules", "venv", ".venv", "__pycache__",
    "proc", "sys", "dev", "run", "snap", "WindowsApps",
}
TEXT_SUFFIXES = {
    ".txt", ".log", ".ini", ".conf", ".config", ".cfg", ".xml", ".json",
    ".yaml", ".yml", ".toml", ".env", ".properties", ".ps1", ".bat",
    ".cmd", ".sh", ".py", ".php", ".bak", ".old", ".save", ".sql",
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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("roots", nargs="*", help="Additional roots for credential/config searches")
    parser.add_argument("-o", "--out", default="manual_privesc_loot.json", help="Output JSON path")
    parser.add_argument("--max-files", type=int, default=50000, help="Max files examined in bounded searches")
    parser.add_argument("--max-file-kb", type=int, default=512, help="Largest text file read")
    parser.add_argument("--max-output-kb", type=int, default=2048, help="Max captured output per command/check")
    parser.add_argument("--command-timeout", type=int, default=30, help="Per-command timeout in seconds")
    parser.add_argument("--max-git-repos", type=int, default=100, help="Max Git repositories examined")
    return parser.parse_args()


def _clip(value: str, max_bytes: int) -> tuple[str, bool]:
    encoded = value.encode("utf-8", errors="replace")
    if len(encoded) <= max_bytes:
        return value, False
    return encoded[:max_bytes].decode("utf-8", errors="replace"), True


class Collector:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.max_output_bytes = max(1, args.max_output_kb) * 1024
        self.max_file_bytes = max(1, args.max_file_kb) * 1024
        self.checks: list[dict[str, Any]] = []
        self.findings: list[dict[str, Any]] = []
        self._finding_keys: set[str] = set()
        self.files_examined = 0

    @staticmethod
    def progress(message: str) -> None:
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

    def walk_files(self, roots: Iterable[Path]) -> Iterable[Path]:
        seen: set[str] = set()
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
                        self.files_examined += 1
                        yield path
                        if self.files_examined >= self.args.max_files:
                            return
            except OSError:
                continue


def _default_search_roots(extra: list[str]) -> list[Path]:
    roots = [Path(value) for value in extra]
    if os.name == "nt":
        roots.extend(Path(value) for value in (
            os.environ.get("USERPROFILE", ""),
            os.environ.get("PROGRAMDATA", ""),
            os.environ.get("APPDATA", ""),
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
            is_credential_artifact = path.suffix.lower() in {".kdbx", ".rdg", ".settings"}
            is_config_candidate = path.suffix.lower() in {
                ".conf", ".config", ".ini", ".env", ".bak", ".old", ".save",
                ".php", ".yml", ".yaml", ".json", ".xml", ".properties",
            }
            interesting = (is_history or is_key or is_credential_artifact
                           or is_config_candidate or bool(INTERESTING_NAME_RE.search(lower_name)))
            if not interesting or path.stat().st_size > collector.max_file_bytes:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        if is_key or PRIVATE_KEY_RE.search(text):
            collector.finding(
                "private_key_found",
                f"Readable private key found at {path}",
                evidence=text,
                path=str(path),
            )
        if is_history:
            collector.finding(
                "credential_material_found",
                f"Readable shell/history file found at {path}",
                evidence=text,
                path=str(path),
                material_type="history",
                confidence="medium",
            )
        if is_credential_artifact:
            collector.finding(
                "credential_material_found",
                f"Credential-store/settings artifact found at {path}",
                evidence=text,
                path=str(path),
                material_type="credential-artifact",
            )
        matching = [line for line in text.splitlines() if SECRET_LINE_RE.search(line)]
        if matching:
            collector.finding(
                "credential_material_found",
                f"Credential-like material found in {path}",
                evidence="\n".join(matching),
                path=str(path),
                material_type="file-content",
            )
    examined = collector.files_examined - starting_count
    collector.progress(
        f"    [complete] bounded credential search: {examined} file(s) examined "
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


def _linux_collect(collector: Collector, roots: list[Path]) -> None:
    inventory_commands = [
        ("identity", ["id"]),
        ("kernel", ["uname", "-a"]),
        ("architecture", ["uname", "-m"]),
        ("interfaces", ["ip", "address"]),
        ("routes", ["ip", "route"]),
        ("listening sockets", ["ss", "-anp"]),
        ("root processes", ["ps", "aux"]),
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
        if mode & stat.S_ISUID:
            collector.finding("suid_binary_found", f"SUID binary: {path}", evidence=str(path), path=str(path))
        if mode & stat.S_ISGID:
            collector.finding("sgid_binary_found", f"SGID binary: {path}", evidence=str(path),
                              path=str(path), confidence="medium")

    caps = collector.command("file capabilities", ["getcap", "-r", "/"], timeout=max(collector.args.command_timeout, 90))
    for line in caps.get("stdout", "").splitlines():
        if "=" in line:
            collector.finding("process_capabilities_found", f"Linux file capability: {line}", evidence=line)

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
        if os.access(cron_path, os.W_OK):
            collector.finding("writable_cron_job", f"Cron configuration is writable: {cron_path}",
                              evidence=record.get("content"), path=str(cron_path))
        for token in re.findall(r"/(?:[^\s'\";|&]+)", record.get("content", "")):
            target = Path(token.rstrip(",)"))
            if target.exists() and os.access(target, os.W_OK):
                collector.finding("writable_cron_job", f"Cron-referenced path is writable: {target}",
                                  evidence=record.get("content"), path=str(target), cron_file=str(cron_path))

    docker_socket = Path("/var/run/docker.sock")
    if docker_socket.exists() and os.access(docker_socket, os.W_OK):
        collector.finding("writable_docker_socket", "Docker socket is writable",
                          evidence=str(docker_socket), path=str(docker_socket))
    identity = next((c.get("stdout", "") for c in collector.checks if c.get("label") == "identity"), "")
    if re.search(r"\b(lxd|lxc)\b", identity):
        collector.finding("lxd_privilege_escalation_possible", "Current user belongs to the LXD/LXC group",
                          evidence=identity)
    exports = next((c.get("content", "") for c in collector.checks if c.get("path") == "/etc/exports"), "")
    if "no_root_squash" in exports:
        collector.finding("nfs_no_root_squash", "NFS export uses no_root_squash", evidence=exports)
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
        if executable and _windows_writable(executable):
            collector.finding("writable_service_binary", f"Writable service binary for {service.get('Name')}: {executable}",
                              evidence=service, service=service.get("Name"), path=executable)
        if " " in path_name and not path_name.lstrip().startswith('"') and executable:
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
        "Execute=$_.Execute;Arguments=$_.Arguments} } } | ConvertTo-Json -Compress"
    )
    tasks = _powershell(collector, "scheduled task actions", task_script, timeout=max(collector.args.command_timeout, 60))
    for task in _json_records(tasks.get("stdout", "")):
        executable = os.path.expandvars(str(task.get("Execute") or ""))
        if executable and _windows_writable(executable):
            collector.finding("writable_scheduled_task_binary",
                              f"Scheduled task action is writable: {task.get('TaskName')} -> {executable}",
                              evidence=task, path=executable, task=task.get("TaskName"))

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
        if record:
            collector.finding("credential_material_found", f"Readable PowerShell history: {history}",
                              evidence=record.get("content"), path=str(history), material_type="history",
                              confidence="medium")
    _git_loot_search(collector, roots)
    _credential_search(collector, roots)


def main() -> int:
    args = parse_args()
    collector = Collector(args)
    roots = _default_search_roots(args.roots)
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
        "notes_references": NOTE_REFERENCES,
        "options": {
            "max_files": args.max_files,
            "max_file_kb": args.max_file_kb,
            "max_output_kb": args.max_output_kb,
            "command_timeout": args.command_timeout,
            "max_git_repos": args.max_git_repos,
            "sensitive_values_redacted": False,
        },
        "stats": {
            "checks_run": len(collector.checks),
            "findings": len(collector.findings),
            "files_examined": collector.files_examined,
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
