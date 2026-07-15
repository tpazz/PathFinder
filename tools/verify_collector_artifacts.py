#!/usr/bin/env python3
"""Verify collector source dependencies and frozen Linux release artifacts."""

from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.metadata
import json
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent.parent
COLLECTORS = {
    "mini-peas": {
        "source": REPO_ROOT / "tools" / "mini-peas.py",
        "report_type": "pathfinder_manual_privesc_loot",
    },
    "ai-peas": {
        "source": REPO_ROOT / "tools" / "ai-peas.py",
        "report_type": "ai_post_exploitation_loot",
    },
}
ARCHITECTURES = {
    "x86_64": {"elf_machine": 62, "aliases": {"x86_64", "amd64"}},
    "arm64": {"elf_machine": 183, "aliases": {"aarch64", "arm64"}},
}
PT_INTERP = 3


class VerificationError(RuntimeError):
    pass


def collector_imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=os.fspath(path))
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".", 1)[0])
    return imports


def verify_stdlib_only(path: Path) -> list[str]:
    imports = collector_imports(path)
    allowed = set(sys.stdlib_module_names) | {"__future__"}
    third_party = sorted(imports - allowed)
    if third_party:
        raise VerificationError(
            f"{path.name} imports non-stdlib module(s): {', '.join(third_party)}"
        )
    return sorted(imports)


def _unpack_from(handle, endian: str, format_code: str, offset: int) -> tuple[Any, ...]:
    handle.seek(offset)
    size = struct.calcsize(endian + format_code)
    data = handle.read(size)
    if len(data) != size:
        raise VerificationError("truncated ELF header")
    return struct.unpack(endian + format_code, data)


def inspect_elf(path: Path) -> dict[str, Any]:
    with path.open("rb") as handle:
        ident = handle.read(16)
        if len(ident) != 16 or ident[:4] != b"\x7fELF":
            raise VerificationError(f"{path.name} is not an ELF executable")
        if ident[4] != 2:
            raise VerificationError(f"{path.name} is not a 64-bit ELF executable")
        endian = "<" if ident[5] == 1 else ">" if ident[5] == 2 else None
        if endian is None:
            raise VerificationError(f"{path.name} has an invalid ELF byte order")
        machine = _unpack_from(handle, endian, "H", 18)[0]
        program_offset = _unpack_from(handle, endian, "Q", 32)[0]
        program_entry_size = _unpack_from(handle, endian, "H", 54)[0]
        program_count = _unpack_from(handle, endian, "H", 56)[0]
        if program_count and program_entry_size < 4:
            raise VerificationError(f"{path.name} has an invalid program-header table")
        has_interpreter = False
        for index in range(program_count):
            entry_offset = program_offset + (index * program_entry_size)
            segment_type = _unpack_from(handle, endian, "I", entry_offset)[0]
            if segment_type == PT_INTERP:
                has_interpreter = True
                break
    return {
        "elf_class": 64,
        "elf_machine": machine,
        "has_dynamic_interpreter": has_interpreter,
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run(command: list[str], *, cwd: Path, env: dict[str, str], timeout: int = 90) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise VerificationError(f"failed to run {Path(command[0]).name}: {exc}") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise VerificationError(
            f"{Path(command[0]).name} exited {result.returncode}: {detail[:1000]}"
        )
    return result


def _runtime_command(name: str, artifact: Path, root: Path, report: Path) -> list[str]:
    if name == "mini-peas":
        return [
            os.fspath(artifact), os.fspath(root), "--only-specified-roots",
            "--quiet", "--max-files", "10", "--max-file-kb", "16",
            "--max-output-kb", "64", "--command-timeout", "2",
            "--max-git-repos", "1", "--out", os.fspath(report),
        ]
    return [
        os.fspath(artifact), os.fspath(root), "--quiet", "--max-files", "10",
        "--max-file-kb", "16", "--max-notebook-kb", "16",
        "--out", os.fspath(report),
    ]


def verify_artifact(name: str, path: Path, architecture: str, *, run_runtime: bool) -> dict[str, Any]:
    if not path.is_file():
        raise VerificationError(f"missing artifact: {path}")
    if not os.access(path, os.X_OK):
        raise VerificationError(f"artifact is not executable: {path}")
    elf = inspect_elf(path)
    expected_machine = ARCHITECTURES[architecture]["elf_machine"]
    if elf["elf_machine"] != expected_machine:
        raise VerificationError(
            f"{path.name} ELF machine {elf['elf_machine']} does not match {architecture}"
        )
    if elf["has_dynamic_interpreter"]:
        raise VerificationError(f"{path.name} still contains a PT_INTERP dynamic loader")

    clean_env = dict(os.environ)
    with tempfile.TemporaryDirectory(prefix=f"verify-{name}-") as directory:
        temp = Path(directory)
        home = temp / "home"
        root = temp / "empty-root"
        extract = temp / "extract"
        home.mkdir()
        root.mkdir()
        extract.mkdir()
        clean_env.update({
            "HOME": os.fspath(home),
            "USER": "pathfinder-artifact-test",
            "LOGNAME": "pathfinder-artifact-test",
            "TMPDIR": os.fspath(extract),
        })
        help_result = _run([os.fspath(path), "--help"], cwd=temp, env=clean_env, timeout=30)
        if "usage:" not in help_result.stdout.lower():
            raise VerificationError(f"{path.name} --help did not render argparse usage")

        payload = None
        if run_runtime:
            report = temp / f"{name}-verification.json"
            _run(_runtime_command(name, path, root, report), cwd=temp, env=clean_env)
            try:
                payload = json.loads(report.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise VerificationError(f"{path.name} did not write valid JSON: {exc}") from exc
            expected = COLLECTORS[name]
            if payload.get("tool") != name or payload.get("type") != expected["report_type"]:
                raise VerificationError(f"{path.name} wrote an unexpected collector schema")
            if not str(payload.get("platform") or "").lower().startswith("linux"):
                raise VerificationError(f"{path.name} runtime did not report Linux")
            if not payload.get("schema_version"):
                raise VerificationError(f"{path.name} report omitted schema_version")

    return {
        "name": path.name,
        "size_bytes": path.stat().st_size,
        "sha256": _sha256(path),
        "elf_machine": elf["elf_machine"],
        "staticx_no_pt_interp": True,
        "help_verified": True,
        "runtime_verified": bool(run_runtime),
        "report_type": payload.get("type") if payload else COLLECTORS[name]["report_type"],
        "schema_version": payload.get("schema_version") if payload else None,
    }


def _package_version(name: str) -> str | None:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None


def verify_sources() -> list[dict[str, Any]]:
    records = []
    for name, details in COLLECTORS.items():
        imports = verify_stdlib_only(details["source"])
        records.append({
            "name": name,
            "source": details["source"].relative_to(REPO_ROOT).as_posix(),
            "stdlib_only": True,
            "imports": imports,
        })
    return records


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-only", action="store_true", help="Only enforce stdlib imports")
    parser.add_argument("--arch", choices=sorted(ARCHITECTURES), help="Expected artifact architecture")
    parser.add_argument("--artifact-dir", type=Path, default=REPO_ROOT / "dist")
    parser.add_argument("--skip-runtime", action="store_true", help="Skip bounded collector execution")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        source_records = verify_sources()
        if args.source_only:
            print("[+] Collector sources import only the Python standard library.")
            return 0
        if not args.arch:
            raise VerificationError("--arch is required unless --source-only is used")

        artifact_dir = args.artifact_dir.resolve()
        artifact_records = []
        for name in COLLECTORS:
            path = artifact_dir / f"{name}-linux-{args.arch}"
            artifact_records.append(
                verify_artifact(name, path, args.arch, run_runtime=not args.skip_runtime)
            )

        manifest = {
            "schema_version": 1,
            "platform": "linux",
            "architecture": args.arch,
            "source_commit": os.environ.get("GITHUB_SHA"),
            "build_tools": {
                "python": platform_python_version(),
                "pyinstaller": _package_version("pyinstaller"),
                "staticx": _package_version("staticx"),
            },
            "sources": source_records,
            "artifacts": artifact_records,
        }
        artifact_dir.mkdir(parents=True, exist_ok=True)
        (artifact_dir / "artifact-manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        checksum_lines = [
            f"{record['sha256']}  {record['name']}" for record in artifact_records
        ]
        (artifact_dir / "SHA256SUMS").write_text(
            "\n".join(checksum_lines) + "\n", encoding="utf-8"
        )
        for record in artifact_records:
            print(f"[+] {record['name']}: {record['sha256']}")
        print(f"[+] Wrote {artifact_dir / 'artifact-manifest.json'}")
        return 0
    except VerificationError as exc:
        print(f"[!] Verification failed: {exc}", file=sys.stderr)
        return 1


def platform_python_version() -> str:
    return ".".join(str(part) for part in sys.version_info[:3])


if __name__ == "__main__":
    raise SystemExit(main())
