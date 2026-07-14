#!/usr/bin/env python3
"""AI-PEAS: read-only AI post-exploitation loot collector for PathFinder.

Run this on a Linux or Windows host after an authorized foothold. It searches
local application/config paths for AI-specific evidence and writes structured
JSON that PathFinder can parse with --ai-peas-json or scan-mode autodetection.

The collector does not invoke tools, call model/agent endpoints, mutate files,
or attempt exploitation. Discovered values are preserved by default for lab use;
redaction is available as an explicit option.
"""

from __future__ import annotations

import argparse
import ctypes
import datetime as dt
import hashlib
import json
import os
import platform
import re
import socket
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "1.1"
TOOL_NAME = "ai-peas"
DEFAULT_OUTPUT = "ai-peas-loot.json"

SKIP_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", ".pytest_cache", ".mypy_cache",
    ".venv", "venv", "env", "node_modules", "dist", "build", ".tox",
}

TEXT_SUFFIXES = {
    ".env", ".txt", ".log", ".json", ".jsonl", ".ipynb", ".yaml", ".yml", ".toml",
    ".ini", ".cfg", ".conf", ".config", ".py", ".ps1", ".sh", ".js", ".ts",
    ".tsx", ".jsx", ".md", ".sql", ".xml", ".properties",
}

CONFIG_NAMES = {
    ".env", "docker-compose.yml", "docker-compose.yaml", "compose.yml",
    "compose.yaml", "config.json", "config.yaml", "config.yml",
    "settings.py", "appsettings.json", "MLmodel", "conda.yaml",
    "python_env.yaml", "requirements.txt", "pyproject.toml",
    "jupyter_notebook_config.py", "jupyter_server_config.py",
    "dockerfile", "containerfile", "pipfile", "poetry.lock",
}

SECRET_NAME_RE = re.compile(
    r"(?<![A-Za-z0-9_])[\"']?("
    r"OPENAI_API_KEY|ANTHROPIC_API_KEY|AZURE_OPENAI_API_KEY|"
    r"HF_TOKEN|HUGGINGFACEHUB_API_TOKEN|PINECONE_API_KEY|QDRANT_API_KEY|"
    r"WEAVIATE_API_KEY|COHERE_API_KEY|GOOGLE_API_KEY|LANGCHAIN_API_KEY|"
    r"LANGSMITH_API_KEY|MLFLOW_TRACKING_TOKEN|MLFLOW_TRACKING_PASSWORD|"
    r"AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|"
    r"MINIO_ACCESS_KEY|MINIO_SECRET_KEY|S3_ACCESS_KEY|S3_SECRET_KEY|"
    r"JUPYTER_TOKEN|DATABASE_URL|REDIS_URL|"
    r"GROQ_API_KEY|MISTRAL_API_KEY|GEMINI_API_KEY|TOGETHER_API_KEY|"
    r"REPLICATE_API_TOKEN|OPENROUTER_API_KEY|DEEPSEEK_API_KEY|"
    r"AZURE_CLIENT_SECRET|GOOGLE_APPLICATION_CREDENTIALS|"
    r"(?:[A-Z0-9_]*(?:LLM|MODEL|GENAI|OPENAI|ANTHROPIC|HUGGINGFACE|"
    r"PINECONE|QDRANT|WEAVIATE|COHERE|LANGCHAIN|LANGSMITH|MLFLOW|"
    r"JUPYTER)[A-Z0-9_]*(?:API_KEY|TOKEN|SECRET|PASSWORD))"
    r")[\"']?\s*(?:=|:)\s*[\"']?([^\"'\s,#}]+)?",
    re.IGNORECASE,
)

TOKEN_VALUE_RE = re.compile(
    r"("
    r"sk-[A-Za-z0-9_-]{8,}|"
    r"AKIA[0-9A-Z]{16}|"
    r"ASIA[0-9A-Z]{16}|"
    r"gh[pousr]_[A-Za-z0-9_]{20,}|"
    r"xox[baprs]-[A-Za-z0-9-]{10,}|"
    r"hf_[A-Za-z0-9]{20,}"
    r")"
)

HIGH_ENTROPY_VALUE_RE = re.compile(r"(?<![A-Za-z0-9/+_=.-])([A-Za-z0-9/+_=.-]{40,})(?![A-Za-z0-9/+_=.-])")

VECTOR_PATTERNS = [
    ("qdrant", re.compile(r"\b(QDRANT_URL|QDRANT_HOST|qdrant[_\-.]?(?:url|host)|qdrant[^\n]{0,60}:6333\b)", re.I)),
    ("chroma", re.compile(r"\b(CHROMA_|chroma[_\-.]?(?:url|host|persist|collection))", re.I)),
    ("weaviate", re.compile(r"\b(WEAVIATE_|weaviate[_\-.]?(?:url|host)|weaviate[^\n]{0,60}:8080\b)", re.I)),
    ("milvus", re.compile(r"\b(MILVUS_|milvus[_\-.]?(?:uri|host)|:19530\b)", re.I)),
    ("opensearch", re.compile(r"\b(OPENSEARCH_|opensearch[_\-.]?(?:url|host)|opensearch[^\n]{0,60}:9200\b)", re.I)),
    ("elasticsearch", re.compile(r"\b(ELASTICSEARCH_|elasticsearch[_\-.]?(?:url|host)|elasticsearch[^\n]{0,60}:9200\b)", re.I)),
    ("pinecone", re.compile(r"\b(PINECONE_|pinecone[_\-.]?(?:index|environment))", re.I)),
]

MLFLOW_RE = re.compile(r"\b(MLFLOW_|mlflow[_\-.]?(?:tracking|artifact|registry)|artifact_uri|runs:/|models:/)", re.I)
OBJECT_STORE_RE = re.compile(r"\b(S3_|MINIO_|AWS_|s3://|endpoint_url|S3_ENDPOINT_URL|AWS_ENDPOINT_URL)", re.I)
RAG_RE = re.compile(r"\b(rag(?:_|\b)|retriever|vectorstore|vector_store|embedding(?:s|_model)?|knowledge[_\-. ]?base|chunk(?:_size|_overlap|ing|s?\b)|document[_\-. ]?store)", re.I)
MCP_RE = re.compile(r"\b(mcpServers|mcp_server|Model Context Protocol|/mcp|tools/list|tool_call|function_call|agent_card|\.well-known/agent\.json)", re.I)
NOTEBOOK_RE = re.compile(r"\b(jupyter|notebook|ipynb|JUPYTER_TOKEN|/api/kernels|/api/sessions)", re.I)
PROMPT_RE = re.compile(r"\b(system_prompt|prompt_template|instructions|developer_prompt|agent_prompt|guardrail|policy_prompt)", re.I)
AI_CONTEXT_RE = re.compile(
    r"\b(llm|rag|agent|prompt|embedding|vector(?:store|_store| db)|model|"
    r"torch|transformers|langchain|llamaindex|mlflow|huggingface|mcp|jupyter)\b",
    re.I,
)
RUNTIME_CONTEXT_RE = re.compile(
    r"\b(ollama|vllm|jupyter|mlflow|qdrant|chroma|weaviate|milvus|"
    r"langchain|llamaindex|openai|anthropic|huggingface|model-server|mcp)\b",
    re.I,
)

UNSAFE_LOADER_PATTERNS = {
    "pickle.load": re.compile(r"\bpickle\.loads?\s*\("),
    "torch.load": re.compile(r"\btorch\.load\s*\("),
    "joblib.load": re.compile(r"\bjoblib\.load\s*\("),
    "pandas.read_pickle": re.compile(r"\b(?:pandas|pd)\.read_pickle\s*\("),
    "yaml.unsafe_load": re.compile(r"\byaml\.(?:unsafe_load|load)\s*\("),
    "trust_remote_code": re.compile(r"trust_remote_code\s*=\s*True"),
    "model auto-discovery": re.compile(r"\b(?:glob|rglob|listdir)\s*\([^)]*(?:pt|pth|pkl|ckpt|joblib|adapter)", re.I),
}

ARTIFACT_SUFFIXES = {
    ".pkl": "pickle",
    ".pickle": "pickle",
    ".joblib": "joblib",
    ".pt": "pytorch",
    ".pth": "pytorch",
    ".ckpt": "checkpoint",
    ".bin": "model-binary",
    ".safetensors": "safetensors",
    ".onnx": "onnx",
    ".h5": "keras",
    ".keras": "keras",
    ".gguf": "gguf",
    ".csv": "dataset",
    ".jsonl": "dataset",
    ".parquet": "dataset",
}

CONTEXTUAL_ARTIFACT_SUFFIXES = {".bin", ".csv", ".jsonl", ".parquet"}

CONFIG_KIND_NAMES = {
    "docker-compose.yml": "docker-compose",
    "docker-compose.yaml": "docker-compose",
    "compose.yml": "docker-compose",
    "compose.yaml": "docker-compose",
    "dockerfile": "container-build",
    "containerfile": "container-build",
    "pyproject.toml": "python-project",
    "requirements.txt": "python-dependencies",
    "jupyter_notebook_config.py": "jupyter-config",
    "jupyter_server_config.py": "jupyter-config",
}

SPECIAL_ARTIFACT_NAMES = {
    "adapter_config.json": "lora-adapter",
    "adapter_model.bin": "lora-adapter",
    "adapter_model.safetensors": "lora-adapter",
    "tokenizer.json": "tokenizer",
    "tokenizer_config.json": "tokenizer",
    "vocab.json": "tokenizer",
    "merges.txt": "tokenizer",
}

TOOL_RISK_KEYWORDS = {
    "code-execution": ("shell", "command", "exec", "python", "run_code", "terminal"),
    "filesystem": ("read_file", "write_file", "path", "directory", "upload", "download"),
    "network-egress": ("fetch", "http", "url", "browser", "crawl", "scrape"),
    "database": ("sql", "query", "database", "table", "postgres", "mssql", "mysql"),
    "secrets": ("secret", "vault", "token", "credential", "password", "key"),
    "cloud": ("aws", "s3", "azure", "gcp", "kubernetes", "kubectl"),
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("roots", nargs="*", default=["."], help="Root directories/files to inspect")
    parser.add_argument(
        "-o",
        "--out",
        default=DEFAULT_OUTPUT,
        help=f"Output JSON path (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument("--common-roots", action="store_true",
                        help="Also inspect common app/config roots for this OS")
    parser.add_argument("--max-files", type=int, default=50000, help="Maximum files to inspect")
    parser.add_argument("--max-file-kb", type=int, default=512,
                        help="Maximum text/config file size to read")
    parser.add_argument("--max-notebook-kb", type=int, default=4096,
                        help="Maximum Jupyter notebook size to read")
    parser.add_argument("--quiet", action="store_true",
                        help="Suppress progressive discovery output")
    privacy = parser.add_mutually_exclusive_group()
    privacy.add_argument("--include-secret-values", action="store_true",
                         help="Preserve raw values (default; retained for compatibility)")
    privacy.add_argument("--redact-secret-values", action="store_true",
                         help="Redact secret values and sensitive evidence snippets")
    return parser.parse_args()


def common_roots() -> list[str]:
    if os.name == "nt":
        candidates = [
            os.environ.get("USERPROFILE"),
            os.environ.get("PROGRAMDATA"),
            os.environ.get("APPDATA"),
            os.environ.get("LOCALAPPDATA"),
            "C:\\inetpub\\wwwroot",
        ]
    else:
        candidates = [
            os.environ.get("HOME"),
            "/opt",
            "/srv",
            "/var/www",
            "/etc",
            "/run/secrets",
            "/var/run/secrets/kubernetes.io/serviceaccount",
        ]
    return [str(Path(c)) for c in candidates if c and Path(c).exists()]


def sha256_short(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()[:16]


def redact_value(value: str | None, redact_secret_values: bool) -> dict[str, Any]:
    value = (value or "").strip().strip("\"'")
    if not value:
        return {"present": False}
    if not redact_secret_values:
        return {"present": True, "value": value}
    return {
        "present": True,
        "redacted": True,
        "length": len(value),
        "sha256_16": sha256_short(value),
        "preview": value[:3] + "..." + value[-2:] if len(value) >= 8 else "<short>",
    }


def source_record(path: Path, line: int | None = None, snippet: str | None = None) -> dict[str, Any]:
    record: dict[str, Any] = {"path": str(path)}
    if line is not None:
        record["line"] = line
    if snippet:
        record["snippet"] = snippet[:500]
    return record


def clean_snippet(line: str, redact_secret_values: bool = False) -> str:
    line = line.strip()
    if not redact_secret_values:
        return line[:500]
    for match in SECRET_NAME_RE.finditer(line):
        key = match.group(1)
        line = line.replace(match.group(0), f"{key}=<redacted>")
    line = TOKEN_VALUE_RE.sub("<redacted-token>", line)

    def redact_high_entropy(match: re.Match) -> str:
        value = match.group(1)
        classes = sum([
            bool(re.search(r"[a-z]", value)),
            bool(re.search(r"[A-Z]", value)),
            bool(re.search(r"\d", value)),
            bool(re.search(r"[^A-Za-z0-9]", value)),
        ])
        return "<redacted-token>" if classes >= 3 else value

    line = HIGH_ENTROPY_VALUE_RE.sub(redact_high_entropy, line)
    return line[:500]


def is_text_candidate(path: Path) -> bool:
    name = path.name
    suffix = path.suffix.lower()
    return suffix in TEXT_SUFFIXES or name in CONFIG_NAMES or any(
        token in name.lower() for token in
        ("prompt", "agent", "tool", "mcp", "rag", "embedding", "notebook", "model", "jupyter")
    )


def artifact_category(path: Path) -> str | None:
    special = SPECIAL_ARTIFACT_NAMES.get(path.name.lower())
    if special:
        return special
    suffix = path.suffix.lower()
    category = ARTIFACT_SUFFIXES.get(suffix)
    if category and suffix in CONTEXTUAL_ARTIFACT_SUFFIXES:
        context = re.sub(r"[_\-./\\]+", " ", " ".join(part.lower() for part in path.parts[-4:]))
        if not AI_CONTEXT_RE.search(context):
            return None
    return category


def config_kind(path: Path) -> str | None:
    name = path.name.lower()
    if name in CONFIG_KIND_NAMES:
        return CONFIG_KIND_NAMES[name]
    if path.suffix.lower() == ".service":
        return "systemd-service"
    if path.suffix.lower() == ".ipynb":
        return "jupyter-notebook"
    if name.startswith("kernel-") and path.suffix.lower() == ".json":
        return "jupyter-runtime"
    if name in {"config", "token", "namespace", "ca.crt"} and "serviceaccount" in str(path).lower():
        return "kubernetes-service-account"
    return "application-config" if name in CONFIG_NAMES else None


def path_priority(path: Path) -> int:
    """Lower numbers are retained first when a broad root exceeds --max-files."""
    kind = config_kind(path)
    name = path.name.lower()
    if kind or any(token in name for token in
                   ("prompt", "agent", "mcp", "rag", "embedding", "jupyter", "model")):
        return 0
    if path.suffix.lower() in {".env", ".yaml", ".yml", ".toml", ".json", ".py"}:
        return 1
    if artifact_category(path):
        return 2
    return 3


def write_state(path: Path) -> dict[str, bool]:
    try:
        file_writable = os.access(path, os.W_OK)
        parent_writable = os.access(path.parent, os.W_OK)
    except OSError:
        file_writable = False
        parent_writable = False
    return {
        "file_writable": bool(file_writable),
        "parent_writable": bool(parent_writable),
        "writable": bool(file_writable or parent_writable),
    }


def walk_paths(roots: list[str], max_files: int, excluded: Path | None = None) -> tuple[list[Path], int, bool]:
    seen: set[str] = set()
    buckets: dict[int, list[Path]] = {0: [], 1: [], 2: [], 3: []}
    candidates_seen = 0
    discovery_cap = max(max_files, 1) * 4
    excluded_resolved = str(excluded.resolve()) if excluded else None
    for root_value in roots:
        root = Path(root_value).expanduser()
        if not root.exists():
            continue
        if root.is_file():
            resolved = str(root.resolve())
            if resolved not in seen and resolved != excluded_resolved:
                seen.add(resolved)
                if is_text_candidate(root) or artifact_category(root):
                    buckets[path_priority(root)].append(root)
                    candidates_seen += 1
            continue
        for current, dirs, names in os.walk(root):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.endswith("-output")]
            for name in names:
                path = Path(current) / name
                resolved = str(path.resolve())
                if resolved in seen or resolved == excluded_resolved:
                    continue
                seen.add(resolved)
                if not (is_text_candidate(path) or artifact_category(path)):
                    continue
                buckets[path_priority(path)].append(path)
                candidates_seen += 1
                if candidates_seen >= discovery_cap:
                    selected = [item for priority in range(4) for item in buckets[priority]][:max_files]
                    return selected, candidates_seen, True
    selected = [item for priority in range(4) for item in buckets[priority]][:max_files]
    return selected, candidates_seen, candidates_seen > len(selected)


def load_text(path: Path, max_bytes: int) -> str | None:
    try:
        if path.stat().st_size > max_bytes:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def extract_urlish(line: str) -> str | None:
    match = re.search(r"(https?://[^\s\"']+|s3://[^\s\"']+|[A-Za-z0-9_.-]+:\d{2,5})", line)
    return match.group(1).rstrip(",);]") if match else None


def classify_tool_risk(text: str) -> list[str]:
    lower = text.lower()
    return sorted(name for name, words in TOOL_RISK_KEYWORDS.items() if any(word in lower for word in words))


def notebook_text(path: Path, text: str, out: dict[str, list[dict[str, Any]]],
                  redact_secret_values: bool) -> str:
    """Extract notebook source/metadata without retaining bulky execution outputs."""
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, RecursionError, ValueError):
        return text
    if not isinstance(data, dict) or not isinstance(data.get("cells"), list):
        return text
    sources = []
    for cell in data["cells"]:
        if not isinstance(cell, dict):
            continue
        source = cell.get("source")
        if isinstance(source, list):
            sources.extend(str(part) for part in source)
        elif isinstance(source, str):
            sources.append(source)
    metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
    out["notebooks"].append({
        **source_record(path, snippet=clean_snippet(" ".join(sources)[:500], redact_secret_values)),
        "kernel": ((metadata.get("kernelspec") or {}).get("name")
                   if isinstance(metadata.get("kernelspec"), dict) else None),
        "cell_count": len(data["cells"]),
    })
    return "\n".join(sources) + "\n" + json.dumps(metadata)


def collect_environment(out: dict[str, list[dict[str, Any]]], redact_secret_values: bool) -> None:
    for name, value in os.environ.items():
        assignment = f"{name}={value}"
        secret_match = SECRET_NAME_RE.search(assignment)
        if secret_match:
            out["secrets"].append({
                "path": f"environment:{name}",
                "snippet": clean_snippet(assignment, redact_secret_values),
                "name": secret_match.group(1).upper(),
                "value": redact_value(secret_match.group(2), redact_secret_values),
            })
        normalized_name = name.replace("_", " ").replace("-", " ")
        if AI_CONTEXT_RE.search(normalized_name) or RUNTIME_CONTEXT_RE.search(normalized_name):
            out["runtime_context"].append({
                "path": f"environment:{name}",
                "kind": "environment-variable",
                "name": name,
                "value": ("<redacted>" if secret_match and redact_secret_values
                          else clean_snippet(value, redact_secret_values)),
            })


def collect_linux_process_context(out: dict[str, list[dict[str, Any]]],
                                  redact_secret_values: bool, limit: int = 256) -> None:
    proc = Path("/proc")
    if os.name == "nt" or not proc.is_dir():
        return
    inspected = 0
    for entry in proc.iterdir():
        if not entry.name.isdigit() or inspected >= limit:
            continue
        inspected += 1
        try:
            command = (entry / "cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", "replace").strip()
        except OSError:
            continue
        if command and RUNTIME_CONTEXT_RE.search(command):
            out["runtime_context"].append({
                "path": f"/proc/{entry.name}/cmdline",
                "kind": "running-process",
                "pid": int(entry.name),
                "command": clean_snippet(command, redact_secret_values),
            })


def collect_windows_process_context(out: dict[str, list[dict[str, Any]]], limit: int = 256) -> None:
    if os.name != "nt":
        return

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", ctypes.c_ulong), ("cntUsage", ctypes.c_ulong),
            ("th32ProcessID", ctypes.c_ulong), ("th32DefaultHeapID", ctypes.c_void_p),
            ("th32ModuleID", ctypes.c_ulong), ("cntThreads", ctypes.c_ulong),
            ("th32ParentProcessID", ctypes.c_ulong), ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", ctypes.c_ulong), ("szExeFile", ctypes.c_wchar * 260),
        ]

    snapshot = ctypes.windll.kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
    if snapshot in (0, ctypes.c_void_p(-1).value):
        return
    entry = PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(entry)
    count = 0
    try:
        ok = ctypes.windll.kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while ok and count < limit:
            name = entry.szExeFile
            if RUNTIME_CONTEXT_RE.search(name):
                out["runtime_context"].append({
                    "path": f"process:{entry.th32ProcessID}",
                    "kind": "running-process",
                    "pid": int(entry.th32ProcessID),
                    "process_name": name,
                })
            count += 1
            ok = ctypes.windll.kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        ctypes.windll.kernel32.CloseHandle(snapshot)


def build_application_chains(out: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    categories = (
        "secrets", "vector_stores", "rag_sources", "mlflow", "object_stores",
        "mcp_tools", "agent_manifests", "unsafe_loaders", "model_artifacts",
    )
    by_path: dict[str, set[str]] = {}
    samples: dict[str, dict[str, Any]] = {}
    for category in categories:
        for item in out.get(category, []):
            if not isinstance(item, dict) or not item.get("path"):
                continue
            path = str(item["path"])
            by_path.setdefault(path, set()).add(category)
            samples.setdefault(path, item)
    chains = []
    anchors = {"secrets", "unsafe_loaders", "model_artifacts", "mcp_tools"}
    for path, signals in by_path.items():
        if len(signals) < 2 or not signals.intersection(anchors):
            continue
        chains.append({
            "path": path,
            "signals": sorted(signals),
            "signal_count": len(signals),
            "sample": samples[path],
        })
    return chains


def inspect_json_structure(path: Path, text: str, out: dict[str, list[dict[str, Any]]]) -> None:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, RecursionError, ValueError):
        return
    if not isinstance(data, (dict, list)):
        return

    def maybe_list_tools(container: Any, context: str) -> None:
        if isinstance(container, dict):
            for key, value in container.items():
                if key in {"tools", "functions", "skills"} and isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            name = item.get("name") or item.get("id") or item.get("tool")
                            desc = item.get("description") or item.get("summary") or ""
                            if name:
                                joined = f"{name} {desc} {json.dumps(item)[:1000]}"
                                out["mcp_tools"].append({
                                    **source_record(path),
                                    "name": name,
                                    "context": context,
                                    "risk_categories": classify_tool_risk(joined),
                                })
                maybe_list_tools(value, f"{context}.{key}" if context else str(key))
        elif isinstance(container, list):
            for item in container:
                maybe_list_tools(item, context)

    if isinstance(data, dict) and isinstance(data.get("mcpServers"), dict):
        for name, server in data["mcpServers"].items():
            text_blob = json.dumps(server)[:1000]
            out["mcp_tools"].append({
                **source_record(path),
                "name": name,
                "context": "mcpServers",
                "risk_categories": classify_tool_risk(text_blob),
            })

    if isinstance(data, dict) and any(k in data for k in ("capabilities", "skills", "endpoint", "agentCard")):
        out["agent_manifests"].append({
            **source_record(path),
            "keys": sorted(str(k) for k in data.keys())[:30],
            "risk_categories": classify_tool_risk(json.dumps(data)[:2000]),
        })

    maybe_list_tools(data, "")


def inspect_text_file(path: Path, text: str, out: dict[str, list[dict[str, Any]]],
                      redact_secret_values: bool) -> None:
    lower_name = path.name.lower()
    kind = config_kind(path)
    if not kind and re.search(r"(?m)^\s*apiVersion\s*:.*$", text) and re.search(
            r"(?m)^\s*kind\s*:\s*(?:Pod|Deployment|StatefulSet|DaemonSet|Job|CronJob|Secret|ConfigMap)\b", text):
        kind = "kubernetes-manifest"
    if not kind and re.search(r"(?m)^\s*\[Service\]\s*$", text):
        kind = "systemd-service"
    if kind:
        out["config_refs"].append({
            **source_record(path),
            "kind": kind,
            **write_state(path),
        })
    if path.suffix.lower() == ".ipynb":
        text = notebook_text(path, text, out, redact_secret_values)
    inspect_json_structure(path, text, out)

    if any(token in lower_name for token in ("prompt", "system", "instruction", "template")):
        first_line = text.splitlines()[0] if text.splitlines() else ""
        out["prompt_templates"].append({
            **source_record(path, snippet=clean_snippet(first_line, redact_secret_values)),
            "reason": "prompt-like filename",
        })

    normalized_path = re.sub(r"[_\-./\\]+", " ", str(path))
    file_has_ai_context = bool(AI_CONTEXT_RE.search(text[:200000]) or
                               AI_CONTEXT_RE.search(normalized_path))
    for line_number, line in enumerate(text.splitlines(), 1):
        cleaned = clean_snippet(line, redact_secret_values)
        for match in SECRET_NAME_RE.finditer(line):
            out["secrets"].append({
                **source_record(path, line_number, cleaned),
                "name": match.group(1).upper(),
                "value": redact_value(match.group(2), redact_secret_values),
            })

        for engine, pattern in VECTOR_PATTERNS:
            if pattern.search(line):
                out["vector_stores"].append({
                    **source_record(path, line_number, cleaned),
                    "engine": engine,
                    "url_or_hint": extract_urlish(line),
                })

        if MLFLOW_RE.search(line):
            out["mlflow"].append({
                **source_record(path, line_number, cleaned),
                "uri_or_hint": extract_urlish(line),
            })
        if OBJECT_STORE_RE.search(line):
            out["object_stores"].append({
                **source_record(path, line_number, cleaned),
                "uri_or_hint": extract_urlish(line),
            })
        if RAG_RE.search(line) and (file_has_ai_context or AI_CONTEXT_RE.search(line)):
            out["rag_sources"].append({
                **source_record(path, line_number, cleaned),
                "path_or_hint": extract_urlish(line),
            })
        if MCP_RE.search(line):
            out["agent_manifests"].append({
                **source_record(path, line_number, cleaned),
                "risk_categories": classify_tool_risk(line),
            })
        if NOTEBOOK_RE.search(line):
            out["notebooks"].append({
                **source_record(path, line_number, cleaned),
                "uri_or_hint": extract_urlish(line),
            })
        if PROMPT_RE.search(line):
            out["prompt_templates"].append({
                **source_record(path, line_number, cleaned),
                "reason": "prompt keyword",
            })

        for signal, pattern in UNSAFE_LOADER_PATTERNS.items():
            if pattern.search(line) and file_has_ai_context:
                out["unsafe_loaders"].append({
                    **source_record(path, line_number, cleaned),
                    "signal": signal,
                    "writable": write_state(path)["writable"],
                })


def dedupe_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped = []
    seen = set()
    for record in records:
        try:
            key = json.dumps(record, sort_keys=True, default=str)
        except (TypeError, ValueError):
            key = repr(sorted(record.items())) if isinstance(record, dict) else repr(record)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(record)
    return deduped


def main() -> int:
    args = parse_args()
    roots = list(args.roots)
    if args.common_roots:
        roots.extend(common_roots())
    max_bytes = max(1, args.max_file_kb) * 1024
    max_notebook_bytes = max(1, args.max_notebook_kb) * 1024

    findings: dict[str, list[dict[str, Any]]] = {
        "secrets": [],
        "config_refs": [],
        "vector_stores": [],
        "rag_sources": [],
        "mlflow": [],
        "object_stores": [],
        "notebooks": [],
        "mcp_tools": [],
        "agent_manifests": [],
        "prompt_templates": [],
        "model_artifacts": [],
        "unsafe_loaders": [],
        "runtime_context": [],
        "application_chains": [],
    }

    def progress(message: str) -> None:
        if not args.quiet:
            print(message, flush=True)

    progress(f"[*] AI-PEAS starting on {len(roots)} root(s)")
    progress("[*] Collecting readable environment and runtime context")
    collect_environment(findings, args.redact_secret_values)
    collect_linux_process_context(findings, args.redact_secret_values)
    collect_windows_process_context(findings)

    files, candidates_seen, file_limit_reached = walk_paths(
        roots, max(1, args.max_files), excluded=Path(args.out)
    )
    progress(f"[*] Selected {len(files)} relevant file(s) from {candidates_seen} candidate(s)")
    if file_limit_reached:
        progress(f"[!] Candidate limit applied; higher-priority AI/config files were retained first")
    skipped_errors = 0
    progress_events = 0
    for path in files:
        try:
            before = {key: len(value) for key, value in findings.items()}
            category = artifact_category(path)
            if category:
                record = {
                    **source_record(path),
                    "category": category,
                    "size": path.stat().st_size if path.exists() else None,
                    **write_state(path),
                }
                findings["model_artifacts"].append(record)

            if not is_text_candidate(path):
                added = [key for key, value in findings.items() if len(value) > before[key]]
                if added and progress_events < 200:
                    progress(f"[+] {path}: {', '.join(added)}")
                    progress_events += 1
                continue
            text_limit = max_notebook_bytes if path.suffix.lower() == ".ipynb" else max_bytes
            text = load_text(path, text_limit)
            if text is None:
                added = [key for key, value in findings.items() if len(value) > before[key]]
                if added and progress_events < 200:
                    progress(f"[+] {path}: {', '.join(added)}")
                    progress_events += 1
                continue
            inspect_text_file(path, text, findings, args.redact_secret_values)
            added = [key for key, value in findings.items() if len(value) > before[key]]
            if added:
                if progress_events < 200:
                    progress(f"[+] {path}: {', '.join(added)}")
                elif progress_events == 200:
                    progress("[*] Additional per-file discoveries suppressed; collection continues")
                progress_events += 1
        except Exception:
            skipped_errors += 1
            continue

    findings["application_chains"] = build_application_chains(findings)
    findings = {key: dedupe_records(value) for key, value in findings.items()}

    payload = {
        "tool": TOOL_NAME,
        "type": "ai_post_exploitation_loot",
        "schema_version": SCHEMA_VERSION,
        "host": socket.gethostname(),
        "platform": platform.platform(),
        "collected_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "roots": roots,
        "options": {
            "max_files": args.max_files,
            "max_file_kb": args.max_file_kb,
            "max_notebook_kb": args.max_notebook_kb,
            "secret_values_redacted": args.redact_secret_values,
            "quiet": args.quiet,
        },
        "stats": {
            "files_seen": len(files),
            "candidate_files_seen": candidates_seen,
            "file_limit_reached": file_limit_reached,
            "files_skipped_due_to_errors": skipped_errors,
            "findings_by_category": {key: len(value) for key, value in findings.items()},
        },
        "findings": findings,
    }

    out_path = Path(args.out)
    # Preserve insertion order so the tool/type/schema signature remains near
    # the start of large reports and scan-mode auto-detection can identify it
    # without loading the entire JSON document.
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"[+] Wrote {out_path} ({len(files)} relevant files inspected; "
          f"{sum(len(v) for v in findings.values())} records)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
