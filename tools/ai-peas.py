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
import ast
import base64
import ctypes
import datetime as dt
import hashlib
import json
import os
import platform
import re
import socket
import sqlite3
import stat
import struct
import zipfile
from pathlib import Path
from typing import Any

try:
    import pwd
except ImportError:  # Windows
    pwd = None


SCHEMA_VERSION = "1.2"
TOOL_NAME = "ai-peas"
DEFAULT_OUTPUT = "ai-peas-loot.json"

SKIP_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", ".pytest_cache", ".mypy_cache",
    ".venv", "venv", "env", "node_modules", ".tox",
}

TEXT_SUFFIXES = {
    ".env", ".txt", ".log", ".json", ".jsonl", ".ipynb", ".yaml", ".yml", ".toml",
    ".ini", ".cfg", ".conf", ".config", ".py", ".ps1", ".sh", ".js", ".ts",
    ".tsx", ".jsx", ".md", ".sql", ".xml", ".properties",
    ".service", ".socket", ".timer", ".rules", ".rail", ".co",
}

CONFIG_NAMES = {
    ".env", "docker-compose.yml", "docker-compose.yaml", "compose.yml",
    "compose.yaml", "config.json", "config.yaml", "config.yml",
    "settings.py", "appsettings.json", "MLmodel", "conda.yaml",
    "python_env.yaml", "requirements.txt", "pyproject.toml",
    "jupyter_notebook_config.py", "jupyter_server_config.py",
    "dockerfile", "containerfile", "pipfile", "poetry.lock",
    "kubeconfig", "credentials", "credentials.json", "application_default_credentials.json",
    "azureprofile.json", "settings.json", ".bash_history", ".zsh_history", "mlmodel",
    "consolehost_history.txt", "auth.json", "config.json", ".dockerconfigjson",
}

ALWAYS_INTERESTING_NAMES = {
    "token", "namespace", "ca.crt", "client.crt", "client.key", "service-account.json",
    "service_account.json", "web_identity_token_file", ".git-credentials", ".netrc",
}

SECRET_MOUNT_PARTS = {
    "/run/secrets/", "/var/run/secrets/", "/secrets/", "\\secrets\\",
    "\\programdata\\docker\\secrets\\",
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

GENERIC_SECRET_RE = re.compile(
    r"(?<![A-Za-z0-9_])[\"']?("
    r"(?:api[_-]?key|access[_-]?token|auth[_-]?token|bearer[_-]?token|refresh[_-]?token|"
    r"client[_-]?secret|private[_-]?token|password|passwd|secret|token)"
    r")[\"']?\s*(?:=|:)\s*[\"']?([^\"'\s,#}]{8,})",
    re.IGNORECASE,
)

JWT_RE = re.compile(r"(?<![A-Za-z0-9_-])(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*)(?![A-Za-z0-9_-])")
URL_CREDENTIAL_RE = re.compile(r"\b([a-z][a-z0-9+.-]*://[^/\s:@]+):([^@\s/]+)@([^\s]+)", re.I)
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")

TOKEN_VALUE_RE = re.compile(
    r"("
    r"sk-[A-Za-z0-9_-]{8,}|"
    r"AKIA[0-9A-Z]{16}|"
    r"ASIA[0-9A-Z]{16}|"
    r"gh[pousr]_[A-Za-z0-9_]{20,}|"
    r"glpat-[A-Za-z0-9_-]{12,}|"
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
    "dill.load": re.compile(r"\bdill\.loads?\s*\("),
    "cloudpickle.load": re.compile(r"\bcloudpickle\.loads?\s*\("),
    "numpy.load allow_pickle": re.compile(r"\b(?:numpy|np)\.load\s*\([^)]*allow_pickle\s*=\s*True"),
    "torch.jit.load": re.compile(r"\btorch\.jit\.load\s*\("),
    "keras load_model": re.compile(r"\b(?:keras(?:\.models)?|tf\.keras\.models)\.load_model\s*\("),
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
    ".whl": "ai-package",
    ".egg": "ai-package",
    ".zip": "archive",
}

CONTEXTUAL_ARTIFACT_SUFFIXES = {".bin", ".csv", ".jsonl", ".parquet", ".zip"}

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
    "chroma.sqlite3": "rag-store",
    "index.faiss": "rag-index",
    "docstore.json": "rag-docstore",
}

RAG_STORE_SUFFIXES = {".sqlite", ".sqlite3", ".db", ".faiss", ".index"}

HISTORY_NAMES = {".bash_history", ".zsh_history", "consolehost_history.txt"}
PROJECT_MARKERS = {
    "pyproject.toml", "requirements.txt", "docker-compose.yml", "docker-compose.yaml",
    "compose.yml", "compose.yaml", "package.json", "MLmodel",
}

PIPELINE_RE = re.compile(
    r"\b(DirectoryLoader|FileSystemLoader|WebBaseLoader|S3Loader|ingest(?:ion)?|"
    r"watch(?:dog|files)?|celery|airflow|argo|kubeflow|kserve|cronjob|systemd|"
    r"artifact_uri|model_uri|model_path|persist_directory|collection_name)\b",
    re.I,
)
GUARDRAIL_RE = re.compile(
    r"\b(guardrail|blocked[_ -]?phrases?|denylist|allowlist|output[_ -]?filter|"
    r"input[_ -]?filter|nemo[_ -]?guardrails|llm[_ -]?guard|rebuff|validator|"
    r"content[_ -]?policy|jailbreak[_ -]?detection)\b",
    re.I,
)

TOOL_RISK_KEYWORDS = {
    "code-execution": ("shell", "command", "exec", "python", "run_code", "terminal"),
    "filesystem": ("read_file", "write_file", "open", "path", "directory", "upload", "download"),
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
            str(Path(os.environ.get("USERPROFILE", "")) / ".kube"),
            str(Path(os.environ.get("USERPROFILE", "")) / ".aws"),
            str(Path(os.environ.get("USERPROFILE", "")) / ".docker"),
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
            str(Path(os.environ.get("HOME", "")) / ".kube"),
            str(Path(os.environ.get("HOME", "")) / ".aws"),
            str(Path(os.environ.get("HOME", "")) / ".config" / "gcloud"),
            str(Path(os.environ.get("HOME", "")) / ".azure"),
            str(Path(os.environ.get("HOME", "")) / ".docker"),
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
    try:
        info = path.stat()
        record.update({
            "size": info.st_size,
            "mtime": dt.datetime.fromtimestamp(info.st_mtime, dt.timezone.utc).isoformat(),
            "mode": stat.filemode(info.st_mode),
            "uid": getattr(info, "st_uid", None),
            "gid": getattr(info, "st_gid", None),
        })
        if pwd is not None:
            try:
                record["owner"] = pwd.getpwuid(info.st_uid).pw_name
            except KeyError:
                pass
    except OSError:
        pass
    return record


def clean_snippet(line: str, redact_secret_values: bool = False) -> str:
    line = line.strip()
    if not redact_secret_values:
        return line[:500]
    for match in SECRET_NAME_RE.finditer(line):
        key = match.group(1)
        line = line.replace(match.group(0), f"{key}=<redacted>")
    for match in GENERIC_SECRET_RE.finditer(line):
        key = match.group(1)
        line = line.replace(match.group(0), f"{key}=<redacted>")
    line = PRIVATE_KEY_RE.sub("-----BEGIN <redacted> PRIVATE KEY-----", line)
    line = JWT_RE.sub("<redacted-jwt>", line)
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
    name = path.name.lower()
    suffix = path.suffix.lower()
    normalized = str(path).lower().replace("\\", "/")
    return (
        suffix in TEXT_SUFFIXES
        or name in CONFIG_NAMES
        or name in ALWAYS_INTERESTING_NAMES
        or name in HISTORY_NAMES
        or (name == "config" and "/.kube/" in f"/{normalized.strip('/')}/")
        or any(part in normalized for part in SECRET_MOUNT_PARTS)
        or any(
            token in name for token in
            ("prompt", "agent", "tool", "mcp", "rag", "embedding", "notebook",
             "model", "jupyter", "kube", "guardrail", "policy")
        )
    )


def artifact_category(path: Path) -> str | None:
    special = SPECIAL_ARTIFACT_NAMES.get(path.name.lower())
    if special:
        return special
    suffix = path.suffix.lower()
    if suffix in RAG_STORE_SUFFIXES and any(
            token in str(path).lower() for token in ("chroma", "faiss", "vector", "rag", "index")):
        return "rag-store"
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
    if path.suffix.lower() in {".timer", ".socket"}:
        return "systemd-unit"
    if path.suffix.lower() == ".ipynb":
        return "jupyter-notebook"
    if name.startswith("kernel-") and path.suffix.lower() == ".json":
        return "jupyter-runtime"
    if name in {"config", "token", "namespace", "ca.crt"} and "serviceaccount" in str(path).lower():
        return "kubernetes-service-account"
    if name in HISTORY_NAMES:
        return "shell-history"
    if name == "config" and ".kube" in str(path).lower():
        return "kubeconfig"
    if name in {"credentials", "application_default_credentials.json", "azureprofile.json"}:
        return "cloud-credentials"
    if any(part in str(path).lower().replace("\\", "/") for part in SECRET_MOUNT_PARTS):
        return "mounted-secret"
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
                    bucket = buckets[path_priority(root)]
                    if len(bucket) < max_files:
                        bucket.append(root)
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
                bucket = buckets[path_priority(path)]
                if len(bucket) < max_files:
                    bucket.append(path)
                candidates_seen += 1
    selected = [item for priority in range(4) for item in buckets[priority]][:max_files]
    return selected, candidates_seen, candidates_seen > len(selected)


def load_text(path: Path, max_bytes: int) -> str | None:
    try:
        if not path.is_file():
            return None
        size = path.stat().st_size
        with path.open("rb") as handle:
            if size <= max_bytes:
                raw = handle.read(max_bytes)
            else:
                head_size = max_bytes // 3
                tail_size = max_bytes - head_size
                head = handle.read(head_size)
                handle.seek(max(0, size - tail_size))
                tail = handle.read(tail_size)
                raw = head + b"\n[... AI-PEAS bounded sample omitted middle ...]\n" + tail
        return raw.decode("utf-8", errors="replace")
    except OSError:
        return None


def extract_urlish(line: str) -> str | None:
    match = re.search(r"(https?://[^\s\"']+|s3://[^\s\"']+|[A-Za-z0-9_.-]+:\d{2,5})", line)
    return match.group(1).rstrip(",);]") if match else None


def classify_tool_risk(text: str) -> list[str]:
    lower = text.lower()
    return sorted(name for name, words in TOOL_RISK_KEYWORDS.items() if any(word in lower for word in words))


def decode_jwt_claims(value: str) -> dict[str, Any] | None:
    parts = value.strip().split(".")
    if len(parts) != 3:
        return None
    try:
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(claims, dict):
        return None
    useful = {}
    for key in ("iss", "sub", "aud", "exp", "iat", "nbf"):
        if key in claims:
            useful[key] = claims[key]
    kubernetes = claims.get("kubernetes.io")
    if isinstance(kubernetes, dict):
        useful["kubernetes.io"] = kubernetes
    for key, item in claims.items():
        if "serviceaccount" in str(key).lower() or "namespace" in str(key).lower():
            useful[str(key)] = item
    return useful or {"claim_keys": sorted(str(key) for key in claims)[:30]}


def current_identity() -> dict[str, Any]:
    identity: dict[str, Any] = {
        "path": "runtime:identity",
        "kind": "current-identity",
        "username": os.environ.get("USERNAME") or os.environ.get("USER"),
    }
    for name in ("getuid", "geteuid", "getgid", "getegid"):
        function = getattr(os, name, None)
        if function:
            try:
                identity[name[3:]] = function()
            except OSError:
                pass
    getgroups = getattr(os, "getgroups", None)
    if getgroups:
        try:
            identity["groups"] = getgroups()
        except OSError:
            pass
    try:
        identity["cwd"] = os.getcwd()
    except OSError:
        pass
    return identity


def _linux_socket_rows(table: Path, ipv6: bool = False) -> list[dict[str, Any]]:
    rows = []
    try:
        lines = table.read_text(encoding="ascii", errors="replace").splitlines()[1:]
    except OSError:
        return rows
    for line in lines:
        fields = line.split()
        if len(fields) < 10 or fields[3] != "0A":
            continue
        try:
            address_hex, port_hex = fields[1].split(":")
            if ipv6:
                packed = bytes.fromhex(address_hex)
                address = socket.inet_ntop(socket.AF_INET6, b"".join(
                    packed[index:index + 4][::-1] for index in range(0, 16, 4)
                ))
            else:
                address = socket.inet_ntoa(struct.pack("<I", int(address_hex, 16)))
            rows.append({
                "address": address,
                "port": int(port_hex, 16),
                "inode": fields[9],
                "protocol": "tcp6" if ipv6 else "tcp",
            })
        except (ValueError, OSError):
            continue
    return rows


def collect_linux_listeners(out: dict[str, list[dict[str, Any]]],
                            process_details: dict[int, dict[str, Any]]) -> None:
    if os.name == "nt" or not Path("/proc/net").is_dir():
        return
    inode_to_pid: dict[str, int] = {}
    for pid in process_details:
        fd_root = Path(f"/proc/{pid}/fd")
        try:
            entries = list(fd_root.iterdir())
        except OSError:
            continue
        for descriptor in entries[:4096]:
            try:
                target = os.readlink(descriptor)
            except OSError:
                continue
            match = re.fullmatch(r"socket:\[(\d+)\]", target)
            if match:
                inode_to_pid.setdefault(match.group(1), pid)
    rows = _linux_socket_rows(Path("/proc/net/tcp"))
    rows.extend(_linux_socket_rows(Path("/proc/net/tcp6"), ipv6=True))
    for row in rows:
        pid = inode_to_pid.get(row.pop("inode"))
        detail = process_details.get(pid or -1, {})
        joined = " ".join(str(detail.get(key) or "") for key in ("command", "process_name", "exe"))
        if not RUNTIME_CONTEXT_RE.search(joined):
            continue
        out["listeners"].append({
            "path": f"listener:{row['address']}:{row['port']}",
            "kind": "listening-socket",
            **row,
            "pid": pid,
            "process_name": detail.get("process_name"),
            "command": detail.get("command"),
            "user": detail.get("user"),
        })


def collect_windows_listeners(out: dict[str, list[dict[str, Any]]],
                              processes: dict[int, dict[str, Any]]) -> None:
    if os.name != "nt":
        return
    try:
        iphlpapi = ctypes.windll.iphlpapi
        size = ctypes.c_ulong(0)
        result = iphlpapi.GetExtendedTcpTable(None, ctypes.byref(size), False, 2, 3, 0)
        if result not in (0, 122):
            return
        buffer = ctypes.create_string_buffer(size.value)
        if iphlpapi.GetExtendedTcpTable(buffer, ctypes.byref(size), False, 2, 3, 0) != 0:
            return
        count = struct.unpack_from("<I", buffer.raw, 0)[0]
        for index in range(min(count, 4096)):
            state, address, port_raw, _, _, pid = struct.unpack_from(
                "<6I", buffer.raw, 4 + index * 24
            )
            if state != 2:
                continue
            detail = processes.get(pid, {})
            joined = " ".join(str(detail.get(key) or "") for key in ("process_name", "command"))
            if not RUNTIME_CONTEXT_RE.search(joined):
                continue
            port = socket.ntohs(port_raw & 0xFFFF)
            host = socket.inet_ntoa(struct.pack("<I", address))
            out["listeners"].append({
                "path": f"listener:{host}:{port}",
                "kind": "listening-socket",
                "protocol": "tcp",
                "address": host,
                "port": port,
                "pid": pid,
                "process_name": detail.get("process_name"),
            })
    except (AttributeError, OSError, ValueError, struct.error):
        return


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
    cloud_identity_names = {
        "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
        "AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_DEFAULT_REGION", "AWS_REGION",
        "AZURE_CLIENT_ID", "AZURE_TENANT_ID", "MSI_ENDPOINT", "IDENTITY_ENDPOINT",
        "GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_CLOUD_PROJECT", "GCP_PROJECT",
        "KUBERNETES_SERVICE_HOST", "KUBERNETES_SERVICE_PORT",
    }
    for name, value in os.environ.items():
        assignment = f"{name}={value}"
        secret_match = SECRET_NAME_RE.search(assignment)
        generic_match = GENERIC_SECRET_RE.search(assignment)
        if secret_match:
            out["secrets"].append({
                "path": f"environment:{name}",
                "snippet": clean_snippet(assignment, redact_secret_values),
                "name": secret_match.group(1).upper(),
                "value": redact_value(secret_match.group(2), redact_secret_values),
            })
        elif generic_match:
            out["secrets"].append({
                "path": f"environment:{name}",
                "snippet": clean_snippet(assignment, redact_secret_values),
                "name": generic_match.group(1).upper().replace("-", "_"),
                "value": redact_value(generic_match.group(2), redact_secret_values),
                "generic": True,
            })
        if name.upper() in cloud_identity_names:
            out["cloud_identities"].append({
                "path": f"environment:{name}",
                "kind": "cloud-or-cluster-environment",
                "name": name,
                "value": clean_snippet(value, redact_secret_values),
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
                                  redact_secret_values: bool,
                                  limit: int = 1024) -> dict[int, dict[str, Any]]:
    details: dict[int, dict[str, Any]] = {}
    proc = Path("/proc")
    if os.name == "nt" or not proc.is_dir():
        return details
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
            pid = int(entry.name)
            detail: dict[str, Any] = {
                "path": f"/proc/{entry.name}/cmdline",
                "kind": "running-process",
                "pid": pid,
                "command": clean_snippet(command, redact_secret_values),
                "process_name": Path(command.split()[0]).name if command.split() else None,
            }
            try:
                detail["cwd"] = os.readlink(entry / "cwd")
            except OSError:
                pass
            try:
                detail["exe"] = os.readlink(entry / "exe")
            except OSError:
                pass
            try:
                status = (entry / "status").read_text(encoding="utf-8", errors="replace")
                uid_match = re.search(r"(?m)^Uid:\s+(\d+)", status)
                if uid_match:
                    uid = int(uid_match.group(1))
                    detail["uid"] = uid
                    if pwd is not None:
                        try:
                            detail["user"] = pwd.getpwuid(uid).pw_name
                        except KeyError:
                            pass
            except OSError:
                pass
            try:
                cgroup = (entry / "cgroup").read_text(encoding="utf-8", errors="replace").strip()
                if cgroup:
                    detail["cgroup"] = clean_snippet(cgroup, redact_secret_values)
            except OSError:
                pass
            try:
                environ = (entry / "environ").read_bytes().split(b"\0")
            except OSError:
                environ = []
            environment_names = []
            for raw_assignment in environ[:4096]:
                assignment = raw_assignment.decode("utf-8", "replace")
                if "=" not in assignment:
                    continue
                name, value = assignment.split("=", 1)
                match = SECRET_NAME_RE.search(assignment) or GENERIC_SECRET_RE.search(assignment)
                if match:
                    out["secrets"].append({
                        "path": f"/proc/{pid}/environ:{name}",
                        "snippet": clean_snippet(assignment, redact_secret_values),
                        "name": name.upper(),
                        "value": redact_value(value, redact_secret_values),
                        "process_pid": pid,
                    })
                    environment_names.append(name)
            if environment_names:
                detail["sensitive_environment_names"] = sorted(set(environment_names))
            details[pid] = detail
            out["runtime_context"].append(detail)
    return details


def collect_windows_process_context(out: dict[str, list[dict[str, Any]]],
                                    limit: int = 1024) -> dict[int, dict[str, Any]]:
    details: dict[int, dict[str, Any]] = {}
    if os.name != "nt":
        return details

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
                details[int(entry.th32ProcessID)] = out["runtime_context"][-1]
            count += 1
            ok = ctypes.windll.kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        ctypes.windll.kernel32.CloseHandle(snapshot)
    return details


def file_fingerprint(path: Path, full_limit: int = 8 * 1024 * 1024) -> dict[str, Any]:
    try:
        size = path.stat().st_size
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            if size <= full_limit:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
                return {"sha256": digest.hexdigest(), "hash_scope": "full"}
            head = handle.read(1024 * 1024)
            handle.seek(max(0, size - 1024 * 1024))
            tail = handle.read(1024 * 1024)
            digest.update(str(size).encode("ascii"))
            digest.update(head)
            digest.update(tail)
            return {"sha256": digest.hexdigest(), "hash_scope": "size+head+tail"}
    except OSError:
        return {}


def inspect_archive(path: Path) -> dict[str, Any]:
    if path.suffix.lower() not in {".zip", ".whl", ".egg"}:
        return {}
    try:
        with zipfile.ZipFile(path) as archive:
            members = archive.infolist()[:500]
            names = [member.filename for member in members]
            interesting = [
                name for name in names
                if any(token in name.lower() for token in (
                    "entry_points", "plugin", "tool", "mcp", "agent", "model",
                    "pickle", "joblib", "setup.py", "__init__.py",
                ))
            ]
            return {
                "archive_member_count": len(archive.infolist()),
                "archive_members": names[:100],
                "interesting_members": interesting[:100],
            }
    except (OSError, zipfile.BadZipFile, RuntimeError):
        return {"archive_inspection_error": "unreadable-or-invalid-zip"}


def collect_git_context(roots: list[str], out: dict[str, list[dict[str, Any]]],
                        redact_secret_values: bool, limit: int = 100) -> None:
    repositories = 0
    seen = set()
    for root_value in roots:
        root = Path(root_value).expanduser()
        if not root.is_dir():
            continue
        for current, dirs, _ in os.walk(root):
            dirs[:] = [
                directory for directory in dirs
                if directory == ".git" or directory not in SKIP_DIRS
            ]
            if repositories >= limit:
                return
            git_dir = Path(current) / ".git"
            if ".git" in dirs and git_dir.is_dir():
                dirs.remove(".git")
                resolved = str(git_dir.resolve())
                if resolved in seen:
                    continue
                seen.add(resolved)
                repositories += 1
                config = load_text(git_dir / "config", 256 * 1024) or ""
                head = load_text(git_dir / "HEAD", 16 * 1024) or ""
                remotes = re.findall(r"(?m)^\s*url\s*=\s*(.+?)\s*$", config)
                branch = None
                head_match = re.search(r"ref:\s+refs/heads/(.+)", head)
                if head_match:
                    branch = head_match.group(1).strip()
                branches = []
                refs = git_dir / "refs" / "heads"
                if refs.is_dir():
                    try:
                        branches = [
                            str(item.relative_to(refs)).replace("\\", "/")
                            for item in refs.rglob("*") if item.is_file()
                        ][:100]
                    except OSError:
                        pass
                packed = load_text(git_dir / "packed-refs", 256 * 1024) or ""
                branches.extend(re.findall(r"(?m)^[0-9a-f]+\s+refs/heads/(.+)$", packed))
                out["developer_context"].append({
                    "path": str(Path(current)),
                    "kind": "git-repository",
                    "current_branch": branch,
                    "branches": sorted(set(branches))[:100],
                    "remotes": [
                        clean_snippet(remote, redact_secret_values)
                        for remote in remotes[:20]
                    ],
                    **write_state(Path(current)),
                })


def inspect_kubernetes_identity(path: Path, text: str,
                                out: dict[str, list[dict[str, Any]]],
                                redact_secret_values: bool) -> None:
    normalized = str(path).lower().replace("\\", "/")
    is_service_account = "serviceaccount" in normalized and path.name.lower() in {
        "token", "namespace", "ca.crt"
    }
    kubeconfig_signal = (
        path.name.lower() in {"kubeconfig", "config"} and ".kube" in normalized
    ) or (
        re.search(r"(?m)^apiVersion:\s*v1\s*$", text)
        and re.search(r"(?m)^kind:\s*Config\s*$", text)
        and "current-context:" in text
    )
    if is_service_account:
        record = {
            **source_record(path),
            "kind": "kubernetes-service-account",
            "component": path.name.lower(),
            **write_state(path),
        }
        if path.name.lower() == "namespace":
            record["namespace"] = clean_snippet(text, redact_secret_values)
        for jwt_match in JWT_RE.finditer(text):
            record["jwt_claims"] = decode_jwt_claims(jwt_match.group(1))
            record["token"] = redact_value(jwt_match.group(1), redact_secret_values)
            break
        out["cloud_identities"].append(record)
    if kubeconfig_signal:
        contexts = re.findall(r"(?m)^\s*-\s*name:\s*([^\s#]+)", text)
        servers = re.findall(r"(?m)^\s*server:\s*([^\s#]+)", text)
        current = re.search(r"(?m)^\s*current-context:\s*([^\s#]+)", text)
        users = re.findall(r"(?m)^\s*user:\s*([^\s#]+)", text)
        record = {
            **source_record(path),
            "kind": "kubeconfig",
            "current_context": current.group(1) if current else None,
            "named_entries": contexts[:30],
            "servers": servers[:20],
            "users": users[:30],
            "has_client_certificate_data": "client-certificate-data:" in text,
            "has_client_key_data": "client-key-data:" in text,
            "has_token": bool(re.search(r"(?m)^\s*token:\s*\S+", text)),
            **write_state(path),
        }
        out["cloud_identities"].append(record)


def inspect_rag_sqlite(path: Path, out: dict[str, list[dict[str, Any]]],
                       redact_secret_values: bool) -> None:
    normalized = str(path).lower()
    if not any(token in normalized for token in ("chroma", "rag", "vector", "embedding")):
        return
    record: dict[str, Any] = {
        **source_record(path),
        "kind": ("sqlite-rag-store"
                 if path.suffix.lower() in {".sqlite", ".sqlite3", ".db"}
                 else "local-rag-artifact"),
        **write_state(path),
        **file_fingerprint(path),
    }
    if path.suffix.lower() not in {".sqlite", ".sqlite3", ".db"}:
        out["rag_stores"].append(record)
        return
    try:
        uri = path.resolve().as_uri() + "?mode=ro"
        connection = sqlite3.connect(uri, uri=True, timeout=1)
        try:
            table_rows = connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name LIMIT 50"
            ).fetchall()
            tables = [str(row[0]) for row in table_rows]
            record["tables"] = tables
            schemas = {}
            samples = []
            for table in tables[:20]:
                quoted = '"' + table.replace('"', '""') + '"'
                columns = [
                    str(row[1]) for row in connection.execute(
                        f"PRAGMA table_info({quoted})"
                    ).fetchall()[:50]
                ]
                schemas[table] = columns
                text_columns = [
                    column for column in columns
                    if any(token in column.lower() for token in
                           ("document", "text", "content", "metadata", "source", "collection", "name"))
                ]
                if text_columns:
                    selected = ", ".join('"' + col.replace('"', '""') + '"' for col in text_columns[:4])
                    try:
                        rows = connection.execute(
                            f"SELECT {selected} FROM {quoted} LIMIT 3"
                        ).fetchall()
                    except sqlite3.DatabaseError:
                        rows = []
                    for row in rows:
                        value = clean_snippet(" | ".join(str(item) for item in row), redact_secret_values)
                        if value:
                            samples.append({"table": table, "value": value})
            record["schemas"] = schemas
            record["plaintext_samples"] = samples[:20]
        finally:
            connection.close()
    except (OSError, sqlite3.DatabaseError, ValueError):
        record["inspection_error"] = "unreadable-or-not-sqlite"
    out["rag_stores"].append(record)


def _call_name(node: ast.AST) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def inspect_python_source(path: Path, text: str,
                          out: dict[str, list[dict[str, Any]]]) -> None:
    if path.suffix.lower() != ".py":
        return
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return
    imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.append(node.module)
    framework_context = any(
        token in imported.lower()
        for imported in imports
        for token in ("mcp", "langchain", "llama_index", "crewai", "autogen", "semantic_kernel")
    ) or bool(AI_CONTEXT_RE.search(text[:200000]))
    if framework_context:
        for imported in sorted(set(imports)):
            top_level = imported.split(".", 1)[0]
            candidates = [path.parent / f"{top_level}.py", path.parent / top_level / "__init__.py"]
            for candidate in candidates:
                if candidate.is_file() and write_state(candidate)["writable"]:
                    out["pipeline_consumers"].append({
                        **source_record(candidate),
                        "signal": "writable-python-import",
                        "module": imported,
                        "consumer": str(path),
                        **write_state(candidate),
                    })
                    break
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        decorators = [_call_name(item.func if isinstance(item, ast.Call) else item)
                      for item in node.decorator_list]
        is_tool = any(
            token in decorator.lower()
            for decorator in decorators
            for token in ("mcp.tool", "fastmcp.tool", "server.tool", "tool", "function_tool")
        ) and framework_context
        if not is_tool:
            continue
        calls = sorted({
            _call_name(item.func)
            for item in ast.walk(node)
            if isinstance(item, ast.Call) and _call_name(item.func)
        })
        description = ast.get_docstring(node) or ""
        joined = " ".join([node.name, description, *calls, *imports])
        out["mcp_tools"].append({
            **source_record(path, getattr(node, "lineno", None), description),
            "name": node.name,
            "context": "python-source",
            "decorators": decorators,
            "parameters": [argument.arg for argument in node.args.args],
            "calls": calls[:50],
            "imports": sorted(set(imports))[:50],
            "risk_categories": classify_tool_risk(joined),
            **write_state(path),
        })


def project_scope(path: str) -> str:
    candidate = Path(path)
    if not candidate.is_absolute() and ":" in path and not re.match(r"^[A-Za-z]:[\\/]", path):
        return path
    parent = candidate.parent
    for directory in [parent, *list(parent.parents)[:4]]:
        try:
            if any((directory / marker).exists() for marker in PROJECT_MARKERS):
                return str(directory)
        except OSError:
            continue
    if parent.name.lower() in {"models", "model", "artifacts", "data", "rag", "prompts", "config"}:
        return str(parent.parent)
    return str(parent)


def build_application_chains(out: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    categories = (
        "secrets", "vector_stores", "rag_sources", "mlflow", "object_stores",
        "mcp_tools", "agent_manifests", "unsafe_loaders", "model_artifacts",
        "rag_stores", "pipeline_consumers", "guardrail_rules", "cloud_identities",
        "developer_context",
    )
    by_scope: dict[str, set[str]] = {}
    samples: dict[str, list[dict[str, Any]]] = {}
    paths: dict[str, set[str]] = {}
    for category in categories:
        for item in out.get(category, []):
            if not isinstance(item, dict) or not item.get("path"):
                continue
            path = str(item["path"])
            scope = project_scope(path)
            by_scope.setdefault(scope, set()).add(category)
            paths.setdefault(scope, set()).add(path)
            samples.setdefault(scope, []).append(item)
    chains = []
    anchors = {"secrets", "unsafe_loaders", "model_artifacts", "mcp_tools"}
    for scope, signals in by_scope.items():
        if len(signals) < 2 or not signals.intersection(anchors):
            continue
        chains.append({
            "path": scope,
            "paths": sorted(paths[scope])[:20],
            "signals": sorted(signals),
            "signal_count": len(signals),
            "samples": samples[scope][:10],
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
                                    "description": str(desc)[:1000],
                                    "parameters": item.get("parameters") or item.get("inputSchema"),
                                    "output_schema": item.get("outputSchema"),
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
                "command": server.get("command") if isinstance(server, dict) else None,
                "args": server.get("args") if isinstance(server, dict) else None,
                "risk_categories": classify_tool_risk(text_blob),
            })

    if isinstance(data, dict) and any(k in data for k in ("capabilities", "skills", "endpoint", "agentCard")):
        out["agent_manifests"].append({
            **source_record(path),
            "name": data.get("name") or data.get("id"),
            "url": data.get("url") or data.get("endpoint"),
            "authentication": data.get("authentication") or data.get("auth"),
            "capabilities": data.get("capabilities"),
            "keys": sorted(str(k) for k in data.keys())[:30],
            "risk_categories": classify_tool_risk(json.dumps(data)[:2000]),
            **write_state(path),
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
    inspect_kubernetes_identity(path, text, out, redact_secret_values)
    if path.suffix.lower() == ".ipynb":
        text = notebook_text(path, text, out, redact_secret_values)
    inspect_json_structure(path, text, out)
    inspect_python_source(path, text, out)

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
        named_secret_spans = []
        for match in SECRET_NAME_RE.finditer(line):
            named_secret_spans.append(match.span())
            out["secrets"].append({
                **source_record(path, line_number, cleaned),
                "name": match.group(1).upper(),
                "value": redact_value(match.group(2), redact_secret_values),
            })
        if kind or file_has_ai_context:
            for match in GENERIC_SECRET_RE.finditer(line):
                if any(start <= match.start() < end for start, end in named_secret_spans):
                    continue
                out["secrets"].append({
                    **source_record(path, line_number, cleaned),
                    "name": match.group(1).upper().replace("-", "_"),
                    "value": redact_value(match.group(2), redact_secret_values),
                    "generic": True,
                })
            for match in TOKEN_VALUE_RE.finditer(line):
                out["secrets"].append({
                    **source_record(path, line_number, cleaned),
                    "name": "TOKEN_VALUE",
                    "value": redact_value(match.group(1), redact_secret_values),
                    "token_format": match.group(1).split("-", 1)[0],
                })
            for match in JWT_RE.finditer(line):
                out["cloud_identities"].append({
                    **source_record(path, line_number, cleaned),
                    "kind": "jwt-token",
                    "claims": decode_jwt_claims(match.group(1)),
                    "token": redact_value(match.group(1), redact_secret_values),
                })
            for match in URL_CREDENTIAL_RE.finditer(line):
                out["secrets"].append({
                    **source_record(path, line_number, cleaned),
                    "name": "URL_CREDENTIAL",
                    "username": match.group(1).split("://", 1)[1],
                    "value": redact_value(match.group(2), redact_secret_values),
                })
            if PRIVATE_KEY_RE.search(line):
                out["secrets"].append({
                    **source_record(path, line_number, cleaned),
                    "name": "PRIVATE_KEY",
                    "value": {"present": True, "redacted": redact_secret_values},
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
        if GUARDRAIL_RE.search(line) and (file_has_ai_context or "guard" in lower_name):
            out["guardrail_rules"].append({
                **source_record(path, line_number, cleaned),
                "writable": write_state(path)["writable"],
            })
        if PIPELINE_RE.search(line) and file_has_ai_context:
            out["pipeline_consumers"].append({
                **source_record(path, line_number, cleaned),
                "signal": PIPELINE_RE.search(line).group(1),
                "writable": write_state(path)["writable"],
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
        "listeners": [],
        "cloud_identities": [],
        "rag_stores": [],
        "pipeline_consumers": [],
        "guardrail_rules": [],
        "developer_context": [],
        "application_chains": [],
    }

    def progress(message: str) -> None:
        if not args.quiet:
            print(message, flush=True)

    progress(f"[*] AI-PEAS starting on {len(roots)} root(s)")
    progress("[*] Collecting readable environment and runtime context")
    identity = current_identity()
    collect_environment(findings, args.redact_secret_values)
    linux_processes = collect_linux_process_context(findings, args.redact_secret_values)
    windows_processes = collect_windows_process_context(findings)
    collect_linux_listeners(findings, linux_processes)
    collect_windows_listeners(findings, windows_processes)
    collect_git_context(roots, findings, args.redact_secret_values)

    files, candidates_seen, file_limit_reached = walk_paths(
        roots, max(1, args.max_files), excluded=Path(args.out)
    )
    progress(f"[*] Selected {len(files)} relevant file(s) from {candidates_seen} candidate(s)")
    if file_limit_reached:
        progress(f"[!] Candidate limit applied; higher-priority AI/config files were retained first")
    skipped_errors = 0
    skipped_error_samples = []
    oversized_sampled = 0
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
                    **file_fingerprint(path),
                    **inspect_archive(path),
                }
                findings["model_artifacts"].append(record)
                if category == "rag-store":
                    inspect_rag_sqlite(path, findings, args.redact_secret_values)

            if not is_text_candidate(path):
                added = [key for key, value in findings.items() if len(value) > before[key]]
                if added and progress_events < 200:
                    progress(f"[+] {path}: {', '.join(added)}")
                    progress_events += 1
                continue
            text_limit = max_notebook_bytes if path.suffix.lower() == ".ipynb" else max_bytes
            try:
                if path.stat().st_size > text_limit:
                    oversized_sampled += 1
            except OSError:
                pass
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
        except Exception as exc:
            skipped_errors += 1
            if len(skipped_error_samples) < 50:
                skipped_error_samples.append({
                    "path": str(path),
                    "error": type(exc).__name__,
                })
            continue

    findings["application_chains"] = build_application_chains(findings)
    findings = {key: dedupe_records(value) for key, value in findings.items()}

    payload = {
        "tool": TOOL_NAME,
        "type": "ai_post_exploitation_loot",
        "schema_version": SCHEMA_VERSION,
        "host": socket.gethostname(),
        "platform": platform.platform(),
        "identity": identity,
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
            "skipped_error_samples": skipped_error_samples,
            "oversized_files_sampled": oversized_sampled,
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
