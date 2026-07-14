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
import datetime as dt
import hashlib
import json
import os
import platform
import re
import socket
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "1.0"
TOOL_NAME = "ai-peas"

SKIP_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", ".pytest_cache", ".mypy_cache",
    ".venv", "venv", "env", "node_modules", "dist", "build", ".tox",
}

TEXT_SUFFIXES = {
    ".env", ".txt", ".log", ".json", ".jsonl", ".yaml", ".yml", ".toml",
    ".ini", ".cfg", ".conf", ".config", ".py", ".ps1", ".sh", ".js", ".ts",
    ".tsx", ".jsx", ".md", ".sql", ".xml", ".properties",
}

CONFIG_NAMES = {
    ".env", "docker-compose.yml", "docker-compose.yaml", "compose.yml",
    "compose.yaml", "config.json", "config.yaml", "config.yml",
    "settings.py", "appsettings.json", "MLmodel", "conda.yaml",
    "python_env.yaml", "requirements.txt", "pyproject.toml",
    "jupyter_notebook_config.py", "jupyter_server_config.py",
}

SECRET_NAME_RE = re.compile(
    r"\b("
    r"OPENAI_API_KEY|ANTHROPIC_API_KEY|AZURE_OPENAI_API_KEY|"
    r"HF_TOKEN|HUGGINGFACEHUB_API_TOKEN|PINECONE_API_KEY|QDRANT_API_KEY|"
    r"WEAVIATE_API_KEY|COHERE_API_KEY|GOOGLE_API_KEY|LANGCHAIN_API_KEY|"
    r"LANGSMITH_API_KEY|MLFLOW_TRACKING_TOKEN|MLFLOW_TRACKING_PASSWORD|"
    r"AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|"
    r"MINIO_ACCESS_KEY|MINIO_SECRET_KEY|S3_ACCESS_KEY|S3_SECRET_KEY|"
    r"JUPYTER_TOKEN|DATABASE_URL|REDIS_URL"
    r")\b\s*(?:=|:)\s*([^\s#]+)?",
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
    ("qdrant", re.compile(r"\b(QDRANT_URL|QDRANT_HOST|qdrant[_\-.]?(?:url|host)|:6333\b)", re.I)),
    ("chroma", re.compile(r"\b(CHROMA_|chroma[_\-.]?(?:url|host|persist|collection))", re.I)),
    ("weaviate", re.compile(r"\b(WEAVIATE_|weaviate[_\-.]?(?:url|host)|:8080\b)", re.I)),
    ("milvus", re.compile(r"\b(MILVUS_|milvus[_\-.]?(?:uri|host)|:19530\b)", re.I)),
    ("opensearch", re.compile(r"\b(OPENSEARCH_|opensearch[_\-.]?(?:url|host)|:9200\b)", re.I)),
    ("elasticsearch", re.compile(r"\b(ELASTICSEARCH_|elasticsearch[_\-.]?(?:url|host)|:9200\b)", re.I)),
    ("pinecone", re.compile(r"\b(PINECONE_|pinecone[_\-.]?(?:index|environment))", re.I)),
]

MLFLOW_RE = re.compile(r"\b(MLFLOW_|mlflow[_\-.]?(?:tracking|artifact|registry)|artifact_uri|runs:/|models:/)", re.I)
OBJECT_STORE_RE = re.compile(r"\b(S3_|MINIO_|AWS_|s3://|endpoint_url|S3_ENDPOINT_URL|AWS_ENDPOINT_URL)", re.I)
RAG_RE = re.compile(r"\b(rag|retriever|vectorstore|vector_store|embedding|embeddings|knowledge[_\-. ]?base|chunk|loader|document[_\-. ]?store)", re.I)
MCP_RE = re.compile(r"\b(mcpServers|mcp_server|Model Context Protocol|/mcp|tools/list|tool_call|function_call|agent_card|\.well-known/agent\.json)", re.I)
NOTEBOOK_RE = re.compile(r"\b(jupyter|notebook|ipynb|JUPYTER_TOKEN|/api/kernels|/api/sessions)", re.I)
PROMPT_RE = re.compile(r"\b(system_prompt|prompt_template|instructions|developer_prompt|agent_prompt|guardrail|policy_prompt)", re.I)

UNSAFE_LOADER_PATTERNS = {
    "pickle.load": re.compile(r"\bpickle\.loads?\s*\("),
    "torch.load": re.compile(r"\btorch\.load\s*\("),
    "joblib.load": re.compile(r"\bjoblib\.load\s*\("),
    "pandas.read_pickle": re.compile(r"\b(?:pandas|pd)\.read_pickle\s*\("),
    "yaml.unsafe_load": re.compile(r"\byaml\.(?:unsafe_load|load)\s*\("),
    "trust_remote_code": re.compile(r"trust_remote_code\s*=\s*True"),
    "dynamic import": re.compile(r"\b(?:importlib\.import_module|__import__)\s*\("),
    "subprocess/shell": re.compile(r"\b(?:subprocess\.(?:run|Popen|call)|os\.system)\s*\("),
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
    parser.add_argument("-o", "--out", default="ai_loot.json", help="Output JSON path")
    parser.add_argument("--common-roots", action="store_true",
                        help="Also inspect common app/config roots for this OS")
    parser.add_argument("--max-files", type=int, default=50000, help="Maximum files to inspect")
    parser.add_argument("--max-file-kb", type=int, default=512,
                        help="Maximum text/config file size to read")
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
        token in name.lower() for token in ("prompt", "agent", "tool", "mcp", "rag", "embedding")
    )


def artifact_category(path: Path) -> str | None:
    return SPECIAL_ARTIFACT_NAMES.get(path.name.lower()) or ARTIFACT_SUFFIXES.get(path.suffix.lower())


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


def walk_paths(roots: list[str], max_files: int) -> list[Path]:
    seen: set[str] = set()
    files: list[Path] = []
    for root_value in roots:
        root = Path(root_value).expanduser()
        if not root.exists():
            continue
        if root.is_file():
            resolved = str(root.resolve())
            if resolved not in seen:
                seen.add(resolved)
                files.append(root)
            continue
        for current, dirs, names in os.walk(root):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.endswith("-output")]
            for name in names:
                path = Path(current) / name
                resolved = str(path.resolve())
                if resolved in seen:
                    continue
                seen.add(resolved)
                files.append(path)
                if len(files) >= max_files:
                    return files
    return files


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
    inspect_json_structure(path, text, out)

    if any(token in lower_name for token in ("prompt", "system", "instruction", "template")):
        first_line = text.splitlines()[0] if text.splitlines() else ""
        out["prompt_templates"].append({
            **source_record(path, snippet=clean_snippet(first_line, redact_secret_values)),
            "reason": "prompt-like filename",
        })

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
        if RAG_RE.search(line):
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
            if pattern.search(line):
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
    }

    files = walk_paths(roots, args.max_files)
    skipped_errors = 0
    for path in files:
        try:
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
                continue
            text = load_text(path, max_bytes)
            if text is None:
                continue
            inspect_text_file(path, text, findings, args.redact_secret_values)
        except Exception:
            skipped_errors += 1
            continue

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
            "secret_values_redacted": args.redact_secret_values,
        },
        "stats": {
            "files_seen": len(files),
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
    print(f"[+] Wrote {out_path} ({len(files)} files seen)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
