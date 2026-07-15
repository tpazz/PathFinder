"""Self-contained HTML engagement report generation for PathFinder."""

import html
import json
import os
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse


DEFAULT_REPORT_NAME = "pathfinder-report.html"
_SECRET_FIELDS = {
    "password", "pass", "passwd", "pwd", "hash", "nt_hash", "lm_hash",
    "ntlm_hash", "aes128_key", "aes256_key", "kerberos_key", "private_key",
    "secret", "token", "access_token", "refresh_token", "api_key", "apikey",
    "dpapi", "credential", "credentials",
}
_COMMAND_FIELDS = {"command", "commands", "producer_command"}
_COMMAND_SECRET_OPTION = re.compile(
    r"(?P<option>(?:^|\s)(?:(?i:-p|--password|--pass|--passwd|--pwd|"
    r"--hash|--hashes|-hashes|--api-key|--apikey|--token|--secret)|-H)\s+)"
    r"(?P<value>'[^']*'|\"[^\"]*\"|\S+)"
)
_COMMAND_ASSIGNMENT = re.compile(
    r"(?i)(?P<name>\b(?:password|passwd|pwd|token|api[_-]?key|secret)=)"
    r"(?P<value>[^\s;&]+)"
)
_URL_USERINFO = re.compile(r"(?i)(://[^:/\s]+:)([^@/\s]+)(@)")
_BEARER_TOKEN = re.compile(r"(?i)(\bBearer\s+)([^\s'\"]+)")
_ACCOUNT_PASSWORD = re.compile(
    r"(?P<prefix>(?:^|\s|'|\")[A-Za-z0-9_.@\\-]+/[A-Za-z0-9_.$@\\-]+:)"
    r"(?P<secret>[^@\s'\"]+)(?P<suffix>@)"
)


class _Redactor:
    def __init__(self, findings, include_secrets=True):
        self.include_secrets = bool(include_secrets)
        self.secret_values = []
        if not self.include_secrets:
            discovered = set()
            for finding in findings or []:
                self._collect((finding or {}).get("attributes") or {}, discovered)
            self.secret_values = sorted(discovered, key=len, reverse=True)

    def _collect(self, value, discovered, field=None):
        if isinstance(value, dict):
            for key, nested in value.items():
                self._collect(nested, discovered, str(key).lower())
            return
        if isinstance(value, list):
            for nested in value:
                self._collect(nested, discovered, field)
            return
        if field in _SECRET_FIELDS and value not in (None, ""):
            text = str(value)
            if len(text) >= 3:
                discovered.add(text)

    def text(self, value, field=None, command=False):
        if value is None:
            return ""
        text = str(value)
        if self.include_secrets:
            return text
        if str(field or "").lower() in _SECRET_FIELDS and text:
            return "[REDACTED]"
        for secret in self.secret_values:
            text = text.replace(secret, "[REDACTED]")
        if command:
            text = _COMMAND_SECRET_OPTION.sub(
                lambda match: f"{match.group('option')}[REDACTED]", text,
            )
            text = _COMMAND_ASSIGNMENT.sub(
                lambda match: f"{match.group('name')}[REDACTED]", text,
            )
            text = _URL_USERINFO.sub(r"\1[REDACTED]\3", text)
            text = _BEARER_TOKEN.sub(r"\1[REDACTED]", text)
            text = _ACCOUNT_PASSWORD.sub(
                lambda match: f"{match.group('prefix')}[REDACTED]{match.group('suffix')}",
                text,
            )
        return text

    def structured(self, value, field=None):
        if self.include_secrets:
            return value
        if str(field or "").lower() in _SECRET_FIELDS and value not in (None, ""):
            return "[REDACTED]"
        if isinstance(value, dict):
            return {key: self.structured(nested, str(key).lower()) for key, nested in value.items()}
        if isinstance(value, list):
            return [self.structured(nested, field) for nested in value]
        if isinstance(value, str):
            return self.text(value, field=field, command=field in _COMMAND_FIELDS)
        return value


def _escape(redactor, value, field=None, command=False):
    return html.escape(redactor.text(value, field=field, command=command), quote=True)


def _priority_class(value):
    try:
        score = int(value)
    except (TypeError, ValueError):
        return "info"
    if score >= 95:
        return "critical"
    if score >= 85:
        return "high"
    if score >= 70:
        return "medium"
    return "info"


def _finding_score(finding):
    value = (finding.get("attributes") or {}).get("score", 0)
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _path_priority(path):
    value = path.get("effective_priority", path.get("priority", 0))
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _host_label(finding):
    host = finding.get("host") or "GLOBAL"
    port = finding.get("port")
    return f"{host}:{port}" if port is not None else str(host)


def _render_counter(title, counter, redactor):
    if not counter:
        return ""
    maximum = max(counter.values()) or 1
    rows = []
    for label, count in counter.most_common(10):
        width = max(4, round((count / maximum) * 100))
        rows.append(
            '<div class="bar-row">'
            f'<span class="bar-label">{_escape(redactor, label)}</span>'
            f'<span class="bar-track"><span class="bar-fill" style="width:{width}%"></span></span>'
            f'<strong>{count}</strong>'
            '</div>'
        )
    return f'<section class="panel"><h3>{html.escape(title)}</h3>{"".join(rows)}</section>'


def _render_value(redactor, key, value):
    safe_value = redactor.structured(value, field=str(key).lower())
    if isinstance(safe_value, (dict, list)):
        text = json.dumps(safe_value, indent=2, sort_keys=True, default=str)
        return f'<pre>{html.escape(text, quote=True)}</pre>'
    return f'<span>{html.escape(str(safe_value if safe_value is not None else ""), quote=True)}</span>'


def _render_attributes(attributes, redactor):
    rows = []
    for key in sorted(attributes):
        if key in {"discovery_provenance", "score"}:
            continue
        rows.append(
            f'<dt>{html.escape(str(key), quote=True)}</dt>'
            f'<dd>{_render_value(redactor, key, attributes[key])}</dd>'
        )
    if not rows:
        return ""
    return '<details><summary>Normalized attributes</summary><dl class="attributes">' + "".join(rows) + '</dl></details>'


def _render_findings(findings, redactor):
    cards = []
    for index, finding in enumerate(sorted(findings, key=_finding_score, reverse=True), start=1):
        attrs = finding.get("attributes") or {}
        score = _finding_score(finding)
        severity = attrs.get("severity") or attrs.get("confidence") or _priority_class(score)
        cards.append(
            f'<article class="card finding" id="finding-{index}">'
            '<div class="card-head">'
            f'<span class="badge {_priority_class(score)}">Score {score}</span>'
            f'<span class="badge neutral">{_escape(redactor, severity)}</span>'
            f'<h3>{_escape(redactor, finding.get("name"))}</h3>'
            '</div>'
            '<div class="meta-grid">'
            f'<span><b>Target</b>{_escape(redactor, _host_label(finding))}</span>'
            f'<span><b>Type</b>{_escape(redactor, finding.get("entity_type"))}</span>'
            f'<span><b>Source</b>{_escape(redactor, finding.get("source_tool"))}</span>'
            f'<span><b>Version</b>{_escape(redactor, finding.get("version") or "—")}</span>'
            '</div>'
            f'{_render_attributes(attrs, redactor)}'
            '</article>'
        )
    return "".join(cards) or '<p class="empty">No findings were available.</p>'


def _safe_reference(value):
    text = str(value or "").strip()
    parsed = urlparse(text)
    return text if parsed.scheme in {"http", "https"} and parsed.netloc else None


def _render_paths(paths, redactor):
    cards = []
    for index, path in enumerate(paths, start=1):
        suggestion = path.get("suggestion") or {}
        priority = _path_priority(path)
        commands = suggestion.get("commands") or []
        evidence = path.get("evidence") or []
        references = suggestion.get("references") or []
        command_html = "".join(
            f'<li><code>{_escape(redactor, command, command=True)}</code></li>'
            for command in commands
        )
        evidence_html = "".join(f'<li>{_escape(redactor, item)}</li>' for item in evidence)
        reference_html = "".join(
            f'<li><a href="{html.escape(url, quote=True)}" rel="noreferrer">{html.escape(url)}</a></li>'
            for reference in references
            for url in [_safe_reference(reference)]
            if url
        )
        cards.append(
            f'<article class="card path" id="path-{index}">'
            '<div class="card-head">'
            f'<span class="badge {_priority_class(priority)}">Priority {priority}</span>'
            f'<span class="badge neutral">{_escape(redactor, path.get("host") or "GLOBAL")}</span>'
            f'<h3>{_escape(redactor, path.get("name"))}</h3>'
            '</div>'
            f'<p class="lead">{_escape(redactor, suggestion.get("description"))}</p>'
            f'<p>{_escape(redactor, suggestion.get("rationale"))}</p>'
            + (f'<h4>Recommended actions</h4><ol class="commands">{command_html}</ol>' if command_html else "")
            + (f'<details><summary>Matched evidence</summary><ul>{evidence_html}</ul></details>' if evidence_html else "")
            + (f'<details><summary>References</summary><ul>{reference_html}</ul></details>' if reference_html else "")
            + '</article>'
        )
    return "".join(cards) or '<p class="empty">No attack paths passed the selected likelihood filter.</p>'


def _collect_provenance(findings, paths):
    records = []
    seen = set()

    def add_from(finding):
        attrs = (finding or {}).get("attributes") or {}
        provenance = attrs.get("discovery_provenance") or []
        if not isinstance(provenance, list):
            return
        for record in provenance:
            if not isinstance(record, dict):
                continue
            marker = (
                record.get("tool"), record.get("command"),
                record.get("source_file"), record.get("status"),
            )
            if marker not in seen:
                seen.add(marker)
                records.append(record)

    for finding in findings:
        add_from(finding)
    for path in paths:
        for matched in path.get("matched_findings") or []:
            if isinstance(matched, dict):
                add_from(matched.get("finding"))
    return records


def _render_provenance(records, redactor):
    rows = []
    for record in records:
        status = str(record.get("status") or "not recorded")
        status_class = "ok" if status.lower() in {"done", "success", "completed"} else "neutral"
        rows.append(
            '<tr>'
            f'<td>{_escape(redactor, record.get("tool") or "unknown")}</td>'
            f'<td><span class="badge {status_class}">{_escape(redactor, status)}</span></td>'
            f'<td>{_escape(redactor, record.get("source_file") or "not recorded")}</td>'
            f'<td><code>{_escape(redactor, record.get("command") or "not recorded", command=True)}</code></td>'
            '</tr>'
        )
    if not rows:
        return '<p class="empty">No discovery provenance was recorded for these findings.</p>'
    return (
        '<div class="table-wrap"><table><thead><tr><th>Tool</th><th>Status</th>'
        '<th>Source file</th><th>Producer command</th></tr></thead><tbody>'
        + "".join(rows) + '</tbody></table></div>'
    )


def render_html_report(findings, attack_paths, *, include_secrets=True,
                       title="PathFinder Engagement Report", generated_at=None):
    """Render findings, attack paths, and provenance into standalone HTML."""
    findings = list(findings or [])
    attack_paths = list(attack_paths or [])
    redactor = _Redactor(findings, include_secrets=include_secrets)
    generated = generated_at or datetime.now(timezone.utc)
    if isinstance(generated, datetime):
        generated_label = generated.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    else:
        generated_label = str(generated)

    hosts = sorted({str(item.get("host")) for item in findings if item.get("host")})
    source_counts = Counter(str(item.get("source_tool") or "unknown") for item in findings)
    type_counts = Counter(str(item.get("entity_type") or "unknown") for item in findings)
    zero_hops = sum(1 for item in attack_paths if "ZERO-HOP" in str(item.get("name") or "").upper())
    critical_paths = sum(1 for item in attack_paths if _path_priority(item) >= 95)
    provenance = _collect_provenance(findings, attack_paths)
    secret_notice = (
        "Findings, evidence, and producer commands are preserved; treat this report as sensitive engagement loot."
        if include_secrets else
        "Passwords, hashes, tokens, private keys, and command-line credential values were redacted by --report-redact-secrets."
    )

    css = """
:root{--ink:#172033;--muted:#637083;--paper:#f5f7fb;--panel:#fff;--line:#dce2ec;--navy:#12233f;--cyan:#1b8fa8;--critical:#a71930;--high:#c84c18;--medium:#b17a00;--ok:#157347;--shadow:0 10px 28px rgba(18,35,63,.08)}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:var(--paper);color:var(--ink);font:15px/1.55 Inter,Segoe UI,Arial,sans-serif}a{color:#0b6680}code,pre{font-family:Cascadia Code,Consolas,monospace}header{background:linear-gradient(135deg,#0d1c35,#163d59 65%,#1a7185);color:#fff;padding:3.2rem max(5vw,1.25rem) 2.5rem}header h1{font-size:clamp(2rem,4vw,3.5rem);line-height:1.05;margin:.35rem 0}header p{max-width:72rem;color:#d8e9f0}.eyebrow{text-transform:uppercase;letter-spacing:.16em;font-size:.78rem;font-weight:700;color:#80d3df}.notice{border-left:4px solid #49bfd0;background:rgba(255,255,255,.1);padding:.7rem 1rem;margin-top:1.25rem;border-radius:.25rem}nav{position:sticky;top:0;z-index:3;background:#fff;border-bottom:1px solid var(--line);padding:.7rem max(5vw,1.25rem);display:flex;gap:1.15rem;overflow:auto;box-shadow:0 4px 15px rgba(18,35,63,.06)}nav a{text-decoration:none;font-weight:700;white-space:nowrap}main{max-width:1500px;margin:auto;padding:2rem max(4vw,1rem) 4rem}.section-head{display:flex;justify-content:space-between;align-items:end;gap:1rem;margin:2.5rem 0 1rem}.section-head h2{font-size:1.65rem;margin:0}.section-head p{margin:0;color:var(--muted)}.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:1rem;margin-top:-1.25rem}.metric,.panel{background:var(--panel);border:1px solid var(--line);border-radius:.8rem;box-shadow:var(--shadow)}.metric{padding:1.15rem}.metric strong{display:block;font-size:2rem;color:var(--navy)}.metric span{color:var(--muted)}.charts{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:1rem;margin-top:1rem}.panel{padding:1rem 1.2rem}.panel h3{margin-top:0}.bar-row{display:grid;grid-template-columns:minmax(90px,1fr) 3fr 2rem;gap:.6rem;align-items:center;margin:.55rem 0}.bar-label{overflow:hidden;text-overflow:ellipsis}.bar-track{height:.58rem;border-radius:1rem;background:#e8edf4;overflow:hidden}.bar-fill{display:block;height:100%;background:linear-gradient(90deg,var(--cyan),#4fc3cf)}.cards{display:grid;gap:1rem}.card{background:var(--panel);border:1px solid var(--line);border-radius:.8rem;padding:1.15rem 1.25rem;box-shadow:var(--shadow);break-inside:avoid}.card-head{display:flex;gap:.55rem;align-items:center;flex-wrap:wrap}.card-head h3{flex-basis:100%;margin:.35rem 0 .2rem;font-size:1.18rem}.badge{display:inline-block;border-radius:99px;padding:.15rem .55rem;font-size:.72rem;font-weight:800;text-transform:uppercase;letter-spacing:.04em;background:#e8edf4;color:#34445d}.badge.critical{background:#fde8eb;color:var(--critical)}.badge.high{background:#fff0e9;color:var(--high)}.badge.medium{background:#fff7d9;color:#856000}.badge.ok{background:#e4f4ea;color:var(--ok)}.badge.neutral{background:#e8edf4;color:#45546b}.lead{font-size:1.03rem;font-weight:650}.meta-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:.65rem;margin:.8rem 0}.meta-grid span{color:var(--muted)}.meta-grid b{display:block;color:var(--ink);font-size:.72rem;text-transform:uppercase;letter-spacing:.06em}.commands{padding-left:1.25rem}.commands li{margin:.55rem 0}.commands code,td code{white-space:pre-wrap;overflow-wrap:anywhere;background:#f0f3f8;padding:.16rem .3rem;border-radius:.25rem}details{border-top:1px solid var(--line);margin-top:.8rem;padding-top:.7rem}summary{cursor:pointer;font-weight:750}.attributes{display:grid;grid-template-columns:minmax(130px,220px) 1fr;gap:.45rem 1rem}.attributes dt{font-weight:700;overflow-wrap:anywhere}.attributes dd{margin:0;min-width:0}.attributes pre{white-space:pre-wrap;overflow-wrap:anywhere;margin:0;background:#f2f5f9;padding:.6rem;border-radius:.4rem}.table-wrap{overflow:auto;background:#fff;border:1px solid var(--line);border-radius:.8rem;box-shadow:var(--shadow)}table{width:100%;border-collapse:collapse;min-width:760px}th,td{text-align:left;vertical-align:top;padding:.75rem;border-bottom:1px solid var(--line)}th{background:#eef2f7;text-transform:uppercase;letter-spacing:.05em;font-size:.72rem}.empty{color:var(--muted);font-style:italic}.scope{overflow-wrap:anywhere}footer{text-align:center;color:var(--muted);padding:2rem}
@media(max-width:650px){header{padding-top:2rem}.attributes{grid-template-columns:1fr}.attributes dd{margin-bottom:.55rem}.bar-row{grid-template-columns:1fr 2fr 2rem}}
@media print{body{background:#fff;font-size:11px}header{background:#fff!important;color:#000;padding:1rem 0;border-bottom:2px solid #000}header p,.eyebrow{color:#333}.notice{background:#fff;border:1px solid #888}nav{display:none}main{padding:0}.metric,.panel,.card,.table-wrap{box-shadow:none}.cards{display:block}.card{margin:.6rem 0}details{display:block}details>summary{display:none}details>*{display:block!important}a{color:#000;text-decoration:none}}
"""

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<title>{html.escape(str(title), quote=True)}</title>
<style>{css}</style>
</head>
<body>
<header>
  <div class="eyebrow">PathFinder · Engagement Intelligence</div>
  <h1>{html.escape(str(title), quote=True)}</h1>
  <p>Generated {html.escape(generated_label)}. This report summarizes normalized evidence, prioritized attack paths, and the commands that produced the underlying loot.</p>
  <div class="notice"><strong>Report data policy:</strong> {html.escape(secret_notice)}</div>
</header>
<nav aria-label="Report sections"><a href="#summary">Summary</a><a href="#paths">Attack paths</a><a href="#findings">Findings</a><a href="#provenance">Provenance</a></nav>
<main>
<section id="summary">
  <div class="section-head"><div><h2>Executive summary</h2><p class="scope">Scope: {_escape(redactor, ', '.join(hosts) if hosts else 'No hosts recorded')}</p></div></div>
  <div class="metrics">
    <div class="metric"><strong>{len(findings)}</strong><span>normalized findings</span></div>
    <div class="metric"><strong>{len(attack_paths)}</strong><span>prioritized attack paths</span></div>
    <div class="metric"><strong>{critical_paths}</strong><span>priority 95+ paths</span></div>
    <div class="metric"><strong>{zero_hops}</strong><span>owned zero-hop wins</span></div>
    <div class="metric"><strong>{len(hosts)}</strong><span>hosts / domains</span></div>
    <div class="metric"><strong>{len(provenance)}</strong><span>provenance records</span></div>
  </div>
  <div class="charts">{_render_counter('Findings by source', source_counts, redactor)}{_render_counter('Findings by type', type_counts, redactor)}</div>
</section>
<section id="paths"><div class="section-head"><div><h2>Prioritized attack paths</h2><p>All paths passing the selected likelihood filter; console <code>--top</code> does not truncate this report.</p></div></div><div class="cards">{_render_paths(attack_paths, redactor)}</div></section>
<section id="findings"><div class="section-head"><div><h2>Normalized findings</h2><p>Sorted by PathFinder score.</p></div></div><div class="cards">{_render_findings(findings, redactor)}</div></section>
<section id="provenance"><div class="section-head"><div><h2>Discovery provenance</h2><p>Source files, producer tools, completion state, and recorded commands.</p></div></div>{_render_provenance(provenance, redactor)}</section>
</main>
<footer>Generated by PathFinder · Use only within the authorized engagement scope.</footer>
</body>
</html>"""


def write_html_report(path, findings, attack_paths, *, include_secrets=True,
                      title="PathFinder Engagement Report", generated_at=None):
    """Write a UTF-8 standalone report and return its absolute path."""
    target = Path(path or DEFAULT_REPORT_NAME).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    document = render_html_report(
        findings, attack_paths,
        include_secrets=include_secrets,
        title=title,
        generated_at=generated_at,
    )
    target.write_text(document, encoding="utf-8")
    return os.fspath(target)
