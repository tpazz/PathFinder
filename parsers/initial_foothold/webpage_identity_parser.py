"""Extract manual-triage identity and request candidates from collected HTML."""

import html
import json
import os
import re
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

from parsers.initial_foothold.web_url_helpers import parameterized_url_finding


_TOKEN = r"[A-Za-z][A-Za-z0-9._-]{2,63}"
_SERVICE_ACCOUNT = re.compile(
    rf"(?<![A-Za-z0-9._-])(?P<value>(?:svc[_-]{_TOKEN}|{_TOKEN}[_-]svc))(?![A-Za-z0-9._-])",
    re.IGNORECASE,
)
_EMAIL = re.compile(rf"(?<![A-Za-z0-9._%+-])(?P<value>{_TOKEN})@[A-Za-z0-9.-]+\.[A-Za-z]{{2,}}")
_LABELLED = re.compile(
    rf"\b(?P<label>username|user(?:name)?|account|login|owner|maintainer|author|contact)\b"
    rf"\s*(?:name\s*)?(?:is\s+|[:=\-]\s*)(?:[\"'`])?(?P<value>{_TOKEN})",
    re.IGNORECASE,
)
_PORT_FROM_NAME = re.compile(r"(?:webpage|page|body)[_-](?:https?[_-])?(\d{1,5})", re.IGNORECASE)
_QUERY_LITERAL = re.compile(
    r"(?P<value>(?:https?://[^\"'`\s<>]+|(?:/|\./|\.\./)?[A-Za-z0-9_.~/-]+)"
    r"\?[A-Za-z0-9_.~-]+=[^\"'`\s<>]*|\?[A-Za-z0-9_.~-]+=[^\"'`\s<>]*)",
    re.IGNORECASE,
)
_STATIC_EXTENSIONS = {
    ".css", ".js", ".mjs", ".map", ".png", ".jpg", ".jpeg", ".gif",
    ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".webp", ".mp4",
}
_TRACKING_PARAMETERS = {"fbclid", "gclid", "msclkid"}

_COMMON_FALSE_POSITIVES = {
    "about", "account", "author", "contact", "copyright",
    "email", "example", "homepage", "index", "login", "logout",
    "maintainer", "password", "profile", "service", "unknown",
    "user", "username", "website", "welcome",
}


class _VisibleTextParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self._ignored_depth = 0
        self.parts = []

    def handle_starttag(self, tag, _attrs):
        if tag.lower() in {"script", "style", "svg", "noscript"}:
            self._ignored_depth += 1

    def handle_endtag(self, tag):
        if tag.lower() in {"script", "style", "svg", "noscript"} and self._ignored_depth:
            self._ignored_depth -= 1

    def handle_data(self, data):
        if not self._ignored_depth:
            self.parts.append(data)

    def handle_comment(self, data):
        # Comments often hold deployment notes and account hints in lab pages.
        self.parts.append(data)


class _IdentityTableParser(HTMLParser):
    """Preserve table rows so identity-labelled columns can be interpreted structurally."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tables = []
        self._table = None
        self._row = None
        self._cell = None
        self._ignored_depth = 0

    def _finish_cell(self):
        if self._cell is not None and self._row is not None:
            text = " ".join(" ".join(self._cell["parts"]).split())
            self._row.append((self._cell["tag"], text))
        self._cell = None

    def _finish_row(self):
        self._finish_cell()
        if self._row and self._table is not None:
            self._table.append(self._row)
        self._row = None

    def _finish_table(self):
        self._finish_row()
        if self._table:
            self.tables.append(self._table)
        self._table = None

    def handle_starttag(self, tag, _attrs):
        tag = tag.lower()
        if tag in {"script", "style", "svg", "noscript"}:
            self._ignored_depth += 1
            return
        if tag == "table":
            self._finish_table()
            self._table = []
        elif self._table is not None and tag == "tr":
            self._finish_row()
            self._row = []
        elif self._row is not None and tag in {"th", "td"}:
            self._finish_cell()
            self._cell = {"tag": tag, "parts": []}

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in {"script", "style", "svg", "noscript"}:
            if self._ignored_depth:
                self._ignored_depth -= 1
            return
        if tag in {"th", "td"}:
            self._finish_cell()
        elif tag == "tr":
            self._finish_row()
        elif tag == "table":
            self._finish_table()

    def handle_data(self, data):
        if self._cell is not None and not self._ignored_depth:
            self._cell["parts"].append(data)

    def close(self):
        super().close()
        self._finish_table()


class _WebSurfaceParser(HTMLParser):
    """Collect navigable references and form fields without rendering the page."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.references = []
        self.forms = []
        self._form = None

    @staticmethod
    def _attrs(attrs):
        return {str(key).lower(): value for key, value in attrs if key}

    def _finish_form(self):
        if self._form is not None:
            self.forms.append(self._form)
            self._form = None

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        values = self._attrs(attrs)
        if tag in {"a", "area", "link"} and values.get("href"):
            self.references.append((values["href"], f"{tag} href"))
        if tag in {"iframe", "frame", "script", "img", "source"} and values.get("src"):
            self.references.append((values["src"], f"{tag} src"))
        if tag == "form":
            self._finish_form()
            self._form = {
                "action": values.get("action") or "",
                "method": (values.get("method") or "GET").upper(),
                "fields": [],
            }
        elif self._form is not None and tag in {"input", "select", "textarea"}:
            name = values.get("name")
            input_type = (values.get("type") or "text").lower()
            if (name and "disabled" not in values
                    and input_type not in {"submit", "button", "reset", "file", "image"}):
                self._form["fields"].append((name, values.get("value") or "1"))

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        if tag.lower() == "form":
            self._finish_form()

    def close(self):
        super().close()
        self._finish_form()


def _page_text(content):
    parser = _VisibleTextParser()
    try:
        parser.feed(content)
        parser.close()
    except Exception:
        pass
    text = html.unescape(" ".join(parser.parts))
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", " ", text)
    text = "".join(character if character >= " " and character != "\x7f" else " "
                   for character in text)
    return " ".join(text.split())


def _ffuf_result_source(path, target_host):
    """Resolve an ffuf -od response hash back to the URL recorded in its JSON."""
    response_path = os.path.abspath(path)
    parent_name = os.path.basename(os.path.dirname(response_path))
    match = re.fullmatch(r"ffuf_pages_(?:https?)_(\d{1,5})", parent_name, re.IGNORECASE)
    if not match:
        return None
    results_path = os.path.join(os.path.dirname(os.path.dirname(response_path)),
                                f"ffuf_{match.group(1)}.json")
    try:
        with open(results_path, "r", encoding="utf-8-sig") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None
    response_name = os.path.basename(response_path)
    for result in payload.get("results", []) if isinstance(payload, dict) else []:
        if not isinstance(result, dict) or os.path.basename(str(result.get("resultfile") or "")) != response_name:
            continue
        url = str(result.get("url") or "")
        try:
            parsed = urlparse(url)
        except ValueError:
            return None
        if (parsed.scheme in {"http", "https"} and parsed.hostname
                and parsed.hostname.lower().strip("[]") == str(target_host).lower().strip("[]")):
            return parsed.port or (443 if parsed.scheme == "https" else 80), url
    return None


def _source_details(path, target_host):
    ffuf_source = _ffuf_result_source(path, target_host)
    if ffuf_source:
        return ffuf_source
    basename = os.path.basename(path)
    match = _PORT_FROM_NAME.search(path)
    port = int(match.group(1)) if match and 0 < int(match.group(1)) <= 65535 else None
    lowered = basename.lower()
    scheme = "https" if "https" in lowered or port in {443, 8443, 9443} else "http"
    url = f"{scheme}://{target_host}"
    if port:
        url += f":{port}"
    return port, url


def _snippet(text, start, end, width=180):
    margin = max(0, (width - (end - start)) // 2)
    left = max(0, start - margin)
    right = min(len(text), end + margin)
    value = text[left:right].strip()
    if left:
        value = "..." + value
    if right < len(text):
        value += "..."
    return value


def _valid_candidate(value):
    lowered = value.lower().strip("._-")
    if lowered in _COMMON_FALSE_POSITIVES:
        return False
    if value.lower().endswith((".css", ".js", ".html", ".php", ".png", ".jpg", ".svg")):
        return False
    return bool(re.fullmatch(_TOKEN, value))


def extract_username_candidates(content):
    """Return deduplicated candidate records from visible HTML text and comments."""
    text = _page_text(content)
    candidates = {}

    def record_value(value, reason, confidence, evidence):
        value = str(value or "").strip().strip("._-")
        if not _valid_candidate(value):
            return
        key = value.lower()
        candidate = {
            "name": value,
            "confidence": confidence,
            "reason": reason,
            "evidence": evidence,
        }
        existing = candidates.get(key)
        rank = {"medium": 1, "high": 2}
        if not existing or rank[confidence] > rank[existing["confidence"]]:
            candidates[key] = candidate

    def record(match, reason, confidence):
        record_value(match.group("value"), reason, confidence,
                     _snippet(text, match.start(), match.end()))

    for match in _SERVICE_ACCOUNT.finditer(text):
        record(match, "service-account naming pattern", "high")
    for match in _EMAIL.finditer(text):
        record(match, "email local-part", "medium")
    for match in _LABELLED.finditer(text):
        label = match.group("label").lower()
        confidence = "high" if label in {"username", "user", "account", "login"} else "medium"
        record(match, f"labelled as {label}", confidence)

    table_parser = _IdentityTableParser()
    try:
        table_parser.feed(content)
        table_parser.close()
    except Exception:
        pass
    identity_labels = {
        "user": "high", "username": "high", "account": "high", "login": "high",
        "owner": "medium", "maintainer": "medium", "author": "medium", "contact": "medium",
    }
    for table in table_parser.tables:
        identity_columns = {}
        for row in table:
            normalized = [re.sub(r"[^a-z]", "", cell_text.lower()) for _tag, cell_text in row]
            header_columns = {
                index: (normalized[index], identity_labels[normalized[index]])
                for index, (tag, _cell_text) in enumerate(row)
                if tag == "th" and normalized[index] in identity_labels
            }
            if header_columns:
                identity_columns.update(header_columns)
                continue
            if not identity_columns:
                continue
            evidence = " | ".join(cell_text for _tag, cell_text in row if cell_text)
            for index, (label, confidence) in identity_columns.items():
                if index < len(row):
                    record_value(row[index][1], f"HTML table column labelled {label}",
                                 confidence, evidence)
    return list(candidates.values())


def _same_target_url(candidate, base_url, target_host):
    value = html.unescape(str(candidate or "").strip())
    if not value or value.startswith(("#", "mailto:", "tel:", "javascript:", "data:")):
        return None
    absolute = urljoin(base_url + "/", value)
    try:
        parsed = urlparse(absolute)
    except ValueError:
        return None
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    if parsed.hostname.lower().strip("[]") != str(target_host).lower().strip("[]"):
        return None
    if any(parsed.path.lower().endswith(extension) for extension in _STATIC_EXTENSIONS):
        return None
    return urlunparse(parsed._replace(fragment=""))


def _useful_query(url):
    try:
        parameters = [name for name, _value in parse_qsl(urlparse(url).query, keep_blank_values=True)]
    except ValueError:
        return False
    if not parameters:
        return False
    return not all(name.lower() in _TRACKING_PARAMETERS or name.lower().startswith("utm_")
                   for name in parameters)


def _get_form_url(action_url, fields):
    parsed = urlparse(action_url)
    query = parse_qsl(parsed.query, keep_blank_values=True) + list(fields)
    return urlunparse(parsed._replace(query=urlencode(query)))


def extract_parameter_candidates(content, target_host, port, base_url):
    """Extract concrete same-target GET URLs and POST form bodies for manual SQLi triage."""
    parser = _WebSurfaceParser()
    try:
        parser.feed(content)
        parser.close()
    except Exception:
        pass

    records = []
    seen = set()

    def add_get(candidate, source):
        url = _same_target_url(candidate, base_url, target_host)
        if not url or not _useful_query(url):
            return
        finding = parameterized_url_finding(
            target_host, port, "webpage_parameter_extractor", url, source,
        )
        if not finding:
            return
        key = ("GET", finding["attributes"]["url"])
        if key in seen:
            return
        seen.add(key)
        finding["attributes"].update({
            "method": "GET",
            "candidate_only": True,
            "requires_manual_validation": True,
            "confidence": "medium",
            "extraction_source": source,
            "source_page": base_url,
        })
        records.append(finding)

    for reference, source in parser.references:
        add_get(reference, source)
    for match in _QUERY_LITERAL.finditer(html.unescape(content)):
        add_get(match.group("value"), "HTML/JavaScript URL literal")

    for form in parser.forms:
        if not form["fields"]:
            continue
        action_url = _same_target_url(form["action"] or base_url, base_url, target_host)
        if not action_url:
            continue
        method = form["method"] if form["method"] in {"GET", "POST"} else "GET"
        if method == "GET":
            add_get(_get_form_url(action_url, form["fields"]), "HTML GET form")
            continue
        data = urlencode(form["fields"])
        parameters = sorted({name for name, _value in form["fields"]})
        key = ("POST", action_url, data)
        if key in seen:
            continue
        seen.add(key)
        parsed = urlparse(action_url)
        records.append({
            "host": parsed.hostname or target_host,
            "port": parsed.port or port,
            "source_tool": "webpage_parameter_extractor",
            "entity_type": "web_parameterized_request",
            "name": f"POST {action_url}",
            "version": None,
            "attributes": {
                "url": action_url,
                "method": "POST",
                "data": data,
                "parameters": parameters,
                "candidate_only": True,
                "requires_manual_validation": True,
                "confidence": "medium",
                "extraction_source": "HTML POST form",
                "source_page": base_url,
            },
        })
    return records


def parse_webpage_html(path, target_host):
    with open(path, "r", encoding="utf-8", errors="ignore") as handle:
        content = handle.read(5_000_000)
    port, url = _source_details(path, target_host)
    findings = []
    for candidate in extract_username_candidates(content):
        findings.append({
            "host": target_host,
            "port": port,
            "source_tool": "webpage_identity_extractor",
            "entity_type": "username_candidate",
            "name": candidate["name"],
            "version": None,
            "attributes": {
                "candidate_only": True,
                "requires_manual_validation": True,
                "confidence": candidate["confidence"],
                "extraction_reason": candidate["reason"],
                "evidence": candidate["evidence"],
                "url": url,
            },
        })
    findings.extend(extract_parameter_candidates(content, target_host, port, url))
    return findings
