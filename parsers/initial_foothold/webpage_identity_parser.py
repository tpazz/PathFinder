"""Extract potential login identities from collected HTML without promoting them to users."""

import html
import os
import re
from html.parser import HTMLParser


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


def _source_details(path, target_host):
    basename = os.path.basename(path)
    match = _PORT_FROM_NAME.search(basename)
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

    def record(match, reason, confidence):
        value = match.group("value").strip("._-")
        if not _valid_candidate(value):
            return
        key = value.lower()
        candidate = {
            "name": value,
            "confidence": confidence,
            "reason": reason,
            "evidence": _snippet(text, match.start(), match.end()),
        }
        existing = candidates.get(key)
        rank = {"medium": 1, "high": 2}
        if not existing or rank[confidence] > rank[existing["confidence"]]:
            candidates[key] = candidate

    for match in _SERVICE_ACCOUNT.finditer(text):
        record(match, "service-account naming pattern", "high")
    for match in _EMAIL.finditer(text):
        record(match, "email local-part", "medium")
    for match in _LABELLED.finditer(text):
        label = match.group("label").lower()
        confidence = "high" if label in {"username", "user", "account", "login"} else "medium"
        record(match, f"labelled as {label}", confidence)
    return list(candidates.values())


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
    return findings
