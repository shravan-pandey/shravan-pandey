"""Non-destructive probes for reflected XSS and SQL-error disclosure.

Methodology: for every URL that has query-string parameters, re-request it
with each parameter's value replaced by a harmless marker string. This never
writes data (GET requests only, nothing is submitted to forms) and never
uses a real exploit payload — it just checks (a) whether a unique marker
string comes back unescaped in the HTML (indicates a reflected-XSS-prone
sink) and (b) whether a single apostrophe causes a database error message to
leak (indicates unsanitized SQL string concatenation).
"""

from __future__ import annotations

import html
import re
import urllib.parse as urlparse

from ..findings import Finding, Report, Severity

NAME = "injection-probe"

_XSS_MARKER = "wsXSSprobe9f3a<>\"'"
_SQLI_PROBE = "'"

_SQL_ERROR_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"you have an error in your sql syntax",
        r"warning: mysql",
        r"unclosed quotation mark after the character string",
        r"quoted string not properly terminated",
        r"sqlstate\[",
        r"pg_query\(\)",
        r"postgresql.*error",
        r"ora-\d{5}",
        r"microsoft ole db provider for sql server",
        r"sqlite3\.OperationalError",
        r"sqlite_error",
        r"syntax error.*near",
    ]
]

_MAX_URLS_TO_PROBE = 25


def _urls_with_params(pages):
    seen = set()
    out = []
    for page in pages:
        parsed = urlparse.urlparse(page.url)
        if not parsed.query:
            continue
        base = parsed._replace(query="").geturl()
        qs = urlparse.parse_qs(parsed.query, keep_blank_values=True)
        key = (base, tuple(sorted(qs.keys())))
        if key in seen:
            continue
        seen.add(key)
        out.append((page.url, parsed, qs))
    return out


def run(pages, session, report: Report, args) -> None:
    candidates = _urls_with_params(pages)[:_MAX_URLS_TO_PROBE]
    if not candidates:
        return

    for original_url, parsed, qs in candidates:
        for param_name in list(qs.keys()):
            _probe_xss(original_url, parsed, qs, param_name, session, report)
            _probe_sqli(original_url, parsed, qs, param_name, session, report)


def _build_url(parsed, qs, param_name, value) -> str:
    new_qs = dict(qs)
    new_qs[param_name] = [value]
    query = urlparse.urlencode(new_qs, doseq=True)
    return parsed._replace(query=query).geturl()


def _probe_xss(original_url, parsed, qs, param_name, session, report) -> None:
    probe_url = _build_url(parsed, qs, param_name, _XSS_MARKER)
    try:
        resp = session.get(probe_url, timeout=10)
    except Exception:
        return
    body = resp.text or ""
    if _XSS_MARKER in body:
        # Reflected verbatim, unescaped — the escaped form would show &lt;&gt;&quot; etc.
        report.add(
            Finding(
                check=NAME,
                severity=Severity.HIGH,
                title=f"Possible reflected XSS via `{param_name}` parameter",
                url=probe_url,
                evidence=f"Marker string containing `<>\"'` was reflected verbatim "
                f"(unescaped) in the response when `{param_name}` was set to it.",
                remediation=f"HTML-escape (or better, use a templating engine that "
                f"auto-escapes by default) any output that includes the `{param_name}` "
                "parameter. Also add a Content-Security-Policy as defense in depth.",
            )
        )
    elif html.escape(_XSS_MARKER) in body or html.escape(_XSS_MARKER, quote=False) in body:
        pass  # properly escaped — good, no finding


def _probe_sqli(original_url, parsed, qs, param_name, session, report) -> None:
    original_value = qs[param_name][0] if qs[param_name] else ""
    probe_url = _build_url(parsed, qs, param_name, original_value + _SQLI_PROBE)
    try:
        resp = session.get(probe_url, timeout=10)
    except Exception:
        return
    body = resp.text or ""
    for pattern in _SQL_ERROR_PATTERNS:
        if pattern.search(body):
            report.add(
                Finding(
                    check=NAME,
                    severity=Severity.CRITICAL,
                    title=f"Possible SQL injection via `{param_name}` parameter (error-based)",
                    url=probe_url,
                    evidence=f"Appending a single `'` to `{param_name}` triggered a "
                    f"database error message matching pattern `{pattern.pattern}`.",
                    remediation=f"Use parameterized queries / prepared statements for "
                    f"any SQL built from the `{param_name}` parameter — never "
                    "concatenate user input into SQL strings. Also disable verbose "
                    "DB error output in production (log it server-side instead of "
                    "rendering it to the client).",
                )
            )
            return
