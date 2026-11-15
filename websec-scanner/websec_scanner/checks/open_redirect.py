"""Open redirect check: do redirect-looking parameters accept an arbitrary external URL?"""

from __future__ import annotations

import urllib.parse as urlparse

from ..findings import Finding, Report, Severity

NAME = "open-redirect"

_REDIRECT_PARAM_NAMES = {
    "url", "redirect", "redirect_uri", "redirecturl", "return", "returnurl",
    "return_to", "next", "dest", "destination", "continue", "r", "u", "go",
    "target", "out", "forward",
}

_PROBE_TARGET = "https://websec-scanner-redirect-probe.invalid/"


def run(pages, session, report: Report, args) -> None:
    seen = set()
    for page in pages:
        parsed = urlparse.urlparse(page.url)
        if not parsed.query:
            continue
        qs = urlparse.parse_qs(parsed.query, keep_blank_values=True)
        for param in qs:
            if param.lower() not in _REDIRECT_PARAM_NAMES:
                continue
            base = parsed._replace(query="").geturl()
            key = (base, param)
            if key in seen:
                continue
            seen.add(key)

            new_qs = dict(qs)
            new_qs[param] = [_PROBE_TARGET]
            probe_url = parsed._replace(query=urlparse.urlencode(new_qs, doseq=True)).geturl()
            try:
                resp = session.get(probe_url, timeout=10, allow_redirects=False)
            except Exception:
                continue

            location = resp.headers.get("Location", "")
            if resp.status_code in (301, 302, 303, 307, 308) and _PROBE_TARGET.rstrip("/") in location:
                report.add(
                    Finding(
                        check=NAME,
                        severity=Severity.MEDIUM,
                        title=f"Open redirect via `{param}` parameter",
                        url=probe_url,
                        evidence=f"Setting `{param}` to an arbitrary external URL caused "
                        f"an HTTP {resp.status_code} redirect to `{location}`.",
                        remediation=f"Validate `{param}` against an allow-list of known-"
                        "safe internal paths before redirecting, or use an indirection "
                        "token (e.g. a short opaque ID mapped server-side to an "
                        "approved destination) instead of taking the URL directly "
                        "from user input. Open redirects are commonly abused in "
                        "phishing to lend credibility to a malicious link.",
                    )
                )
