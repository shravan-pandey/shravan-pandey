"""Checks which HTTP methods are allowed on the target (OPTIONS / TRACE probing)."""

from __future__ import annotations

import urllib.parse as urlparse

from ..findings import Finding, Report, Severity

NAME = "http-methods"

_DANGEROUS = {"TRACE", "TRACK", "PUT", "DELETE", "CONNECT"}


def run(pages, session, report: Report, args) -> None:
    if not pages:
        return
    base = pages[0].url
    parsed = urlparse.urlparse(base)
    root = f"{parsed.scheme}://{parsed.netloc}/"

    try:
        resp = session.request("OPTIONS", root, timeout=10)
        allow = resp.headers.get("Allow", "") or resp.headers.get("Access-Control-Allow-Methods", "")
        allowed_methods = {m.strip().upper() for m in allow.split(",") if m.strip()}
    except Exception:
        allowed_methods = set()

    risky = allowed_methods & _DANGEROUS
    if risky:
        report.add(
            Finding(
                check=NAME,
                severity=Severity.MEDIUM,
                title=f"Potentially dangerous HTTP methods enabled: {', '.join(sorted(risky))}",
                url=root,
                evidence=f"OPTIONS response advertised: {', '.join(sorted(allowed_methods)) or allow}",
                remediation="Disable methods your application doesn't need. `TRACE` "
                "can enable Cross-Site Tracing (XST) to steal cookies marked HttpOnly "
                "in some older browsers; unauthenticated `PUT`/`DELETE` on a web "
                "server (as opposed to an authenticated API) can allow arbitrary "
                "file write/delete.",
            )
        )

    # Separately confirm TRACE is actually honored (some servers list it in Allow but block it).
    try:
        trace_resp = session.request("TRACE", root, timeout=10)
        if trace_resp.status_code < 400 and "TRACE" in (trace_resp.text or ""):
            report.add(
                Finding(
                    check=NAME,
                    severity=Severity.MEDIUM,
                    title="HTTP TRACE method is enabled and echoes the request",
                    url=root,
                    evidence=f"TRACE request returned HTTP {trace_resp.status_code} and "
                    "echoed the request back in the response body.",
                    remediation="Disable the TRACE method at the web server level "
                    "(`TraceEnable Off` in Apache, or an explicit deny in nginx/"
                    "your reverse proxy).",
                )
            )
    except Exception:
        pass
