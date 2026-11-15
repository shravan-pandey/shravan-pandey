"""Security response header checks: CSP, HSTS, X-Content-Type-Options, etc."""

from __future__ import annotations

from ..findings import Finding, Report, Severity

NAME = "security-headers"

_CHECKS = [
    (
        "Content-Security-Policy",
        Severity.MEDIUM,
        "Missing Content-Security-Policy header",
        "Add a `Content-Security-Policy` header restricting script/style/frame "
        "sources, e.g. `Content-Security-Policy: default-src 'self'`. This is "
        "the strongest single mitigation against XSS and data-exfiltration "
        "via injected scripts.",
    ),
    (
        "Strict-Transport-Security",
        Severity.MEDIUM,
        "Missing Strict-Transport-Security (HSTS) header",
        "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` "
        "(only on HTTPS responses) to force browsers to always use HTTPS for "
        "this domain, preventing SSL-stripping downgrade attacks.",
    ),
    (
        "X-Content-Type-Options",
        Severity.LOW,
        "Missing X-Content-Type-Options header",
        "Add `X-Content-Type-Options: nosniff` to stop browsers from "
        "MIME-sniffing responses into an executable type.",
    ),
    (
        "Referrer-Policy",
        Severity.LOW,
        "Missing Referrer-Policy header",
        "Add `Referrer-Policy: strict-origin-when-cross-origin` (or stricter) "
        "to avoid leaking full URLs (possibly containing tokens) to "
        "third-party sites via the Referer header.",
    ),
    (
        "Permissions-Policy",
        Severity.INFO,
        "Missing Permissions-Policy header",
        "Add a `Permissions-Policy` header to explicitly disable browser "
        "features (camera, microphone, geolocation, etc.) your site doesn't "
        "use.",
    ),
]


def run(pages, session, report: Report, args) -> None:
    if not pages:
        return
    # Check the homepage/representative page; headers are usually set globally
    # (e.g. in middleware), so checking once avoids duplicate noise, but we
    # still scan every distinct header set we saw across the crawl.
    seen_header_sets = set()
    for page in pages:
        key = frozenset(page.headers.keys())
        if key in seen_header_sets:
            continue
        seen_header_sets.add(key)

        for header_name, severity, title, remediation in _CHECKS:
            if header_name not in page.headers:
                report.add(
                    Finding(
                        check=NAME,
                        severity=severity,
                        title=title,
                        url=page.url,
                        evidence=f"Response headers did not include `{header_name}`.",
                        remediation=remediation,
                    )
                )

        xfo = page.headers.get("X-Frame-Options", "")
        csp = page.headers.get("Content-Security-Policy", "")
        if not xfo and "frame-ancestors" not in csp:
            report.add(
                Finding(
                    check="clickjacking",
                    severity=Severity.MEDIUM,
                    title="No clickjacking protection (X-Frame-Options / frame-ancestors)",
                    url=page.url,
                    evidence="Neither `X-Frame-Options` nor CSP `frame-ancestors` was present.",
                    remediation="Add `X-Frame-Options: DENY` (or `SAMEORIGIN` if you "
                    "intentionally frame your own pages) and/or a CSP "
                    "`frame-ancestors 'none'` directive to prevent the page "
                    "being embedded in a malicious iframe for clickjacking.",
                )
            )

        server = page.headers.get("Server", "")
        powered_by = page.headers.get("X-Powered-By", "")
        for banner_name, banner_val in (("Server", server), ("X-Powered-By", powered_by)):
            if banner_val and any(c.isdigit() for c in banner_val):
                report.add(
                    Finding(
                        check="info-disclosure",
                        severity=Severity.INFO,
                        title=f"Verbose `{banner_name}` header discloses software version",
                        url=page.url,
                        evidence=f"`{banner_name}: {banner_val}`",
                        remediation=f"Suppress or generalize the `{banner_name}` header "
                        "(e.g. `ServerTokens Prod` on Apache, `server_tokens off` on "
                        "nginx, or remove `X-Powered-By` in your framework config) so "
                        "attackers can't fingerprint exact software versions to target "
                        "known CVEs.",
                    )
                )
