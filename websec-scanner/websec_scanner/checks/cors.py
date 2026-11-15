"""CORS misconfiguration check: does the server reflect an arbitrary Origin + allow credentials?"""

from __future__ import annotations

from ..findings import Finding, Report, Severity

NAME = "cors"

_PROBE_ORIGIN = "https://websec-scanner-cors-probe.invalid"


def run(pages, session, report: Report, args) -> None:
    if not pages:
        return
    checked_urls = set()
    for page in pages[: min(len(pages), 10)]:  # sample, not every page — origin behavior is usually global
        if page.url in checked_urls:
            continue
        checked_urls.add(page.url)
        try:
            resp = session.get(
                page.url,
                headers={"Origin": _PROBE_ORIGIN},
                timeout=10,
            )
        except Exception:
            continue

        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")

        if acao == "*" and acac.lower() == "true":
            # Browsers actually reject this combination, but some proxies/CDNs don't
            # and it signals a misconfigured intent — still worth flagging.
            report.add(
                Finding(
                    check=NAME,
                    severity=Severity.HIGH,
                    title="CORS: wildcard origin combined with credentials allowed",
                    url=page.url,
                    evidence="`Access-Control-Allow-Origin: *` with "
                    "`Access-Control-Allow-Credentials: true`.",
                    remediation="Never combine a wildcard origin with credentialed "
                    "CORS. Use an explicit allow-list of trusted origins instead.",
                )
            )
        elif acao == _PROBE_ORIGIN:
            severity = Severity.HIGH if acac.lower() == "true" else Severity.MEDIUM
            report.add(
                Finding(
                    check=NAME,
                    severity=severity,
                    title="CORS: arbitrary Origin is reflected back",
                    url=page.url,
                    evidence=f"Sending `Origin: {_PROBE_ORIGIN}` caused the server to "
                    f"respond with `Access-Control-Allow-Origin: {_PROBE_ORIGIN}`"
                    + (" and `Access-Control-Allow-Credentials: true`" if acac.lower() == "true" else "")
                    + ".",
                    remediation="Validate the `Origin` header against an explicit "
                    "allow-list server-side instead of reflecting whatever origin "
                    "the browser sent — reflecting it lets any website read "
                    "responses from this endpoint on a logged-in victim's behalf.",
                )
            )
