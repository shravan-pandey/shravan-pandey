"""Cookie attribute checks: Secure, HttpOnly, SameSite."""

from __future__ import annotations

from http.cookies import SimpleCookie

from ..findings import Finding, Report, Severity

NAME = "cookie-flags"

_SESSION_HINTS = ("session", "sess", "auth", "token", "sid", "login", "jwt")


def run(pages, session, report: Report, args) -> None:
    checked = set()
    for page in pages:
        raw_cookies = page.headers.get("Set-Cookie")
        if not raw_cookies:
            continue
        # requests merges multiple Set-Cookie headers with ", " — split carefully isn't
        # fully reliable, so also inspect the session's real cookie jar for flags where possible.
        for cookie in session.cookies:
            if cookie.name in checked:
                continue
            checked.add(cookie.name)
            looks_sensitive = any(h in cookie.name.lower() for h in _SESSION_HINTS)
            secure = bool(cookie.secure)
            httponly = bool(cookie.has_nonstandard_attr("HttpOnly") or cookie.get_nonstandard_attr("httponly"))
            # http.cookiejar doesn't expose HttpOnly directly; fall back to raw header sniff.
            if not httponly and raw_cookies and "httponly" in raw_cookies.lower():
                httponly = cookie.name.lower() in raw_cookies.lower()
            samesite = cookie.get_nonstandard_attr("SameSite") or cookie.get_nonstandard_attr("samesite")

            severity = Severity.MEDIUM if looks_sensitive else Severity.LOW

            if not secure and page.url.startswith("https://"):
                report.add(
                    Finding(
                        check=NAME,
                        severity=severity,
                        title=f"Cookie `{cookie.name}` missing Secure flag",
                        url=page.url,
                        evidence=f"Set-Cookie for `{cookie.name}` had no `Secure` attribute on an HTTPS page.",
                        remediation=f"Set the `Secure` flag on the `{cookie.name}` cookie so it is "
                        "never sent over plain HTTP, protecting it from network eavesdroppers.",
                    )
                )
            if not httponly:
                report.add(
                    Finding(
                        check=NAME,
                        severity=severity,
                        title=f"Cookie `{cookie.name}` missing HttpOnly flag",
                        url=page.url,
                        evidence=f"Set-Cookie for `{cookie.name}` had no `HttpOnly` attribute.",
                        remediation=f"Set `HttpOnly` on the `{cookie.name}` cookie so client-side "
                        "JavaScript cannot read it, limiting damage from any XSS that does "
                        "occur (session theft).",
                    )
                )
            if not samesite:
                report.add(
                    Finding(
                        check=NAME,
                        severity=Severity.LOW,
                        title=f"Cookie `{cookie.name}` missing SameSite attribute",
                        url=page.url,
                        evidence=f"Set-Cookie for `{cookie.name}` had no `SameSite` attribute.",
                        remediation=f"Set `SameSite=Lax` (or `Strict` for highly sensitive "
                        f"cookies) on `{cookie.name}` to mitigate CSRF by default.",
                    )
                )
