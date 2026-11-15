"""CSRF protection check: do state-changing forms include an anti-CSRF token field?

This is purely static analysis of crawled HTML — no forms are ever submitted.
"""

from __future__ import annotations

import re

from ..findings import Finding, Report, Severity

NAME = "csrf"

_TOKEN_NAME_HINTS = re.compile(
    r"csrf|xsrf|authenticity_token|_token|nonce|anti.?forgery", re.IGNORECASE
)
_STATE_CHANGING_METHODS = {"post", "put", "patch", "delete"}


def run(pages, session, report: Report, args) -> None:
    reported = set()
    for page in pages:
        for form in page.forms:
            if form.method not in _STATE_CHANGING_METHODS:
                continue
            key = (form.action, form.method)
            if key in reported:
                continue
            has_token = any(_TOKEN_NAME_HINTS.search(f) for f in form.fields)
            if not has_token:
                reported.add(key)
                report.add(
                    Finding(
                        check=NAME,
                        severity=Severity.MEDIUM,
                        title="State-changing form without a visible CSRF token field",
                        url=page.url,
                        evidence=f"A `{form.method.upper()}` form targeting `{form.action}` "
                        f"had fields {form.fields or '(none)'} — none matched common "
                        "CSRF token naming patterns.",
                        remediation="Add a per-session (or per-request) anti-CSRF token "
                        "as a hidden form field, validated server-side on submit. Most "
                        "frameworks provide this built-in (e.g. Django's `{% csrf_token "
                        "%}`, Rails' `form_authenticity_token`, Express with `csurf`). "
                        "Also consider `SameSite=Lax/Strict` cookies as defense in depth. "
                        "Note: a token delivered via a custom header for an AJAX/SPA "
                        "endpoint won't show up in static HTML — if that's the case here, "
                        "this finding is a false positive and can be disregarded.",
                    )
                )
