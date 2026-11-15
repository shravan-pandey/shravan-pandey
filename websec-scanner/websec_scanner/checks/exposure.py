"""Checks for publicly accessible sensitive files/paths (.git, .env, backups, directory listing)."""

from __future__ import annotations

import urllib.parse as urlparse

from ..findings import Finding, Report, Severity

NAME = "exposed-files"

# Path -> (severity, description, remediation)
_SENSITIVE_PATHS = {
    ".git/config": (
        Severity.CRITICAL,
        "Exposed `.git` repository",
        "Remove the `.git` directory from the deployed web root, or block web "
        "server access to any dot-directories. An exposed `.git` folder lets "
        "anyone download your entire source history, including past secrets.",
    ),
    ".git/HEAD": (
        Severity.CRITICAL,
        "Exposed `.git` repository",
        "Remove the `.git` directory from the deployed web root, or block web "
        "server access to any dot-directories.",
    ),
    ".env": (
        Severity.CRITICAL,
        "Exposed `.env` file",
        "Never deploy `.env` files into the public web root. Move secrets to "
        "environment variables set by your hosting platform/process manager, "
        "or a secrets manager, and rotate any credentials this file may have "
        "exposed.",
    ),
    ".env.local": (
        Severity.CRITICAL,
        "Exposed `.env.local` file",
        "Same as `.env` — remove from the public web root and rotate any "
        "exposed credentials.",
    ),
    "wp-config.php.bak": (
        Severity.CRITICAL,
        "Exposed WordPress config backup",
        "Delete backup files from the web root; they often render as plain "
        "text and leak DB credentials.",
    ),
    "config.php.bak": (
        Severity.CRITICAL,
        "Exposed config backup file",
        "Delete backup files from the web root.",
    ),
    "backup.zip": (
        Severity.HIGH,
        "Exposed backup archive",
        "Remove backup archives from the public web root; store backups "
        "outside of web-served directories.",
    ),
    "database.sql": (
        Severity.CRITICAL,
        "Exposed SQL database dump",
        "Remove database dump files from the web root immediately and rotate "
        "any credentials/secrets stored in the data.",
    ),
    "dump.sql": (
        Severity.CRITICAL,
        "Exposed SQL database dump",
        "Remove database dump files from the web root immediately.",
    ),
    ".DS_Store": (
        Severity.LOW,
        "Exposed `.DS_Store` file",
        "Remove `.DS_Store` files from the deployed site and add them to "
        "`.gitignore`/deployment excludes; they can leak directory listings "
        "of local folder structure.",
    ),
    "web.config": (
        Severity.MEDIUM,
        "Exposed IIS `web.config`",
        "Ensure `web.config` is not served as plain text; verify the handler "
        "mapping that normally protects this file is intact.",
    ),
    "phpinfo.php": (
        Severity.HIGH,
        "Exposed `phpinfo()` page",
        "Remove `phpinfo.php` (or any debug endpoint calling `phpinfo()`) from "
        "production — it discloses PHP version, loaded extensions, paths, and "
        "sometimes environment variables.",
    ),
    ".htpasswd": (
        Severity.CRITICAL,
        "Exposed `.htpasswd` credential file",
        "Remove or relocate `.htpasswd` outside the web root and rotate the "
        "credentials it contained.",
    ),
    "server-status": (
        Severity.MEDIUM,
        "Exposed Apache `server-status` page",
        "Disable or restrict `mod_status` (`server-status`) to internal IPs "
        "only — it discloses active request URLs, client IPs, and internal "
        "paths.",
    ),
}

_LISTING_MARKERS = ("Index of /", "<title>Directory listing for", "Parent Directory</a>")


def run(pages, session, report: Report, args) -> None:
    if not pages:
        return
    base = pages[0].url
    parsed = urlparse.urlparse(base)
    root = f"{parsed.scheme}://{parsed.netloc}/"

    reported_paths = set()
    for path, (severity, title, remediation) in _SENSITIVE_PATHS.items():
        if path in reported_paths:
            continue
        url = urlparse.urljoin(root, path)
        try:
            resp = session.get(url, timeout=10, allow_redirects=False)
        except Exception:
            continue
        if resp.status_code == 200 and len(resp.content) > 0:
            # Avoid false positives from catch-all SPA routes that return 200 for everything.
            if resp.headers.get("Content-Type", "").startswith("text/html") and b"<html" in resp.content[:500].lower():
                # Likely an SPA fallback page, not the real file — skip unless the path itself
                # looks like it returned structured non-HTML content.
                if path not in (".git/HEAD", ".git/config"):
                    continue
            reported_paths.add(path)
            report.add(
                Finding(
                    check=NAME,
                    severity=severity,
                    title=title,
                    url=url,
                    evidence=f"GET {url} returned HTTP {resp.status_code} with {len(resp.content)} bytes.",
                    remediation=remediation,
                )
            )

    # Directory listing check on crawled directory-like URLs
    checked_dirs = set()
    for page in pages:
        if not page.text:
            continue
        if page.url in checked_dirs:
            continue
        checked_dirs.add(page.url)
        if any(marker in page.text for marker in _LISTING_MARKERS):
            report.add(
                Finding(
                    check="directory-listing",
                    severity=Severity.MEDIUM,
                    title="Directory listing enabled",
                    url=page.url,
                    evidence="Response body matched directory-index markers "
                    "(e.g. 'Index of /').",
                    remediation="Disable autoindex/directory browsing on the web "
                    "server (e.g. `Options -Indexes` in Apache, remove `autoindex on;` "
                    "in nginx) and add an `index.html` to directories that must stay "
                    "public.",
                )
            )
