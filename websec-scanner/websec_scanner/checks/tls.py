"""TLS/SSL checks: certificate validity, protocol version, HTTP->HTTPS redirect."""

from __future__ import annotations

import datetime
import socket
import ssl
import urllib.parse as urlparse

from ..findings import Finding, Report, Severity

NAME = "tls"

_WEAK_PROTOCOLS = {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}


def run(pages, session, report: Report, args) -> None:
    if not pages:
        return
    base = pages[0].url
    parsed = urlparse.urlparse(base)
    host = parsed.hostname
    if not host:
        return

    if parsed.scheme == "http":
        report.add(
            Finding(
                check=NAME,
                severity=Severity.HIGH,
                title="Site is served over plain HTTP",
                url=base,
                evidence=f"Target scheme was `http://` for {host}.",
                remediation="Serve the site exclusively over HTTPS, and redirect all "
                "HTTP requests to HTTPS (301) with HSTS enabled.",
            )
        )
        # Still try HTTPS for cert checks, in case it exists but isn't the default.
    port = parsed.port or 443

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                proto = ssock.version()
    except ssl.SSLCertVerificationError as e:
        report.add(
            Finding(
                check=NAME,
                severity=Severity.CRITICAL,
                title="TLS certificate verification failed",
                url=f"https://{host}:{port}",
                evidence=str(e),
                remediation="Install a valid certificate chain (e.g. via Let's Encrypt) "
                "signed by a trusted CA for this exact hostname, and ensure "
                "intermediate certificates are served correctly.",
            )
        )
        return
    except (socket.timeout, socket.error, ssl.SSLError, ConnectionRefusedError) as e:
        report.add(
            Finding(
                check=NAME,
                severity=Severity.INFO,
                title="Could not establish TLS connection for inspection",
                url=f"https://{host}:{port}",
                evidence=str(e),
                remediation="If HTTPS should be available on this host/port, verify the "
                "TLS listener is correctly configured and reachable.",
            )
        )
        return

    if proto in _WEAK_PROTOCOLS:
        report.add(
            Finding(
                check=NAME,
                severity=Severity.HIGH,
                title=f"Outdated TLS protocol negotiated: {proto}",
                url=f"https://{host}:{port}",
                evidence=f"Connection negotiated {proto}.",
                remediation="Disable TLS 1.0/1.1 and SSLv2/v3 on the server; require "
                "TLS 1.2 as a minimum (TLS 1.3 preferred).",
            )
        )

    not_after = cert.get("notAfter")
    if not_after:
        try:
            expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry - datetime.datetime.utcnow()).days
            if days_left < 0:
                report.add(
                    Finding(
                        check=NAME,
                        severity=Severity.CRITICAL,
                        title="TLS certificate has expired",
                        url=f"https://{host}:{port}",
                        evidence=f"Certificate expired on {not_after}.",
                        remediation="Renew the TLS certificate immediately and set up "
                        "automated renewal (e.g. certbot with a cron/systemd timer).",
                    )
                )
            elif days_left < 14:
                report.add(
                    Finding(
                        check=NAME,
                        severity=Severity.MEDIUM,
                        title="TLS certificate expires soon",
                        url=f"https://{host}:{port}",
                        evidence=f"Certificate expires on {not_after} ({days_left} days left).",
                        remediation="Renew the TLS certificate before it expires, and "
                        "set up automated renewal if not already in place.",
                    )
                )
        except ValueError:
            pass
