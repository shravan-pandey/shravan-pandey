# Security Scan Report: https://swarrehab.com

- Scanned at: 2026-11-15T08:58:20.111774Z
- Pages crawled: 40
- Total findings: 7 (Medium: 3, Low: 2, Info: 2)

---

## Medium (3)

### 1. Missing Content-Security-Policy header
- **Check:** `security-headers`
- **URL:** https://swarrehab.com
- **Evidence:** Response headers did not include `Content-Security-Policy`.
- **Remediation:** Add a `Content-Security-Policy` header restricting script/style/frame sources, e.g. `Content-Security-Policy: default-src 'self'`. This is the strongest single mitigation against XSS and data-exfiltration via injected scripts.

### 2. Missing Strict-Transport-Security (HSTS) header
- **Check:** `security-headers`
- **URL:** https://swarrehab.com
- **Evidence:** Response headers did not include `Strict-Transport-Security`.
- **Remediation:** Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` (only on HTTPS responses) to force browsers to always use HTTPS for this domain, preventing SSL-stripping downgrade attacks.

### 3. No clickjacking protection (X-Frame-Options / frame-ancestors)
- **Check:** `clickjacking`
- **URL:** https://swarrehab.com
- **Evidence:** Neither `X-Frame-Options` nor CSP `frame-ancestors` was present.
- **Remediation:** Add `X-Frame-Options: DENY` (or `SAMEORIGIN` if you intentionally frame your own pages) and/or a CSP `frame-ancestors 'none'` directive to prevent the page being embedded in a malicious iframe for clickjacking.

## Low (2)

### 1. Missing X-Content-Type-Options header
- **Check:** `security-headers`
- **URL:** https://swarrehab.com
- **Evidence:** Response headers did not include `X-Content-Type-Options`.
- **Remediation:** Add `X-Content-Type-Options: nosniff` to stop browsers from MIME-sniffing responses into an executable type.

### 2. Missing Referrer-Policy header
- **Check:** `security-headers`
- **URL:** https://swarrehab.com
- **Evidence:** Response headers did not include `Referrer-Policy`.
- **Remediation:** Add `Referrer-Policy: strict-origin-when-cross-origin` (or stricter) to avoid leaking full URLs (possibly containing tokens) to third-party sites via the Referer header.

## Info (2)

### 1. Missing Permissions-Policy header
- **Check:** `security-headers`
- **URL:** https://swarrehab.com
- **Evidence:** Response headers did not include `Permissions-Policy`.
- **Remediation:** Add a `Permissions-Policy` header to explicitly disable browser features (camera, microphone, geolocation, etc.) your site doesn't use.

### 2. Could not establish TLS connection for inspection
- **Check:** `tls`
- **URL:** https://swarrehab.com:443
- **Evidence:** [Errno -2] Name or service not known
- **Remediation:** If HTTPS should be available on this host/port, verify the TLS listener is correctly configured and reachable.
