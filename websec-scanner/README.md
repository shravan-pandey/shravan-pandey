# websec-scanner

A command-line web vulnerability crawler/scanner for testing **your own** websites and applications.

It crawls a target site (staying within the same domain), and runs a set of
non-destructive checks commonly used in DAST (Dynamic Application Security
Testing) tools like OWASP ZAP and Nikto, then produces a plain-text/Markdown
report with concrete remediation suggestions.

## ⚠️ Authorization required

This tool **will refuse to run** unless you pass `--i-am-authorized`,
explicitly confirming that you own the target or have written permission to
test it (e.g. a pentest engagement letter, bug bounty program scope, or it's
your own staging/production site).

Scanning a website you do not own or have explicit permission to test is
illegal in most jurisdictions (e.g. the US Computer Fraud and Abuse Act, UK
Computer Misuse Act) even when using "safe" detection probes. Only use this
against:

- Sites/apps you personally own or operate
- Targets covered by a signed pentest engagement or bug bounty program scope
- Intentionally vulnerable practice labs (DVWA, Juice Shop, WebGoat, etc.)

## What it checks

All checks are **read-only / non-destructive** — they detect conditions, they
don't exploit them, modify data, brute force credentials, or send floods of
traffic. This is a vulnerability *scanner*, not an exploitation framework.

| Category | What it looks for |
|---|---|
| Security headers | Missing CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy |
| Cookie flags | Missing `Secure`, `HttpOnly`, `SameSite` on session-looking cookies |
| TLS/SSL | Expired/weak certs, outdated protocol versions, missing redirect to HTTPS |
| Clickjacking | Missing frame-busting headers (`X-Frame-Options` / CSP `frame-ancestors`) |
| CORS misconfiguration | `Access-Control-Allow-Origin` reflecting arbitrary Origin + credentials |
| Exposed sensitive files | `.git/`, `.env`, backup files, config files, `.DS_Store`, etc. left publicly accessible |
| HTTP methods | Dangerous methods enabled (`TRACE`, `PUT`, `DELETE`, etc.) |
| Reflected XSS (probe-based) | Benign marker string reflected unescaped in responses |
| SQL error disclosure | DB error messages triggered by a single harmless `'` probe |
| Open redirect | Redirect/return-url parameters that accept arbitrary external URLs |
| CSRF protection | Forms (POST/PUT/DELETE) without a visible anti-CSRF token field |
| Outdated client-side libraries | Known-old jQuery/Bootstrap/Angular versions loaded from CDNs |
| Directory listing | Autoindex-style directory browsing enabled |
| Server/software fingerprint | Verbose `Server`/`X-Powered-By` banners leaking version info |

## Install

```bash
cd websec-scanner
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python3 -m websec_scanner.cli --url https://your-own-site.example \
  --i-am-authorized \
  --max-pages 50 \
  --delay 0.5 \
  --output report.md
```

Key flags:

- `--url` — target to scan (required)
- `--i-am-authorized` — required confirmation flag (required)
- `--max-pages` — crawl page budget, default 50 (keeps the tool from running forever / hammering a big site)
- `--delay` — seconds between requests, default 0.5 (politeness/rate-limit; raise it on smaller servers)
- `--max-depth` — crawl link depth, default 3
- `--output` — write Markdown report to this file (also prints a summary to stdout)
- `--cookie "name=value"` — pass an auth cookie to scan pages behind login (repeatable)
- `--header "Name: value"` — pass a custom header, e.g. an Authorization bearer token (repeatable)

The crawler never leaves the target's registered domain, never submits forms
(other than the two detection probes above, which only add a URL query
parameter — no POST bodies are sent to state-changing endpoints), and does
not attempt login/credential brute force, denial-of-service, or exploitation
of anything it finds.

## Output

A Markdown report grouped by severity (Critical/High/Medium/Low/Info), each
finding with: the URL it was found on, evidence, and a specific remediation
suggestion (e.g. exact header to add, a code snippet, or a config change).

## Disclaimer

This tool is provided for legitimate security testing of systems you own or
are authorized to test. You are responsible for ensuring you have proper
authorization before scanning any target.
