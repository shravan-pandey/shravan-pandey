"""CLI entry point: python3 -m websec_scanner.cli --url https://example.com --i-am-authorized"""

from __future__ import annotations

import argparse
import sys
import urllib.parse as urlparse

import requests
import urllib3

from .checks import ALL_CHECK_MODULES
from .crawler import Crawler
from .findings import Report

# This tool only ever talks to a target the user explicitly names and confirms
# they're authorized to test; it does not disable TLS verification by default.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="websec-scanner",
        description="Non-destructive web vulnerability crawler/scanner for sites you own or are authorized to test.",
    )
    p.add_argument("--url", required=True, help="Target base URL, e.g. https://example.com")
    p.add_argument(
        "--i-am-authorized",
        action="store_true",
        required=True,
        help="Required: confirms you own this target or have written authorization to test it.",
    )
    p.add_argument("--max-pages", type=int, default=50, help="Max pages to crawl (default: 50)")
    p.add_argument("--max-depth", type=int, default=3, help="Max link depth from the start URL (default: 3)")
    p.add_argument("--delay", type=float, default=0.5, help="Seconds to wait between requests (default: 0.5)")
    p.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout in seconds (default: 10)")
    p.add_argument("--output", default=None, help="Path to write the Markdown report (default: print to stdout only)")
    p.add_argument(
        "--cookie",
        action="append",
        default=[],
        metavar="NAME=VALUE",
        help="Cookie to send with every request (repeatable), e.g. for scanning pages behind login.",
    )
    p.add_argument(
        "--header",
        action="append",
        default=[],
        metavar="NAME: VALUE",
        help="Extra header to send with every request (repeatable), e.g. an Authorization token.",
    )
    p.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification (only for self-signed local/staging certs).",
    )
    p.add_argument(
        "--user-agent",
        default="websec-scanner/0.1 (+authorized security self-test)",
        help="User-Agent string to send (identifying the scanner is good practice on shared infra).",
    )
    return p.parse_args(argv)


def build_session(args: argparse.Namespace) -> requests.Session:
    session = requests.Session()
    session.headers["User-Agent"] = args.user_agent
    for raw in args.header:
        if ":" not in raw:
            print(f"warning: ignoring malformed --header value: {raw!r}", file=sys.stderr)
            continue
        name, _, value = raw.partition(":")
        session.headers[name.strip()] = value.strip()
    for raw in args.cookie:
        if "=" not in raw:
            print(f"warning: ignoring malformed --cookie value: {raw!r}", file=sys.stderr)
            continue
        name, _, value = raw.partition("=")
        session.cookies.set(name.strip(), value.strip())
    if args.insecure:
        session.verify = False
    return session


def main(argv=None) -> int:
    args = parse_args(argv)

    parsed = urlparse.urlparse(args.url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        print(f"error: --url must be a full http(s) URL, got: {args.url}", file=sys.stderr)
        return 2

    print(f"[*] Target: {args.url}")
    print(f"[*] Authorization confirmed via --i-am-authorized. Scope: {parsed.netloc} only.")
    print(f"[*] Crawling up to {args.max_pages} pages (depth {args.max_depth}), {args.delay}s delay between requests...")

    session = build_session(args)
    crawler = Crawler(
        base_url=args.url,
        session=session,
        max_pages=args.max_pages,
        max_depth=args.max_depth,
        delay=args.delay,
        timeout=args.timeout,
    )
    pages = crawler.crawl()
    print(f"[*] Crawled {len(pages)} page(s). Running checks...")

    report = Report(target=args.url, pages_crawled=len(pages))
    for module in ALL_CHECK_MODULES:
        try:
            module.run(pages, session, report, args)
        except Exception as e:  # a single check failing shouldn't abort the whole scan
            print(f"warning: check '{module.NAME}' raised {e!r}", file=sys.stderr)

    markdown = report.to_markdown()
    if args.output:
        with open(args.output, "w") as f:
            f.write(markdown)
        print(f"[*] Report written to {args.output}")

    print()
    print(f"=== Summary: {report.summary_line()} ===")
    if not args.output:
        print()
        print(markdown)

    return 0


if __name__ == "__main__":
    sys.exit(main())
