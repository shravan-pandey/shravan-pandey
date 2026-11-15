"""Polite, same-domain-only crawler.

Deliberately conservative: bounded page count, bounded depth, a delay between
every request, and it never leaves the target's registered domain. It also
never submits forms with real data — it only records form metadata (action,
method, field names) for the CSRF check to inspect.
"""

from __future__ import annotations

import time
import urllib.parse as urlparse
from dataclasses import dataclass, field

import requests
from bs4 import BeautifulSoup


@dataclass
class FormInfo:
    action: str
    method: str
    fields: list[str]


@dataclass
class Page:
    url: str
    status_code: int
    headers: object  # requests.structures.CaseInsensitiveDict — keep case-insensitive lookups
    text: str
    forms: list[FormInfo] = field(default_factory=list)


def _registrable_domain(netloc: str) -> str:
    """Rough same-site check: last two labels (good enough for scoping a crawl)."""
    parts = netloc.split(":")[0].split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else netloc


class Crawler:
    def __init__(
        self,
        base_url: str,
        session: requests.Session,
        max_pages: int = 50,
        max_depth: int = 3,
        delay: float = 0.5,
        timeout: float = 10.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.session = session
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.delay = delay
        self.timeout = timeout
        self.base_domain = _registrable_domain(urlparse.urlparse(self.base_url).netloc)
        self.visited: set[str] = set()
        self.pages: list[Page] = []

    def _in_scope(self, url: str) -> bool:
        parsed = urlparse.urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        return _registrable_domain(parsed.netloc) == self.base_domain

    def _normalize(self, url: str) -> str:
        parsed = urlparse.urlparse(url)
        return parsed._replace(fragment="").geturl()

    def fetch(self, url: str):
        """Fetch a single URL (used by checks too, to reuse the rate-limited session)."""
        time.sleep(self.delay)
        try:
            return self.session.get(url, timeout=self.timeout, allow_redirects=True)
        except requests.RequestException:
            return None

    def crawl(self) -> list[Page]:
        queue: list[tuple[str, int]] = [(self.base_url, 0)]
        while queue and len(self.pages) < self.max_pages:
            url, depth = queue.pop(0)
            norm = self._normalize(url)
            if norm in self.visited:
                continue
            self.visited.add(norm)

            resp = self.fetch(norm)
            if resp is None:
                continue

            content_type = resp.headers.get("Content-Type", "")
            text = resp.text if "text" in content_type or "html" in content_type else ""
            # Keep requests' CaseInsensitiveDict as-is (don't flatten to a plain dict):
            # servers vary in header casing (e.g. "content-security-policy" vs
            # "Content-Security-Policy"), and a plain dict's case-sensitive lookups
            # would wrongly report present headers as missing.
            page = Page(url=norm, status_code=resp.status_code, headers=resp.headers, text=text)

            if text:
                soup = BeautifulSoup(text, "html.parser")
                page.forms = self._extract_forms(soup, norm)
                if depth < self.max_depth:
                    for link in soup.find_all("a", href=True):
                        next_url = urlparse.urljoin(norm, link["href"])
                        next_norm = self._normalize(next_url)
                        if self._in_scope(next_norm) and next_norm not in self.visited:
                            queue.append((next_norm, depth + 1))

            self.pages.append(page)
        return self.pages

    @staticmethod
    def _extract_forms(soup: BeautifulSoup, page_url: str) -> list[FormInfo]:
        forms = []
        for form in soup.find_all("form"):
            action = urlparse.urljoin(page_url, form.get("action", ""))
            method = form.get("method", "get").lower()
            fields = [
                inp.get("name", "")
                for inp in form.find_all(["input", "textarea", "select"])
                if inp.get("name")
            ]
            forms.append(FormInfo(action=action, method=method, fields=fields))
        return forms
