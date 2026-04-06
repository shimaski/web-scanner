"""Reflected XSS detection scanner."""

import html
import re
from urllib.parse import parse_qs, urlparse

from web_scanner.scanner import BaseScanner

# XSS payloads that trigger different contexts
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "'\"><script>alert(1)</script>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
    "\"><img src=x onerror=alert(1)>",
    "<iframe src=javascript:alert(1)>",
]


class XSSScanner(BaseScanner):
    """Detect reflected XSS by injecting payloads into URL parameters."""

    def run(self) -> list[dict]:
        findings: list[dict] = []

        # Test root page with various payloads
        resp = self.client.get("/")
        if resp is None:
            return findings

        # Extract any query parameters from links on the page
        test_params = self._extract_params(resp.text)
        test_params = test_params if test_params else ["q", "search", "id", "page", "redirect", "url", "lang", "file"]

        for param in test_params:
            for payload in XSS_PAYLOADS:
                query = f"?{param}={payload}"
                resp = self.client.get(query)
                if resp is None:
                    continue

                # Check if payload is reflected in response
                if payload in resp.text:
                    # Check if it's unencoded (actual vulnerability) vs HTML-encoded
                    if self._is_reflected_unsafe(resp.text, payload):
                        findings.append({
                            "severity": "HIGH",
                            "title": f"Reflected XSS via parameter '{param}'",
                            "detail": f"URL: {self._full_url(f'?{param}={payload[:40]}')}\nPayload reflected raw in response",
                        })
                        break  # One finding per param is enough

        return findings

    def _extract_params(self, html: str) -> list[str]:
        """Extract parameter names from URLs found in page."""
        params = set()
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, "html.parser")
            for tag in soup.find_all(True, href=True):
                href = tag["href"]
                if "?" in href:
                    parsed = urlparse(href)
                    params.update(parse_qs(parsed.query).keys())
        except Exception:
            pass
        return list(params)

    def _is_reflected_unsafe(self, body: str, payload: str) -> bool:
        """Check if the payload appears un-encoded in the response."""
        encoded = html.escape(payload)
        return payload in body and encoded not in body
