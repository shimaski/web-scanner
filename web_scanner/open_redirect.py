"""Open redirect detection scanner (enhanced)."""

import re
from urllib.parse import parse_qs, urlparse

from web_scanner.scanner import BaseScanner

# Core redirect payloads — target evil.com / google.com for detection
REDIRECT_PAYLOADS = [
    "http://evil.com",
    "//evil.com",
    "https://evil.com",
    "http://localhost",
    "https://google.com%2f..%2f..%2f",
    "%2f%2fevil.com",
    # URL-encoded bypass payloads
    "%09evil.com",       # horizontal tab
    "%0aevil.com",       # line feed
    "%0devil.com",       # carriage return
    "%00evil.com",       # null byte
    "//evil.com/%2f%2e%2e",  # encoded /..
    # Protocol-relative bypasses
    "//%09/evil.com",
    "/%5c/%5c/evil.com",
    "/%5c/evil.com",
    # Scheme manipulation
    "https:evil.com",
    "http:/evil.com",
    "/./evil.com",
    # Backslash variants (encoded)
    "/%2f/evil.com",
]

REDIRECT_PARAMS = [
    "url", "redirect", "next", "return", "returnUrl", "return_url",
    "to", "target", "dest", "destination", "go", "link", "forward",
    "redir", "rurl", "checkout_url", "continue",
    "u", "src", "page", "ref", "redirect_url", "redirectUrl",
    "callback", "goto", "next_url", "nextPage", "back",
]


class OpenRedirectScanner(BaseScanner):
    """Detect open redirects via URL parameters and JavaScript sinks."""

    def run(self) -> list[dict]:
        findings: list[dict] = []

        resp = self.client.get("/")
        if resp is None:
            return findings

        # Discover redirect-prone params
        test_params: list[str] = self._discover_params(resp.text)
        test_params = list(dict.fromkeys(test_params + REDIRECT_PARAMS))

        findings += self._test_parameters(test_params)
        findings += self._check_javascript_redirects(resp.text)

        return findings

    # -- parameter testing ------------------------------------------------

    def _test_parameters(self, params: list[str]) -> list[dict]:
        findings: list[dict] = []
        seen = set()

        for param in params:
            for payload in REDIRECT_PAYLOADS:
                resp = self.client.get(f"?{param}={payload}", allow_redirects=False)
                if resp is None:
                    continue

                key = (param, payload)

                # 3xx redirect to an external domain
                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location", "")
                    if self._is_external_redirect(location):
                        dedup_key = (param, location)
                        if dedup_key not in seen:
                            seen.add(dedup_key)
                            findings.append({
                                "severity": "MEDIUM",
                                "title": f"Open Redirect via parameter '{param}'",
                                "detail": (
                                    f"Parameter '{param}' redirects to: "
                                    f"{location[:120]} (status {resp.status_code})"
                                ),
                            })
                        break

                # Meta refresh
                if "meta" in resp.text.lower() and "refresh" in resp.text.lower():
                    if "evil.com" in resp.text or "google.com" in resp.text:
                        if key not in seen:
                            seen.add(key)
                            findings.append({
                                "severity": "MEDIUM",
                                "title": (
                                    f"Open Redirect (meta refresh) via '{param}'"
                                ),
                                "detail": "Meta refresh redirects to attacker domain",
                            })
                        break

            # Parameter pollution: ?url=good.com&url=evil.com
            findings += self._check_param_pollution(param)

        return findings

    def _check_param_pollution(self, param: str) -> list[dict]:
        findings: list[dict] = []
        pollution_payloads = [
            f"good.com&{param}=evil.com",
            f"good.com%26{param}=evil.com",
            f"good.com;{param}=evil.com",
            f"good.com%3B{param}=evil.com",
        ]
        for pp in pollution_payloads:
            resp = self.client.get(f"?{param}={pp}", allow_redirects=False)
            if resp is None:
                continue
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                if self._is_external_redirect(location):
                    findings.append({
                        "severity": "MEDIUM",
                        "title": (
                            f"Open Redirect (param pollution) via '{param}'"
                        ),
                        "detail": (
                            f"Parameter pollution redirects to: {location[:100]}"
                        ),
                    })
                    break
        return findings

    # -- JavaScript sink detection -----------------------------------------

    def _check_javascript_redirects(self, html: str) -> list[dict]:
        findings: list[dict] = []

        js_redirect_patterns = [
            r"location\.href\s*=\s*([^;]+)",
            r"window\.location\s*=\s*([^;]+)",
            r"window\.location\.href\s*=\s*([^;]+)",
            r"document\.location\s*=\s*([^;]+)",
            r"location\.assign\s*\([^)]+\)",
            r"location\.replace\s*\([^)]+\)",
            r"window\.open\s*\([^)]+\)",
        ]

        for pattern in js_redirect_patterns:
            for match in re.finditer(pattern, html, re.IGNORECASE):
                sink = match.group(1).strip()
                # Flag if the sink uses an untrusted value (queryParams, params, search, hash)
                if self._uses_untrusted_source(sink):
                    findings.append({
                        "severity": "MEDIUM",
                        "title": "JavaScript-based redirect using untrusted source",
                        "detail": (
                            f"Sink: {match.group(0)[:80]} — uses untrusted data "
                            f"for client-side redirect"
                        ),
                    })

        return findings

    # -- helpers -----------------------------------------------------------

    def _discover_params(self, html: str) -> list[str]:
        params: list[str] = []
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, "html.parser")
            for form in soup.find_all("form"):
                for inp in form.find_all(["input", "select"]):
                    name = inp.get("name", "")
                    for rp in REDIRECT_PARAMS:
                        if rp.lower() in name.lower():
                            params.append(name)
            for tag in soup.find_all(True, href=True):
                href = tag.get("href", "")
                if "?" in href:
                    for p in parse_qs(urlparse(href).query):
                        for rp in REDIRECT_PARAMS:
                            if rp.lower() in p.lower():
                                params.append(p)
        except Exception:
            pass
        return params

    def _is_external_redirect(self, location: str) -> bool:
        """Return True if the Location header points outside the target."""
        danger = ["evil.com", "google.com"]
        return any(d in location.lower() for d in danger)

    def _uses_untrusted_source(self, sink: str) -> bool:
        untrusted_markers = [
            "location.search", "location.hash", "document.URL",
            "document.documentURI", "document.referrer",
            "location.hostname", "URLSearchParams",
            "getQueryParam", "getParameter", "params[",
            "$location", "window.location",
        ]
        return any(m in sink for m in untrusted_markers)
