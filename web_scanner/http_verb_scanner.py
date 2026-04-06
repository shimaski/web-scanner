"""HTTP Verb Tampering — detect method bypass on restricted endpoints."""

import logging

from web_scanner.scanner import BaseScanner

logger = logging.getLogger(__name__)

# Methods to try beyond GET/POST
METHODS_TO_TEST = ["DELETE", "PUT", "PATCH", "OPTIONS", "HEAD", "TRACE", "TRACK"]


class HTTPVerbScanner(BaseScanner):
    """Detect HTTP verb tampering by trying non-standard methods on endpoints."""

    def run(self):
        findings: list[dict] = []

        # First, establish baseline
        base_get = self.client.get("/")
        if base_get is None:
            return findings

        base_code = base_get.status_code
        base_length = len(base_get.text)

        # Also test GET on admin-like paths
        test_paths = ["/", "/admin", "/dashboard", "/api/users", "/config"]

        for path in test_paths:
            resp_check = self.client.get(path)
            if resp_check is None:
                continue

            # Always check TRACE/TRACK — should be disabled regardless of auth
            for method in ("TRACE", "TRACK"):
                resp = self.client.request(method, path)
                if resp is None:
                    continue
                if resp.status_code == 200:
                    findings.append({
                        "severity": "MEDIUM",
                        "title": f"HTTP {method} enabled on {path}",
                        "detail": f"URL: {self._full_url(path)}\nTRACE/TRACK method enabled — cross-site tracing (XST) possible",
                    })
                    break

            if resp_check.status_code in (403, 401, 405):
                # Restricted with GET/POST — try other methods
                for method in METHODS_TO_TEST:
                    resp = self.client.request(method, path)
                    if resp is None:
                        continue

                    # Bypass if we get 200 with a forbidden method
                    if resp.status_code == 200 and len(resp.text) > base_length * 0.8:
                        findings.append({
                            "severity": "HIGH",
                            "title": f"HTTP verb tampering bypass on {path} via {method}",
                            "detail": f"URL: {self._full_url(path)}\nGET/POST blocked (403/401/405) but {method} returned 200 with content",
                        })
                        break

        return findings
