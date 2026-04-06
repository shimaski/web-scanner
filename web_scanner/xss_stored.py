"""Stored XSS detection scanner."""

from web_scanner.config import ScanConfig
from web_scanner.http_client import HTTPClient
from web_scanner.scanner import BaseScanner

STORED_XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    '<iframe srcdoc="<script>alert(1)</script>">',
    "<marquee onstart=alert(1)>",
    "<details open ontoggle=alert(1)>",
]

# Common POST fields that reflect data
COMMON_FORM_FIELDS = [
    "comment", "message", "content", "body", "text", "name",
    "title", "description", "bio", "about", "signature",
    "username", "nickname", "display_name",
]


class StoredXSSScanner(BaseScanner):
    """Detect stored XSS by submitting payloads via POST and checking other pages."""

    def run(self) -> list[dict]:
        findings: list[dict] = []

        from bs4 import BeautifulSoup
        resp = self.client.get("/")
        if resp is None:
            return findings

        soup = BeautifulSoup(resp.text, "html.parser")

        # Find POST forms
        forms = soup.find_all("form", method=lambda v: v and v.lower() == "post")
        if not forms:
            # Try common form fields on known paths
            findings.extend(self._test_common_paths())
            return findings

        for form in forms:
            action = form.get("action", "/")
            inputs = form.find_all(["input", "textarea", "select"])

            for inp in inputs:
                name = inp.get("name", "")
                if not name or inp.get("type") == "hidden":
                    continue

                for payload in STORED_XSS_PAYLOADS:
                    data = {name: payload}
                    self.client.post(action, data=data)

                    # Check if payload appears on other pages
                    for check_path in ["/", "/about", "/profile", "/users", "/posts"]:
                        resp_check = self.client.get(check_path)
                        if resp_check and payload in resp_check.text:
                            findings.append({
                                "severity": "CRITICAL",
                                "title": f"Stored XSS via form field '{name}' on {action}",
                                "detail": f"Payload reflected on {check_path} after POST",
                            })
                            break

        return findings

    def _test_common_paths(self) -> list[dict]:
        findings = []
        for field in COMMON_FORM_FIELDS[:3]:
            for payload in STORED_XSS_PAYLOADS[:2]:
                # Try common POST endpoints
                for endpoint in ["/comment", "/post", "/submit", "/api/comment", "/feedback"]:
                    resp = self.client.post(endpoint, data={field: payload})
                    if resp is None:
                        continue
                    if resp.status_code in (200, 201, 302):
                        # Check reflection
                        resp2 = self.client.get("/")
                        if resp2 and payload in resp2.text:
                            findings.append({
                                "severity": "CRITICAL",
                                "title": f"Stored XSS via '{field}' on {endpoint}",
                                "detail": f"Payload persisted and reflected on homepage",
                            })
                            break
        return findings
