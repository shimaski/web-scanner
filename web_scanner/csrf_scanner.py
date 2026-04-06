"""CSRF vulnerability detection."""

from web_scanner.scanner import BaseScanner

CSRF_TOKEN_NAMES = [
    "csrf_token", "_token", "csrfmiddlewaretoken", "authenticity_token",
    "csrf", "xsrf_token", "x-csrf-token", "x_xsrf_token",
]


class CSRFScanner(BaseScanner):
    """Detect missing CSRF protection in forms."""

    def run(self) -> list[dict]:
        findings: list[dict] = []

        resp = self.client.get("/")
        if resp is None:
            return findings

        # Check forms for CSRF tokens
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(resp.text, "html.parser")

        forms = soup.find_all("form")
        forms_with_post = [f for f in forms if f.get("method", "get").upper() == "POST"]

        for form in forms_with_post:
            has_token = False
            for inp in form.find_all(["input"]):
                name = inp.get("name", "").lower()
                if name in CSRF_TOKEN_NAMES:
                    has_token = True
                    break

            # Also check hidden inputs
            if not has_token:
                for inp in form.find_all("input", type="hidden"):
                    if any(t in inp.get("name", "").lower() for t in CSRF_TOKEN_NAMES):
                        has_token = True
                        break

            if not has_token:
                action = form.get("action", "/")
                findings.append({
                    "severity": "MEDIUM",
                    "title": f"Form without CSRF protection: {action}",
                    "detail": f"URL: {self._full_url(action)}\nPOST form has no CSRF token",
                })

        # Check for CSRF header in requests
        found_csrf_header = False
        for name in ["x-csrf-token", "x-xsrf-token"]:
            if resp.request.headers.get(name):
                found_csrf_header = True
                break

        # Check SameSite cookie attribute
        cookies_headers = resp.headers.get_list("Set-Cookie") if hasattr(resp.headers, 'get_list') else [resp.headers.get("Set-Cookie", "")]
        for cookie_str in cookies_headers:
            if not cookie_str:
                continue
            cookie_lower = cookie_str.lower()
            if "samesite" not in cookie_lower and "secure" not in cookie_lower:
                findings.append({
                    "severity": "LOW",
                    "title": "Cookie without SameSite attribute",
                    "detail": f"Cookie may be vulnerable to CSRF: {cookie_str[:60]}...",
                })

        return findings
