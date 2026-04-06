"""Tests for scanner modules using mocks."""

import unittest.mock as mock
from unittest.mock import MagicMock

from web_scanner.config import ScanConfig
from web_scanner.cors_scanner import CORSScanner
from web_scanner.csrf_scanner import CSRFScanner
from web_scanner.info_gather import InfoGatherer
from web_scanner.xss_scanner import XSSScanner


def make_response(status_code=200, text="", headers=None):
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.headers = headers if headers is not None else {}
    resp.elapsed.total_seconds.return_value = 0.5
    resp.request = MagicMock()
    resp.request.headers = {}
    return resp


def make_client(target="https://example.com"):
    config = ScanConfig(target=target)
    return mock.MagicMock()


# --- InfoGatherer ---

class TestInfoGatherer:
    def test_unreachable_target(self):
        client = make_client()
        client.get.return_value = None
        scanner = InfoGatherer(client, ScanConfig(target="https://bad"))
        findings = scanner.run()
        assert len(findings) == 1
        assert findings[0]["severity"] == "HIGH"
        assert "unreachable" in findings[0]["title"].lower()

    def test_missing_security_headers(self):
        client = make_client()
        # Root response with NO security headers
        client.get.return_value = make_response(
            headers={"Content-Type": "text/html"}
        )
        scanner = InfoGatherer(client, ScanConfig(target="https://example.com"))
        findings = scanner.run()

        severities = [f["severity"] for f in findings]
        titles = [f["title"] for f in findings]

        assert "Missing HSTS header" in titles
        assert "Missing X-Content-Type-Options" in titles
        assert "Missing X-Frame-Options" in titles
        assert "Missing Content-Security-Policy" in titles

    def test_all_security_headers_present(self):
        headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "strict-origin",
            "Permissions-Policy": "geolocation=()",
        }
        client = make_client()
        client.get.return_value = make_response(headers=headers)
        scanner = InfoGatherer(client, ScanConfig(target="https://example.com"))
        findings = scanner.run()

        missing_titles = [f["title"] for f in findings if "missing" in f["title"].lower()]
        assert len(missing_titles) == 0

    def test_server_detection_nginx(self):
        client = make_client()
        client.get.return_value = make_response(
            headers={"Server": "nginx/1.25.0"}
        )
        scanner = InfoGatherer(client, ScanConfig(target="https://example.com"))
        findings = scanner.run()

        titles = [f["title"] for f in findings]
        assert any("Server technology detected" in t for t in titles)
        # Should NOT also report the Server header as a separate leakage finding
        server_leak = [f for f in findings if "Server header discloses" in f["title"]]
        assert len(server_leak) == 1

    def test_server_error_status(self):
        client = make_client()
        resp = make_response(status_code=500, headers={})
        client.get.return_value = resp
        scanner = InfoGatherer(client, ScanConfig(target="https://example.com"))
        findings = scanner.run()

        assert any("Server error" in f["title"] for f in findings)

    def test_sensitive_file_exposed(self):
        def mock_get(path, *args, **kwargs):
            if path in (".env", "phpinfo.php"):
                return make_response(status_code=200)
            return make_response(status_code=404)

        client = make_client()
        client.get.side_effect = mock_get
        scanner = InfoGatherer(client, ScanConfig(target="https://example.com"))
        findings = scanner.run()

        titles = [f["title"] for f in findings]
        assert any(".env" in t for t in titles)
        assert any("phpinfo" in t for t in titles)


# --- CORSScanner ---

class TestCORSScanner:
    def test_no_cors_headers(self):
        client = make_client()
        client.get.return_value = make_response(headers={})
        client.request.return_value = make_response(headers={})
        scanner = CORSScanner(client, ScanConfig(target="https://example.com"))
        findings = scanner.run()
        assert len(findings) == 0

    def test_wildcard_cors(self):
        client = make_client()
        client.get.return_value = make_response(
            headers={"Access-Control-Allow-Origin": "*"}
        )
        client.request.return_value = make_response()
        # Second call with evil.com origin also returns *
        client.get.side_effect = [
            make_response(headers={"Access-Control-Allow-Origin": "*"}),
            make_response(headers={"Access-Control-Allow-Origin": "*"}),
            make_response(headers={"Access-Control-Allow-Origin": "*"}),
            make_response(headers={"Access-Control-Allow-Origin": "*"}),
            make_response(headers={"Access-Control-Allow-Origin": "*"}),
            make_response(headers={"Access-Control-Allow-Origin": "*"}),
        ]

        scanner = CORSScanner(client, ScanConfig(target="https://example.com"))
        findings = scanner.run()
        assert any("wildcard" in f["title"] or "*" in f["title"] for f in findings)

    def test_reflected_origin(self):
        def mock_get(path, *args, **kwargs):
            headers = kwargs.get("headers", {})
            origin = headers.get("Origin", "")
            if origin:
                # Server reflects the origin back
                return make_response(
                    headers={
                        "Access-Control-Allow-Origin": origin,
                        "Access-Control-Allow-Credentials": "true",
                    }
                )
            return make_response(
                headers={"Access-Control-Allow-Origin": "https://example.com"}
            )

        client = make_client()
        client.get.side_effect = mock_get
        scanner = CORSScanner(client, ScanConfig(target="https://example.com"))
        findings = scanner.run()
        assert any("reflected" in f["title"].lower() for f in findings)


# --- CSRFScanner ---

class TestCSRFScanner:
    def test_page_without_forms(self):
        client = make_client()
        client.get.return_value = make_response(text="<html><body>Hello</body></html>")
        scanner = CSRFScanner(client, ScanConfig(target="https://example.com"))
        findings = scanner.run()
        csrf_findings = [f for f in findings if "CSRF" in f["title"]]
        assert len(csrf_findings) == 0

    def test_form_without_token(self):
        html = '<html><body><form method="post" action="/submit"><input type="text" name="name"></form></body></html>'
        client = make_client()
        client.get.return_value = make_response(text=html)
        scanner = CSRFScanner(client, ScanConfig(target="https://example.com"))
        findings = scanner.run()
        csrf_findings = [f for f in findings if "CSRF" in f["title"]]
        assert len(csrf_findings) == 1
        assert "without CSRF" in csrf_findings[0]["title"]

    def test_form_with_token(self):
        html = '<html><body><form method="post" action="/submit"><input type="hidden" name="csrf_token" value="abc"></form></body></html>'
        client = make_client()
        client.get.return_value = make_response(text=html)
        scanner = CSRFScanner(client, ScanConfig(target="https://example.com"))
        findings = scanner.run()
        csrf_findings = [f for f in findings if "CSRF" in f["title"]]
        assert len(csrf_findings) == 0

    def test_form_with_authenticity_token(self):
        html = '<html><body><form method="post" action="/login"><input type="hidden" name="authenticity_token" value="xyz"></form></body></html>'
        client = make_client()
        client.get.return_value = make_response(text=html)
        scanner = CSRFScanner(client, ScanConfig(target="https://example.com"))
        findings = scanner.run()
        csrf_findings = [f for f in findings if "CSRF" in f["title"]]
        assert len(csrf_findings) == 0

    def test_get_form_not_flaged(self):
        html = '<html><body><form method="get" action="/search"><input type="text" name="q"></form></body></html>'
        client = make_client()
        client.get.return_value = make_response(text=html)
        scanner = CSRFScanner(client, ScanConfig(target="https://example.com"))
        findings = scanner.run()
        csrf_findings = [f for f in findings if "CSRF" in f["title"]]
        assert len(csrf_findings) == 0


# --- XSSScanner ---

class TestXSSScanner:
    def test_target_unreachable(self):
        client = make_client()
        client.get.return_value = None
        scanner = XSSScanner(client, ScanConfig(target="https://example.com"))
        findings = scanner.run()
        assert len(findings) == 0

    def test_no_reflection(self):
        client = make_client()
        client.get.return_value = make_response(text="<html><body>Hello</body></html>")
        scanner = XSSScanner(client, ScanConfig(target="https://example.com"))
        findings = scanner.run()
        assert len(findings) == 0

    def test_xss_reflected_raw(self):
        client = make_client()
        call_count = [0]

        def mock_get(path, *args, **kwargs):
            call_count[0] += 1
            if "<script>alert(1)</script>" in path:
                return make_response(
                    text=f"<html><body>Search results for: <script>alert(1)</script></body></html>"
                )
            return make_response(text="<html><body></body></html>")

        client.get.side_effect = mock_get
        scanner = XSSScanner(client, ScanConfig(target="https://example.com"))
        findings = scanner.run()
        assert len(findings) > 0
        assert any("XSS" in f["title"] for f in findings)

    def test_xss_encoded_not_flagged(self):
        client = make_client()

        def mock_get(path, *args, **kwargs):
            if "<script>alert(1)</script>" in path:
                return make_response(
                    text="<html><body>&lt;script&gt;alert(1)&lt;/script&gt;</body></html>"
                )
            return make_response(text="<html><body></body></html>")

        client.get.side_effect = mock_get
        scanner = XSSScanner(client, ScanConfig(target="https://example.com"))
        findings = scanner.run()
        # Encoded reflection should NOT trigger a finding
        assert len(findings) == 0
