"""Tests for new scanner modules — cmdi, xxe, upload, http_verb, backup."""

import unittest.mock as mock
from unittest.mock import MagicMock

from web_scanner.config import ScanConfig
from web_scanner.cmd_injection import CommandInjectionScanner
from web_scanner.xxe_scanner import XXEScanner
from web_scanner.upload_scanner import UploadScanner
from web_scanner.http_verb_scanner import HTTPVerbScanner
from web_scanner.backup_scanner import BackupScanner


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
    return mock.MagicMock()


# --- Command Injection ---

class TestCommandInjection:
    def test_target_unreachable(self):
        client = make_client()
        client.get.return_value = None
        scanner = CommandInjectionScanner(client, ScanConfig(target="https://example.com"))
        assert scanner.run() == []

    def test_no_injection(self):
        client = make_client()
        client.get.return_value = make_response(text="<html><body>Hello</body></html>")
        scanner = CommandInjectionScanner(client, ScanConfig(target="https://example.com"))
        findings = scanner.run()
        assert len(findings) == 0

    def test_cmd_output_detected(self):
        client = make_client()

        def mock_get(path, **kwargs):
            if ";cat /etc/passwd" in path or "||cat" in path or "|cat" in path:
                return make_response(text="root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:")
            return make_response(text="<html><body></body></html>")

        client.get.side_effect = mock_get
        scanner = CommandInjectionScanner(client, ScanConfig(target="https://example.com"))
        findings = scanner.run()
        assert len(findings) > 0
        assert any("Command injection" in f["title"] for f in findings)

    def test_whoami_detected(self):
        client = make_client()

        def mock_get(path, **kwargs):
            if "whoami" in path:
                return make_response(text="www-data")
            return make_response(text="<html><body></body></html>")

        client.get.side_effect = mock_get
        scanner = CommandInjectionScanner(client, ScanConfig(target="https://example.com"))
        findings = scanner.run()
        assert any("Command injection" in f["title"] for f in findings)


# --- XXE ---

class TestXXEScanner:
    def test_no_xml_endpoint(self):
        client = make_client()
        client.get.return_value = make_response(text="<html><body>Hello</body></html>")
        client.post.return_value = make_response(text="OK")
        scanner = XXEScanner(client, ScanConfig(target="https://example.com"))
        findings = scanner.run()
        # Should not crash even with no XML endpoints
        assert isinstance(findings, list)

    def test_xxe_file_read_detected(self):
        client = make_client()
        client.get.return_value = make_response(text='<html><a href="/api/data">API</a></html>')

        def mock_post(path, **kwargs):
            return make_response(text="root:x:0:0:root:/root:/bin/bash")

        client.post.side_effect = mock_post
        scanner = XXEScanner(client, ScanConfig(target="https://example.com"))
        findings = scanner.run()
        assert any("XXE" in f["title"] for f in findings)


# --- Upload Scanner ---

class TestUploadScanner:
    def test_no_upload_form(self):
        client = make_client()
        client.get.return_value = make_response(text="<html><body>Hello</body></html>")
        scanner = UploadScanner(client, ScanConfig(target="https://example.com"))
        findings = scanner.run()
        assert len(findings) == 0

    def test_upload_form_without_restrictions(self):
        html = '''
        <html><body>
        <form method="post" action="/upload" enctype="multipart/form-data">
            <input type="file" name="file">
            <input type="submit">
        </form>
        </body></html>'''
        client = make_client()
        client.get.return_value = make_response(text=html)
        scanner = UploadScanner(client, ScanConfig(target="https://example.com"))
        findings = scanner.run()
        titles = [f["title"] for f in findings]
        assert any("type restriction" in t for t in titles)
        assert any("size limit" in t for t in titles)
        assert any("CSRF" in t for t in titles)

    def test_upload_form_with_accept(self):
        html = '''
        <html><body>
        <form method="post" action="/upload" enctype="multipart/form-data">
            <input type="file" name="file" accept="image/*">
            <input type="submit">
        </form>
        </body></html>'''
        client = make_client()
        client.get.return_value = make_response(text=html)
        scanner = UploadScanner(client, ScanConfig(target="https://example.com"))
        findings = scanner.run()
        # With accept attribute, should NOT report type restriction issue
        assert not any("type restriction" in f["title"] for f in findings)


# --- HTTP Verb ---

class TestHTTPVerb:
    def test_target_unreachable(self):
        client = make_client()
        client.get.return_value = None
        scanner = HTTPVerbScanner(client, ScanConfig(target="https://example.com"))
        assert scanner.run() == []

    def test_no_bypass(self):
        client = make_client()
        client.get.return_value = make_response(status_code=200, text="OK")
        client.request.return_value = make_response(status_code=405, text="Method not allowed")
        scanner = HTTPVerbScanner(client, ScanConfig(target="https://example.com"))
        findings = scanner.run()
        assert len(findings) == 0

    def test_trace_enabled(self):
        client = make_client()
        client.get.return_value = make_response(status_code=200, text="OK")

        def mock_request(method, path, **kwargs):
            if method in ("TRACE", "TRACK"):
                return make_response(status_code=200, text="TRACE echo")
            return make_response(status_code=405, text="Not allowed")

        client.request.side_effect = mock_request
        scanner = HTTPVerbScanner(client, ScanConfig(target="https://example.com"))
        findings = scanner.run()
        assert any("TRACE" in f["title"] for f in findings)


# --- Backup Files ---

class TestBackupScanner:
    def test_no_backups_exposed(self):
        client = make_client()
        client.get.return_value = make_response(status_code=404, text="")
        scanner = BackupScanner(client, ScanConfig(target="https://example.com"))
        findings = scanner.run()
        assert len(findings) == 0

    def test_git_config_exposed(self):
        client = make_client()

        def mock_get(path, **kwargs):
            if path == ".git/config":
                return make_response(status_code=200, text="[core]\nrepositoryformatversion = 0")
            return make_response(status_code=404, text="")

        client.get.side_effect = mock_get
        scanner = BackupScanner(client, ScanConfig(target="https://example.com"))
        findings = scanner.run()
        assert any(".git" in f["title"] for f in findings)

    def test_sql_dump_exposed(self):
        client = make_client()

        def mock_get(path, **kwargs):
            if path == "backup.sql":
                return make_response(status_code=200, text="-- MySQL dump\nCREATE TABLE ...")
            if path == "db.sql":
                return make_response(status_code=200, text="-- SQL dump")
            return make_response(status_code=404, text="")

        client.get.side_effect = mock_get
        scanner = BackupScanner(client, ScanConfig(target="https://example.com"))
        findings = scanner.run()
        assert any("backup" in f["title"] or "SQL" in f["title"] or "dump" in f["title"] for f in findings)

    def test_empty_response_not_flagged(self):
        """404 and 200 with empty body should not be flagged."""
        client = make_client()
        client.get.return_value = make_response(status_code=200, text="")
        scanner = BackupScanner(client, ScanConfig(target="https://example.com"))
        findings = scanner.run()
        assert len(findings) == 0
