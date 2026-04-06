"""Tests for report generation — console, JSON, and HTML."""

import json
import tempfile
from pathlib import Path

from web_scanner.report import print_report_console, export_json, export_html, export_html_string

SAMPLE_FINDINGS = [
    {"severity": "CRITICAL", "title": "SQL Injection on /login", "detail": "Error-based SQLi via user param"},
    {"severity": "HIGH", "title": "Reflected XSS via search", "detail": "Payload reflected raw in response"},
    {"severity": "MEDIUM", "title": "CORS wildcard", "detail": "Access-Control-Allow-Origin: *"},
    {"severity": "LOW", "title": "Missing X-Content-Type-Options", "detail": "No nosniff header"},
    {"severity": "INFO", "title": "Server technology detected", "detail": "Detected: Nginx"},
]


class TestJsonExport:
    def test_json_structure(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            export_json(SAMPLE_FINDINGS, "example.com", f.name)
            data = json.loads(Path(f.name).read_text())

        assert data["target"] == "example.com"
        assert data["total_findings"] == 5
        assert len(data["findings"]) == 5
        assert "date" in data

    def test_json_findings_preserved(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            export_json(SAMPLE_FINDINGS, "example.com", f.name)
            data = json.loads(Path(f.name).read_text())

        assert data["findings"][0]["severity"] == "CRITICAL"
        assert data["findings"][0]["title"] == "SQL Injection on /login"

    def test_empty_findings(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            export_json([], "example.com", f.name)
            data = json.loads(Path(f.name).read_text())

        assert data["total_findings"] == 0
        assert data["findings"] == []


class TestHtmlExport:
    def test_html_file_created(self):
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            export_html(SAMPLE_FINDINGS, "example.com", f.name)
            html = Path(f.name).read_text()

        assert "<!DOCTYPE html>" in html
        assert "example.com" in html
        assert "SQL Injection on /login" in html
        assert "CRITICAL" in html

    def test_html_contains_all_findings(self):
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            export_html(SAMPLE_FINDINGS, "example.com", f.name)
            html = Path(f.name).read_text()

        for finding in SAMPLE_FINDINGS:
            assert finding["title"] in html

    def test_html_empty_findings(self):
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            export_html([], "example.com", f.name)
            html = Path(f.name).read_text()

        assert "example.com" in html
        assert "Total findings: 0" in html


class TestHtmlString:
    def test_returns_string(self):
        result = export_html_string(SAMPLE_FINDINGS, "example.com")
        assert isinstance(result, str)
        assert "<!DOCTYPE html>" in result

    def test_contains_viewport_meta(self):
        result = export_html_string(SAMPLE_FINDINGS, "example.com")
        assert 'name="viewport"' in result


class TestConsoleOutput:
    def test_console_no_crash(self):
        """Ensure console output doesn't raise."""
        print_report_console(SAMPLE_FINDINGS, "example.com")
        print_report_console([], "example.com")
