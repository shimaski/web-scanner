"""Tests for ScanConfig."""

import time
from web_scanner.config import ScanConfig, DEFAULT_HEADERS


class TestScanConfig:
    def test_defaults(self):
        c = ScanConfig()
        assert c.target == ""
        assert c.timeout == 10
        assert c.max_threads == 10
        assert c.verify_ssl is False
        assert c.follow_redirects is True
        assert c.output_format == "text"
        assert c.delay == 0.0
        assert c.proxy == ""
        assert c.cookie == ""
        assert c.crawled_urls == []
        assert c.crawled_forms == []

    def test_custom_values(self):
        c = ScanConfig(
            target="https://example.com",
            timeout=30,
            max_threads=20,
            user_agent="TestAgent",
            output_format="json",
            delay=0.5,
            proxy="http://127.0.0.1:8080",
        )
        assert c.target == "https://example.com"
        assert c.timeout == 30
        assert c.max_threads == 20
        assert c.user_agent == "TestAgent"
        assert c.output_format == "json"
        assert c.delay == 0.5
        assert c.proxy == "http://127.0.0.1:8080"

    def test_sleep_zero(self):
        c = ScanConfig(delay=0.0)
        start = time.monotonic()
        c.sleep()
        elapsed = time.monotonic() - start
        assert elapsed < 0.01  # practically instant

    def test_sleep_nonzero(self):
        c = ScanConfig(delay=0.1)
        start = time.monotonic()
        c.sleep()
        elapsed = time.monotonic() - start
        assert elapsed >= 0.08

    def test_default_headers_content(self):
        assert "Accept" in DEFAULT_HEADERS
        assert "Accept-Language" in DEFAULT_HEADERS
        assert DEFAULT_HEADERS["Accept-Encoding"] == "gzip, deflate"


class TestScanConfigDataclass:
    def test_crawled_attrs_mutability(self):
        c = ScanConfig()
        c.crawled_urls.append("https://example.com/a")
        c.crawled_urls.append("https://example.com/b")
        assert len(c.crawled_urls) == 2

        c.crawled_forms.append({"action": "/login"})
        assert len(c.crawled_forms) == 1

    def test_str_representation(self):
        c = ScanConfig(target="example.com")
        assert "example.com" in str(c)
