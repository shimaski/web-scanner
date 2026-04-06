"""Tests for HTTPClient and URL normalization."""

import requests
import unittest.mock as mock
from unittest.mock import MagicMock

from web_scanner.config import ScanConfig
from web_scanner.http_client import HTTPClient


class TestUrlNormalization:
    def test_adds_https_prefix(self):
        config = ScanConfig(target="example.com")
        client = HTTPClient(config)
        assert client.base_url == "https://example.com"

    def test_keeps_http_prefix(self):
        config = ScanConfig(target="http://example.com")
        client = HTTPClient(config)
        assert client.base_url == "http://example.com"

    def test_keeps_https_prefix(self):
        config = ScanConfig(target="https://example.com")
        client = HTTPClient(config)
        assert client.base_url == "https://example.com"

    def test_strips_path(self):
        config = ScanConfig(target="https://example.com/admin/login")
        client = HTTPClient(config)
        assert client.base_url == "https://example.com"

    def test_preserves_port(self):
        config = ScanConfig(target="http://localhost:8080")
        client = HTTPClient(config)
        assert client.base_url == "http://localhost:8080"


class TestUrlJoining:
    def get_client(self, target="https://example.com"):
        config = ScanConfig(target=target)
        return HTTPClient(config)

    def test_get_root(self):
        client = self.get_client()
        with mock.patch.object(client.session, "request") as mock_req:
            mock_req.return_value = MagicMock()
            client.get("/")
            mock_req.assert_called_once()
            assert mock_req.call_args[0] == ("GET", "https://example.com/")

    def test_get_path(self):
        client = self.get_client()
        with mock.patch.object(client.session, "request") as mock_req:
            mock_req.return_value = MagicMock()
            client.get("/admin")
            assert mock_req.call_args[0] == ("GET", "https://example.com/admin")

    def test_get_path_without_leading_slash(self):
        client = self.get_client()
        with mock.patch.object(client.session, "request") as mock_req:
            mock_req.return_value = MagicMock()
            client.get("admin")
            assert mock_req.call_args[0] == ("GET", "https://example.com/admin")

    def test_post_path(self):
        client = self.get_client()
        with mock.patch.object(client.session, "request") as mock_req:
            mock_req.return_value = MagicMock()
            client.post("/api/login")
            assert mock_req.call_args[0][0] == "POST"
            assert mock_req.call_args[0][1] == "https://example.com/api/login"

    def test_custom_method(self):
        client = self.get_client()
        with mock.patch.object(client.session, "request") as mock_req:
            mock_req.return_value = MagicMock()
            client.request("OPTIONS", "/")
            assert mock_req.call_args[0] == ("OPTIONS", "https://example.com/")


class TestHttpErrors:
    def test_get_returns_none_on_error(self):
        config = ScanConfig(target="https://example.com")
        client = HTTPClient(config)
        with mock.patch.object(client.session, "request", side_effect=requests.RequestException("connection refused")):
            result = client.get("/")
            assert result is None

    def test_post_returns_none_on_error(self):
        config = ScanConfig(target="https://example.com")
        client = HTTPClient(config)
        with mock.patch.object(client.session, "request", side_effect=requests.RequestException("timeout")):
            result = client.post("/")
            assert result is None


class TestProxyAndCookie:
    def test_proxy_config(self):
        config = ScanConfig(target="example.com", proxy="http://127.0.0.1:8080")
        client = HTTPClient(config)
        assert client.session.proxies == {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}

    def test_cookie_config(self):
        config = ScanConfig(target="example.com", cookie="session=abc123")
        client = HTTPClient(config)
        assert client.session.headers["Cookie"] == "session=abc123"

    def test_user_agent_config(self):
        config = ScanConfig(target="example.com", user_agent="CustomAgent/1.0")
        client = HTTPClient(config)
        assert client.session.headers["User-Agent"] == "CustomAgent/1.0"
