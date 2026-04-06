"""HTTP client with session management and authentication."""

import json
import time
import logging
from urllib.parse import urljoin, urlparse

import requests
from requests.auth import HTTPBasicAuth
from urllib3.exceptions import InsecureRequestWarning

from web_scanner.config import DEFAULT_HEADERS, ScanConfig

logger = logging.getLogger(__name__)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class HTTPClient:
    def __init__(self, config: ScanConfig):
        self.session = requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)
        self.session.headers.update({"User-Agent": config.user_agent})
        self.session.timeout = config.timeout
        self.session.verify = config.verify_ssl
        self.session.allow_redirects = config.follow_redirects
        self.base_url = self._normalize_url(config.target)

        # Proxy support
        if config.proxy:
            self.session.proxies = {
                "http": config.proxy,
                "https": config.proxy,
            }
            logger.info("Using proxy: %s", config.proxy)

        # Cookie support
        if config.cookie:
            self.session.headers["Cookie"] = config.cookie
            logger.info("Using cookies: %s", config.cookie[:60])

        # --- Authentication ---

        # Basic Auth
        if config.basic_user and config.basic_pass:
            self.session.auth = HTTPBasicAuth(config.basic_user, config.basic_pass)
            logger.info("Using HTTP Basic Auth (user: %s)", config.basic_user)

        # Bearer Token
        if config.bearer_token:
            self.session.headers["Authorization"] = "Bearer " + config.bearer_token
            logger.info("Using Bearer token authentication")

        # Form-based login
        if config.login_url and config.login_username and config.login_password:
            self._form_login(config)

        self.config = config

    def _form_login(self, config: ScanConfig):
        """Perform form-based login via POST and persist cookies."""
        login_url = config.login_url
        if not login_url.startswith(("http://", "https://")):
            login_url = urljoin(self.base_url, config.login_url.lstrip("/"))
        elif not login_url.startswith(self.base_url):
            login_url = urljoin(self.base_url, login_url.lstrip("/"))

        payload = {
            config.login_username_field: config.login_username,
            config.login_password_field: config.login_password,
        }

        logger.info("Logging in to %s (user: %s)", login_url, config.login_username)
        try:
            resp = self.session.post(
                login_url,
                data=json.dumps(payload),
                headers={"Content-Type": "application/json"},
            )
            if resp.ok:
                logger.info("Login successful (status %d, %d cookies)", resp.status_code, len(self.session.cookies))
            else:
                logger.warning("Login returned status %d — continuing anyway", resp.status_code)
        except requests.RequestException as e:
            logger.error("Login failed: %s", e)

    def _relogin(self):
        """Retry form-based login after a 401/403."""
        config = self.config
        if not (config.login_url and config.login_username and config.login_password):
            return
        self.session.cookies.clear()
        self._form_login(config)

    def _sleep(self):
        if self.config.delay > 0:
            time.sleep(self.config.delay)

    def _normalize_url(self, url: str) -> str:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def _request_with_retry(self, method: str, url: str, **kwargs) -> requests.Response | None:
        """Internal: perform an HTTP request with optional auto-relogin on 401/403."""
        self._sleep()
        try:
            resp = self.session.request(method, url, **kwargs)
            if self.config.auto_relogin and resp.status_code in (401, 403):
                logger.info("Got %d, retrying login...", resp.status_code)
                self._relogin()
                resp = self.session.request(method, url, **kwargs)
            return resp
        except requests.RequestException as e:
            logger.error("%s %s failed: %s", method.upper(), url, e)
            return None

    def get(self, path: str = "", **kwargs) -> requests.Response | None:
        url = urljoin(self.base_url + "/", path.lstrip("/"))
        return self._request_with_retry("GET", url, **kwargs)

    def post(self, path: str = "", data=None, **kwargs) -> requests.Response | None:
        url = urljoin(self.base_url + "/", path.lstrip("/"))
        return self._request_with_retry("POST", url, data=data, **kwargs)

    def request(self, method: str, path: str = "", **kwargs) -> requests.Response | None:
        url = urljoin(self.base_url + "/", path.lstrip("/"))
        return self._request_with_retry(method, url, **kwargs)
