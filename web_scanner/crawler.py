"""Web crawler / spider — discovers URLs and endpoints."""

import logging
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from web_scanner.config import ScanConfig
from web_scanner.http_client import HTTPClient

logger = logging.getLogger(__name__)


class Crawler:
    """Simple spider to discover URLs from a target."""

    def __init__(self, client: HTTPClient, config: ScanConfig, max_pages: int = 50):
        self.client = client
        self.config = config
        self.max_pages = max_pages
        self.visited: set[str] = set()
        self.found_urls: list[str] = []
        self.forms: list[dict] = []

    def crawl(self, start_url: str = "/") -> tuple[list[str], list[dict]]:
        queue = [start_url]
        self.visited.add(self.client.base_url.rstrip("/") + start_url)

        while queue and len(self.visited) < self.max_pages:
            current = queue.pop(0)
            resp = self.client.get(current)
            if resp is None:
                continue

            full_url = self._full_url(current)
            self.found_urls.append(full_url)
            logger.info("Crawled: %s", full_url)

            soup = BeautifulSoup(resp.text, "html.parser")

            # Extract links
            for tag in soup.find_all(True):
                for attr in ("href", "src", "action", "data-url"):
                    url = tag.get(attr)
                    if url and not url.startswith(("javascript:", "mailto:", "tel:", "#")):
                        absolute = urljoin(self.client.base_url, url)
                        if self._is_same_domain(absolute) and absolute not in self.visited:
                            self.visited.add(absolute)
                            rel = self._relative(absolute)
                            queue.append(rel)

            # Extract forms
            self._extract_forms(soup, current)

        logger.info("Crawling done: %d URLs, %d forms", len(self.found_urls), len(self.forms))
        return self.found_urls, self.forms

    def finding(self) -> dict:
        """Return a finding dict summarizing the crawl results."""
        return {
            "severity": "INFO",
            "title": f"Crawler: {len(self.found_urls)} URLs, {len(self.forms)} forms discovered",
            "detail": f"Pages crawled: {len(self.visited)}",
        }

    def _extract_forms(self, soup, path: str):
        for form in soup.find_all("form"):
            form_info = {
                "action": urljoin(self.client.base_url, form.get("action", path)),
                "method": form.get("method", "get").upper(),
                "inputs": [],
            }
            for inp in form.find_all(["input", "select", "textarea"]):
                form_info["inputs"].append({
                    "name": inp.get("name", ""),
                    "type": inp.get("type", "text"),
                    "value": inp.get("value", ""),
                })
            self.forms.append(form_info)

    def _full_url(self, path: str) -> str:
        return urljoin(self.client.base_url, path)

    def _is_same_domain(self, url: str) -> bool:
        return urlparse(url).netloc == urlparse(self.client.base_url).netloc

    def _relative(self, url: str) -> str:
        parsed = urlparse(url)
        return parsed.path + ("?" + parsed.query if parsed.query else "")
