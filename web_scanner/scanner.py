"""Base class for all scan modules."""

from abc import ABC, abstractmethod

from web_scanner.config import ScanConfig
from web_scanner.http_client import HTTPClient


class BaseScanner(ABC):
    def __init__(self, client: HTTPClient, config: ScanConfig):
        self.client = client
        self.config = config

    @property
    def target(self) -> str:
        """Full target base URL."""
        return self.client.base_url

    def _full_url(self, path: str) -> str:
        """Build a full URL from a relative path."""
        if path.startswith(("http://", "https://")):
            return path
        return f"{self.client.base_url}/{path.lstrip('/')}"

    @abstractmethod
    def run(self) -> list[dict]:
        ...
