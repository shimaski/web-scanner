import time
from dataclasses import dataclass, field


@dataclass
class ScanConfig:
    target: str = ""
    timeout: int = 10
    max_threads: int = 10
    user_agent: str = "WebScanner/0.1.0"
    follow_redirects: bool = True
    verify_ssl: bool = False
    output_format: str = "text"
    output_file: str = ""
    wordlist_path: str = "wordlists/common.txt"
    scan_modules: list[str] = field(default_factory=list)
    delay: float = 0.0
    proxy: str = ""
    cookie: str = ""
    crawled_urls: list[str] = field(default_factory=list)
    crawled_forms: list[dict] = field(default_factory=list)

    # Auth options
    basic_user: str = ""
    basic_pass: str = ""
    bearer_token: str = ""
    login_url: str = ""
    login_username_field: str = "username"
    login_password_field: str = "password"
    login_username: str = ""
    login_password: str = ""
    auto_relogin: bool = False

    @classmethod
    def from_dict(cls, **data) -> "ScanConfig":
        """Build a ScanConfig from keyword arguments (ignoring unknown keys)."""
        fields = {f.name for f in cls.__dataclass_fields__.values()}
        return cls(**{k: v for k, v in data.items() if k in fields})

    def sleep(self):
        if self.delay > 0:
            time.sleep(self.delay)


DEFAULT_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
}
