"""Directory / file brute force scanner (enhanced)."""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from web_scanner.config import ScanConfig
from web_scanner.http_client import HTTPClient
from web_scanner.scanner import BaseScanner

logger = logging.getLogger(__name__)

DEFAULT_PATHS = [
    "admin", "login", "dashboard", "config", "api", "api/v1", "api/v2",
    "debug", "console", "actuator", "health", "status", "phpmyadmin",
    "wp-admin", "wp-login.php", "wp-content", "wp-includes",
    "robots.txt", "sitemap.xml", ".env", ".git", ".git/config",
    ".htaccess", ".htpasswd", "web.config", "server-status",
    "phpinfo.php", "info.php", "test.php", "info.txt",
    "backup.sql", "database.sql", "dump.sql", "backup.zip",
    "config.php", "config.yml", "config.json", "settings.py",
    "id_rsa", "id_rsa.pub", "id_dsa", "authorized_keys",
    "server-info", ".well-known/security.txt",
    "cgi-bin/", "manager/html", "jenkins", "solr/admin",
    "swagger.json", "swagger-ui.html", "api-docs", "graphql",
    "elmah.axd", "trace.axd", ".DS_Store", "Thumbs.db",
    "composer.json", "package.json", "Gemfile", "requirements.txt",
    "Dockerfile", "docker-compose.yml", ".dockerenv",
    ".aws/credentials", ".ssh/known_hosts",
    "wp-config.php", "configuration.php", "settings.php",
    "admin.php", "phpmyadmin/", "pma/", "webmail/",
    "xmlrpc.php", "readme.html", "CHANGELOG.md",
    "test", "temp", "tmp", "old", "dev", "staging",
    "cgi-bin", "backup", "backups", "log", "logs", "error_log",
]

# Paths that indicate sensitive files (severity bump)
SENSITIVE_PATHS = [
    ".git", ".env", ".htpasswd", "config", "backup", "id_rsa",
    ".aws", "sql", "phpinfo", "phpmyadmin", "credentials",
    "web.config", ".htaccess", "authorized_keys", "known_hosts",
    "docker-compose", "Dockerfile", ".dockerenv", "elmah",
    "wp-config", "id_dsa", ".ssh",
]

# Number of concurrent threads
MAX_DIR_THREADS = 20


class DirBruteforce(BaseScanner):
    """Discover hidden files and directories via brute force with
    concurrent requests, status differentiation, and false-positive
    filtering."""

    def run(self) -> list[dict]:
        findings: list[dict] = []

        paths = self._load_wordlist()

        # Establish a baseline content length for 404 pages
        baseline_cl = self._cached_baseline

        # Classify every path
        with ThreadPoolExecutor(max_workers=MAX_DIR_THREADS) as executor:
            future_map = {
                executor.submit(self._probe_path, path): path
                for path in paths
            }
            status_groups: dict[int, list[tuple[str, dict | None]]] = {}
            for future in as_completed(future_map):
                path = future_map[future]
                try:
                    status_code, finding = future.result()
                    status_groups.setdefault(status_code, []).append(
                        (path, finding)
                    )
                except Exception:
                    pass

        # 200 — resource found
        for path, finding in status_groups.get(200, []):
            if finding:
                findings.append(finding)

        # 403 — forbidden, directory likely exists
        for path, finding in status_groups.get(403, []):
            findings.append({
                "severity": "MEDIUM",
                "title": f"Forbidden resource: /{path}",
                "detail": f"URL: {self._full_url(path)}\nStatus 403 — directory or file exists but access is denied",
            })

        # 405 — method not allowed (resource exists)
        for path, finding in status_groups.get(405, []):
            findings.append({
                "severity": "LOW",
                "title": f"Resource found (Method Not Allowed): /{path}",
                "detail": f"URL: {self._full_url(path)}\nStatus 405 — resource exists but the HTTP method is not allowed",
            })

        # 500 — internal error (resource exists, may be interesting)
        for path, finding in status_groups.get(500, []):
            findings.append({
                "severity": "MEDIUM",
                "title": f"Server error on resource: /{path}",
                "detail": f"URL: {self._full_url(path)}\nStatus 500 — requesting this path triggers an error",
            })

        # 301/302 — redirects (followed and reported separately)
        for path, finding in status_groups.get(301, []):
            if finding:
                findings.append(finding)
        for path, finding in status_groups.get(302, []):
            if finding:
                findings.append(finding)

        # Sort: high severity first, then by path
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        findings.sort(key=lambda f: (severity_order.get(f["severity"], 5), f["title"]))

        return findings

    # -- probe logic -------------------------------------------------------

    def _probe_path(self, path: str) -> tuple[int, dict | None]:
        """Probe a single path. Return (status_code, finding_dict_or_None)."""
        resp = self.client.get(path)
        if resp is None:
            return (0, None)

        sc = resp.status_code
        cl = len(resp.text)
        full_url = f"{self.client.base_url}/{path.lstrip('/')}"

        # Skip noise: content-length matches 404 baseline
        if cl > 0 and cl == self._cached_baseline:
            return (sc, None)

        if sc == 200:
            severity = "LOW"
            for s in SENSITIVE_PATHS:
                if s in path.lower():
                    severity = "HIGH"
                    break

            finding: dict = {
                "severity": severity,
                "title": f"Discovered: /{path}",
                "detail": f"URL: {full_url}\nStatus 200 — {cl} bytes",
            }
            return (sc, finding)

        if sc in (301, 302):
            location = resp.headers.get("Location", "")
            detail = f"URL: {full_url}\nStatus {sc} — Location: {location[:100]}"
            # Follow redirect to see what's there
            location_resp = self._follow_redirect(resp)
            if location_resp and location_resp.status_code == 200:
                detail += f" — resolves to {len(location_resp.text)} bytes"
            severity = "MEDIUM"
            for s in SENSITIVE_PATHS:
                if s in path.lower():
                    severity = "HIGH"
                    break
            finding = {
                "severity": severity,
                "title": f"Redirect: /{path}",
                "detail": detail,
            }
            return (sc, finding)

        return (sc, None)

    def _follow_redirect(self, resp):
        """Follow a redirect one hop and return the final response."""
        location = resp.headers.get("Location", "")
        if location:
            try:
                return self.client.get(location, allow_redirects=True)
            except Exception:
                pass
        return None

    def _measure_404_baseline(self) -> int:
        """Request a non-existent path and return its Content-Length for
        false-positive filtering."""
        try:
            resp = self.client.get(
                f".nonexistent_{self._rand_suffix()}",
                allow_redirects=False,
            )
            if resp and resp.status_code == 404:
                return len(resp.text)
        except Exception:
            pass
        return 0

    def _rand_suffix(self) -> str:
        import hashlib, time
        return hashlib.md5(str(time.time()).encode()).hexdigest()[:12]

    @property
    def _cached_baseline(self):
        """Cached 404 baseline content-length."""
        if not hasattr(self, "__baseline_cl"):
            self.__baseline_cl = self._measure_404_baseline()
        return self.__baseline_cl

    # -- wordlist ----------------------------------------------------------

    def _load_wordlist(self) -> list[str]:
        wordlist_path = Path(self.config.wordlist_path)
        if wordlist_path.exists():
            lines = wordlist_path.read_text().splitlines()
            lines = [l.strip() for l in lines if l.strip() and not l.startswith("#")]
            return sorted(set(lines + DEFAULT_PATHS))
        return sorted(DEFAULT_PATHS)
