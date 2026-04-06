"""Port scanner with concurrent probing and service detection."""

import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from ipaddress import ip_address
from urllib.parse import urlparse

import requests

from web_scanner.config import ScanConfig
from web_scanner.http_client import HTTPClient
from web_scanner.scanner import BaseScanner
from web_scanner.utils import extract_title

logger = logging.getLogger(__name__)

# Common ports with service labels
COMMON_PORTS = [
    (21, "FTP"), (22, "SSH"), (23, "Telnet"), (25, "SMTP"),
    (53, "DNS"), (80, "HTTP"), (110, "POP3"), (143, "IMAP"),
    (443, "HTTPS"), (445, "SMB"), (993, "IMAPS"), (995, "POP3S"),
    (1433, "MSSQL"), (1521, "Oracle"), (3306, "MySQL"),
    (5432, "PostgreSQL"), (5900, "VNC"), (6379, "Redis"),
    (8080, "HTTP-Alt"), (8443, "HTTPS-Alt"), (9090, "HTTP-Alt2"),
    (9200, "Elasticsearch"), (10000, "Webmin"), (11211, "Memcached"),
    (27017, "MongoDB"),
]

# Ports that should not be publicly accessible
DATABASE_PORTS = {
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
    9200: "Elasticsearch",
    11211: "Memcached",
    1433: "MSSQL",
    1521: "Oracle",
}

# Web ports where we try HTTP banner grab
WEB_PORTS = {80, 443, 8080, 8443, 9090, 10000}

# Maximum concurrent threads for port probing
MAX_PORT_THREADS = 50


class PortScanner(BaseScanner):
    """Check for open ports on the target with concurrent scanning."""

    def run(self) -> list[dict]:
        findings: list[dict] = []

        parsed = urlparse(self.client.base_url)
        host = parsed.hostname
        if not host:
            return findings

        # Check if host is an IP; if so, we can note whether it is public
        host_is_ip = self._is_ip_address(host)

        open_ports: list[tuple[int, str]] = []

        def _probe(port: int, service: str) -> tuple[int, str] | None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.timeout / 3)
            try:
                result = sock.connect_ex((host, port))
                if result == 0:
                    return (port, service)
            except (socket.error, socket.timeout, OSError):
                pass
            finally:
                sock.close()
            return None

        with ThreadPoolExecutor(max_workers=MAX_PORT_THREADS) as executor:
            futures = {
                executor.submit(_probe, port, service): (port, service)
                for port, service in COMMON_PORTS
            }
            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    port, service = result
                    open_ports.append((port, service))

        open_ports.sort(key=lambda x: x[0])

        for port, service in open_ports:
            severity = self._port_severity(port)
            detail = f"Port {port}/{service} is open and accessible"

            # Try HTTP banner on web ports
            if port in WEB_PORTS:
                banner = self._http_banner(host, port, service)
                if banner:
                    detail += f" | Banner: {banner}"

            finding = {
                "severity": severity,
                "title": f"Open port {port} ({service}) on {host}",
                "detail": detail,
            }

            # Flag database ports exposed to the internet
            if port in DATABASE_PORTS:
                finding["title"] = (
                    f"Database port {port} ({DATABASE_PORTS[port]}) "
                    f"publicly exposed on {host}"
                )
                finding["detail"] = (
                    f"{DATABASE_PORTS[port]} port {port} is openly reachable. "
                    f"This should typically be restricted to internal networks. "
                    + finding["detail"]
                )

            findings.append(finding)

        return findings

    # -- helpers -----------------------------------------------------------

    def _port_severity(self, port: int) -> str:
        if port in DATABASE_PORTS:
            return "HIGH"
        if port in (22, 23, 445, 5900):
            return "MEDIUM"
        return "LOW"

    def _http_banner(self, host: str, port: int, service: str) -> str | None:
        scheme = "https" if port in (443, 8443) else "http"
        url = f"{scheme}://{host}:{port}/"
        try:
            resp = requests.get(
                url,
                timeout=self.config.timeout / 2,
                verify=self.config.verify_ssl,
                allow_redirects=False,
            )
            server = resp.headers.get("Server", "")
            parts: list[str] = []
            if server:
                parts.append(f"Server={server}")
            if resp.status_code:
                parts.append(f"HTTP {resp.status_code}")
            title = extract_title(resp.text)
            if title:
                parts.append(f"title=\"{title}\"")
            return " | ".join(parts) if parts else None
        except Exception:
            return None

    def _is_ip_address(self, host: str) -> bool:
        try:
            ip_address(host)
            return True
        except ValueError:
            return False
