"""Information gathering — server fingerprinting and header analysis."""

import logging
from urllib.parse import urlparse

from web_scanner.config import ScanConfig
from web_scanner.http_client import HTTPClient
from web_scanner.scanner import BaseScanner

logger = logging.getLogger(__name__)


class InfoGatherer(BaseScanner):
    """Detect server tech, security headers, robots, and common files."""

    def run(self) -> list[dict]:
        findings: list[dict] = []
        resp = self.client.get("/")
        if resp is None:
            findings.append({"severity": "HIGH", "title": "Target unreachable", "detail": "Could not connect to target"})
            return findings

        findings.extend(self._check_headers(resp))
        findings.extend(self._check_server(resp))
        findings.extend(self._check_common_files())
        findings.extend(self._check_robots())

        return findings

    def _check_headers(self, resp) -> list[dict]:
        findings = []
        headers = {h.lower(): v for h, v in resp.headers.items()}

        security_headers = {
            "strict-transport-security": {
                "title": "Missing HSTS header",
                "severity": "MEDIUM",
                "detail": "No Strict-Transport-Security — vulnerable to SSL stripping",
            },
            "x-content-type-options": {
                "title": "Missing X-Content-Type-Options",
                "severity": "LOW",
                "detail": "No X-Content-Type-Options: nosniff — MIME sniffing possible",
            },
            "x-frame-options": {
                "title": "Missing X-Frame-Options",
                "severity": "MEDIUM",
                "detail": "No X-Frame-Options — clickjacking possible",
            },
            "content-security-policy": {
                "title": "Missing Content-Security-Policy",
                "severity": "MEDIUM",
                "detail": "No CSP header — XSS protection is weaker",
            },
            "x-xss-protection": {
                "title": "Missing X-XSS-Protection",
                "severity": "LOW",
                "detail": "No X-XSS-Protection header (legacy browsers)",
            },
            "referrer-policy": {
                "title": "Missing Referrer-Policy",
                "severity": "LOW",
                "detail": "No Referrer-Policy — referrer data may leak",
            },
            "permissions-policy": {
                "title": "Missing Permissions-Policy",
                "severity": "LOW",
                "detail": "No Permissions-Policy — browser features not restricted",
            },
        }

        for header, finding in security_headers.items():
            if header not in headers:
                findings.append(finding)

        # Information leakage headers
        if "server" in headers:
            findings.append({
                "severity": "LOW",
                "title": "Server header discloses technology",
                "detail": f"Server: {headers['server']}",
            })
        if "x-powered-by" in headers:
            findings.append({
                "severity": "LOW",
                "title": "X-Powered-By discloses technology",
                "detail": f"X-Powered-By: {headers['x-powered-by']}",
            })

        # Insecure cookie flags
        for cookie_header in ["set-cookie"]:
            if cookie_header in headers:
                cookie_val = headers[cookie_header].lower()
                if "secure" not in cookie_val:
                    findings.append({
                        "severity": "MEDIUM",
                        "title": "Cookie without Secure flag",
                        "detail": "Set-Cookie missing Secure attribute",
                    })
                if "httponly" not in cookie_val:
                    findings.append({
                        "severity": "MEDIUM",
                        "title": "Cookie without HttpOnly flag",
                        "detail": "Set-Cookie missing HttpOnly attribute — accessible via JavaScript",
                    })

        return findings

    def _check_server(self, resp) -> list[dict]:
        findings = []
        headers = {h.lower(): v for h, v in resp.headers.items()}
        server = headers.get("server", "")

        known_servers = {
            "nginx": "Nginx",
            "apache": "Apache",
            "iis": "Microsoft IIS",
            "gunicorn": "Gunicorn",
            "cloudflare": "Cloudflare",
            "akamai": "Akamai",
        }

        detected = []
        for key, name in known_servers.items():
            if key in server.lower():
                detected.append(name)

        if detected:
            findings.append({
                "severity": "INFO",
                "title": "Server technology detected",
                "detail": f"Detected: {', '.join(detected)}",
            })

        # Check status code issues
        if resp.status_code in (500, 502, 503, 504):
            findings.append({
                "severity": "HIGH",
                "title": "Server error on root",
                "detail": f"Status code: {resp.status_code} — server may be misconfigured",
            })

        return findings

    def _check_common_files(self) -> list[dict]:
        findings = []
        sensitive_paths = [
            ("robots.txt", "INFO", "robots.txt found"),
            (".env", "HIGH", ".env file exposed — may contain secrets"),
            (".git/config", "HIGH", ".git/config exposed — repository info leaked"),
            ("wp-config.php", "MEDIUM", "WordPress config file accessible"),
            ("phpinfo.php", "HIGH", "phpinfo() exposed — server details leaked"),
            (".htaccess", "MEDIUM", ".htaccess accessible"),
            ("server-status", "HIGH", "Apache server-status exposed"),
            ("sitemap.xml", "INFO", "Sitemap found"),
            ("admin/", "MEDIUM", "Admin path accessible"),
            ("login.php", "LOW", "Login page found"),
        ]

        for path, severity, detail in sensitive_paths:
            resp = self.client.get(path)
            if resp and resp.status_code == 200:
                findings.append({
                    "severity": severity,
                    "title": f"Sensitive file: {path}",
                    "detail": f"URL: {self._full_url(path)}\n{detail}",
                })

        return findings

    def _check_robots(self) -> list[dict]:
        findings = []
        resp = self.client.get("/robots.txt")
        if resp and resp.status_code == 200:
            admin_paths = ["admin", "wp-admin", "dashboard", "manager", "config"]
            for line in resp.text.lower().splitlines():
                if line.startswith("disallow:"):
                    path = line.split(":", 1)[1].strip().lstrip("/")
                    for admin in admin_paths:
                        if admin in path:
                            findings.append({
                                "severity": "MEDIUM",
                                "title": f"Admin path in robots.txt: /{path}",
                                "detail": f"URL: {self._full_url(path)}\nrobots.txt reveals admin path",
                            })
        return findings
