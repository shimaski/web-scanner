"""Subdomain enumeration via DNS brute force (enhanced)."""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from web_scanner.config import ScanConfig
from web_scanner.http_client import HTTPClient
from web_scanner.scanner import BaseScanner
from web_scanner.utils import extract_title

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail",
    "admin", "dev", "staging", "prod", "api", "app", "cdn",
    "blog", "docs", "forum", "shop", "store", "portal",
    "vpn", "dns", "ns1", "ns2", "mx", "mx1", "mx2",
    "db", "database", "backup", "test", "qa", "uat",
    "git", "jenkins", "monitoring", "grafana", "kibana",
    "sso", "auth", "login", "s3", "cloud", "proxy",
    # Additional subdomains
    "api-v2", "api-v1", "internal",
    "web", "mobile", "m", "beta",
    "demo", "sandbox", "old", "legacy",
    "status", "ci", "ci-cd", "pipeline", "artifact",
    "mail2", "mx3", "smtp2",
    "ns3", "dns2",
    "crm", "erp", "help", "support",
    "wiki", "kb", "intranet",
    "jira", "confluence", "mattermost",
    "elastic", "kafka", "rabbitmq",
    "assets", "static", "media", "images", "files",
    "uploads", "download", "updates",
    "devops", "build", "release",
    "uat", "preprod", "preview",
    "dashboard", "analytics", "metrics",
    "payments", "billing", "checkout",
    "cpanel", "whm", "directadmin",
    "ftp2", "ftp3",
    "origin", "edge",
]

MAX_DNS_THREADS = 50


class SubdomainEnum(BaseScanner):
    """Discover subdomains via concurrent DNS brute force and identify
    services via HTTP probing."""

    def run(self) -> list[dict]:
        findings: list[dict] = []

        from urllib.parse import urlparse
        domain = urlparse(self.client.base_url).netloc
        # Strip port if present
        domain = domain.split(":")[0]

        # Already a subdomain? Extract base domain
        parts = domain.split(".")
        if len(parts) > 2:
            base_domain = ".".join(parts[-2:])
        else:
            base_domain = domain

        discovered: list[dict] = []

        # --- concurrent DNS lookup ---
        with ThreadPoolExecutor(max_workers=MAX_DNS_THREADS) as executor:
            futures = {
                executor.submit(self._resolve_subdomain, sub, base_domain): sub
                for sub in COMMON_SUBDOMAINS
            }
            for future in as_completed(futures):
                sub = futures[future]
                try:
                    result = future.result()
                    if result:
                        discovered.append(result)
                except Exception:
                    pass

        discovered.sort(key=lambda d: d["candidate"])

        # --- HTTP probe on discovered subdomains ---
        for entry in discovered:
            service_info = self._http_check_subdomain(entry["candidate"])
            if service_info:
                entry["detail"] += f" | {service_info}"

        for entry in discovered:
            findings.append({
                "severity": entry.pop("severity"),
                "title": entry.pop("title"),
                "detail": entry.pop("detail"),
            })

        if findings:
            findings.insert(0, {
                "severity": "INFO",
                "title": f"Subdomain enumeration for {base_domain}",
                "detail": f"Found {len(findings)} subdomain(s)",
            })

        return findings

    # -- helpers -----------------------------------------------------------

    def _resolve_subdomain(
        self, sub: str, base_domain: str
    ) -> dict | None:
        """Resolve a single subdomain. Return info dict or None."""
        candidate = f"{sub}.{base_domain}"
        try:
            records = socket.getaddrinfo(candidate, None)
            ips: set[str] = set()
            for r in records:
                if r[4] and len(r[4]) >= 1:
                    ips.add(r[4][0])
            if ips:
                return {
                    "severity": "INFO",
                    "title": f"Subdomain found: {candidate}",
                    "detail": f"Resolved to: {', '.join(sorted(ips))}",
                    "candidate": candidate,
                }
        except (socket.gaierror, OSError):
            pass
        return None

    def _http_check_subdomain(self, subdomain: str) -> str | None:
        """Try HTTP and HTTPS on a subdomain to identify the service."""
        import requests
        parts: list[str] = []
        for scheme, port in [("http", 80), ("https", 443)]:
            url = f"{scheme}://{subdomain}:{port}/"
            try:
                resp = requests.get(
                    url,
                    timeout=self.config.timeout / 2,
                    verify=self.config.verify_ssl,
                    allow_redirects=False,
                )
                server = resp.headers.get("Server", "")
                p = []
                if server:
                    p.append(f"Server={server}")
                p.append(f"HTTP {resp.status_code}")
                title = extract_title(resp.text)
                if title:
                    p.append(f"title=\"{title}\"")
                if p:
                    parts.append(f"{scheme.upper()}: {'; '.join(p)}")
                break  # one scheme worked, no need for the other
            except Exception:
                continue
        return " | ".join(parts) if parts else None
