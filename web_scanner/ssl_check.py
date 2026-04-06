"""SSL/TLS certificate analysis."""

import ssl
import socket
from datetime import datetime

from web_scanner.config import ScanConfig
from web_scanner.http_client import HTTPClient
from web_scanner.scanner import BaseScanner


class SSLCheck(BaseScanner):
    """Analyze SSL/TLS certificate and configuration."""

    def run(self) -> list[dict]:
        findings: list[dict] = []

        from urllib.parse import urlparse
        parsed = urlparse(self.client.base_url)
        if parsed.scheme != "https":
            return findings

        host = parsed.hostname
        port = parsed.port or 443

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with ctx.wrap_socket(socket.socket(), server_hostname=host) as sock:
                sock.settimeout(self.config.timeout)
                sock.connect((host, port))
                cert = sock.getpeercert()
                protocol = sock.version()

        except ssl.SSLError as e:
            findings.append({
                "severity": "HIGH",
                "title": f"SSL error: {e}",
                "detail": "SSL/TLS certificate issue detected",
            })
            return findings
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            findings.append({
                "severity": "MEDIUM",
                "title": f"Could not connect on port {port}: {e}",
                "detail": "Unable to retrieve certificate information",
            })
            return findings

        # Check expiry
        not_after = cert.get("notAfter", "")
        if not_after:
            try:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry - datetime.now()).days
                if days_left < 0:
                    findings.append({
                        "severity": "CRITICAL",
                        "title": "SSL certificate has expired",
                        "detail": f"Expired on {expiry.strftime('%Y-%m-%d')}",
                    })
                elif days_left < 30:
                    findings.append({
                        "severity": "HIGH",
                        "title": "SSL certificate expires soon",
                        "detail": f"Expires in {days_left} days ({expiry.strftime('%Y-%m-%d')})",
                    })
                elif days_left < 90:
                    findings.append({
                        "severity": "LOW",
                        "title": "SSL certificate expiring in less than 90 days",
                        "detail": f"Expires in {days_left} days",
                    })

            except ValueError:
                pass

        # Check issuer
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        org = issuer.get("organizationName", "Unknown")
        cn = issuer.get("commonName", "Unknown")

        if org == "Unknown" or cn == "Unknown":
            findings.append({
                "severity": "MEDIUM",
                "title": "Self-signed or untrusted certificate",
                "detail": f"Issuer: O={org}, CN={cn}",
            })

        # Check protocol version
        if protocol:
            findings.append({
                "severity": "INFO",
                "title": f"SSL protocol: {protocol}",
                "detail": f"Certificate issued to: {cert.get('subject', ({},))[0].get('commonName', 'Unknown')}",
            })

        # Check SAN (Subject Alternative Names)
        san = cert.get("subjectAltName", [])
        if san:
            dns_names = [v for t, v in san if t == "DNS"]
            findings.append({
                "severity": "INFO",
                "title": f"Certificate covers {len(dns_names)} domain(s)",
                "detail": f"Domains: {', '.join(dns_names[:5])}",
            })

        return findings
