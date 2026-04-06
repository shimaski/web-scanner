"""SQL injection detection scanner."""

import re

from web_scanner.scanner import BaseScanner

SQLI_PAYLOADS = [
    ("'", "single_quote"),
    ("1' OR '1'='1' --", "classic_or"),
    ("1 UNION SELECT NULL --", "union_select"),
    ("'; WAITFOR DELAY '0:0:5'--", "time_based_mssql"),
    ("1' AND SLEEP(5) --", "time_based_mysql"),
    ("1' AND 1=1 --", "boolean_true"),
    ("1' AND 1=2 --", "boolean_false"),
    ("\" OR \"1\"=\"1", "double_quote_or"),
    ("admin'--", "comment_bypass"),
    ("0 OR 1=1", "tautology"),
]

SQL_ERROR_PATTERNS = [
    r"MySQL.*syntax",
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_",
    r"mysql_fetch",
    r"mysqli_",
    r"SQLServer.*Driver",
    r"Unclosed quotation mark",
    r"SQLite3::query",
    r"SQLITE_ERROR",
    r"PostgreSQL.*ERROR",
    r"PgSQL.*ERROR",
    r"ORA-\d{5}",
    r"Microsoft OLE DB Provider",
    r"ODBC SQL Server",
    r"syntax error",
    r"unexpected end of",
    r"invalid identifier",
    r"division by zero",
]


class SQLiScanner(BaseScanner):
    """Detect SQL injection via error-based, boolean-based, and time-based methods."""

    def run(self) -> list[dict]:
        findings: list[dict] = []

        # Get baseline response
        resp = self.client.get("/")
        if resp is None:
            return findings

        baseline_len = len(resp.text)
        baseline_time = resp.elapsed.total_seconds()

        # Extract params from page
        test_params = self._extract_params(resp.text)
        test_params = test_params if test_params else ["q", "search", "id", "page", "user"]

        for param in test_params:
            for payload, payload_type in SQLI_PAYLOADS:
                resp = self.client.get(f"?{param}={payload}")
                if resp is None:
                    continue

                # Error-based detection
                for pattern in SQL_ERROR_PATTERNS:
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        findings.append({
                            "severity": "CRITICAL",
                            "title": f"SQL injection ({payload_type}) via '{param}'",
                            "detail": f"URL: {self._full_url(f'?{param}={payload[:40]}')}\nSQL error pattern detected in response",
                        })
                        break

                # Boolean-based detection
                if "boolean" in payload_type:
                    resp2 = self.client.get(f"?{param}={payload}")
                    if resp2:
                        diff = abs(len(resp2.text) - baseline_len)
                        if diff > baseline_len * 0.3:
                            findings.append({
                                "severity": "HIGH",
                                "title": f"Possible SQL injection (boolean) via '{param}'",
                                "detail": f"URL: {self._full_url(f'?{param}={payload[:40]}')}\nResponse length changed by {diff} bytes ({payload_type})",
                            })

                # Time-based detection
                if "sleep" in payload_type.lower() or "delay" in payload_type.lower():
                    elapsed = resp.elapsed.total_seconds()
                    if elapsed >= baseline_time + 4:
                        findings.append({
                            "severity": "CRITICAL",
                            "title": f"SQL injection (time-based) via '{param}'",
                            "detail": f"URL: {self._full_url(f'?{param}={payload[:40]}')}\nResponse delayed {elapsed:.1f}s — possible {payload_type}",
                        })

        return findings

    def _extract_params(self, html: str) -> list[str]:
        params = set()
        try:
            from bs4 import BeautifulSoup
            from urllib.parse import parse_qs, urlparse
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
