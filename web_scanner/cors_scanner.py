"""CORS misconfiguration detection."""

from web_scanner.scanner import BaseScanner

ORIGIN_PAYLOADS = [
    "https://evil.com",
    "null",
    "https://localhost.evil.com",
    "https://evil.example.com",
]


class CORSScanner(BaseScanner):
    """Detect CORS misconfigurations."""

    def run(self) -> list[dict]:
        findings: list[dict] = []

        # Test root
        resp = self.client.get("/")
        if resp is None:
            return findings

        original_ao = resp.headers.get("Access-Control-Allow-Origin", "")

        if not original_ao:
            # Check if CORS headers exist at all
            resp_preflight = self.client.request("OPTIONS", "/")
            if resp_preflight is None:
                return findings
            original_ao = resp_preflight.headers.get("Access-Control-Allow-Origin", "")

        if not original_ao:
            return findings

        # Test 1: wildcard with credentials
        if original_ao == "*":
            findings.append({
                "severity": "MEDIUM",
                "title": "CORS Allow-Origin wildcard (*)",
                "detail": f"URL: {self._full_url('/')}\nAccess-Control-Allow-Origin is set to * — any origin can access resources",
            })
            if "true" in resp.headers.get("Access-Control-Allow-Credentials", "").lower():
                findings.append({
                    "severity": "HIGH",
                    "title": "CORS wildcard with credentials",
                    "detail": f"URL: {self._full_url('/')}\nAllow-Origin: * with Allow-Credentials: true",
                })

        # Test 2: reflected origin
        for origin in ORIGIN_PAYLOADS:
            resp_cors = self.client.get("/", headers={"Origin": origin})
            if resp_cors is None:
                continue

            acao = resp_cors.headers.get("Access-Control-Allow-Origin", "")
            if acao == origin or (origin == "null" and acao.lower() == "null"):
                acac = resp_cors.headers.get("Access-Control-Allow-Credentials", "")
                severity = "HIGH" if "true" in acac.lower() else "MEDIUM"
                findings.append({
                    "severity": severity,
                    "title": f"CORS misconfiguration — reflected origin: {origin}",
                    "detail": f"URL: {self._full_url('/')}\nServer reflected Origin: {origin} (credentials: {acac or 'none'})",
                })
                break

        # Test 3: subdomain wildcard
        test_subdomain = "https://test.evil.com"
        resp_sub = self.client.get("/", headers={"Origin": test_subdomain})
        if resp_sub:
            allowed = resp_sub.headers.get("Access-Control-Allow-Origin", "")
            if "evil.com" in allowed and allowed != test_subdomain:
                findings.append({
                    "severity": "HIGH",
                    "title": "CORS overly permissive origin matching",
                    "detail": f"URL: {self._full_url('/')}\nOrigin {test_subdomain} matched allow rule: {allowed}",
                })

        return findings
