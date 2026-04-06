"""Insecure file upload detection — checks upload forms for validation."""

import logging

from web_scanner.scanner import BaseScanner
from web_scanner.config import ScanConfig
from web_scanner.http_client import HTTPClient

logger = logging.getLogger(__name__)

DANGEROUS_EXTENSIONS = [".php", ".jsp", ".asp", ".aspx", ".cgi", ".py", ".sh"]


class UploadScanner(BaseScanner):
    """Detect potentially insecure file upload configurations."""

    def run(self):
        findings: list[dict] = []
        resp = self.client.get("/")
        if resp is None:
            return findings

        from bs4 import BeautifulSoup
        soup = BeautifulSoup(resp.text, "html.parser")

        upload_forms = self._find_upload_forms(soup)
        if not upload_forms:
            return findings

        for form_info in upload_forms:
            action = form_info["action"]
            enctype = form_info.get("enctype", "")

            # No accept attribute = wider upload scope
            if not form_info.get("accept_types"):
                findings.append({
                    "severity": "MEDIUM",
                    "title": f"Upload endpoint without type restriction: {action}",
                    "detail": f"URL: {self._full_url(action)}\nFile input has no 'accept' attribute — may accept arbitrary file types",
                })

            # No hidden size limits visible in client-side validation
            has_size_limit = False
            for inp in soup.find_all("input"):
                name = inp.get("name", "").lower()
                if any(kw in name for kw in ("maxsize", "max_size", "max_file_size")):
                    has_size_limit = True
            if not has_size_limit:
                findings.append({
                    "severity": "LOW",
                    "title": f"No client-side file size limit on {action}",
                    "detail": f"URL: {self._full_url(action)}\nNo max_file_size or similar constraint found in form",
                })

            # Missing CSRF on multipart forms
            has_csrf = False
            for inp in form_info.get("inputs", []):
                if any(t in inp.get("name", "").lower() for t in ("csrf", "token", "xsrf")):
                    has_csrf = True
            if not has_csrf:
                findings.append({
                    "severity": "MEDIUM",
                    "title": f"Upload form without CSRF token: {action}",
                    "detail": f"URL: {self._full_url(action)}\nMultipart form submission missing CSRF protection",
                })

            # Test uploading a .php file
            finding = self._test_dangerous_upload(form_info)
            if finding:
                findings.append(finding)

        return findings

    def _find_upload_forms(self, soup) -> list[dict]:
        forms = []
        for form in soup.find_all("form"):
            file_inputs = [inp for inp in form.find_all("input") if inp.get("type") == "file"]
            if not file_inputs:
                continue
            form_info = {
                "action": form.get("action", "/"),
                "method": form.get("method", "post").upper(),
                "enctype": form.get("enctype", ""),
                "accept_types": [],
                "inputs": [],
            }
            for inp in file_inputs:
                accept = inp.get("accept", "")
                if accept:
                    form_info["accept_types"].append(accept)
            for inp in form.find_all(["input", "select", "textarea"]):
                form_info["inputs"].append({
                    "name": inp.get("name", ""),
                    "type": inp.get("type", "text"),
                })
            forms.append(form_info)
        return forms

    def _test_dangerous_upload(self, form_info: dict) -> dict | None:
        """Attempt to upload a .php file and check if it's served as executable."""
        from io import BytesIO

        action = form_info["action"]
        try:
            files = {
                "file": ("test.php", b"<?php echo 'VULNERABLE'; ?>", "application/x-httpd-php"),
            }
            # Add other form fields
            data = {}
            for inp in form_info.get("inputs", []):
                if inp.get("type", "") != "file":
                    data[inp.get("name", "")] = inp.get("value", "")

            resp = self.client.request(
                form_info.get("method", "POST").upper(),
                action,
                files=files,
                data=data,
            )
            if resp is None:
                return None

            # If we get back exact PHP content, it's not being executed — good
            # If we see "VULNERABLE" in response but not as PHP source, it was executed
            if "VULNERABLE" in resp.text and "<?php" not in resp.text.split("VULNERABLE")[0]:
                return {
                    "severity": "CRITICAL",
                    "title": f"Executable file upload at {action}",
                    "detail": f"URL: {self._full_url(action)}\nUploaded .php was executed — arbitrary code execution possible",
                }
        except Exception as e:
            logger.debug("Upload test failed for %s: %s", action, e)
        return None
