"""Shared utility functions used across the scanner modules."""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import parse_qs, urlparse

SEVERITY_RANK: dict[str, int] = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def count_by_severity(findings: list[dict]) -> dict[str, int]:
    """Count findings grouped by severity level."""
    result: dict[str, int] = {}
    for f in findings:
        s = f.get("severity", "INFO")
        result[s] = result.get(s, 0) + 1
    return result


def sort_findings(findings: list[dict]) -> list[dict]:
    """Return a new list sorted by severity (CRITICAL first)."""
    return sorted(findings, key=lambda f: SEVERITY_RANK.get(f.get("severity", "INFO"), 5))


@dataclass
class ExtractedParams:
    """Result from extract_params."""
    form_params: list[str]
    url_params: list[str]

    @property
    def all(self) -> list[str]:
        seen = set()
        out: list[str] = []
        for p in self.form_params + self.url_params:
            if p not in seen:
                seen.add(p)
                out.append(p)
        return out


def extract_params(html: str) -> ExtractedParams:
    """Extract parameter names from forms and query strings in HTML.

    Returns an ExtractedParams with form_params (from <input>/<select>/<textarea>)
    and url_params (from keys in href query strings).
    """
    form_params: set[str] = set()
    url_params: set[str] = set()
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, "html.parser")
        for form in soup.find_all("form"):
            for inp in form.find_all(["input", "select", "textarea"]):
                name = inp.get("name")
                if name:
                    form_params.add(name)
        for tag in soup.find_all(True, href=True):
            href = tag.get("href", "")
            if "?" in href:
                parsed = urlparse(href)
                url_params.update(parse_qs(parsed.query).keys())
    except Exception:
        pass
    return ExtractedParams(list(form_params), list(url_params))


def extract_title(html: str) -> str | None:
    """Extract the page title from an HTML string."""
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if m:
        return m.group(1).strip()
    return None
