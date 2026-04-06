"""Central registry of all scanner modules, labels, and templates."""

from web_scanner.backup_scanner import BackupScanner
from web_scanner.cmd_injection import CommandInjectionScanner
from web_scanner.cors_scanner import CORSScanner
from web_scanner.crlf_scanner import CRLFScanner
from web_scanner.csrf_scanner import CSRFScanner
from web_scanner.dir_bruteforce import DirBruteforce
from web_scanner.http_verb_scanner import HTTPVerbScanner
from web_scanner.info_gather import InfoGatherer
from web_scanner.open_redirect import OpenRedirectScanner
from web_scanner.param_fuzzer import ParameterFuzzer
from web_scanner.path_traversal import PathTraversalScanner
from web_scanner.plugin_loader import load_plugins
from web_scanner.port_scan import PortScanner
from web_scanner.sqli_scanner import SQLiScanner
from web_scanner.ssrf_scanner import SSRFScanner
from web_scanner.subdomain_enum import SubdomainEnum
from web_scanner.ssl_check import SSLCheck
from web_scanner.upload_scanner import UploadScanner
from web_scanner.xss_scanner import XSSScanner
from web_scanner.xss_stored import StoredXSSScanner
from web_scanner.xxe_scanner import XXEScanner

SCANNER_MAP: dict[str, type] = {
    "info": InfoGatherer,
    "xss": XSSScanner,
    "xss_stored": StoredXSSScanner,
    "sqli": SQLiScanner,
    "traversal": PathTraversalScanner,
    "redirect": OpenRedirectScanner,
    "csrf": CSRFScanner,
    "cors": CORSScanner,
    "ssrf": SSRFScanner,
    "crlf": CRLFScanner,
    "dirb": DirBruteforce,
    "fuzz": ParameterFuzzer,
    "port": PortScanner,
    "ssl": SSLCheck,
    "subdomains": SubdomainEnum,
    "cmdi": CommandInjectionScanner,
    "xxe": XXEScanner,
    "upload": UploadScanner,
    "http_verb": HTTPVerbScanner,
    "backup": BackupScanner,
}

# Load plugins (extend the registry)
SCANNER_MAP.update(load_plugins())

ALL_MODULES = list(SCANNER_MAP.keys())

MODULE_LABELS: dict[str, str] = {
    "info": "Information Gathering",
    "xss": "XSS (Reflected)",
    "xss_stored": "XSS (Stored)",
    "sqli": "SQL Injection",
    "traversal": "Path Traversal",
    "redirect": "Open Redirect",
    "csrf": "CSRF",
    "cors": "CORS",
    "ssrf": "SSRF",
    "crlf": "CRLF Injection",
    "dirb": "Directory Bruteforce",
    "fuzz": "Parameter Fuzzer (ffuf-style)",
    "port": "Port Scan",
    "ssl": "SSL/TLS Check",
    "subdomains": "Subdomain Enumeration",
    "cmdi": "Command Injection",
    "xxe": "XXE Injection",
    "upload": "File Upload",
    "http_verb": "HTTP Verb Tampering",
    "backup": "Backup Files",
}

TEMPLATES: dict[str, list[str]] = {
    "quick": ["info", "port", "ssl"],
    "full": ALL_MODULES,
    "fast": ["info", "xss", "redirect", "cors"],
}
