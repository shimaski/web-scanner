"""Command-line interface for the vulnerability scanner."""

import argparse
import logging
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from web_scanner.config import ScanConfig
from web_scanner.crawler import Crawler
from web_scanner.http_client import HTTPClient
from web_scanner.modules import ALL_MODULES, MODULE_LABELS, SCANNER_MAP, TEMPLATES
from web_scanner.report import export_html, export_json, print_report_console
from web_scanner.attack_descriptions import enrich_findings


def cli():
    parser = argparse.ArgumentParser(
        description="Web Application Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modules:
  info          Information gathering (headers, server, common files)
  xss           Reflected XSS detection
  xss_stored    Stored XSS detection
  sqli          SQL injection detection
  traversal     Path traversal & file inclusion
  redirect      Open redirect detection
  csrf          CSRF protection check
  cors          CORS misconfiguration
  ssrf          Server-Side Request Forgery
  crlf          CRLF injection / HTTP response splitting
  dirb          Directory/file brute force
  port          Port scan
  ssl           SSL/TLS certificate check
  subdomains    Subdomain enumeration
  cmdi          OS command injection
  xxe           XML External Entity injection
  upload        Insecure file upload detection
  http_verb     HTTP verb tampering
  backup        Exposed backup & temp files

Templates:
  quick     info, port, ssl
  full      all modules
  fast      info, xss, redirect, cors

Examples:
  web-scanner -t example.com
  web-scanner -t https://example.com -m info,xss -f json -o report.json
  web-scanner -t example.com -m all --threads 20
  web-scanner -t example.com --template full
  web-scanner -t http://localhost:8080 --crawl -m all --output report.html
        """,
    )
    parser.add_argument("-t", "--target", required=True, help="Target URL or hostname")
    parser.add_argument(
        "-m", "--modules", nargs="+", default=[],
        help=f"Modules to run. Available: {', '.join(ALL_MODULES)}. Use 'all' for everything.",
    )
    parser.add_argument("--template", default="", choices=["quick", "full", "fast"],
                        help="Scan template presets")
    parser.add_argument("--crawl", action="store_true", help="Crawl target before scanning")
    parser.add_argument("--plugin-dir", default="", help="Directory to load plugin .py files from")
    parser.add_argument("-f", "--format", default="text", choices=["text", "json", "html"],
                        help="Output format (default: text)")
    parser.add_argument("-o", "--output", default="", help="Output file path")
    parser.add_argument("--threads", type=int, default=10, help="Max concurrent threads (default: 10)")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP timeout in seconds (default: 10)")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay between requests (seconds)")
    parser.add_argument("--proxy", default="", help="HTTP proxy URL")
    parser.add_argument("--ua", default="WebScanner/0.1.0", help="Custom User-Agent")
    parser.add_argument("--cookie", default="", help="Cookie string for authenticated scans")

    # Auth options
    parser.add_argument("--basic-user", default="", help="HTTP Basic Auth username")
    parser.add_argument("--basic-pass", default="", help="HTTP Basic Auth password")
    parser.add_argument("--bearer", default="", help="Bearer token for authentication")
    parser.add_argument("--login-url", default="", help="Form login URL (POST to this endpoint)")
    parser.add_argument("--login-user", default="", help="Username for form login")
    parser.add_argument("--login-pass", default="", help="Password for form login")
    parser.add_argument("--login-user-field", default="username", help="Form field name for username")
    parser.add_argument("--login-pass-field", default="password", help="Form field name for password")
    parser.add_argument("--auto-relogin", action="store_true", help="Auto re-login on 401/403 responses")

    parser.add_argument("--wordlist", default="wordlists/extended.txt", help="Custom wordlist path")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")

    args = parser.parse_args()

    # Logging
    level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(level=level, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    # Resolve modules (template or explicit)
    if args.template:
        modules = TEMPLATES[args.template]
    elif not args.modules:
        modules = ["info"]
    else:
        modules = ALL_MODULES if "all" in args.modules or "ALL" in args.modules else args.modules

    for m in modules:
        if m not in ALL_MODULES:
            print(f"[!] Unknown module: {m}. Available: {', '.join(ALL_MODULES)}")
            sys.exit(1)

    config = ScanConfig.from_dict(
        target=args.target,
        timeout=args.timeout,
        max_threads=args.threads,
        user_agent=args.ua,
        output_format=args.format,
        output_file=args.output,
        delay=args.delay,
        proxy=args.proxy,
        cookie=args.cookie,
        wordlist_path=args.wordlist,
        basic_user=args.basic_user,
        basic_pass=args.basic_pass,
        bearer_token=args.bearer,
        login_url=args.login_url,
        login_username_field=args.login_user_field,
        login_password_field=args.login_pass_field,
        login_username=args.login_user,
        login_password=args.login_pass,
        auto_relogin=args.auto_relogin,
    )

    print(f"[*] Starting scan against {args.target}")
    if args.template:
        print(f"[*] Template: {args.template}")
    print(f"[*] Modules: {', '.join(MODULE_LABELS.get(m, m) for m in modules)}\n")

    all_findings = []
    client = HTTPClient(config)

    # Crawl before scanning
    if args.crawl:
        print("[*] Crawling target to discover URLs...")
        crawler = Crawler(client, config)
        urls, forms = crawler.crawl()
        print(f"[+] Found {len(urls)} URLs and {len(forms)} forms\n")
        all_findings.append(crawler.finding())
        # Attach discovered forms for scanners that need them
        config.crawled_urls = urls
        config.crawled_forms = forms

    # Run modules
    def run_module(module_name: str) -> list[dict]:
        scanner_cls = SCANNER_MAP[module_name]
        scanner = scanner_cls(client, config)
        try:
            findings = scanner.run()
            print(f"[+] {MODULE_LABELS.get(module_name, module_name)}: {len(findings)} finding(s)")
            return findings
        except Exception as e:
            print(f"[!] {MODULE_LABELS.get(module_name, module_name)} error: {e}")
            return []

    if len(modules) == 1:
        all_findings += run_module(modules[0])
    else:
        with ThreadPoolExecutor(max_workers=config.max_threads) as pool:
            futures = {pool.submit(run_module, m): m for m in modules}
            for future in as_completed(futures):
                all_findings.extend(future.result())

    # Add attack descriptions
    all_findings = enrich_findings(all_findings)

    # Sort by severity
    from web_scanner.utils import sort_findings
    all_findings = sort_findings(all_findings)

    # Report
    if args.format == "json":
        export_json(all_findings, args.target, args.output or "report.json")
    elif args.format == "html":
        export_html(all_findings, args.target, args.output or "report.html")

    print_report_console(all_findings, args.target)

    if args.output:
        print(f"[*] Report saved to {args.output}")


if __name__ == "__main__":
    cli()
