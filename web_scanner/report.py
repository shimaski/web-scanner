"""Report generation — console, JSON, and HTML output."""

import json
import logging
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",  # red
    "HIGH": "\033[31m",      # dark red
    "MEDIUM": "\033[33m",    # yellow
    "LOW": "\033[36m",       # cyan
    "INFO": "\033[37m",      # white
}
RESET = "\033[0m"


def _safe_str(text: str) -> str:
    """Replace characters not supported by the current console encoding."""
    import sys
    enc = getattr(sys.stdout, "encoding", "utf-8") or "utf-8"
    return text.encode(enc, errors="replace").decode(enc)


def print_report_console(findings: list[dict], target: str):
    total = len(findings)
    by_severity = {}
    for f in findings:
        s = f.get("severity", "INFO")
        by_severity[s] = by_severity.get(s, 0) + 1

    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    print(f"\n{'='*60}")
    print(f"  Scan Report — {target}")
    print(f"  Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    print(f"  Total findings: {total}")
    for s in severity_order:
        count = by_severity.get(s, 0)
        if count > 0:
            color = SEVERITY_COLORS.get(s, RESET)
            print(f"  {color}{s}: {count}{RESET}")
    print(f"{'='*60}\n")

    for i, f in enumerate(findings, 1):
        color = SEVERITY_COLORS.get(f.get("severity", "INFO"), RESET)
        title = _safe_str(f.get("title", ""))
        detail = _safe_str(f.get("detail", ""))
        print(f"  [{i}] {color}[{f.get('severity', 'INFO')}]{RESET} {title}")
        print(f"      {detail}")
        attack = _safe_str(f.get("attack", ""))
        if attack:
            print(f"      \033[33mAttack scenarios: {attack}\033[0m")
        print()


def export_json(findings: list[dict], target: str, path: str):
    report = {
        "target": target,
        "date": datetime.now().isoformat(),
        "total_findings": len(findings),
        "findings": findings,
    }
    p = Path(path)
    p.write_text(json.dumps(report, indent=2))
    logger.info("JSON report saved to %s", p)


_FINDING_CARD_CSS = """
.finding-card {
    background: #252525; border: 1px solid #444; border-radius: 8px;
    margin-bottom: 1rem; overflow: hidden;
}
.finding-card-header {
    padding: 0.75rem 1rem; display: flex; align-items: center; gap: 0.5rem;
    border-bottom: 1px solid #444;
}
.finding-card-body { padding: 0.75rem 1rem; }
.finding-detail { color: #9ca3af; font-size: 0.85rem; margin-bottom: 0.5rem; }
.atk-toggle {
    cursor: pointer; font-size: 0.78rem; color: #f97316; font-weight: 600;
    background: none; border: none; font-family: inherit;
}
.atk-toggle:hover { text-decoration: underline; }
.atk-body { display: none; margin-top: 0.5rem; font-size: 0.82rem; }
.atk-body.open { display: block; }
.atk-label {
    font-weight: 600; font-size: 0.72rem; text-transform: uppercase;
    letter-spacing: 0.04em; color: #f97316; margin-bottom: 0.2rem;
}
.atk-section, .atk-severity { margin-top: 0.65rem; }
.atk-impact {
    margin-bottom: 0.6rem; padding: 0.5rem 0.75rem; background: rgba(239,68,68,0.1);
    border-radius: 4px; border-left: 3px solid #ef4444; color: #fca5a5;
}
.atk-impact .atk-label { color: #ef4444; }
.atk-list { margin: 0.25rem 0 0 1.2rem; color: #d1d5db; font-size: 0.82rem; }
.atk-list li { margin-bottom: 0.25rem; }
.atk-section { color: #9ca3af; font-size: 0.82rem; }
.atk-severity {
    padding: 0.4rem 0.65rem; background: #1e1e1e; border-radius: 4px;
    border-left: 2px solid #71717a; color: #a1a1aa; font-size: 0.82rem; margin-top: 0.5rem;
}
"""


def _render_cards(findings, target):
    """Render findings as detail cards."""
    severity_colors = {
        "CRITICAL": "#ef4444", "HIGH": "#f97316",
        "MEDIUM": "#eab308", "LOW": "#3b82f6", "INFO": "#71717a",
    }
    cards = ""
    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "INFO")
        color = severity_colors.get(sev, "#aaa")
        attack_html = ""
        if f.get("attack"):
            attack_html = (
                f'<button class="atk-toggle" '
                f'onclick="this.nextElementSibling.classList.toggle(\'open\')">'
                f'\u26a0 Poss\u00edveis Ataques \u25bc</button>'
                f'<div class="atk-body">{f["attack"]}</div>'
            )
        cards += f"""
        <div class="finding-card">
            <div class="finding-card-header">
                <span style="color:{color};font-weight:bold;min-width:24px">{sev}</span>
                <span style="color:#ccc">#{i}</span> — {f.get('title', '')}
            </div>
            <div class="finding-card-body">
                <div class="finding-detail">{f.get('detail', '')}</div>
                {attack_html}
            </div>
        </div>"""
    return cards


def _build_html(findings: list[dict], target: str) -> str:
    """Shared HTML template for report output."""
    cards = _render_cards(findings, target)
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Scan Report — {target}</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', monospace; background: #1e1e1e; color: #d4d4d4; padding: 2em; }}
h1 {{ color: #fff; margin-bottom: 0.25em; }}
p {{ margin-bottom: 0.5em; color: #71717a; }}
{_FINDING_CARD_CSS}
</style></head><body>
<h1>Scan Report — {target}</h1>
<p>Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | Total findings: {len(findings)}</p>
{cards}
</body></html>"""


def export_html(findings: list[dict], target: str, path: str):
    html = _build_html(findings, target)
    p = Path(path)
    p.write_text(html)
    logger.info("HTML report saved to %s", p)


def export_html_string(findings: list[dict], target: str) -> str:
    """Return HTML report as a string for inline viewing."""
    return _build_html(findings, target)
