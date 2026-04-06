"""Webhook notifications for scan events."""

import json
import logging
import os
import urllib.error
import urllib.request
from pathlib import Path

logger = logging.getLogger(__name__)


def send_webhook(url: str, payload: dict) -> bool:
    """Send a JSON webhook notification."""
    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            logger.info("Webhook sent to %s — status %d", url, resp.status)
            return True
    except Exception as e:
        logger.warning("Webhook failed: %s", e)
        return False


def notify_scan_started(scan_id: str, target: str, modules: list[str], webhook_url: str):
    send_webhook(webhook_url, {
        "event": "scan_started",
        "scan_id": scan_id,
        "target": target,
        "modules": modules,
    })


def notify_scan_completed(scan_id: str, target: str, findings: list, webhook_url: str):
    criticals = [f for f in findings if f.get("severity") == "CRITICAL"]
    highs = [f for f in findings if f.get("severity") == "HIGH"]
    send_webhook(webhook_url, {
        "event": "scan_completed",
        "scan_id": scan_id,
        "target": target,
        "total_findings": len(findings),
        "critical": len(criticals),
        "high": len(highs),
        "critical_findings": criticals[:5],
    })


WEBHOOKS_FILE = "webhooks.json"


def load_webhooks() -> list[str]:
    try:
        p = Path(__file__).parent.parent / WEBHOOKS_FILE
        if p.exists():
            return json.loads(p.read_text())
    except Exception:
        pass
    return []


def save_webhooks(urls: list[str]):
    p = Path(__file__).parent.parent / WEBHOOKS_FILE
    p.write_text(json.dumps(urls, indent=2))
