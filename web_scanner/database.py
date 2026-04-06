"""SQLite database for scan persistence."""

import json
import sqlite3
import threading
from datetime import datetime
from pathlib import Path

from web_scanner.attack_descriptions import enrich_findings

DB_PATH = Path(__file__).parent.parent / "scans.db"
_local = threading.local()


def get_conn() -> sqlite3.Connection:
    if not hasattr(_local, "conn"):
        _local.conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        _local.conn.row_factory = sqlite3.Row
    return _local.conn


def init_db():
    conn = get_conn()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS scans (
        id TEXT PRIMARY KEY,
        target TEXT NOT NULL,
        modules TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'starting',
        total_findings INTEGER DEFAULT 0,
        by_severity TEXT DEFAULT '{}',
        started_at TEXT NOT NULL,
        completed_at TEXT DEFAULT '',
        config TEXT DEFAULT '{}',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT NOT NULL REFERENCES scans(id),
        severity TEXT,
        title TEXT,
        detail TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS scan_urls (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT NOT NULL REFERENCES scans(id),
        url TEXT NOT NULL,
        status_code INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS schedules (
        id TEXT PRIMARY KEY,
        target TEXT NOT NULL,
        interval_hours INTEGER NOT NULL DEFAULT 24,
        modules TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'active',
        timeout INTEGER DEFAULT 10,
        threads INTEGER DEFAULT 10,
        user_agent TEXT DEFAULT 'WebScanner/0.1.0',
        crawl INTEGER DEFAULT 0,
        last_run TEXT DEFAULT '',
        next_run TEXT DEFAULT '',
        run_count INTEGER DEFAULT 0,
        created_at TEXT NOT NULL,
        config TEXT DEFAULT '{}',
        delay REAL DEFAULT 0,
        proxy TEXT DEFAULT '',
        cookie TEXT DEFAULT ''
    );
    """)
    conn.commit()


def save_scan(scan_id: str, target: str, modules: list, status: str,
              findings: list, by_severity: dict, config: dict | None = None):
    conn = get_conn()
    conn.execute("""
        INSERT OR REPLACE INTO scans (id, target, modules, status, total_findings,
                                       by_severity, started_at, completed_at, config)
        VALUES (?, ?, ?, ?, ?, ?, COALESCE(
            (SELECT started_at FROM scans WHERE id = ?), ?),
            ?, ?)
    """, (
        scan_id,
        target,
        json.dumps(modules),
        status,
        len(findings),
        json.dumps(by_severity),
        scan_id,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        datetime.now().strftime("%Y-%m-%d %H:%M:%S") if status == "completed" else "",
        json.dumps(config or {}),
    ))

    # Save findings
    conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
    for f in findings:
        conn.execute(
            "INSERT INTO findings (scan_id, severity, title, detail) VALUES (?, ?, ?, ?)",
            (scan_id, f.get("severity", "INFO"), f.get("title", ""), f.get("detail", "")),
        )

    conn.commit()


def get_scan(scan_id: str) -> dict | None:
    conn = get_conn()
    row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if row is None:
        return None

    findings = conn.execute(
        "SELECT severity, title, detail FROM findings WHERE scan_id = ? ORDER BY id",
        (scan_id,),
    ).fetchall()

    findings_list = [dict(f) for f in findings]
    findings_list = enrich_findings(findings_list)

    return {
        "scan_id": row["id"],
        "target": row["target"],
        "modules": json.loads(row["modules"]),
        "status": row["status"],
        "findings": findings_list,
        "total_findings": row["total_findings"],
        "by_severity": json.loads(row["by_severity"]),
        "started_at": row["started_at"],
        "completed_at": row["completed_at"],
        "config": json.loads(row["config"]),
    }


def list_scans(limit: int = 50) -> list[dict]:
    conn = get_conn()
    rows = conn.execute(
        "SELECT id, target, modules, status, total_findings, by_severity, started_at, completed_at FROM scans ORDER BY created_at DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]


def delete_scan(scan_id: str):
    conn = get_conn()
    conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
    conn.execute("DELETE FROM scan_urls WHERE scan_id = ?", (scan_id,))
    conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    conn.commit()


def compare_scans(scan_id_a: str, scan_id_b: str) -> dict:
    """Compare two scans of the same target and return diff."""
    a = get_scan(scan_id_a)
    b = get_scan(scan_id_b)
    if a is None or b is None:
        return {"error": "Scan not found"}

    findings_a = {(f["severity"], f["title"]) for f in a["findings"]}
    findings_b = {(f["severity"], f["title"]) for f in b["findings"]}

    return {
        "scan_a": {"id": scan_id_a, "target": a["target"], "findings": a["total_findings"], "date": a["started_at"]},
        "scan_b": {"id": scan_id_b, "target": b["target"], "findings": b["total_findings"], "date": b["started_at"]},
        "a_only": [{"severity": s, "title": t} for s, t in findings_a - findings_b],
        "b_only": [{"severity": s, "title": t} for s, t in findings_b - findings_a],
        "common": [{"severity": s, "title": t} for s, t in findings_a & findings_b],
        "delta": b["total_findings"] - a["total_findings"],
    }


# --- Schedule persistence ---

def save_schedule(schedule: dict):
    """Insert or replace a schedule record."""
    conn = get_conn()
    conn.execute("""
        INSERT OR REPLACE INTO schedules (
            id, target, interval_hours, modules, status, timeout, threads,
            user_agent, crawl, last_run, next_run, run_count, created_at,
            config, delay, proxy, cookie
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        schedule["id"],
        schedule["target"],
        schedule.get("interval_hours", 24),
        json.dumps(schedule.get("modules", [])),
        schedule.get("status", "active"),
        schedule.get("timeout", 10),
        schedule.get("threads", 10),
        schedule.get("user_agent", "WebScanner/0.1.0"),
        int(schedule.get("crawl", False)),
        schedule.get("last_run", ""),
        schedule.get("next_run", ""),
        schedule.get("run_count", 0),
        schedule.get("created_at", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        json.dumps({}),
        schedule.get("_delay", 0),
        schedule.get("_proxy", ""),
        schedule.get("_cookie", ""),
    ))
    conn.commit()


def get_schedule(sched_id: str) -> dict | None:
    """Get a single schedule by id."""
    conn = get_conn()
    row = conn.execute("SELECT * FROM schedules WHERE id = ?", (sched_id,)).fetchone()
    if row is None:
        return None
    d = dict(row)
    d["modules"] = json.loads(d["modules"])
    d["crawl"] = bool(d["crawl"])
    d["_delay"] = d.pop("delay", 0)
    d["_proxy"] = d.pop("proxy", "")
    d["_cookie"] = d.pop("cookie", "")
    d["config"] = json.loads(d.get("config", "{}"))
    return d


def list_schedules() -> list[dict]:
    """List all schedules."""
    conn = get_conn()
    rows = conn.execute("SELECT * FROM schedules ORDER BY created_at DESC").fetchall()
    result = []
    for r in rows:
        d = dict(r)
        d["modules"] = json.loads(d["modules"])
        d["crawl"] = bool(d["crawl"])
        d["_delay"] = d.pop("delay", 0)
        d["_proxy"] = d.pop("proxy", "")
        d["_cookie"] = d.pop("cookie", "")
        d["config"] = json.loads(d.get("config", "{}"))
        result.append(d)
    return result


def delete_schedule(sched_id: str):
    """Delete a schedule."""
    conn = get_conn()
    conn.execute("DELETE FROM schedules WHERE id = ?", (sched_id,))
    conn.commit()


SCHEDULE_VALID_FIELDS = frozenset([
    "target", "interval_hours", "modules", "status", "timeout", "threads",
    "user_agent", "crawl", "last_run", "next_run", "run_count",
    "config", "delay", "proxy", "cookie",
])


def update_schedule_field(sched_id: str, field: str, value):
    """Update a single field on a schedule."""
    if field not in SCHEDULE_VALID_FIELDS:
        raise ValueError(f"Unknown schedule field: {field}")
    conn = get_conn()
    if field in ("modules", "config"):
        value = json.dumps(value)
    elif field == "crawl":
        value = int(bool(value))
    conn.execute(
        f"UPDATE schedules SET {field} = ? WHERE id = ?",
        (value, sched_id),
    )
    conn.commit()


# Initialize DB on import
init_db()