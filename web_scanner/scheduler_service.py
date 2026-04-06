"""Persistent scheduler service using threading.Timer and SQLite."""

import json
import logging
import threading
import uuid
from datetime import datetime, timedelta

from web_scanner.database import (
    delete_schedule,
    get_scan,
    get_schedule,
    list_schedules,
    save_schedule,
    update_schedule_field,
)
from web_scanner.notifications import load_webhooks, send_webhook

logger = logging.getLogger(__name__)


class SchedulerService:
    """Manages recurring vulnerability scans backed by SQLite."""

    def __init__(self, run_scan_fn):
        """
        Args:
            run_scan_fn: callable(scan_id, target, modules, timeout, threads,
                         user_agent, delay, proxy, cookie, do_crawl) that runs
                         a scan in a background thread.
        """
        self._run_scan = run_scan_fn
        # sched_id -> threading.Timer
        self._timers: dict[str, threading.Timer] = {}
        # sched_id -> schedule dict (mirrors DB state)
        self._schedules: dict[str, dict] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create(self, target: str, interval_hours: int, modules: list[str],
               timeout: int = 10, threads: int = 10,
               user_agent: str = "WebScanner/0.1.0",
               do_crawl: bool = False,
               proxy: str = "", cookie: str = "",
               delay: float = 0) -> dict:
        """Create a new schedule, persist it, and start the timer."""
        sched_id = str(uuid.uuid4())[:8]
        now = datetime.now()
        sched = {
            "id": sched_id,
            "target": target,
            "interval_hours": interval_hours,
            "modules": modules,
            "status": "active",
            "timeout": timeout,
            "threads": threads,
            "user_agent": user_agent,
            "crawl": do_crawl,
            "last_run": "",
            "next_run": (now + timedelta(hours=interval_hours)).strftime("%Y-%m-%d %H:%M:%S"),
            "run_count": 0,
            "created_at": now.strftime("%Y-%m-%d %H:%M:%S"),
            # Extra fields used internally for execution
            "_delay": delay,
            "_proxy": proxy,
            "_cookie": cookie,
        }
        with self._lock:
            save_schedule(sched)
            self._schedules[sched_id] = sched
        self._schedule_timer(sched_id)
        logger.info("Schedule %s created for %s (every %dh)", sched_id, target, interval_hours)
        return sched

    def delete(self, sched_id: str) -> bool:
        """Stop timer, remove from DB, forget in memory."""
        self._stop_timer(sched_id)
        with self._lock:
            delete_schedule(sched_id)
            self._schedules.pop(sched_id, None)
        logger.info("Schedule %s deleted", sched_id)
        return True

    def pause(self, sched_id: str) -> dict | None:
        """Pause a schedule (stop its timer, update status)."""
        self._stop_timer(sched_id)
        with self._lock:
            update_schedule_field(sched_id, "status", "paused")
            if sched_id in self._schedules:
                self._schedules[sched_id]["status"] = "paused"
        logger.info("Schedule %s paused", sched_id)
        return self._schedules.get(sched_id)

    def resume(self, sched_id: str) -> dict | None:
        """Resume a paused schedule."""
        with self._lock:
            sched = self._schedules.get(sched_id)
        if sched is None:
            # Reload from DB if not in memory
            sched = get_schedule(sched_id)
            if sched is None:
                return None
            sched["modules"] = json.loads(sched["modules"]) if isinstance(sched.get("modules"), str) else sched.get("modules", [])
            self._schedules[sched_id] = sched

        update_schedule_field(sched_id, "status", "active")
        sched["status"] = "active"
        self._schedule_timer(sched_id)
        logger.info("Schedule %s resumed", sched_id)
        return sched

    def run_now(self, sched_id: str) -> dict | None:
        """Trigger an immediate scan for a schedule (does not reschedule the timer)."""
        with self._lock:
            sched = self._schedules.get(sched_id)
        if sched is None:
            sched = get_schedule(sched_id)
            if sched is None:
                return None
            sched["modules"] = json.loads(sched["modules"]) if isinstance(sched.get("modules"), str) else sched.get("modules", [])

        self._execute_scan(sched_id)
        # Update the regular timer to fire from now
        self._schedule_timer(sched_id)
        return sched

    def list_all(self) -> list[dict]:
        """Return all schedules (from memory, falling back to DB)."""
        with self._lock:
            items = list(self._schedules.values())
        # Ensure we have everything from DB too
        db_items = list_schedules()
        db_ids = {s["id"] for s in items}
        for db_s in db_items:
            if db_s["id"] not in db_ids:
                # Parse modules if stored as JSON string
                if isinstance(db_s.get("modules"), str):
                    db_s["modules"] = json.loads(db_s["modules"])
                # Convert crawl from int to bool if needed
                db_s["crawl"] = bool(db_s.get("crawl", False))
                items.append(db_s)
        return items

    def update_interval(self, sched_id: str, interval_hours: int) -> dict | None:
        """Change the interval and reschedule the timer."""
        with self._lock:
            sched = self._schedules.get(sched_id)
        if sched is None:
            return None
        sched["interval_hours"] = interval_hours
        now = datetime.now()
        sched["next_run"] = (now + timedelta(hours=interval_hours)).strftime("%Y-%m-%d %H:%M:%S")
        save_schedule(sched)
        self._stop_timer(sched_id)
        self._schedule_timer(sched_id)
        return sched

    def load_all(self):
        """Load active/paused schedules from DB on startup and schedule timers."""
        items = list_schedules()
        for item in items:
            # Parse modules (may be JSON string or list)
            modules = item.get("modules", [])
            if isinstance(modules, str):
                modules = json.loads(modules)
            item["modules"] = modules
            # Normalize bool
            item["crawl"] = bool(item.get("crawl", False))
            # Restore internal fields if present
            config = json.loads(item.get("config", "{}")) if isinstance(item.get("config"), str) else {}
            item.setdefault("_delay", config.get("delay", 0))
            item.setdefault("_proxy", item.get("proxy", ""))
            item.setdefault("_cookie", config.get("cookie", ""))
            with self._lock:
                self._schedules[item["id"]] = item
            # Re-schedule active timers
            if item.get("status") == "active":
                self._schedule_timer(item["id"])
                logger.info("Re-scheduled %s for %s (every %dh)",
                            item["id"], item["target"], item["interval_hours"])

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _schedule_timer(self, sched_id: str):
        """Set a threading.Timer for the next run."""
        with self._lock:
            sched = self._schedules.get(sched_id)
        if sched is None or sched.get("status") != "active":
            return
        self._stop_timer(sched_id)
        interval_seconds = sched["interval_hours"] * 3600
        # If next_run is set and in the future, use that delta; otherwise use full interval
        if sched.get("next_run"):
            try:
                next_dt = datetime.strptime(sched["next_run"], "%Y-%m-%d %H:%M:%S")
                delta = max(0, (next_dt - datetime.now()).total_seconds())
                interval_seconds = delta if delta > 0 else sched["interval_hours"] * 3600
            except (ValueError, TypeError):
                interval_seconds = sched["interval_hours"] * 3600

        t = threading.Timer(interval_seconds, self._execute_scan, args=(sched_id,))
        t.daemon = True
        t.start()
        with self._lock:
            self._timers[sched_id] = t

    def _stop_timer(self, sched_id: str):
        """Cancel and remove a running timer."""
        with self._lock:
            t = self._timers.pop(sched_id, None)
        if t is not None:
            t.cancel()

    def _execute_scan(self, sched_id: str):
        """Run a scheduled scan in a daemon thread."""
        with self._lock:
            sched = self._schedules.get(sched_id)
        if sched is None:
            return

        scan_id = f"{sched_id}-{str(uuid.uuid4())[:6]}"
        target = sched["target"]
        modules = sched.get("modules", [])
        timeout = sched.get("timeout", 10)
        threads_num = sched.get("threads", 10)
        user_agent = sched.get("user_agent", "WebScanner/0.1.0")
        delay = sched.get("_delay", 0)
        proxy = sched.get("_proxy", "")
        cookie = sched.get("_cookie", "")
        do_crawl = sched.get("crawl", False)

        # Record start
        started_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        logger.info("Scheduled scan %s for %s started at %s",
                    scan_id, target, started_at)

        # Update schedule metadata
        update_schedule_field(sched_id, "last_run", started_at)
        new_count = sched.get("run_count", 0) + 1
        update_schedule_field(sched_id, "run_count", new_count)
        with self._lock:
            sched["last_run"] = started_at
            sched["run_count"] = new_count

        # Next run time
        interval = sched.get("interval_hours", 24)
        next_run = (datetime.now() + timedelta(hours=interval)).strftime("%Y-%m-%d %H:%M:%S")
        update_schedule_field(sched_id, "next_run", next_run)
        with self._lock:
            sched["next_run"] = next_run

        # Run the scan in a thread
        t = threading.Thread(
            target=self._scan_with_notifications,
            args=(scan_id, sched_id, target, modules, timeout, threads_num,
                  user_agent, delay, proxy, cookie, do_crawl),
            daemon=True,
        )
        t.start()

        # Re-schedule the next timer
        self._schedule_timer(sched_id)

    def _scan_with_notifications(self, scan_id, sched_id, target, modules,
                                  timeout, threads, user_agent, delay, proxy,
                                  cookie, do_crawl):
        """Wrap the scan execution to send webhook notifications."""
        # Call the actual scan function
        self._run_scan(scan_id, target, modules, timeout, threads,
                       user_agent, delay, proxy, cookie, do_crawl)

        # After scan completes, send webhooks
        webhooks = load_webhooks()
        if webhooks and sched_id:
            # Try to get findings from the scan result
            try:
                result = get_scan(scan_id)
                if result and result.get("findings"):
                    findings = result["findings"]
                    criticals = [f for f in findings if f.get("severity") == "CRITICAL"]
                    highs = [f for f in findings if f.get("severity") == "HIGH"]
                    payload = {
                        "event": "scheduled_scan_completed",
                        "schedule_id": sched_id,
                        "scan_id": scan_id,
                        "target": target,
                        "total_findings": len(findings),
                        "critical": len(criticals),
                        "high": len(highs),
                        "critical_findings": criticals[:5],
                    }
                    for url in webhooks:
                        send_webhook(url, payload)
            except Exception as e:
                logger.warning("Scheduled scan webhook notification failed: %s", e)
