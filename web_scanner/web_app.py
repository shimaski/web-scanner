"""Web UI for the vulnerability scanner."""

import json
import logging
import threading
import uuid
from datetime import datetime
from pathlib import Path

from concurrent.futures import ThreadPoolExecutor, as_completed

from flask import Flask, Response, send_file, jsonify, render_template, request

from web_scanner.config import ScanConfig
from web_scanner.crawler import Crawler
from web_scanner.database import compare_scans, delete_scan, get_scan, init_db, list_scans as db_list_scans, save_scan
from web_scanner.scheduler_service import SchedulerService
from web_scanner.http_client import HTTPClient
from web_scanner.modules import ALL_MODULES, MODULE_LABELS, SCANNER_MAP, TEMPLATES
from web_scanner.pdf_report import generate_pdf
from web_scanner.report import export_html, export_json, export_html_string
from web_scanner.attack_descriptions import enrich_findings, describe_vulnerability
from web_scanner.notifications import load_webhooks, notify_scan_completed, notify_scan_started, save_webhooks
from web_scanner.utils import count_by_severity, sort_findings

logging.basicConfig(level=logging.WARNING, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

app = Flask(__name__)

# In-memory scan progress store
scan_progress: dict[str, dict] = {}
results_lock = threading.Lock()

scheduler = None  # Set up in app_main


def _get_run_scan_wrapper():
    """Return a closure that matches the SchedulerService.run_scan 10-arg signature."""
    return lambda scan_id, target, modules, timeout, threads, ua, delay, proxy, cookie, do_crawl: \
        run_scan(scan_id, target, modules, timeout, threads, ua, delay, proxy, cookie, do_crawl, {})


def run_scan(scan_id: str, target: str, modules: list[str], timeout: int,
             threads: int, ua: str, delay: float, proxy: str, cookie: str,
             do_crawl: bool, auth_config: dict = None):
    if auth_config is None:
        auth_config = {}
    config = ScanConfig.from_dict(
        target=target, timeout=timeout, max_threads=threads,
        user_agent=ua, verify_ssl=False, delay=delay,
        proxy=proxy, cookie=cookie,
        basic_user=auth_config.get("basic_user", ""),
        basic_pass=auth_config.get("basic_pass", ""),
        bearer_token=auth_config.get("bearer_token", ""),
        login_url=auth_config.get("login_url", ""),
        login_username_field=auth_config.get("login_user_field", "username"),
        login_password_field=auth_config.get("login_pass_field", "password"),
        login_username=auth_config.get("login_username", ""),
        login_password=auth_config.get("login_password", ""),
        auto_relogin=auth_config.get("auto_relogin", False),
    )
    client = HTTPClient(config)
    all_findings = []

    # Crawl before scanning
    if do_crawl:
        with results_lock:
            if scan_id in scan_progress:
                scan_progress[scan_id]["current_module"] = "Crawling..."
        crawler = Crawler(client, config)
        urls, forms = crawler.crawl()
        all_findings.append(crawler.finding())
        config.crawled_urls = urls
        config.crawled_forms = forms

    # Run modules in parallel
    def run_module(module_name: str) -> list[dict]:
        scanner_cls = SCANNER_MAP.get(module_name)
        if scanner_cls is None:
            return []
        scanner = scanner_cls(client, config)
        with results_lock:
            if scan_id not in scan_progress:
                return []
            scan_progress[scan_id]["current_module"] = module_name
            scan_progress[scan_id]["status"] = "running"
        try:
            return scanner.run()
        except Exception as e:
            return [{
                "severity": "HIGH",
                "title": f"Module error: {module_name}",
                "detail": str(e),
            }]

    if len(modules) == 1:
        all_findings += run_module(modules[0])
    else:
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {pool.submit(run_module, m): m for m in modules}
            for future in as_completed(futures):
                with results_lock:
                    if scan_id not in scan_progress:
                        return
                all_findings.extend(future.result())

    all_findings = enrich_findings(all_findings)
    all_findings = sort_findings(all_findings)
    by_severity = count_by_severity(all_findings)

    completed_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Save to DB
    save_scan(scan_id, target, modules, "completed", all_findings, by_severity, {
        "timeout": timeout, "threads": threads, "ua": ua,
        "delay": delay, "proxy": proxy, "cookie": bool(cookie),
        "crawl": do_crawl,
        "auth": bool(auth_config.get("basic_user") or auth_config.get("bearer_token") or auth_config.get("login_username")),
    })

    with results_lock:
        if scan_id in scan_progress:
            scan_progress[scan_id].update({
                "status": "completed",
                "current_module": "",
                "completed_at": completed_at,
            })

@app.route("/")
def index():
    return render_template("index.html", modules=SCANNER_MAP.keys(), templates=TEMPLATES)


@app.route("/api/scan", methods=["POST"])
def start_scan():
    data = request.get_json()
    target = data.get("target", "").strip()
    if not target:
        return jsonify({"error": "Target is required"}), 400

    modules = data.get("modules", [])
    template = data.get("template", "")
    if template and template in TEMPLATES:
        modules = TEMPLATES[template]
    if not modules:
        return jsonify({"error": "At least one module is required"}), 400

    timeout = data.get("timeout", 10)
    threads = data.get("threads", 10)
    ua = data.get("user_agent", "WebScanner/0.1.0")
    delay = data.get("delay", 0)
    proxy = data.get("proxy", "")
    cookie = data.get("cookie", "")
    do_crawl = data.get("crawl", False)

    auth_config = {
        "basic_user": data.get("basic_user", ""),
        "basic_pass": data.get("basic_pass", ""),
        "bearer_token": data.get("bearer_token", ""),
        "login_url": data.get("login_url", ""),
        "login_user_field": data.get("login_user_field", "username"),
        "login_pass_field": data.get("login_pass_field", "password"),
        "login_username": data.get("login_username", ""),
        "login_password": data.get("login_password", ""),
        "auto_relogin": data.get("auto_relogin", False),
    }

    scan_id = str(uuid.uuid4())[:8]
    started_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Save initial entry in DB
    save_scan(scan_id, target, modules, "starting", [], {})

    with results_lock:
        scan_progress[scan_id] = {
            "scan_id": scan_id,
            "target": target,
            "modules": modules,
            "status": "starting",
            "current_module": "",
            "findings": [],
            "total_findings": 0,
            "by_severity": {},
            "started_at": started_at,
            "completed_at": "",
        }

    t = threading.Thread(target=run_scan, args=(
        scan_id, target, modules, timeout, threads, ua, delay, proxy, cookie, do_crawl, auth_config
    ), daemon=True)
    t.start()

    return jsonify({"scan_id": scan_id, "message": "Scan started"})


@app.route("/api/scan/<scan_id>")
def scan_status(scan_id):
    # Check memory first (in-progress scan)
    with results_lock:
        progress = scan_progress.get(scan_id)
    if progress and progress.get("status") in ("starting", "running"):
        return jsonify(progress)

    # Fall back to DB
    result = get_scan(scan_id)
    if result is None:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify(result)


@app.route("/api/scans")
def list_scans():
    # Merge in-memory progress with DB data
    scans = db_list_scans()
    with results_lock:
        for sid, prog in scan_progress.items():
            if prog.get("status") in ("starting", "running"):
                # Update or insert
                for s in scans:
                    if s["id"] == sid:
                        s.update({
                            "status": prog["status"],
                            "current_module": prog.get("current_module", ""),
                        })
                        break
                else:
                    scans.append({
                        "id": sid,
                        "target": prog["target"],
                        "modules": prog["modules"],
                        "status": prog["status"],
                        "total_findings": 0,
                        "started_at": prog["started_at"],
                        "completed_at": "",
                    })
    # Rename 'id' to 'scan_id' for frontend compat
    for s in scans:
        s["scan_id"] = s.pop("id", s.get("scan_id", ""))
    return jsonify({"scans": scans})


@app.route("/api/export/<scan_id>", methods=["POST"])
def export_scan(scan_id):
    result = get_scan(scan_id)
    if result is None:
        return jsonify({"error": "Scan not found"}), 404

    data = request.get_json()
    fmt = data.get("format", "html")
    filename = f"scan_{scan_id}.{fmt}"

    if fmt == "json":
        export_json(result["findings"], result["target"], filename)
    elif fmt == "html":
        export_html(result["findings"], result["target"], filename)
    elif fmt == "pdf":
        filename = f"scan_{scan_id}.pdf"
        generate_pdf(result["findings"], result["target"], filename)

    return jsonify({"filename": filename, "path": str(Path(filename).absolute())})


@app.route("/api/view/<scan_id>/<fmt>")
def view_report(scan_id, fmt):
    """Serve a generated report inline for viewing."""
    result = get_scan(scan_id)
    if result is None:
        return jsonify({"error": "Scan not found"}), 404
    if fmt == "html":
        html = export_html_string(result["findings"], result["target"])
        return Response(html, mimetype="text/html")
    if fmt == "pdf":
        pdf_dir = Path(__file__).parent.parent / "tmp"
        pdf_dir.mkdir(exist_ok=True)
        pdf_path = pdf_dir / f"scan_{scan_id}.pdf"
        generate_pdf(result["findings"], result["target"], str(pdf_path))
        return send_file(str(pdf_path), mimetype="application/pdf", as_attachment=False)
    return jsonify({"error": "Unsupported format"}), 400


@app.route("/api/delete/<scan_id>", methods=["DELETE"])
def delete_scan_api(scan_id):
    delete_scan(scan_id)
    with results_lock:
        scan_progress.pop(scan_id, None)
    return jsonify({"message": "Deleted"})


@app.route("/api/compare/<scan_a>/<scan_b>")
def compare_api(scan_a, scan_b):
    result = compare_scans(scan_a, scan_b)
    if "error" in result:
        return jsonify(result), 404
    return jsonify(result)


@app.route("/api/schedule", methods=["POST"])
def create_schedule():
    global scheduler
    data = request.get_json()
    target = data.get("target", "")
    interval_hours = data.get("interval_hours", 24)
    modules = data.get("modules", [])
    if not target or not modules:
        return jsonify({"error": "Target and modules required"}), 400

    sched = scheduler.create(
        target=target,
        interval_hours=interval_hours,
        modules=modules,
        timeout=data.get("timeout", 10),
        threads=data.get("threads", 10),
        user_agent=data.get("user_agent", "WebScanner/0.1.0"),
        do_crawl=data.get("crawl", False),
        proxy=data.get("proxy", ""),
        cookie=data.get("cookie", ""),
        delay=data.get("delay", 0),
    )
    return jsonify({"schedule_id": sched["id"], "message": "Schedule created"}), 201


@app.route("/api/schedules")
def list_schedules_api():
    global scheduler
    items = scheduler.list_all()
    return jsonify({"schedules": items})


@app.route("/api/schedule/<sched_id>", methods=["DELETE"])
def delete_schedule_api(sched_id):
    global scheduler
    scheduler.delete(sched_id)
    return jsonify({"message": "Schedule deleted"})


@app.route("/api/schedule/<sched_id>/pause", methods=["POST"])
def pause_schedule(sched_id):
    global scheduler
    result = scheduler.pause(sched_id)
    if result is None:
        return jsonify({"error": "Schedule not found"}), 404
    return jsonify({"message": "Schedule paused", "schedule": result})


@app.route("/api/schedule/<sched_id>/resume", methods=["POST"])
def resume_schedule(sched_id):
    global scheduler
    result = scheduler.resume(sched_id)
    if result is None:
        return jsonify({"error": "Schedule not found"}), 404
    return jsonify({"message": "Schedule resumed", "schedule": result})


@app.route("/api/schedule/<sched_id>/run-now", methods=["POST"])
def run_schedule_now(sched_id):
    global scheduler
    result = scheduler.run_now(sched_id)
    if result is None:
        return jsonify({"error": "Schedule not found"}), 404
    return jsonify({"message": "Scheduled scan triggered", "schedule": result})


@app.route("/api/schedule/<sched_id>/interval", methods=["PUT"])
def update_schedule_interval(sched_id):
    global scheduler
    data = request.get_json()
    interval_hours = data.get("interval_hours")
    if interval_hours is None:
        return jsonify({"error": "interval_hours required"}), 400
    result = scheduler.update_interval(sched_id, int(interval_hours))
    if result is None:
        return jsonify({"error": "Schedule not found"}), 404
    return jsonify({"message": "Interval updated", "schedule": result})


# --- Webhooks ---

@app.route("/api/webhooks", methods=["GET"])
def list_webhooks():
    return jsonify({"webhooks": load_webhooks()})


@app.route("/api/webhooks", methods=["POST"])
def add_webhook():
    data = request.get_json()
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "URL required"}), 400
    urls = load_webhooks()
    if url not in urls:
        urls.append(url)
        save_webhooks(urls)
    return jsonify({"message": "Webhook added", "webhooks": urls})


@app.route("/api/webhooks", methods=["DELETE"])
def remove_webhook():
    data = request.get_json()
    url = data.get("url", "")
    urls = [u for u in load_webhooks() if u != url]
    save_webhooks(urls)
    return jsonify({"message": "Webhook removed", "webhooks": urls})


# --- Stats ---

@app.route("/api/stats")
def stats():
    scans = db_list_scans()
    total = len(scans)
    completed = sum(1 for s in scans if s["status"] == "completed")
    total_findings = sum(s.get("total_findings", 0) for s in scans)
    targets = set(s["target"] for s in scans)
    by_sev = {}
    for s in scans:
        sev = json.loads(s.get("by_severity", "{}"))
        for k, v in sev.items():
            by_sev[k] = by_sev.get(k, 0) + v
    return jsonify({
        "total_scans": total,
        "completed_scans": completed,
        "total_findings": total_findings,
        "unique_targets": len(targets),
        "by_severity": by_sev,
    })


# --- Import Targets (batch scan) ---

@app.route("/api/import", methods=["POST"])
def import_targets():
    data = request.get_json()
    targets_raw = data.get("targets", "")
    modules = data.get("modules", ["info"])
    if not targets_raw:
        return jsonify({"error": "No targets provided"}), 400

    targets = [t.strip() for t in targets_raw.splitlines() if t.strip()]
    scan_ids = []
    for target in targets:
        scan_id = str(uuid.uuid4())[:8]
        started_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        save_scan(scan_id, target, modules, "starting", [], {})
        with results_lock:
            scan_progress[scan_id] = {
                "scan_id": scan_id, "target": target, "modules": modules,
                "status": "starting", "current_module": "", "findings": [],
                "total_findings": 0, "by_severity": {},
                "started_at": started_at, "completed_at": "",
            }
        t = threading.Thread(target=run_scan, args=(
            scan_id, target, modules, 10, 10, "WebScanner/0.1.0", 0, "", "", False, {}
        ), daemon=True)
        t.start()
        scan_ids.append(scan_id)

    return jsonify({"message": f"Queued {len(scan_ids)} scans", "scan_ids": scan_ids})


def app_main():
    global scheduler
    print("\n[*] Starting Web Scanner UI on http://localhost:5000")
    print("[*] Open your browser and navigate to http://localhost:5000\n")
    print("[*] Database: scans.db\n")

    # Initialize scheduler and load saved schedules
    scheduler = SchedulerService(_get_run_scan_wrapper())
    scheduler.load_all()
    active = sum(1 for s in scheduler.list_all() if s.get("status") == "active")
    total = len(scheduler.list_all())
    print(f"[*] Scheduler loaded: {total} schedule(s), {active} active\n")

    app.run(host="0.0.0.0", port=5000, debug=False)
