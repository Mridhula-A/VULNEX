
# ==========================================================
# VULNEX - SECURITY INTELLIGENCE CENTER
# STAGE 5.1 - BACKEND & SCANNER AUDIT
# ==========================================================

import json
import sqlite3
import threading
import uuid

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

from flask import Flask, render_template, jsonify, request, send_file

from config import DB_PATH, load_config
from database.db_manager import initialize, save_scan, history

from utils.validators import validate_target, parse_ports

from scanner.socket_scanner import scan_ports
from scanner.nmap_scanner import (
    scan_with_nmap,
    discover_hosts,
    nmap_available
)
from scanner.scapy_scanner import syn_scan
from scanner.service_detector import enrich_service

from vulnerability.cve_matcher import lookup_for_services
from vulnerability.risk_analyzer import (
    assess_services,
    summarize,
    summarize_risks
)

from reports.report_generator import (
    export_pdf,
    export_csv,
    export_json
)


# ==========================================================
# APPLICATION SETUP
# ==========================================================

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

initialize()


# ==========================================================
# BACKGROUND SCAN MANAGEMENT
# ==========================================================

scan_jobs = {}
scan_lock = threading.Lock()
active_job_id = None


def update_job(job_id, **values):
    """Safely update scan job information."""

    with scan_lock:
        if job_id in scan_jobs:
            scan_jobs[job_id].update(values)


def progress_callback(job_id, current, total, message):
    """Keep CVE lookup progress within the CVE analysis stage."""

    percentage = int((current / total) * 100) if total > 0 else 0

    stage_progress = min(
        89,
        72 + int(percentage * 0.18)
    )

    update_job(
        job_id,
        progress=stage_progress,
        message=message
    )


# ==========================================================
# DATABASE CONNECTION
# ==========================================================

@contextmanager
def get_database_connection():
    """Create and always close a SQLite connection."""

    connection = sqlite3.connect(
        DB_PATH,
        timeout=30
    )

    connection.row_factory = sqlite3.Row

    try:
        yield connection

    finally:
        connection.close()


# ==========================================================
# DATABASE HELPERS
# ==========================================================

def normalize_scan_record(row):
    """Convert a database row into a safe dictionary."""

    if not row:
        return None

    record = dict(row)

    raw_results = record.pop("results_json", None)

    try:
        results = json.loads(raw_results) if raw_results else {}

    except (ValueError, TypeError):
        results = {}

    if not isinstance(results, dict):
        results = {}

    if not isinstance(results.get("services"), list):
        results["services"] = []

    if not isinstance(results.get("cves"), list):
        results["cves"] = []

    record["results"] = results

    return record


def get_scan_record(scan_id):
    """Retrieve one complete scan record."""

    with get_database_connection() as db:

        row = db.execute(
            """
            SELECT *
            FROM scans
            WHERE id = ?
            """,
            (scan_id,)
        ).fetchone()

    return normalize_scan_record(row)


def get_all_scan_records():
    """Retrieve all scan records for accurate dashboard statistics."""

    with get_database_connection() as db:

        rows = db.execute(
            """
            SELECT *
            FROM scans
            ORDER BY id DESC
            """
        ).fetchall()

    return [
        normalize_scan_record(row)
        for row in rows
    ]


def get_history_records(limit=100):
    """Return scan history as JSON-friendly dictionaries."""

    records = history(limit=limit)

    return [
        {
            "id": row[0],
            "scanned_at": row[1],
            "target": row[2],
            "ports_scanned": row[3],
            "open_ports": row[4],
            "cve_count": row[5]
        }
        for row in records
    ]


# ==========================================================
# SCAN ONE HOST
# ==========================================================

def scan_single_host(
    host,
    ports,
    use_nmap,
    use_scapy,
    job_id
):
    """Execute available scanning methods for one host."""

    services = []
    warnings = []

    # SOCKET SCAN

    try:

        update_job(
            job_id,
            message=f"Running socket scan against {host}"
        )

        socket_results = scan_ports(
            host,
            ports,
            progress=lambda current, total, message:
                update_job(
                    job_id,
                    message=f"{host}: {message}"
                )
        )

        services.extend(socket_results)

    except Exception as error:

        warnings.append(
            f"Socket scan failed for {host}: {error}"
        )

    # NMAP SCAN

    if use_nmap:

        try:

            update_job(
                job_id,
                message=f"Running Nmap service detection against {host}"
            )

            if not nmap_available():

                raise RuntimeError(
                    "Nmap executable is not installed or not in PATH."
                )

            nmap_results = scan_with_nmap(
                host,
                ports
            )

            existing_ports = {
                int(item["port"]): index
                for index, item in enumerate(services)
                if item.get("port") is not None
            }

            for item in nmap_results:

                item.setdefault("host", host)

                port = int(item["port"])

                if port in existing_ports:

                    services[existing_ports[port]] = item

                else:

                    existing_ports[port] = len(services)
                    services.append(item)

        except Exception as error:

            warnings.append(
                f"Nmap scan failed for {host}: {error}"
            )

    # SCAPY SYN SCAN

    if use_scapy:

        try:

            update_job(
                job_id,
                message=f"Running Scapy SYN scan against {host}"
            )

            scapy_results = syn_scan(
                host,
                ports
            )

            existing_ports = {
                int(item["port"])
                for item in services
                if item.get("port") is not None
            }

            for item in scapy_results:

                item["host"] = host

                port = int(item["port"])

                if port not in existing_ports:

                    services.append(item)
                    existing_ports.add(port)

        except Exception as error:

            warnings.append(
                f"Scapy scan failed for {host}: {error}"
            )

    # SERVICE ENRICHMENT

    enriched = []

    for item in services:

        try:

            item.setdefault("host", host)

            enriched_item = enrich_service(item)

            if enriched_item:
                enriched.append(enriched_item)

        except Exception as error:

            warnings.append(
                f"Service enrichment failed on {host}: {error}"
            )

            enriched.append(item)

    return sorted(
        enriched,
        key=lambda item: int(item.get("port", 0) or 0)
    ), warnings


# ==========================================================
# BACKGROUND SCAN WORKER
# ==========================================================

def run_scan_job(
    job_id,
    target,
    target_type,
    ports,
    options
):

    global active_job_id

    all_services = []
    all_cves = []
    all_warnings = []

    try:

        # TARGET DISCOVERY

        if target_type == "network":

            update_job(
                job_id,
                progress=2,
                message="Discovering network hosts..."
            )

            if not options["use_nmap"]:

                raise RuntimeError(
                    "Nmap is required for CIDR network discovery."
                )

            if not nmap_available():

                raise RuntimeError(
                    "Install Nmap to perform network discovery."
                )

            discovered = discover_hosts(target)

            hosts = [
                item["host"]
                for item in discovered
                if item.get("state") == "up"
            ]

            if not hosts:

                raise RuntimeError(
                    "No active hosts were discovered in this network."
                )

        else:

            hosts = [target]

        update_job(
            job_id,
            progress=5,
            message=(
                f"Discovered {len(hosts)} host(s). "
                "Starting assessment."
            )
        )

        # SCAN EACH HOST

        for index, host in enumerate(hosts):

            host_services, warnings = scan_single_host(
                host=host,
                ports=ports,
                use_nmap=options["use_nmap"],
                use_scapy=options["use_scapy"],
                job_id=job_id
            )

            all_services.extend(host_services)
            all_warnings.extend(warnings)

            progress = 5 + int(
                ((index + 1) / len(hosts)) * 65
            )

            update_job(
                job_id,
                progress=progress,
                message=(
                    f"Scanned host {index + 1}/"
                    f"{len(hosts)}: {host}"
                )
            )

        # CVE INTELLIGENCE

        if options["use_cve"]:

            update_job(
                job_id,
                progress=72,
                message="Analyzing services with NVD CVE intelligence..."
            )

            settings = load_config()
            api_key = settings.get("nvd_api_key", "")

            try:

                all_cves = lookup_for_services(
                    all_services,
                    api_key=api_key,
                    progress=lambda current, total, message:
                        progress_callback(
                            job_id,
                            current,
                            total,
                            message
                        )
                )

                if not isinstance(all_cves, list):
                    all_cves = []

            except Exception as error:

                all_warnings.append(
                    f"NVD lookup encountered an error: {error}"
                )

                all_cves = []

        # RISK ANALYSIS

        update_job(
            job_id,
            progress=90,
            message="Analyzing security exposure and risk levels..."
        )

        risk_findings = assess_services(all_services)

        cve_summary = summarize(all_cves)
        risk_summary = summarize_risks(risk_findings)

        # SAVE RESULTS

        update_job(
            job_id,
            progress=95,
            message="Saving assessment results..."
        )

        scan_id = save_scan(
            target=target,
            ports_scanned=len(ports),
            services=all_services,
            cves=all_cves
        )

        # COMPLETED RESULT

        results = {
            "scan_id": scan_id,
            "target": target,
            "hosts_scanned": hosts,
            "ports_scanned": len(ports),
            "services": all_services,
            "cves": all_cves,
            "risk_findings": risk_findings,
            "severity_summary": cve_summary,
            "risk_summary": risk_summary,
            "warnings": all_warnings
        }

        update_job(
            job_id,
            status="completed",
            progress=100,
            message="Security assessment completed.",
            results=results,
            error=None
        )

    except Exception as error:

        app.logger.exception(
            "Background scan failed"
        )

        update_job(
            job_id,
            status="failed",
            message="Scan failed.",
            error=str(error)
        )

    finally:

        with scan_lock:

            if active_job_id == job_id:
                active_job_id = None


# ==========================================================
# HOME PAGE
# ==========================================================

@app.route("/")
def index():

    return render_template("index.html")


# ==========================================================
# BACKEND HEALTH CHECK
# ==========================================================

@app.route("/api/health")
def health_check():

    return jsonify({
        "status": "online",
        "application": "VULNEX",
        "backend": "Flask",
        "version": "2.2"
    })


# ==========================================================
# START SCAN
# ==========================================================

@app.route("/api/scan", methods=["POST"])
def start_scan():

    global active_job_id

    data = request.get_json(silent=True)

    if not isinstance(data, dict):

        return jsonify({
            "error": "A valid JSON request is required."
        }), 400

    if data.get("authorized") is not True:

        return jsonify({
            "error": (
                "Confirm that you are authorized "
                "to scan this target."
            )
        }), 400

    try:

        target, target_type = validate_target(
            str(data.get("target", ""))
        )

        ports = parse_ports(
            str(data.get("ports", ""))
        )

    except (ValueError, TypeError) as error:

        return jsonify({
            "error": str(error)
        }), 400

    options = {
        "use_nmap": data.get("use_nmap", True) is True,
        "use_scapy": data.get("use_scapy", False) is True,
        "use_cve": data.get("use_cve", True) is True
    }

    if target_type == "network" and not options["use_nmap"]:

        return jsonify({
            "error": (
                "Nmap must be enabled for "
                "CIDR network discovery."
            )
        }), 400

    with scan_lock:

        if active_job_id is not None:

            return jsonify({
                "error": (
                    "Another scan is already running. "
                    "Please wait."
                )
            }), 409

        job_id = str(uuid.uuid4())

        active_job_id = job_id

        scan_jobs[job_id] = {
            "job_id": job_id,
            "status": "running",
            "progress": 0,
            "message": "Scan initialized.",
            "results": None,
            "error": None
        }

    try:

        worker = threading.Thread(
            target=run_scan_job,
            args=(
                job_id,
                target,
                target_type,
                ports,
                options
            ),
            daemon=True
        )

        worker.start()

    except Exception as error:

        with scan_lock:

            active_job_id = None
            scan_jobs.pop(job_id, None)

        return jsonify({
            "error": f"Unable to start scan: {error}"
        }), 500

    return jsonify({
        "message": "Scan accepted.",
        "job_id": job_id,
        "status": "running"
    }), 202


# ==========================================================
# GET SCAN PROGRESS
# ==========================================================

@app.route("/api/scan/<job_id>", methods=["GET"])
def get_scan_status(job_id):

    with scan_lock:

        job = scan_jobs.get(job_id)

        if job is not None:
            job = dict(job)

    if job is None:

        return jsonify({
            "error": (
                "Scan job not found. It may have expired "
                "after a server restart."
            )
        }), 404

    return jsonify(job)


# ==========================================================
# DASHBOARD STATISTICS
# ==========================================================

@app.route("/api/dashboard")
def dashboard_data():

    records = get_all_scan_records()

    total_scans = len(records)
    total_open_ports = 0

    severity_summary = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Unknown": 0
    }

    for record in records:

        results = record.get("results", {})

        services = results.get("services", [])
        cves = results.get("cves", [])

        total_open_ports += int(
            record.get("open_ports") or len(services)
        )

        summary = summarize(cves)

        for severity, count in summary.items():

            if severity not in severity_summary:
                severity_summary[severity] = 0

            severity_summary[severity] += count

    # SEVEN-DAY ACTIVITY

    today = datetime.now(timezone.utc).date()

    activity_counts = {}

    for offset in range(6, -1, -1):

        date = today - timedelta(days=offset)

        activity_counts[date.isoformat()] = 0

    for record in records:

        try:

            scanned_at = record.get("scanned_at", "")

            scanned_date = datetime.fromisoformat(
                scanned_at.replace("Z", "+00:00")
            ).date().isoformat()

            if scanned_date in activity_counts:
                activity_counts[scanned_date] += 1

        except (ValueError, AttributeError, TypeError):
            continue

    activity = [
        {
            "date": date,
            "count": count
        }
        for date, count in activity_counts.items()
    ]

    # RECENT SCANS

    recent_scans = [
        {
            "id": record.get("id"),
            "scanned_at": record.get("scanned_at"),
            "target": record.get("target"),
            "ports_scanned": record.get("ports_scanned", 0),
            "open_ports": record.get("open_ports", 0),
            "cve_count": record.get("cve_count", 0)
        }
        for record in records[:5]
    ]

    return jsonify({
        "total_scans": total_scans,
        "open_ports": total_open_ports,
        "critical_risks": severity_summary["Critical"],
        "high_risks": severity_summary["High"],
        "severity_summary": severity_summary,
        "activity": activity,
        "recent_scans": recent_scans
    })


# ==========================================================
# SCAN HISTORY
# ==========================================================

@app.route("/api/history")
def scan_history():

    return jsonify({
        "scans": get_history_records(limit=100)
    })


# ==========================================================
# INDIVIDUAL SCAN DETAILS
# ==========================================================

@app.route("/api/history/<int:scan_id>")
def scan_details(scan_id):

    record = get_scan_record(scan_id)

    if not record:

        return jsonify({
            "error": "Scan record not found."
        }), 404

    return jsonify(record)


# ==========================================================
# REPORT PREVIEW
# ==========================================================

@app.route("/api/reports/preview/<int:scan_id>")
def report_preview(scan_id):

    record = get_scan_record(scan_id)

    if not record:

        return jsonify({
            "error": "Scan record not found."
        }), 404

    results = record["results"]

    services = results.get("services", [])
    cves = results.get("cves", [])

    risk_findings = assess_services(services)

    return jsonify({
        "scan_id": scan_id,
        "target": record.get("target"),
        "scanned_at": record.get("scanned_at"),
        "ports_scanned": record.get("ports_scanned", 0),
        "open_ports": len(services),
        "cve_count": len(cves),
        "severity_summary": summarize(cves),
        "risk_summary": summarize_risks(risk_findings),
        "services": services,
        "cves": cves
    })


# ==========================================================
# REPORT EXPORT
# ==========================================================

@app.route("/api/reports/<report_format>/<int:scan_id>")
def download_report(report_format, scan_id):

    exporters = {
        "pdf": export_pdf,
        "csv": export_csv,
        "json": export_json
    }

    exporter = exporters.get(report_format.lower())

    if exporter is None:

        return jsonify({
            "error": "Unsupported report format."
        }), 400

    record = get_scan_record(scan_id)

    if not record:

        return jsonify({
            "error": "Scan record not found."
        }), 404

    results = record["results"]

    try:

        path = exporter(
            record.get("target"),
            results.get("services", []),
            results.get("cves", [])
        )

        return send_file(
            path,
            as_attachment=True,
            download_name=path.name
        )

    except Exception as error:

        app.logger.exception(
            "Report export failed"
        )

        return jsonify({
            "error": f"Report generation failed: {error}"
        }), 500


# ==========================================================
# APPLICATION START
# ==========================================================

if __name__ == "__main__":

    print("=" * 60)
    print("          VULNEX - SECURITY INTELLIGENCE CENTER")
    print("=" * 60)
    print("Backend Status : ONLINE")
    print("Scan Engine    : READY")
    print("Database       : SQLITE")
    print("Report Preview : ENABLED")
    print("Audit Stage    : 5.1")
    print("Dashboard URL  : http://127.0.0.1:5000")
    print("=" * 60)

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
        use_reloader=False
    )
