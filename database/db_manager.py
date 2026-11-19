import sqlite3, json
from datetime import datetime, timezone
from config import DB_PATH

def connect():
    return sqlite3.connect(DB_PATH)

def initialize():
    with connect() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scanned_at TEXT NOT NULL,
            target TEXT NOT NULL,
            ports_scanned INTEGER NOT NULL,
            open_ports INTEGER NOT NULL,
            cve_count INTEGER NOT NULL,
            results_json TEXT NOT NULL
        )""")

def save_scan(target, ports_scanned, services, cves):
    payload = {"services": services, "cves": cves}
    with connect() as db:
        cur = db.execute(
            "INSERT INTO scans(scanned_at,target,ports_scanned,open_ports,cve_count,results_json) VALUES(?,?,?,?,?,?)",
            (datetime.now(timezone.utc).isoformat(), target, ports_scanned,
             len(services), len(cves), json.dumps(payload))
        )
        return cur.lastrowid

def history(limit=100):
    with connect() as db:
        return db.execute(
            "SELECT id, scanned_at, target, ports_scanned, open_ports, cve_count FROM scans ORDER BY id DESC LIMIT ?",
            (limit,)
        ).fetchall()
