"""
db.py — SQLite storage layer for GPON-Guard.

Three tables:
  telemetry     -> raw ONU signal/temp/voltage readings (time-series)
  alerts        -> security/fault events raised by the detection engine
  auth_attempts -> simulated OLT web-console login attempts (for brute-force detection)
"""

import sqlite3
import threading
import time

DB_PATH = "gpon_guard.db"
_lock = threading.Lock()


def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS telemetry (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL NOT NULL,
            onu_id TEXT NOT NULL,
            serial TEXT NOT NULL,
            rx_power REAL NOT NULL,
            tx_power REAL NOT NULL,
            temperature REAL NOT NULL,
            voltage REAL NOT NULL,
            traffic_mbps REAL NOT NULL
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL NOT NULL,
            onu_id TEXT,
            category TEXT NOT NULL,       -- 'security' or 'fault'
            event_type TEXT NOT NULL,     -- e.g. ROGUE_ONU, SIGNAL_TAMPER, BRUTE_FORCE
            severity TEXT NOT NULL,       -- low / medium / high / critical
            description TEXT NOT NULL,
            resolved INTEGER DEFAULT 0
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS auth_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL NOT NULL,
            source_ip TEXT NOT NULL,
            username TEXT NOT NULL,
            success INTEGER NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def insert_telemetry(row):
    with _lock:
        conn = get_conn()
        conn.execute(
            """INSERT INTO telemetry (ts, onu_id, serial, rx_power, tx_power,
               temperature, voltage, traffic_mbps) VALUES (?,?,?,?,?,?,?,?)""",
            (row["ts"], row["onu_id"], row["serial"], row["rx_power"],
             row["tx_power"], row["temperature"], row["voltage"], row["traffic_mbps"])
        )
        conn.commit()
        conn.close()


def insert_alert(onu_id, category, event_type, severity, description):
    with _lock:
        conn = get_conn()
        conn.execute(
            """INSERT INTO alerts (ts, onu_id, category, event_type, severity, description)
               VALUES (?,?,?,?,?,?)""",
            (time.time(), onu_id, category, event_type, severity, description)
        )
        conn.commit()
        conn.close()


def insert_auth_attempt(source_ip, username, success):
    with _lock:
        conn = get_conn()
        conn.execute(
            "INSERT INTO auth_attempts (ts, source_ip, username, success) VALUES (?,?,?,?)",
            (time.time(), source_ip, username, int(success))
        )
        conn.commit()
        conn.close()


def get_recent_telemetry(onu_id, limit=30):
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM telemetry WHERE onu_id=? ORDER BY ts DESC LIMIT ?",
        (onu_id, limit)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows][::-1]


def get_latest_telemetry_all():
    conn = get_conn()
    rows = conn.execute("""
        SELECT t.* FROM telemetry t
        INNER JOIN (
            SELECT onu_id, MAX(ts) AS max_ts FROM telemetry GROUP BY onu_id
        ) latest ON t.onu_id = latest.onu_id AND t.ts = latest.max_ts
        ORDER BY t.onu_id
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_recent_alerts(limit=50):
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM alerts ORDER BY ts DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_recent_auth_attempts(source_ip, window_seconds=60):
    conn = get_conn()
    since = time.time() - window_seconds
    rows = conn.execute(
        "SELECT * FROM auth_attempts WHERE source_ip=? AND ts>=? ORDER BY ts",
        (source_ip, since)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def counts_summary():
    conn = get_conn()
    total_onus = conn.execute("SELECT COUNT(DISTINCT onu_id) c FROM telemetry").fetchone()["c"]
    total_alerts = conn.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"]
    critical = conn.execute("SELECT COUNT(*) c FROM alerts WHERE severity='critical'").fetchone()["c"]
    conn.close()
    return {"total_onus": total_onus, "total_alerts": total_alerts, "critical": critical}
