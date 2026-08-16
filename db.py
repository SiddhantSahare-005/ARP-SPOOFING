import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "arp_shield.db"


def get_connection():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_ip TEXT,
            source_mac TEXT,
            previous_mac TEXT,
            attack_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Open'
        )
        """
    )
    conn.commit()
    conn.close()


def add_alert(timestamp, source_ip, source_mac, previous_mac,
              attack_type, severity, description, status="Open"):
    conn = get_connection()
    conn.execute(
        """
        INSERT INTO alerts
        (timestamp, source_ip, source_mac, previous_mac,
         attack_type, severity, description, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (timestamp, source_ip, source_mac, previous_mac,
         attack_type, severity, description, status),
    )
    conn.commit()
    conn.close()


def get_alerts(page=1, per_page=50):
    page = max(1, int(page))
    per_page = max(1, min(100, int(per_page)))
    offset = (page - 1) * per_page

    conn = get_connection()
    rows = conn.execute(
        """
        SELECT * FROM alerts
        ORDER BY id DESC
        LIMIT ? OFFSET ?
        """,
        (per_page, offset),
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_alert_count():
    conn = get_connection()
    count = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    conn.close()
    return count


def get_statistics():
    conn = get_connection()
    row = conn.execute(
        """
        SELECT
            COUNT(*) AS total,
            COALESCE(SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END), 0) AS high,
            COALESCE(SUM(CASE WHEN severity = 'MEDIUM' THEN 1 ELSE 0 END), 0) AS medium,
            COALESCE(SUM(CASE WHEN severity = 'LOW' THEN 1 ELSE 0 END), 0) AS low
        FROM alerts
        """
    ).fetchone()
    conn.close()
    return dict(row)


def clear_alerts():
    conn = get_connection()
    conn.execute("DELETE FROM alerts")
    conn.commit()
    conn.close()


def update_alert_status(alert_id, status):
    if status not in {"Open", "Investigating", "Resolved"}:
        return False

    conn = get_connection()
    cursor = conn.execute(
        "UPDATE alerts SET status = ? WHERE id = ?",
        (status, alert_id),
    )
    conn.commit()
    updated = cursor.rowcount > 0
    conn.close()
    return updated
