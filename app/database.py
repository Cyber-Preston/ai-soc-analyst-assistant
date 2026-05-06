import sqlite3
from pathlib import Path
from typing import Any

DB_PATH = Path("soc_alerts.db")

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db() -> None:
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                risk_score INTEGER,

                source_ip TEXT,
                event_type TEXT NOT NULL,

                mitre_technique TEXT,
                mitre_name TEXT,
                mitre_tactic TEXT,

                threat_reputation TEXT,
                threat_confidence INTEGER,
                threat_country TEXT,

                raw_event TEXT UNIQUE,
                ai_summary TEXT NOT NULL,
                recommendation TEXT NOT NULL,

                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()

def save_alert(alert: dict[str, Any]) -> None:
    with get_connection() as conn:
        conn.execute("""
            INSERT OR IGNORE INTO alerts (
                title,
                severity,
                risk_score,
                source_ip,
                event_type,

                mitre_technique,
                mitre_name,
                mitre_tactic,

                threat_reputation,
                threat_confidence,
                threat_country,

                raw_event,
                ai_summary,
                recommendation
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            alert["title"],
            alert["severity"],
            alert.get("risk_score"),

            alert.get("source_ip"),
            alert["event_type"],

            alert.get("mitre_technique"),
            alert.get("mitre_name"),
            alert.get("mitre_tactic"),

            alert.get("threat_reputation"),
            alert.get("threat_confidence"),
            alert.get("threat_country"),

            alert["raw_event"],
            alert["ai_summary"],
            alert["recommendation"],
        ))
        conn.commit()

def get_alerts() -> list[dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM alerts ORDER BY created_at DESC"
        ).fetchall()

        return [dict(row) for row in rows]

def clear_alerts() -> None:
    with get_connection() as conn:
        conn.execute("DELETE FROM alerts")
        conn.commit()