"""
Database module for storing vulnerability scan records, port intelligence,
risk predictions, and Explainable AI (XAI) feature attributions.
Uses SQLite for zero-configuration, lightweight, and Android-friendly execution.
"""

import sqlite3
import os
import json
from datetime import datetime

DB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "database")
DB_PATH = os.path.join(DB_DIR, "vulnerability.db")

def get_db_connection():
    """Returns a SQLite connection with row dictionary factory."""
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes the database schema if not already present."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Scans table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        scan_type TEXT NOT NULL,
        risk_score REAL NOT NULL,
        risk_tier TEXT NOT NULL,
        total_ports INTEGER NOT NULL,
        open_ports INTEGER NOT NULL,
        vulnerable_ports INTEGER NOT NULL,
        critical_risks INTEGER NOT NULL,
        status TEXT NOT NULL
    )
    """)

    # Port Results table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS port_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL,
        port INTEGER NOT NULL,
        protocol TEXT NOT NULL,
        service TEXT NOT NULL,
        version TEXT,
        state TEXT NOT NULL,
        risk_level TEXT NOT NULL,
        confidence REAL NOT NULL,
        cvss_score REAL,
        encryption_detected INTEGER,
        exposure_level TEXT,
        banner TEXT,
        recommendations TEXT,
        timestamp TEXT NOT NULL,
        FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
    )
    """)

    # Explanations table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS explanations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        port_result_id INTEGER NOT NULL,
        feature TEXT NOT NULL,
        importance_pct REAL NOT NULL,
        contribution_type TEXT NOT NULL,
        explanation_text TEXT NOT NULL,
        FOREIGN KEY (port_result_id) REFERENCES port_results (id) ON DELETE CASCADE
    )
    """)

    conn.commit()
    conn.close()
    print(f"[+] SQLite database successfully initialized at '{DB_PATH}'.")

def save_scan_record(scan_data):
    """
    Saves a complete scan session including target meta, ports, and XAI explanations.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Insert scan
        cursor.execute("""
        INSERT INTO scans (
            target, timestamp, scan_type, risk_score, risk_tier,
            total_ports, open_ports, vulnerable_ports, critical_risks, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_data["target"],
            scan_data.get("timestamp", datetime.now().isoformat()),
            scan_data.get("scan_type", "demo"),
            scan_data["risk_score"],
            scan_data["risk_tier"],
            scan_data["total_ports"],
            scan_data["open_ports"],
            scan_data["vulnerable_ports"],
            scan_data["critical_risks"],
            scan_data.get("status", "Completed")
        ))
        scan_id = cursor.lastrowid

        # Insert port results and their XAI explanations
        for port in scan_data.get("ports", []):
            recs_json = json.dumps(port.get("recommendations", []))
            cursor.execute("""
            INSERT INTO port_results (
                scan_id, port, protocol, service, version, state,
                risk_level, confidence, cvss_score, encryption_detected,
                exposure_level, banner, recommendations, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_id,
                port["port"],
                port["protocol"],
                port["service"],
                port.get("version", "Standard"),
                port.get("state", "Open"),
                port["risk_level"],
                port["confidence"],
                port.get("cvss_score", 0.0),
                1 if port.get("encryption_detected") else 0,
                port.get("exposure_level", "External"),
                port.get("banner", ""),
                recs_json,
                datetime.now().isoformat()
            ))
            port_result_id = cursor.lastrowid

            # Insert explanations
            xai_data = port.get("xai", {})
            for reason in xai_data.get("reasons", []):
                cursor.execute("""
                INSERT INTO explanations (
                    port_result_id, feature, importance_pct, contribution_type, explanation_text
                ) VALUES (?, ?, ?, ?, ?)
                """, (
                    port_result_id,
                    reason.get("feature", "General"),
                    reason.get("importance_pct", 0.0),
                    reason.get("type", "Risk Booster"),
                    reason.get("text", "")
                ))

        conn.commit()
        return scan_id
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()

def get_recent_scans(limit=10):
    """Retrieves list of recent scan summaries."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT id, target, timestamp, scan_type, risk_score, risk_tier,
           total_ports, open_ports, vulnerable_ports, critical_risks, status
    FROM scans
    ORDER BY id DESC
    LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    scans = [dict(row) for row in rows]
    conn.close()
    return scans

def get_scan_details(scan_id):
    """Retrieves full scan details, port items, and explanations."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    scan_row = cursor.fetchone()
    if not scan_row:
        conn.close()
        return None

    scan = dict(scan_row)

    # Get port results
    cursor.execute("SELECT * FROM port_results WHERE scan_id = ? ORDER BY port ASC", (scan_id,))
    port_rows = cursor.fetchall()

    ports = []
    for prow in port_rows:
        port_dict = dict(prow)
        try:
            port_dict["recommendations"] = json.loads(port_dict["recommendations"])
        except Exception:
            port_dict["recommendations"] = []

        # Get explanations
        cursor.execute("SELECT * FROM explanations WHERE port_result_id = ?", (port_dict["id"],))
        exp_rows = cursor.fetchall()
        port_dict["explanations"] = [dict(e) for e in exp_rows]
        ports.append(port_dict)

    scan["ports"] = ports
    conn.close()
    return scan

def get_port_analysis(scan_id, port_number):
    """Retrieves specific port analysis and XAI breakdown."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT * FROM port_results WHERE scan_id = ? AND port = ?
    """, (scan_id, port_number))
    prow = cursor.fetchone()
    if not prow:
        conn.close()
        return None

    port_dict = dict(prow)
    try:
        port_dict["recommendations"] = json.loads(port_dict["recommendations"])
    except Exception:
        port_dict["recommendations"] = []

    cursor.execute("SELECT * FROM explanations WHERE port_result_id = ?", (port_dict["id"],))
    exp_rows = cursor.fetchall()
    port_dict["explanations"] = [dict(e) for e in exp_rows]
    conn.close()
    return port_dict

def get_global_statistics():
    """Aggregates security metrics across all recorded scans."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) as total_scans, AVG(risk_score) as avg_risk FROM scans")
    summary = dict(cursor.fetchone() or {"total_scans": 0, "avg_risk": 0.0})

    cursor.execute("""
    SELECT risk_level, COUNT(*) as count 
    FROM port_results 
    GROUP BY risk_level
    """)
    risk_distribution = {row["risk_level"]: row["count"] for row in cursor.fetchall()}

    cursor.execute("""
    SELECT service, COUNT(*) as count 
    FROM port_results 
    WHERE risk_level IN ('High', 'Critical')
    GROUP BY service
    ORDER BY count DESC
    LIMIT 5
    """)
    top_vulnerable_services = [dict(row) for row in cursor.fetchall()]

    conn.close()
    return {
        "total_scans": summary.get("total_scans", 0),
        "avg_network_risk": round(summary.get("avg_risk", 0.0) or 0.0, 1),
        "risk_distribution": risk_distribution,
        "top_vulnerable_services": top_vulnerable_services
    }

if __name__ == "__main__":
    init_db()
