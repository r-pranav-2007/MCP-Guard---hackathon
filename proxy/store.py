"""All SQLite read/write functions for MCP Guard.

Plain sqlite3, no ORM. Tables map directly to the JSON contracts in
PROJECT_BRIEF.md section 7:
  - fingerprints   -> 7.2 Fingerprint Record
  - diff_reports   -> 7.3 Diff Report
  - scan_results   -> 7.4 Scan Result
  - alerts         -> 7.5 Alert
"""

import json
import os
import sqlite3
from contextlib import contextmanager

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "guard.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS fingerprints (
    tool_id           TEXT PRIMARY KEY,
    fingerprint       TEXT NOT NULL,
    approved_manifest TEXT NOT NULL,
    approved_at       TEXT NOT NULL,
    status            TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS diff_reports (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    tool_id         TEXT NOT NULL,
    old_fingerprint TEXT,
    new_fingerprint TEXT,
    changed_fields  TEXT NOT NULL,
    diff_text       TEXT,
    risk_level      TEXT,
    detected_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_results (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    source         TEXT NOT NULL,
    tool_id        TEXT NOT NULL,
    flagged        INTEGER NOT NULL,
    matched_patterns TEXT,
    cleaned_text   TEXT,
    removed_text   TEXT,
    created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS alerts (
    id              TEXT PRIMARY KEY,
    type            TEXT NOT NULL,
    tool_id         TEXT NOT NULL,
    severity        TEXT NOT NULL,
    message         TEXT NOT NULL,
    status          TEXT NOT NULL,
    diff_report     TEXT,
    scan_result     TEXT,
    timestamp       TEXT NOT NULL
);
"""


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with get_conn() as conn:
        conn.executescript(SCHEMA)


# ---------------------------------------------------------------------------
# Fingerprints (7.2)
# ---------------------------------------------------------------------------

def save_fingerprint(record: dict):
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO fingerprints (tool_id, fingerprint, approved_manifest, approved_at, status)
            VALUES (:tool_id, :fingerprint, :approved_manifest, :approved_at, :status)
            ON CONFLICT(tool_id) DO UPDATE SET
                fingerprint=excluded.fingerprint,
                approved_manifest=excluded.approved_manifest,
                approved_at=excluded.approved_at,
                status=excluded.status
            """,
            {
                "tool_id": record["tool_id"],
                "fingerprint": record["fingerprint"],
                "approved_manifest": json.dumps(record["approved_manifest"]),
                "approved_at": record["approved_at"],
                "status": record["status"],
            },
        )


def get_fingerprint(tool_id: str):
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM fingerprints WHERE tool_id = ?", (tool_id,)
        ).fetchone()
        return _row_to_fingerprint(row) if row else None


def list_fingerprints():
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM fingerprints").fetchall()
        return [_row_to_fingerprint(r) for r in rows]


def _row_to_fingerprint(row):
    return {
        "tool_id": row["tool_id"],
        "fingerprint": row["fingerprint"],
        "approved_manifest": json.loads(row["approved_manifest"]),
        "approved_at": row["approved_at"],
        "status": row["status"],
    }


# ---------------------------------------------------------------------------
# Diff Reports (7.3)
# ---------------------------------------------------------------------------

def save_diff_report(report: dict):
    with get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO diff_reports
                (tool_id, old_fingerprint, new_fingerprint, changed_fields, diff_text, risk_level, detected_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                report["tool_id"],
                report.get("old_fingerprint"),
                report.get("new_fingerprint"),
                json.dumps(report.get("changed_fields", [])),
                report.get("diff_text"),
                report.get("risk_level"),
                report["detected_at"],
            ),
        )
        return cur.lastrowid


def list_diff_reports(tool_id: str = None):
    with get_conn() as conn:
        if tool_id:
            rows = conn.execute(
                "SELECT * FROM diff_reports WHERE tool_id = ? ORDER BY id DESC", (tool_id,)
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM diff_reports ORDER BY id DESC").fetchall()
        return [_row_to_diff_report(r) for r in rows]


def _row_to_diff_report(row):
    return {
        "id": row["id"],
        "tool_id": row["tool_id"],
        "old_fingerprint": row["old_fingerprint"],
        "new_fingerprint": row["new_fingerprint"],
        "changed_fields": json.loads(row["changed_fields"]),
        "diff_text": row["diff_text"],
        "risk_level": row["risk_level"],
        "detected_at": row["detected_at"],
    }


# ---------------------------------------------------------------------------
# Scan Results (7.4)
# ---------------------------------------------------------------------------

def save_scan_result(result: dict):
    with get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO scan_results
                (source, tool_id, flagged, matched_patterns, cleaned_text, removed_text)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                result["source"],
                result["tool_id"],
                1 if result.get("flagged") else 0,
                json.dumps(result.get("matched_patterns", [])),
                result.get("cleaned_text"),
                json.dumps(result.get("removed_text", [])),
            ),
        )
        return cur.lastrowid


def list_scan_results(tool_id: str = None):
    with get_conn() as conn:
        if tool_id:
            rows = conn.execute(
                "SELECT * FROM scan_results WHERE tool_id = ? ORDER BY id DESC", (tool_id,)
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM scan_results ORDER BY id DESC").fetchall()
        return [_row_to_scan_result(r) for r in rows]


def _row_to_scan_result(row):
    return {
        "id": row["id"],
        "source": row["source"],
        "tool_id": row["tool_id"],
        "flagged": bool(row["flagged"]),
        "matched_patterns": json.loads(row["matched_patterns"]),
        "cleaned_text": row["cleaned_text"],
        "removed_text": json.loads(row["removed_text"]),
    }


# ---------------------------------------------------------------------------
# Alerts (7.5)
# ---------------------------------------------------------------------------

def save_alert(alert: dict):
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO alerts (id, type, tool_id, severity, message, status, diff_report, scan_result, timestamp)
            VALUES (:id, :type, :tool_id, :severity, :message, :status, :diff_report, :scan_result, :timestamp)
            ON CONFLICT(id) DO UPDATE SET
                type=excluded.type,
                tool_id=excluded.tool_id,
                severity=excluded.severity,
                message=excluded.message,
                status=excluded.status,
                diff_report=excluded.diff_report,
                scan_result=excluded.scan_result,
                timestamp=excluded.timestamp
            """,
            {
                "id": alert["id"],
                "type": alert["type"],
                "tool_id": alert["tool_id"],
                "severity": alert["severity"],
                "message": alert["message"],
                "status": alert["status"],
                "diff_report": json.dumps(alert["diff_report"]) if alert.get("diff_report") else None,
                "scan_result": json.dumps(alert["scan_result"]) if alert.get("scan_result") else None,
                "timestamp": alert["timestamp"],
            },
        )


def list_alerts():
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM alerts ORDER BY timestamp DESC").fetchall()
        return [_row_to_alert(r) for r in rows]


def update_alert_status(alert_id: str, status: str):
    with get_conn() as conn:
        conn.execute("UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id))


def _row_to_alert(row):
    return {
        "id": row["id"],
        "type": row["type"],
        "tool_id": row["tool_id"],
        "severity": row["severity"],
        "message": row["message"],
        "status": row["status"],
        "diff_report": json.loads(row["diff_report"]) if row["diff_report"] else None,
        "scan_result": json.loads(row["scan_result"]) if row["scan_result"] else None,
        "timestamp": row["timestamp"],
    }


if __name__ == "__main__":
    init_db()
    print(f"Initialized database at {DB_PATH}")
