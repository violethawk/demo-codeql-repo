"""Persistence Layer: SQLite-backed alert tracking, lifecycle, and audit trail.

The audit layer turns security work from tribal process into inspectable
evidence. Every state transition is logged as an immutable event.
"""

import json
import sqlite3
from datetime import datetime, timezone

from pipeline.ingest import Alert

DEFAULT_DB_PATH = "pipeline.db"

_CREATE_ALERTS = """\
CREATE TABLE IF NOT EXISTS alerts (
    alert_id        TEXT PRIMARY KEY,
    cwe             TEXT NOT NULL,
    rule_name       TEXT NOT NULL,
    severity        TEXT NOT NULL,
    owner_team      TEXT NOT NULL DEFAULT '',
    policy_action   TEXT NOT NULL DEFAULT '',
    disposition     TEXT NOT NULL,
    confidence      TEXT NOT NULL,
    lifecycle_state TEXT NOT NULL DEFAULT 'DETECTED',
    sla_hours       INTEGER NOT NULL DEFAULT 24,
    sla_deadline    TEXT NOT NULL DEFAULT '',
    pr_url          TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    report_json     TEXT NOT NULL
)"""

_CREATE_EVENTS = """\
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id    TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    old_state   TEXT NOT NULL DEFAULT '',
    new_state   TEXT NOT NULL DEFAULT '',
    detail      TEXT NOT NULL DEFAULT '',
    timestamp   TEXT NOT NULL,
    FOREIGN KEY (alert_id) REFERENCES alerts(alert_id)
)"""


def init_db(db_path: str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Open (or create) the SAGE alert tracking database."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute(_CREATE_ALERTS)
    conn.execute(_CREATE_EVENTS)
    conn.commit()
    return conn


def _log_event(
    conn: sqlite3.Connection,
    alert_id: str,
    event_type: str,
    old_state: str = "",
    new_state: str = "",
    detail: str = "",
) -> None:
    """Write an immutable event to the audit trail."""
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """INSERT INTO events (alert_id, event_type, old_state, new_state, detail, timestamp)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (alert_id, event_type, old_state, new_state, detail, now),
    )


def record_alert(
    conn: sqlite3.Connection,
    alert: Alert,
    report: dict,
    *,
    policy_action: str = "",
    sla_hours: int = 24,
) -> None:
    """Insert or update an alert record with full lifecycle tracking."""
    now = datetime.now(timezone.utc).isoformat()
    disposition = report.get("disposition", "UNKNOWN")
    confidence = report.get("confidence", "")

    # Map disposition to lifecycle state
    if disposition == "PR_READY":
        lifecycle_state = "UNDER_REVIEW"
    elif disposition == "NEEDS_HUMAN_REVIEW":
        lifecycle_state = "ESCALATED"
    else:
        lifecycle_state = "DETECTED"

    # Compute SLA deadline
    from pipeline.enforcement import compute_sla_deadline
    sla_deadline = compute_sla_deadline(now, sla_hours)

    # Check if this is an update
    existing = get_alert(conn, alert.alert_id)
    old_state = existing["lifecycle_state"] if existing else ""

    conn.execute(
        """INSERT OR REPLACE INTO alerts
           (alert_id, cwe, rule_name, severity, owner_team, policy_action,
            disposition, confidence, lifecycle_state, sla_hours, sla_deadline,
            pr_url, created_at, updated_at, report_json)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                   COALESCE((SELECT created_at FROM alerts WHERE alert_id = ?), ?),
                   ?, ?)""",
        (
            alert.alert_id, alert.cwe, alert.rule_name, alert.severity,
            alert.owner_team, policy_action,
            disposition, confidence, lifecycle_state, sla_hours, sla_deadline,
            report.get("pr_url", ""),
            alert.alert_id, now,
            now, json.dumps(report),
        ),
    )

    # Log the state transition
    event_type = "state_change" if old_state else "created"
    _log_event(
        conn, alert.alert_id, event_type,
        old_state=old_state,
        new_state=lifecycle_state,
        detail=f"disposition={disposition}, action={policy_action}",
    )

    conn.commit()


def get_alert(conn: sqlite3.Connection, alert_id: str) -> dict | None:
    """Look up a single alert by ID."""
    row = conn.execute(
        "SELECT * FROM alerts WHERE alert_id = ?", (alert_id,),
    ).fetchone()
    return dict(row) if row else None


def get_events(conn: sqlite3.Connection, alert_id: str) -> list[dict]:
    """Get the full audit trail for an alert."""
    rows = conn.execute(
        "SELECT * FROM events WHERE alert_id = ? ORDER BY timestamp",
        (alert_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def list_alerts(
    conn: sqlite3.Connection,
    status: str | None = None,
    cwe: str | None = None,
    team: str | None = None,
) -> list[dict]:
    """List alerts with optional filters."""
    query = "SELECT * FROM alerts WHERE 1=1"
    params: list[str] = []
    if status:
        query += " AND lifecycle_state = ?"
        params.append(status)
    if cwe:
        query += " AND cwe = ?"
        params.append(cwe)
    if team:
        query += " AND owner_team = ?"
        params.append(team)
    query += " ORDER BY updated_at DESC"
    return [dict(r) for r in conn.execute(query, params).fetchall()]


def get_metrics(conn: sqlite3.Connection) -> dict:
    """Compute aggregate remediation metrics."""
    total = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    if total == 0:
        return {
            "total": 0,
            "remediation_rate": 0.0,
            "by_disposition": {},
            "by_cwe": {},
            "by_team": {},
            "by_action": {},
            "by_lifecycle": {},
        }

    by_disp: dict[str, int] = {}
    for row in conn.execute(
        "SELECT disposition, COUNT(*) as cnt FROM alerts GROUP BY disposition",
    ):
        by_disp[row["disposition"]] = row["cnt"]

    by_cwe: dict[str, int] = {}
    for row in conn.execute(
        "SELECT cwe, COUNT(*) as cnt FROM alerts GROUP BY cwe",
    ):
        by_cwe[row["cwe"]] = row["cnt"]

    by_team: dict[str, int] = {}
    for row in conn.execute(
        "SELECT owner_team, COUNT(*) as cnt FROM alerts GROUP BY owner_team",
    ):
        by_team[row["owner_team"]] = row["cnt"]

    by_action: dict[str, int] = {}
    for row in conn.execute(
        "SELECT policy_action, COUNT(*) as cnt FROM alerts GROUP BY policy_action",
    ):
        by_action[row["policy_action"]] = row["cnt"]

    by_lifecycle: dict[str, int] = {}
    for row in conn.execute(
        "SELECT lifecycle_state, COUNT(*) as cnt FROM alerts GROUP BY lifecycle_state",
    ):
        by_lifecycle[row["lifecycle_state"]] = row["cnt"]

    pr_ready = by_disp.get("PR_READY", 0)

    return {
        "total": total,
        "remediation_rate": round(pr_ready / total, 2) if total else 0.0,
        "by_disposition": by_disp,
        "by_cwe": by_cwe,
        "by_team": by_team,
        "by_action": by_action,
        "by_lifecycle": by_lifecycle,
    }
