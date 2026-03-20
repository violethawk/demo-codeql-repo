"""Tests for the persistence layer."""

from pipeline.ingest import Alert, LineRange
from pipeline import store


def _make_alert(**overrides) -> Alert:
    defaults = dict(
        alert_id="test-001",
        rule_name="Test rule",
        severity="high",
        cwe="CWE-89",
        language="python",
        repo_name="repo",
        default_branch="main",
        file_path="app.py",
        line_range=LineRange(start=1, end=5),
        vulnerable_code_snippet=["x"],
        alert_description="desc",
        security_guidance="fix",
        owner_team="backend",
    )
    defaults.update(overrides)
    return Alert(**defaults)


def test_init_creates_tables(tmp_path):
    conn = store.init_db(str(tmp_path / "test.db"))
    tables = [
        r["name"] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    ]
    assert "alerts" in tables
    assert "events" in tables
    conn.close()


def test_record_and_get_alert(tmp_path):
    conn = store.init_db(str(tmp_path / "test.db"))
    alert = _make_alert()
    report = {"disposition": "PR_READY", "confidence": "HIGH", "pr_url": "http://pr/1"}

    store.record_alert(conn, alert, report, policy_action="AUTO_REMEDIATE", sla_hours=24)
    result = store.get_alert(conn, "test-001")

    assert result is not None
    assert result["alert_id"] == "test-001"
    assert result["disposition"] == "PR_READY"
    assert result["lifecycle_state"] == "UNDER_REVIEW"
    assert result["policy_action"] == "AUTO_REMEDIATE"
    assert result["sla_deadline"] != ""
    conn.close()


def test_audit_events_logged(tmp_path):
    conn = store.init_db(str(tmp_path / "test.db"))
    alert = _make_alert()
    report = {"disposition": "PR_READY", "confidence": "HIGH", "pr_url": ""}

    store.record_alert(conn, alert, report, policy_action="AUTO_REMEDIATE")
    events = store.get_events(conn, "test-001")

    assert len(events) >= 1
    assert events[0]["event_type"] == "created"
    assert events[0]["new_state"] == "UNDER_REVIEW"
    conn.close()


def test_get_alert_not_found(tmp_path):
    conn = store.init_db(str(tmp_path / "test.db"))
    assert store.get_alert(conn, "nonexistent") is None
    conn.close()


def test_metrics(tmp_path):
    conn = store.init_db(str(tmp_path / "test.db"))

    store.record_alert(
        conn,
        _make_alert(alert_id="a1", cwe="CWE-89", owner_team="backend"),
        {"disposition": "PR_READY", "confidence": "HIGH", "pr_url": ""},
        policy_action="AUTO_REMEDIATE",
    )
    store.record_alert(
        conn,
        _make_alert(alert_id="a2", cwe="CWE-79", owner_team="frontend"),
        {"disposition": "NEEDS_HUMAN_REVIEW", "confidence": "LOW", "pr_url": ""},
        policy_action="ESCALATE",
    )
    store.record_alert(
        conn,
        _make_alert(alert_id="a3", cwe="CWE-78", owner_team="platform"),
        {"disposition": "PR_READY", "confidence": "HIGH", "pr_url": ""},
        policy_action="REMEDIATE_WITH_REVIEW",
    )

    metrics = store.get_metrics(conn)

    assert metrics["total"] == 3
    assert metrics["remediation_rate"] == 0.67
    assert metrics["by_disposition"]["PR_READY"] == 2
    assert metrics["by_action"]["AUTO_REMEDIATE"] == 1
    assert metrics["by_action"]["REMEDIATE_WITH_REVIEW"] == 1
    conn.close()


def test_list_alerts_with_filter(tmp_path):
    conn = store.init_db(str(tmp_path / "test.db"))

    store.record_alert(
        conn,
        _make_alert(alert_id="a1", cwe="CWE-89"),
        {"disposition": "PR_READY", "confidence": "HIGH", "pr_url": ""},
    )
    store.record_alert(
        conn,
        _make_alert(alert_id="a2", cwe="CWE-79"),
        {"disposition": "NEEDS_HUMAN_REVIEW", "confidence": "LOW", "pr_url": ""},
    )

    escalated = store.list_alerts(conn, status="ESCALATED")
    assert len(escalated) == 1
    assert escalated[0]["alert_id"] == "a2"
    conn.close()
