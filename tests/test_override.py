"""Tests for the human override system."""

from datetime import datetime, timezone

from sage.pipeline import store
from sage.pipeline.ingest import Alert, LineRange


def _make_alert(**overrides) -> Alert:
    defaults = dict(
        alert_id="test-001",
        rule_name="Test",
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


def _setup_alert(tmp_path, lifecycle_state="UNDER_REVIEW"):
    conn = store.init_db(str(tmp_path / "test.db"))
    alert = _make_alert()
    report = {"disposition": "PR_READY", "confidence": "HIGH", "pr_url": ""}
    store.record_alert(conn, alert, report, policy_action="AUTO_REMEDIATE")
    # Force the lifecycle state for testing
    conn.execute(
        "UPDATE alerts SET lifecycle_state = ? WHERE alert_id = ?",
        (lifecycle_state, alert.alert_id),
    )
    conn.commit()
    return conn


def test_merge_from_under_review(tmp_path):
    conn = _setup_alert(tmp_path, "UNDER_REVIEW")
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "UPDATE alerts SET lifecycle_state = 'MERGED', updated_at = ? WHERE alert_id = ?",
        (now, "test-001"),
    )
    store._log_event(conn, "test-001", "manual_override",
                     old_state="UNDER_REVIEW", new_state="MERGED")
    conn.commit()

    alert = store.get_alert(conn, "test-001")
    assert alert["lifecycle_state"] == "MERGED"

    events = store.get_events(conn, "test-001")
    override_events = [e for e in events if e["event_type"] == "manual_override"]
    assert len(override_events) == 1
    conn.close()


def test_defer_from_under_review(tmp_path):
    conn = _setup_alert(tmp_path, "UNDER_REVIEW")
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "UPDATE alerts SET lifecycle_state = 'DEFERRED', updated_at = ? WHERE alert_id = ?",
        (now, "test-001"),
    )
    store._log_event(conn, "test-001", "manual_override",
                     old_state="UNDER_REVIEW", new_state="DEFERRED",
                     detail="low priority this sprint")
    conn.commit()

    alert = store.get_alert(conn, "test-001")
    assert alert["lifecycle_state"] == "DEFERRED"
    conn.close()


def test_reopen_from_deferred(tmp_path):
    conn = _setup_alert(tmp_path, "DEFERRED")
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "UPDATE alerts SET lifecycle_state = 'UNDER_REVIEW', updated_at = ? WHERE alert_id = ?",
        (now, "test-001"),
    )
    conn.commit()

    alert = store.get_alert(conn, "test-001")
    assert alert["lifecycle_state"] == "UNDER_REVIEW"
    conn.close()


def test_escalate_from_under_review(tmp_path):
    conn = _setup_alert(tmp_path, "UNDER_REVIEW")
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "UPDATE alerts SET lifecycle_state = 'ESCALATED', updated_at = ? WHERE alert_id = ?",
        (now, "test-001"),
    )
    store._log_event(conn, "test-001", "manual_override",
                     old_state="UNDER_REVIEW", new_state="ESCALATED",
                     detail="needs senior review")
    conn.commit()

    alert = store.get_alert(conn, "test-001")
    assert alert["lifecycle_state"] == "ESCALATED"
    conn.close()
