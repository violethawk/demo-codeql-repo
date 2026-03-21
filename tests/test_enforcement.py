"""Tests for the enforcement layer."""

from datetime import datetime, timedelta, timezone

from sage.pipeline.enforcement import (
    check_enforcement, compute_sla_deadline,
    check_kpi_enforcement, apply_kpi_enforcement,
    UNDER_REVIEW, MERGED, CLOSED,
)
from sage.pipeline import store
from sage.pipeline.ingest import Alert, LineRange


def test_compute_sla_deadline():
    created = "2026-03-20T10:00:00+00:00"
    deadline = compute_sla_deadline(created, 24)
    assert "2026-03-21T10:00:00" in deadline


def test_no_action_within_sla():
    now = datetime(2026, 3, 20, 15, 0, tzinfo=timezone.utc)
    check = check_enforcement(
        "test-001", UNDER_REVIEW,
        "2026-03-20T10:00:00+00:00", sla_hours=24, now=now,
    )
    assert check.action_required == "none"
    assert check.sla_breached is False
    assert check.hours_elapsed == 5.0


def test_remind_owner_after_24h():
    now = datetime(2026, 3, 21, 12, 0, tzinfo=timezone.utc)
    check = check_enforcement(
        "test-001", UNDER_REVIEW,
        "2026-03-20T10:00:00+00:00", sla_hours=48, now=now,
    )
    assert check.action_required == "remind_owner"
    assert check.sla_breached is False


def test_escalate_manager_after_48h():
    now = datetime(2026, 3, 22, 12, 0, tzinfo=timezone.utc)
    check = check_enforcement(
        "test-001", UNDER_REVIEW,
        "2026-03-20T10:00:00+00:00", sla_hours=72, now=now,
    )
    assert check.action_required == "escalate_manager"


def test_sla_breach():
    now = datetime(2026, 3, 21, 12, 0, tzinfo=timezone.utc)
    check = check_enforcement(
        "test-001", UNDER_REVIEW,
        "2026-03-20T10:00:00+00:00", sla_hours=24, now=now,
    )
    assert check.sla_breached is True
    assert check.action_required == "sla_breach"


def test_terminal_state_no_action():
    """Merged/closed alerts need no enforcement."""
    now = datetime(2026, 3, 25, 0, 0, tzinfo=timezone.utc)
    for state in [MERGED, CLOSED]:
        check = check_enforcement(
            "test-001", state,
            "2026-03-20T10:00:00+00:00", sla_hours=24, now=now,
        )
        assert check.action_required == "none"
        assert check.sla_breached is False


# ---------------------------------------------------------------------------
# KPI-driven enforcement tests
# ---------------------------------------------------------------------------


def _make_alert(**overrides) -> Alert:
    defaults = dict(
        alert_id="test-001", rule_name="Test", severity="high", cwe="CWE-89",
        language="python", repo_name="repo", default_branch="main",
        file_path="app.py", line_range=LineRange(start=1, end=5),
        vulnerable_code_snippet=["x"], alert_description="desc",
        security_guidance="fix", owner_team="backend",
    )
    defaults.update(overrides)
    return Alert(**defaults)


def test_kpi_violation_lifecycle_completion(tmp_path):
    """Low lifecycle completion triggers a KPI violation."""
    conn = store.init_db(str(tmp_path / "test.db"))

    # 3 findings, none in terminal state → 0% completion
    for i in range(3):
        store.record_alert(
            conn,
            _make_alert(alert_id=f"a{i}", owner_team="backend"),
            {"disposition": "PR_READY", "confidence": "HIGH", "pr_url": ""},
            policy_action="AUTO_REMEDIATE",
        )

    violations = check_kpi_enforcement(conn)
    names = [v.kpi_name for v in violations]
    assert "Lifecycle Completion Rate" in names
    conn.close()


def test_kpi_violation_unowned_findings(tmp_path):
    """Unowned findings trigger auto-assignment."""
    conn = store.init_db(str(tmp_path / "test.db"))

    store.record_alert(
        conn,
        _make_alert(alert_id="a1", owner_team=""),
        {"disposition": "PR_READY", "confidence": "HIGH", "pr_url": ""},
        policy_action="AUTO_REMEDIATE",
    )

    violations = check_kpi_enforcement(conn)
    names = [v.kpi_name for v in violations]
    assert "Unowned Findings" in names

    # Apply the enforcement
    actions = apply_kpi_enforcement(conn, violations)
    assert any("Assigned" in a for a in actions)

    # Verify the finding now has a team
    alert = store.get_alert(conn, "a1")
    assert alert["owner_team"] == "security"
    conn.close()


def test_no_kpi_violations_when_healthy(tmp_path):
    """No violations when all KPIs are within thresholds."""
    conn = store.init_db(str(tmp_path / "test.db"))

    # 1 finding, already merged → 100% completion, 100% merge rate
    store.record_alert(
        conn,
        _make_alert(alert_id="a1", owner_team="backend"),
        {"disposition": "PR_READY", "confidence": "HIGH", "pr_url": ""},
        policy_action="AUTO_REMEDIATE",
    )
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "UPDATE alerts SET lifecycle_state = 'MERGED', updated_at = ? WHERE alert_id = ?",
        (now, "a1"),
    )
    conn.commit()

    violations = check_kpi_enforcement(conn)
    assert len(violations) == 0
    conn.close()
