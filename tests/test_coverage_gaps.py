"""Tests to close coverage gaps in enforcement, output, validate, and notify."""

from datetime import datetime, timedelta, timezone

from pipeline import store
from pipeline.ingest import Alert, LineRange
from pipeline.triage import triage, TriageResult
from pipeline.execute import ExecutionResult
from pipeline.output import build_report
from pipeline.enforcement import (
    check_kpi_enforcement, apply_kpi_enforcement,
    KPIViolation, UNDER_REVIEW, ESCALATED,
)
from integrations.notify import (
    build_notification, build_escalation_notification, deliver_notification,
)


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


# ---------------------------------------------------------------------------
# Enforcement: escalate_at_risk
# ---------------------------------------------------------------------------


def test_apply_escalate_at_risk(tmp_path):
    """escalate_at_risk escalates findings past 50% of SLA."""
    conn = store.init_db(str(tmp_path / "test.db"))

    # Create a finding with a very short SLA (1 hour), created 2 hours ago
    alert = _make_alert(alert_id="risk-1")
    past = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    report = {"disposition": "PR_READY", "confidence": "HIGH", "pr_url": ""}
    store.record_alert(conn, alert, report, policy_action="AUTO_REMEDIATE", sla_hours=1)

    # Force created_at to 2 hours ago
    conn.execute("UPDATE alerts SET created_at = ? WHERE alert_id = ?", (past, "risk-1"))
    conn.commit()

    violation = KPIViolation(
        kpi_name="SLA Compliance Rate",
        current_value=0.0, threshold=0.8,
        action="escalate_at_risk",
        detail="test",
    )
    actions = apply_kpi_enforcement(conn, [violation])
    assert any("Escalated" in a for a in actions)

    alert_data = store.get_alert(conn, "risk-1")
    assert alert_data["lifecycle_state"] == "ESCALATED"
    conn.close()


def test_apply_escalate_breached(tmp_path):
    """escalate_breached escalates findings past SLA deadline."""
    conn = store.init_db(str(tmp_path / "test.db"))

    alert = _make_alert(alert_id="breach-1")
    report = {"disposition": "PR_READY", "confidence": "HIGH", "pr_url": ""}
    store.record_alert(conn, alert, report, policy_action="AUTO_REMEDIATE", sla_hours=1)

    # Set SLA deadline to the past
    past_deadline = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    conn.execute(
        "UPDATE alerts SET sla_deadline = ? WHERE alert_id = ?",
        (past_deadline, "breach-1"),
    )
    conn.commit()

    violation = KPIViolation(
        kpi_name="SLA Breach Count",
        current_value=1, threshold=0,
        action="escalate_breached",
        detail="test",
    )
    actions = apply_kpi_enforcement(conn, [violation])
    assert any("SLA breached" in a for a in actions)

    alert_data = store.get_alert(conn, "breach-1")
    assert alert_data["lifecycle_state"] == "ESCALATED"
    conn.close()


def test_apply_notify_security_lead(tmp_path):
    """notify_security_lead produces a notification action."""
    conn = store.init_db(str(tmp_path / "test.db"))

    violation = KPIViolation(
        kpi_name="Lifecycle Completion Rate",
        current_value=0.3, threshold=0.8,
        action="notify_security_lead",
        detail="Lifecycle completion 30% is below 80%.",
    )
    actions = apply_kpi_enforcement(conn, [violation])
    assert any("Notification" in a for a in actions)
    conn.close()


def test_kpi_sla_compliance_violation(tmp_path):
    """Low SLA compliance triggers escalate_at_risk."""
    conn = store.init_db(str(tmp_path / "test.db"))

    # 2 findings, neither resolved within SLA
    for i in range(2):
        alert = _make_alert(alert_id=f"sla-{i}", owner_team="backend")
        report = {"disposition": "PR_READY", "confidence": "HIGH", "pr_url": ""}
        store.record_alert(conn, alert, report, policy_action="AUTO_REMEDIATE", sla_hours=24)

    violations = check_kpi_enforcement(conn)
    names = [v.kpi_name for v in violations]
    assert "SLA Compliance Rate" in names
    conn.close()


def test_kpi_pr_merge_rate_violation(tmp_path):
    """Low PR merge rate triggers notify_security_lead."""
    conn = store.init_db(str(tmp_path / "test.db"))

    # 3 findings that went through UNDER_REVIEW, none merged
    for i in range(3):
        alert = _make_alert(alert_id=f"pr-{i}", owner_team="backend")
        report = {"disposition": "PR_READY", "confidence": "HIGH", "pr_url": ""}
        store.record_alert(conn, alert, report, policy_action="AUTO_REMEDIATE")

    violations = check_kpi_enforcement(conn)
    names = [v.kpi_name for v in violations]
    assert "PR Merge Rate" in names
    conn.close()


# ---------------------------------------------------------------------------
# Output: edge cases
# ---------------------------------------------------------------------------


def test_report_triage_failed():
    """Report with failed triage produces NEEDS_HUMAN_REVIEW."""
    alert = _make_alert()
    triage_result = TriageResult(
        eligible=False, auto_fixable=False, action="ESCALATE",
        reasons=["severity too low"],
    )
    report = build_report(alert, triage_result, None, None)
    assert report["disposition"] == "NEEDS_HUMAN_REVIEW"
    assert report["confidence"] == "LOW"


def test_report_execution_failed():
    """Report with failed execution produces NEEDS_HUMAN_REVIEW."""
    alert = _make_alert()
    triage_result = TriageResult(
        eligible=True, auto_fixable=True, action="AUTO_REMEDIATE", reasons=[],
    )
    exec_result = ExecutionResult(
        success=False, files_changed=[], summary="", root_cause="",
        fix_description="", why_fix_works="", error="pattern not found",
    )
    report = build_report(alert, triage_result, exec_result, None)
    assert report["disposition"] == "NEEDS_HUMAN_REVIEW"
    assert "pattern not found" in report["summary"]


def test_report_validation_failed():
    """Report with failed validation produces NEEDS_HUMAN_REVIEW."""
    from pipeline.validate import ValidationResult, ValidationStep

    alert = _make_alert()
    triage_result = TriageResult(
        eligible=True, auto_fixable=True, action="AUTO_REMEDIATE", reasons=[],
    )
    exec_result = ExecutionResult(
        success=True, files_changed=["app.py"], summary="fixed",
        root_cause="cause", fix_description="fix", why_fix_works="works",
    )
    val_result = ValidationResult(
        passed=False,
        steps=[ValidationStep(command="py_compile app.py", result="fail")],
    )
    report = build_report(alert, triage_result, exec_result, val_result)
    assert report["disposition"] == "NEEDS_HUMAN_REVIEW"
    assert report["confidence"] == "MEDIUM"


def test_report_all_passed():
    """Report with all checks passed produces PR_READY."""
    from pipeline.validate import ValidationResult, ValidationStep

    alert = _make_alert()
    triage_result = TriageResult(
        eligible=True, auto_fixable=True, action="AUTO_REMEDIATE", reasons=[],
    )
    exec_result = ExecutionResult(
        success=True, files_changed=["app.py"], summary="fixed",
        root_cause="cause", fix_description="fix", why_fix_works="works",
        residual_risk="None.",
    )
    val_result = ValidationResult(
        passed=True,
        steps=[ValidationStep(command="py_compile app.py", result="pass")],
    )
    report = build_report(
        alert, triage_result, exec_result, val_result,
        pr_url="http://pr/1", notification_sent=True,
    )
    assert report["disposition"] == "PR_READY"
    assert report["confidence"] == "HIGH"
    assert report["pr_url"] == "http://pr/1"
    assert report["residual_risk"] == "None."


# ---------------------------------------------------------------------------
# Notify: delivery writes artifact
# ---------------------------------------------------------------------------


def test_deliver_notification_writes_artifact(tmp_path):
    """Stub delivery writes JSON artifact."""
    payload = build_notification(
        _make_alert(), "PR_READY", "http://pr/1",
    )
    out = str(tmp_path / "notif.json")
    result = deliver_notification(payload, output_path=out)
    assert result.delivered is True
    assert result.method == "stub_artifact"

    import json
    data = json.loads(open(out).read())
    assert data["alert_id"] == "test-001"
    assert data["channel"] == "#backend-security"


def test_escalation_notification_all_types():
    """All escalation types produce valid notifications."""
    for action in ["remind_owner", "escalate_manager", "sla_breach"]:
        notif = build_escalation_notification(
            alert_id="test-001", cwe="CWE-89", owner_team="backend",
            action_required=action, hours_elapsed=30.0, sla_hours=24,
        )
        assert notif.alert_id == "test-001"
        assert notif.message  # non-empty

    # Unknown action
    notif = build_escalation_notification(
        alert_id="test-001", cwe="CWE-89", owner_team="backend",
        action_required="unknown_action", hours_elapsed=1.0, sla_hours=24,
    )
    assert "unknown_action" in notif.message


# ---------------------------------------------------------------------------
# Validate: ruff not installed path
# ---------------------------------------------------------------------------


def test_validate_without_ruff(tmp_path):
    """Validation works when ruff is not installed."""
    f = tmp_path / "ok.py"
    f.write_text("x = 1\n")

    from pipeline.validate import validate
    result = validate(str(f))
    assert result.passed is True
    # Should have at least py_compile step
    assert len(result.steps) >= 1
    assert result.steps[0].result == "pass"


# ---------------------------------------------------------------------------
# Store: KPI edge cases
# ---------------------------------------------------------------------------


def test_kpis_with_zero_prs(tmp_path):
    """PR merge rate is 0 when no PRs exist."""
    conn = store.init_db(str(tmp_path / "test.db"))

    alert = _make_alert(alert_id="nop-1")
    report = {"disposition": "NEEDS_HUMAN_REVIEW", "confidence": "LOW", "pr_url": ""}
    store.record_alert(conn, alert, report, policy_action="ESCALATE")

    kpis = store.get_kpis(conn)
    assert kpis["pr_merge_rate"] == 0.0
    assert kpis["total_prs"] == 0
    conn.close()


def test_kpis_empty_db(tmp_path):
    """KPIs return zeros on empty database."""
    conn = store.init_db(str(tmp_path / "test.db"))
    kpis = store.get_kpis(conn)
    assert kpis["total"] == 0
    assert kpis["sla_compliance_rate"] == 0.0
    assert kpis["mttr_hours"] == 0.0
    conn.close()
