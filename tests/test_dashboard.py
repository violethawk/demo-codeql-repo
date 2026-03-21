"""Tests for the dashboard generator."""

from sage.pipeline import store
from sage.pipeline.ingest import Alert, LineRange
from sage.integrations.dashboard import generate_aggregate_dashboard


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


def test_aggregate_dashboard_renders(tmp_path):
    """Aggregate dashboard generates valid HTML with KPIs."""
    db_path = str(tmp_path / "test.db")
    conn = store.init_db(db_path)

    store.record_alert(
        conn,
        _make_alert(alert_id="a1", cwe="CWE-89", owner_team="backend"),
        {"disposition": "PR_READY", "confidence": "HIGH", "pr_url": "http://pr/1"},
        policy_action="AUTO_REMEDIATE",
    )
    store.record_alert(
        conn,
        _make_alert(alert_id="a2", cwe="CWE-79", owner_team="frontend"),
        {"disposition": "NEEDS_HUMAN_REVIEW", "confidence": "LOW", "pr_url": ""},
        policy_action="ESCALATE",
    )

    out_path = str(tmp_path / "dashboard.html")
    result = generate_aggregate_dashboard(conn, output_path=out_path)

    assert result == out_path
    html = open(out_path).read()

    # SAGE branding
    assert "SAGE" in html
    assert "Governance Dashboard" in html

    # KPIs present
    assert "SLA Compliance" in html
    assert "Auto-Remediation Rate" in html
    assert "PR Merge Rate" in html
    assert "Lifecycle Completion" in html
    assert "Unowned Findings" in html
    assert "SLA Breaches" in html

    # Alert data present
    assert "a1" in html
    assert "a2" in html
    assert "CWE-89" in html
    assert "CWE-79" in html
    assert "backend" in html
    assert "frontend" in html

    # Interactive elements
    assert "filterAlerts" in html
    assert "filter-btn" in html

    conn.close()


def test_aggregate_dashboard_empty_db(tmp_path):
    """Aggregate dashboard handles empty database gracefully."""
    conn = store.init_db(str(tmp_path / "test.db"))
    out_path = str(tmp_path / "dashboard.html")
    generate_aggregate_dashboard(conn, output_path=out_path)

    html = open(out_path).read()
    assert "No alerts tracked yet" in html
    conn.close()
