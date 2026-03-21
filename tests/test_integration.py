"""Integration tests: full pipeline end-to-end."""

import json
from pathlib import Path

from sage.pipeline import store
from sage.pipeline.ingest import Alert, LineRange
from sage.pipeline.enforcement import check_kpi_enforcement, apply_kpi_enforcement


def _write_fixture(tmp_path, alert_id, cwe, lines, snippet):
    """Write a fixture JSON and a vulnerable app.py for testing."""
    fixture = {
        "alert_id": alert_id,
        "rule_name": f"Test {cwe}",
        "severity": "high",
        "cwe": cwe,
        "language": "python",
        "repo_name": "test-repo",
        "default_branch": "main",
        "file_path": "app.py",
        "line_range": {"start": lines[0], "end": lines[1]},
        "vulnerable_code_snippet": snippet,
        "alert_description": f"Test {cwe} vulnerability",
        "security_guidance": "Fix it",
        "owner_team": "backend",
    }
    fixture_path = tmp_path / f"{alert_id}.json"
    fixture_path.write_text(json.dumps(fixture))
    return str(fixture_path)


def test_full_pipeline_cwe89(tmp_path):
    """CWE-89: full pipeline from fixture to audit trail."""
    # Set up vulnerable code
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text('''\
from flask import request

def search():
    user_input = request.args.get("name", "")
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    cursor = db.cursor()
    cursor.execute(query)
    return cursor.fetchall()
''')

    fixture_path = _write_fixture(
        tmp_path, "int-001", "CWE-89", [3, 8],
        ["query = f\"SELECT * FROM users WHERE name = '{user_input}'\"",
         "cursor.execute(query)"],
    )

    # Run pipeline
    from sage.cli.demo import process_alert

    db_conn = store.init_db(str(tmp_path / "test.db"))
    report = process_alert(
        fixture_path, str(repo), db_conn=db_conn, quiet=True,
    )
    assert report["disposition"] == "PR_READY"
    assert report["confidence"] == "HIGH"
    assert report["policy_action"] == "AUTO_REMEDIATE"

    # Verify the code was fixed
    fixed_code = (repo / "app.py").read_text()
    assert "f\"SELECT" not in fixed_code
    assert "?" in fixed_code

    # Verify database record
    alert = store.get_alert(db_conn, "int-001")
    assert alert is not None
    assert alert["lifecycle_state"] == "UNDER_REVIEW"
    assert alert["policy_action"] == "AUTO_REMEDIATE"

    # Verify audit trail
    events = store.get_events(db_conn, "int-001")
    assert len(events) >= 1
    assert events[0]["event_type"] == "created"

    db_conn.close()


def test_full_pipeline_cwe79_devin_path(tmp_path):
    """CWE-79: REMEDIATE_WITH_REVIEW path (Devin stub)."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text('''\
from flask import request

def search_page():
    user_input = request.args.get("query", "")
    return f"<h1>Results for {user_input}</h1>"
''')

    fixture_path = _write_fixture(
        tmp_path, "int-002", "CWE-79", [3, 5],
        ["user_input = request.args.get('query', '')",
         "return f'<h1>Results for {user_input}</h1>'"],
    )

    from sage.cli.demo import process_alert

    db_conn = store.init_db(str(tmp_path / "test.db"))
    report = process_alert(
        fixture_path, str(repo), db_conn=db_conn, quiet=True,
    )
    assert report["disposition"] == "PR_READY"
    assert report["policy_action"] == "REMEDIATE_WITH_REVIEW"
    assert report["review_required"] is True
    assert "devin_session_id" in report
    assert "remediation_plan" in report

    db_conn.close()


def test_full_pipeline_escalate(tmp_path):
    """CWE-798: ESCALATE path (no auto-fix)."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("password = 'hardcoded123'\n")

    fixture_path = _write_fixture(
        tmp_path, "int-003", "CWE-798", [1, 1],
        ["password = 'hardcoded123'"],
    )

    from sage.cli.demo import process_alert

    db_conn = store.init_db(str(tmp_path / "test.db"))
    report = process_alert(
        fixture_path, str(repo), db_conn=db_conn, quiet=True,
    )
    assert report["disposition"] == "NEEDS_HUMAN_REVIEW"

    alert = store.get_alert(db_conn, "int-003")
    assert alert["lifecycle_state"] == "ESCALATED"

    db_conn.close()


def test_kpi_enforcement_end_to_end(tmp_path):
    """KPI enforcement triggers system actions on threshold breach."""
    db_conn = store.init_db(str(tmp_path / "test.db"))

    # Create 3 findings, none resolved → 0% completion → KPI violation
    for i in range(3):
        alert = Alert(
            alert_id=f"kpi-{i}", rule_name="Test", severity="high",
            cwe="CWE-89", language="python", repo_name="repo",
            default_branch="main", file_path="app.py",
            line_range=LineRange(start=1, end=5),
            vulnerable_code_snippet=["x"], alert_description="desc",
            security_guidance="fix", owner_team="backend" if i < 2 else "",
        )
        store.record_alert(
            db_conn, alert,
            {"disposition": "PR_READY", "confidence": "HIGH", "pr_url": ""},
            policy_action="AUTO_REMEDIATE",
        )

    # Check KPI enforcement
    violations = check_kpi_enforcement(db_conn)
    assert len(violations) > 0

    # Apply enforcement
    actions = apply_kpi_enforcement(db_conn, violations)
    assert len(actions) > 0

    # Verify the unowned finding was auto-assigned
    alert = store.get_alert(db_conn, "kpi-2")
    assert alert["owner_team"] == "security"

    # Verify enforcement events were logged
    events = store.get_events(db_conn, "kpi-2")
    kpi_events = [e for e in events if e["event_type"] == "kpi_enforcement"]
    assert len(kpi_events) > 0

    db_conn.close()


def test_override_after_pipeline(tmp_path):
    """Human override works on pipeline-created findings."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text('''\
from flask import request

def search():
    user_input = request.args.get("name", "")
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    cursor = db.cursor()
    cursor.execute(query)
    return cursor.fetchall()
''')

    fixture_path = _write_fixture(
        tmp_path, "ovr-001", "CWE-89", [3, 8],
        ["query = f\"...\"", "cursor.execute(query)"],
    )

    from sage.cli.demo import process_alert
    from datetime import datetime, timezone

    db_conn = store.init_db(str(tmp_path / "test.db"))
    process_alert(fixture_path, str(repo), db_conn=db_conn, quiet=True)

    # Override: merge
    now = datetime.now(timezone.utc).isoformat()
    db_conn.execute(
        "UPDATE alerts SET lifecycle_state = 'MERGED', updated_at = ? WHERE alert_id = ?",
        (now, "ovr-001"),
    )
    store._log_event(
        db_conn, "ovr-001", "manual_override",
        old_state="UNDER_REVIEW", new_state="MERGED",
        detail="Integration test merge",
    )
    db_conn.commit()

    # Verify full audit trail
    alert = store.get_alert(db_conn, "ovr-001")
    assert alert["lifecycle_state"] == "MERGED"

    events = store.get_events(db_conn, "ovr-001")
    assert events[-1]["event_type"] == "manual_override"
    assert events[-1]["new_state"] == "MERGED"

    # Verify KPIs reflect the merge
    kpis = store.get_kpis(db_conn)
    assert kpis["merged"] >= 1
    assert kpis["pr_merge_rate"] > 0

    db_conn.close()
