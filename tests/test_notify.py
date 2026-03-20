"""Tests for the notification layer."""

from pipeline.ingest import Alert, LineRange
from integrations.notify import build_notification


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


def test_backend_team_routes_to_backend_channel():
    notif = build_notification(
        _make_alert(owner_team="backend"), "PR_READY", "http://pr/1",
    )
    assert notif.channel == "#backend-security"


def test_frontend_team_routes_to_frontend_channel():
    notif = build_notification(
        _make_alert(owner_team="frontend"), "NEEDS_HUMAN_REVIEW", "",
    )
    assert notif.channel == "#frontend-security"


def test_platform_team_routes_to_platform_channel():
    notif = build_notification(
        _make_alert(owner_team="platform"), "PR_READY", "http://pr/1",
    )
    assert notif.channel == "#platform-security"


def test_unknown_team_routes_to_default_channel():
    notif = build_notification(
        _make_alert(owner_team="unknown-team"), "PR_READY", "http://pr/1",
    )
    assert notif.channel == "#security-alerts"


def test_pr_ready_notification_content():
    notif = build_notification(
        _make_alert(), "PR_READY", "http://pr/1",
    )
    assert notif.status == "ready_for_review"
    assert "auto-remediated" in notif.message
    assert "http://pr/1" in notif.message


def test_needs_review_notification_content():
    notif = build_notification(
        _make_alert(), "NEEDS_HUMAN_REVIEW", "",
    )
    assert notif.status == "needs_attention"
    assert "human review" in notif.message
