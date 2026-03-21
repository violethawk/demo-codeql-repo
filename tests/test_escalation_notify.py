"""Tests for escalation notifications."""

from sage.integrations.notify import build_escalation_notification


def test_remind_owner_goes_to_team_channel():
    notif = build_escalation_notification(
        alert_id="test-001", cwe="CWE-89", owner_team="backend",
        action_required="remind_owner", hours_elapsed=26.0, sla_hours=24,
    )
    assert notif.channel == "#backend-security"
    assert "Reminder" in notif.message
    assert notif.status == "needs_attention"


def test_escalate_manager_goes_to_leads_channel():
    notif = build_escalation_notification(
        alert_id="test-001", cwe="CWE-89", owner_team="backend",
        action_required="escalate_manager", hours_elapsed=50.0, sla_hours=24,
    )
    assert notif.channel == "#engineering-leads"
    assert "Escalation" in notif.message
    assert notif.status == "escalation"


def test_sla_breach_goes_to_escalations_channel():
    notif = build_escalation_notification(
        alert_id="test-001", cwe="CWE-89", owner_team="backend",
        action_required="sla_breach", hours_elapsed=30.0, sla_hours=24,
    )
    assert notif.channel == "#security-escalations"
    assert "SLA BREACH" in notif.message
    assert notif.status == "sla_breach"


def test_unknown_team_uses_default_channel():
    notif = build_escalation_notification(
        alert_id="test-001", cwe="CWE-89", owner_team="unknown",
        action_required="remind_owner", hours_elapsed=26.0, sla_hours=24,
    )
    assert notif.channel == "#security-alerts"
