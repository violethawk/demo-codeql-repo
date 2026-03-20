"""Tests for the enforcement layer."""

from datetime import datetime, timedelta, timezone

from pipeline.enforcement import (
    check_enforcement, compute_sla_deadline,
    UNDER_REVIEW, MERGED, CLOSED,
)


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
