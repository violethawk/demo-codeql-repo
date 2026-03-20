"""Enforcement Layer: SLA tracking, reminders, and escalation.

SAGE is designed so high-risk findings cannot silently persist.
Every item advances toward fix, review, or escalation.

Lifecycle states:
    DETECTED → TRIAGED → REMEDIATED → UNDER_REVIEW → MERGED → CLOSED
                       ↘ ESCALATED (if SLA breached or policy requires)
                       ↘ DEFERRED (if policy action is DEFER)

Enforcement rules:
    - 24h without review → remind owner
    - 48h without action → escalate to manager
    - SLA breach → flag in dashboard + compliance log
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

# Lifecycle states
DETECTED = "DETECTED"
TRIAGED = "TRIAGED"
REMEDIATED = "REMEDIATED"
UNDER_REVIEW = "UNDER_REVIEW"
MERGED = "MERGED"
ESCALATED = "ESCALATED"
DEFERRED = "DEFERRED"
CLOSED = "CLOSED"

ALL_STATES = [
    DETECTED, TRIAGED, REMEDIATED, UNDER_REVIEW,
    MERGED, ESCALATED, DEFERRED, CLOSED,
]


@dataclass
class EnforcementCheck:
    """Result of checking enforcement rules for an alert."""
    alert_id: str
    lifecycle_state: str
    sla_hours: int
    sla_deadline: str  # ISO timestamp
    hours_elapsed: float
    sla_breached: bool
    action_required: str  # "none" | "remind_owner" | "escalate_manager" | "sla_breach"


def compute_sla_deadline(created_at: str, sla_hours: int) -> str:
    """Compute the SLA deadline from creation time."""
    created = datetime.fromisoformat(created_at)
    deadline = created + timedelta(hours=sla_hours)
    return deadline.isoformat()


def check_enforcement(
    alert_id: str,
    lifecycle_state: str,
    created_at: str,
    sla_hours: int,
    now: datetime | None = None,
) -> EnforcementCheck:
    """Check enforcement rules for a single alert.

    Returns an EnforcementCheck describing what action (if any) is needed.
    """
    if now is None:
        now = datetime.now(timezone.utc)

    created = datetime.fromisoformat(created_at)
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    elapsed = (now - created).total_seconds() / 3600
    deadline = compute_sla_deadline(created_at, sla_hours)
    sla_breached = elapsed > sla_hours

    # Terminal states need no action
    if lifecycle_state in (MERGED, CLOSED, DEFERRED):
        return EnforcementCheck(
            alert_id=alert_id,
            lifecycle_state=lifecycle_state,
            sla_hours=sla_hours,
            sla_deadline=deadline,
            hours_elapsed=round(elapsed, 1),
            sla_breached=False,
            action_required="none",
        )

    # Determine required action based on elapsed time
    action = "none"
    if sla_breached:
        action = "sla_breach"
    elif elapsed > 48:
        action = "escalate_manager"
    elif elapsed > 24:
        action = "remind_owner"

    return EnforcementCheck(
        alert_id=alert_id,
        lifecycle_state=lifecycle_state,
        sla_hours=sla_hours,
        sla_deadline=deadline,
        hours_elapsed=round(elapsed, 1),
        sla_breached=sla_breached,
        action_required=action,
    )


def check_all_enforcement(db_conn) -> list[EnforcementCheck]:
    """Check enforcement rules for all non-terminal alerts in the database."""
    from pipeline.store import list_alerts

    results: list[EnforcementCheck] = []
    alerts = list_alerts(db_conn)

    for alert in alerts:
        state = alert.get("lifecycle_state", alert.get("status", "DETECTED"))
        sla_hours = alert.get("sla_hours", 24)
        created_at = alert.get("created_at", "")

        if not created_at:
            continue

        check = check_enforcement(
            alert_id=alert["alert_id"],
            lifecycle_state=state,
            created_at=created_at,
            sla_hours=sla_hours,
        )
        if check.action_required != "none":
            results.append(check)

    return results
