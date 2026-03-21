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


# ---------------------------------------------------------------------------
# KPI-driven enforcement: metrics that trigger system actions
# ---------------------------------------------------------------------------


@dataclass
class KPIViolation:
    """A KPI that crossed its threshold — triggers a system action."""
    kpi_name: str
    current_value: float
    threshold: float
    action: str  # what the system does about it
    detail: str


def _load_kpi_thresholds() -> dict:
    """Load KPI thresholds from sage.config.json."""
    import json
    from pathlib import Path
    config_path = Path("sage.config.json")
    if config_path.exists():
        config = json.loads(config_path.read_text())
        return config.get("kpi_thresholds", {})
    return {}


def check_kpi_enforcement(db_conn) -> list[KPIViolation]:
    """Check aggregate KPIs against thresholds and return violations.

    This is what makes KPIs load-bearing: when a metric degrades past
    its threshold, the system takes action — not just reports.
    """
    from pipeline.store import get_kpis

    kpis = get_kpis(db_conn)
    thresholds = _load_kpi_thresholds()
    violations: list[KPIViolation] = []

    if kpis["total"] == 0:
        return violations

    # SLA compliance below threshold → escalate all at-risk findings
    sla_min = thresholds.get("sla_compliance_min", 0.80)
    if kpis["sla_compliance_rate"] < sla_min:
        violations.append(KPIViolation(
            kpi_name="SLA Compliance Rate",
            current_value=kpis["sla_compliance_rate"],
            threshold=sla_min,
            action="escalate_at_risk",
            detail=(
                f"SLA compliance {kpis['sla_compliance_rate']:.0%} is below "
                f"{sla_min:.0%} threshold. Escalating all at-risk findings."
            ),
        ))

    # Lifecycle completion below threshold → notify security lead
    comp_min = thresholds.get("lifecycle_completion_min", 0.80)
    if kpis["lifecycle_completion_rate"] < comp_min:
        violations.append(KPIViolation(
            kpi_name="Lifecycle Completion Rate",
            current_value=kpis["lifecycle_completion_rate"],
            threshold=comp_min,
            action="notify_security_lead",
            detail=(
                f"Lifecycle completion {kpis['lifecycle_completion_rate']:.0%} "
                f"is below {comp_min:.0%}. {kpis['total'] - kpis['lifecycle_completed']} "
                f"findings have not reached terminal state."
            ),
        ))

    # PR merge rate below threshold → flag trust issue
    merge_min = thresholds.get("pr_merge_rate_min", 0.60)
    if kpis["total_prs"] > 0 and kpis["pr_merge_rate"] < merge_min:
        violations.append(KPIViolation(
            kpi_name="PR Merge Rate",
            current_value=kpis["pr_merge_rate"],
            threshold=merge_min,
            action="notify_security_lead",
            detail=(
                f"PR merge rate {kpis['pr_merge_rate']:.0%} is below "
                f"{merge_min:.0%}. Engineers may be rejecting auto-fixes. "
                f"Review fix quality and policy confidence thresholds."
            ),
        ))

    # Unowned findings > threshold → auto-assign
    max_unowned = thresholds.get("max_unowned_findings", 0)
    if kpis["unowned_findings"] > max_unowned:
        violations.append(KPIViolation(
            kpi_name="Unowned Findings",
            current_value=kpis["unowned_findings"],
            threshold=max_unowned,
            action="auto_assign_unowned",
            detail=(
                f"{kpis['unowned_findings']} finding(s) have no assigned team. "
                f"Auto-assigning to default team."
            ),
        ))

    # SLA breaches > threshold → escalate all breached
    max_breaches = thresholds.get("max_sla_breaches", 0)
    if kpis["sla_breach_count"] > max_breaches:
        violations.append(KPIViolation(
            kpi_name="SLA Breach Count",
            current_value=kpis["sla_breach_count"],
            threshold=max_breaches,
            action="escalate_breached",
            detail=(
                f"{kpis['sla_breach_count']} finding(s) have breached SLA. "
                f"Auto-escalating."
            ),
        ))

    return violations


def apply_kpi_enforcement(db_conn, violations: list[KPIViolation]) -> list[str]:
    """Execute the system actions triggered by KPI violations.

    Returns a list of actions taken (for logging/display).
    """
    from pipeline.store import _log_event, list_alerts

    thresholds = _load_kpi_thresholds()
    actions_taken: list[str] = []
    now = datetime.now(timezone.utc).isoformat()

    for v in violations:
        if v.action == "escalate_at_risk":
            # Escalate all non-terminal findings that are past 50% of their SLA
            alerts = list_alerts(db_conn)
            for a in alerts:
                if a["lifecycle_state"] in (MERGED, CLOSED, DEFERRED, ESCALATED):
                    continue
                created = datetime.fromisoformat(a["created_at"])
                if created.tzinfo is None:
                    created = created.replace(tzinfo=timezone.utc)
                now_dt = datetime.now(timezone.utc)
                elapsed = (now_dt - created).total_seconds() / 3600
                if elapsed > a["sla_hours"] * 0.5:
                    db_conn.execute(
                        "UPDATE alerts SET lifecycle_state = 'ESCALATED', updated_at = ? "
                        "WHERE alert_id = ?",
                        (now, a["alert_id"]),
                    )
                    _log_event(
                        db_conn, a["alert_id"], "kpi_enforcement",
                        old_state=a["lifecycle_state"], new_state=ESCALATED,
                        detail=f"KPI trigger: {v.kpi_name} = {v.current_value:.0%} < {v.threshold:.0%}",
                    )
                    actions_taken.append(
                        f"Escalated {a['alert_id']} (at-risk, {elapsed:.0f}h elapsed)"
                    )

        elif v.action == "auto_assign_unowned":
            default_team = thresholds.get("auto_assign_unowned_to", "security")
            alerts = list_alerts(db_conn)
            for a in alerts:
                if a["lifecycle_state"] in (MERGED, CLOSED, DEFERRED):
                    continue
                if not a.get("owner_team"):
                    db_conn.execute(
                        "UPDATE alerts SET owner_team = ?, updated_at = ? "
                        "WHERE alert_id = ?",
                        (default_team, now, a["alert_id"]),
                    )
                    _log_event(
                        db_conn, a["alert_id"], "kpi_enforcement",
                        old_state="", new_state="",
                        detail=f"Auto-assigned to {default_team}: unowned findings KPI violated",
                    )
                    actions_taken.append(
                        f"Assigned {a['alert_id']} to {default_team}"
                    )

        elif v.action == "escalate_breached":
            alerts = list_alerts(db_conn)
            now_dt = datetime.now(timezone.utc)
            for a in alerts:
                if a["lifecycle_state"] in (MERGED, CLOSED, DEFERRED, ESCALATED):
                    continue
                if a.get("sla_deadline") and a["sla_deadline"] < now_dt.isoformat():
                    db_conn.execute(
                        "UPDATE alerts SET lifecycle_state = 'ESCALATED', updated_at = ? "
                        "WHERE alert_id = ?",
                        (now, a["alert_id"]),
                    )
                    _log_event(
                        db_conn, a["alert_id"], "kpi_enforcement",
                        old_state=a["lifecycle_state"], new_state=ESCALATED,
                        detail=f"KPI trigger: SLA breach count = {int(v.current_value)} > {int(v.threshold)}",
                    )
                    actions_taken.append(
                        f"Escalated {a['alert_id']} (SLA breached)"
                    )

        elif v.action == "notify_security_lead":
            # This triggers a notification — the caller (run_enforce.py) handles delivery
            actions_taken.append(f"Notification: {v.detail}")

    db_conn.commit()
    return actions_taken
