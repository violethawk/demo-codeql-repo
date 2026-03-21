"""Triage Layer: Deterministic rule-based governance decision.

Uses the policy registry to classify each finding and assign one of
four actions: AUTO_REMEDIATE, REMEDIATE_WITH_REVIEW, ESCALATE, DEFER.
"""

from dataclasses import dataclass
from typing import List

from sage.pipeline.ingest import Alert
from sage.pipeline.policy import (
    AUTO_REMEDIATE,
    DEFER,
    ESCALATE,
    REMEDIATE_WITH_REVIEW,
    get_policy,
)

ELIGIBLE_SEVERITIES = {"high", "critical"}


@dataclass
class TriageResult:
    eligible: bool
    auto_fixable: bool
    action: str  # AUTO_REMEDIATE | REMEDIATE_WITH_REVIEW | ESCALATE | DEFER
    reasons: List[str]
    sla_hours: int = 0


def triage(alert: Alert) -> TriageResult:
    """Classify an alert and assign a governance action.

    Returns a TriageResult with the policy-driven action.
    """
    reasons: List[str] = []

    if alert.severity not in ELIGIBLE_SEVERITIES:
        reasons.append(
            f"Severity '{alert.severity}' not in {ELIGIBLE_SEVERITIES}"
        )

    policy = get_policy(alert.cwe)
    if policy is None:
        reasons.append(f"CWE '{alert.cwe}' has no registered policy")

    if not alert.file_path:
        reasons.append("file_path is empty")

    if not alert.vulnerable_code_snippet:
        reasons.append("vulnerable_code_snippet is empty")

    if reasons:
        return TriageResult(
            eligible=False,
            auto_fixable=False,
            action=ESCALATE,
            reasons=reasons,
        )

    # Policy exists and basic checks passed — apply the policy action
    action = policy.action
    auto_fixable = action in (AUTO_REMEDIATE, REMEDIATE_WITH_REVIEW)
    sla_hours = policy.sla_hours

    if not auto_fixable and policy.escalation_note:
        reasons.append(
            f"Policy for {alert.cwe} ({policy.name}): {policy.escalation_note}"
        )

    return TriageResult(
        eligible=True,
        auto_fixable=auto_fixable,
        action=action,
        reasons=reasons,
        sla_hours=sla_hours,
    )
