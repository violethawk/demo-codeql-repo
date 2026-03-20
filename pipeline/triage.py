"""Triage Layer: Deterministic rule-based eligibility check.

Uses the policy registry to decide whether a CWE is recognized and
whether auto-fix is supported.
"""

from dataclasses import dataclass
from typing import List

from pipeline.ingest import Alert
from pipeline.policy import get_policy

ELIGIBLE_SEVERITIES = {"high"}


@dataclass
class TriageResult:
    eligible: bool
    auto_fixable: bool
    reasons: List[str]


def triage(alert: Alert) -> TriageResult:
    """Determine if an alert is eligible for automatic remediation.

    Eligible (recognized by the system) if ALL conditions are met:
    - severity is high
    - CWE has a registered policy
    - file_path is present
    - vulnerable_code_snippet is present and non-empty

    Auto-fixable only if the policy has auto_fix=True.
    Recognized but non-auto-fixable CWEs are routed to NEEDS_HUMAN_REVIEW
    with a clear escalation note.
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
        return TriageResult(eligible=False, auto_fixable=False, reasons=reasons)

    # Policy exists and basic checks passed -- check auto_fix flag
    auto_fixable = policy.auto_fix if policy else False
    if not auto_fixable and policy:
        reasons.append(
            f"Policy for {alert.cwe} ({policy.name}) does not support "
            f"auto-fix: {policy.escalation_note}"
        )

    return TriageResult(
        eligible=True,
        auto_fixable=auto_fixable,
        reasons=reasons,
    )
