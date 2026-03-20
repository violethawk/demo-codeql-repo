"""Triage Layer: Deterministic rule-based eligibility check."""

from dataclasses import dataclass
from typing import List

from pipeline.ingest import Alert

ELIGIBLE_SEVERITIES = {"high"}
ELIGIBLE_CWES = {"CWE-89", "CWE-79"}


@dataclass
class TriageResult:
    eligible: bool
    reasons: List[str]


def triage(alert: Alert) -> TriageResult:
    """Determine if an alert is eligible for automatic remediation.

    Eligible ONLY if ALL conditions are met:
    - severity == "high"
    - cwe in ["CWE-89", "CWE-79"]
    - exactly one file is affected (single file_path)
    - vulnerable_code_snippet is present and non-empty
    """
    reasons: List[str] = []

    if alert.severity not in ELIGIBLE_SEVERITIES:
        reasons.append(
            f"Severity '{alert.severity}' not in {ELIGIBLE_SEVERITIES}"
        )

    if alert.cwe not in ELIGIBLE_CWES:
        reasons.append(f"CWE '{alert.cwe}' not in {ELIGIBLE_CWES}")

    if not alert.file_path:
        reasons.append("file_path is empty")

    if not alert.vulnerable_code_snippet:
        reasons.append("vulnerable_code_snippet is empty")

    eligible = len(reasons) == 0
    return TriageResult(eligible=eligible, reasons=reasons)
