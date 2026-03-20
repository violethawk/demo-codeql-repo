"""Policy Layer: Governance decisions per CWE.

The policy engine is the heart of SAGE. It separates signal from action
by combining severity, exploitability, and fix confidence into a
governance decision.

Each policy maps to one of four actions:

    AUTO_REMEDIATE         Fix automatically, standard code review
    REMEDIATE_WITH_REVIEW  Fix automatically, require security reviewer
    ESCALATE               No auto-fix; route to owning team + security
    DEFER                  Low-risk; log and revisit later

To add a new CWE:
    1. Add an entry to REMEDIATION_POLICIES below.
    2. If the action includes remediation, register a handler in execute.py.
"""

from dataclasses import dataclass

# Policy actions — the four governance outcomes
AUTO_REMEDIATE = "AUTO_REMEDIATE"
REMEDIATE_WITH_REVIEW = "REMEDIATE_WITH_REVIEW"
ESCALATE = "ESCALATE"
DEFER = "DEFER"


@dataclass
class RemediationPolicy:
    cwe: str
    name: str
    action: str  # one of the four actions above
    fix_confidence: str  # HIGH, MEDIUM, LOW
    sla_hours: int  # hours before escalation
    escalation_note: str


# ---------------------------------------------------------------------------
# Policy registry
# ---------------------------------------------------------------------------

REMEDIATION_POLICIES: dict[str, RemediationPolicy] = {
    "CWE-89": RemediationPolicy(
        cwe="CWE-89",
        name="SQL Injection",
        action=AUTO_REMEDIATE,
        fix_confidence="HIGH",
        sla_hours=24,
        escalation_note="",
    ),
    "CWE-79": RemediationPolicy(
        cwe="CWE-79",
        name="Cross-Site Scripting (XSS)",
        action=REMEDIATE_WITH_REVIEW,
        fix_confidence="MEDIUM",
        sla_hours=24,
        escalation_note=(
            "XSS fixes are context-dependent. Auto-fix applied but "
            "security reviewer must verify the output context."
        ),
    ),
    "CWE-78": RemediationPolicy(
        cwe="CWE-78",
        name="OS Command Injection",
        action=REMEDIATE_WITH_REVIEW,
        fix_confidence="MEDIUM",
        sla_hours=24,
        escalation_note=(
            "Command injection fix replaces shell invocation with argument "
            "lists. Security reviewer must verify no residual shell usage."
        ),
    ),
    "CWE-798": RemediationPolicy(
        cwe="CWE-798",
        name="Hardcoded Credentials",
        action=ESCALATE,
        fix_confidence="LOW",
        sla_hours=12,
        escalation_note=(
            "Hardcoded credentials require secret rotation and vault "
            "integration. Cannot be safely auto-remediated."
        ),
    ),
    "CWE-287": RemediationPolicy(
        cwe="CWE-287",
        name="Improper Authentication",
        action=ESCALATE,
        fix_confidence="LOW",
        sla_hours=12,
        escalation_note=(
            "Authentication logic fixes require understanding the full "
            "auth flow. Escalate to owning team for manual review."
        ),
    ),
}


def get_policy(cwe: str) -> RemediationPolicy | None:
    """Look up the remediation policy for a CWE identifier."""
    return REMEDIATION_POLICIES.get(cwe)
