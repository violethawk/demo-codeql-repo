"""Policy Layer: Remediation eligibility rules per CWE.

Each policy entry defines:
    - whether auto-fix is supported
    - the expected handler name in the execute layer
    - a human-readable note for escalation

To add a new CWE:
    1. Add an entry to REMEDIATION_POLICIES below.
    2. If auto_fix is True, register a handler in pipeline/execute.py.
    3. If auto_fix is False, the system will route to NEEDS_HUMAN_REVIEW.
"""

from dataclasses import dataclass


@dataclass
class RemediationPolicy:
    cwe: str
    name: str
    auto_fix: bool
    escalation_note: str


# ---------------------------------------------------------------------------
# Policy registry
# ---------------------------------------------------------------------------

REMEDIATION_POLICIES: dict[str, RemediationPolicy] = {
    "CWE-89": RemediationPolicy(
        cwe="CWE-89",
        name="SQL Injection",
        auto_fix=True,
        escalation_note="",
    ),
    "CWE-79": RemediationPolicy(
        cwe="CWE-79",
        name="Cross-Site Scripting (XSS)",
        auto_fix=False,
        escalation_note=(
            "XSS fixes depend heavily on the templating engine and output "
            "context (HTML body, attribute, script). Auto-remediation is not "
            "safe without understanding the rendering pipeline. Escalate to "
            "the owning team for manual review."
        ),
    ),
}


def get_policy(cwe: str) -> RemediationPolicy | None:
    """Look up the remediation policy for a CWE identifier."""
    return REMEDIATION_POLICIES.get(cwe)
