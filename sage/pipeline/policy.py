"""Policy Layer: Governance decisions per CWE.

The policy engine is the heart of SAGE. It separates signal from action
by combining severity, exploitability, and fix confidence into a
governance decision.

Methodology
-----------
Routing decisions are derived from CISA's Stakeholder-Specific
Vulnerability Categorization (SSVC) framework [1], which evaluates
vulnerabilities along three decision points:

    Exploitation   — Is this being exploited in the wild? (None / PoC / Active)
    Automatable    — Can an attacker exploit this at scale without human
                     interaction? (Yes / No)
    Technical Impact — Does exploitation give full system control or limited
                       effect? (Total / Partial)

SSVC produces a priority (Act / Attend / Track / Track*) that drives
urgency and SLA.  SAGE extends this with a fourth axis:

    Fix Confidence — Can a deterministic code transform reliably fix
                     this class of vulnerability? (HIGH / MEDIUM / LOW)

The combination of SSVC priority and fix confidence determines the
execution path:

    SSVC priority  Fix confidence  →  SAGE action
    ─────────────  ──────────────     ────────────────────
    Act / Attend   HIGH               AUTO_REMEDIATE
    Act / Attend   MEDIUM             REMEDIATE_WITH_REVIEW
    Act / Attend   LOW                ESCALATE
    Track / Track* any                DEFER

Fix confidence is assessed per CWE based on:
  • Fix determinism   — Is there a single canonical fix pattern?
  • Scope of change   — Single-file transform vs. cross-service change?
  • Regression risk   — Can the fix alter intended behavior?

References
----------
[1] CISA, "Stakeholder-Specific Vulnerability Categorization Guide",
    https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc
[2] Carnegie Mellon SEI, "Prioritizing Vulnerability Response: A
    Stakeholder-Specific Vulnerability Categorization", 2019.

Each policy maps to one of four actions:

    AUTO_REMEDIATE         Fix automatically, standard code review
    REMEDIATE_WITH_REVIEW  Fix automatically, require security reviewer
    ESCALATE               No auto-fix; route to owning team + security
    DEFER                  Low-risk; log and revisit later

To add a new CWE:
    1. Evaluate the CWE against the SSVC decision points above.
    2. Assess fix confidence (determinism, scope, regression risk).
    3. Add an entry to REMEDIATION_POLICIES below.
    4. If the action includes remediation, register a handler in execute.py.
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
    # SSVC decision points (for audit trail)
    ssvc_exploitation: str = ""  # None, PoC, Active
    ssvc_automatable: str = ""  # Yes, No
    ssvc_technical_impact: str = ""  # Total, Partial


# ---------------------------------------------------------------------------
# Policy registry
# ---------------------------------------------------------------------------

REMEDIATION_POLICIES: dict[str, RemediationPolicy] = {
    # SSVC: Active exploitation, automatable, total impact → Act
    # Fix confidence HIGH: canonical fix is parameterized queries (single-file,
    # deterministic, no behavioral regression). → AUTO_REMEDIATE
    "CWE-89": RemediationPolicy(
        cwe="CWE-89",
        name="SQL Injection",
        action=AUTO_REMEDIATE,
        fix_confidence="HIGH",
        sla_hours=24,
        escalation_note="",
        ssvc_exploitation="Active",
        ssvc_automatable="Yes",
        ssvc_technical_impact="Total",
    ),
    # SSVC: Active exploitation, automatable, partial impact → Attend
    # Fix confidence MEDIUM: fix is output escaping, but correct encoding
    # depends on output context (HTML body vs. attribute vs. JS). → REMEDIATE_WITH_REVIEW
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
        ssvc_exploitation="Active",
        ssvc_automatable="Yes",
        ssvc_technical_impact="Partial",
    ),
    # SSVC: Active exploitation, automatable, total impact → Act
    # Fix confidence MEDIUM: canonical fix replaces shell=True with argv lists,
    # but residual shell usage across the call site must be verified. → REMEDIATE_WITH_REVIEW
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
        ssvc_exploitation="Active",
        ssvc_automatable="Yes",
        ssvc_technical_impact="Total",
    ),
    # SSVC: PoC exploitation, automatable, total impact → Act
    # Fix confidence LOW: remediation requires secret rotation + vault
    # integration — cross-service change with high regression risk. → ESCALATE
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
        ssvc_exploitation="PoC",
        ssvc_automatable="Yes",
        ssvc_technical_impact="Total",
    ),
    # SSVC: Active exploitation, automatable, total impact → Act
    # Fix confidence LOW: auth logic spans multiple services/flows —
    # no single-file deterministic transform exists. → ESCALATE
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
        ssvc_exploitation="Active",
        ssvc_automatable="Yes",
        ssvc_technical_impact="Total",
    ),
}


def get_policy(cwe: str) -> RemediationPolicy | None:
    """Look up the remediation policy for a CWE identifier."""
    return REMEDIATION_POLICIES.get(cwe)
