# SAGE Requirements

**Security Automation & Governance Engine**
*Derived from MedSecure discovery call*

---

## 1. Problem statement

MedSecure has a growing backlog of CodeQL security findings that are detected but not consistently remediated. Security teams can identify and file findings, but engineering teams do not reliably prioritize them because they fall outside normal sprint workflows. This creates audit risk, weakens security posture, and leaves no dependable mechanism to ensure findings are fixed, reviewed, or escalated without manual follow-up.

## 2. Product objective

Build an automation system using Devin + Devin API that converts eligible CodeQL findings into remediated code changes, routes them to the correct reviewers, enforces follow-through through escalation logic, and produces an auditable record of the remediation lifecycle.

## 3. Core user outcome

The client should be able to say:

> High-risk CodeQL findings no longer pile up silently. Each finding is automatically triaged, acted on, routed, tracked, and either resolved or escalated within SLA.

---

## 4. Functional requirements

### FR-1: Ingest CodeQL findings

The system must accept CodeQL findings as input.

**Minimum required fields:**

- finding ID
- rule name
- CWE or vulnerability class
- severity
- repository
- file path
- line number
- description
- timestamp

**Implication:**

- CodeQL remains the detection source of truth
- the system does not need to replace scanning

### FR-2: Normalize findings into a standard internal schema

The system must convert raw scanner output into a normalized finding object that downstream components can process consistently.

**The schema should support:**

- vulnerability metadata
- code location
- decision status
- owner
- remediation state
- timestamps
- audit history

*Subtext addressed: scanner output alone is not operationally actionable.*

### FR-3: Apply a policy-based decision engine

The system must determine the appropriate next action for each finding using explicit policy rules.

**Supported actions:**

| Action | Meaning |
|---|---|
| `AUTO_REMEDIATE` | Fix automatically, standard code review |
| `REMEDIATE_WITH_REVIEW` | Fix automatically, require security reviewer |
| `ESCALATE` | No auto-fix; route to owning team + security |
| `DEFER` | Low-risk; log and revisit later |

**Decision inputs should include:**

- severity
- vulnerability type
- fix confidence
- exploitability or contextual risk
- policy allowlist / denylist
- SLA tier

*Subtext addressed: not every issue should be auto-fixed. Trust depends on bounded autonomy.*

### FR-4: Restrict autonomous remediation to approved issue classes

The system must only auto-remediate vulnerability classes explicitly approved by policy.

**Examples:**

| Class | Action |
|---|---|
| SQL injection with known safe pattern | AUTO_REMEDIATE |
| Hardcoded secrets, dependency misuse | REMEDIATE_WITH_REVIEW |
| Auth logic flaws, business logic vulns | ESCALATE only |

*Subtext addressed: uncontrolled autonomy will destroy trust. Safe automation requires policy guardrails.*

### FR-5: Invoke Devin as the remediation execution engine

For findings eligible for automated remediation, the system must call Devin through the Devin API to generate a candidate fix.

**Devin's task should include:**

- analyze the vulnerable code
- produce a patch
- generate or update relevant tests
- explain the proposed remediation
- return structured output for PR creation

*Subtext addressed: Devin must be central to the remediation loop, not peripheral.*

### FR-6: Create a pull request for remediation output

The system must create a PR or PR-equivalent artifact for each successful automated remediation.

**The PR should include:**

- summary of the issue
- remediation explanation
- affected files
- test evidence
- finding metadata
- policy decision metadata

*Subtext addressed: "actual remediated code" is the target, not just a recommendation.*

### FR-7: Route the PR to the correct stakeholders

The system must assign or notify the appropriate people for review.

**Minimum routing targets:**

- code owner or engineering owner
- security reviewer when policy requires it
- optional engineering manager on escalation

*Subtext addressed: "the right people know what's happening at each step." Ownership must be explicit, not implied.*

### FR-8: Maintain explicit state transitions

Each finding must progress through a defined lifecycle.

**Minimum states:**

```
DETECTED → TRIAGED → REMEDIATION_IN_PROGRESS → PR_OPEN → UNDER_REVIEW → MERGED → CLOSED
                   ↘ ESCALATED
                   ↘ DEFERRED
```

**Rules:**

- each finding must have exactly one current state
- each transition must be timestamped
- invalid transitions should be rejected

*Subtext addressed: hidden stalling is the current failure mode.*

### FR-9: Enforce follow-through with time-based automation

The system must detect inactivity and automatically advance the process through reminders or escalation.

**Minimum enforcement examples:**

| Condition | Action |
|---|---|
| No review after 24 hours | Remind owner |
| No action after 48 hours | Escalate to manager |
| SLA breach | Mark non-compliant, notify stakeholders |

*Subtext addressed: "without anyone having to babysit the process." The system must self-advance when humans do not act.*

### FR-10: Support escalation paths

The system must escalate unresolved findings or stalled PRs according to policy.

**Escalation targets may include:**

- security lead
- engineering manager
- compliance owner

**Escalation conditions may include:**

- high severity unresolved
- review inactivity
- repeated rejection
- SLA breach

*Subtext addressed: the system needs authority, not just visibility.*

### FR-11: Produce an auditable remediation trail

The system must persist an audit log for each finding from ingestion through closure.

**Audit records should include:**

- original finding metadata
- policy decision
- Devin invocation
- remediation artifact
- PR status
- reviewer actions
- escalation events
- timestamps
- final outcome

*Subtext addressed: audit failure is part of the problem statement. Evidence is a required output, not a nice-to-have.*

### FR-12: Provide status visibility

The system should provide a dashboard, report, or equivalent interface showing remediation status across findings.

**Minimum visibility:**

- open findings by state
- auto-remediated findings
- escalated findings
- SLA breaches
- merged fixes
- deferred items by reason

*Subtext addressed: stakeholders need operational awareness without manual digging.*

---

## 5. Non-functional requirements

### NFR-1: Policy-bounded autonomy

The system must never auto-remediate outside explicitly approved policy categories.

### NFR-2: Explainability

Every automated action must include a machine-readable and human-readable explanation of:

- why the action was taken
- what the system changed
- what remains for a reviewer

### NFR-3: Traceability

Every major action must be logged with timestamps and identifiers.

### NFR-4: Human override

Humans must be able to reject, defer, or escalate a finding even after automated action is initiated.

### NFR-5: Safe failure mode

If remediation cannot be completed confidently, the system must fail into review or escalation, not silent dismissal.

### NFR-6: Low operational overhead

The system should reduce manual coordination rather than create more dashboards, tickets, or orphaned PRs.

### NFR-7: Extensibility

The policy engine should allow new vulnerability classes and remediation rules to be added without redesigning the system.

---

## 6. Implied governance requirements

*This is the important layer most people would miss.*

### GR-1: Clear ownership at every stage

At any point, each finding must have a current responsible party: system, developer, reviewer, manager, or security.

### GR-2: Separation of authority and execution

- CodeQL detects
- Policy decides
- Devin executes
- Humans approve or escalate

### GR-3: No silent backlog accumulation

The system must not allow high-risk findings to remain unowned or inactive beyond defined thresholds.

### GR-4: Review is mandatory where policy requires it

Automated remediation must not bypass human review for classes deemed sensitive.

### GR-5: Evidence must be inspection-ready

A client auditor or security leader should be able to inspect how a finding moved from detection to closure.

---

## 7. Out-of-scope requirements

The first version does not need to:

- replace CodeQL
- solve every vulnerability class
- merge code automatically without review
- fully integrate with every enterprise notification system
- prove zero false positives
- autonomously remediate business-logic security flaws

*This helps position the demo as disciplined rather than overclaimed.*

---

## 8. Acceptance criteria

A successful demo should show at least one finding moving through the full governed lifecycle:

1. CodeQL finding is ingested
2. Policy engine classifies it
3. Eligible finding is sent to Devin
4. Devin returns a remediation artifact
5. System creates a PR
6. PR is assigned to correct reviewer(s)
7. System records state transitions
8. Inactivity or completion updates the lifecycle
9. Audit report reflects the full chain

**Stretch acceptance:**

- a second finding that is escalated instead of auto-fixed
- dashboard showing both outcomes

---

## 9. Hidden success criteria from the assignment

*This is the real evaluator rubric hiding in the prompt.*

The submission should demonstrate that you understand:

| ID | Criterion |
|---|---|
| HS-1 | This is not just an AI coding demo — it is a workflow and control-plane problem |
| HS-2 | More PRs is not success — resolved and auditable findings is success |
| HS-3 | Devin should sit inside a governed loop, not just be a generic coding assistant |
| HS-4 | Trust is a design requirement — the system must show why engineers would not reject it outright |
| HS-5 | The solution must reflect enterprise realities — ownership, review, escalation, and compliance are first-class requirements |

---

## 10. Condensed requirements summary

> Build a policy-governed remediation system that ingests CodeQL findings, decides whether they should be auto-remediated or escalated, uses Devin to generate fixes for approved issue classes, routes changes to the correct reviewers, enforces follow-through through reminders and escalation, and records the full lifecycle for auditability.

---

## Implementation status

| Requirement | Status | Module |
|---|---|---|
| FR-1: Ingest findings | Implemented | `sage/pipeline/ingest.py`, `sage/pipeline/sarif.py` |
| FR-2: Normalize schema | Implemented | `sage/pipeline/ingest.py` (Alert dataclass) |
| FR-3: Policy decision engine | Implemented | `sage/pipeline/policy.py`, `sage/pipeline/triage.py` |
| FR-4: Restrict auto-remediation | Implemented | Policy registry with 4 actions |
| FR-5: Devin execution | Implemented | `sage/integrations/devin_client.py` (stub + real API) |
| FR-6: Create PR | Implemented | `sage/integrations/pr_client.py` (stub + gh CLI) |
| FR-7: Route to stakeholders | Implemented | `sage/integrations/pr_client.py` (reviewer assignment + labels), `sage/integrations/notify.py` (team routing) |
| FR-8: State transitions | Implemented | `sage/pipeline/store.py` (lifecycle states + events), `sage/cli/override.py` (validated transitions) |
| FR-9: Enforcement | Implemented | `sage/pipeline/enforcement.py` (SLA + escalation), `sage/cli/enforce.py` (cron-ready runner) |
| FR-10: Escalation paths | Implemented | `sage/integrations/notify.py` (escalation notifications), `sage/cli/enforce.py` (auto-escalate on SLA breach) |
| FR-11: Audit trail | Implemented | `sage/pipeline/store.py` (events table, enforcement + override logging) |
| FR-12: Status visibility | Implemented | `sage/integrations/dashboard.py` (single + aggregate) |
| NFR-1–3 | Implemented | Policy-bounded, explainable, traceable |
| NFR-4: Human override | Implemented | `sage/cli/override.py` (merge, close, reject, defer, escalate, reopen + transition validation) |
| NFR-5–7 | Implemented | Safe failure, low overhead, extensible |
| GR-1–5 | Implemented | Ownership, separation, evidence |
