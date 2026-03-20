# SAGE — Security Automation & Governance Engine

> SAGE is a security remediation control plane that converts CodeQL
> findings into fixed, reviewed, and auditable outcomes through
> policy-driven automation and escalation.

## Problem

MedSecure does not have a detection problem. MedSecure has an **authority gap**:

- CodeQL detects issues
- Security files them
- Engineering ignores them
- Audit findings pile up

SAGE closes that gap by introducing a programmable control layer that
decides what happens to each finding, uses Devin to execute remediations
when appropriate, and enforces follow-through until the issue is resolved
or escalated.

```
Detection → Decision → Execution → Review → Enforcement → Evidence
  CodeQL     Policy     Devin      GitHub    Reminders     Audit Log
             Engine                + Owners  + Escalation
```

---

## Quick Start

```bash
# Single alert (CWE-89 SQL injection — auto-remediated)
python run_demo.py

# XSS fixture (CWE-79 — auto-fixed, security reviewer required)
python run_demo.py fixtures/sample_alert_xss.json

# Command injection (CWE-78 — auto-fixed, security reviewer required)
python run_demo.py fixtures/sample_alert_cmdi.json

# Batch: process all fixtures at once
python run_batch.py fixtures/

# Ingest real CodeQL SARIF output
python run_sarif.py fixtures/sample_scan.sarif

# View remediation metrics
python run_metrics.py

# Run enforcement checks (SLA reminders + escalation)
python run_enforce.py

# Human override: merge, close, reject, defer, escalate, reopen
python run_override.py <alert_id> merge --reason "reviewed and approved"
python run_override.py <alert_id> status   # show audit trail

# Open dashboards
open artifacts/dashboard.html       # single-alert view
open artifacts/dashboard_all.html   # aggregate governance view
```

No external dependencies — Python standard library + `gh` CLI only.

---

## Architecture

```
                    SAGE — Security Automation & Governance Engine

   ┌──────────┐      ┌──────────────┐      ┌──────────┐      ┌─────────────┐
   │  CodeQL  │ ───▶ │ Policy Engine│ ───▶ │  Devin   │ ───▶ │   GitHub PR │
   │ Findings │      │ Risk + Fix   │      │ Remediate│      │ + Reviewers │
   └──────────┘      │ Confidence   │      └──────────┘      └─────────────┘
                     └──────┬───────┘                               │
                            │                                       │
                            │                                       ▼
                            │                              ┌─────────────────┐
                            ├──────────────▶               │ Enforcement Loop│
                            │                              │ Remind / Escalate│
                            ▼                              └────────┬────────┘
                    ┌──────────────┐                                 │
                    │ Escalation   │ ◀───────────────────────────────┘
                    │ Security / EM│
                    └──────┬───────┘
                           │
                           ▼
                    ┌──────────────┐
                    │  Audit Trail │
                    │ Evidence Log │
                    └──────────────┘
```

### Layers

| Layer | Module | Purpose |
|-------|--------|---------|
| Detection | `pipeline/ingest.py`, `pipeline/sarif.py` | Ingest CodeQL findings (JSON + SARIF) |
| Decision | `pipeline/policy.py`, `pipeline/triage.py` | Policy-driven governance action per finding |
| Execution | `pipeline/execute.py`, `integrations/devin_client.py` | Devin API + local fix handlers |
| Review | `integrations/pr_client.py`, `integrations/notify.py` | PR creation, reviewer assignment, team notifications |
| Enforcement | `pipeline/enforcement.py`, `run_enforce.py` | SLA tracking, reminders, auto-escalation |
| Evidence | `pipeline/store.py`, `pipeline/output.py` | SQLite persistence, immutable audit trail |
| Visibility | `integrations/dashboard.py`, `run_metrics.py` | HTML dashboards, CLI metrics |
| Override | `run_override.py` | Human reject/defer/escalate/merge with transition validation |

---

## Policy Engine

The policy layer separates signal from action. Each CWE maps to one of four governance actions:

| CWE | Name | Action | Fix Confidence | SLA |
|-----|------|--------|---------------|-----|
| CWE-89 | SQL Injection | `AUTO_REMEDIATE` | HIGH | 24h |
| CWE-79 | Cross-Site Scripting | `REMEDIATE_WITH_REVIEW` | MEDIUM | 24h |
| CWE-78 | OS Command Injection | `REMEDIATE_WITH_REVIEW` | MEDIUM | 24h |
| CWE-798 | Hardcoded Credentials | `ESCALATE` | LOW | 12h |
| CWE-287 | Improper Authentication | `ESCALATE` | LOW | 12h |

| Action | Meaning |
|--------|---------|
| `AUTO_REMEDIATE` | Fix automatically, standard code review |
| `REMEDIATE_WITH_REVIEW` | Fix automatically, security reviewer required |
| `ESCALATE` | No auto-fix; route to owning team + security |
| `DEFER` | Low-risk; log and revisit later |

### Adding a new CWE

1. Add an entry to `REMEDIATION_POLICIES` in `pipeline/policy.py`
2. If the action includes remediation, register a handler in `pipeline/execute.py`
3. If the action is `ESCALATE` or `DEFER`, no code needed — the system routes automatically

---

## Lifecycle

Every finding progresses through explicit states. No finding can silently persist.

```
DETECTED → TRIAGED → REMEDIATED → UNDER_REVIEW → MERGED → CLOSED
                   ↘ ESCALATED (policy or SLA breach)
                   ↘ DEFERRED (low-risk, revisit later)
```

Every transition is timestamped in an immutable `events` table.

### Enforcement

Run `python run_enforce.py` on a schedule (e.g., hourly cron):

| Condition | Action |
|-----------|--------|
| No review after 24h | Remind owner via team channel |
| No action after 48h | Escalate to `#engineering-leads` |
| SLA breach | Flag in `#security-escalations`, auto-escalate state |

### Human Override

```bash
python run_override.py <alert_id> merge      # mark as merged
python run_override.py <alert_id> reject     # reject the fix
python run_override.py <alert_id> defer      # defer to later
python run_override.py <alert_id> escalate   # manual escalation
python run_override.py <alert_id> reopen     # reopen a closed finding
python run_override.py <alert_id> status     # full audit trail
```

All transitions are validated — invalid state changes are rejected.

---

## Integration Modes

### Devin

| Variable | Value | Behavior |
|----------|-------|----------|
| `DEVIN_MODE` | `stub` (default) | Simulates session locally |
| `DEVIN_MODE` | `real` | Calls Devin API, polls for completion |
| `DEVIN_API_KEY` | your key | Required for real mode |

```bash
DEVIN_MODE=real DEVIN_API_KEY=your-key python run_demo.py
```

### GitHub PRs

| Variable | Value | Behavior |
|----------|-------|----------|
| `PR_MODE` | `stub` (default) | Writes JSON artifact |
| `PR_MODE` | `github` | Creates branch, commits, pushes, opens PR via `gh` CLI |

PRs include reviewer assignment and labels (`security-review-required`, `cwe:CWE-89`, etc.).

### Notifications

Team-based routing:

| Team | Channel |
|------|---------|
| backend | `#backend-security` |
| frontend | `#frontend-security` |
| platform | `#platform-security` |
| (unknown) | `#security-alerts` |

Escalations route to `#engineering-leads` and `#security-escalations`.

---

## Success Metrics

See [docs/KPIS.md](docs/KPIS.md) for the full framework.

| Category | Metrics |
|----------|---------|
| Outcome | SLA compliance rate, severity-weighted MTTR, aging backlog |
| System | Auto-remediation rate, PR merge rate, time to first action |
| Governance | Unowned findings (target: 0), SLA breaches, lifecycle completion |

All metrics are computable from the existing `pipeline.db` schema.

---

## Documentation

| Document | Description |
|----------|-------------|
| [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md) | Full requirements spec — 12 FRs, 7 NFRs, 5 governance requirements |
| [docs/KPIS.md](docs/KPIS.md) | Success metrics framework — outcome, system, and governance KPIs |

---

## Tests

```bash
python -m pytest tests/ -v
```

61 tests covering: ingest, triage, policy, execute (3 CWEs), validate, store, enforcement, notifications, escalation routing, dashboard, and human overrides.

---

## Design Principles

**Separation of authority and execution.** Detection systems should not decide. Execution agents should not self-authorize. Policy governs both.

**Policy-bounded autonomy.** The system never auto-remediates outside explicitly approved categories. Uncontrolled autonomy destroys trust.

**Safe failure.** If remediation cannot be completed confidently, the system fails into review or escalation — never silent dismissal.

**Evidence as a first-class output.** The audit layer turns security work from tribal process into inspectable evidence.
