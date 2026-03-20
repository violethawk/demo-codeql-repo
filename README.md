# SAGE

**Security Automation & Governance Engine**

CodeQL flags dozens of new issues every week and they just pile up. Security files them, engineering ignores them, auditors flag the backlog. SAGE makes that operationally impossible.

```
python run_interactive.py
# Open http://localhost:8000 — click a vulnerability, watch it get fixed
```

---

## What it does

SAGE sits between CodeQL and your engineering team. Findings go in. Fixed, reviewed, auditable outcomes come out.

```
Detection → Decision → Execution → Review → Enforcement → Evidence
  CodeQL     Policy     Devin      GitHub    SLA tracking   Audit log
             Engine     + local    + owners  + escalation
```

Two execution paths, split by policy:

| Policy action | Execution | What happens |
|---|---|---|
| `AUTO_REMEDIATE` | Local handler | Instant fix, standard code review. For well-understood patterns (SQL injection). |
| `REMEDIATE_WITH_REVIEW` | Devin API | Devin analyzes the code, produces a remediation plan, implements the fix, opens a PR. Security reviewer required. |
| `ESCALATE` | None | Finding routed to owning team + security. No auto-fix attempted. |
| `DEFER` | None | Low-risk. Logged, revisited later. |

The local handler is the fast path for HIGH confidence fixes. Devin is the execution engine for everything that needs analysis. Policy decides which path runs — not the developer, not the tool.

---

## Demo

### Interactive (recommended)

```bash
python run_interactive.py
```

Three vulnerable code blocks. Click one. Watch SAGE process it — policy decision, execution, validation, reviewer assignment, notification routing. The code transforms from vulnerable to fixed. The routing panel shows who gets notified, who reviews the PR, and what happens if they don't.

- **CWE-89 (SQL Injection)** → AUTO_REMEDIATE → instant local fix
- **CWE-79 (XSS)** → REMEDIATE_WITH_REVIEW → Devin analyzes and fixes
- **CWE-78 (Command Injection)** → REMEDIATE_WITH_REVIEW → Devin analyzes and fixes

### Full lifecycle

```bash
python run_full_demo.py
```

Five-phase demo: ingest 3 findings → enforce KPIs → merge one via human override → display all 9 KPIs → generate governance dashboard.

### Individual commands

```bash
python run_demo.py                              # single alert
python run_batch.py fixtures/                   # batch processing
python run_sarif.py fixtures/sample_scan.sarif  # real CodeQL SARIF input
python run_metrics.py                           # all 9 KPIs
python run_enforce.py                           # SLA + KPI enforcement
python run_override.py demo-001 merge           # human override
python run_override.py demo-001 status          # audit trail
python run_check.py                             # validate deployment
```

---

## Architecture

```
   ┌──────────┐      ┌──────────────┐      ┌──────────┐      ┌─────────────┐
   │  CodeQL  │ ───▶ │ Policy Engine│ ───▶ │  Devin   │ ───▶ │   GitHub PR │
   │ Findings │      │ Risk + Fix   │      │ Remediate│      │ + Reviewers │
   └──────────┘      │ Confidence   │      └──────────┘      └─────────────┘
                     └──────┬───────┘                               │
                            │                                       ▼
                            │                              ┌─────────────────┐
                            ├──────────────▶               │ Enforcement Loop│
                            │                              │ Remind / Escalate│
                            ▼                              └────────┬────────┘
                    ┌──────────────┐                                 │
                    │ Escalation   │ ◀───────────────────────────────┘
                    │ Security / EM│
                    └──────┬───────┘
                           ▼
                    ┌──────────────┐
                    │  Audit Trail │
                    │ Evidence Log │
                    └──────────────┘
```

| Layer | Module | What it does |
|---|---|---|
| Detection | `pipeline/ingest.py`, `pipeline/sarif.py` | Ingest findings from JSON fixtures or CodeQL SARIF |
| Decision | `pipeline/policy.py`, `pipeline/triage.py` | Classify each finding → one of four governance actions |
| Execution | `integrations/devin_client.py`, `pipeline/execute.py` | Devin API for REMEDIATE_WITH_REVIEW; local handlers for AUTO_REMEDIATE |
| Review | `integrations/pr_client.py`, `integrations/notify.py` | Create PRs via `gh` CLI, assign reviewers, route notifications by team |
| Enforcement | `pipeline/enforcement.py`, `run_enforce.py` | Per-finding SLA tracking + aggregate KPI-driven escalation |
| Evidence | `pipeline/store.py`, `pipeline/output.py` | SQLite with WAL, lifecycle states, immutable event log |
| Override | `run_override.py` | Humans can merge, reject, defer, escalate, reopen — with validated transitions |

---

## Policy

| CWE | Name | Action | Confidence | SLA | Execution |
|---|---|---|---|---|---|
| CWE-89 | SQL Injection | `AUTO_REMEDIATE` | HIGH | 24h | Local handler |
| CWE-79 | Cross-Site Scripting | `REMEDIATE_WITH_REVIEW` | MEDIUM | 24h | Devin |
| CWE-78 | Command Injection | `REMEDIATE_WITH_REVIEW` | MEDIUM | 24h | Devin |
| CWE-798 | Hardcoded Credentials | `ESCALATE` | LOW | 12h | None |
| CWE-287 | Improper Authentication | `ESCALATE` | LOW | 12h | None |

Adding a CWE: add to `REMEDIATION_POLICIES` in `pipeline/policy.py`. If auto-fixable, register a handler in `pipeline/execute.py`. If not, the system routes to ESCALATE automatically.

---

## Enforcement

Two layers, both with teeth:

### Per-finding SLA

| Condition | Action |
|---|---|
| No review after 24h | Remind owner via team Slack channel |
| No action after 48h | Escalate to `#engineering-leads` |
| SLA breach | Notify `#security-escalations`, auto-escalate state |

### Aggregate KPIs

KPIs aren't decorative. When they degrade past thresholds, the system acts:

| KPI | Threshold | System action |
|---|---|---|
| SLA compliance rate | < 80% | Escalate all at-risk findings |
| Lifecycle completion | < 80% | Notify security lead |
| PR merge rate | < 60% | Flag trust degradation to security lead |
| Unowned findings | > 0 | Auto-assign to default team |
| SLA breaches | > 0 | Auto-escalate all breached findings |

Thresholds are configured in `sage.config.json`. Run `python run_enforce.py` on a cron.

---

## Lifecycle

```
DETECTED → TRIAGED → REMEDIATED → UNDER_REVIEW → MERGED → CLOSED
                   ↘ ESCALATED (policy or SLA breach or KPI trigger)
                   ↘ DEFERRED (low-risk, revisit later)
```

Every transition is timestamped in an immutable `events` table. `run_override.py` validates transitions — you can't merge from DEFERRED or close from DETECTED.

---

## KPIs

9 metrics computed from `pipeline.db`, displayed by `run_metrics.py`:

**Outcome**: SLA compliance rate, mean time to remediation, aging high-risk backlog (within SLA / at risk / breached)

**System**: Auto-remediation rate, PR merge rate (trust metric), time to first action

**Governance**: Unowned findings (target: 0), SLA breach count (target: 0), lifecycle completion rate

```
$ python run_metrics.py

  OUTCOME METRICS
  SLA Compliance Rate:       33% (1/3 high-risk resolved within SLA)
  Mean Time to Remediation:  0m
  Aging High-Risk Backlog:   2 open (2 within SLA, 0 at risk, 0 breached)

  GOVERNANCE
  Unowned Findings:          PASS
  SLA Breaches:              PASS
  Lifecycle Completion:      33% (1/3 reached terminal state)
```

---

## Integration

| System | Env var | Behavior |
|---|---|---|
| Devin | `DEVIN_MODE=real` + `DEVIN_API_KEY` | Creates sessions, polls completion, extracts PR + plan + insights |
| GitHub | `PR_MODE=github` | Branch → commit → push → PR via `gh` CLI with reviewers + labels |
| Slack | `NOTIFY_MODE=slack` + `SLACK_WEBHOOK_URL` | Block Kit messages with status, CWE, team, PR button |

All integrations fall back to stub mode (JSON artifacts on disk) when env vars aren't set. `run_check.py` validates connectivity before deployment.

Reviewer and channel mappings are in `sage.config.json`.

---

## CI/CD

`.github/workflows/sage.yml` — triggers on CodeQL completion, hourly cron, or manual dispatch:

- **remediate**: Fetch CodeQL alerts via `gh api`, run pipeline, enforce, display metrics
- **enforce**: Hourly SLA + KPI enforcement checks
- **metrics**: On-demand KPI display
- **check**: Validate configuration and connectivity

---

## Tests

```bash
python -m pytest tests/ -v    # 67 tests
```

Covers: ingest, triage, policy, execute (3 CWEs × multiple patterns), validate, store, enforcement (SLA + KPI-driven), notifications, escalation routing, dashboard, and human overrides.

---

## Documentation

| Document | What's in it |
|---|---|
| [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md) | 12 functional requirements, 7 non-functional, 5 governance, acceptance criteria |
| [docs/KPIS.md](docs/KPIS.md) | 9 KPIs mapped to the system components that drive them |
