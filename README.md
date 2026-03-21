# SAGE

CodeQL flags dozens of new issues every week and they just pile up. Security files them, engineering ignores them, auditors flag the backlog. SAGE makes that operationally impossible.

```bash
python run_interactive.py    # open http://localhost:8000
```

Three vulnerable code blocks. Click one. Watch the policy engine decide, the execution layer fix it, and the routing panel show exactly which team, channel, and reviewer gets notified.

Built as a technical demonstration for MedSecure's security remediation challenge.

---

## How it works

SAGE is a control plane between CodeQL and your engineering team. Findings go in. Fixed, reviewed, auditable outcomes come out.

```
Detection → Decision → Execution → Review → Enforcement → Evidence
  CodeQL     Policy     Devin      GitHub    SLA tracking   Audit log
             Engine     + local    + owners  + escalation
```

**Two execution paths, split by policy:**

| Policy | Execution | Example |
|---|---|---|
| `AUTO_REMEDIATE` | Local handler — instant fix, standard review | SQL injection (HIGH confidence) |
| `REMEDIATE_WITH_REVIEW` | Devin API — analyzes code, plans fix, opens PR, security reviewer required | XSS, command injection (MEDIUM confidence) |
| `ESCALATE` | No auto-fix — routed to owning team + security | Hardcoded credentials, auth flaws |
| `DEFER` | Logged, revisited later | Low-risk findings |

The local handler is the fast path for well-understood patterns. Devin is the execution engine for everything that needs analysis. Policy decides which path — not the developer, not the tool.

---

## Demo

**Interactive** (recommended):
```bash
python run_interactive.py
```

**Full lifecycle** (5 phases — ingest, enforce, override, metrics, dashboard):
```bash
python run_full_demo.py
```

<details>
<summary><strong>All commands</strong></summary>

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

</details>

---

## Enforcement

Two layers, both with teeth.

**Per-finding SLA** — `run_enforce.py` on hourly cron:

| Condition | Action |
|---|---|
| No review after 24h | Remind owner via team channel |
| No action after 48h | Escalate to `#engineering-leads` |
| SLA breach | Notify `#security-escalations`, auto-escalate |

**Aggregate KPI** — when metrics degrade, the system acts:

| KPI crosses threshold | System action |
|---|---|
| SLA compliance < 80% | Escalate all at-risk findings |
| Lifecycle completion < 80% | Notify security lead |
| PR merge rate < 60% | Flag trust issue |
| Unowned findings > 0 | Auto-assign to default team |

KPIs aren't a dashboard. They drive system behavior. Thresholds configured in `sage.config.json`.

---

## KPIs

```
$ python run_metrics.py

  OUTCOME METRICS
  SLA Compliance Rate:       33% (1/3 high-risk resolved within SLA)
  Mean Time to Remediation:  0m
  Aging High-Risk Backlog:   2 open (2 within SLA, 0 breached)

  SYSTEM EFFECTIVENESS
  Auto-Remediation Rate:     100% (3/3 resolved via automation)
  PR Merge Rate:             33% (1/3 PRs merged)

  GOVERNANCE
  Unowned Findings:          PASS
  SLA Breaches:              PASS
  Lifecycle Completion:      33% (1/3 reached terminal state)
```

9 metrics across three categories: outcome, system effectiveness, governance. All computed from `pipeline.db`.

---

## Integration

| System | How to enable | What happens |
|---|---|---|
| Devin | `DEVIN_MODE=real` + `DEVIN_API_KEY` | Creates sessions, polls completion, extracts plan + PR + insights |
| GitHub | `PR_MODE=github` | Branch → commit → push → PR with reviewers + labels via `gh` |
| Slack | `NOTIFY_MODE=slack` + `SLACK_WEBHOOK_URL` | Block Kit messages to team channels + escalation channels |

All fall back to stub mode when env vars aren't set. `python run_check.py` validates connectivity.

Real Devin sessions create branches in this repo — see `devin/*` branches for proof of live API integration.

<details>
<summary><strong>Architecture details</strong></summary>

```
   ┌──────────┐      ┌──────────────┐      ┌──────────┐      ┌─────────────┐
   │  CodeQL  │ ───▶ │ Policy Engine│ ───▶ │  Devin   │ ───▶ │   GitHub PR │
   │ Findings │      │ Risk + Fix   │      │ Remediate│      │ + Reviewers │
   └──────────┘      │ Confidence   │      └──────────┘      └─────────────┘
                     └──────┬───────┘                               │
                            │                                       ▼
                            │                              ┌─────────────────-┐
                            ├──────────────▶               │ Enforcement Loop │
                            │                              │ Remind / Escalate│
                            ▼                              └────────-┬────────┘
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

| Layer | Module |
|---|---|
| Detection | `pipeline/ingest.py`, `pipeline/sarif.py` |
| Decision | `pipeline/policy.py`, `pipeline/triage.py` |
| Execution | `integrations/devin_client.py`, `pipeline/execute.py` |
| Review | `integrations/pr_client.py`, `integrations/notify.py` |
| Enforcement | `pipeline/enforcement.py`, `run_enforce.py` |
| Evidence | `pipeline/store.py`, `pipeline/output.py` |
| Override | `run_override.py` |

**Policy table:**

| CWE | Name | Action | Confidence | SLA |
|---|---|---|---|---|
| CWE-89 | SQL Injection | `AUTO_REMEDIATE` | HIGH | 24h |
| CWE-79 | Cross-Site Scripting | `REMEDIATE_WITH_REVIEW` | MEDIUM | 24h |
| CWE-78 | Command Injection | `REMEDIATE_WITH_REVIEW` | MEDIUM | 24h |
| CWE-798 | Hardcoded Credentials | `ESCALATE` | LOW | 12h |
| CWE-287 | Improper Authentication | `ESCALATE` | LOW | 12h |

**Lifecycle:**

```
DETECTED → TRIAGED → REMEDIATED → UNDER_REVIEW → MERGED → CLOSED
                   ↘ ESCALATED (policy, SLA breach, or KPI trigger)
                   ↘ DEFERRED (low-risk)
```

Every transition is timestamped. Invalid transitions are rejected. `run_override.py` provides human merge/reject/defer/escalate/reopen.

**CI/CD** — `.github/workflows/sage.yml`:
- Triggers on CodeQL completion, hourly cron, or manual dispatch
- Fetches alerts via `gh api`, runs pipeline, enforces KPIs, uploads artifacts

</details>

---

## Tests

```bash
python -m pytest tests/ -v    # 86 tests
```

Covers: ingest, triage, policy, execute (3 CWEs × 4 SQL patterns), validate, store, enforcement (SLA + KPI-driven), notifications, escalation routing, dashboard, and human overrides.

---

## Docs

| | |
|---|---|
| [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md) | 12 functional, 7 non-functional, 5 governance requirements |
| [docs/KPIS.md](docs/KPIS.md) | 9 KPIs mapped to the system components that drive them |
