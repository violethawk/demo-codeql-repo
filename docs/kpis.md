# SAGE Success Metrics Framework

**Security Automation & Governance Engine**

---

## 1. Objective

Measure whether SAGE successfully converts security findings into resolved, auditable outcomes while reducing backlog and enforcing SLAs.

---

## 2. Outcome Metrics (Primary)

### 2.1 SLA Compliance Rate

| | |
|---|---|
| **Definition** | % of high-risk findings resolved within SLA |
| **Formula** | `(# resolved within SLA) / (total high-risk findings)` |
| **Why it matters** | Direct audit signal. Proves enforcement works. |
| **Driven by** | Enforcement layer |

### 2.2 Severity-Weighted MTTR

| | |
|---|---|
| **Definition** | Average time to remediation weighted by severity |
| **Why it matters** | Captures real risk reduction, not just activity |
| **Driven by** | Devin + routing + review speed |

### 2.3 Aging High-Risk Backlog

| | |
|---|---|
| **Definition** | Count of unresolved high-risk findings segmented by age |
| **Why it matters** | Shows whether risk is accumulating |
| **Driven by** | Policy + throughput |

**Age buckets:**

| Bucket | Status |
|---|---|
| < 24h | Within SLA |
| 24–72h | At risk |
| > 72h | SLA breach |

---

## 3. System Effectiveness Metrics (Secondary)

### 3.1 Auto-Remediation Rate

| | |
|---|---|
| **Definition** | % of findings resolved via Devin |
| **Why it matters** | Measures automation coverage |
| **Driven by** | Policy engine + Devin execution |

### 3.2 PR Merge Rate

| | |
|---|---|
| **Definition** | % of system-generated PRs that are merged |
| **Why it matters** | Trust metric — if engineers reject auto-fixes, the system isn't working |
| **Driven by** | Fix quality + trust |

### 3.3 Time to First Action

| | |
|---|---|
| **Definition** | Time from detection to PR opened or escalation |
| **Why it matters** | Measures elimination of dead time between detection and response |
| **Driven by** | Pipeline throughput + policy speed |

---

## 4. Governance Metrics (Critical)

### 4.1 Unowned Findings

| | |
|---|---|
| **Definition** | Count of findings with no assigned responsible party |
| **Target** | 0 |
| **Driven by** | Routing + state model |

### 4.2 SLA Breach Count

| | |
|---|---|
| **Definition** | Number of findings exceeding their SLA deadline |
| **Target** | Minimize to zero |
| **Driven by** | Enforcement layer |

### 4.3 Lifecycle Completion Rate

| | |
|---|---|
| **Definition** | % of findings that reach a terminal state: MERGED or ESCALATED |
| **Why it matters** | Proves nothing falls through the cracks |
| **Driven by** | Enforcement + state transitions |

---

## 5. Metrics → System Components

Every metric is driven by a specific architectural layer. This proves the system was designed for measurable outcomes, not just activity.

| Metric | Driven by |
|---|---|
| MTTR | Devin + routing + review speed |
| SLA compliance | Enforcement layer |
| PR merge rate | Fix quality + trust |
| Backlog aging | Policy + throughput |
| Unowned findings | Routing + state model |
| Auto-remediation rate | Policy engine + Devin |
| Time to first action | Pipeline throughput |
| Lifecycle completion | Enforcement + state transitions |

---

## 6. Implementation status

All metrics are computable from the existing `pipeline.db` schema:

| Metric | Query source | Available |
|---|---|---|
| SLA compliance | `alerts.sla_deadline` vs `alerts.updated_at` | Yes |
| MTTR | `alerts.created_at` vs terminal state timestamp in `events` | Yes |
| Aging backlog | `alerts.created_at` + `alerts.lifecycle_state` | Yes |
| Auto-remediation rate | `alerts.policy_action` = `AUTO_REMEDIATE` | Yes |
| PR merge rate | `alerts.lifecycle_state` = `MERGED` / total PRs | Yes |
| Time to first action | `events` table: `created` → first `state_change` | Yes |
| Unowned findings | `alerts.owner_team` = empty + non-terminal state | Yes |
| SLA breach count | `alerts` where `sla_deadline` < now + non-terminal | Yes |
| Lifecycle completion | `alerts.lifecycle_state` in (`MERGED`, `ESCALATED`, `CLOSED`) | Yes |

`sage/cli/metrics.py` surfaces the core metrics. `sage/cli/enforce.py` acts on SLA breaches. The aggregate dashboard visualizes disposition and team breakdowns.
