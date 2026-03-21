# SAGE Demo Script

**~7 minutes. Framed as a presentation back to MedSecure's VP of Engineering and their team after a discovery call.**

Try it yourself: **[live demo](https://demo-codeql-repo.onrender.com/)** (no setup required).

---

## Setup

```bash
python -m sage interactive
# Open http://localhost:8000
```

If using real Devin:
```bash
DEVIN_MODE=real DEVIN_API_KEY=your-key python -m sage interactive
```

> **Stub vs real mode:** Without `DEVIN_API_KEY`, Devin cards (XSS, command injection) run in stub mode — the fix is simulated locally. A banner at the top of the dashboard notes this and links to real Devin branches as proof of live integration. The demo flow is identical either way.

---

## Script

### 1. Opening — Restate the Problem (30 seconds)

> "Thanks for the time last week. I want to play back what I heard and show you what we built."
>
> "Your problem isn't detection — CodeQL is already finding the vulnerabilities. The problem is the gap between detection and resolution. Findings pile up because they're not sprint work. Your security team files them, your engineers deprioritize them, and last audit you got flagged for the backlog. Nobody's closing the loop."
>
> "What I built is called SAGE — Security Automation & Governance Engine. It sits between CodeQL and your engineering workflow and closes that loop: triages findings, fixes what it can, escalates what it can't, enforces SLAs, and gives your security team an audit trail that proves follow-through."

---

### 2. Why Devin — Not Just Another Coding Agent (60 seconds)

*This section is a talking point — no clicking yet.*

> "Before I show the demo, I want to explain why Devin is the right execution engine here, because you could reasonably ask: why not Copilot, or Cursor, or any other AI coding tool?"
>
> "The difference is workflow ownership. A coding assistant suggests a patch — an engineer still has to prompt it, evaluate the output, create the branch, open the PR, assign reviewers, and follow up. That's the work your engineers are already skipping."
>
> "Devin owns the full workflow. SAGE gives Devin a session with the vulnerability context — the CWE, the file, the vulnerable code. Devin analyzes the surrounding code, produces a remediation plan, implements the fix, writes tests, opens the PR, and returns structured output — root cause, changes made, reviewer notes. Your engineers interact with a pull request, not a security ticket."
>
> "And critically, Devin operates inside a policy-controlled loop. It doesn't decide what to fix or when — the policy engine does. Devin is the execution layer, not the decision-maker. That separation matters for governance."

---

### 3. Policy Design — How Decisions Are Made (15 seconds)

> "How does the system decide what gets auto-fixed versus what gets routed to humans? Routing decisions are anchored to CISA's SSVC framework — exploitation likelihood, impact, and fix confidence — so your security team can audit every triage call. Let's look at how that policy engine actually plays out for an engineer on a Tuesday afternoon."

---

### 4. Interactive Demo — Three Governance Paths (3 minutes)

*Open the dashboard. Five vulnerability cards are visible, all red.*

#### Click CWE-89 — SQL Injection (40 seconds)

> "SQL injection first — the fast path."

*Click the card. Wait for the animation to complete.*

> "Fix confidence is HIGH — the canonical fix is parameterized queries. Single file, deterministic, no behavioral regression. The local handler fixes it in about one second."

Point out:
- Code transforms from red (vulnerable) to green (fixed)
- Routing panel: notification to `#backend-security`, two backend engineers assigned as reviewers
- Escalation path shown: 24h no review → remind owner, 48h → escalate to `#engineering-leads`

> "Your engineers get a PR in their normal workflow. They review code, not a security ticket. If they don't review it within 24 hours, the system reminds them. At 48 hours, it escalates to their manager."

#### Click CWE-79 — Cross-Site Scripting (60 seconds)

> "XSS is different. The safe encoding depends on output context — HTML body, attribute, JavaScript. Fix confidence drops to MEDIUM. This is where Devin comes in."

*Click the card. Let the Devin execution panel animate.*

> "Devin creates a session, analyzes the vulnerable code, produces a remediation plan, implements the fix, and opens a PR. A security reviewer is required — that's policy-enforced, not optional."

Point out:
- Different execution path — Devin API, not local handler
- Security reviewer added alongside the frontend engineer
- Notification goes to `#frontend-security` — different team, different channel
- PR includes remediation plan, root cause analysis, and reviewer notes

> "Notice what the engineer didn't have to do here. They didn't log into SAGE. They didn't look at CodeQL. Devin handed them a standard GitHub PR with the context they need. We're meeting them where they already work."
>
> "We have three real Devin-generated PRs merged in this repo — PRs 7, 11, and 12. The banner links to them. Devin analyzed the code, planned the fix, and opened the PRs autonomously."

#### Click CWE-798 — Hardcoded Credentials (30 seconds)

> "Not everything should be auto-fixed. Hardcoded credentials require secret rotation and vault integration — cross-service change, high regression risk. Fix confidence is LOW. The system escalates."

*Click the card. Let it resolve.*

> "No PR generated. The finding goes directly to the owning team and security with a 12-hour SLA. The system knows its limits."

Point out:
- Status: ESCALATED, not FIXED
- Routing: `#security-escalations` — different channel
- Three governance paths demonstrated: deterministic fix, AI-assisted fix, route-to-humans

---

### 5. KPIs and Enforcement — Nothing Stalls Silently (75 seconds)

*Point to the KPI panel at the bottom of the dashboard.*

> "This is the part that directly addresses your audit problem. SAGE tracks nine KPIs, and — this is the key part — the enforcement layer *acts* on them. These aren't dashboards. They're triggers."

Highlight two or three:
- **SLA Compliance Rate** — if this drops below 80%, the system automatically escalates all at-risk findings
- **Fix Rate** — PRs merged vs. opened. Below 60% signals engineers are rejecting automated fixes — a trust problem the system flags
- **Unowned Findings** — target is zero. If any finding has no owner, the system auto-assigns it

> "Enforcement runs on two layers. Per-finding: every finding has an SLA deadline. At 24 hours, the owner gets a Slack reminder. At 48 hours, it escalates to engineering leads. On SLA breach, security escalations gets notified."
>
> "And aggregate: the system evaluates KPI thresholds hourly. If compliance drops, it doesn't just report — it finds every at-risk finding and escalates them. If findings are unowned, it auto-assigns. The enforcement layer closes the gap that your audit flagged."
>
> "Every action — every triage decision, every fix, every escalation, every human override — is recorded in an immutable audit trail with a timestamp, actor, and reason. When your compliance team asks 'what happened to finding X,' the answer is a query, not a meeting."

---

### 6. Next Steps (60 seconds)

> "Here's what I'd propose."

**Immediate (weeks 1-2):**

> "We start with your top five CWEs by volume. We configure SAGE's policy engine for your environment — your teams, your Slack channels, your review owners — and connect it to your existing CodeQL output. We run it in dry-run mode first so your security team can validate the triage decisions before anything auto-fixes."
>
> "The goal for week one is: your security team sees every new CodeQL finding get triaged and routed automatically, with the right SLA. Week two, we turn on auto-remediation for the high-confidence patterns and let Devin start opening PRs for the medium-confidence ones."

**Longer-term (month 2+):**

> "Once the core pipeline is running, there are three natural extensions."
>
> "First, expanding CWE coverage. The policy registry is designed for this — adding a new vulnerability class is a four-step process: evaluate it against SSVC, assess fix confidence, add the policy entry, register the handler. Your security team can own this."
>
> "Second, integration depth. Right now SAGE supports Slack, GitHub, and Devin. But the notification and escalation layers are pluggable — Jira, PagerDuty, whatever your incident workflow uses. And for a HIPAA environment, the immutable audit log can feed directly into your compliance reporting — every finding's full lifecycle is already timestamped and queryable."
>
> "Third, the metrics tell a story over time. MTTR trending down. SLA compliance trending up. Auto-remediation rate climbing as you add CWE handlers. That's the evidence your compliance team wants at the next audit — not a promise that you'll do better, but data showing you already are."

---

### 7. Closing (15 seconds)

> "The bottom line is this: SAGE and Devin let your security team stop acting as a nag, and your engineering team stop treating security as a distraction. You get your compliance, and they get to stay in their flow state. Let's get this connected to a test repo next week and watch the backlog burn down."

---

## Key lines to land

**Non-negotiable — land these even if time runs short:**

1. "Devin owns the full workflow — your engineers interact with pull requests, not security tickets."
2. "The audit trail proves follow-through — a query, not a meeting."

**Land if possible:**

3. "Your problem isn't detection. It's the gap between detection and resolution."
4. "Devin operates inside a policy-controlled loop. It's the execution layer, not the decision-maker."
5. "KPIs drive system behavior, not dashboards. Nothing can silently stall."
6. "Policy decisions are anchored to CISA's SSVC framework — not judgment calls."

---

## Timing breakdown

| Section | Duration | Format |
|---|---|---|
| 1. Opening — Restate the Problem | 30s | Talking point |
| 2. Why Devin — Not Just Another Agent | 60s | Talking point |
| 3. Policy Design — How Decisions Are Made | 15s | Talking point |
| 4. Interactive Demo (3 cards) | 3m | Live demo |
| 5. KPIs and Enforcement | 75s | Live demo + talking |
| 6. Next Steps | 60s | Talking point |
| 7. Closing | 15s | Talking point |
| **Total** | **~7 minutes** | |

> **Contingency:** If the demo runs long, CWE-79 (XSS/Devin card) is the safest cut — CWE-89 and CWE-798 together still show the full governance spectrum (auto-fix → escalate). Mention Devin's role verbally and point to the merged PRs instead.

---

## If you have more time

- Click the remaining cards (CWE-78 command injection, CWE-287 improper auth) to show all five governance paths
- Click Reset, then process all five to show batch behavior and watch KPIs update live
- Run `python -m sage enforce --dry-run` to show enforcement detecting SLA breaches
- Run `python -m sage metrics` to show all 9 KPIs from the CLI
- Run `python -m sage override demo-001 status` to show the immutable audit trail
- Open `artifacts/dashboard_all.html` to show the aggregate governance dashboard
- Show `sage.config.json` to demonstrate how teams, channels, reviewers, and KPI thresholds are configured
