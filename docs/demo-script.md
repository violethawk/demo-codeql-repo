# SAGE Demo Script

**60-90 second walkthrough for Loom or live presentation.**

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

### Opening (10 seconds)

> "The system I built is called SAGE: Security Automation & Governance Engine."
>
> "MedSecure's problem isn't detection — CodeQL already finds the issues. The problem is that findings don't reliably turn into fixed code, and the last audit flagged the backlog. SAGE closes that gap."

### Click CWE-89 — SQL Injection (15 seconds)

> "This SQL injection is a well-understood pattern. The policy engine assigns AUTO_REMEDIATE — a local handler fixes it instantly with a parameterized query. Standard code review. No Devin needed."

*Wait for the animation to finish before speaking to the next point.*

Point out:
- The code transforms from red (vulnerable) to green (fixed)
- The routing panel shows it goes to `#backend-security`
- Two backend engineers are assigned as reviewers

### Click CWE-79 — XSS (20 seconds)

> "Cross-site scripting is different. The fix depends on the output context. The policy engine assigns REMEDIATE_WITH_REVIEW — Devin is the execution engine here. It analyzes the surrounding code, produces a remediation plan, implements the fix, and opens a PR. A security reviewer is required."

*Let the Devin execution panel animate before continuing.*

Point out:
- Different execution path — Devin API, not local handler
- The routing panel shows a security reviewer is added
- The notification goes to `#frontend-security` — different team

> "This is why Devin, not just CodeQL autofix. CodeQL detects the pattern but can't fix it — the safe output encoding depends on rendering context. A generic copilot could suggest a patch, but it doesn't own the workflow. Devin creates a session, analyzes the code, plans the fix, opens the PR, and assigns reviewers."

### Click CWE-798 — Hardcoded Credentials (15 seconds)

> "Not everything should be auto-fixed. Hardcoded credentials are flagged ESCALATE — no automated patch. The policy engine routes this directly to the owning team and security. The finding gets a 12-hour SLA, and if no one acts, the enforcement layer escalates automatically."

*Let the card resolve before continuing.*

Point out:
- Status shows ESCALATED, not COMPLETE — no PR was generated
- Routing goes to `#security-escalations` — different channel than the remediated findings
- This is the third governance path: auto-fix, AI-fix, route-to-humans

### Enforcement (15 seconds)

> "Enforcement is MedSecure's core gap. SAGE runs `enforce` on an hourly cron. If no one reviews a finding within 24 hours, the owner gets a reminder. At 48 hours, it escalates to engineering leads. If SLA compliance drops below 80%, the system escalates all at-risk findings automatically. Nothing can silently stall."

> "The enforcement layer doesn't just report — it acts. KPIs drive system behavior, not dashboards."

### Closing (10 seconds)

> "Every step — detection, decision, execution, review, enforcement — is recorded in an immutable audit trail. The goal isn't to automate security theater. The goal is to make unresolved high-risk findings operationally impossible to ignore."

---

## If you have more time

- Click the remaining cards (CWE-78 command injection, CWE-287 improper auth) to show all five governance paths
- Click Reset, then process all five to show batch behavior
- Switch to terminal and run `python -m sage metrics` to show the 9 KPIs
- Run `python -m sage enforce --dry-run` to show enforcement detecting SLA breaches and KPI violations
- Run `python -m sage override demo-001 status` to show the immutable audit trail
- Open `artifacts/dashboard_all.html` to show the aggregate governance dashboard

---

## Key lines to land

1. "This is not AI generating patches. It is a governed remediation system."
2. "Devin is the execution engine inside a policy-controlled loop — not a generic coding assistant."
3. "The business outcome is not more PRs. It is fewer unresolved high-risk findings and better audit posture."
