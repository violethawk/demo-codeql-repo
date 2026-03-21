# SAGE Demo Script

**60-90 second walkthrough for Loom or live presentation.**

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

---

## Script

### Opening (10 seconds)

> "The system I built is called SAGE: Security Automation & Governance Engine."
>
> "MedSecure's problem isn't detection — CodeQL already finds the issues. The problem is that findings don't reliably turn into fixed code. SAGE closes that gap."

### Click CWE-89 — SQL Injection (15 seconds)

> "This SQL injection is a well-understood pattern. The policy engine assigns AUTO_REMEDIATE — a local handler fixes it instantly with a parameterized query. Standard code review. No Devin needed."

Point out:
- The code transforms from red (vulnerable) to green (fixed)
- The routing panel shows it goes to `#backend-security`
- Two backend engineers are assigned as reviewers

### Click CWE-79 — XSS (20 seconds)

> "Cross-site scripting is different. The fix depends on the output context. The policy engine assigns REMEDIATE_WITH_REVIEW — Devin is the execution engine here. It analyzes the code, produces a remediation plan, implements the fix, and opens a PR. A security reviewer is required."

Point out:
- Different execution path — Devin API, not local handler
- The routing panel shows a security reviewer is added
- The notification goes to `#frontend-security` — different team

### Routing panel (10 seconds)

> "Every fix is routed to the right humans. The notification goes to the team's channel. The PR gets reviewers. If no one acts within 24 hours, the enforcement layer sends a reminder. At 48 hours, it escalates to engineering leads. Nothing can silently stall."

### Architecture summary (15 seconds)

> "SAGE has six layers. Detection is CodeQL. Decision is the policy engine. Execution is Devin for complex fixes, local handlers for simple ones. Review routes to the right humans. Enforcement prevents stalling. And every step is recorded in an audit trail."
>
> "The key design principle: authority is separated from execution. Policy decides what's allowed. Devin performs the fix. The enforcement layer ensures nothing falls through the cracks."

### Closing (10 seconds)

> "The goal isn't to automate security theater. The goal is to make unresolved high-risk findings operationally impossible to ignore."

---

## If you have more time

- Click Reset, then process all three to show batch behavior
- Run `python -m sage metrics` to show the 9 KPIs
- Run `python -m sage enforce --dry-run` to show enforcement detecting KPI violations
- Run `python -m sage override demo-001 status` to show the audit trail
- Open `artifacts/dashboard_all.html` to show the aggregate governance dashboard

---

## Key lines to land

1. "This is not AI generating patches. It is a governed remediation system."
2. "Devin is the execution engine inside a policy-controlled loop — not a generic coding assistant."
3. "The business outcome is not more PRs. It is fewer unresolved high-risk findings and better audit posture."
