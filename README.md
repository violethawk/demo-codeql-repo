# demo-codeql-repo

A controlled demo environment for an autonomous CodeQL remediation system powered by Devin.

This repository contains a deliberately vulnerable SQL injection to demonstrate a complete end-to-end workflow: **alert → triage → fix → pull request → merge.**

The system produces minimal, reviewable patches with full auditability and human-review guardrails at every decision point.

---

## The Problem

Security scanning tools like CodeQL generate a continuous stream of findings. Remediation lags behind.

Security teams identify and track issues. Engineering teams deprioritize them because they arrive outside sprint planning. Over time, this creates a growing backlog of unresolved vulnerabilities and audit risk.

The core challenge is not detection — it is closing the loop:

- Turning scanner output into actionable engineering work
- Ensuring fixes are reviewed and merged through normal PR workflows
- Maintaining full visibility without requiring manual coordination

---

## What This Repo Contains

| File | Purpose |
|---|---|
| `app.py` | Deliberately vulnerable Flask app with a SQL injection on lines 12–14 |
| `sample_alert.json` | Structured CodeQL alert payload consumed by the orchestrator |
| `requirements.txt` | Python dependencies |

---

## How It Works

1. The orchestrator ingests `sample_alert.json`
2. The triage engine evaluates remediation eligibility
3. A Devin session is launched with the alert context and remediation playbook
4. Devin investigates, implements the minimal fix, and opens a PR
5. The dashboard and Slack notification update automatically

To trigger the workflow manually:

```bash
curl -X POST http://localhost:8000/alerts/ingest \
  -H "Content-Type: application/json" \
  -d @sample_alert_v2.json
```

---

## Remediation Guardrails

The system will not auto-patch unless all conditions are met:

- Finding is classified as a true positive
- Fix is narrow in scope with low blast radius
- All CI checks pass after the change
- The agent can clearly explain why the fix resolves the issue

If any condition fails, the system routes to `NEEDS_HUMAN_REVIEW` instead of forcing a patch.

---

## See Also

- [Orchestrator & system architecture](#) — main repo with triage engine, Devin orchestrator, and dashboard
- [Remediation playbook](#) — Devin prompt and operating constraints

---

> ⚠️ This repository intentionally includes insecure code for demonstration purposes. Do not deploy to production.
