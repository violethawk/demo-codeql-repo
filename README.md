# CodeQL Remediation Pipeline

> **Prototype** — Automated security alert remediation for enterprise
> security teams. Takes a CodeQL alert as input, triages it against a
> policy registry, applies the minimal safe fix when possible, and
> produces auditable artifacts for review.

## Problem

Security teams receive hundreds of CodeQL alerts. Triaging, fixing, and
tracking each one manually is slow and error-prone. This prototype
demonstrates an end-to-end control loop that automates the workflow:

```
alert → triage → devin → remediation → validate → PR → notification → audit → dashboard
```

The system is intentionally small so it can be understood, run, and
explained in under five minutes.

---

## Quick Start

```bash
# 1. Run the default demo (CWE-89 SQL injection — auto-remediated)
python run_demo.py

# 2. Run with the XSS fixture (CWE-79 — escalated to human review)
python run_demo.py fixtures/sample_alert_xss.json

# 3. Open the visual dashboard
open artifacts/dashboard.html

# 4. Read the demo summary (Markdown)
cat artifacts/demo_summary.md
```

No external dependencies are required — the system uses only the Python
standard library and `ruff` (if installed) for linting.

---

## Architecture

| Layer | Module | Purpose |
|-------|--------|---------|
| Ingest | `pipeline/ingest.py` | Load alert JSON into typed `Alert` dataclass |
| Policy | `pipeline/policy.py` | Per-CWE remediation eligibility rules |
| Triage | `pipeline/triage.py` | Deterministic eligibility check against policy |
| Execute | `pipeline/execute.py` | Apply minimal safe fix (dispatch by CWE) |
| Validate | `pipeline/validate.py` | Run `py_compile` + `ruff` checks |
| Output | `pipeline/output.py` | Produce `remediation_report.json` with full audit fields |
| Devin | `integrations/devin_client.py` | Session creation — stub or real mode (`DevinSession`) |
| PR | `integrations/pr_client.py` | PR payload builder + delivery (`PullRequestPayload`) |
| Notify | `integrations/notify.py` | Notification builder + delivery (`NotificationPayload`) |
| Dashboard | `integrations/dashboard.py` | HTML status page generated from artifacts |

Each integration module exposes **typed dataclass contracts** for its
request and response, and a **delivery function** with a documented
placeholder showing exactly where a real API call would be inserted.

---

## Integration Modes

### Devin

Controlled by the `DEVIN_MODE` environment variable:

| Mode | Behavior |
|------|----------|
| `stub` (default) | Simulates session creation locally — no network calls |
| `real` | Calls the Devin API — requires `DEVIN_API_KEY` |

```bash
# Default: stub mode
python run_demo.py

# Real mode (placeholder until credentials are provided)
DEVIN_MODE=real DEVIN_API_KEY=your-key python run_demo.py
```

### GitHub PR / Notification

Both modules follow the same pattern: a `build_*` function assembles a
typed payload, and a `deliver_*` function handles delivery. In stub mode,
delivery writes a JSON artifact to disk. The docstring of each `deliver_*`
function contains the exact code needed to replace the stub with a real
API call (GitHub REST API, Slack `chat.postMessage`, etc.).

---

## CWE Coverage

| CWE | Name | Auto-Fix | Behavior |
|-----|------|----------|----------|
| CWE-89 | SQL Injection | Yes | Replaces f-string SQL with parameterized query |
| CWE-79 | Cross-Site Scripting | No | Recognized, escalated to `NEEDS_HUMAN_REVIEW` |
| CWE-78 | OS Command Injection | No | Recognized, escalated to `NEEDS_HUMAN_REVIEW` |

### Adding a new CWE

1. Add an entry to `REMEDIATION_POLICIES` in `pipeline/policy.py`
2. If `auto_fix=True`, register a handler in `pipeline/execute.py`
3. If `auto_fix=False`, the system routes to `NEEDS_HUMAN_REVIEW`
   automatically — no additional code required

---

## Output Artifacts

After running, `artifacts/` contains:

| File | Description |
|------|-------------|
| `remediation_report.json` | Full audit record — disposition, decision trace, timestamps, integration mode |
| `pr_payload.json` | Structured PR payload (typed `PullRequestPayload`) |
| `notification_payload.json` | Team notification payload (typed `NotificationPayload`) |
| `dashboard.html` | Visual status page for demo and review |
| `demo_summary.md` | Markdown summary of the run, suitable for sharing |

---

## What is Real vs Stubbed

| Component | Status | Notes |
|-----------|--------|-------|
| Alert ingestion | **Implemented** | Reads JSON fixtures into typed dataclass |
| Policy registry | **Implemented** | Deterministic per-CWE rules |
| Triage engine | **Implemented** | Severity + policy + snippet checks |
| CWE-89 fix | **Implemented** | Rewrites vulnerable code to parameterized query |
| Validation | **Implemented** | Runs `py_compile` + `ruff` |
| Audit report | **Implemented** | Full JSON with timestamps, trace, mode |
| HTML dashboard | **Implemented** | Generated from artifact data |
| Devin session | **Stubbed** | Simulated locally; real-mode placeholder included |
| GitHub PR | **Stubbed** | Writes JSON artifact; `deliver_pr()` shows real API call |
| Slack notification | **Stubbed** | Writes JSON artifact; `deliver_notification()` shows real API call |

---

## Path to Production

| Step | What to do |
|------|------------|
| Connect Devin | Set `DEVIN_MODE=real`, provide `DEVIN_API_KEY`, replace placeholder in `_create_session_real()` |
| Connect GitHub | Replace `deliver_pr()` body with `requests.post()` to GitHub REST API |
| Connect Slack | Replace `deliver_notification()` body with Slack `chat.postMessage` |
| Add CWEs | Add policy entries + optional fix handlers |
| Webhook trigger | Replace CLI invocation with a GitHub webhook listener |
| Persistence | Store reports in a database instead of JSON files |

---

## Constraints (by design)

- No databases, queues, or cloud infrastructure
- No external dependencies beyond the Python standard library
- No complex frameworks
- All behavior is deterministic and auditable
- The system is honest about what is stubbed vs implemented
