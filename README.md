# CodeQL Remediation Pipeline

Minimal proof-of-concept: takes a CodeQL alert as input and produces a
remediation outcome through a fully auditable control loop.

```
alert -> triage -> devin -> remediation -> validate -> PR -> notification -> audit -> dashboard
```

## Quick Start

```bash
# Run the default demo (CWE-89 SQL injection — auto-remediated)
python run_demo.py

# Run with the XSS alert (CWE-79 — escalated to human review)
python run_demo.py fixtures/sample_alert_xss.json

# View the HTML dashboard
open artifacts/dashboard.html
```

## Architecture

| Layer | Module | Purpose |
|-------|--------|---------|
| Ingest | `pipeline/ingest.py` | Load alert JSON into typed dataclass |
| Policy | `pipeline/policy.py` | Per-CWE remediation eligibility rules |
| Triage | `pipeline/triage.py` | Deterministic eligibility check |
| Execute | `pipeline/execute.py` | Apply minimal safe fix |
| Validate | `pipeline/validate.py` | Run py_compile + ruff |
| Output | `pipeline/output.py` | Produce `remediation_report.json` |
| Devin | `integrations/devin_client.py` | Session creation (stub / real mode) |
| PR | `integrations/pr_client.py` | PR payload generation |
| Notify | `integrations/notify.py` | Team notification payload |
| Dashboard | `integrations/dashboard.py` | HTML status page from artifacts |

## Devin Integration Modes

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

The real-mode code path is a documented placeholder. Replace the body of
`_create_session_real()` in `integrations/devin_client.py` with actual
HTTP calls when API credentials are available.

## CWE Coverage

| CWE | Name | Auto-Fix | Notes |
|-----|------|----------|-------|
| CWE-89 | SQL Injection | Yes | Replaces f-string SQL with parameterized query |
| CWE-79 | Cross-Site Scripting | No | Recognized, escalated to `NEEDS_HUMAN_REVIEW` |

To add a new CWE:
1. Add an entry to `REMEDIATION_POLICIES` in `pipeline/policy.py`
2. If `auto_fix=True`, register a handler in `pipeline/execute.py`
3. If `auto_fix=False`, the system routes to `NEEDS_HUMAN_REVIEW` automatically

## Artifacts

After running, `artifacts/` contains:

| File | Description |
|------|-------------|
| `remediation_report.json` | Full audit record (disposition, decision trace, timestamps, integration mode) |
| `pr_payload.json` | Structured PR payload |
| `notification_payload.json` | Team notification payload |
| `dashboard.html` | Visual status page |

## What is Real vs Stubbed

| Component | Status |
|-----------|--------|
| Alert ingestion | Real (reads JSON fixtures) |
| Triage rules | Real (deterministic policy check) |
| CWE-89 fix | Real (rewrites code to parameterized query) |
| Validation | Real (runs py_compile + ruff) |
| Devin session | Stubbed (simulated locally; real mode placeholder included) |
| PR creation | Stubbed (generates JSON artifact, not a real GitHub API call) |
| Notification | Stubbed (generates JSON artifact, not a real Slack/email call) |
| Dashboard | Real (generates HTML from artifact data) |
