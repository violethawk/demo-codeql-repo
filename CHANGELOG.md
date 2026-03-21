# Changelog

## 1.0.0 — 2026-03-21

Initial release of SAGE — Security Automation & Governance Engine.

### Core

- **Policy engine** with four governance actions: AUTO_REMEDIATE, REMEDIATE_WITH_REVIEW, ESCALATE, DEFER
- **Three CWE handlers**: CWE-89 (SQL injection, 4 patterns), CWE-79 (XSS), CWE-78 (command injection, 3 patterns)
- **Two execution paths**: local handlers for HIGH confidence, Devin API for MEDIUM confidence
- **SARIF ingestion** for real CodeQL output
- **SQLite persistence** with WAL mode, lifecycle states, immutable audit trail

### Integrations

- **Devin API**: session creation, polling, structured output, insights extraction
- **GitHub PRs**: branch/commit/push/PR via `gh` CLI with reviewer assignment and labels
- **Slack**: Block Kit messages to team channels + escalation channels

### Enforcement

- **Per-finding SLA**: 24h remind → 48h escalate → SLA breach auto-escalate
- **KPI-driven**: SLA compliance, lifecycle completion, PR merge rate, unowned findings thresholds
- **Human override**: merge, close, reject, defer, escalate, reopen with validated transitions

### Visibility

- **9 KPIs**: SLA compliance, MTTR, aging backlog, auto-remediation rate, PR merge rate, time to first action, unowned findings, SLA breaches, lifecycle completion
- **Aggregate dashboard**: dark theme, animated progress bars, filterable alert table
- **Interactive demo**: browser-based, self-narrating, self-testing

### Infrastructure

- **86 tests**, 84% coverage
- **GitHub Actions**: triggers on CodeQL, hourly cron, manual dispatch
- **Health check**: validates config, API connectivity, database, module imports, tests
- **Configuration**: `sage.config.json` for reviewers, channels, KPI thresholds
