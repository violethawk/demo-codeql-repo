# demo-codeql-repo

This is a controlled demo repository for an autonomous CodeQL remediation system using Devin.

It contains a deliberately vulnerable SQL query to demonstrate an end-to-end workflow:
alert → triage → fix → pull request → merge.

The system is designed to produce minimal, reviewable patches with clear auditability and guardrails.

## Problem

Security scanning tools like CodeQL generate a continuous stream of findings, but remediation often lags behind.

Security teams identify and track issues, while engineering teams deprioritize them because they fall outside normal sprint work. Over time, this creates a growing backlog of unresolved vulnerabilities and audit risk.

The core challenge is not detection — it is closing the loop:
- turning scanner output into actionable engineering work
- ensuring fixes are reviewed and merged
- maintaining visibility without requiring manual coordination

⚠️ This repository intentionally includes insecure code for demonstration purposes. Do not use in production.
