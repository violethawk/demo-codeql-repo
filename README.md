# demo-codeql-repo

This is a controlled demo repository for an autonomous CodeQL remediation system using Devin.

It contains a deliberately vulnerable SQL query to demonstrate an end-to-end workflow:
alert → triage → fix → pull request → merge.

The system is designed to produce minimal, reviewable patches with clear auditability and guardrails.

⚠️ This repository intentionally includes insecure code for demonstration purposes. Do not use in production.
