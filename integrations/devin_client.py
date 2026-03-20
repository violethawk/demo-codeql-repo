"""Devin Integration Layer: Create remediation sessions via Devin API.

This module represents how a Devin session would be created to remediate
a CodeQL alert. When real API access is available, replace the stub with
actual API calls to api.devin.ai.

Currently: STUB -- simulates Devin session creation and response.
"""

import uuid
from dataclasses import dataclass

from pipeline.ingest import Alert


@dataclass
class DevinSession:
    session_id: str
    disposition: str
    confidence: str
    pr_url: str


def build_prompt(alert: Alert) -> dict:
    """Build the prompt payload that would be sent to Devin."""
    return {
        "task": "remediate_codeql_alert",
        "alert": {
            "alert_id": alert.alert_id,
            "rule_name": alert.rule_name,
            "severity": alert.severity,
            "cwe": alert.cwe,
            "file_path": alert.file_path,
            "line_range": {
                "start": alert.line_range.start,
                "end": alert.line_range.end,
            },
            "vulnerable_code_snippet": alert.vulnerable_code_snippet,
            "alert_description": alert.alert_description,
            "security_guidance": alert.security_guidance,
        },
        "instructions": (
            "Investigate the CodeQL alert. If it is a true positive and "
            "safely fixable, apply the minimal remediation and open a PR. "
            "Otherwise, escalate for human review."
        ),
    }


def create_session(alert: Alert, disposition: str, confidence: str) -> DevinSession:
    """Create a Devin remediation session.

    STUB: In production, this would call the Devin API:
        POST https://api.devin.ai/v1/sessions
        {
            "prompt": build_prompt(alert),
            "idempotency_key": alert.alert_id
        }

    The session would return structured output matching DevinSession.
    """
    session_id = f"devin-{uuid.uuid4().hex[:12]}"

    pr_url = ""
    if disposition == "PR_READY":
        repo = alert.repo_name
        pr_url = f"https://github.com/violethawk/{repo}/pull/3"

    return DevinSession(
        session_id=session_id,
        disposition=disposition,
        confidence=confidence,
        pr_url=pr_url,
    )
