"""Devin Integration Layer: Create remediation sessions via Devin API.

Supports two modes controlled by the DEVIN_MODE environment variable:

    DEVIN_MODE=stub   (default) -- Simulates session creation locally.
    DEVIN_MODE=real   -- Calls the Devin API at https://api.devin.ai/v1/sessions.
                         Requires DEVIN_API_KEY to be set.

In real mode, if DEVIN_API_KEY is missing the module raises a clear error
so operators know exactly what to provide.
"""

import os
import uuid
from dataclasses import dataclass

from pipeline.ingest import Alert

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEVIN_API_URL = "https://api.devin.ai/v1/sessions"


def _get_mode() -> str:
    """Return the configured integration mode (stub or real)."""
    return os.environ.get("DEVIN_MODE", "stub")


@dataclass
class DevinSession:
    session_id: str
    disposition: str
    confidence: str
    pr_url: str
    integration_mode: str  # "stub" or "real"


# ---------------------------------------------------------------------------
# Prompt builder (shared by both modes)
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Stub implementation
# ---------------------------------------------------------------------------


def _create_session_stub(
    alert: Alert, disposition: str, confidence: str,
) -> DevinSession:
    """Simulate a Devin session locally (no network calls)."""
    session_id = f"devin-{uuid.uuid4().hex[:12]}"

    pr_url = ""
    if disposition == "PR_READY":
        pr_url = f"https://github.com/violethawk/{alert.repo_name}/pull/3"

    return DevinSession(
        session_id=session_id,
        disposition=disposition,
        confidence=confidence,
        pr_url=pr_url,
        integration_mode="stub",
    )


# ---------------------------------------------------------------------------
# Real implementation (placeholder -- requires DEVIN_API_KEY)
# ---------------------------------------------------------------------------


def _create_session_real(
    alert: Alert, disposition: str, confidence: str,
) -> DevinSession:
    """Call the Devin API to create a remediation session.

    Requires DEVIN_API_KEY in the environment.

    Production flow:
        1. POST to DEVIN_API_URL with build_prompt(alert)
        2. Poll or wait for session completion
        3. Parse structured output into DevinSession

    This is a documented placeholder. Replace the body of this function
    with real HTTP calls when credentials are available.
    """
    api_key = os.environ.get("DEVIN_API_KEY", "")
    if not api_key:
        raise RuntimeError(
            "DEVIN_MODE=real but DEVIN_API_KEY is not set. "
            "Set the environment variable or switch to DEVIN_MODE=stub."
        )

    # ---- PLACEHOLDER: real API call would go here ----
    #
    # import requests
    #
    # prompt = build_prompt(alert)
    # resp = requests.post(
    #     DEVIN_API_URL,
    #     headers={
    #         "Authorization": f"Bearer {api_key}",
    #         "Content-Type": "application/json",
    #     },
    #     json={
    #         "prompt": prompt["instructions"],
    #         "context": prompt,
    #         "idempotency_key": alert.alert_id,
    #     },
    # )
    # resp.raise_for_status()
    # data = resp.json()
    # return DevinSession(
    #     session_id=data["session_id"],
    #     disposition=data.get("disposition", disposition),
    #     confidence=data.get("confidence", confidence),
    #     pr_url=data.get("pr_url", ""),
    #     integration_mode="real",
    # )
    #
    # ---- END PLACEHOLDER ----

    # Until real credentials are available, fall back to stub with a label
    # so callers know the real path was attempted.
    session = _create_session_stub(alert, disposition, confidence)
    session.integration_mode = "real (placeholder)"
    return session


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def create_session(
    alert: Alert, disposition: str, confidence: str,
) -> DevinSession:
    """Create a Devin session using the configured mode.

    Set DEVIN_MODE=real and DEVIN_API_KEY=<key> to use the live API.
    Defaults to stub mode for local development and demos.
    """
    mode = _get_mode()
    if mode == "real":
        return _create_session_real(alert, disposition, confidence)
    return _create_session_stub(alert, disposition, confidence)
