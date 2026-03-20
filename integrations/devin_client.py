"""Devin Integration Layer: Create remediation sessions via Devin API.

Supports two modes controlled by the DEVIN_MODE environment variable:

    DEVIN_MODE=stub   (default) -- Simulates session creation locally.
    DEVIN_MODE=real   -- Calls the Devin API to create a session and
                         polls until completion. Requires DEVIN_API_KEY.

Devin is not a generic coding assistant here. It is the constrained
execution engine inside a policy-governed workflow.
"""

import json
import os
import time
import uuid
import urllib.request
import urllib.error
from dataclasses import dataclass

from pipeline.ingest import Alert

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEVIN_API_BASE = "https://api.devin.ai/v1"
POLL_INTERVAL_SECONDS = 10
POLL_TIMEOUT_SECONDS = 600  # 10 minutes max

# Terminal session statuses (v1 API)
_TERMINAL_STATUSES = {"finished", "error", "stopped", "expired"}
_SUCCESS_STATUSES = {"finished"}


def _get_mode() -> str:
    """Return the configured integration mode (stub or real)."""
    return os.environ.get("DEVIN_MODE", "stub")


def _get_api_key() -> str:
    key = os.environ.get("DEVIN_API_KEY", "")
    if not key:
        raise RuntimeError(
            "DEVIN_MODE=real but DEVIN_API_KEY is not set. "
            "Set the environment variable or switch to DEVIN_MODE=stub."
        )
    return key


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
# HTTP helpers (stdlib only — no requests dependency)
# ---------------------------------------------------------------------------


def _api_request(method: str, path: str, body: dict | None = None) -> dict:
    """Make an authenticated request to the Devin API."""
    api_key = _get_api_key()
    url = f"{DEVIN_API_BASE}{path}"

    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        error_body = ""
        try:
            error_body = e.read().decode()
        except Exception:
            pass
        raise RuntimeError(
            f"Devin API {method} {path} returned {e.code}: {error_body}"
        ) from e


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
# Real implementation
# ---------------------------------------------------------------------------


def _create_devin_session(alert: Alert) -> dict:
    """POST to Devin API to create a new remediation session."""
    prompt = build_prompt(alert)

    body = {
        "prompt": (
            f"SAGE Remediation Task: {alert.cwe} — {alert.rule_name}\n\n"
            f"File: {alert.file_path} (lines {alert.line_range.start}-{alert.line_range.end})\n\n"
            f"Description: {alert.alert_description}\n\n"
            f"Security guidance: {alert.security_guidance}\n\n"
            f"Vulnerable code:\n"
            + "\n".join(f"  {line}" for line in alert.vulnerable_code_snippet)
            + "\n\n"
            f"{prompt['instructions']}"
        ),
        "idempotent": True,
        "tags": [
            f"sage:{alert.alert_id}",
            f"cwe:{alert.cwe}",
            f"severity:{alert.severity}",
        ],
    }

    return _api_request("POST", "/sessions", body)


def _poll_session(session_id: str) -> dict:
    """Poll the Devin session until it reaches a terminal state."""
    elapsed = 0

    while elapsed < POLL_TIMEOUT_SECONDS:
        data = _api_request("GET", f"/session/{session_id}")
        status = data.get("status", "")

        if status in _TERMINAL_STATUSES:
            return data

        time.sleep(POLL_INTERVAL_SECONDS)
        elapsed += POLL_INTERVAL_SECONDS

    return {"status": "timeout", "session_id": session_id}


def _extract_pr_url(session_data: dict) -> str:
    """Extract the PR URL from a completed Devin session."""
    # v1/v3: pull_requests is a list of {pr_url, pr_state}
    prs = session_data.get("pull_requests", [])
    for pr in prs:
        url = pr.get("pr_url", "")
        if url:
            return url

    # Fallback: check structured_output
    output = session_data.get("structured_output") or {}
    return output.get("pr_url", "")


def _create_session_real(
    alert: Alert, disposition: str, confidence: str,
) -> DevinSession:
    """Create a real Devin session, poll to completion, and return results.

    Flow:
        1. POST /v1/sessions with the remediation prompt
        2. Poll GET /v1/session/{id} until terminal state
        3. Extract PR URL from session data
        4. Map Devin status to SAGE disposition
    """
    # Create session
    create_resp = _create_devin_session(alert)
    session_id = create_resp.get("session_id", "")
    session_url = create_resp.get("url", "")

    if not session_id:
        raise RuntimeError(
            f"Devin API did not return a session_id: {create_resp}"
        )

    # Poll for completion
    final_data = _poll_session(session_id)
    status = final_data.get("status", "error")

    # Map Devin status to SAGE disposition
    if status in _SUCCESS_STATUSES:
        pr_url = _extract_pr_url(final_data)
        if pr_url:
            return DevinSession(
                session_id=session_id,
                disposition="PR_READY",
                confidence="HIGH",
                pr_url=pr_url,
                integration_mode="real",
            )
        else:
            # Devin finished but no PR — treat as needing review
            return DevinSession(
                session_id=session_id,
                disposition="NEEDS_HUMAN_REVIEW",
                confidence="MEDIUM",
                pr_url="",
                integration_mode="real",
            )
    else:
        # Error, timeout, or stopped — escalate
        return DevinSession(
            session_id=session_id or f"devin-error-{uuid.uuid4().hex[:8]}",
            disposition="NEEDS_HUMAN_REVIEW",
            confidence="LOW",
            pr_url="",
            integration_mode="real",
        )


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
