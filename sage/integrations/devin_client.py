"""Devin Integration Layer: Create remediation sessions via Devin API.

Supports two modes controlled by the DEVIN_MODE environment variable:

    DEVIN_MODE=stub   (default) -- Simulates session creation locally.
    DEVIN_MODE=real   -- Calls the Devin API to create a session and
                         polls until completion. Requires DEVIN_API_KEY.

Devin is not a generic coding assistant here. It is the constrained
execution engine inside a policy-governed workflow.

Two execution paths:

    AUTO_REMEDIATE         → Local fix handlers (fast path, HIGH confidence)
    REMEDIATE_WITH_REVIEW  → Devin session (full autonomous engineer)

For REMEDIATE_WITH_REVIEW, Devin:
    1. Analyzes the finding and produces a remediation plan
    2. Implements the patch + tests
    3. Opens a PR
    4. Returns structured output for audit
"""

import json
import os
import time
import uuid
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Optional

from sage.pipeline.ingest import Alert

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEVIN_API_BASE = "https://api.devin.ai/v1"
POLL_INTERVAL_SECONDS = 10
POLL_TIMEOUT_SECONDS = 600  # 10 minutes max

# Terminal session statuses (v1 API)
# "suspended" means Devin completed work but the session was paused —
# treat as terminal and check structured_output for results.
_TERMINAL_STATUSES = {"finished", "error", "stopped", "expired", "suspended"}
_SUCCESS_STATUSES = {"finished", "suspended"}


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


# ---------------------------------------------------------------------------
# Data contracts
# ---------------------------------------------------------------------------


@dataclass
class RemediationPlan:
    """Structured remediation plan produced by Devin before code changes."""
    root_cause: str = ""
    fix_strategy: str = ""
    affected_files: list[str] = field(default_factory=list)
    test_plan: str = ""
    confidence: str = ""


@dataclass
class SessionInsights:
    """Post-session analysis from Devin."""
    summary: str = ""
    changes_made: str = ""
    tests_added: str = ""
    reviewer_notes: str = ""


@dataclass
class DevinSession:
    session_id: str
    disposition: str
    confidence: str
    pr_url: str
    integration_mode: str  # "stub" or "real"
    plan: Optional[RemediationPlan] = None
    insights: Optional[SessionInsights] = None


# ---------------------------------------------------------------------------
# Prompt builders
# ---------------------------------------------------------------------------

# JSON Schema for structured output — Devin returns this alongside the fix.
_REMEDIATION_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "root_cause": {
            "type": "string",
            "description": "Root cause analysis of the vulnerability",
        },
        "fix_strategy": {
            "type": "string",
            "description": "Description of the remediation approach",
        },
        "affected_files": {
            "type": "array",
            "items": {"type": "string"},
            "description": "List of files modified",
        },
        "test_plan": {
            "type": "string",
            "description": "Tests added or updated to verify the fix",
        },
        "confidence": {
            "type": "string",
            "enum": ["HIGH", "MEDIUM", "LOW"],
            "description": "Confidence that the fix fully resolves the issue",
        },
        "pr_url": {
            "type": "string",
            "description": "URL of the created pull request",
        },
    },
    "required": ["root_cause", "fix_strategy", "confidence"],
}


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


def _build_remediation_prompt(alert: Alert) -> str:
    """Build a detailed remediation prompt for REMEDIATE_WITH_REVIEW sessions."""
    snippet = "\n".join(f"  {line}" for line in alert.vulnerable_code_snippet)
    return (
        f"SAGE Remediation Task: {alert.cwe} — {alert.rule_name}\n\n"
        f"File: {alert.file_path} "
        f"(lines {alert.line_range.start}-{alert.line_range.end})\n\n"
        f"Description: {alert.alert_description}\n\n"
        f"Security guidance: {alert.security_guidance}\n\n"
        f"Vulnerable code:\n{snippet}\n\n"
        f"Instructions:\n"
        f"1. Analyze the root cause of this vulnerability\n"
        f"2. Develop a remediation strategy\n"
        f"3. Implement the minimal safe fix\n"
        f"4. Add or update tests to verify the fix\n"
        f"5. Open a pull request with a clear explanation\n\n"
        f"Return your analysis as structured output including root_cause, "
        f"fix_strategy, affected_files, test_plan, and confidence level."
    )


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
# Stub implementations
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


def _remediate_stub(alert: Alert) -> DevinSession:
    """Simulate a full Devin remediation session in stub mode."""
    session_id = f"devin-{uuid.uuid4().hex[:12]}"

    plan = RemediationPlan(
        root_cause=(
            f"User-controlled input is used unsafely in {alert.file_path} "
            f"at lines {alert.line_range.start}-{alert.line_range.end}, "
            f"enabling {alert.rule_name}."
        ),
        fix_strategy=(
            f"Apply the standard remediation pattern for {alert.cwe}: "
            f"{alert.security_guidance}"
        ),
        affected_files=[alert.file_path],
        test_plan=(
            f"Add test case verifying that malicious input to the vulnerable "
            f"code path in {alert.file_path} is safely handled."
        ),
        confidence="MEDIUM",
    )

    insights = SessionInsights(
        summary=(
            f"Devin analyzed {alert.cwe} ({alert.rule_name}) in "
            f"{alert.file_path} and applied the recommended remediation."
        ),
        changes_made=(
            f"Modified {alert.file_path} to neutralize the {alert.cwe} vector."
        ),
        tests_added="Added regression test for the vulnerable code path.",
        reviewer_notes=(
            f"Security review recommended: {alert.cwe} fix confidence is MEDIUM. "
            f"Verify the fix covers all input paths to the affected code."
        ),
    )

    return DevinSession(
        session_id=session_id,
        disposition="PR_READY",
        confidence="MEDIUM",
        pr_url=f"https://github.com/violethawk/{alert.repo_name}/pull/3",
        integration_mode="stub",
        plan=plan,
        insights=insights,
    )


# ---------------------------------------------------------------------------
# Real implementations
# ---------------------------------------------------------------------------


def _create_devin_session(alert: Alert) -> dict:
    """POST to Devin API to create a basic remediation session."""
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


def _create_remediation_session(alert: Alert) -> dict:
    """POST to Devin API with structured output schema for full remediation."""
    body = {
        "prompt": _build_remediation_prompt(alert),
        "structured_output_schema": _REMEDIATION_OUTPUT_SCHEMA,
        "idempotent": False,
        "tags": [
            f"sage:{alert.alert_id}",
            f"sage:remediate_with_review",
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
    prs = session_data.get("pull_requests") or []
    for pr in prs:
        url = pr.get("pr_url", "")
        if url:
            return url

    output = session_data.get("structured_output") or {}
    return output.get("pr_url", "")


def _extract_plan(session_data: dict) -> RemediationPlan:
    """Extract the remediation plan from structured output."""
    output = session_data.get("structured_output") or {}
    return RemediationPlan(
        root_cause=output.get("root_cause", ""),
        fix_strategy=output.get("fix_strategy", ""),
        affected_files=output.get("affected_files", []),
        test_plan=output.get("test_plan", ""),
        confidence=output.get("confidence", "MEDIUM"),
    )


def _fetch_insights(session_id: str) -> SessionInsights:
    """Fetch post-session insights from Devin.

    Tries POST /v1/session/{id}/insights. If the endpoint is not
    available, returns empty insights gracefully.
    """
    try:
        data = _api_request("POST", f"/session/{session_id}/insights")
        return SessionInsights(
            summary=data.get("summary", ""),
            changes_made=data.get("changes_made", ""),
            tests_added=data.get("tests_added", ""),
            reviewer_notes=data.get("reviewer_notes", ""),
        )
    except RuntimeError:
        # Insights endpoint may not be available — degrade gracefully
        return SessionInsights()


def _create_session_real(
    alert: Alert, disposition: str, confidence: str,
) -> DevinSession:
    """Create a real Devin session, poll to completion, and return results."""
    create_resp = _create_devin_session(alert)
    session_id = create_resp.get("session_id", "")

    if not session_id:
        raise RuntimeError(
            f"Devin API did not return a session_id: {create_resp}"
        )

    final_data = _poll_session(session_id)
    status = final_data.get("status", "error")

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
            return DevinSession(
                session_id=session_id,
                disposition="NEEDS_HUMAN_REVIEW",
                confidence="MEDIUM",
                pr_url="",
                integration_mode="real",
            )
    else:
        return DevinSession(
            session_id=session_id or f"devin-error-{uuid.uuid4().hex[:8]}",
            disposition="NEEDS_HUMAN_REVIEW",
            confidence="LOW",
            pr_url="",
            integration_mode="real",
        )


def _remediate_real(alert: Alert) -> DevinSession:
    """Full Devin remediation: plan → patch → PR → insights.

    This is the REMEDIATE_WITH_REVIEW path. Devin acts as the primary
    execution engine, not a sidecar.
    """
    # 1. Create session with structured output for remediation plan
    create_resp = _create_remediation_session(alert)
    session_id = create_resp.get("session_id", "")

    if not session_id:
        raise RuntimeError(
            f"Devin API did not return a session_id: {create_resp}"
        )

    # 2. Poll for completion
    final_data = _poll_session(session_id)
    status = final_data.get("status", "error")

    # 3. Extract plan from structured output
    plan = _extract_plan(final_data)

    # 4. Fetch post-session insights
    insights = SessionInsights()
    if status in _SUCCESS_STATUSES:
        insights = _fetch_insights(session_id)

    # 5. Build result
    if status in _SUCCESS_STATUSES:
        pr_url = _extract_pr_url(final_data)
        return DevinSession(
            session_id=session_id,
            disposition="PR_READY" if pr_url else "NEEDS_HUMAN_REVIEW",
            confidence=plan.confidence or "MEDIUM",
            pr_url=pr_url,
            integration_mode="real",
            plan=plan,
            insights=insights,
        )
    else:
        return DevinSession(
            session_id=session_id or f"devin-error-{uuid.uuid4().hex[:8]}",
            disposition="NEEDS_HUMAN_REVIEW",
            confidence="LOW",
            pr_url="",
            integration_mode="real",
            plan=plan,
            insights=insights,
        )


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------


def create_session(
    alert: Alert, disposition: str, confidence: str,
) -> DevinSession:
    """Create a Devin session using the configured mode.

    Used for basic session tracking (AUTO_REMEDIATE path).
    """
    mode = _get_mode()
    if mode == "real":
        return _create_session_real(alert, disposition, confidence)
    return _create_session_stub(alert, disposition, confidence)


def remediate(alert: Alert) -> DevinSession:
    """Run a full Devin remediation session (REMEDIATE_WITH_REVIEW path).

    Devin is the primary execution engine here:
        1. Analyzes the finding and produces a remediation plan
        2. Implements the patch + tests
        3. Opens a PR
        4. Returns structured output + insights for audit

    In stub mode, simulates the full flow with realistic output.
    """
    mode = _get_mode()
    if mode == "real":
        return _remediate_real(alert)
    return _remediate_stub(alert)
