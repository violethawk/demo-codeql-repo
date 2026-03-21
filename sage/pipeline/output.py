"""Output Layer: Produce the structured remediation_report.json."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from sage.pipeline.execute import ExecutionResult
from sage.pipeline.ingest import Alert
from sage.pipeline.triage import TriageResult
from sage.pipeline.validate import ValidationResult


def build_report(
    alert: Alert,
    triage_result: TriageResult,
    exec_result: Optional[ExecutionResult],
    val_result: Optional[ValidationResult],
    pr_url: str = "",
    notification_sent: bool = False,
    integration_mode: str = "stub",
) -> dict:
    """Build the final remediation report as a dict."""
    timestamp = datetime.now(timezone.utc).isoformat()

    # NEEDS_HUMAN_REVIEW: triage failed
    if not triage_result.eligible:
        return {
            "alert_id": alert.alert_id,
            "rule_name": alert.rule_name,
            "cwe": alert.cwe,
            "disposition": "NEEDS_HUMAN_REVIEW",
            "confidence": "LOW",
            "files_changed": [],
            "summary": f"Alert not eligible for auto-remediation: "
            f"{'; '.join(triage_result.reasons)}",
            "root_cause": "",
            "fix": "",
            "why_fix_works": "",
            "validation": [],
            "scope": "",
            "residual_risk": "",
            "decision_trace": "TRIAGE_REJECTED → NEEDS_HUMAN_REVIEW",
            "pr_url": "",
            "notification_sent": notification_sent,
            "integration_mode": integration_mode,
            "timestamp": timestamp,
        }

    # NEEDS_HUMAN_REVIEW: execution failed
    if exec_result is None or not exec_result.success:
        error_msg = exec_result.error if exec_result else "Execution not attempted"
        return {
            "alert_id": alert.alert_id,
            "rule_name": alert.rule_name,
            "cwe": alert.cwe,
            "disposition": "NEEDS_HUMAN_REVIEW",
            "confidence": "LOW",
            "files_changed": [],
            "summary": f"Fix could not be applied: {error_msg}",
            "root_cause": "",
            "fix": "",
            "why_fix_works": "",
            "validation": [],
            "scope": "",
            "residual_risk": "",
            "decision_trace": "TRUE_POSITIVE → Eligible → Fix Failed → NEEDS_HUMAN_REVIEW",
            "pr_url": "",
            "notification_sent": notification_sent,
            "integration_mode": integration_mode,
            "timestamp": timestamp,
        }

    # NEEDS_HUMAN_REVIEW: validation failed
    if val_result is None or not val_result.passed:
        val_steps = (
            [{"command": s.command, "result": s.result} for s in val_result.steps]
            if val_result
            else []
        )
        return {
            "alert_id": alert.alert_id,
            "rule_name": alert.rule_name,
            "cwe": alert.cwe,
            "disposition": "NEEDS_HUMAN_REVIEW",
            "confidence": "MEDIUM",
            "files_changed": exec_result.files_changed,
            "summary": "Fix was applied but validation failed.",
            "root_cause": exec_result.root_cause,
            "fix": exec_result.fix_description,
            "why_fix_works": exec_result.why_fix_works,
            "validation": val_steps,
            "scope": "",
            "residual_risk": "",
            "decision_trace": (
                "TRUE_POSITIVE → Eligible → Fix Applied → "
                "Validation Failed → NEEDS_HUMAN_REVIEW"
            ),
            "pr_url": "",
            "notification_sent": notification_sent,
            "integration_mode": integration_mode,
            "timestamp": timestamp,
        }

    # PR_READY: all checks passed
    val_steps = [
        {"command": s.command, "result": s.result} for s in val_result.steps
    ]
    return {
        "alert_id": alert.alert_id,
        "rule_name": alert.rule_name,
        "cwe": alert.cwe,
        "disposition": "PR_READY",
        "confidence": "HIGH",
        "files_changed": exec_result.files_changed,
        "summary": exec_result.summary,
        "root_cause": exec_result.root_cause,
        "fix": exec_result.fix_description,
        "why_fix_works": exec_result.why_fix_works,
        "validation": val_steps,
        "scope": (
            f"Minimal change: {len(exec_result.files_changed)} file(s) modified. "
            f"Only necessary lines were changed."
        ),
        "residual_risk": exec_result.residual_risk or "None identified.",
        "decision_trace": (
            "TRUE_POSITIVE → Eligible → Fix Applied → "
            "Validation Passed → PR_READY"
        ),
        "pr_url": pr_url,
        "notification_sent": notification_sent,
        "integration_mode": integration_mode,
        "timestamp": timestamp,
    }


def write_report(report: dict, output_path: str) -> None:
    """Write the report dict to a JSON file."""
    Path(output_path).write_text(json.dumps(report, indent=2) + "\n")


def generate_report(
    alert: Alert,
    triage_result: TriageResult,
    exec_result: Optional[ExecutionResult],
    val_result: Optional[ValidationResult],
    pr_url: str = "",
    notification_sent: bool = False,
    integration_mode: str = "stub",
    output_path: str = "artifacts/remediation_report.json",
) -> dict:
    """Build and write the remediation report. Returns the report dict."""
    report = build_report(
        alert, triage_result, exec_result, val_result,
        pr_url=pr_url, notification_sent=notification_sent,
        integration_mode=integration_mode,
    )
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    write_report(report, output_path)
    return report
