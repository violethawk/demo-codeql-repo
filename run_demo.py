#!/usr/bin/env python3
"""SAGE — Security Automation & Governance Engine

    Detection → Decision → Execution → Review → Enforcement → Evidence
"""

import sys
from datetime import datetime, timezone
from pathlib import Path

from pipeline.ingest import Alert, load_alert
from pipeline.triage import triage
from pipeline.policy import AUTO_REMEDIATE, REMEDIATE_WITH_REVIEW, ESCALATE, DEFER
from pipeline.execute import execute
from pipeline.validate import validate
from pipeline.output import generate_report
from pipeline import store

from integrations.devin_client import create_session, build_prompt, _get_mode
from integrations.pr_client import build_pr_payload, deliver_pr
from integrations.notify import build_notification, deliver_notification
from integrations.dashboard import generate_dashboard


SEPARATOR = "-" * 56


def process_alert(
    alert_path: str,
    repo_root: str = "target_repo",
    *,
    db_conn=None,
    quiet: bool = False,
) -> dict:
    """Run the full SAGE pipeline for a single alert. Returns the report dict."""
    def _print(*args, **kwargs):
        if not quiet:
            print(*args, **kwargs)

    mode = _get_mode()

    _print()
    _print(SEPARATOR)
    _print("  SAGE — Security Automation & Governance Engine")
    _print(SEPARATOR)
    _print(f"  Alert file:  {alert_path}")
    _print(f"  Target repo: {repo_root}")
    _print(f"  Devin mode:  {mode}")
    _print(SEPARATOR)
    _print()

    # 1. Detection — ingest finding from CodeQL
    _print("[1/9] Ingesting alert...")
    alert = load_alert(alert_path)
    _print(f"  Alert ID:  {alert.alert_id}")
    _print(f"  Rule:      {alert.rule_name}")
    _print(f"  CWE:       {alert.cwe}")
    _print(f"  Severity:  {alert.severity}")
    _print(f"  File:      {alert.file_path}")
    _print(f"  Lines:     {alert.line_range.start}-{alert.line_range.end}")
    _print()

    # 2. Decision — policy engine classifies and assigns action
    _print("[2/9] Policy decision...")
    triage_result = triage(alert)
    action = triage_result.action

    if not triage_result.eligible:
        _print(f"  Action: {action} (not eligible)")
        for reason in triage_result.reasons:
            _print(f"    - {reason}")
        session = create_session(alert, "NEEDS_HUMAN_REVIEW", "LOW")
        notification = build_notification(
            alert, "NEEDS_HUMAN_REVIEW", "",
            integration_mode=session.integration_mode,
        )
        deliver_notification(notification)
        report = generate_report(
            alert, triage_result, None, None,
            notification_sent=True,
            integration_mode=session.integration_mode,
        )
        if db_conn:
            store.record_alert(
                db_conn, alert, report,
                policy_action=action, sla_hours=triage_result.sla_hours,
            )
        _finalize(alert, action, report, session, quiet=quiet)
        return report

    if action == DEFER:
        _print(f"  Action: DEFER (low-risk, log and revisit)")
        report = generate_report(
            alert, triage_result, None, None,
            integration_mode="stub",
        )
        report["disposition"] = "DEFERRED"
        report["confidence"] = "N/A"
        if db_conn:
            store.record_alert(
                db_conn, alert, report,
                policy_action=DEFER, sla_hours=triage_result.sla_hours,
            )
        _finalize(alert, DEFER, report, type("S", (), {
            "session_id": "N/A", "integration_mode": "stub",
            "pr_url": "", "disposition": "DEFERRED",
        })(), quiet=quiet)
        return report

    if action == ESCALATE:
        _print(f"  Action: ESCALATE (requires human review)")
        for reason in triage_result.reasons:
            _print(f"    - {reason}")
        session = create_session(alert, "NEEDS_HUMAN_REVIEW", "MEDIUM")
        notification = build_notification(
            alert, "NEEDS_HUMAN_REVIEW", "",
            integration_mode=session.integration_mode,
        )
        deliver_notification(notification)
        report = generate_report(
            alert, triage_result, None, None,
            notification_sent=True,
            integration_mode=session.integration_mode,
        )
        if db_conn:
            store.record_alert(
                db_conn, alert, report,
                policy_action=ESCALATE, sla_hours=triage_result.sla_hours,
            )
        _finalize(alert, ESCALATE, report, session, quiet=quiet)
        return report

    # AUTO_REMEDIATE or REMEDIATE_WITH_REVIEW
    review_required = action == REMEDIATE_WITH_REVIEW
    _print(f"  Action: {action}")
    if review_required:
        _print("  Note: security reviewer required on PR")
    _print()

    # 3. Execution — Devin generates the remediation
    _print("[3/9] Creating Devin remediation session...")
    prompt = build_prompt(alert)
    _print(f"  Mode:        {mode}")
    _print(f"  Prompt task: {prompt['task']}")
    _print(f"  Target:      {prompt['alert']['file_path']}")
    _print()

    # 4. Apply fix
    _print("[4/9] Applying fix...")
    exec_result = execute(alert, repo_root)
    if not exec_result.success:
        _print(f"  Error: {exec_result.error}")
        session = create_session(alert, "NEEDS_HUMAN_REVIEW", "LOW")
        report = generate_report(
            alert, triage_result, exec_result, None,
            integration_mode=session.integration_mode,
        )
        if db_conn:
            store.record_alert(
                db_conn, alert, report,
                policy_action=action, sla_hours=triage_result.sla_hours,
            )
        _finalize(alert, action, report, session, quiet=quiet)
        return report

    _print(f"  {exec_result.summary}")
    _print()

    # 5. Validate
    target_file = str(Path(repo_root) / alert.file_path)
    _print("[5/9] Validating fix...")
    val_result = validate(target_file)
    for step in val_result.steps:
        _print(f"  {step.command} -> {step.result}")
    _print()

    if not val_result.passed:
        session = create_session(alert, "NEEDS_HUMAN_REVIEW", "MEDIUM")
        report = generate_report(
            alert, triage_result, exec_result, val_result,
            integration_mode=session.integration_mode,
        )
        if db_conn:
            store.record_alert(
                db_conn, alert, report,
                policy_action=action, sla_hours=triage_result.sla_hours,
            )
        _finalize(alert, action, report, session, quiet=quiet)
        return report

    # 6. Devin session complete
    _print("[6/9] Devin session complete...")
    session = create_session(alert, "PR_READY", "HIGH")
    _print(f"  Session ID:  {session.session_id}")
    _print(f"  Disposition: {session.disposition}")
    _print(f"  PR URL:      {session.pr_url}")
    _print()

    # 7. Review & Routing — PR + notification to right humans
    _print("[7/9] Routing to reviewers...")
    pr_payload = build_pr_payload(
        alert, exec_result, session.pr_url,
        integration_mode=session.integration_mode,
        review_required=review_required,
    )
    pr_result = deliver_pr(pr_payload, repo_root=repo_root)
    _print(f"  PR payload:     {pr_result.artifact_path} ({pr_result.method})")
    if pr_result.pr_url:
        session.pr_url = pr_result.pr_url

    if review_required:
        _print("  Security reviewer: REQUIRED")

    notification = build_notification(
        alert, session.disposition, session.pr_url,
        integration_mode=session.integration_mode,
    )
    notif_result = deliver_notification(notification)
    _print(f"  Notification:   {notif_result.artifact_path} ({notif_result.method})")
    _print()

    # 8. Audit — evidence for compliance
    _print("[8/9] Recording audit evidence...")
    report = generate_report(
        alert, triage_result, exec_result, val_result,
        pr_url=session.pr_url, notification_sent=True,
        integration_mode=session.integration_mode,
    )
    report["policy_action"] = action
    report["review_required"] = review_required
    _print("  Written: artifacts/remediation_report.json")
    _print()

    if db_conn:
        store.record_alert(
            db_conn, alert, report,
            policy_action=action, sla_hours=triage_result.sla_hours,
        )

    # 9. Dashboard
    _finalize(alert, action, report, session, quiet=quiet)
    return report


# ---------------------------------------------------------------------------
# Finalization helpers
# ---------------------------------------------------------------------------


def _finalize(
    alert: Alert, policy_action: str, report: dict, session: "object",
    *, quiet: bool = False,
) -> None:
    def _print(*args, **kwargs):
        if not quiet:
            print(*args, **kwargs)

    _print("[9/9] Generating dashboard...")
    dashboard_path = generate_dashboard()
    summary_path = _write_demo_summary(alert, policy_action, report, session)
    _print(f"  Dashboard:    {dashboard_path}")
    _print(f"  Demo summary: {summary_path}")
    _print()
    if not quiet:
        _print_summary(alert, policy_action, report, session)


def _write_demo_summary(
    alert: Alert, policy_action: str, report: dict, session: "object",
) -> str:
    disposition = report["disposition"]
    status = "COMPLETE" if disposition == "PR_READY" else "ESCALATED"
    ts = report.get("timestamp", datetime.now(timezone.utc).isoformat())

    lines = [
        "# SAGE Remediation Summary",
        "",
        f"**Generated**: {ts}",
        "",
        "## Alert",
        "",
        "| Field | Value |",
        "|-------|-------|",
        f"| Alert ID | {alert.alert_id} |",
        f"| Rule | {alert.rule_name} |",
        f"| CWE | {alert.cwe} |",
        f"| Severity | {alert.severity} |",
        f"| File | `{alert.file_path}` |",
        "",
        "## Governance Decision",
        "",
        "| Field | Value |",
        "|-------|-------|",
        f"| Policy Action | **{policy_action}** |",
        f"| Disposition | {disposition} |",
        f"| Confidence | {report.get('confidence', '')} |",
        f"| Decision Trace | {report.get('decision_trace', '')} |",
        "",
        f"**{status}** — {disposition}",
        "",
    ]

    out = "artifacts/demo_summary.md"
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_text("\n".join(lines))
    return out


def _print_summary(
    alert: Alert, policy_action: str, report: dict, session: "object",
) -> None:
    disposition = report["disposition"]
    status = "COMPLETE" if disposition == "PR_READY" else "ESCALATED"

    print(SEPARATOR)
    print("  SAGE REMEDIATION SUMMARY")
    print(SEPARATOR)
    print(f"  Alert ID:       {alert.alert_id}")
    print(f"  Rule:           {alert.rule_name}")
    print(f"  CWE:            {alert.cwe}")
    print(f"  Policy Action:  {policy_action}")
    print(f"  Disposition:    {disposition}")
    print(f"  Confidence:     {report['confidence']}")
    print(f"  Devin Session:  {session.session_id}")
    print(f"  Devin Mode:     {session.integration_mode}")
    print(f"  PR URL:         {session.pr_url or 'N/A'}")
    print(f"  Notification:   {'sent' if report.get('notification_sent') else 'not sent'}")
    print(f"  Status:         {status}")
    print(SEPARATOR)


def main() -> int:
    alert_path = sys.argv[1] if len(sys.argv) > 1 else "fixtures/sample_alert.json"
    repo_root = sys.argv[2] if len(sys.argv) > 2 else "target_repo"

    db_conn = store.init_db()
    report = process_alert(alert_path, repo_root, db_conn=db_conn)
    db_conn.close()

    return 0 if report["disposition"] == "PR_READY" else 1


if __name__ == "__main__":
    sys.exit(main())
