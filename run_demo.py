#!/usr/bin/env python3
"""Run the full CodeQL remediation control loop.

    alert -> triage -> devin -> remediation -> validate
         -> PR -> notification -> audit -> dashboard
"""

import sys
from datetime import datetime, timezone
from pathlib import Path

from pipeline.ingest import Alert, load_alert
from pipeline.triage import triage
from pipeline.execute import execute
from pipeline.validate import validate
from pipeline.output import generate_report

from integrations.devin_client import create_session, build_prompt, _get_mode
from integrations.pr_client import build_pr_payload, deliver_pr
from integrations.notify import build_notification, deliver_notification
from integrations.dashboard import generate_dashboard


SEPARATOR = "-" * 56


def main() -> int:
    alert_path = sys.argv[1] if len(sys.argv) > 1 else "fixtures/sample_alert.json"
    repo_root = sys.argv[2] if len(sys.argv) > 2 else "target_repo"
    mode = _get_mode()

    print()
    print(SEPARATOR)
    print("  CodeQL Remediation Control Loop")
    print(SEPARATOR)
    print(f"  Alert file:  {alert_path}")
    print(f"  Target repo: {repo_root}")
    print(f"  Devin mode:  {mode}")
    print(SEPARATOR)
    print()

    # 1. Ingest
    print("[1/9] Ingesting alert...")
    alert = load_alert(alert_path)
    print(f"  Alert ID:  {alert.alert_id}")
    print(f"  Rule:      {alert.rule_name}")
    print(f"  CWE:       {alert.cwe}")
    print(f"  Severity:  {alert.severity}")
    print(f"  File:      {alert.file_path}")
    print(f"  Lines:     {alert.line_range.start}-{alert.line_range.end}")
    print()

    # 2. Triage
    print("[2/9] Triaging alert...")
    triage_result = triage(alert)

    if not triage_result.eligible:
        print("  Result: NOT ELIGIBLE")
        for reason in triage_result.reasons:
            print(f"    - {reason}")
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
        _finalize(alert, "NOT ELIGIBLE", report, session)
        return 0

    if not triage_result.auto_fixable:
        print("  Result: RECOGNIZED but NOT AUTO-FIXABLE")
        for reason in triage_result.reasons:
            print(f"    - {reason}")
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
        _finalize(alert, "RECOGNIZED (escalated)", report, session)
        return 0

    print("  Result: ELIGIBLE for auto-remediation")
    print()

    # 3. Devin session
    print("[3/9] Creating Devin remediation session...")
    prompt = build_prompt(alert)
    print(f"  Mode:        {mode}")
    print(f"  Prompt task: {prompt['task']}")
    print(f"  Target:      {prompt['alert']['file_path']}")
    print()

    # 4. Execute fix
    print("[4/9] Applying fix...")
    exec_result = execute(alert, repo_root)
    if not exec_result.success:
        print(f"  Error: {exec_result.error}")
        session = create_session(alert, "NEEDS_HUMAN_REVIEW", "LOW")
        report = generate_report(
            alert, triage_result, exec_result, None,
            integration_mode=session.integration_mode,
        )
        _finalize(alert, "ELIGIBLE", report, session)
        return 1

    print(f"  {exec_result.summary}")
    print()

    # 5. Validate
    target_file = str(Path(repo_root) / alert.file_path)
    print("[5/9] Validating fix...")
    val_result = validate(target_file)
    for step in val_result.steps:
        print(f"  {step.command} -> {step.result}")
    print()

    if not val_result.passed:
        session = create_session(alert, "NEEDS_HUMAN_REVIEW", "MEDIUM")
        report = generate_report(
            alert, triage_result, exec_result, val_result,
            integration_mode=session.integration_mode,
        )
        _finalize(alert, "ELIGIBLE", report, session)
        return 1

    # 6. Devin session result
    print("[6/9] Devin session complete...")
    session = create_session(alert, "PR_READY", "HIGH")
    print(f"  Session ID:  {session.session_id}")
    print(f"  Disposition: {session.disposition}")
    print(f"  PR URL:      {session.pr_url}")
    print()

    # 7. PR + Notification
    print("[7/9] Generating PR and notification payloads...")
    pr_payload = build_pr_payload(
        alert, exec_result, session.pr_url,
        integration_mode=session.integration_mode,
    )
    pr_result = deliver_pr(pr_payload)
    print(f"  PR payload:     {pr_result.artifact_path} ({pr_result.method})")

    notification = build_notification(
        alert, session.disposition, session.pr_url,
        integration_mode=session.integration_mode,
    )
    notif_result = deliver_notification(notification)
    print(f"  Notification:   {notif_result.artifact_path} ({notif_result.method})")
    print()

    # 8. Audit report
    print("[8/9] Generating remediation report...")
    report = generate_report(
        alert, triage_result, exec_result, val_result,
        pr_url=session.pr_url, notification_sent=True,
        integration_mode=session.integration_mode,
    )
    print("  Written: artifacts/remediation_report.json")
    print()

    # 9. Dashboard + summary
    _finalize(alert, "ELIGIBLE", report, session)
    return 0


# ---------------------------------------------------------------------------
# Finalization helpers
# ---------------------------------------------------------------------------


def _finalize(
    alert: Alert, triage_decision: str, report: dict, session: "object",
) -> None:
    """Generate dashboard, demo summary, and print console summary."""
    print("[9/9] Generating dashboard and demo summary...")
    dashboard_path = generate_dashboard()
    summary_path = _write_demo_summary(alert, triage_decision, report, session)
    print(f"  Dashboard:    {dashboard_path}")
    print(f"  Demo summary: {summary_path}")
    print()
    _print_summary(alert, triage_decision, report, session)


def _write_demo_summary(
    alert: Alert, triage_decision: str, report: dict, session: "object",
) -> str:
    """Write a Markdown demo summary to artifacts/demo_summary.md."""
    disposition = report["disposition"]
    status = "COMPLETE" if disposition == "PR_READY" else "ESCALATED"
    ts = report.get("timestamp", datetime.now(timezone.utc).isoformat())

    lines = [
        "# Remediation Demo Summary",
        "",
        f"**Generated**: {ts}",
        "",
        "## Alert Processed",
        "",
        "| Field | Value |",
        "|-------|-------|",
        f"| Alert ID | {alert.alert_id} |",
        f"| Rule | {alert.rule_name} |",
        f"| CWE | {alert.cwe} |",
        f"| Severity | {alert.severity} |",
        f"| File | `{alert.file_path}` |",
        f"| Lines | {alert.line_range.start}-{alert.line_range.end} |",
        "",
        "## Decision",
        "",
        "| Field | Value |",
        "|-------|-------|",
        f"| Triage | {triage_decision} |",
        f"| Disposition | **{disposition}** |",
        f"| Confidence | {report.get('confidence', '')} |",
        f"| Decision Trace | {report.get('decision_trace', '')} |",
        "",
        "## Remediation",
        "",
        f"- **Summary**: {report.get('summary', 'N/A')}",
        f"- **Root Cause**: {report.get('root_cause', '') or 'N/A'}",
        f"- **Fix**: {report.get('fix', '') or 'N/A'}",
        "",
        "## Artifacts Generated",
        "",
        "| Artifact | Path |",
        "|----------|------|",
        "| Remediation Report | `artifacts/remediation_report.json` |",
        "| PR Payload | `artifacts/pr_payload.json` |",
        "| Notification Payload | `artifacts/notification_payload.json` |",
        "| HTML Dashboard | `artifacts/dashboard.html` |",
        "| Demo Summary | `artifacts/demo_summary.md` |",
        "",
        "## Integration Status",
        "",
        "| Integration | Mode |",
        "|-------------|------|",
        f"| Devin | {session.integration_mode} |",
        "| GitHub PR | stub (JSON artifact) |",
        "| Notification | stub (JSON artifact) |",
        "",
        "## Final Status",
        "",
        f"**{status}** — {disposition}",
        "",
    ]

    out = "artifacts/demo_summary.md"
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_text("\n".join(lines))
    return out


def _print_summary(
    alert: Alert, triage_decision: str, report: dict, session: "object",
) -> None:
    """Print a clean console summary suitable for screen recording."""
    disposition = report["disposition"]
    status = "COMPLETE" if disposition == "PR_READY" else "ESCALATED"

    print(SEPARATOR)
    print("  REMEDIATION SUMMARY")
    print(SEPARATOR)
    print(f"  Alert ID:       {alert.alert_id}")
    print(f"  Rule:           {alert.rule_name}")
    print(f"  CWE:            {alert.cwe}")
    print(f"  Triage:         {triage_decision}")
    print(f"  Disposition:    {disposition}")
    print(f"  Confidence:     {report['confidence']}")
    print(f"  Devin Session:  {session.session_id}")
    print(f"  Devin Mode:     {session.integration_mode}")
    print(f"  PR URL:         {session.pr_url or 'N/A'}")
    print(f"  Notification:   {'sent' if report['notification_sent'] else 'not sent'}")
    print(f"  Status:         {status}")
    print(SEPARATOR)
    print()
    print("  Artifacts:")
    print("    artifacts/remediation_report.json")
    print("    artifacts/pr_payload.json")
    print("    artifacts/notification_payload.json")
    print("    artifacts/dashboard.html")
    print("    artifacts/demo_summary.md")
    print()
    print("  Open artifacts/dashboard.html in a browser to view the dashboard.")
    print(SEPARATOR)


if __name__ == "__main__":
    sys.exit(main())
