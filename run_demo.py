#!/usr/bin/env python3
"""Run the full CodeQL remediation control loop.

    alert → triage → devin → remediation → PR → notification → audit
"""

import sys
from pathlib import Path

from pipeline.ingest import load_alert
from pipeline.triage import triage
from pipeline.execute import execute
from pipeline.validate import validate
from pipeline.output import generate_report

from integrations.devin_client import create_session, build_prompt
from integrations.pr_client import build_pr_payload, write_pr_payload
from integrations.notify import build_notification, write_notification


SEPARATOR = "-" * 50


def main() -> int:
    alert_path = sys.argv[1] if len(sys.argv) > 1 else "fixtures/sample_alert.json"
    repo_root = sys.argv[2] if len(sys.argv) > 2 else "target_repo"

    print("=== CodeQL Remediation Control Loop ===")
    print(f"Alert:  {alert_path}")
    print(f"Repo:   {repo_root}")
    print()

    # 1. Ingest
    print("[1/8] Ingesting alert...")
    alert = load_alert(alert_path)
    print(f"  Alert ID:  {alert.alert_id}")
    print(f"  CWE:       {alert.cwe}")
    print(f"  Severity:  {alert.severity}")
    print(f"  File:      {alert.file_path}")
    print(f"  Lines:     {alert.line_range.start}-{alert.line_range.end}")
    print()

    # 2. Triage
    print("[2/8] Triaging alert...")
    triage_result = triage(alert)
    if not triage_result.eligible:
        print("  Result: NOT ELIGIBLE")
        for reason in triage_result.reasons:
            print(f"    - {reason}")
        session = create_session(alert, "NEEDS_HUMAN_REVIEW", "LOW")
        notification = build_notification(alert, "NEEDS_HUMAN_REVIEW", "")
        write_notification(notification)
        report = generate_report(
            alert, triage_result, None, None, notification_sent=True,
        )
        _print_summary(alert, "NOT ELIGIBLE", report, session)
        return 0

    print("  Result: ELIGIBLE for auto-remediation")
    print()

    # 3. Devin session
    print("[3/8] Creating Devin remediation session...")
    prompt = build_prompt(alert)
    print(f"  Prompt task: {prompt['task']}")
    print(f"  Target:      {prompt['alert']['file_path']}")
    print()

    # 4. Execute fix
    print("[4/8] Applying fix...")
    exec_result = execute(alert, repo_root)
    if not exec_result.success:
        print(f"  Error: {exec_result.error}")
        session = create_session(alert, "NEEDS_HUMAN_REVIEW", "LOW")
        report = generate_report(alert, triage_result, exec_result, None)
        _print_summary(alert, "ELIGIBLE", report, session)
        return 1

    print(f"  {exec_result.summary}")
    print()

    # 5. Validate
    target_file = str(Path(repo_root) / alert.file_path)
    print("[5/8] Validating fix...")
    val_result = validate(target_file)
    for step in val_result.steps:
        print(f"  {step.command} -> {step.result}")
    print()

    if not val_result.passed:
        session = create_session(alert, "NEEDS_HUMAN_REVIEW", "MEDIUM")
        report = generate_report(alert, triage_result, exec_result, val_result)
        _print_summary(alert, "ELIGIBLE", report, session)
        return 1

    # 6. Devin session result
    print("[6/8] Devin session complete...")
    session = create_session(alert, "PR_READY", "HIGH")
    print(f"  Session ID:  {session.session_id}")
    print(f"  Disposition: {session.disposition}")
    print(f"  PR URL:      {session.pr_url}")
    print()

    # 7. PR + Notification
    print("[7/8] Generating PR and notification payloads...")
    pr_payload = build_pr_payload(alert, exec_result, session.pr_url)
    write_pr_payload(pr_payload)
    print("  Written: artifacts/pr_payload.json")

    notification = build_notification(alert, session.disposition, session.pr_url)
    write_notification(notification)
    print("  Written: artifacts/notification_payload.json")
    print()

    # 8. Audit report
    print("[8/8] Generating remediation report...")
    report = generate_report(
        alert, triage_result, exec_result, val_result,
        pr_url=session.pr_url, notification_sent=True,
    )
    print("  Written: artifacts/remediation_report.json")
    print()

    _print_summary(alert, "ELIGIBLE", report, session)
    return 0


def _print_summary(alert, triage_decision, report, session):
    """Print a clean console summary for demos."""
    print(SEPARATOR)
    print("  REMEDIATION SUMMARY")
    print(SEPARATOR)
    print(f"  Alert ID:       {alert.alert_id}")
    print(f"  Triage:         {triage_decision}")
    print(f"  Disposition:    {report['disposition']}")
    print(f"  Confidence:     {report['confidence']}")
    print(f"  Devin Session:  {session.session_id}")
    print(f"  PR URL:         {session.pr_url or 'N/A'}")
    print(f"  Notification:   {'sent' if report['notification_sent'] else 'not sent'}")
    print(f"  Status:         {'COMPLETE' if report['disposition'] == 'PR_READY' else 'ESCALATED'}")
    print(SEPARATOR)


if __name__ == "__main__":
    sys.exit(main())
