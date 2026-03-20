#!/usr/bin/env python3
"""Run the full CodeQL remediation pipeline on a sample alert."""

import sys
from pathlib import Path

from pipeline.ingest import load_alert
from pipeline.triage import triage
from pipeline.execute import execute
from pipeline.validate import validate
from pipeline.output import generate_report


def main() -> int:
    alert_path = sys.argv[1] if len(sys.argv) > 1 else "fixtures/sample_alert.json"
    repo_root = sys.argv[2] if len(sys.argv) > 2 else "target_repo"

    print("=== CodeQL Remediation Pipeline ===")
    print(f"Alert:  {alert_path}")
    print(f"Repo:   {repo_root}")
    print()

    # 1. Ingest
    print("[1/5] Ingesting alert...")
    alert = load_alert(alert_path)
    print(f"  Alert ID:  {alert.alert_id}")
    print(f"  CWE:       {alert.cwe}")
    print(f"  Severity:  {alert.severity}")
    print(f"  File:      {alert.file_path}")
    print(f"  Lines:     {alert.line_range.start}-{alert.line_range.end}")
    print()

    # 2. Triage
    print("[2/5] Triaging alert...")
    triage_result = triage(alert)
    if not triage_result.eligible:
        print("  Result: NOT ELIGIBLE")
        for reason in triage_result.reasons:
            print(f"    - {reason}")
        report = generate_report(alert, triage_result, None, None)
        print()
        print(f"Disposition: {report['disposition']}")
        return 0

    print("  Result: ELIGIBLE for auto-remediation")
    print()

    # 3. Execute
    print("[3/5] Applying fix...")
    exec_result = execute(alert, repo_root)
    if not exec_result.success:
        print(f"  Error: {exec_result.error}")
        report = generate_report(alert, triage_result, exec_result, None)
        print()
        print(f"Disposition: {report['disposition']}")
        return 1

    print(f"  {exec_result.summary}")
    print()

    # 4. Validate
    target_file = str(Path(repo_root) / alert.file_path)
    print("[4/5] Validating fix...")
    val_result = validate(target_file)
    for step in val_result.steps:
        print(f"  {step.command} → {step.result}")
    print()

    # 5. Output
    print("[5/5] Generating report...")
    report = generate_report(alert, triage_result, exec_result, val_result)
    print("  Written to: remediation_report.json")
    print()

    print(f"Disposition: {report['disposition']}")
    print(f"Confidence:  {report['confidence']}")

    if report["disposition"] != "PR_READY":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
