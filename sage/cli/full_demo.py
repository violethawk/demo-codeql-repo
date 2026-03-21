#!/usr/bin/env python3
"""SAGE Full Demo: End-to-end governed remediation in motion.

This script runs the complete SAGE lifecycle for a live demo:

  1. LIVE FLOW  — Three findings enter the system, each takes a different
                  governance path (auto-remediate, remediate with review,
                  escalate). Devin executes. PRs route. Audit records.

  2. ENFORCEMENT — SLA checks run against all tracked findings. Stalled
                   items get reminders or escalations.

  3. HUMAN OVERRIDE — A finding is manually merged, proving humans retain
                      authority over the system.

  4. SYSTEM STATE — Metrics and aggregate dashboard render the evidence
                    view an auditor or security lead would inspect.

Usage:
    python -m sage full-demo

The dashboard is not the product. It's just a view into a system that is
continuously ingesting findings, making decisions, executing remediations
through Devin, and enforcing follow-through.
"""

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SEPARATOR = "=" * 62
THIN_SEP = "-" * 62
PAUSE = 0.6  # seconds between sections for readability

# Path to the vulnerable app (we restore it between fixes)
APP_PATH = Path("demo/app.py")
APP_ORIGINAL = None  # stored at startup


def banner(title: str) -> None:
    print()
    print(SEPARATOR)
    print(f"  {title}")
    print(SEPARATOR)
    print()


def section(title: str) -> None:
    print()
    print(THIN_SEP)
    print(f"  {title}")
    print(THIN_SEP)
    print()


def pause() -> None:
    time.sleep(PAUSE)


def restore_app() -> None:
    """Restore the vulnerable app.py to its original state."""
    if APP_ORIGINAL:
        APP_PATH.write_text(APP_ORIGINAL)


def run(cmd: str, show_output: bool = True) -> str:
    """Run a shell command, print and return output."""
    result = subprocess.run(
        cmd, shell=True, capture_output=True, text=True,
    )
    output = result.stdout + result.stderr
    if show_output and output.strip():
        for line in output.strip().splitlines():
            print(f"  {line}")
    return output


# ---------------------------------------------------------------------------
# Demo phases
# ---------------------------------------------------------------------------


def phase_1_live_flow() -> None:
    """Three findings, three governance paths."""
    banner("PHASE 1: LIVE FLOW — Findings enter the system")

    print("  Three CodeQL findings from a single SARIF scan.")
    print("  Each takes a different governance path:")
    print()
    print("    CWE-89  SQL Injection      → AUTO_REMEDIATE")
    print("    CWE-79  Cross-Site Script   → REMEDIATE_WITH_REVIEW")
    print("    CWE-78  Command Injection   → REMEDIATE_WITH_REVIEW")
    print()
    print("  Watch the policy engine decide, Devin execute, and")
    print("  the system route each fix to the right reviewers.")
    pause()

    # Process each fixture individually for visible output
    fixtures = [
        ("demo/fixtures/sample_alert.json", "CWE-89 SQL Injection"),
        ("demo/fixtures/sample_alert_xss.json", "CWE-79 Cross-Site Scripting"),
        ("demo/fixtures/sample_alert_cmdi.json", "CWE-78 Command Injection"),
    ]

    for fixture, label in fixtures:
        section(f"Processing: {label}")
        restore_app()
        run(f"python -m sage demo {fixture}")
        pause()


def phase_2_enforcement() -> None:
    """SLA enforcement + KPI-driven enforcement."""
    banner("PHASE 2: ENFORCEMENT — KPIs drive system actions")

    print("  The enforcement layer doesn't just report metrics.")
    print("  When KPIs degrade past thresholds, the system acts:")
    print()
    print("    SLA compliance < 80%     → escalate at-risk findings")
    print("    Lifecycle completion < 80% → notify security lead")
    print("    PR merge rate < 60%      → flag trust issue")
    print("    Unowned findings > 0     → auto-assign to default team")
    print("    SLA breaches > 0         → auto-escalate breached findings")
    pause()

    section("Running enforcement (dry-run)")
    run("python -m sage enforce --dry-run")
    pause()


def phase_3_override() -> None:
    """Human override — prove humans retain authority."""
    banner("PHASE 3: HUMAN OVERRIDE — Humans retain authority")

    print("  A security lead reviews demo-001 (SQL injection) and")
    print("  approves the merge. The system records the override")
    print("  with a reason and timestamps it in the audit trail.")
    pause()

    section("Merging demo-001")
    run('python -m sage override demo-001 merge --reason "Reviewed and approved by security lead"')
    pause()

    section("Audit trail for demo-001")
    run("python -m sage override demo-001 status")
    pause()


def phase_4_system_state() -> None:
    """Metrics + dashboard — the evidence view."""
    banner("PHASE 4: SYSTEM STATE — The evidence view")

    print("  This is what an auditor or security lead inspects.")
    print("  Not a dashboard someone built — evidence the system")
    print("  generated by doing its job.")
    pause()

    section("Remediation metrics")
    run("python -m sage metrics")
    pause()

    section("Generating aggregate governance dashboard")
    # Generate the aggregate dashboard from DB
    run(
        'python -c "'
        "from sage.pipeline.store import init_db; "
        "from sage.integrations.dashboard import generate_aggregate_dashboard; "
        "conn = init_db(); "
        "p = generate_aggregate_dashboard(conn); "
        "conn.close(); "
        "print(f'  Dashboard: {p}')"
        '"'
    )
    pause()


def phase_5_summary() -> None:
    """Closing summary."""
    banner("DEMO COMPLETE")

    print("  What you just saw:")
    print()
    print("    1. Three CodeQL findings ingested from fixtures")
    print("    2. Policy engine assigned a governance action to each")
    print("    3. Devin executed remediations for approved classes")
    print("    4. PRs routed to correct reviewers with labels")
    print("    5. Enforcement checked SLAs across all findings")
    print("    6. Human override merged a finding with audit trail")
    print("    7. Metrics and dashboard rendered as evidence")
    print()
    print("  The dashboard is not the product.")
    print("  It's evidence of a system that is continuously ingesting")
    print("  findings, making decisions, executing remediations through")
    print("  Devin, and enforcing follow-through.")
    print()
    print("  Artifacts:")
    print("    artifacts/dashboard.html       — single-alert view")
    print("    artifacts/dashboard_all.html   — aggregate governance view")
    print("    artifacts/remediation_report.json")
    print("    pipeline.db                    — full audit database")
    print()
    print(THIN_SEP)
    print('  "The goal isn\'t to automate security theater.')
    print('   The goal is to make unresolved high-risk findings')
    print('   operationally impossible to ignore."')
    print(THIN_SEP)
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    global APP_ORIGINAL

    # Clean state
    for f in Path("artifacts").glob("*"):
        f.unlink()
    Path("artifacts").mkdir(exist_ok=True)
    if Path("pipeline.db").exists():
        Path("pipeline.db").unlink()

    # Save original app.py
    APP_ORIGINAL = APP_PATH.read_text()

    banner("SAGE — Security Automation & Governance Engine")
    print("  A security remediation control plane that converts CodeQL")
    print("  findings into fixed, reviewed, and auditable outcomes")
    print("  through policy-driven automation and escalation.")
    print()
    print("  This demo runs the full governed lifecycle:")
    print()
    print("    Detection → Decision → Execution → Review → Enforcement → Evidence")
    pause()

    phase_1_live_flow()
    phase_2_enforcement()
    phase_3_override()
    phase_4_system_state()
    phase_5_summary()

    # Restore app.py
    restore_app()

    return 0


if __name__ == "__main__":
    sys.exit(main())
