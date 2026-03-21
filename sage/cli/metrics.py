#!/usr/bin/env python3
"""SAGE Metrics: Display all KPIs from the alert tracking database.

Computes and displays every metric defined in docs/KPIS.md:
  - Outcome: SLA compliance, MTTR, aging backlog
  - System: auto-remediation rate, PR merge rate, time to first action
  - Governance: unowned findings, SLA breaches, lifecycle completion
"""

import sys

from sage.pipeline import store


SEPARATOR = "-" * 62
THIN_SEP = "-" * 62


def main() -> int:
    db_conn = store.init_db()
    metrics = store.get_metrics(db_conn)
    kpis = store.get_kpis(db_conn)

    total = metrics["total"]
    if total == 0:
        print()
        print("  No alerts tracked yet. Run 'python -m sage full-demo' first.")
        print()
        db_conn.close()
        return 0

    by_disp = metrics["by_disposition"]
    by_cwe = metrics["by_cwe"]
    by_team = metrics["by_team"]
    by_action = metrics["by_action"]
    by_lifecycle = metrics["by_lifecycle"]

    print()
    print(SEPARATOR)
    print("  SAGE KPI Dashboard")
    print(SEPARATOR)
    print()

    # -----------------------------------------------------------------------
    # Outcome Metrics
    # -----------------------------------------------------------------------
    print("  OUTCOME METRICS")
    print(THIN_SEP)
    print()

    # SLA Compliance Rate
    sla_pct = int(kpis["sla_compliance_rate"] * 100)
    print(f"  SLA Compliance Rate:       {sla_pct}% "
          f"({kpis['sla_compliant']}/{kpis['sla_total']} high-risk resolved within SLA)")

    # MTTR
    mttr = kpis["mttr_hours"]
    if mttr < 1:
        mttr_str = f"{mttr * 60:.0f}m"
    else:
        mttr_str = f"{mttr:.1f}h"
    print(f"  Mean Time to Remediation:  {mttr_str}")

    # Aging Backlog
    aging = kpis["aging_backlog"]
    aging_total = aging["within_sla"] + aging["at_risk"] + aging["breached"]
    print(f"  Aging High-Risk Backlog:   {aging_total} open")
    if aging_total:
        print(f"    < 24h (within SLA):      {aging['within_sla']}")
        print(f"    24-72h (at risk):        {aging['at_risk']}")
        print(f"    > 72h (SLA breach):      {aging['breached']}")
    print()

    # -----------------------------------------------------------------------
    # System Effectiveness Metrics
    # -----------------------------------------------------------------------
    print("  SYSTEM EFFECTIVENESS")
    print(THIN_SEP)
    print()

    # Auto-Remediation Rate
    auto_pct = int(kpis["auto_remediation_rate"] * 100)
    print(f"  Auto-Remediation Rate:     {auto_pct}% "
          f"({kpis['auto_remediated']}/{total} resolved via automation)")

    # PR Merge Rate
    merge_pct = int(kpis["pr_merge_rate"] * 100)
    print(f"  PR Merge Rate:             {merge_pct}% "
          f"({kpis['merged']}/{kpis['total_prs']} PRs merged)")

    # Time to First Action
    ttfa = kpis["time_to_first_action_hours"]
    if ttfa < 1:
        ttfa_str = f"{ttfa * 60:.0f}m"
    else:
        ttfa_str = f"{ttfa:.1f}h"
    print(f"  Time to First Action:      {ttfa_str}")
    print()

    # -----------------------------------------------------------------------
    # Governance Metrics
    # -----------------------------------------------------------------------
    print("  GOVERNANCE")
    print(THIN_SEP)
    print()

    unowned = kpis["unowned_findings"]
    unowned_status = "PASS" if unowned == 0 else f"FAIL ({unowned})"
    print(f"  Unowned Findings:          {unowned_status}")

    breach = kpis["sla_breach_count"]
    breach_status = "PASS" if breach == 0 else f"FAIL ({breach})"
    print(f"  SLA Breaches:              {breach_status}")

    comp_pct = int(kpis["lifecycle_completion_rate"] * 100)
    print(f"  Lifecycle Completion:      {comp_pct}% "
          f"({kpis['lifecycle_completed']}/{total} reached terminal state)")
    print()

    # -----------------------------------------------------------------------
    # Breakdowns
    # -----------------------------------------------------------------------
    print("  BREAKDOWNS")
    print(THIN_SEP)
    print()

    print("  By Policy Action:")
    for action, count in sorted(by_action.items()):
        if action:
            bar = "#" * (count * 3)
            print(f"    {action:<28} {count:>3}  {bar}")
    print()

    print("  By Lifecycle State:")
    for state, count in sorted(by_lifecycle.items()):
        bar = "#" * (count * 3)
        print(f"    {state:<28} {count:>3}  {bar}")
    print()

    print("  By CWE:")
    for cwe, count in sorted(by_cwe.items()):
        bar = "#" * (count * 3)
        print(f"    {cwe:<28} {count:>3}  {bar}")
    print()

    print("  By Team:")
    for team, count in sorted(by_team.items()):
        label = team or "(unassigned)"
        bar = "#" * (count * 3)
        print(f"    {label:<28} {count:>3}  {bar}")
    print()

    # -----------------------------------------------------------------------
    # Alert Table
    # -----------------------------------------------------------------------
    alerts = store.list_alerts(db_conn)
    if alerts:
        print("  ALERT LOG")
        print(THIN_SEP)
        print()
        print(f"  {'ID':<16} {'CWE':<10} {'Team':<12} {'Action':<24} {'State':<16} {'Updated'}")
        print(f"  {'-'*14:<16} {'-'*8:<10} {'-'*10:<12} {'-'*22:<24} {'-'*14:<16} {'-'*19}")
        for a in alerts:
            print(
                f"  {a['alert_id']:<16} {a['cwe']:<10} {a['owner_team']:<12} "
                f"{a['policy_action']:<24} {a['lifecycle_state']:<16} "
                f"{a['updated_at'][:19]}"
            )
        print()

    print(SEPARATOR)

    db_conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
