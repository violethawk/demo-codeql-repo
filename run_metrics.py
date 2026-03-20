#!/usr/bin/env python3
"""Display remediation metrics from the alert tracking database."""

import sys

from pipeline import store


SEPARATOR = "-" * 56


def main() -> int:
    db_conn = store.init_db()
    metrics = store.get_metrics(db_conn)

    total = metrics["total"]
    if total == 0:
        print()
        print("  No alerts tracked yet. Run 'python run_demo.py' or")
        print("  'python run_batch.py fixtures/' first.")
        print()
        db_conn.close()
        return 0

    rate = metrics["remediation_rate"]
    by_disp = metrics["by_disposition"]
    by_cwe = metrics["by_cwe"]
    by_team = metrics["by_team"]

    print()
    print(SEPARATOR)
    print("  SAGE Remediation Metrics")
    print(SEPARATOR)
    print()
    print(f"  Total alerts tracked:  {total}")
    print(f"  Remediation rate:      {rate:.0%} ({by_disp.get('PR_READY', 0)}/{total})")
    print()

    print("  By Disposition:")
    for disp, count in sorted(by_disp.items()):
        bar = "#" * (count * 4)
        print(f"    {disp:<24} {count:>3}  {bar}")
    print()

    print("  By CWE:")
    for cwe, count in sorted(by_cwe.items()):
        bar = "#" * (count * 4)
        print(f"    {cwe:<24} {count:>3}  {bar}")
    print()

    print("  By Team:")
    for team, count in sorted(by_team.items()):
        team_label = team or "(unassigned)"
        bar = "#" * (count * 4)
        print(f"    {team_label:<24} {count:>3}  {bar}")

    print()

    # List recent alerts
    alerts = store.list_alerts(db_conn)
    if alerts:
        print(f"  {'Alert ID':<16} {'CWE':<10} {'Team':<12} {'Disposition':<24} {'Updated'}")
        print(f"  {'-'*14:<16} {'-'*8:<10} {'-'*10:<12} {'-'*22:<24} {'-'*20}")
        for a in alerts:
            print(
                f"  {a['alert_id']:<16} {a['cwe']:<10} {a['owner_team']:<12} "
                f"{a['disposition']:<24} {a['updated_at'][:19]}"
            )
    print()
    print(SEPARATOR)

    db_conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
