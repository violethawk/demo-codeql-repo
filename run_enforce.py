#!/usr/bin/env python3
"""SAGE Enforcement Runner: SLA checks + KPI-driven enforcement.

Two enforcement layers:

  1. Per-finding: SLA deadlines, reminder/escalation timers
  2. Aggregate KPIs: when metrics degrade past thresholds, the system acts

Run on a schedule (e.g., cron every hour):

    python run_enforce.py            # check and deliver
    python run_enforce.py --dry-run  # check only, no delivery

Crontab example:
    0 * * * * cd /path/to/repo && python run_enforce.py >> logs/enforce.log 2>&1
"""

import argparse
import sys
from datetime import datetime, timezone

from pipeline import store
from pipeline.enforcement import (
    check_all_enforcement,
    check_kpi_enforcement,
    apply_kpi_enforcement,
)
from integrations.notify import (
    build_escalation_notification,
    deliver_notification,
    NotificationPayload,
)


SEPARATOR = "-" * 62
THIN_SEP = "-" * 62


def main() -> int:
    parser = argparse.ArgumentParser(
        description="SAGE enforcement: SLA checks + KPI-driven actions",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Report enforcement actions without delivering notifications",
    )
    args = parser.parse_args()

    db_conn = store.init_db()

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    print()
    print(SEPARATOR)
    print("  SAGE Enforcement")
    print(SEPARATOR)
    print(f"  Timestamp:  {now}")
    print(f"  Mode:       {'dry-run' if args.dry_run else 'live'}")
    print(SEPARATOR)

    total_actions = 0

    # -------------------------------------------------------------------
    # Layer 1: Per-finding SLA enforcement
    # -------------------------------------------------------------------
    print()
    print("  PER-FINDING SLA CHECKS")
    print(THIN_SEP)
    print()

    checks = check_all_enforcement(db_conn)

    if not checks:
        print("  All findings within SLA.")
    else:
        print(f"  {len(checks)} finding(s) require action:")
        print()

    delivered = 0
    for check in checks:
        alert = store.get_alert(db_conn, check.alert_id)
        owner_team = alert.get("owner_team", "") if alert else ""
        cwe = alert.get("cwe", "") if alert else ""

        icon = {
            "remind_owner": "~",
            "escalate_manager": "!",
            "sla_breach": "X",
        }.get(check.action_required, "?")

        print(
            f"  [{icon}] {check.alert_id:<16} "
            f"{check.action_required:<20} "
            f"{check.hours_elapsed:>6.1f}h / {check.sla_hours}h SLA  "
            f"state={check.lifecycle_state}"
        )

        if not args.dry_run:
            notif = build_escalation_notification(
                alert_id=check.alert_id,
                cwe=cwe,
                owner_team=owner_team,
                action_required=check.action_required,
                hours_elapsed=check.hours_elapsed,
                sla_hours=check.sla_hours,
            )
            result = deliver_notification(
                notif,
                output_path=f"artifacts/escalation_{check.alert_id}.json",
            )
            if result.delivered:
                delivered += 1

            store._log_event(
                db_conn,
                check.alert_id,
                event_type="enforcement",
                old_state=check.lifecycle_state,
                new_state=check.lifecycle_state,
                detail=f"action={check.action_required}, elapsed={check.hours_elapsed}h",
            )

            if check.action_required == "sla_breach" and alert:
                db_conn.execute(
                    "UPDATE alerts SET lifecycle_state = 'ESCALATED', updated_at = ? "
                    "WHERE alert_id = ?",
                    (datetime.now(timezone.utc).isoformat(), check.alert_id),
                )
                store._log_event(
                    db_conn,
                    check.alert_id,
                    event_type="state_change",
                    old_state=check.lifecycle_state,
                    new_state="ESCALATED",
                    detail="SLA breach — auto-escalated by enforcement",
                )

            db_conn.commit()

    total_actions += len(checks)

    # -------------------------------------------------------------------
    # Layer 2: KPI-driven enforcement
    # -------------------------------------------------------------------
    print()
    print("  AGGREGATE KPI ENFORCEMENT")
    print(THIN_SEP)
    print()

    kpi_violations = check_kpi_enforcement(db_conn)

    if not kpi_violations:
        print("  All KPIs within thresholds.")
    else:
        print(f"  {len(kpi_violations)} KPI violation(s):")
        print()
        for v in kpi_violations:
            status = f"{v.current_value:.0%}" if v.current_value <= 1 else f"{int(v.current_value)}"
            threshold = f"{v.threshold:.0%}" if v.threshold <= 1 else f"{int(v.threshold)}"
            print(f"  [!] {v.kpi_name:<28} {status:>6} (threshold: {threshold})")
            print(f"      Action: {v.action}")
            print(f"      {v.detail}")
            print()

        if not args.dry_run:
            actions = apply_kpi_enforcement(db_conn, kpi_violations)
            if actions:
                print("  Actions taken:")
                for a in actions:
                    print(f"    -> {a}")

                # Deliver KPI violation notifications
                for v in kpi_violations:
                    if v.action == "notify_security_lead":
                        notif = NotificationPayload(
                            channel="#security-escalations",
                            alert_id="SYSTEM",
                            rule_name="",
                            cwe="",
                            disposition="KPI_VIOLATION",
                            pr_url="",
                            owner_team="",
                            status="sla_breach",
                            message=f"SAGE KPI Alert: {v.detail}",
                        )
                        deliver_notification(
                            notif,
                            output_path=f"artifacts/kpi_violation_{v.kpi_name.lower().replace(' ', '_')}.json",
                        )

            total_actions += len(actions)

    # -------------------------------------------------------------------
    # Summary
    # -------------------------------------------------------------------
    print()
    print(THIN_SEP)
    if args.dry_run:
        print(f"  Dry run: {len(checks)} SLA action(s), {len(kpi_violations)} KPI violation(s). None delivered.")
    else:
        print(f"  {total_actions} enforcement action(s) executed.")
    print(SEPARATOR)

    db_conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
