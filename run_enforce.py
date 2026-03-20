#!/usr/bin/env python3
"""SAGE Enforcement Runner: Check SLAs and deliver escalations.

Run on a schedule (e.g., cron every hour) to enforce follow-through:

    python run_enforce.py            # check and deliver
    python run_enforce.py --dry-run  # check only, no delivery

Crontab example (every hour):
    0 * * * * cd /path/to/repo && python run_enforce.py >> logs/enforce.log 2>&1

SAGE is designed so high-risk findings cannot silently persist.
Every item advances toward fix, review, or escalation.
"""

import argparse
import sys
from datetime import datetime, timezone

from pipeline import store
from pipeline.enforcement import check_all_enforcement
from integrations.notify import (
    build_escalation_notification,
    deliver_notification,
)


SEPARATOR = "-" * 56


def main() -> int:
    parser = argparse.ArgumentParser(
        description="SAGE enforcement: check SLAs and escalate stalled findings",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Report enforcement actions without delivering notifications",
    )
    args = parser.parse_args()

    db_conn = store.init_db()
    checks = check_all_enforcement(db_conn)

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    print()
    print(SEPARATOR)
    print("  SAGE Enforcement Check")
    print(SEPARATOR)
    print(f"  Timestamp:  {now}")
    print(f"  Mode:       {'dry-run' if args.dry_run else 'live'}")
    print(f"  Findings requiring action: {len(checks)}")
    print(SEPARATOR)
    print()

    if not checks:
        print("  All findings within SLA. No action required.")
        print()
        db_conn.close()
        return 0

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
            # Build and deliver escalation notification
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

            # Log the enforcement action to audit trail
            store._log_event(
                db_conn,
                check.alert_id,
                event_type="enforcement",
                old_state=check.lifecycle_state,
                new_state=check.lifecycle_state,
                detail=f"action={check.action_required}, elapsed={check.hours_elapsed}h",
            )

            # If SLA breached, update lifecycle state to ESCALATED
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

    print()
    if args.dry_run:
        print(f"  Dry run: {len(checks)} action(s) identified, none delivered.")
    else:
        print(f"  Delivered {delivered} escalation notification(s).")
    print(SEPARATOR)

    db_conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
