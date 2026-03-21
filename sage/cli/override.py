#!/usr/bin/env python3
"""SAGE Human Override: Manually change the state of a finding.

Humans must be able to reject, defer, or escalate a finding even after
automated action is initiated. This is NFR-4.

Usage:
    python run_override.py demo-001 merge              # mark as merged
    python run_override.py demo-001 close              # close without merge
    python run_override.py demo-001 reject             # reject remediation
    python run_override.py demo-001 defer              # defer to later
    python run_override.py demo-001 escalate           # manual escalation
    python run_override.py demo-001 reopen             # reopen a closed finding
    python run_override.py demo-001 status             # show current state + audit trail
"""

import argparse
import sys
from datetime import datetime, timezone

from sage.pipeline import store
from sage.pipeline.enforcement import (
    MERGED, CLOSED, DEFERRED, ESCALATED, UNDER_REVIEW, DETECTED,
)


SEPARATOR = "-" * 56

# Map CLI verbs to lifecycle states
_ACTION_MAP = {
    "merge": MERGED,
    "close": CLOSED,
    "reject": ESCALATED,
    "defer": DEFERRED,
    "escalate": ESCALATED,
    "reopen": UNDER_REVIEW,
}

# Valid transitions: from_state -> set of allowed to_states
_VALID_TRANSITIONS: dict[str, set[str]] = {
    DETECTED: {ESCALATED, DEFERRED, CLOSED},
    "TRIAGED": {ESCALATED, DEFERRED, CLOSED},
    "REMEDIATED": {UNDER_REVIEW, ESCALATED, CLOSED},
    UNDER_REVIEW: {MERGED, ESCALATED, DEFERRED, CLOSED},
    ESCALATED: {UNDER_REVIEW, MERGED, DEFERRED, CLOSED},
    DEFERRED: {UNDER_REVIEW, ESCALATED, CLOSED},
    MERGED: {CLOSED},
    CLOSED: {UNDER_REVIEW, ESCALATED},  # reopen paths
}


def _print_status(db_conn, alert_id: str) -> int:
    """Print the current state and audit trail for a finding."""
    alert = store.get_alert(db_conn, alert_id)
    if not alert:
        print(f"  Alert '{alert_id}' not found in database.")
        return 1

    print()
    print(SEPARATOR)
    print(f"  SAGE Finding: {alert_id}")
    print(SEPARATOR)
    print(f"  CWE:            {alert['cwe']}")
    print(f"  Rule:           {alert['rule_name']}")
    print(f"  Severity:       {alert['severity']}")
    print(f"  Team:           {alert['owner_team']}")
    print(f"  Policy Action:  {alert['policy_action']}")
    print(f"  Disposition:    {alert['disposition']}")
    print(f"  State:          {alert['lifecycle_state']}")
    print(f"  SLA:            {alert['sla_hours']}h (deadline: {alert['sla_deadline'][:16]})")
    print(f"  Created:        {alert['created_at'][:19]}")
    print(f"  Updated:        {alert['updated_at'][:19]}")
    if alert.get("pr_url"):
        print(f"  PR:             {alert['pr_url']}")
    print()

    events = store.get_events(db_conn, alert_id)
    if events:
        print("  Audit Trail:")
        print(f"  {'Timestamp':<22} {'Event':<16} {'From':<16} {'To':<16} Detail")
        print(f"  {'-'*20:<22} {'-'*14:<16} {'-'*14:<16} {'-'*14:<16} {'-'*30}")
        for e in events:
            ts = e["timestamp"][:19]
            print(
                f"  {ts:<22} {e['event_type']:<16} "
                f"{e['old_state'] or '-':<16} {e['new_state'] or '-':<16} "
                f"{e.get('detail', '')}"
            )
    print()
    print(SEPARATOR)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="SAGE: manually override finding lifecycle state",
    )
    parser.add_argument("alert_id", help="Alert ID to modify")
    parser.add_argument(
        "action",
        choices=["merge", "close", "reject", "defer", "escalate", "reopen", "status"],
        help="Override action to apply",
    )
    parser.add_argument(
        "--reason", default="",
        help="Reason for the override (recorded in audit trail)",
    )
    args = parser.parse_args()

    db_conn = store.init_db()

    # Status is read-only
    if args.action == "status":
        rc = _print_status(db_conn, args.alert_id)
        db_conn.close()
        return rc

    # Look up the alert
    alert = store.get_alert(db_conn, args.alert_id)
    if not alert:
        print(f"  Alert '{args.alert_id}' not found in database.")
        db_conn.close()
        return 1

    current_state = alert["lifecycle_state"]
    new_state = _ACTION_MAP[args.action]

    # Validate transition
    allowed = _VALID_TRANSITIONS.get(current_state, set())
    if new_state not in allowed:
        print(
            f"  Invalid transition: {current_state} -> {new_state} "
            f"(via '{args.action}')"
        )
        print(f"  Allowed from {current_state}: {', '.join(sorted(allowed))}")
        db_conn.close()
        return 1

    # Apply the override
    now = datetime.now(timezone.utc).isoformat()
    db_conn.execute(
        "UPDATE alerts SET lifecycle_state = ?, updated_at = ? WHERE alert_id = ?",
        (new_state, now, args.alert_id),
    )

    reason = args.reason or f"manual override: {args.action}"
    store._log_event(
        db_conn,
        args.alert_id,
        event_type="manual_override",
        old_state=current_state,
        new_state=new_state,
        detail=reason,
    )
    db_conn.commit()

    print()
    print(f"  {args.alert_id}: {current_state} -> {new_state} ({args.action})")
    if args.reason:
        print(f"  Reason: {args.reason}")
    print()

    db_conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
