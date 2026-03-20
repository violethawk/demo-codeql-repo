"""Notification Layer: Generate notifications for engineering teams.

Produces a structured notification payload that represents a message
sent to the owning engineering team (e.g., via Slack, PagerDuty, email).

Currently: Generates a notification_payload.json artifact.
"""

import json
from pathlib import Path

from pipeline.ingest import Alert


def build_notification(alert: Alert, disposition: str, pr_url: str) -> dict:
    """Build a notification payload for the owning team."""
    if disposition == "PR_READY":
        status = "ready_for_review"
        message = (
            f"CodeQL alert {alert.alert_id} ({alert.cwe}) has been "
            f"auto-remediated. PR is ready for review: {pr_url}"
        )
    else:
        status = "needs_attention"
        message = (
            f"CodeQL alert {alert.alert_id} ({alert.cwe}) requires "
            f"human review. Auto-remediation was not possible."
        )

    return {
        "channel": "backend-security",
        "alert_id": alert.alert_id,
        "disposition": disposition,
        "pr_url": pr_url,
        "owner_team": alert.owner_team,
        "status": status,
        "message": message,
    }


def write_notification(
    payload: dict, output_path: str = "artifacts/notification_payload.json"
) -> None:
    """Write the notification payload to a JSON artifact."""
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(json.dumps(payload, indent=2) + "\n")
